import copy
import importlib.util
import json
from pathlib import Path
import sys

import pytest
pytest.importorskip('fcntl')

sys.path.insert(0, str(Path(__file__).parents[1] / 'scripts'))
import nct_update_host as host_module
from build_nct_range_package import write_manifest

spec = importlib.util.spec_from_file_location('helper_upgrade', Path(__file__).parents[1] / 'scripts/nct-upgrade-recovery.py')
upgrade_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(upgrade_module)


class Engine:
    def __init__(self, items, image):
        self.items, self.image, self.commands = items, image, []
    def inspect(self, name):
        return copy.deepcopy(next(v for k,v in self.items.items() if k == name or v['Id'] == name))
    def exists(self, name):
        try:
            return self.inspect(name)
        except StopIteration:
            return None
    def command(self, verb, *args):
        self.commands.append((verb, *args))
        if verb == 'image':
            return json.dumps([self.image])
        key = next(k for k,v in self.items.items() if k == args[0] or v['Id'] == args[0])
        if verb == 'rename':
            self.items[args[1]] = self.items.pop(key)
        elif verb == 'rm':
            del self.items[key]
        elif verb in {'start','stop'}:
            self.items[key]['State']['Running'] = verb == 'start'
        else:
            raise AssertionError(verb)
    def create(self, name, config):
        runtime = copy.deepcopy(config)
        host = runtime.pop('HostConfig')
        self.items[name] = {'Id':'new-console','Image':runtime['Image'], 'Config':runtime, 'HostConfig':host,
                           'Mounts':copy.deepcopy(self.items[next(k for k in self.items if '-before-' in k)]['Mounts']),
                           'State':{'Running':False}}


def fixture(tmp_path, monkeypatch):
    installed, source, state = tmp_path/'installed', tmp_path/'package/scripts', tmp_path/'state'
    for p in (installed, source, state, tmp_path/'deployment'):
        p.mkdir(parents=True)
    (state/'operation.json').write_text(json.dumps({'phase':'complete','id':'retained-operation','controller_sign_in_verified':True}))
    (state/'retained-receipt.json').write_bytes(b'retained receipt')
    config = {'contract':'nct-update-v1','console_image_id':upgrade_module.OLD_CONSOLE,'console_container':'console',
              'container':'nct','state_dir':str(state),'maintenance_lock':str(tmp_path/'deployment/maintenance.lock')}
    path = installed/'config.json'
    host_module.save(path, config)
    bindings = []
    for name in (*upgrade_module.FILES,'nct-upgrade-recovery.py','build_nct_range_package.py'):
        (source/name).write_bytes(('new '+name).encode())
        bindings.append({'package':'scripts/'+name,'sha256':host_module.digest_file(source/name)})
        if name in upgrade_module.FILES:
            (installed/name).write_bytes(('old '+name).encode())
    monkeypatch.setattr(upgrade_module,'BASE_HASHES',{name:{host_module.digest_file(installed/name)} for name in upgrade_module.FILES})
    monkeypatch.setattr(upgrade_module,'protected',lambda path,directory=False:Path(path))
    unit = tmp_path/'unit';unit.write_text('unchanged service unit')
    image = {'Id':'sha256:'+'b'*64,'Config':{'Env':['NCT_BUILD_COMMIT='+'c'*40,'NCT_BUILD_ID=new-release']}}
    release = {'contract':'nct-full-range-package-v1','commit':'c'*40,'build_id':'new-release','console_image':'new-console',
               'images':{'new-console':{'archive_config_digest':image['Id']}},'source_bindings':bindings}
    (source.parent/'release.json').write_text(json.dumps(release));write_manifest(source.parent)
    app = {'Id':'app-id','Image':'app-image','State':{'Running':True},'Config':{'Env':['NCT_BUILD_ID='+upgrade_module.R3,'NCT_BUILD_COMMIT='+upgrade_module.R3_COMMIT]},'HostConfig':{},
           'Mounts':[{'Type':'bind','Source':str(tmp_path/('server.'+ext)),'Destination':'/run/tls/nct-server.'+ext,'RW':False} for ext in ('crt','key')]}
    mounts = [{'Type':'bind','Source':str(src),'Destination':dst,'RW':rw} for src,dst,rw in (
        (state/'sockets/control','/run/nct-recovery',False),(state/'spool','/staging',True),
        (tmp_path/'server.crt','/run/tls/server.crt',False),(tmp_path/'server.key','/run/tls/server.key',False))]
    console = {'Id':'old-console','Image':upgrade_module.OLD_CONSOLE,'Config':{'Image':upgrade_module.OLD_CONSOLE,'Env':['NCT_BUILD_ID=old-console','NCT_BUILD_COMMIT=old-source','KEEP=retained']},
               'State':{'Running':False},'Mounts':mounts,'HostConfig':{'ReadonlyRootfs':True,'CapDrop':['ALL'],'SecurityOpt':['no-new-privileges:true']}}
    engine = Engine({'nct':app,'console':console},image)
    calls = []
    upgrade = upgrade_module.Upgrade(path,source,'new-console',engine=engine,service=calls.append,unit=unit)
    monkeypatch.setattr(upgrade,'check_service',lambda:None)
    monkeypatch.setattr(upgrade,'ready',lambda cfg:None)
    return upgrade,engine,calls


def test_helper_upgrade_preserves_app_evidence_receipts_and_runtime(tmp_path,monkeypatch):
    upgrade,engine,calls = fixture(tmp_path,monkeypatch)
    app = copy.deepcopy(engine.items['nct'])
    receipt = (upgrade.state/'operation.json').read_bytes()
    upgrade.apply()
    assert engine.items['nct'] == app
    assert (upgrade.state/'operation.json').read_bytes() == receipt
    assert (upgrade.state/'retained-receipt.json').read_bytes() == b'retained receipt'
    assert upgrade.config['console_image_id'] == upgrade_module.OLD_CONSOLE
    assert json.loads(upgrade.path.read_text())['console_image_id'] == engine.image['Id']
    assert json.loads(upgrade.journal_path.read_text())['phase'] == 'complete'
    assert engine.items['console']['HostConfig'] == next(v['HostConfig'] for k,v in engine.items.items() if '-before-' in k)
    assert not engine.items['console']['State']['Running']
    assert set(engine.items['console']['Config']['Env']) == {'KEEP=retained','NCT_BUILD_ID=new-release','NCT_BUILD_COMMIT='+'c'*40}
    assert not any(command[1] == 'app-id' for command in engine.commands if len(command)>1)


class PowerLoss(BaseException):
    pass


@pytest.mark.parametrize('phase',['prepared','stop_intent','files_intent','config_intent','console_intent','create_intent','rename_intent','start_intent'])
def test_crash_boundaries_restore_original_helper_console_without_app_changes(tmp_path,monkeypatch,phase):
    upgrade,engine,_ = fixture(tmp_path,monkeypatch)
    app = copy.deepcopy(engine.items['nct'])
    original = {n:(upgrade.path.parent/n).read_bytes() for n in ('config.json',*upgrade_module.FILES)}
    real_phase = upgrade.phase
    def crash(journal,value):
        real_phase(journal,value)
        if value == phase:
            raise PowerLoss()
    monkeypatch.setattr(upgrade,'phase',crash)
    with pytest.raises(PowerLoss):
        upgrade.apply()
    monkeypatch.setattr(upgrade,'phase',real_phase)
    upgrade.rollback()
    assert engine.items['nct'] == app
    assert engine.items['console']['Id'] == 'old-console'
    assert not engine.items['console']['State']['Running']
    assert {n:(upgrade.path.parent/n).read_bytes() for n in original} == original
    assert json.loads(upgrade.journal_path.read_text())['phase'] == 'rolled_back'


@pytest.mark.parametrize('change',['unknown_helper','mixed_source','mixed_image','pending_operation','writable_control','wrong_mount','duplicate_mount','capability','privileged','host_network'])
def test_preflight_refuses_unsupported_or_drifted_installation_before_stop(tmp_path,monkeypatch,change):
    upgrade,engine,calls = fixture(tmp_path,monkeypatch)
    console = engine.items['console']
    if change=='unknown_helper':(upgrade.path.parent/'nct_update_host.py').write_bytes(b'unknown')
    elif change=='mixed_source':(upgrade.source/'nct_update_host.py').write_bytes(b'changed')
    elif change=='mixed_image':engine.image['Config']['Env']=['NCT_BUILD_COMMIT=wrong']
    elif change=='pending_operation':(upgrade.state/'operation.json').write_text('{"phase":"awaiting_sign_in"}')
    elif change=='writable_control':console['Mounts'][0]['RW']=True
    elif change=='wrong_mount':console['Mounts'][0]['Source']='/somewhere/else'
    elif change=='duplicate_mount':console['Mounts'][1]=copy.deepcopy(console['Mounts'][0])
    elif change=='capability':console['HostConfig']['CapAdd']=['SYS_ADMIN']
    elif change=='privileged':console['HostConfig']['Privileged']=True
    elif change=='host_network':console['HostConfig']['NetworkMode']='host'
    with pytest.raises(ValueError):upgrade.apply()
    assert 'stop' not in calls and not upgrade.journal_path.exists()
    assert engine.items['nct']['State']['Running']


def test_candidate_drift_halts_rollback_before_removing_unknown_runtime(tmp_path,monkeypatch):
    upgrade,engine,_ = fixture(tmp_path,monkeypatch)
    phase = upgrade.phase
    def crash(journal,value):
        phase(journal,value)
        if value=='start_intent':raise PowerLoss()
    monkeypatch.setattr(upgrade,'phase',crash)
    with pytest.raises(PowerLoss):upgrade.apply()
    monkeypatch.setattr(upgrade,'phase',phase)
    engine.items['console']['Config']['Env']=['DRIFT=1']
    with pytest.raises(ValueError,match='Ambiguous console identity'):upgrade.rollback()
    assert engine.items['console']['Id']=='new-console'


def test_crash_after_create_before_id_receipt_recovers_owned_orphan(tmp_path,monkeypatch):
    upgrade,engine,_ = fixture(tmp_path,monkeypatch)
    create = engine.create
    def crash(name,runtime):
        create(name,runtime)
        raise PowerLoss()
    monkeypatch.setattr(engine,'create',crash)
    with pytest.raises(PowerLoss):upgrade.apply()
    assert 'new_console_id' not in json.loads(upgrade.journal_path.read_text())
    upgrade.rollback()
    assert engine.items['console']['Id'] == 'old-console'
    assert not any('-upgrade-' in name for name in engine.items)


def test_missing_backup_hash_refuses_rollback_without_replacing_files(tmp_path,monkeypatch):
    upgrade,engine,_=fixture(tmp_path,monkeypatch)
    phase=upgrade.phase
    def crash(journal,value):
        phase(journal,value)
        if value=='files_intent':raise PowerLoss()
    monkeypatch.setattr(upgrade,'phase',crash)
    with pytest.raises(PowerLoss):upgrade.apply()
    monkeypatch.setattr(upgrade,'phase',phase)
    journal=json.loads(upgrade.journal_path.read_text());del journal['backup_hashes']['nct_update_host.py']
    host_module.save(upgrade.journal_path,journal)
    before={n:(upgrade.path.parent/n).read_bytes() for n in ('config.json',*upgrade_module.FILES)}
    with pytest.raises(ValueError,match='hashes are incomplete'):upgrade.rollback()
    assert {n:(upgrade.path.parent/n).read_bytes() for n in before}==before
