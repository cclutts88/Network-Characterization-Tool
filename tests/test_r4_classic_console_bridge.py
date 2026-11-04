import copy
import importlib.util
import json
import os
from pathlib import Path
import sys

import pytest
pytest.importorskip('fcntl')
import test_recovery_helper_upgrade as lifecycle

spec = importlib.util.spec_from_file_location('classic_bridge', Path(__file__).parents[1]/'scripts/nct-r4-classic-console-bridge.py')
bridge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bridge)


def classic_fixture(tmp_path, monkeypatch):
    monkeypatch.setattr(lifecycle.upgrade_module, 'OLD_CONSOLE', bridge.CLASSIC)
    upgrade, engine, calls = lifecycle.fixture(tmp_path, monkeypatch)
    upgrade.config['console_image_id'] = bridge.CLASSIC
    lifecycle.host_module.save(upgrade.path, upgrade.config)
    engine.items['console']['Image'] = bridge.CLASSIC
    engine.items['console']['Config']['Image'] = bridge.CLASSIC
    baseline = next(iter(lifecycle.upgrade_module.BASELINES.values()))
    baseline['console_config_digest'] = bridge.CLASSIC
    release_path = upgrade.source.parent / 'release.json'
    release = json.loads(release_path.read_text())
    release['helper_upgrade_source']['console_image_id'] = bridge.CLASSIC
    release_path.write_text(json.dumps(release))
    lifecycle.write_manifest(upgrade.source.parent)
    old = {'Id': bridge.CLASSIC, 'Config': {'Env': ['NCT_BUILD_ID='+bridge.OLD_BUILD, 'NCT_BUILD_COMMIT='+bridge.OLD_COMMIT]}}
    command = engine.command
    monkeypatch.setattr(engine, 'command', lambda verb,*args: json.dumps([old]) if (verb,*args)==('image','inspect',bridge.CLASSIC) else command(verb,*args))
    digest = upgrade.image_config_digest
    monkeypatch.setattr(upgrade,'image_config_digest',lambda image:bridge.CLASSIC if image==bridge.CLASSIC else digest(image))
    return upgrade, engine, calls, old


def test_classic_content_admission_and_unchanged_lifecycle(tmp_path, monkeypatch):
    upgrade, engine, calls, old = classic_fixture(tmp_path, monkeypatch)
    before = copy.deepcopy(engine.items['nct'])
    receipt = (upgrade.state/'operation.json').read_bytes()
    assert bridge.qualify(upgrade)['original_console_content'] == bridge.CLASSIC
    upgrade.preflight()
    upgrade.apply()
    assert engine.items['nct'] == before
    assert (upgrade.state/'operation.json').read_bytes() == receipt
    assert json.loads(upgrade.journal_path.read_text())['phase']=='complete'


@pytest.mark.parametrize('change',['runtime','content','build','source','configured','actual'])
def test_refuses_changed_original_before_service_actions(tmp_path, monkeypatch,change):
    upgrade, engine, calls, old = classic_fixture(tmp_path, monkeypatch)
    if change=='runtime': old['Id']='sha256:'+'a'*64
    elif change=='content': monkeypatch.setattr(upgrade,'image_config_digest',lambda _: 'sha256:'+'a'*64)
    elif change=='build': old['Config']['Env'][0]='NCT_BUILD_ID=other'
    elif change=='source': old['Config']['Env'][1]='NCT_BUILD_COMMIT=other'
    elif change=='configured': upgrade.config['console_image_id']='sha256:'+'a'*64
    else: engine.items['console']['Image']='sha256:'+'a'*64
    with pytest.raises(ValueError): bridge.qualify(upgrade)
    assert calls==[]


def test_sealed_manifest_refuses_tamper_before_import(tmp_path):
    (tmp_path/'PACKAGE-MANIFEST.sha256').write_text('altered')
    with pytest.raises(ValueError,match='manifest'): bridge.check_release(tmp_path)


def test_actual_final_sealed_package_admitted(monkeypatch):
    package = os.environ.get('NCT_SEALED_R4_PACKAGE')
    if not package:
        pytest.skip('Exact sealed release mounted in package qualification')
    # Docker Desktop bind modes do not represent Linux protected host paths.
    monkeypatch.setattr(bridge, 'protected', lambda p: None)
    source, image = bridge.check_release(Path(package))
    assert source.name == 'nct-upgrade-recovery.py'
    assert image == 'nct-recovery-console:' + bridge.BUILD


def test_bridge_rollback_after_new_console_was_configured(tmp_path, monkeypatch):
    upgrade, engine, calls, old = classic_fixture(tmp_path, monkeypatch)
    sys.modules[upgrade.__class__.__module__] = lifecycle.upgrade_module
    original = copy.deepcopy(engine.items['console'])
    class PowerLoss(BaseException):
        pass
    def interrupted(_):
        raise PowerLoss()
    monkeypatch.setattr(upgrade, 'ready', interrupted)
    with pytest.raises(PowerLoss):
        upgrade.apply()
    upgrade.config = json.loads(upgrade.path.read_text())
    assert upgrade.config['console_image_id'] != bridge.CLASSIC
    assert bridge.qualify(upgrade, rollback=True)['original_console_content']==bridge.CLASSIC
    monkeypatch.setattr(upgrade, 'ready', lambda _: None)
    upgrade.rollback()
    assert engine.items['console']['Id'] == original['Id']
    assert engine.items['console']['Image'] == bridge.CLASSIC


def test_bridge_rollback_refuses_wrong_original_journal(tmp_path, monkeypatch):
    upgrade, engine, calls, old = classic_fixture(tmp_path, monkeypatch)
    sys.modules[upgrade.__class__.__module__] = lifecycle.upgrade_module
    upgrade.journal_path.write_text(json.dumps({'old_console':{'Image':'other'}}))
    with pytest.raises(ValueError,match='journal'): bridge.qualify(upgrade, rollback=True)
    assert calls == []
