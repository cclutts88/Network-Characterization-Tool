"""Exact offline fresh shell setup; only systemd/ss and admin peer are substituted.

Uses real Docker, empty bind storage, interactive password setup, CA-verified TLS,
the copied helper process, pinned console, account and evidence workflows.
"""
import argparse
import hashlib
import http.cookiejar
import json
import os
from pathlib import Path
import pty
import secrets
import select
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import termios
import time
import urllib.request

CLEANUP = {}


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--root',type=Path,required=True)
    parser.add_argument('--package',type=Path,required=True)
    args=parser.parse_args(); root=args.root
    assert root.name=='_data' and root.parent.name.startswith('nct-fresh-package-acceptance-') and root.parent.parent==Path('/var/lib/docker/volumes')
    assert not any(root.iterdir())
    os.umask(0o077)
    package=root/'package'; shutil.copytree(args.package,package)
    sys.path.insert(0,str(package/'scripts'))
    import nct_update_host as module
    from build_nct_range_package import verify_manifest
    tested=verify_manifest(package); release=json.loads((package/'release.json').read_text())
    own=Path('/etc/hostname').read_text().strip()
    class Engine(module.Docker):
        def inventory(self): return [x for x in super().inventory() if not x['Id'].startswith(own)]
    engine=Engine(); name='nct-fresh-acceptance-'+secrets.token_hex(6)
    CLEANUP.update(engine=engine,name=name,root=root)
    console=name+'-console'; persist=root/'p'; installed=root/'i'; state=root/'s'
    bin_dir=root/'bin'; shim=root/'shim'; bin_dir.mkdir(); shim.mkdir()
    service=root/'service.py'
    service.write_text("import sys\nsys.path.insert(0,"+repr(str(installed))+")\nimport nct_update_host as m\nclass D(m.Docker):\n def inventory(self): return [x for x in super().inventory() if not x['Id'].startswith("+repr(own)+")]\nm.Docker=D\nm.main()\n")
    (shim/'sitecustomize.py').write_text("import sys\nsys.path.insert(0,"+repr(str(package/'scripts'))+")\nimport nct_update_host as m\nclass D(m.Docker):\n def inventory(self): return [x for x in super().inventory() if not x['Id'].startswith("+repr(own)+")]\nm.Docker=D\n")
    systemctl=bin_dir/'systemctl'
    systemctl.write_text("#!/usr/local/bin/python\nimport os,sys,subprocess\nfrom pathlib import Path\nif 'show' in sys.argv: print('not-found')\nif 'enable' in sys.argv:\n env=dict(os.environ);env.pop('PYTHONPATH',None)\n log=open("+repr(str(root/'service.log'))+",'ab')\n p=subprocess.Popen([sys.executable,"+repr(str(service)) +",'--config',"+repr(str(installed/'config.json'))+"],env=env,stdout=log,stderr=log,start_new_session=True)\n Path("+repr(str(root/'service.pid'))+").write_text(str(p.pid))\n")
    systemctl.chmod(0o700)
    ss=bin_dir/'ss'; ss.write_text("#!/bin/sh\nprintf 'State Recv-Q Send-Q Local Address:Port Peer Address:Port\\n'\n"); ss.chmod(0o700)
    address=socket.gethostbyname('host.docker.internal')
    env={**os.environ,'PATH':str(bin_dir)+':'+os.environ['PATH'],'PYTHONPATH':str(shim),
        'NCT_CONTAINER':name,'NCT_RECOVERY_CONTAINER':console,'NCT_PERSIST_ROOT':str(persist),
        'NCT_RECOVERY_INSTALL_DIR':str(installed),'NCT_RECOVERY_STATE_DIR':str(state),
        'NCT_HTTPS_PORT':'18177','NCT_RECOVERY_PORT':'18178','NCT_APP_BIND_ADDRESS':'127.0.0.1',
        'NCT_RECOVERY_BIND_ADDRESS':'127.0.0.1','NCT_ADMIN_USER':'admin'}
    env.pop('PYTHONDONTWRITEBYTECODE',None)  # The trusted launcher must set this itself.
    late=root/'inject-late-container'
    docker_wrapper=bin_dir/'docker'
    docker_wrapper.write_text("#!/usr/local/bin/python\nimport os,sys,subprocess\nfrom pathlib import Path\nactual='/usr/local/bin/docker'\nmarker=Path("+repr(str(late))+")\ncount=marker.with_suffix('.count')\nif marker.exists() and len(sys.argv)>2 and sys.argv[1]=='inspect' and sys.argv[-1]=="+repr(name)+":\n n=int(count.read_text())+1 if count.exists() else 1\n count.write_text(str(n))\n if n==4:\n  subprocess.run([actual,'create','--name',"+repr(name)+","+repr(release['application_image'])+"],check=True,stdout=subprocess.DEVNULL)\n  marker.unlink();count.unlink()\nos.execv(actual,[actual]+sys.argv[1:])\n")
    docker_wrapper.chmod(0o700)
    launcher=['sh',str(package/'scripts/nct-install-range.sh'),address]
    def check(expected):
        value=subprocess.run(launcher+['check-fresh'],env=env,capture_output=True,text=True,timeout=90)
        assert (value.returncode==0)==expected,value.stdout[-1000:]+value.stderr[-1000:]
    persist.mkdir(); sentinel=persist/'do-not-adopt'; sentinel.write_bytes(b'preserve fixture marker')
    check(False); assert sentinel.read_bytes()==b'preserve fixture marker';sentinel.unlink()
    persist.rmdir(); linked=root/'linked-data';linked.mkdir();sentinel=linked/'do-not-adopt';sentinel.write_bytes(b'preserve linked data')
    persist.symlink_to(linked,target_is_directory=True);check(False);assert sentinel.read_bytes()==b'preserve linked data'
    persist.unlink();persist.mkdir()
    (root/'linked-parent').symlink_to(root,target_is_directory=True)
    prior_persist=env['NCT_PERSIST_ROOT'];env['NCT_PERSIST_ROOT']=str(root/'linked-parent'/'p')
    check(False);env['NCT_PERSIST_ROOT']=prior_persist
    engine.command('create','--name',name,release['application_image'])
    check(False); engine.command('rm',name)
    state.mkdir(); marker=state/'prior-state';marker.write_bytes(b'preserve recovery')
    check(False);assert marker.read_bytes()==b'preserve recovery';marker.unlink();state.rmdir()
    installed.mkdir();marker=installed/'nct_update_host.py';marker.write_bytes(b'preserve installed helper')
    check(False);assert marker.read_bytes()==b'preserve installed helper';marker.unlink();installed.rmdir()
    check(True); assert not any(persist.iterdir()) and not installed.exists()
    late.write_text('Inject a container during image loading')
    refused=subprocess.run(launcher+['fresh'],env=env,capture_output=True,text=True,timeout=180)
    assert refused.returncode and 'Fresh setup will not replace it' in refused.stderr, (
        refused.stdout[-2000:] + refused.stderr[-2000:]
    )
    assert not engine.inspect(name)['State']['Running'] and not any(persist.iterdir()) and not installed.exists()
    engine.command('rm',name)
    password=secrets.token_urlsafe(24)
    def interactive(command, interrupt_at_first_prompt=False):
        child,master=pty.fork()
        if child==0: os.execvpe('sh',command,env)
        CLEANUP['child']=child
        captured=bytearray();sent=0;deadline=time.monotonic()+600;status=None
        while time.monotonic()<deadline:
            if select.select([master],[],[],0.2)[0]:
                try: block=os.read(master,65536)
                except OSError: block=b''
                captured.extend(block)
            if interrupt_at_first_prompt and b'New password (' in captured:
                os.killpg(child,signal.SIGTERM)
                _,status=os.waitpid(child,0)
                break
            expected=b'New password (' if sent==0 else b'Confirm password:'
            if sent<2 and expected in captured and not termios.tcgetattr(master)[3]&termios.ECHO:
                os.write(master,password.encode()+b'\n');sent+=1
            ended,exit_status=os.waitpid(child,os.WNOHANG)
            if ended: status=exit_status;break
        os.close(master)
        if status is not None: CLEANUP.pop('child',None)
        return status,sent,bytes(captured).replace(password.encode(),b'[redacted]')

    interrupted_status,interrupted_sent,interrupted_log=interactive(launcher+['fresh'],True)
    (root/'fresh-interrupted.log').write_bytes(interrupted_log)
    assert interrupted_status is not None and os.waitstatus_to_exitcode(interrupted_status)!=0 and interrupted_sent==0,interrupted_log[-2500:]
    receipt_path=persist/'deployment/bootstrap/fresh-resume.json'
    assert receipt_path.is_file(),interrupted_log[-4000:]
    receipt=json.loads(receipt_path.read_text())
    assert receipt['phase']=='awaiting_password' and engine.inspect(name)['State']['Running'] is True
    status,sent,captured=interactive(launcher+['resume-fresh'])
    (root/'fresh-setup.log').write_bytes(interrupted_log+b'\n--- RESUME ---\n'+captured)
    assert status is not None and os.waitstatus_to_exitcode(status)==0 and sent==2,captured[-2500:]
    assert not (persist/'deployment/bootstrap/initial-password.txt').exists()
    receipt=json.loads((persist/'deployment/bootstrap/fresh-resume.json').read_text())
    assert receipt['phase']=='runtime_ready'
    assert not list(package.rglob('__pycache__'))
    assert verify_manifest(package)==tested
    config=json.loads((installed/'config.json').read_text());host=module.Host(config,engine)
    context=ssl.create_default_context(cafile=config['ca_file'])
    browser=urllib.request.build_opener(urllib.request.HTTPSHandler(context=context),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),urllib.request.ProxyHandler({}))
    def request(path,body=None,console_request=False):
        base=config['console_url'] if console_request else config['application_url']
        with browser.open(urllib.request.Request(base+path,data=None if body is None else json.dumps(body).encode(),headers={'Content-Type':'application/json','X-NCT-Recovery':'1'}),timeout=120) as r:return json.load(r)
    assert request('/health')['build_commit']==release['commit']
    request('/api/auth/login',{'username':'admin','password':password})
    for _ in range(60):
        operation=host.read()
        if operation['phase']=='complete':break
        time.sleep(1)
    assert operation['phase']=='complete',operation
    assert operation.get('verification_mode')=='fresh_normal_sign_in'
    assert all(operation.get(k) for k in ['backup_verified','evidence_verified','controller_sign_in_verified'])
    assert host.read()['release_restart_started'] is True
    assert not (persist/'data/recovery/update-maintenance.json').exists()
    empty=json.loads(engine.command('exec',name,'python','-c',"import sqlite3,json;d=sqlite3.connect('file:/data/analyzer.db?mode=ro',uri=True);print(json.dumps({'users':d.execute('select username,role,disabled from analyst_users').fetchall(),'counts':{t:d.execute('select count(*) from '+t).fetchone()[0] for t in ['scan_runs','imports','artifact_registry','artifact_observations','device_collection_authority']}}))"))
    assert empty['users']==[['admin','admin',0]] and not any(empty['counts'].values()),empty
    assert request('/api/evidence-library')['total']==0
    handoff=request('/api/updates/launch',{})
    request('/api/exchange',{'code':handoff['url'].split('#handoff=')[1]},True)
    assert request('/api/status',console_request=True)['operation']['phase']=='complete'
    assert engine.inspect(console)['Image']==json.loads(engine.command('image','inspect',release['console_image']))[0]['Id']
    assert engine.inspect(name)['Image']==json.loads(engine.command('image','inspect',release['application_image']))[0]['Id']
    request('/api/close',{},True);time.sleep(4);assert not engine.inspect(console)['State']['Running']
    engine.command('stop',name);engine.command('start',name)
    host.wait_url(config['application_url']+'/health/readiness',lambda x:x.get('healthy') is True)
    request('/api/auth/login',{'username':'admin','password':password})
    oldpid=int((root/'service.pid').read_text());os.kill(oldpid,signal.SIGTERM);time.sleep(1)
    log=(root/'service.log').open('ab')
    cleanenv={**env};cleanenv.pop('PYTHONPATH',None)
    service_process=subprocess.Popen([sys.executable,str(service),'--config',str(installed/'config.json')],env=cleanenv,stdout=log,stderr=log)
    (root/'service.pid').write_text(str(service_process.pid))
    time.sleep(1)
    code_output=subprocess.check_output([sys.executable,str(service),'--config',str(installed/'config.json'),'--access-code'],env=cleanenv,text=True)
    access=code_output.split('One-use recovery code (expires in 2 minutes): ')[1].strip()
    request('/api/exchange',{'code':access},True)
    assert request('/api/status',console_request=True)['operation']['id']==operation['id']
    request('/api/close',{},True);time.sleep(4);assert not engine.inspect(console)['State']['Running']
    xml=b'<nmaprun scanner="nmap"><host><status state="up"/><address addr="192.0.2.10" addrtype="ipv4"/></host></nmaprun>'
    body=b'--fresh\r\nContent-Disposition: form-data; name="file"; filename="fresh.xml"\r\nContent-Type: application/xml\r\n\r\n'+xml+b'\r\n--fresh--\r\n'
    with browser.open(urllib.request.Request(config['application_url']+'/api/import',data=body,headers={'Content-Type':'multipart/form-data; boundary=fresh'}),timeout=60) as r: imported=json.load(r)
    device=b'hostname fresh-router\ninterface GigabitEthernet0/1\n ip address 192.0.2.1 255.255.255.0\n'
    fields={'operator':'admin','originating_host':'isolated-fresh-host','vendor':'cisco','device_type':'router','device_address':'192.0.2.1','device_name':'Fresh router'}
    body=b''.join(b'--fresh\r\nContent-Disposition: form-data; name="'+k.encode()+b'"\r\n\r\n'+v.encode()+b'\r\n' for k,v in fields.items())
    body+=b'--fresh\r\nContent-Disposition: form-data; name="result_file"; filename="fresh-router.txt"\r\nContent-Type: text/plain\r\n\r\n'+device+b'\r\n--fresh--\r\n'
    with browser.open(urllib.request.Request(config['application_url']+'/api/device-configs/upload',data=body,headers={'Content-Type':'multipart/form-data; boundary=fresh'}),timeout=60) as r: uploaded=json.load(r)
    catalog=request('/api/evidence-library'); assert catalog['total']==2
    import_record=next(x for x in catalog['items'] if x['kind']=='import')
    assert browser.open(config['application_url']+import_record['download_url']).read()==xml
    device_record=next(x for x in catalog['items'] if x['kind']=='device');assert device_record['source_id']==uploaded['run_id']
    detail=request(device_record['detail_url']);link=next(x['url'] for x in detail['artifacts'] if x['name'].startswith('uploaded-'))
    assert browser.open(config['application_url']+link).read()==device
    assert not list((persist/'data').rglob('*library*.sqlite3'))
    assert all(m['Destination']!='/var/run/docker.sock' for m in engine.inspect(name)['Mounts'])
    assert all(m['Destination'] not in {'/data','/var/run/docker.sock'} for m in engine.inspect(console)['Mounts'])
    proof={'result':'pass','route':release['fresh_install'],'tested_manifest_sha256':tested,'commit':release['commit'],'images':release['images'],
        **{k:True for k in ['empty_storage_verified','fresh_admission_refusals','interrupted_password_resume','interactive_admin_setup','ca_verified','exact_application','exact_console','recovery_handoff','sign_in_final_restart','stop_start_persistence','helper_service_restart','console_stops_after_return','library_import_and_device_downloads']},
        'systemd_boot_tested':False,'substitutions':['systemctl runs exact installed helper process','ss fixture uses actual Docker port admission','administrative coordinator excluded from evidence peer checks'],
        'initial_empty_counts':empty['counts'],'range_accepted':False}
    (root/'fresh-acceptance.json').write_text(json.dumps(proof,indent=2))
    print('PASS: exact-package fresh shell install, interactive admin, empty data, CA HTTPS, recovery helper/console restart and original evidence downloads.',flush=True)
    service_process.terminate();service_process.wait(timeout=15)
    for item in engine.inventory():
        if any(x.lstrip('/').startswith(name) for x in item.get('Names',[])):
            engine.command('update','--restart=no',item['Id']);engine.command('stop',item['Id'])


if __name__=='__main__':
    try:
        main()
    finally:
        child=CLEANUP.get('child')
        if child:
            try: os.killpg(child,signal.SIGTERM);os.waitpid(child,0)
            except (ProcessLookupError,ChildProcessError):pass
        root=CLEANUP.get('root')
        if root and (root/'service.pid').exists():
            pid=int((root/'service.pid').read_text())
            try:
                if str(root/'service.py').encode() in Path(f'/proc/{pid}/cmdline').read_bytes():os.kill(pid,signal.SIGTERM)
            except (FileNotFoundError,ProcessLookupError):pass
        engine=CLEANUP.get('engine')
        if engine:
            for item in engine.inventory():
                if any(x.lstrip('/').startswith(CLEANUP['name']) for x in item.get('Names',[])):
                    engine.command('update','--restart=no',item['Id']);engine.command('stop',item['Id'])
