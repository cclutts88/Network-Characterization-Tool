"""Isolated real Docker/TLS helper upgrade from the package-declared baseline.

systemd is represented by a controlled host process; no real host unit is changed.
Only this administrative fixture is excluded from peer-data mount checks.
"""
import argparse
import copy
import hashlib
import http.cookiejar
import importlib.util
import json
import os
from pathlib import Path
import secrets
import shutil
import ssl
import subprocess
import sys
import time
import urllib.request


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--root',type=Path,required=True)
    parser.add_argument('--package',type=Path,required=True)
    parser.add_argument('--baseline-tools',type=Path,required=True)
    parser.add_argument('--exercise-crash-after-create',action='store_true')
    args = parser.parse_args()
    root = args.root
    if root.name != '_data' or not root.parent.name.startswith('nct-helper-upgrade-') or root.parent.parent != Path('/var/lib/docker/volumes') or any(root.iterdir()):
        raise ValueError('Use a new dedicated disposable helper-upgrade volume')
    os.umask(0o077)
    sys.path.insert(0,str(args.package/'scripts'))
    import nct_update_host as host_module
    from build_nct_range_package import verify_manifest
    spec=importlib.util.spec_from_file_location('helper_upgrade',args.package/'scripts/nct-upgrade-recovery.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    manifest=verify_manifest(args.package)
    release=json.loads((args.package/'release.json').read_text())
    source=release['helper_upgrade_source']
    old_app='network-characterization-tool:'+source['build_id']
    old_console=source['console_image']
    own=Path('/etc/hostname').read_text().strip()
    class Engine(host_module.Docker):
        def inventory(self):
            return [v for v in super().inventory() if not v['Id'].startswith(own)]
    engine=Engine()
    old_console_id=json.loads(engine.command('image','inspect',old_console))[0]['Id']
    name='nct-helper-acceptance-'+secrets.token_hex(6)
    installed,state,data,tls=(root/v for v in ('installed','state','data','tls'))
    for path in (installed,state,data,tls,state/'sockets',state/'sockets/launch',state/'sockets/control',state/'spool',root/'deployment'):
        path.mkdir(mode=0o700,exist_ok=True)
    cert,key=tls/'server.crt',tls/'server.key'
    subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','2','-subj','/CN=host.docker.internal',
                    '-addext','subjectAltName=DNS:host.docker.internal,IP:127.0.0.1','-keyout',str(key),'-out',str(cert)],check=True,capture_output=True)
    config={'contract':'nct-update-v1','state_dir':str(state),'data_dir':str(data),'container':name,'console_container':name+'-console',
            'console_image_id':old_console_id,'application_url':'https://host.docker.internal:18171','console_url':'https://host.docker.internal:18172',
            'ca_file':str(cert),'launch_socket':str(state/'sockets/launch/launch.sock'),'control_socket':str(state/'sockets/control/control.sock'),
            'maintenance_lock':str(root/'deployment/maintenance.lock'),'allowed_operators':'all'}
    host_module.save(installed/'config.json',config)
    for file in module.FILES:
        payload=(args.baseline_tools/file).read_bytes()
        assert hashlib.sha256(payload).hexdigest() in module.BASELINES[(source['build_id'],source['build_commit'])]['files'][file]
        (installed/file).write_bytes(payload)
    password=secrets.token_urlsafe(24)
    service=None
    wrapper=root/'service.py'
    wrapper.write_text("import sys\nfrom pathlib import Path\nsys.path.insert(0,"+repr(str(installed))+")\nimport nct_update_host as h\nclass D(h.Docker):\n def inventory(self):\n  own=Path('/etc/hostname').read_text().strip()\n  return [v for v in super().inventory() if not v['Id'].startswith(own)]\nh.Docker=D\nh.main()\n")
    command=[sys.executable,str(wrapper),'--config',str(installed/'config.json')]
    log=(root/'service.log').open('wb')
    def service_command(verb):
        nonlocal service
        if verb=='stop':
            if service and service.poll() is None:
                service.terminate();service.wait(timeout=15)
        elif verb=='start':
            service=subprocess.Popen(command,stdout=log,stderr=log)
        elif verb=='is-active':
            assert service and service.poll() is None
        else:raise AssertionError(verb)
    engine.command('run','-d','--name',name,'--restart','unless-stopped','-p','127.0.0.1:18171:8080',
        '-v',str(data)+':/data','-v',str(state/'sockets/launch')+':/run/nct-update:ro',
        '-v',str(cert)+':/run/tls/server.crt:ro','-v',str(key)+':/run/tls/server.key:ro',
        '-e','NCT_AUTH_MODE=local','-e','NCT_COOKIE_SECURE=1','-e','NCT_BOOTSTRAP_ADMIN=fixture-operator','-e','NCT_BOOTSTRAP_PASSWORD='+password,
        old_app,'uvicorn','app.main:app','--host','0.0.0.0','--port','8080','--ssl-certfile','/run/tls/server.crt','--ssl-keyfile','/run/tls/server.key')
    console=engine.command('create','--name',config['console_container'],'--read-only','--cap-drop','ALL','--security-opt','no-new-privileges',
        '--tmpfs','/tmp:rw,noexec,nosuid,size=16m','-p','127.0.0.1:18172:8446',
        '-v',str(state/'sockets/control')+':/run/nct-recovery:ro','-v',str(state/'spool')+':/staging',
        '-v',str(cert)+':/run/tls/server.crt:ro','-v',str(key)+':/run/tls/server.key:ro',
        '-e','NCT_RECOVERY_SOCKET=/run/nct-recovery/control.sock','-e','NCT_RECOVERY_SPOOL=/staging',old_console,
        'uvicorn','app.recovery_console:app','--host','0.0.0.0','--port','8446','--ssl-certfile','/run/tls/server.crt','--ssl-keyfile','/run/tls/server.key').strip()
    probe=host_module.Host(config,engine)
    context=ssl.create_default_context(cafile=str(cert))
    browser=urllib.request.build_opener(urllib.request.HTTPSHandler(context=context),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),urllib.request.ProxyHandler({}))
    def request(path,body=None,console=False):
        with browser.open(urllib.request.Request(config['console_url' if console else 'application_url']+path,data=None if body is None else json.dumps(body).encode(),headers={'Content-Type':'application/json','X-NCT-Recovery':'1'}),timeout=180) as response:
            return json.load(response)
    try:
        probe.wait_url(config['application_url']+'/health/readiness',lambda v:v.get('healthy') is True)
        request('/api/auth/login',{'username':'fixture-operator','password':password})
        xml=b'<nmaprun scanner="nmap" start="100"><host><status state="up"/><address addr="192.0.2.10" addrtype="ipv4"/><ports><port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port></ports></host><runstats><finished time="101" exit="success"/></runstats></nmaprun>'
        body=b'--fixture\r\nContent-Disposition: form-data; name="file"; filename="retained.xml"\r\nContent-Type: application/xml\r\n\r\n'+xml+b'\r\n--fixture--\r\n'
        with browser.open(urllib.request.Request(config['application_url']+'/api/import',data=body,headers={'Content-Type':'multipart/form-data; boundary=fixture'}),timeout=30) as response:
            imported=json.load(response)
        host_module.save(state/'operation.json',{'phase':'complete','id':'retained-operation','controller_sign_in_verified':True})
        receipt=(state/'operation.json').read_bytes()
        before=module.fingerprint(engine.inspect(name))
        canonical_before={str(p.relative_to(data)):host_module.digest_file(p) for p in (data/'artifacts').rglob('*') if p.is_file()}
        assert canonical_before, 'The fixture must retain a real canonical XML artifact'
        def verify_xml():
            request('/api/auth/login',{'username':'fixture-operator','password':password})
            with browser.open(config['application_url']+'/api/imports/'+hashlib.sha256(xml).hexdigest()+'/raw',timeout=30) as response:
                assert response.read()==xml and 'xml' in response.headers['Content-Type']
        verify_xml()
        service_command('start')
        unit=root/'service.unit'
        unit.write_text('ExecStart='+ ' '.join(command)+'\n')
        upgrade=module.Upgrade(installed/'config.json',args.package/'scripts',release['console_image'],engine=engine,service=service_command,unit=unit)
        # The fixture owns a real helper process; only systemd's PID lookup is substituted.
        upgrade.check_service=lambda: service_command('is-active')
        engine.command('start',console)
        upgrade.ready(config)
        engine.command('stop',console)
        if args.exercise_crash_after_create:
            class InjectedPowerLoss(BaseException):pass
            create=engine.create
            def crash(name,runtime):
                result=create(name,runtime)
                engine.create=create
                raise InjectedPowerLoss()
            engine.create=crash
            try:
                upgrade.apply()
            except InjectedPowerLoss:
                assert 'new_console_id' not in json.loads(upgrade.journal_path.read_text())
            else:
                raise AssertionError('The injected interruption did not occur')
            upgrade.rollback()
            assert engine.inspect(config['console_container'])['Id']==console
            assert module.fingerprint(engine.inspect(name))==before
            assert (state/'operation.json').read_bytes()==receipt
            assert json.loads(upgrade.journal_path.read_text())['phase']=='rolled_back'
            # Preserve the finished private rehearsal journal before the fresh attempt.
            upgrade.journal_path.rename(root/'crash-after-create-rollback.json')
            print('PASS: immediate-after-create power loss recovered against real Docker defaults.',flush=True)
        upgrade.apply()
        assert module.fingerprint(engine.inspect(name))==before
        assert (state/'operation.json').read_bytes()==receipt
        assert all(host_module.digest_file(data/p)==v for p,v in canonical_before.items())
        assert engine.inspect(console)['State']['Running'] is False
        # Re-open through a real handoff, then install the new app via the updated console.
        config=json.loads((installed/'config.json').read_text())
        host=host_module.Host(config,engine)
        handoff=host.launch('fixture-operator')
        request('/api/exchange',{'code':handoff['url'].split('#handoff=')[1]},console=True)
        status=request('/api/status',console=True)
        assert 'runtime' in status and 'observed_at' in status
        package=next(args.package.glob('nct-update-*.tar.gz'))
        with package.open('rb') as stream:
            with browser.open(urllib.request.Request(config['console_url']+'/api/upload',data=stream,headers={'Content-Type':'application/octet-stream','Content-Length':str(package.stat().st_size),'X-NCT-Recovery':'1'}),timeout=180) as response:
                plan=json.load(response)
        request('/api/apply',{'plan_digest':plan['plan_digest']},console=True)
        for _ in range(180):
            if host.read()['phase']=='awaiting_sign_in':break
            if host.read()['phase'] in {'interrupted','failed','awaiting_restore_sign_in'}:raise AssertionError(host.public())
            time.sleep(1)
        else:raise AssertionError(host.public())
        request('/api/verify-sign-in',{'username':'fixture-operator','password':password},console=True)
        assert request('/health')['build_commit']==release['commit']
        verify_xml()
        assert all(host_module.digest_file(data/p)==v for p,v in canonical_before.items())
        later=data/'later-evidence.txt';later.write_bytes(b'preserve after helper upgrade')
        request('/api/rollback',{'confirm':'RESTORE'},console=True)
        for _ in range(180):
            phase=host.read()['phase']
            if phase=='awaiting_compatible_recovery':
                request('/api/resume-compatible',{'confirm':'START COMPATIBLE RECOVERY'},console=True)
            elif phase=='awaiting_restore_sign_in':break
            elif phase in {'interrupted','failed'}:raise AssertionError(host.public())
            time.sleep(1)
        else:raise AssertionError(host.public())
        request('/api/verify-sign-in',{'username':'fixture-operator','password':password},console=True)
        assert request('/health')['build_commit']==release['commit']
        verify_xml()
        assert (Path(host.read()['quarantine_path'])/'later-evidence.txt').read_bytes()==b'preserve after helper upgrade'
        result={'result':'pass','tested_manifest_sha256':manifest,'commit':release['commit'],'images':release['images'],
                'source_build':source['build_id'],'source_commit':source['build_commit'],'old_console':source['console_image_id'],
                'old_helper_sha256':source['host_sha256'],'ca_verified':True,
                'systemd_substitution':'controlled exact helper process','app_unchanged_by_helper_upgrade':True,
                'existing_receipt_preserved':True,'existing_account_preserved':True,'app_update_and_backup_restore':True,'later_evidence_preserved':True}
        result['crash_after_create_recovered']=args.exercise_crash_after_create
        host_module.save(root/'acceptance.json',result)
        print('PASS: package-declared helper/console upgrade, real TLS/account/evidence checks, GUI app update and backup restore.',flush=True)
    finally:
        service_command('stop')
        # Stop only this fixture's app and retained originals identified by its prefix.
        for item in engine.inventory():
            if any(n.lstrip('/').startswith(name) for n in item.get('Names',[])):
                engine.command('update','--restart=no',item['Id']);engine.command('stop',item['Id'])


if __name__=='__main__':main()
