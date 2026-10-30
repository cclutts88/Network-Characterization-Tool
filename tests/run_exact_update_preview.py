"""Disposable exact-release GUI fixture. HTTP is loopback-only, never Range TLS.

The administrative runner substitutes for the host service. It excludes only
itself from peer checks; NCT and its pinned console never receive Docker access.
No real scan is launched. Receipts retain no account password or container env.
"""
from __future__ import annotations

import argparse
import hashlib
import http.cookiejar
import json
from pathlib import Path
import secrets
import shutil
import sqlite3
import ssl
import subprocess
import sys
import tarfile
import threading
import time
import urllib.request


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--application-image', required=True)
    parser.add_argument('--console-image', required=True)
    parser.add_argument('--application-port', type=int, default=18163)
    parser.add_argument('--console-port', type=int, default=18164)
    parser.add_argument('--https', action='store_true', help='CA-verified HTTPS API acceptance; browser leg uses loopback HTTP')
    parser.add_argument('--exercise-package', type=Path)
    parser.add_argument('--failure-package', type=Path)
    args = parser.parse_args()
    if args.exercise_package and not args.https:
        raise ValueError('Automated exact-package acceptance requires CA-verified HTTPS')
    root = args.root
    if root.name != '_data' or not root.parent.name.startswith('nct-update-acceptance-') or root.parent.parent != Path('/var/lib/docker/volumes'):
        raise ValueError('Use a new dedicated persistent acceptance volume')
    if any(root.iterdir()):
        raise ValueError('Refusing to overwrite an existing fixture')
    tools = root / 'tools'
    tools.mkdir()
    for name in ('nct_update_host.py', 'nct-range-data-check.py', 'nct_update_work.py'):
        shutil.copyfile(Path('/workspace/scripts') / name, tools / name)
    sys.path.insert(0, str(tools))
    import nct_update_host as module
    own_id = Path('/etc/hostname').read_text().strip()

    class FixtureDocker(module.Docker):
        def inventory(self):
            return [x for x in super().inventory() if not x['Id'].startswith(own_id)]

        def command(self, *values, **kwargs):
            result = super().command(*values, **kwargs)
            if values[:2] == ('ps', '-aq'):
                return '\n'.join(x for x in result.split() if not x.startswith(own_id))
            return result

    class LoopbackHandler(module.Handler):
        def handle_request(self):
            value = super().handle_request()
            if isinstance(value, dict):
                for key in ('url', 'application_url'):
                    if isinstance(value.get(key), str):
                        value[key] = value[key].replace('http://host.docker.internal:', 'http://127.0.0.1:')
            return value

    engine = FixtureDocker()
    app_id = json.loads(engine.command('image', 'inspect', args.application_image))[0]['Id']
    console_id = json.loads(engine.command('image', 'inspect', args.console_image))[0]['Id']
    name = 'nct-exact-update-' + secrets.token_hex(6)
    data, launch, control, spool = (root / p for p in ('data', 'launch', 'control', 'spool'))
    for path in (data, launch, control, spool):
        path.mkdir(mode=0o700)
    tls_options, app_command, console_tls = [], [], []
    scheme = 'https' if args.https else 'http'
    context = None
    if args.https:
        tls = root / 'tls'
        tls.mkdir()
        cert, key = tls / 'server.crt', tls / 'server.key'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2',
                        '-subj', '/CN=host.docker.internal', '-addext', 'subjectAltName=DNS:host.docker.internal,DNS:localhost,IP:127.0.0.1',
                        '-keyout', str(key), '-out', str(cert)], check=True, capture_output=True)
        context = ssl.create_default_context(cafile=str(cert))
        tls_options = ['-v', f'{tls}:/run/tls:ro']
        app_command = ['uvicorn', 'app.main:app', '--host', '0.0.0.0', '--port', '8080', '--ssl-certfile', '/run/tls/server.crt', '--ssl-keyfile', '/run/tls/server.key']
        console_tls = ['--ssl-certfile', '/run/tls/server.crt', '--ssl-keyfile', '/run/tls/server.key']
    config = {'state_dir': str(root / 'state'), 'data_dir': str(data), 'container': name,
              'console_container': name + '-console', 'console_image_id': console_id,
              'application_url': f'{scheme}://host.docker.internal:{args.application_port}',
              'console_url': f'{scheme}://host.docker.internal:{args.console_port}',
              'launch_socket': str(launch / 'launch.sock'), 'control_socket': str(control / 'control.sock'),
              'maintenance_lock': str(root / 'maintenance.lock')}
    if args.https:
        config['ca_file'] = str(cert)
    module.save(root / 'config.json', config)
    password = secrets.token_urlsafe(18)
    engine.command('run', '-d', '--name', name, '--restart', 'on-failure:3',
                   *(['--security-opt', 'seccomp=unconfined', '--cap-add', 'NET_RAW'] if args.https else []),
                   '--label', 'org.nct.acceptance=' + root.parent.name,
                   '-p', f'127.0.0.1:{args.application_port}:8080',
                   '-v', f'{data}:/data', '-v', f'{launch}:/run/nct-update:ro',
                   *tls_options, '-e', 'NCT_AUTH_MODE=local', '-e', 'NCT_COOKIE_SECURE=' + ('1' if args.https else '0'),
                   '-e', 'NCT_BOOTSTRAP_ADMIN=preview-operator', '-e', 'NCT_BOOTSTRAP_PASSWORD=' + password,
                   app_id, *app_command)
    host = module.Host(config, engine)
    for key, launch_only in (('launch_socket', True), ('control_socket', False)):
        server = module.Server(config[key], LoopbackHandler)
        server.host, server.launch_only = host, launch_only
        threading.Thread(target=server.serve_forever, daemon=True).start()
    engine.command('create', '--name', config['console_container'],
                   '--label', 'org.nct.acceptance=' + root.parent.name,
                   '-p', f'127.0.0.1:{args.console_port}:8446', '--read-only', '--cap-drop', 'ALL',
                   '--security-opt', 'no-new-privileges', '--tmpfs', '/tmp:rw,noexec,nosuid,size=16m',
                   '-v', f'{control}:/run/nct-recovery:ro', '-v', f'{spool}:/staging',
                   *tls_options, '-e', 'NCT_RECOVERY_INSECURE_TEST=' + ('0' if args.https else '1'), '-e', 'NCT_RECOVERY_SPOOL=/staging',
                   console_id, 'uvicorn', 'app.recovery_console:app', '--host', '0.0.0.0', '--port', '8446', *console_tls)
    host.wait_url(config['application_url'] + '/health/readiness', lambda x: x.get('healthy') is True)
    browser = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context), urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()), urllib.request.ProxyHandler({}))

    def request(path, body=None, *, console=False):
        with browser.open(urllib.request.Request(config['console_url' if console else 'application_url'] + path,
                          data=None if body is None else json.dumps(body).encode(),
                          headers={'Content-Type': 'application/json', 'X-NCT-Recovery': '1'}), timeout=60) as response:
            return json.load(response)

    request('/api/auth/login', {'username': 'preview-operator', 'password': password})
    xml = b'<?xml version="1.0"?><nmaprun scanner="nmap" start="1780000000"><scaninfo type="syn" protocol="tcp" numservices="1" services="443"/><host><status state="up"/><address addr="192.0.2.10" addrtype="ipv4"/><ports><port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port></ports></host><runstats><finished time="1780000001" exit="success"/><hosts up="1" down="0" total="1"/></runstats></nmaprun>'
    body = b'--fixture\r\nContent-Disposition: form-data; name="file"; filename="acceptance.xml"\r\nContent-Type: application/xml\r\n\r\n' + xml + b'\r\n--fixture--\r\n'
    with browser.open(urllib.request.Request(config['application_url'] + '/api/import', data=body,
                      headers={'Content-Type': 'multipart/form-data; boundary=fixture'}), timeout=60) as response:
        imported = json.load(response)
    host.stop_exact(engine.inspect(name))
    run_id = 'e7f6a1b2c3d44e5f8091029384756abc'
    folder = data / 'scan-runs' / run_id
    folder.mkdir(parents=True)
    (folder / 'scan.xml').write_bytes(xml)
    manifest = {'run_id': run_id, 'created_at': '2026-10-29T00:00:00Z', 'completed_at': '2026-10-29T00:01:00Z',
                'status': 'completed', 'operator': 'preview-operator', 'targets': ['192.0.2.0/24'],
                'reason': 'Offline synthetic acceptance', 'originating_host': 'fixture', 'interface': 'lo',
                'display_name': 'Exact release retained evidence', 'profile': 'Common ports', 'scheduled': False,
                'artifacts': [{'name': 'xml', 'filename': 'scan.xml', 'download_url': '/api/scan-runs/' + run_id + '/artifacts/xml'}]}
    (folder / 'manifest.json').write_text(json.dumps(manifest))
    seed = "from app.poc import insert_scan_run_manifest; import json; insert_scan_run_manifest(json.loads(" + repr(json.dumps(manifest)) + "))"
    host.run_helper(app_id, ['--mount', f'type=bind,src={data},dst=/data'], ['-c', seed])
    engine.command('update', '--restart=on-failure:3', name)
    engine.command('start', name)
    health = host.wait_url(config['application_url'] + '/health/readiness', lambda x: x.get('healthy') is True)
    original = engine.inspect(name)

    def runtime(item):
        return {'host': item['HostConfig'], 'mounts': sorted(item['Mounts'], key=lambda x: x['Destination']),
                'env': sorted(x for x in item['Config']['Env'] if not x.startswith(('NCT_BUILD_ID=', 'NCT_BUILD_COMMIT=', 'NCT_APP_VERSION='))),
                'cmd': item['Config']['Cmd'], 'entrypoint': item['Config']['Entrypoint']}

    def private_row_digest():
        with sqlite3.connect('file:' + str(data / 'analyzer.db') + '?mode=ro', uri=True) as db:
            rows = {table: sorted(db.execute('SELECT * FROM ' + table).fetchall())
                    for table in ('analyst_users', 'scan_runs', 'artifact_registry', 'artifact_observations')}
        return hashlib.sha256(module.canonical(rows)).hexdigest()

    def counts():
        with sqlite3.connect('file:' + str(data / 'analyzer.db') + '?mode=ro', uri=True) as db:
            return {table: db.execute('SELECT COUNT(*) FROM ' + table).fetchone()[0]
                    for table in ('analyst_users', 'scan_runs', 'artifact_registry', 'artifact_observations')}

    baseline = {str(p.relative_to(data)): module.digest_file(p) for p in data.rglob('*')
                if p.is_file() and (p.is_relative_to(folder) or 'artifacts' in p.parts)}
    initial_counts = counts()
    initial_rows = private_row_digest()
    original_runtime = module.canonical(runtime(original))
    helper_hash = module.digest_file(tools / 'nct_update_host.py')
    module.save(root / 'baseline.json', {'image_id': app_id, 'console_image_id': console_id, 'helper_sha256': helper_hash,
                'counts': initial_counts, 'row_digest': initial_rows, 'runtime_digest': hashlib.sha256(original_runtime).hexdigest(),
                'evidence_sha256': baseline, 'xml_sha256': hashlib.sha256(xml).hexdigest(),
                'import': imported, 'restart_policy': original['HostConfig']['RestartPolicy'], 'health': health})
    module.save(root / 'preview-access.json', {'username': 'preview-operator', 'password': password,
                'application_url': f'{scheme}://127.0.0.1:{args.application_port}',
                'console_url': f'{scheme}://127.0.0.1:{args.console_port}'})
    print('READY: exact-source GUI fixture, retained canonical import and completed synthetic scan; no network scan.', flush=True)
    recorded = set()

    def record():
        current = host.read()
        if current.get('phase') in {'complete', 'restored'} and (current.get('id'), current['phase']) not in recorded:
            result = {'operation': host.public(), 'counts': counts(), 'helper_unchanged': helper_hash == module.digest_file(tools / 'nct_update_host.py'),
                      'rows_unchanged': private_row_digest() == initial_rows,
                      'runtime_preserved': module.canonical(runtime(engine.inspect(name))) == original_runtime,
                      'verification_complete': all(current.get(k) for k in ('backup_verified', 'evidence_verified', 'controller_sign_in_verified', 'release_restart_started')),
                      'exact_runtime_image': engine.inspect(name)['Image'] == (app_id if current['phase'] == 'restored' else current['candidate_image_id']),
                      'console_unchanged': engine.inspect(config['console_container'])['Image'] == console_id,
                      'restart_policy_preserved': engine.inspect(name)['HostConfig']['RestartPolicy'] == original['HostConfig']['RestartPolicy'],
                      'evidence_unchanged': all((data / p).is_file() and module.digest_file(data / p) == digest for p, digest in baseline.items()),
                      'update_pause_absent': not (data / 'recovery/update-maintenance.json').exists()}
            result['pass'] = result['counts'] == initial_counts and all(result[k] for k in ('helper_unchanged', 'console_unchanged', 'restart_policy_preserved', 'evidence_unchanged', 'update_pause_absent', 'rows_unchanged', 'runtime_preserved', 'verification_complete', 'exact_runtime_image'))
            module.save(root / ('receipt-' + current['id'] + '-' + current['phase'] + '.json'), result)
            recorded.add((current.get('id'), current['phase']))
            print('GUI operation checked: ' + current['phase'] + ' pass=' + str(result['pass']), flush=True)
            assert result['pass'], result

    if args.exercise_package:
        handoff = request('/api/updates/launch', {})
        request('/api/exchange', {'code': handoff['url'].split('#handoff=')[1]}, console=True)

        def wait_phase(expected):
            for _ in range(180):
                if host.read()['phase'] == expected:
                    return
                time.sleep(1)
            raise AssertionError(host.public())

        def verify_xml():
            with browser.open(config['application_url'] + '/api/scan-runs/' + run_id + '/artifacts/xml', timeout=30) as response:
                assert 'application/xml' in response.headers['Content-Type']
                assert 'scan.xml' in response.headers['Content-Disposition']
                assert hashlib.sha256(response.read()).hexdigest() == hashlib.sha256(xml).hexdigest()

        def install(package, expected):
            with tarfile.open(package, 'r:gz') as archive:
                assert set(archive.getnames()) == {'release.json', 'image.tar'}
                release = json.load(archive.extractfile('release.json'))
            with package.open('rb') as stream:
                with browser.open(urllib.request.Request(config['console_url'] + '/api/upload', data=stream, method='POST',
                                  headers={'Content-Type': 'application/octet-stream', 'Content-Length': str(package.stat().st_size), 'X-NCT-Recovery': '1'}), timeout=180) as response:
                    plan = json.load(response)
            assert plan['phase'] == 'validated'
            request('/api/apply', {'plan_digest': plan['plan_digest']}, console=True)
            wait_phase(expected)
            operation = host.read()
            assert operation['package_sha256'] == module.digest_file(package)
            candidate = engine.inspect(operation['candidate_id'])
            candidate_env = dict(x.split('=', 1) for x in candidate['Config']['Env'] if '=' in x)
            assert candidate['Image'] == operation['candidate_image_id']
            assert candidate_env['NCT_BUILD_ID'] == release['build_id'] and candidate_env['NCT_BUILD_COMMIT'] == release['build_commit']
            assert candidate['State']['StartedAt'] and not candidate['State']['StartedAt'].startswith('0001-')
            if expected == 'awaiting_restore_sign_in':
                assert candidate['State']['ExitCode'] != 0
                assert operation['backup_verified'] and Path(operation['quarantine_path']).is_dir()
                assert engine.inspect(name)['Image'] == app_id
            request('/api/verify-sign-in', {'username': 'preview-operator', 'password': password}, console=True)
            verify_xml()
            record()
            return release

        release = install(args.exercise_package, 'awaiting_sign_in')
        running = request('/health')
        assert running['build_id'] == release['build_id'] and running['build_commit'] == release['build_commit']
        later = data / 'post-update-evidence.txt'
        later.write_bytes(b'Isolated evidence created after the verified update backup')
        later_sha = module.digest_file(later)
        request('/api/rollback', {'confirm': 'RESTORE'}, console=True)
        wait_phase('awaiting_restore_sign_in')
        request('/api/verify-sign-in', {'username': 'preview-operator', 'password': password}, console=True)
        assert not later.exists()
        assert module.digest_file(Path(host.read()['quarantine_path']) / later.name) == later_sha
        verify_xml()
        record()
        if args.failure_package:
            install(args.failure_package, 'awaiting_restore_sign_in')
        assert engine.inspect(name)['Image'] == app_id
        module.save(root / 'https-acceptance.json', {'pass': True, 'ca_verified': args.https, 'exact_console_image': console_id,
                    'helper_sha256': helper_hash, 'package_sha256': module.digest_file(args.exercise_package), 'controlled_failure': bool(args.failure_package),
                    'post_update_evidence_preserved_sha256': later_sha, 'legacy_security_runtime_exercised': args.https,
                    'authenticated_xml_download_after_update_and_restore': True, 'xml_sha256': hashlib.sha256(xml).hexdigest()})
        for item in engine.command('ps', '-aq', '--filter', 'label=org.nct.acceptance=' + root.parent.name).split():
            engine.command('update', '--restart=no', item)
            engine.command('stop', item)
        print('PASS: exact-package HTTPS update, existing-account verification, explicit restore and controlled failure.', flush=True)
        return

    while True:
        record()
        time.sleep(1)


if __name__ == '__main__':
    main()
