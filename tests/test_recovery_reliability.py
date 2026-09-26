from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path

import pytest

from app import device_analysis, device_configs, main, poc
from app.database import configure_database, connect_database
from app.host_identities import apply_analysis_host_identities, apply_topology_host_identities, select_host_identity


def collection(tmp_path, text=None):
    run_id = 'e' * 32
    root = tmp_path / 'device-configs'
    folder = root / run_id
    folder.mkdir(parents=True)
    (folder / 'manifest.json').write_text(json.dumps({
        'run_id': run_id, 'vendor': 'cisco', 'device_type': 'router',
        'device_address': '10.80.0.1', 'status': 'uploaded',
        'created_at': '2026-09-25T12:00:00Z', 'operation': 'manual_upload',
        'commands': ['show history', 'show running-config', 'show startup-config'],
    }))
    (folder / 'uploaded-config.txt').write_text(text or '''===== show running-config =====
interface Ethernet1
 ip address 10.80.0.1 255.255.255.0
ip route 10.90.0.0 255.255.255.0 10.80.0.2
end
===== show startup-config =====
interface Ethernet1
 ip address 10.80.0.1 255.255.255.0
ip route 10.99.0.0 255.255.255.0 10.80.0.3
end
===== show history =====
  1 show version
  2 configure terminal
''')
    return run_id, root, folder


def test_database_context_commits_rolls_back_and_closes(tmp_path):
    path = tmp_path/'test.db'
    configure_database(path)
    with connect_database(path) as db:
        assert db.execute('PRAGMA journal_mode').fetchone()[0] == 'wal'
        db.execute('CREATE TABLE sample (value TEXT)')
        db.execute("INSERT INTO sample VALUES ('kept')")
    with pytest.raises(sqlite3.ProgrammingError):
        db.execute('SELECT 1')
    with pytest.raises(RuntimeError):
        with connect_database(path) as db:
            db.execute("INSERT INTO sample VALUES ('rolled back')")
            raise RuntimeError('cancel')
    with connect_database(path) as db:
        assert db.execute('SELECT value FROM sample').fetchall() == [('kept',)]


def test_poc_reads_do_not_request_writes_while_another_writer_is_active(tmp_path):
    path = tmp_path/'test.db'
    poc.init_poc_storage(path)
    with connect_database(path) as writer:
        writer.execute('BEGIN IMMEDIATE')
        writer.execute("INSERT INTO app_settings VALUES ('held', '{}', 'now', 'test')")
        start = time.monotonic()
        assert poc._queued_run_ids(path) == []
        assert poc.list_scan_schedules(path) == []
        assert poc.get_scan_run_plan('a'*32, path) is None
        assert poc.list_scan_profiles(path)
        assert time.monotonic() - start < 2


def test_write_waits_for_short_lock_then_succeeds(tmp_path):
    path = tmp_path/'test.db'
    configure_database(path)
    with connect_database(path) as db:
        db.execute('CREATE TABLE sample (value INTEGER)')
    locked = threading.Event()
    def hold():
        with connect_database(path) as db:
            db.execute('BEGIN IMMEDIATE')
            locked.set()
            time.sleep(.15)
    thread = threading.Thread(target=hold)
    thread.start()
    assert locked.wait(2)
    with connect_database(path) as db:
        db.execute('INSERT INTO sample VALUES (1)')
    thread.join(2)
    with connect_database(path) as db:
        assert db.execute('SELECT value FROM sample').fetchone() == (1,)


def test_device_cache_reuses_and_invalidates_evidence_and_version(tmp_path, monkeypatch):
    run_id, root, folder = collection(tmp_path)
    db_path = tmp_path/'test.db'
    original = device_analysis.device_collection_summary
    calls = []
    def parse(*args, **kwargs):
        calls.append(1)
        return original(*args, **kwargs)
    monkeypatch.setattr(device_analysis, 'device_collection_summary', parse)
    first = device_analysis._cached_device_summary(run_id, root, db_path)
    second = device_analysis._cached_device_summary(run_id, root, db_path)
    assert first['routes'] == second['routes']
    assert len(calls) == 1
    assert 'configuration_text' not in second
    (folder/'command-history.txt').write_text('1 show version\n2 reload\n')
    third = device_analysis._cached_device_summary(run_id, root, db_path)
    assert third['command_history']['entries'][-1]['command'] == 'reload'
    assert len(calls) == 2
    monkeypatch.setattr(device_analysis, 'DEVICE_SUMMARY_VERSION', 2)
    device_analysis._cached_device_summary(run_id, root, db_path)
    assert len(calls) == 3
    device_analysis.delete_device_analysis_storage(run_id, db_path)
    with connect_database(db_path) as db:
        assert db.execute('SELECT COUNT(*) FROM device_analysis_cache').fetchone()[0] == 0
        assert db.execute('SELECT COUNT(*) FROM device_command_observations').fetchone()[0] == 0


def test_saved_config_and_history_never_become_active_routes(tmp_path):
    run_id, root, _ = collection(tmp_path)
    summary = device_configs.device_collection_summary(run_id, config_dir=root)
    assert '10.90.0.0/24' in {route['network'] for route in summary['routes']}
    assert '10.99.0.0/24' not in {route['network'] for route in summary['routes']}
    assert summary['volatile_configuration']['status'] == 'different'
    assert summary['command_history']['other_command_count'] == 1


def test_configuration_comparison_tracks_parent_interfaces():
    result = device_configs.assess_volatile_configuration('''===== show running-config =====
interface Ethernet1
 description users
interface Ethernet2
 description servers
end
===== show startup-config =====
interface Ethernet1
 description servers
interface Ethernet2
 description users
end
''', 'cisco')
    assert result['status'] == 'different'
    assert result['running_only_count'] == 2


@pytest.mark.parametrize('error', ['% Invalid input detected', '[NCT] Command unavailable', 'startup-config is not present'])
def test_failed_config_is_not_compared(error):
    result = device_configs.assess_volatile_configuration(
        '===== show running-config =====\nhostname router\nend\n'
        f'===== show startup-config =====\n{error}\n', 'cisco')
    assert result['status'] == 'unavailable'


def test_history_command_match_does_not_claim_attribution():
    result = device_configs.parse_command_history('1 show version\n2 configure terminal\n', True)
    assert result['entries'][0]['classification'] == 'nct_collection'
    assert 'unverified' in result['entries'][0]['label']
    assert result['entries'][1]['classification'] == 'other'
    assert device_configs.parse_command_history('% Invalid input detected', True)['status'] == 'unavailable'


def test_custom_collection_command_is_labeled_as_nct_activity():
    result = device_configs.parse_command_history(
        '1 show version\n2 show platform custom-status\n',
        True,
        nct_commands=['show platform custom-status'],
    )
    assert result['entries'][1]['classification'] == 'nct_collection'


def test_device_cache_preserves_command_history_line_numbers(tmp_path):
    run_id, root, folder = collection(tmp_path)
    (folder/'command-history.txt').write_text('10 show version\n11 configure terminal\n')
    db_path = tmp_path/'test.db'
    first = device_analysis._cached_device_summary(run_id, root, db_path)
    second = device_analysis._cached_device_summary(run_id, root, db_path)
    assert first['command_history']['entries'][1]['line_number'] == 2
    assert second['command_history']['entries'][1]['line_number'] == 2


def test_device_history_defers_artifact_lookup(tmp_path, monkeypatch):
    run_id, root, _ = collection(tmp_path)
    monkeypatch.setattr(device_configs, 'CONFIG_DIR', root)
    def forbidden(*args):
        pytest.fail('History must not enumerate evidence')
    original = device_configs.artifact_records
    monkeypatch.setattr(device_configs, 'artifact_records', forbidden)
    records = device_configs.history(limit=25)
    assert records[0]['run_id'] == run_id
    assert 'commands' not in records[0] and 'artifacts' not in records[0]
    monkeypatch.setattr(device_configs, 'artifact_records', original)
    detail = device_configs.collection_detail(run_id)
    assert detail['commands'] and detail['artifacts']


def test_selected_dns_names_visible_without_losing_scanner_evidence(tmp_path):
    path = tmp_path/'test.db'
    select_host_identity(path, ip='10.0.0.2', hostname='server.example', selection_source='dns', imported_by='analyst')
    analysis = {'hosts': [{'ip': '10.0.0.2', 'hostname': 'old-scanner-name'}]}
    apply_analysis_host_identities(analysis, path)
    assert analysis['hosts'][0]['hostname'] == 'server.example'
    assert analysis['hosts'][0]['observed_hostname'] == 'old-scanner-name'
    nodes = {'node': {'kind': 'host', 'ip': '10.0.0.2', 'hostname': 'old-scanner-name', 'label': 'old-scanner-name'}}
    apply_topology_host_identities(nodes, path)
    assert nodes['node']['label'] == 'server.example'


def test_cisco_key_collection_retains_history_first(tmp_path, monkeypatch):
    from starlette.requests import Request
    monkeypatch.setattr(device_configs, 'CONFIG_DIR', tmp_path/'device-configs')
    monkeypatch.setattr(device_configs, 'key_preflight', lambda _: {'status': 'ready'})
    monkeypatch.setattr(device_configs, 'start_accountability_capture', lambda *args: (None, None, None))
    monkeypatch.setattr(device_configs, 'stop_accountability_capture', lambda *args: None)
    monkeypatch.setattr(device_configs, 'capture_is_valid', lambda *args: True)
    def collect(prefix, commands, output):
        assert commands[0] == 'show history'
        output.write_text('===== show history =====\n1 show version\n===== show running-config =====\nhostname test-router\nend\n')
        return '', 0, [], None, False
    monkeypatch.setattr(device_configs, '_run_cisco_command_sequence_to_file', collect)
    plan = device_configs.DeviceConfigPlan(vendor='cisco', device_type='router', device_address='10.0.0.1', username='operator', key_path='/keys/test', operator='analyst', originating_host='test', accountability_interface='eth0')
    result = device_configs.execute(plan, Request({'type': 'http', 'headers': []}))
    assert result['status'] == 'completed'
    assert result['command_history_status'] == 'captured'
    assert (tmp_path/'device-configs'/result['run_id']/'command-history.txt').is_file()


def test_history_pagination_reaches_older_device_records(tmp_path, monkeypatch):
    root = tmp_path/'collections'
    for index in range(110):
        folder = root/f'{index:032x}'
        folder.mkdir(parents=True)
        (folder/'manifest.json').write_text(json.dumps({'run_id': folder.name, 'operation': 'manual_upload'}))
    monkeypatch.setattr(device_configs, 'CONFIG_DIR', root)
    pages = [device_configs.history(limit=25, offset=offset) for offset in range(0, 125, 25)]
    assert [len(page) for page in pages] == [25, 25, 25, 25, 10]
    assert len({row['run_id'] for page in pages for row in page}) == 110


def test_scan_history_does_not_parse_xml_and_pages_beyond_old_limit(tmp_path, monkeypatch):
    path = tmp_path/'test.db'
    poc.init_poc_storage(path)
    with connect_database(path) as db:
        for index in range(205):
            record = {'run_id': f'{index:032x}', 'created_at': str(index).zfill(5), 'status': 'completed', 'commands': ['large evidence'], 'artifacts': [{'name': 'xml'}]}
            db.execute('INSERT INTO scan_runs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
                       (record['run_id'], record['created_at'], 'completed', 'operator', '', 'test', 'eth0', 'profile', json.dumps(record)))
    def no_files(*args):
        pytest.fail('Metadata-only history must not load host-count evidence')
    monkeypatch.setattr(poc, 'with_host_count', no_files)
    result = poc.list_scan_run_plans(path, limit=25, offset=200, metadata_only=True)
    assert len(result) == 5
    assert all('commands' not in row and 'artifacts' not in row for row in result)


def test_sqlite_lock_error_returns_retryable_json(monkeypatch):
    from fastapi.testclient import TestClient
    monkeypatch.setattr(main, 'list_host_identities', lambda *_: (_ for _ in ()).throw(sqlite3.OperationalError('database is locked')))
    with TestClient(main.app) as client:
        response = client.get('/api/hostnames/identities')
    assert response.status_code == 503
    assert response.headers['retry-after'] == '2'
    assert 'retry' in response.json()['detail'].lower()


def test_configuration_rule_order_is_not_ignored():
    result = device_configs.assess_volatile_configuration('''===== show running-config =====
ip access-list extended CLIENTS
 permit ip any any
 deny ip host 10.0.0.2 any
end
===== show startup-config =====
ip access-list extended CLIENTS
 deny ip host 10.0.0.2 any
 permit ip any any
end
''', 'cisco')
    assert result['status'] == 'different'
    assert 'order' in result['detail']


def test_interactive_collection_preserves_history_even_when_config_fails(tmp_path, monkeypatch):
    from types import SimpleNamespace
    plan = device_configs.DeviceConfigPlan(vendor='cisco', device_type='router', device_address='10.0.0.1', username='operator', authentication_mode='password_prompt', operator='analyst', originating_host='test', accountability_interface='eth0')
    preview = device_configs.build_plan(plan)
    session = SimpleNamespace(plan=plan, preview=preview, run_dir=tmp_path)
    monkeypatch.setattr(device_configs, '_control_ssh_args', lambda *_: ['ssh','target'])
    monkeypatch.setattr(device_configs, '_finish_interactive_session', lambda _, **kwargs: kwargs)
    def collect(prefix, commands, output):
        assert commands[0] == 'show history'
        output.write_text('===== show history =====\n1 show version\n===== show running-config =====\n[NCT] no usable output\n')
        return '', 0, ['show running-config'], 'Running configuration unavailable', False
    monkeypatch.setattr(device_configs, '_run_cisco_command_sequence_to_file', collect)
    result = device_configs._run_interactive_collection(session)
    assert result['status'] == 'failed'
    assert result['extra']['command_history_status'] == 'captured'
    assert 'show version' in (tmp_path/'command-history.txt').read_text()
