import copy
import json

import pytest

from test_update_recovery_console import planned_host, host_module


def test_activity_throttles_durable_checkpoints_and_preserves_phase_events(tmp_path, monkeypatch):
    host, _ = planned_host(tmp_path)
    state = host.read()
    events = (host.root / (state['id'] + '.events.jsonl')).read_bytes()
    clock = [100.0]
    monkeypatch.setattr(host_module.time, 'time', lambda: clock[0])
    host.activity(state, 'copy', 'Copying', completed=0, total=100, unit='bytes')
    initial = host.current.read_bytes()
    clock[0] = 101
    for n in range(1, 100):
        host.activity(state, 'copy', 'Copying', completed=n, total=100, unit='bytes')
    assert host.current.read_bytes() == initial
    clock[0] = 102
    host.activity(state, 'copy', 'Copying', completed=99, total=100, unit='bytes')
    saved = host.read()
    assert saved['phase'] == 'validated' and saved['plan_digest'] == 'd' * 64
    assert saved['activity']['started_at'] == 100
    assert saved['activity']['updated_at'] == 102
    assert saved['activity']['completed'] == 99
    host.activity(state, 'copy', 'Copying', completed=100, total=100, unit='bytes', force=True)
    assert host.read()['activity']['completed'] == 100
    assert (host.root / (state['id'] + '.events.jsonl')).read_bytes() == events


def test_old_activity_cannot_overwrite_a_newer_phase_or_operation(tmp_path):
    host, _ = planned_host(tmp_path)
    stale = host.read()
    host.phase(host.read(), 'interrupted')
    before = host.current.read_bytes()
    with pytest.raises(ValueError, match='no longer belongs'):
        host.activity(stale, 'copy', 'Copying', force=True)
    assert host.current.read_bytes() == before


def test_interruption_keeps_last_measurement_but_ends_working_indicator(tmp_path):
    host, _ = planned_host(tmp_path)
    state = host.read()
    host.activity(state, 'copy', 'Copying', completed=10, total=20, unit='files')
    host.phase(state, 'interrupted')
    reloaded = host_module.Host(host.config, host.engine)
    assert reloaded.public()['activity']['completed'] == 10
    assert reloaded.public()['activity']['active'] is False


def test_backup_progress_measures_real_bytes_and_verifies_exact_contents(tmp_path):
    host, _ = planned_host(tmp_path)
    (host.data / 'large.bin').write_bytes(b'abc' * 1024**2)
    before = {p.name:p.read_bytes() for p in host.data.iterdir() if p.is_file()}
    checkpoints = []
    original = host.activity
    def record(state, step, label, **kwargs):
        result = original(state, step, label, **kwargs)
        if kwargs.get('force'):
            checkpoints.append(copy.deepcopy(state['activity']))
        return result
    host.activity = record
    host.apply('d' * 64, 'fixture')
    state = host.read()
    assert state['backup_verified'] and state['evidence_verified']
    assert state['phase'] == 'awaiting_sign_in'
    measured = [x for x in checkpoints if x['step'] in {'backup_create','backup_extract','backup_hash'} and x.get('completed') == x.get('total')]
    assert {x['step'] for x in measured} == {'backup_create','backup_extract','backup_hash'}
    assert next(x for x in measured if x['step']=='backup_create')['total'] == sum(map(len,before.values()))
    assert (host.data/'large.bin').read_bytes() == before['large.bin']
    assert state['activity']['active'] is False


@pytest.mark.parametrize('marker,expected', [(False,'original_reconciliation'),(None,'original_restart_unknown_history')])
def test_recovery_reports_original_restart_without_claiming_backup_swap(tmp_path, marker, expected):
    host, _ = planned_host(tmp_path)
    state = host.read()
    if marker is not None:
        state['candidate_may_have_written'] = marker
    host.phase(state, 'interrupted')
    host.rollback('fixture')
    state = host.read()
    assert state['completion_kind'] == expected
    assert state['recovery_outcome'] == {'backup_swapped':False,'later_evidence_preserved':False}
    assert 'without a backup data swap' in state['detail']
    assert not state.get('backup_verified')


def test_actual_restore_reports_swap_and_preserved_later_evidence(tmp_path):
    host, _ = planned_host(tmp_path)
    host.fail_candidate = True
    host.apply('d'*64,'fixture')
    state = host.read()
    assert state['completion_kind'] == 'backup_restore'
    assert state['recovery_outcome'] == {'backup_swapped':True,'later_evidence_preserved':True}
    assert state['quarantine_path']


def test_status_projection_is_read_only_and_does_not_expose_runtime_configuration(tmp_path):
    host, engine = planned_host(tmp_path)
    before = host.current.read_bytes()
    value = host.public()
    assert value['recovery_guidance'] == 'unknown'
    assert 'original' not in value and 'manifest' not in value
    runtime = host.runtime_status()
    assert runtime['available'] and runtime['running'] is True
    assert set(runtime) == {'available','observed_at','running','status'}
    assert host.current.read_bytes() == before
    engine.items['old']['Id'] = 'unrelated'
    assert host.runtime_status()['available'] is False
    engine.items.clear()
    assert host.runtime_status()['available'] is False


def test_progress_failure_never_bypasses_apply_fencing(tmp_path, monkeypatch):
    host, engine = planned_host(tmp_path)
    def fail(*a, **k):
        raise OSError('fixture display checkpoint failed')
    monkeypatch.setattr(host, 'activity', fail)
    with pytest.raises(OSError):
        host.apply('d'*64,'fixture')
    assert engine.inspect('old')['State']['Running']
    assert not engine.exists('new')


def test_final_restart_keeps_active_progress_until_readiness_finishes(tmp_path, monkeypatch):
    host, _ = planned_host(tmp_path)
    host.apply('d'*64, 'fixture')
    state = host.read()
    host.phase(state, 'release_intent', verified_runtime_id='new',
               verified_result_phase='complete', controller_sign_in_verified=True)
    observed = []
    def readiness(*args, **kwargs):
        saved = host.public()
        observed.append(saved)
        assert saved['activity']['active'] is True
        assert saved['activity']['step'] == 'final_restart'
        assert saved['phase'] == 'release_intent'
    monkeypatch.setattr(host, 'verify_health', readiness)
    host.finalize(state)
    assert observed
    assert host.read()['phase'] == 'complete'
    assert host.read()['activity']['active'] is False
