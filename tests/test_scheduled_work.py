from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sqlite3
import subprocess
import sys

import pytest

pytestmark = pytest.mark.usefixtures("bypass_collection_safety_gate")

from app import poc
from app.database import connect_database

from app.poc import (
    ScanScheduleCreate,
    create_scan_schedule,
    prepare_schedule_occurrence,
    schedule_target_chunks,
)
from app.scheduled_work import (
    abandon_chunk_after_worker_error,
    bind_chunk_scan_run,
    claim_next_chunk,
    close_reviewed_occurrence,
    get_occurrence,
    prepare_occurrence,
    publish_chunk_terminal,
    mark_chunk_contact_starting,
    recover_schedule_occurrences,
)
from app.work_coordination import WorkLeaseLost, WorkRecoveryRequired


def make_schedule(db_path: Path, *, first_run: datetime | None = None) -> dict:
    return create_scan_schedule(
        ScanScheduleCreate(
            name="Durable schedule",
            created_by="analyst.one",
            profile_id="builtin-standard",
            profile_version=1,
            targets=["198.51.100.0/29"],
            interface="eth0",
            cadence="daily",
            first_run_at=first_run or datetime(2026, 1, 1, tzinfo=timezone.utc),
            chunking_enabled=True,
            chunk_size=3,
            enabled=True,
        ),
        db_path,
    )


def frozen() -> dict:
    return {
        "resolved_targets": ["198.51.100.0/29"],
        "network_scope_context": None,
        "profile": {"profile_id": "builtin-standard", "profile_version": 1},
        "schedule_no_strike": [],
        "global_no_strike": {"revision": 0, "entries": []},
        "contact_policy": {"interface": "eth0"},
        "authorization": {"executed_by": "scheduler"},
    }


@pytest.mark.parametrize("state", ["waiting", "preparing", "active", "needs_attention", "complete", "cancelled"])
def test_legacy_migration_preserves_existing_durable_occurrences(tmp_path, state):
    from app.scheduled_work import migrate_legacy_schedules

    db_path = tmp_path / "analyzer.db"
    schedule = make_schedule(db_path)
    prepared = prepare_occurrence(
        db_path, schedule=schedule, due_at="2026-01-01T00:00:00+00:00",
        trigger_kind="scheduled", trigger_key="cadence", actor="scheduler",
        frozen_contract=frozen(), chunks=[["198.51.100.1"]], next_due_at=None,
    )
    # Native execution uses the same mutable batch fields as the old scheduler.
    # Even stale fields after completion must not reinterpret durable history.
    with connect_database(db_path) as connection:
        connection.execute(
            "UPDATE scan_schedule_occurrences SET state = ? WHERE occurrence_id = ?",
            (state, prepared.occurrence_id),
        )
        schedule.update(active_batch_id=prepared.occurrence_id,
                        batch_status="running", active_target_chunks=[["198.51.100.1"]])
        connection.execute("UPDATE scan_schedules SET definition_json = ? WHERE schedule_id = ?",
                           (json.dumps(schedule), schedule["schedule_id"]))

    def snapshot():
        with connect_database(db_path) as connection:
            return {table: connection.execute(f"SELECT * FROM {table}").fetchall()
                    for table in ("scan_schedules", "scan_schedule_definitions",
                                  "scan_schedule_occurrences", "scan_schedule_chunks")}

    before = snapshot()
    for _ in range(2):
        assert migrate_legacy_schedules(db_path) == []
        # Exercise the same storage initialization called by application startup,
        # without the previous process's readiness shortcut.
        poc._POC_STORAGE_READY.clear()
        poc.init_poc_storage(db_path)
        assert snapshot() == before
        with connect_database(db_path) as connection:
            assert connection.execute("PRAGMA foreign_key_check").fetchall() == []


def test_legacy_active_migration_is_idempotent_alongside_native_work(tmp_path):
    from app.scheduled_work import migrate_legacy_schedules

    db_path = tmp_path / "analyzer.db"
    native = make_schedule(db_path)
    prepared = prepare_occurrence(
        db_path, schedule=native, due_at="2026-01-01T00:00:00+00:00",
        trigger_kind="scheduled", trigger_key="cadence", actor="scheduler",
        frozen_contract=frozen(), chunks=[["198.51.100.1"]], next_due_at=None,
    )
    before = get_occurrence(db_path, prepared.occurrence_id)
    legacy = make_schedule(db_path)
    legacy.pop("definition_version", None)
    legacy.pop("definition_digest", None)
    legacy.update(active_batch_id="old-batch", batch_status="running",
                  active_target_chunks=[["198.51.100.2"], ["198.51.100.3"], ["198.51.100.4"]],
                  completed_chunk_count=1, active_chunk_number=2)
    with connect_database(db_path) as connection:
        connection.execute("UPDATE scan_schedules SET definition_json = ? WHERE schedule_id = ?",
                           (json.dumps(legacy), legacy["schedule_id"]))
    assert migrate_legacy_schedules(db_path) == [legacy["schedule_id"]]
    migrated = poc.get_scan_schedule(legacy["schedule_id"], db_path)
    occurrence = get_occurrence(db_path, migrated["active_batch_id"])
    assert migrated["enabled"] is False
    assert occurrence["state"] == "needs_attention"
    assert [c["state"] for c in occurrence["chunks"]] == ["complete", "needs_attention", "waiting"]
    assert [c["contact_phase"] for c in occurrence["chunks"]] == ["complete", "uncertain", "not_started"]
    assert migrate_legacy_schedules(db_path) == []
    assert get_occurrence(db_path, migrated["active_batch_id"]) == occurrence
    assert get_occurrence(db_path, prepared.occurrence_id) == before
    with connect_database(db_path) as connection:
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []


@pytest.mark.parametrize("prepared", [True, False])
@pytest.mark.parametrize("failure", [poc.MissionEnvironmentConflict, poc.SavedNetworkScopeConflict, RuntimeError])
def test_scheduler_does_not_starve_valid_schedule_behind_blocked_one(tmp_path, monkeypatch, prepared, failure):
    db_path = tmp_path / "analyzer.db"
    schedules = [make_schedule(db_path) for _ in range(3)]
    if prepared:
        for schedule in schedules:
            prepare_schedule_occurrence(
                schedule["schedule_id"], advance_schedule=True, trigger_key="cadence",
                actor="scheduler", now=datetime(2026, 1, 1, tzinfo=timezone.utc), db_path=db_path,
            )
        ordered = sorted(poc.list_scan_schedules(db_path), key=lambda s: (
            s["latest_occurrence"]["created_at"], s["schedule_id"]))
    else:
        ordered = sorted(poc.list_scan_schedules(db_path), key=lambda s: s["next_run_at"])
    blocked_id = ordered[0]["schedule_id"]
    calls = []

    def dispatch(schedule_id, *args, **kwargs):
        calls.append(schedule_id)
        if schedule_id == blocked_id:
            raise failure("This schedule needs review")
        return True if prepared else {"schedule_id": schedule_id}

    monkeypatch.setattr(poc, "_start_prepared_schedule_occurrence" if prepared else "queue_scan_schedule_batch", dispatch)
    result = poc.dispatch_due_schedules(datetime(2026, 1, 1, tzinfo=timezone.utc), db_path)
    assert calls == [blocked_id, ordered[1]["schedule_id"]]
    assert len(result) == 1 and result[0]["schedule_id"] == ordered[1]["schedule_id"]
    if prepared:
        unchanged = get_occurrence(db_path, ordered[0]["latest_occurrence"]["occurrence_id"])
        assert unchanged["state"] == "waiting"
        assert all(c["contact_phase"] == "not_started" for c in unchanged["chunks"])


def test_scheduler_all_waiting_blocked_starts_nothing(tmp_path, monkeypatch):
    db_path = tmp_path / "analyzer.db"
    schedules = [make_schedule(db_path) for _ in range(2)]
    for schedule in schedules:
        prepare_schedule_occurrence(
            schedule["schedule_id"], advance_schedule=True, trigger_key="cadence",
            actor="scheduler", now=datetime(2026, 1, 1, tzinfo=timezone.utc), db_path=db_path,
        )
    calls = []

    def blocked(schedule_id, *args, **kwargs):
        calls.append(schedule_id)
        raise poc.MissionEnvironmentConflict("Scope prohibited")

    monkeypatch.setattr(poc, "_start_prepared_schedule_occurrence", blocked)
    assert poc.dispatch_due_schedules(datetime(2026, 1, 1, tzinfo=timezone.utc), db_path) == []
    assert set(calls) == {s["schedule_id"] for s in schedules}
    assert all(not poc.get_scan_schedule(s["schedule_id"], db_path)["enabled"] for s in schedules)
    # Even if the condition later changes, disabled blocked occurrences need an
    # explicit operator action rather than automatic contact on the next tick.
    monkeypatch.setattr(poc, "_start_prepared_schedule_occurrence",
                        lambda *args, **kwargs: pytest.fail("Blocked work restarted"))
    before = [poc.get_scan_schedule(s["schedule_id"], db_path) for s in schedules]
    assert poc.dispatch_due_schedules(datetime(2026, 1, 1, tzinfo=timezone.utc), db_path) == []
    assert [poc.get_scan_schedule(s["schedule_id"], db_path) for s in schedules] == before


def bound_queued_run(db_path: Path) -> tuple[dict, dict, object]:
    schedule = make_schedule(db_path)
    occurrence = prepare_occurrence(
        db_path,
        schedule=schedule,
        due_at="2026-01-01T00:00:00+00:00",
        trigger_kind="scheduled",
        trigger_key="cadence",
        actor="scheduler",
        frozen_contract=frozen(),
        chunks=[["198.51.100.1"]],
        next_due_at="2026-01-02T00:00:00+00:00",
    )
    claimed = claim_next_chunk(
        db_path, occurrence.occurrence_id,
        owner_id="scan-run:reserved", lease_seconds=30,
    )
    assert claimed is not None
    chunk, lease = claimed
    request = poc._scheduled_request(
        schedule,
        chunk["targets"],
        batch_id=occurrence.occurrence_id,
        chunk_number=1,
        chunk_count=1,
        batch_hosts_total=1,
        batch_hosts_completed_before=0,
        db_path=db_path,
    )
    manifest = poc.prepare_scan_run(
        request,
        db_path,
        {"eth0"},
        reserved_run_id="c" * 32,
        scheduled_chunk_claim=(occurrence.occurrence_id, 1, lease),
    )
    return manifest, get_occurrence(db_path, occurrence.occurrence_id), lease


class CompletedFakeProcess:
    def __init__(self, *, running: bool = False):
        self.running = running
        self.terminated = False

    def poll(self):
        if self.terminated:
            return 0
        return None if self.running else 0

    def terminate(self):
        self.terminated = True

    def kill(self):
        self.terminated = True

    def wait(self, timeout=None):
        self.terminated = True
        return 0


def test_multi_year_downtime_creates_one_bounded_catchup(tmp_path: Path) -> None:
    db_path = tmp_path / "analyzer.db"
    first = datetime(2020, 1, 1, tzinfo=timezone.utc)
    schedule = make_schedule(db_path, first_run=first)

    saved = prepare_schedule_occurrence(
        schedule["schedule_id"],
        advance_schedule=True,
        trigger_key="cadence",
        actor="scheduler",
        now=datetime(2030, 1, 1, 12, tzinfo=timezone.utc),
        db_path=db_path,
    )
    occurrence = get_occurrence(db_path, saved["occurrence_id"])

    assert occurrence is not None
    assert occurrence["due_at"] == "2030-01-01T00:00:00+00:00"
    assert occurrence["skipped_due_count"] == 3653
    assert len(occurrence["chunks"]) == 3
    with connect_database(db_path) as connection:
        count = connection.execute(
            "SELECT COUNT(*) FROM scan_schedule_occurrences"
        ).fetchone()[0]
    assert count == 1


def test_two_processes_converge_on_one_occurrence(tmp_path: Path) -> None:
    db_path = tmp_path / "analyzer.db"
    schedule = make_schedule(db_path)
    chunks = schedule_target_chunks(schedule, db_path)
    payload = json.dumps({"schedule": schedule, "chunks": chunks})
    code = r"""
import json, sys
from pathlib import Path
from app.scheduled_work import prepare_occurrence
p=json.loads(sys.argv[2])
r=prepare_occurrence(Path(sys.argv[1]),schedule=p['schedule'],due_at='2026-01-01T00:00:00+00:00',trigger_kind='scheduled',trigger_key='cadence',actor='scheduler',frozen_contract={'test':True},chunks=p['chunks'],next_due_at='2026-01-02T00:00:00+00:00')
print(r.occurrence_id, r.created)
"""
    processes = [
        subprocess.Popen(
            [sys.executable, "-c", code, str(db_path), payload],
            cwd=Path(__file__).parents[1],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for _ in range(2)
    ]
    results = [process.communicate(timeout=20) for process in processes]

    assert all(process.returncode == 0 for process in processes), results
    ids = [stdout.split()[0] for stdout, _stderr in results]
    assert len(set(ids)) == 1
    with sqlite3.connect(db_path) as connection:
        occurrence_count = connection.execute(
            "SELECT COUNT(*) FROM scan_schedule_occurrences"
        ).fetchone()[0]
        chunk_count = connection.execute(
            "SELECT COUNT(*) FROM scan_schedule_chunks"
        ).fetchone()[0]
    assert occurrence_count == 1
    assert chunk_count == 3


def test_occurrence_creation_rechecks_global_no_strike_revision(tmp_path: Path) -> None:
    db_path = tmp_path / "analyzer.db"
    schedule = make_schedule(db_path)
    with connect_database(db_path) as connection:
        connection.execute(
            """INSERT INTO global_no_strike_history(
                   revision, entries_json, action, changed_at, changed_by
               ) VALUES (1, '[\"203.0.113.0/24\"]', 'add',
                         '2026-01-01T00:00:00+00:00', 'analyst.two')"""
        )

    with pytest.raises(RuntimeError, match="Global No-Strike list changed"):
        prepare_occurrence(
            db_path,
            schedule=schedule,
            due_at="2026-01-01T00:00:00+00:00",
            trigger_kind="scheduled",
            trigger_key="cadence",
            actor="scheduler",
            frozen_contract=frozen(),
            chunks=[["198.51.100.1"]],
            next_due_at="2026-01-02T00:00:00+00:00",
        )


def test_stale_chunk_owner_cannot_publish_after_reclaim(tmp_path: Path) -> None:
    db_path = tmp_path / "analyzer.db"
    schedule = make_schedule(db_path)
    occurrence = prepare_occurrence(
        db_path,
        schedule=schedule,
        due_at="2026-01-01T00:00:00+00:00",
        trigger_kind="scheduled",
        trigger_key="cadence",
        actor="scheduler",
        frozen_contract=frozen(),
        chunks=[["198.51.100.1"]],
        next_due_at="2026-01-02T00:00:00+00:00",
    )
    first = claim_next_chunk(
        db_path, occurrence.occurrence_id, owner_id="worker-one", lease_seconds=5
    )
    assert first is not None
    _chunk, stale = first
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            "UPDATE work_leases SET expires_at = '2000-01-01T00:00:00.000Z'"
        )
    second = claim_next_chunk(
        db_path, occurrence.occurrence_id, owner_id="worker-two", lease_seconds=5
    )
    assert second is not None
    _chunk, current = second

    with pytest.raises(WorkLeaseLost):
        publish_chunk_terminal(
            db_path,
            occurrence_id=occurrence.occurrence_id,
            chunk_number=1,
            terminal_state="complete",
            reason="stale publication",
            lease=stale,
        )
    published = publish_chunk_terminal(
        db_path,
        occurrence_id=occurrence.occurrence_id,
        chunk_number=1,
        terminal_state="complete",
        reason="current publication",
        lease=current,
    )
    assert published["state"] == "complete"


def test_worker_failure_before_binding_releases_chunk_for_safe_retry(tmp_path: Path) -> None:
    db_path = tmp_path / "analyzer.db"
    schedule = make_schedule(db_path)
    occurrence = prepare_occurrence(
        db_path,
        schedule=schedule,
        due_at="2026-01-01T00:00:00+00:00",
        trigger_kind="scheduled",
        trigger_key="cadence",
        actor="scheduler",
        frozen_contract=frozen(),
        chunks=[["198.51.100.1"]],
        next_due_at="2026-01-02T00:00:00+00:00",
    )
    claimed = claim_next_chunk(
        db_path, occurrence.occurrence_id, owner_id="worker-one", lease_seconds=30
    )
    assert claimed is not None
    _chunk, lease = claimed

    state = abandon_chunk_after_worker_error(
        db_path,
        occurrence_id=occurrence.occurrence_id,
        chunk_number=1,
        lease=lease,
        reason="Injected failure before a scan run was bound",
    )

    assert state == "waiting"
    retained = get_occurrence(db_path, occurrence.occurrence_id)
    assert retained is not None
    assert retained["state"] == "waiting"
    assert retained["chunks"][0]["state"] == "waiting"
    assert retained["chunks"][0]["contact_phase"] == "not_started"
    replacement = claim_next_chunk(
        db_path, occurrence.occurrence_id, owner_id="worker-two", lease_seconds=30
    )
    assert replacement is not None


def test_worker_failure_after_binding_but_before_contact_reuses_same_run(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "analyzer.db"
    manifest, occurrence, lease = bound_queued_run(db_path)

    state = abandon_chunk_after_worker_error(
        db_path,
        occurrence_id=occurrence["occurrence_id"],
        chunk_number=1,
        lease=lease,
        reason="Injected failure after binding but before contact",
    )

    assert state == "waiting"
    replacement = claim_next_chunk(
        db_path,
        occurrence["occurrence_id"],
        owner_id="worker-two",
        lease_seconds=30,
    )
    assert replacement is not None
    rebound_chunk, _replacement_lease = replacement
    assert rebound_chunk["scan_run_id"] == manifest["run_id"]
    rebound = poc.get_scan_run_plan(manifest["run_id"], db_path)
    assert rebound is not None and rebound["status"] == "queued"


def test_worker_failure_after_contact_requires_review(tmp_path: Path) -> None:
    db_path = tmp_path / "analyzer.db"
    _manifest, occurrence, lease = bound_queued_run(db_path)
    mark_chunk_contact_starting(
        db_path,
        occurrence_id=occurrence["occurrence_id"],
        chunk_number=1,
        lease=lease,
    )

    state = abandon_chunk_after_worker_error(
        db_path,
        occurrence_id=occurrence["occurrence_id"],
        chunk_number=1,
        lease=lease,
        reason="Injected failure after network contact started",
    )

    assert state == "needs_attention"
    retained = get_occurrence(db_path, occurrence["occurrence_id"])
    assert retained is not None and retained["state"] == "needs_attention"
    assert retained["chunks"][0]["state"] == "needs_attention"
    with pytest.raises(WorkRecoveryRequired):
        claim_next_chunk(
            db_path,
            occurrence["occurrence_id"],
            owner_id="worker-two",
            lease_seconds=30,
        )


def test_two_processes_allow_only_one_next_chunk_claim(tmp_path: Path) -> None:
    db_path = tmp_path / "analyzer.db"
    schedule = make_schedule(db_path)
    occurrence = prepare_occurrence(
        db_path,
        schedule=schedule,
        due_at="2026-01-01T00:00:00+00:00",
        trigger_kind="scheduled",
        trigger_key="cadence",
        actor="scheduler",
        frozen_contract=frozen(),
        chunks=[["198.51.100.1"]],
        next_due_at="2026-01-02T00:00:00+00:00",
    )
    code = r"""
import sys
from pathlib import Path
from app.scheduled_work import claim_next_chunk
from app.work_coordination import WorkLeaseConflict
try:
    result=claim_next_chunk(Path(sys.argv[1]),sys.argv[2],owner_id=sys.argv[3],lease_seconds=30)
    print('claimed' if result else 'none')
except WorkLeaseConflict:
    print('conflict')
"""
    processes = [
        subprocess.Popen(
            [
                sys.executable, "-c", code, str(db_path),
                occurrence.occurrence_id, f"worker-{number}",
            ],
            cwd=Path(__file__).parents[1],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for number in range(2)
    ]
    results = [process.communicate(timeout=20) for process in processes]

    assert all(process.returncode == 0 for process in processes), results
    outcomes = sorted(stdout.strip() for stdout, _stderr in results)
    assert outcomes == ["claimed", "conflict"]


def test_two_processes_allow_only_one_scan_dispatch_claim(tmp_path: Path) -> None:
    db_path = tmp_path / "analyzer.db"
    popen_log = tmp_path / "fake-popen.log"
    manifest, _occurrence, _lease = bound_queued_run(db_path)
    code = r"""
import sys
from pathlib import Path
from app.poc import claim_next_queued_scan
claimed=claim_next_queued_scan(Path(sys.argv[1]))
def fake_popen():
    with Path(sys.argv[2]).open('a', encoding='utf-8') as handle:
        handle.write('started\n')
if claimed:
    fake_popen()
print('popen' if claimed else 'none')
"""
    processes = [
        subprocess.Popen(
            [sys.executable, "-c", code, str(db_path), str(popen_log)],
            cwd=Path(__file__).parents[1],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for _ in range(2)
    ]
    results = [process.communicate(timeout=20) for process in processes]

    assert all(process.returncode == 0 for process in processes), results
    assert sorted(stdout.strip() for stdout, _stderr in results) == ["none", "popen"]
    assert popen_log.read_text(encoding="utf-8").splitlines() == ["started"]
    saved = poc.get_scan_run_plan(manifest["run_id"], db_path)
    assert saved is not None and saved["status"] == "dispatching"


def test_precontact_restart_rebinds_same_run_and_fences_old_owner(tmp_path: Path) -> None:
    db_path = tmp_path / "analyzer.db"
    _manifest, occurrence, old_chunk_lease = bound_queued_run(db_path)
    old_execution = poc.claim_next_queued_scan(db_path)
    assert old_execution is not None

    recover_schedule_occurrences(db_path, owner_process_ended=True)
    recovered = poc.recover_scan_execution_fence(db_path)
    assert recovered and recovered["safe_pre_contact"] is True
    claimed = claim_next_chunk(
        db_path,
        occurrence["occurrence_id"],
        owner_id="scan-run:replacement",
        lease_seconds=30,
    )
    assert claimed is not None
    rebound_chunk, new_chunk_lease = claimed
    assert rebound_chunk["scan_run_id"] == old_execution["run_id"]
    rebound = poc.get_scan_run_plan(old_execution["run_id"], db_path)
    assert rebound is not None
    assert rebound["work_claim"]["lease_id"] == new_chunk_lease.lease_id
    replacement = poc.claim_next_queued_scan(db_path)
    assert replacement is not None
    assert replacement["run_id"] == old_execution["run_id"]

    old_execution["status"] = "running"
    with pytest.raises(WorkLeaseLost):
        poc.update_scan_run_manifest(old_execution, db_path)
    with pytest.raises(WorkLeaseLost):
        publish_chunk_terminal(
            db_path,
            occurrence_id=occurrence["occurrence_id"],
            chunk_number=1,
            terminal_state="complete",
            reason="stale owner",
            lease=old_chunk_lease,
        )


def test_worker_retains_one_safe_retry_after_local_precontact_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_path = tmp_path / "analyzer.db"
    manifest, occurrence, _chunk_lease = bound_queued_run(db_path)
    claimed = poc.claim_next_queued_scan(db_path)
    assert claimed is not None
    monkeypatch.setattr(
        poc,
        "execute_scan_run",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            RuntimeError("injected before contact")
        ),
    )
    monkeypatch.setattr(poc, "dispatch_next_queued_run", lambda **_kwargs: None)

    poc._scan_worker_entry(
        manifest["run_id"],
        poc.RunControl(),
        db_path=db_path,
        data_dir=tmp_path / "data",
    )

    saved = poc.get_scan_run_plan(manifest["run_id"], db_path)
    retained = get_occurrence(db_path, occurrence["occurrence_id"])
    assert saved is not None and saved["status"] == "queued"
    assert saved["precontact_start_failure_count"] == 1
    assert "injected before contact" in saved["last_precontact_start_error"]
    assert "execution_claim" not in saved
    assert retained is not None and retained["state"] == "waiting"
    assert retained["chunks"][0]["state"] == "waiting"
    assert retained["chunks"][0]["contact_phase"] == "not_started"
    with connect_database(db_path) as connection:
        capacity = connection.execute(
            "SELECT state FROM work_leases WHERE lease_key = ?",
            (poc.SCAN_CAPACITY_LEASE_KEY,),
        ).fetchone()
    assert capacity is not None and capacity[0] == "released"


def test_replacement_worker_reuses_exact_precontact_folder_and_completes_same_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_path = tmp_path / "analyzer.db"
    data_dir = tmp_path / "data"
    manifest, occurrence, _old_chunk_lease = bound_queued_run(db_path)
    old_execution = poc.claim_next_queued_scan(db_path)
    assert old_execution is not None
    run_dir = poc.prepare_scan_run_directory(old_execution, data_dir)
    poc._write_text_atomic(run_dir / "targets.txt", "198.51.100.1\n")
    poc._write_text_atomic(run_dir / "no-strike.txt", "")
    poc.write_manifest_file(old_execution, data_dir)

    recover_schedule_occurrences(db_path, owner_process_ended=True)
    recovered = poc.recover_scan_execution_fence(db_path)
    assert recovered and recovered["safe_pre_contact"] is True
    rebound = claim_next_chunk(
        db_path,
        occurrence["occurrence_id"],
        owner_id="scan-run:replacement",
        lease_seconds=30,
    )
    assert rebound is not None
    replacement = poc.claim_next_queued_scan(db_path)
    assert replacement is not None
    assert replacement["run_id"] == manifest["run_id"]

    launched: list[str] = []
    discovery_xml = b'''<?xml version="1.0"?><nmaprun scanner="nmap"><host><status state="up"/><address addr="198.51.100.1" addrtype="ipv4"/></host><runstats><finished time="1"/><hosts up="1" down="0" total="1"/></runstats></nmaprun>'''
    scan_xml = b'''<?xml version="1.0"?><nmaprun scanner="nmap"><scaninfo type="syn" protocol="tcp"/><host><status state="up"/><address addr="198.51.100.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="443"><state state="open"/></port></ports></host><runstats><finished time="2"/><hosts up="1" down="0" total="1"/></runstats></nmaprun>'''

    def fake_popen(argv, *, cwd: Path, **kwargs):
        tokens = [str(item) for item in argv]
        command = " ".join(tokens)
        launched.append(command)
        executable = Path(tokens[0]).name
        if executable == "tcpdump":
            return CompletedFakeProcess(running=True)
        if executable == "fping":
            kwargs["stdout"].write(b"198.51.100.1\n")
            kwargs["stdout"].flush()
            return CompletedFakeProcess()
        if "discovery.xml" in command:
            (cwd / "discovery.xml").write_bytes(discovery_xml)
            return CompletedFakeProcess()
        if "tcp-scan.xml" in command:
            (cwd / "tcp-scan.xml").write_bytes(scan_xml)
            return CompletedFakeProcess()
        if "udp-scan.xml" in command:
            (cwd / "udp-scan.xml").write_bytes(scan_xml)
            return CompletedFakeProcess()
        if "-oX" in tokens:
            output = Path(tokens[tokens.index("-oX") + 1])
            if not output.is_absolute():
                output = cwd / output
            output.write_bytes(
                discovery_xml if output.name == "discovery.xml" else scan_xml
            )
            return CompletedFakeProcess()
        raise AssertionError(command)

    monkeypatch.setattr(poc, "start_derived_job_worker", lambda *_args, **_kwargs: None)
    poc.execute_scan_run(
        manifest["run_id"],
        poc.RunControl(),
        db_path=db_path,
        data_dir=data_dir,
        popen_factory=fake_popen,
        sleep_fn=lambda _seconds: None,
    )

    completed = poc.get_scan_run_plan(manifest["run_id"], db_path)
    retained = get_occurrence(db_path, occurrence["occurrence_id"])
    assert completed is not None
    assert completed["status"] == "completed", (completed.get("error"), launched)
    assert completed["run_id"] == old_execution["run_id"]
    assert retained is not None and retained["state"] == "complete"
    assert retained["chunks"][0]["state"] == "complete"
    assert launched
    assert (run_dir / "scan.xml").is_file()


def test_precontact_folder_with_unexpected_output_is_never_reused(tmp_path: Path) -> None:
    db_path = tmp_path / "analyzer.db"
    data_dir = tmp_path / "data"
    _manifest, _occurrence, _lease = bound_queued_run(db_path)
    claimed = poc.claim_next_queued_scan(db_path)
    assert claimed is not None
    run_dir = poc.prepare_scan_run_directory(claimed, data_dir)
    (run_dir / "scan.xml").write_text("unexpected evidence", encoding="utf-8")

    with pytest.raises(RuntimeError, match="unexpected output: scan.xml"):
        poc.prepare_scan_run_directory(claimed, data_dir)


@pytest.mark.parametrize("cancellation_kind", ["operator", "global_no_strike"])
def test_dispatching_cancellation_closes_before_any_network_process(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    cancellation_kind: str,
) -> None:
    db_path = tmp_path / "analyzer.db"
    data_dir = tmp_path / "data"
    manifest, occurrence, _lease = bound_queued_run(db_path)
    claimed = poc.claim_next_queued_scan(db_path)
    assert claimed is not None and claimed["status"] == "dispatching"
    if cancellation_kind == "operator":
        poc.request_scan_cancellation(
            manifest["run_id"],
            requested_by="analyst.one",
            cause="operator",
            detail="Operator cancelled before contact",
            db_path=db_path,
        )
    else:
        poc.add_global_no_strike(
            poc.NoStrikeUpdate(
                entries=["198.51.100.1"], changed_by="safety.officer"
            ),
            db_path,
        )

    launched: list[list[str]] = []
    real_execute = poc.execute_scan_run

    def execute_without_contact(run_id, control, *, db_path, data_dir):
        return real_execute(
            run_id,
            control,
            db_path=db_path,
            data_dir=data_dir,
            popen_factory=lambda argv, **_kwargs: launched.append(list(argv)),
            sleep_fn=lambda _seconds: None,
        )

    monkeypatch.setattr(poc, "execute_scan_run", execute_without_contact)
    monkeypatch.setattr(poc, "dispatch_next_queued_run", lambda **_kwargs: None)
    poc._scan_worker_entry(
        manifest["run_id"], poc.RunControl(), db_path=db_path, data_dir=data_dir
    )

    completed = poc.get_scan_run_plan(manifest["run_id"], db_path)
    retained = get_occurrence(db_path, occurrence["occurrence_id"])
    assert launched == []
    assert completed is not None and completed["status"] == "cancelled"
    assert completed.get("started_at") is None
    assert retained is not None and retained["state"] == "cancelled"
    assert retained["chunks"][0]["state"] == "cancelled"
    assert retained["chunks"][0]["contact_phase"] == "not_started"
    with connect_database(db_path) as connection:
        capacity = connection.execute(
            "SELECT state FROM work_leases WHERE lease_key = ?",
            (poc.SCAN_CAPACITY_LEASE_KEY,),
        ).fetchone()
        control = connection.execute(
            """SELECT cancellation_acknowledged_at FROM scan_run_control
                 WHERE run_id = ?""",
            (manifest["run_id"],),
        ).fetchone()
    assert capacity is not None and capacity[0] == "released"
    assert control is not None and control[0]


def test_running_and_scheduled_contact_start_publish_atomically(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_path = tmp_path / "analyzer.db"
    manifest, occurrence, _chunk_lease = bound_queued_run(db_path)
    claimed = poc.claim_next_queued_scan(db_path)
    assert claimed is not None
    claimed["started_at"] = "2026-01-01T00:00:00+00:00"
    claimed["status"] = "running"
    monkeypatch.setattr(
        poc,
        "sync_scan_history_manifest",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("injected")),
    )

    with pytest.raises(RuntimeError, match="injected"):
        poc.publish_scan_contact_starting(claimed, db_path=db_path)

    saved = poc.get_scan_run_plan(manifest["run_id"], db_path)
    retained = get_occurrence(db_path, occurrence["occurrence_id"])
    assert saved is not None and saved["status"] == "dispatching"
    assert saved.get("started_at") is None
    assert retained is not None and retained["state"] == "preparing"
    assert retained["chunks"][0]["contact_phase"] == "preparing"


def test_restart_after_atomic_contact_start_is_reviewable_and_clears_capacity(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "analyzer.db"
    manifest, occurrence, _chunk_lease = bound_queued_run(db_path)
    claimed = poc.claim_next_queued_scan(db_path)
    assert claimed is not None
    claimed["started_at"] = "2026-01-01T00:00:00+00:00"
    claimed["status"] = "running"
    poc.publish_scan_contact_starting(claimed, db_path=db_path)

    recovered_occurrences = recover_schedule_occurrences(
        db_path, owner_process_ended=True
    )
    recovered_scan = poc.recover_scan_execution_fence(db_path)
    assert recovered_occurrences == [occurrence["occurrence_id"]]
    assert recovered_scan == {
        "run_id": manifest["run_id"],
        "safe_pre_contact": False,
        "state": "interrupted",
    }
    retained = get_occurrence(db_path, occurrence["occurrence_id"])
    assert retained is not None and retained["state"] == "needs_attention"

    closed = close_reviewed_occurrence(
        db_path,
        occurrence["occurrence_id"],
        reviewed_by="admin.one",
        reason="Verified the former scanner process is stopped",
        confirmed_former_contact_stopped=True,
    )
    assert closed["state"] == "cancelled"
    with sqlite3.connect(db_path) as connection:
        capacity = connection.execute(
            "SELECT state FROM work_leases WHERE lease_key = ?",
            (poc.SCAN_CAPACITY_LEASE_KEY,),
        ).fetchone()
    assert capacity == ("released",)


def test_terminal_scan_and_chunk_publication_roll_back_together(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_path = tmp_path / "analyzer.db"
    schedule = make_schedule(db_path)
    occurrence = prepare_occurrence(
        db_path,
        schedule=schedule,
        due_at="2026-01-01T00:00:00+00:00",
        trigger_kind="scheduled",
        trigger_key="cadence",
        actor="scheduler",
        frozen_contract=frozen(),
        chunks=[["198.51.100.1"]],
        next_due_at="2026-01-02T00:00:00+00:00",
    )
    claimed = claim_next_chunk(
        db_path, occurrence.occurrence_id, owner_id="worker", lease_seconds=30
    )
    assert claimed is not None
    chunk, lease = claimed
    request = poc._scheduled_request(
        schedule,
        chunk["targets"],
        batch_id=occurrence.occurrence_id,
        chunk_number=1,
        chunk_count=1,
        batch_hosts_total=1,
        batch_hosts_completed_before=0,
        db_path=db_path,
    )
    manifest = poc.prepare_scan_run(
        request,
        db_path,
        {"eth0"},
        reserved_run_id="b" * 32,
        scheduled_chunk_claim=(occurrence.occurrence_id, 1, lease),
    )
    claimed_manifest = poc.claim_next_queued_scan(db_path)
    assert claimed_manifest is not None
    manifest = claimed_manifest
    manifest.update({
        "status": "completed",
        "success": True,
        "completed_at": "2026-01-01T00:10:00+00:00",
        "artifact_registry": {"files": [], "errors": [], "status": "complete"},
    })
    monkeypatch.setattr(
        poc,
        "sync_scan_history_manifest",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("injected")),
    )

    with pytest.raises(RuntimeError, match="injected"):
        poc.publish_scheduled_scan_terminal(
            manifest, manifest["work_claim"], db_path=db_path
        )

    saved = poc.get_scan_run_plan(manifest["run_id"], db_path)
    current = get_occurrence(db_path, occurrence.occurrence_id)
    assert saved is not None and saved["status"] == "dispatching"
    assert current is not None and current["chunks"][0]["state"] == "preparing"
    with sqlite3.connect(db_path) as connection:
        lease_state = connection.execute(
            "SELECT state FROM work_leases"
        ).fetchone()[0]
    assert lease_state == "active"


def test_owner_loss_after_contact_blocks_transfer_and_later_chunks(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "analyzer.db"
    schedule = make_schedule(db_path)
    occurrence = prepare_occurrence(
        db_path,
        schedule=schedule,
        due_at="2026-01-01T00:00:00+00:00",
        trigger_kind="scheduled",
        trigger_key="cadence",
        actor="scheduler",
        frozen_contract=frozen(),
        chunks=[["198.51.100.1"], ["198.51.100.2"]],
        next_due_at="2026-01-02T00:00:00+00:00",
    )
    claimed = claim_next_chunk(
        db_path, occurrence.occurrence_id, owner_id="worker-one", lease_seconds=30
    )
    assert claimed is not None
    chunk, lease = claimed
    bind_chunk_scan_run(
        db_path,
        occurrence_id=occurrence.occurrence_id,
        chunk_number=chunk["chunk_number"],
        scan_run_id="a" * 32,
        lease=lease,
    )
    mark_chunk_contact_starting(
        db_path,
        occurrence_id=occurrence.occurrence_id,
        chunk_number=1,
        lease=lease,
    )

    recovered = recover_schedule_occurrences(db_path, owner_process_ended=True)
    current = get_occurrence(db_path, occurrence.occurrence_id)

    assert recovered == [occurrence.occurrence_id]
    assert current is not None and current["state"] == "needs_attention"
    assert current["chunks"][0]["state"] == "needs_attention"
    assert current["chunks"][1]["state"] == "waiting"
    with pytest.raises(WorkRecoveryRequired):
        claim_next_chunk(
            db_path, occurrence.occurrence_id, owner_id="worker-two"
        )
    with sqlite3.connect(db_path) as connection:
        event = connection.execute(
            "SELECT event_kind FROM work_lease_events ORDER BY rowid DESC LIMIT 1"
        ).fetchone()
    assert event == ("recovery_required",)

    closed = close_reviewed_occurrence(
        db_path,
        occurrence.occurrence_id,
        reviewed_by="admin.one",
        reason="Verified the former scanner process is stopped",
        confirmed_former_contact_stopped=True,
    )
    assert closed["state"] == "cancelled"
    reviewed = get_occurrence(db_path, occurrence.occurrence_id)
    assert reviewed is not None and reviewed["state"] == "cancelled"
    assert reviewed["chunks"][0]["state"] == "needs_attention"
    assert reviewed["chunks"][1]["state"] == "cancelled"
    with sqlite3.connect(db_path) as connection:
        review = connection.execute(
            """SELECT reviewed_by, confirmed_former_contact_stopped
                 FROM scan_schedule_recovery_reviews WHERE occurrence_id = ?""",
            (occurrence.occurrence_id,),
        ).fetchone()
    assert review == ("admin.one", 1)


def test_manual_request_id_is_idempotent_across_retry_time(tmp_path: Path) -> None:
    db_path = tmp_path / "analyzer.db"
    schedule = make_schedule(db_path)
    first = prepare_occurrence(
        db_path,
        schedule=schedule,
        due_at="2026-01-01T00:00:00+00:00",
        trigger_kind="manual",
        trigger_key="request-1234567890",
        actor="analyst.one",
        frozen_contract=frozen(),
        chunks=[["198.51.100.1"]],
        next_due_at=schedule["next_run_at"],
    )
    claim = claim_next_chunk(
        db_path, first.occurrence_id, owner_id="worker", lease_seconds=30
    )
    assert claim is not None
    _chunk, lease = claim
    publish_chunk_terminal(
        db_path,
        occurrence_id=first.occurrence_id,
        chunk_number=1,
        terminal_state="complete",
        reason="finished",
        lease=lease,
    )
    second = prepare_occurrence(
        db_path,
        schedule=schedule,
        due_at="2026-01-02T00:00:00+00:00",
        trigger_kind="manual",
        trigger_key="request-1234567890",
        actor="analyst.one",
        frozen_contract=frozen(),
        chunks=[["198.51.100.1"]],
        next_due_at=schedule["next_run_at"],
    )
    assert second.occurrence_id == first.occurrence_id
    assert second.created is False
    retained = get_occurrence(db_path, first.occurrence_id)
    assert retained is not None
    assert retained["due_at"] == "2026-01-01T00:00:00+00:00"


def test_stale_worker_status_update_does_not_reenable_paused_schedule(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "analyzer.db"
    schedule = make_schedule(db_path)
    stale = dict(schedule)
    paused = poc.set_scan_schedule_enabled(
        schedule["schedule_id"], False, changed_by="analyst.two", db_path=db_path
    )
    assert paused["enabled"] is False
    stale["batch_status"] = "active"
    stale["last_dispatch_note"] = "Worker progress"
    stored = poc._store_scan_schedule(stale, db_path)
    assert stored["enabled"] is False
    assert stored["control_revision"] == paused["control_revision"]
    current = poc.get_scan_schedule(schedule["schedule_id"], db_path)
    assert current is not None and current["enabled"] is False


def test_completed_chunk_is_irreversible(tmp_path: Path) -> None:
    db_path = tmp_path / "analyzer.db"
    schedule = make_schedule(db_path)
    occurrence = prepare_occurrence(
        db_path,
        schedule=schedule,
        due_at="2026-01-01T00:00:00+00:00",
        trigger_kind="scheduled",
        trigger_key="cadence",
        actor="scheduler",
        frozen_contract=frozen(),
        chunks=[["198.51.100.1"]],
        next_due_at="2026-01-02T00:00:00+00:00",
    )
    claimed = claim_next_chunk(
        db_path, occurrence.occurrence_id, owner_id="worker", lease_seconds=30
    )
    assert claimed is not None
    _chunk, lease = claimed
    publish_chunk_terminal(
        db_path,
        occurrence_id=occurrence.occurrence_id,
        chunk_number=1,
        terminal_state="complete",
        reason="complete",
        lease=lease,
    )

    with sqlite3.connect(db_path) as connection, pytest.raises(
        sqlite3.IntegrityError, match="cannot reopen"
    ):
        connection.execute(
            "UPDATE scan_schedule_chunks SET state = 'waiting' WHERE occurrence_id = ?",
            (occurrence.occurrence_id,),
        )
