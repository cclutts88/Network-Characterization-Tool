from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

import app.poc as poc
from app.poc import (
    ScanOptions,
    ScanProfileCreate,
    ScanProfileVersionCreate,
    ScanScheduleCreate,
    ScheduleProfileChange,
    change_scan_schedule_profile,
    add_global_no_strike,
    create_scan_profile,
    create_scan_profile_version,
    create_scan_schedule,
    delete_scan_data,
    delete_scan_profile,
    delete_scan_schedule,
    effective_no_strike,
    execute_schedule_batch,
    get_global_no_strike,
    get_scan_profile,
    issue_delete_challenge,
    insert_scan_run_manifest,
    NoStrikeRemoval,
    NoStrikeUpdate,
    remove_global_no_strike,
    recover_scheduler_state,
    record_schedule_conflict,
    scan_safety_summary,
    schedule_target_chunks,
    set_scan_schedule_enabled,
)


def test_profile_versions_are_immutable_and_schedules_remain_pinned(tmp_path):
    db_path = tmp_path / "analyzer.db"
    version_one = create_scan_profile(
        ScanProfileCreate(
            name="DMZ Weekly",
            created_by="analyst01",
            settings=ScanOptions(protocol="tcp", tcp_scope="common"),
        ),
        db_path,
    )
    schedule = create_scan_schedule(
        ScanScheduleCreate(
            name="DMZ Monday",
            created_by="analyst01",
            profile_id=version_one["profile_id"],
            profile_version=1,
            targets=["172.16.20.0/24"],
            interface="eth0",
            cadence="weekly",
            first_run_at=datetime(2026, 9, 14, 2, 0, tzinfo=timezone.utc),
        ),
        db_path,
    )
    assert schedule["timeout_seconds"] == 45 * 60
    version_two = create_scan_profile_version(
        version_one["profile_id"],
        ScanProfileVersionCreate(
            created_by="analyst02",
            description="Add UDP",
            settings=ScanOptions(
                protocol="tcp_udp", tcp_scope="common", udp_scope="common"
            ),
        ),
        db_path,
    )

    assert version_two["version"] == 2
    assert get_scan_profile(version_one["profile_id"], 1, db_path)["settings"]["protocol"] == "tcp"
    assert schedule["profile_version"] == 1
    assert schedule["profile_snapshot"]["protocol"] == "tcp"
    assert schedule["implementation_status"] == "active_scheduler"


def test_custom_profile_delete_is_protected_until_schedule_is_repinned(tmp_path):
    db_path = tmp_path / "analyzer.db"
    profile = create_scan_profile(
        ScanProfileCreate(
            name="Temporary Mission Profile",
            created_by="analyst01",
            settings=ScanOptions(protocol="tcp", tcp_scope="common"),
        ),
        db_path,
    )
    schedule = create_scan_schedule(
        ScanScheduleCreate(
            name="Mission Schedule",
            created_by="analyst01",
            profile_id=profile["profile_id"],
            profile_version=1,
            targets=["192.0.2.0/30"],
            interface="eth0",
            cadence="daily",
            first_run_at=datetime(2026, 9, 10, 2, 0, tzinfo=timezone.utc),
        ),
        db_path,
    )
    challenge = issue_delete_challenge("profile", profile["profile_id"])["challenge"]
    with pytest.raises(RuntimeError, match="pinned"):
        delete_scan_profile(profile["profile_id"], challenge, db_path)

    changed = change_scan_schedule_profile(
        schedule["schedule_id"],
        ScheduleProfileChange(
            profile_id="builtin-standard",
            profile_version=1,
            changed_by="analyst02",
        ),
        db_path,
    )
    assert changed["profile_id"] == "builtin-standard"
    assert changed["last_changed_by"] == "analyst02"

    deleted = delete_scan_profile(profile["profile_id"], challenge, db_path)
    assert deleted["versions_removed"] == 1
    assert get_scan_profile(profile["profile_id"], db_path=db_path) is None


def test_built_in_profile_cannot_be_deleted(tmp_path):
    db_path = tmp_path / "analyzer.db"
    challenge = issue_delete_challenge("profile", "builtin-standard")["challenge"]
    with pytest.raises(PermissionError, match="Built-in"):
        delete_scan_profile("builtin-standard", challenge, db_path)


def test_scan_and_schedule_deletion_accept_visible_confirmation_challenges(tmp_path):
    db_path = tmp_path / "analyzer.db"
    data_dir = tmp_path / "data"
    schedule = create_scan_schedule(
        ScanScheduleCreate(
            name="Disposable Schedule",
            created_by="analyst01",
            profile_id="builtin-standard",
            profile_version=1,
            targets=["192.0.2.10"],
            interface="eth0",
            cadence="once",
            first_run_at=datetime(2026, 9, 10, 2, 0, tzinfo=timezone.utc),
        ),
        db_path,
    )
    schedule_confirmation = issue_delete_challenge(
        "schedule", schedule["schedule_id"]
    )["challenge"]
    assert delete_scan_schedule(
        schedule["schedule_id"], schedule_confirmation, db_path
    )["deleted"] is True
    assert poc.get_scan_schedule(schedule["schedule_id"], db_path) is None

    run_id = "f" * 32
    manifest = {
        "run_id": run_id,
        "created_at": "2026-09-09T12:00:00+00:00",
        "status": "completed",
        "operator": "analyst01",
        "reason": "Deletion test",
        "originating_host": "test-host",
        "interface": "eth0",
        "profile": "Standard",
    }
    insert_scan_run_manifest(manifest, db_path)
    run_dir = data_dir / "scan-runs" / run_id
    run_dir.mkdir(parents=True)
    (run_dir / "scan.xml").write_text("evidence", encoding="utf-8")
    scan_confirmation = issue_delete_challenge("scan", run_id)["challenge"]
    assert delete_scan_data(
        run_id, scan_confirmation, db_path=db_path, data_dir=data_dir
    )["deleted"] is True
    assert not run_dir.exists()
    assert poc.get_scan_run_plan(run_id, db_path) is None


def test_scheduler_splits_a_slash_24_into_six_sequential_chunks(tmp_path):
    db_path = tmp_path / "analyzer.db"
    now = datetime(2026, 9, 9, 20, 0, tzinfo=timezone.utc)
    schedule = create_scan_schedule(
        ScanScheduleCreate(
            name="Hourly Terrain",
            created_by="analyst01",
            profile_id="builtin-standard",
            profile_version=1,
            targets=["198.51.100.0/24"],
            interface="eth0",
            cadence="hourly",
            first_run_at=now - timedelta(minutes=1),
            chunk_size=50,
            chunk_delay_seconds=30,
            enabled=True,
        ),
        db_path,
    )
    chunks = schedule_target_chunks(schedule, db_path)

    assert [len(chunk) for chunk in chunks] == [50, 50, 50, 50, 50, 6]
    assert len({address for chunk in chunks for address in chunk}) == 256


def test_new_schedule_is_unchunked_unless_analyst_opts_in(tmp_path):
    db_path = tmp_path / "analyzer.db"
    schedule = create_scan_schedule(
        ScanScheduleCreate(
            name="Continuous Terrain",
            created_by="analyst01",
            profile_id="builtin-standard",
            profile_version=1,
            targets=["198.51.100.0/24"],
            interface="eth0",
            cadence="daily",
            first_run_at=datetime(2026, 9, 10, 2, 0, tzinfo=timezone.utc),
            chunking_enabled=False,
            chunk_size=50,
            chunk_delay_seconds=30,
        ),
        db_path,
    )

    chunks = schedule_target_chunks(schedule, db_path)

    assert schedule["chunking_enabled"] is False
    assert schedule["chunk_delay_seconds"] == 0
    assert len(chunks) == 1
    assert len(chunks[0]) == 256


def test_schedule_batch_waits_after_completion_and_advances(monkeypatch, tmp_path):
    db_path = tmp_path / "analyzer.db"
    now = datetime(2026, 9, 9, 20, 0, tzinfo=timezone.utc)
    schedule = create_scan_schedule(
        ScanScheduleCreate(
            name="Hourly Terrain",
            created_by="analyst01",
            profile_id="builtin-standard",
            profile_version=1,
            targets=["198.51.100.0/29"],
            interface="eth0",
            cadence="hourly",
            first_run_at=now - timedelta(minutes=1),
            chunk_size=3,
            chunk_delay_seconds=30,
            enabled=True,
        ),
        db_path,
    )
    captured = []
    completed = {}
    waits = []

    def fake_launch(request, **_kwargs):
        captured.append(request.model_dump())
        run_id = f"{len(captured):032x}"
        completed[run_id] = {"run_id": run_id, "status": "completed"}
        return {"run_id": run_id, "status": "queued"}

    monkeypatch.setattr(poc, "launch_scan_run", fake_launch)
    monkeypatch.setattr(
        poc, "get_scan_run_plan", lambda run_id, _db_path: completed.get(run_id)
    )
    execute_schedule_batch(
        schedule["schedule_id"],
        "a" * 32,
        advance_schedule=True,
        db_path=db_path,
        sleep_fn=waits.append,
    )

    assert [len(item["targets"]) for item in captured] == [3, 3, 2]
    assert [item["chunk_number"] for item in captured] == [1, 2, 3]
    assert [item["batch_hosts_total"] for item in captured] == [8, 8, 8]
    assert [item["batch_hosts_completed_before"] for item in captured] == [0, 3, 6]
    assert all(item["scheduled"] is True for item in captured)
    assert all(item["profile_id"] == "builtin-standard" for item in captured)
    assert waits == [30, 30]
    updated = poc.get_scan_schedule(schedule["schedule_id"], db_path)
    assert updated["run_count"] == 3
    assert updated["batch_status"] == "completed"
    assert datetime.fromisoformat(updated["next_run_at"]) > now


def test_custom_hour_cadence_advances_by_operator_selected_hours(tmp_path):
    db_path = tmp_path / "analyzer.db"
    first_run = datetime(2026, 9, 9, 20, 0, tzinfo=timezone.utc)
    schedule = create_scan_schedule(
        ScanScheduleCreate(
            name="Six Hour Terrain",
            created_by="analyst01",
            profile_id="builtin-standard",
            profile_version=1,
            targets=["198.51.100.10"],
            interface="eth0",
            cadence="custom_hours",
            cadence_hours=6,
            first_run_at=first_run,
        ),
        db_path,
    )

    following = poc.next_schedule_time(
        schedule, first_run + timedelta(minutes=1)
    )

    assert schedule["cadence_hours"] == 6
    assert following == first_run + timedelta(hours=6)


def test_monthly_cadence_preserves_the_requested_day_when_possible(tmp_path):
    db_path = tmp_path / "analyzer.db"
    first_run = datetime(2027, 1, 31, 20, 15, tzinfo=timezone.utc)
    schedule = create_scan_schedule(
        ScanScheduleCreate(
            name="Month End Terrain",
            created_by="analyst01",
            profile_id="builtin-standard",
            profile_version=1,
            targets=["198.51.100.10"],
            interface="eth0",
            cadence="monthly",
            first_run_at=first_run,
        ),
        db_path,
    )

    february = poc.next_schedule_time(schedule, first_run + timedelta(minutes=1))
    march = poc.next_schedule_time(schedule, february + timedelta(minutes=1))

    assert february == datetime(2027, 2, 28, 20, 15, tzinfo=timezone.utc)
    assert march == datetime(2027, 3, 31, 20, 15, tzinfo=timezone.utc)


def test_schedule_changes_retain_operator_audit_history(tmp_path):
    db_path = tmp_path / "analyzer.db"
    schedule = create_scan_schedule(
        ScanScheduleCreate(
            name="Audited Terrain",
            created_by="analyst01",
            profile_id="builtin-standard",
            profile_version=1,
            targets=["198.51.100.10"],
            interface="eth0",
            cadence="daily",
            first_run_at=datetime(2026, 9, 10, 20, 0, tzinfo=timezone.utc),
        ),
        db_path,
    )

    set_scan_schedule_enabled(
        schedule["schedule_id"], True, "shift-lead", db_path
    )
    changed = change_scan_schedule_profile(
        schedule["schedule_id"],
        ScheduleProfileChange(
            profile_id="builtin-comprehensive",
            profile_version=1,
            changed_by="mission-owner",
        ),
        db_path,
    )

    assert [item["event"] for item in changed["modification_history"]] == [
        "created",
        "enabled",
        "profile_changed",
    ]
    assert changed["last_changed_by"] == "mission-owner"
    assert "builtin-comprehensive" in changed["profile_id"]


def test_restart_recovery_resumes_after_completed_chunks(monkeypatch, tmp_path):
    db_path = tmp_path / "analyzer.db"
    data_dir = tmp_path / "data"
    schedule = create_scan_schedule(
        ScanScheduleCreate(
            name="Recoverable Terrain",
            created_by="analyst01",
            profile_id="builtin-standard",
            profile_version=1,
            targets=["198.51.100.0/29"],
            interface="eth0",
            cadence="daily",
            first_run_at=datetime(2026, 9, 9, 20, 0, tzinfo=timezone.utc),
            chunk_size=3,
            chunk_delay_seconds=0,
            enabled=True,
        ),
        db_path,
    )
    batch_id = "a" * 32
    schedule.update(
        {
            "batch_status": "running",
            "active_batch_id": batch_id,
            "active_chunk_number": 2,
            "active_chunk_count": 3,
            "completed_chunk_count": 1,
        }
    )
    poc._store_scan_schedule(schedule, db_path)
    completed_run = {
        "run_id": "1" * 32,
        "created_at": "2026-09-09T20:00:00+00:00",
        "status": "completed",
        "operator": "analyst01",
        "reason": "test",
        "originating_host": "scheduler",
        "interface": "eth0",
        "profile": "Standard",
        "schedule_batch_id": batch_id,
        "chunk_number": 1,
    }
    orphaned_run = {
        **completed_run,
        "run_id": "2" * 32,
        "status": "running",
        "chunk_number": 2,
        "progress": {"phase": "nmap"},
    }
    insert_scan_run_manifest(completed_run, db_path)
    insert_scan_run_manifest(orphaned_run, db_path)

    recovered = recover_scheduler_state(db_path, data_dir)
    pending = poc.get_scan_schedule(schedule["schedule_id"], db_path)

    assert recovered["orphaned_run_ids"] == ["2" * 32]
    assert pending["batch_status"] == "recovery_pending"
    assert pending["resume_after_chunk"] == 1
    assert poc.get_scan_run_plan("2" * 32, db_path)["status"] == "interrupted"

    captured = []
    completed = {}

    def fake_launch(request, **_kwargs):
        captured.append(request.model_dump())
        run_id = f"{len(captured) + 2:032x}"
        completed[run_id] = {"run_id": run_id, "status": "completed"}
        return {"run_id": run_id, "status": "queued"}

    monkeypatch.setattr(poc, "launch_scan_run", fake_launch)
    monkeypatch.setattr(
        poc, "get_scan_run_plan", lambda run_id, _db_path: completed.get(run_id)
    )
    execute_schedule_batch(
        schedule["schedule_id"],
        "b" * 32,
        advance_schedule=True,
        db_path=db_path,
        data_dir=data_dir,
        sleep_fn=lambda _seconds: None,
    )

    assert [item["chunk_number"] for item in captured] == [2, 3]
    finished = poc.get_scan_schedule(schedule["schedule_id"], db_path)
    assert finished["last_occurrence_status"] == "completed"
    assert finished["completed_chunk_count"] == 3


def test_schedule_conflict_flag_counts_occurrences_not_retry_checks(tmp_path):
    db_path = tmp_path / "analyzer.db"
    schedule = create_scan_schedule(
        ScanScheduleCreate(
            name="Conflict Tracking",
            created_by="analyst01",
            profile_id="builtin-standard",
            profile_version=1,
            targets=["198.51.100.10"],
            interface="eth0",
            cadence="daily",
            first_run_at=datetime(2026, 9, 9, 20, 0, tzinfo=timezone.utc),
        ),
        db_path,
    )

    for _ in range(4):
        schedule = record_schedule_conflict(schedule, "scheduled:occurrence-1", db_path)
    assert schedule["conflict_count"] == 1
    assert schedule["conflict_flagged"] is False

    for occurrence in range(2, 5):
        schedule = record_schedule_conflict(
            schedule, f"scheduled:occurrence-{occurrence}", db_path
        )
    assert schedule["conflict_count"] == 4
    assert schedule["conflict_flagged"] is True
    assert schedule["last_conflict_at"]


def test_global_no_strike_is_automatic_and_requires_confirmation_to_remove(tmp_path):
    db_path = tmp_path / "analyzer.db"
    saved = add_global_no_strike(
        NoStrikeUpdate(entries=["203.0.113.9"], changed_by="safety-officer"),
        db_path,
    )
    assert saved["entries"] == ["203.0.113.9/32"]
    effective, global_entries = effective_no_strike(["203.0.113.20"], db_path)
    assert global_entries == ["203.0.113.9/32"]
    assert effective == ["203.0.113.9/32", "203.0.113.20/32"]

    request = NoStrikeRemoval(
        entries=["203.0.113.9/32"],
        changed_by="safety-officer",
        confirmation="WRONG",
    )
    with pytest.raises(PermissionError, match="confirmation"):
        remove_global_no_strike(request, db_path)
    assert get_global_no_strike(db_path)["entries"] == ["203.0.113.9/32"]

    confirmation = issue_delete_challenge(
        "global-no-strike", "203.0.113.9/32"
    )["challenge"]
    request.confirmation = confirmation
    removed = remove_global_no_strike(request, db_path)
    assert removed["removed"] == ["203.0.113.9/32"]
    assert removed["entries"] == []


def test_scan_safety_summary_does_not_double_count_overlapping_exclusions(tmp_path):
    db_path = tmp_path / "analyzer.db"
    add_global_no_strike(
        NoStrikeUpdate(entries=["192.0.2.0/30"], changed_by="safety-officer"),
        db_path,
    )

    summary = scan_safety_summary(
        ["192.0.2.0/29"],
        ["192.0.2.2/31", "192.0.2.6"],
        db_path,
    )

    assert summary == {
        "targets": ["192.0.2.0/29"],
        "requested_address_count": 8,
        "global_entry_count": 1,
        "global_excluded_address_count": 4,
        "additional_entry_count": 2,
        "additional_excluded_address_count": 1,
        "overlap_address_count": 2,
        "excluded_address_count": 5,
        "effective_address_count": 3,
    }
