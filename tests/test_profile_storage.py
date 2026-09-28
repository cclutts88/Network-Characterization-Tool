from __future__ import annotations

import ipaddress
import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException, Request

import app.poc as poc
from app.database import connect_database
from app.poc import (
    ScanOptions,
    FallbackDecision,
    RunControl,
    ScanProfileCreate,
    ScanProfileVersionCreate,
    ScanScheduleCreate,
    ScheduleProfileChange,
    change_scan_schedule_profile,
    add_to_global_no_strike,
    add_global_no_strike,
    create_scan_profile,
    create_scan_profile_version,
    create_scan_schedule,
    delete_all_scan_data,
    delete_scan_data,
    delete_scan_profile,
    delete_scan_schedule,
    decide_scan_fallback,
    effective_no_strike,
    execute_schedule_batch,
    get_global_no_strike,
    get_scan_profile,
    issue_delete_challenge,
    insert_scan_run_manifest,
    NoStrikeRemoval,
    NoStrikeUpdate,
    remove_global_no_strike,
    remove_from_global_no_strike,
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


def test_latest_builtin_defaults_to_fping_without_changing_version_one(tmp_path):
    db_path = tmp_path / "analyzer.db"

    original = get_scan_profile("builtin-standard", 1, db_path)
    current = get_scan_profile("builtin-standard", db_path=db_path)

    assert original["settings"]["discovery_mode"] == "nmap"
    assert current["version"] == 2
    assert current["settings"]["discovery_mode"] == "fping"


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


def test_bulk_scan_deletion_removes_database_rows_before_files(tmp_path):
    db_path = tmp_path / "analyzer.db"
    data_dir = tmp_path / "data"
    run_ids = ["d" * 32, "e" * 32]
    for run_id in run_ids:
        insert_scan_run_manifest(
            {
                "run_id": run_id,
                "created_at": "2026-09-09T12:00:00+00:00",
                "status": "completed",
                "operator": "analyst01",
                "reason": "Bulk deletion test",
                "originating_host": "test-host",
                "interface": "eth0",
                "profile": "Standard",
            },
            db_path,
        )
        run_dir = data_dir / "scan-runs" / run_id
        run_dir.mkdir(parents=True)
        (run_dir / "scan.xml").write_text("evidence", encoding="utf-8")
    imported = data_dir / "imports" / "manual.xml"
    imported.parent.mkdir(parents=True)
    imported.write_text("evidence", encoding="utf-8")

    challenge = issue_delete_challenge("all", None)["challenge"]
    result = delete_all_scan_data(challenge, db_path=db_path, data_dir=data_dir)

    assert result == {"deleted": True, "removed_runs": 2, "removed_imports": 1}
    assert not imported.exists()
    assert all(poc.get_scan_run_plan(run_id, db_path) is None for run_id in run_ids)


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
    assert chunks == [["198.51.100.0/24"]]


def test_unchunked_schedule_compacts_scope_after_no_strike_exclusion(tmp_path):
    db_path = tmp_path / "analyzer.db"
    schedule = create_scan_schedule(
        ScanScheduleCreate(
            name="Protected Terrain",
            created_by="analyst01",
            profile_id="builtin-standard",
            profile_version=1,
            targets=["198.51.100.0/24"],
            no_strike=["198.51.100.100/32"],
            interface="eth0",
            cadence="daily",
            first_run_at=datetime(2026, 9, 10, 2, 0, tzinfo=timezone.utc),
            chunking_enabled=False,
        ),
        db_path,
    )

    chunks = schedule_target_chunks(schedule, db_path)
    effective = [ipaddress.ip_network(item) for item in chunks[0]]

    assert len(chunks) == 1
    assert len(effective) < 16
    assert sum(network.num_addresses for network in effective) == 255
    assert not any(ipaddress.ip_address("198.51.100.100") in network for network in effective)


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
    frozen_chunks = schedule_target_chunks(schedule, db_path)
    schedule.update(
        {
            "batch_status": "running",
            "active_batch_id": batch_id,
            "active_chunk_number": 2,
            "active_chunk_count": 3,
            "completed_chunk_count": 1,
            "active_target_chunks": frozen_chunks,
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
    assert pending["active_target_chunks"] == frozen_chunks
    assert poc.get_scan_run_plan("2" * 32, db_path)["status"] == "interrupted"

    add_global_no_strike(
        NoStrikeUpdate(entries=["198.51.100.4"], changed_by="safety-officer"),
        db_path,
    )

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
    assert [item["targets"] for item in captured] == frozen_chunks[1:]
    assert all(item["no_strike"] == [] for item in captured)
    finished = poc.get_scan_schedule(schedule["schedule_id"], db_path)
    assert finished["last_occurrence_status"] == "completed"
    assert finished["completed_chunk_count"] == 3


def test_legacy_restart_without_frozen_chunks_pauses_for_review(tmp_path):
    db_path = tmp_path / "analyzer.db"
    data_dir = tmp_path / "data"
    schedule = create_scan_schedule(
        ScanScheduleCreate(
            name="Legacy interrupted schedule",
            created_by="analyst01",
            profile_id="builtin-standard",
            profile_version=1,
            targets=["198.51.100.0/29"],
            interface="eth0",
            cadence="daily",
            first_run_at=datetime(2026, 9, 9, 20, 0, tzinfo=timezone.utc),
            chunk_size=3,
            enabled=True,
        ),
        db_path,
    )
    schedule.update(
        {
            "batch_status": "running",
            "active_batch_id": "d" * 32,
            "active_chunk_number": 2,
            "active_chunk_count": 3,
            "completed_chunk_count": 1,
            "active_target_chunks": None,
        }
    )
    poc._store_scan_schedule(schedule, db_path)

    recover_scheduler_state(db_path, data_dir)
    recovered = poc.get_scan_schedule(schedule["schedule_id"], db_path)

    assert recovered["enabled"] is False
    assert recovered["batch_status"] == "recovery_review_required"
    assert "original chunk plan" in recovered["last_dispatch_note"]


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
        "global_no_strike_revision": 1,
        "global_no_strike_as_of": summary["global_no_strike_as_of"],
    }
    assert summary["global_no_strike_as_of"]


def test_global_no_strike_updates_are_atomic_and_versioned(tmp_path):
    db_path = tmp_path / "analyzer.db"

    def add(index: int):
        return add_global_no_strike(
            NoStrikeUpdate(
                entries=[f"198.51.100.{index}"], changed_by=f"analyst-{index}"
            ),
            db_path,
        )

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(add, range(1, 17)))

    state = get_global_no_strike(db_path)
    assert state["entries"] == ["198.51.100.1/32", "198.51.100.2/31", "198.51.100.4/30", "198.51.100.8/29", "198.51.100.16/32"]
    assert state["revision"] == 16
    with sqlite3.connect(db_path) as db:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            db.execute(
                "UPDATE global_no_strike_history SET changed_by = 'tampered' WHERE revision = 1"
            )


def test_global_no_strike_current_state_comes_from_valid_contiguous_history(tmp_path):
    db_path = tmp_path / "analyzer.db"
    add_global_no_strike(
        NoStrikeUpdate(entries=["192.0.2.1"], changed_by="analyst"), db_path
    )

    with sqlite3.connect(db_path) as db:
        db.execute(
            """
            INSERT INTO app_settings (key, value_json, updated_at, updated_by)
            VALUES ('global_no_strike', '[]', '2026-09-27T00:00:00Z', 'bypass')
            ON CONFLICT(key) DO UPDATE SET
                value_json = excluded.value_json,
                updated_at = excluded.updated_at,
                updated_by = excluded.updated_by
            """
        )
    assert get_global_no_strike(db_path) == {
        "entries": ["192.0.2.1/32"],
        "updated_at": get_global_no_strike(db_path)["updated_at"],
        "updated_by": "analyst",
        "revision": 1,
    }

    with connect_database(db_path) as db:
        with pytest.raises(sqlite3.IntegrityError, match="Invalid Global No-Strike"):
            db.execute(
                """
                INSERT INTO global_no_strike_history
                    (revision, entries_json, action, changed_at, changed_by)
                VALUES (3, '[\"192.0.2.2/32\"]', 'add', '2026-09-27T00:00:00Z', 'bypass')
                """
            )
        with pytest.raises(sqlite3.IntegrityError, match="Invalid Global No-Strike"):
            db.execute(
                """
                INSERT INTO global_no_strike_history
                    (revision, entries_json, action, changed_at, changed_by)
                VALUES (2, '[\"not-a-network\"]', 'add', '2026-09-27T00:00:00+00:00', 'bypass')
                """
            )
        for changed_at, changed_by in (
            ("not-a-time", "bypass"),
            ("2026-09-27T00:00:00+00:00", " padded actor "),
            ("2026-09-27T00:00:00+00:00", ""),
        ):
            with pytest.raises(sqlite3.IntegrityError, match="Invalid Global No-Strike"):
                db.execute(
                    """
                    INSERT INTO global_no_strike_history
                        (revision, entries_json, action, changed_at, changed_by)
                    VALUES (2, '[\"192.0.2.2/32\"]', 'add', ?, ?)
                    """,
                    (changed_at, changed_by),
                )


def test_legacy_settings_mirror_tracks_add_and_remove_for_immediate_rollback(tmp_path):
    db_path = tmp_path / "analyzer.db"
    added = add_global_no_strike(
        NoStrikeUpdate(entries=["203.0.113.9"], changed_by="analyst"), db_path
    )
    with sqlite3.connect(db_path) as db:
        legacy_after_add = db.execute(
            "SELECT value_json, updated_by FROM app_settings WHERE key = 'global_no_strike'"
        ).fetchone()
    assert legacy_after_add == (json.dumps(added["entries"]), "analyst")

    challenge = issue_delete_challenge(
        "global-no-strike", "203.0.113.9/32"
    )["challenge"]
    removed = remove_global_no_strike(
        NoStrikeRemoval(
            entries=["203.0.113.9/32"],
            changed_by="admin",
            confirmation=challenge,
        ),
        db_path,
    )
    with sqlite3.connect(db_path) as db:
        legacy_after_remove = db.execute(
            "SELECT value_json, updated_by FROM app_settings WHERE key = 'global_no_strike'"
        ).fetchone()
    assert legacy_after_remove == (json.dumps(removed["entries"]), "admin")


def test_reupgrade_conservatively_merges_exclusions_added_by_older_version(tmp_path):
    db_path = tmp_path / "analyzer.db"
    add_global_no_strike(
        NoStrikeUpdate(entries=["203.0.113.9"], changed_by="analyst"), db_path
    )
    with sqlite3.connect(db_path) as db:
        db.execute(
            """
            UPDATE app_settings
            SET value_json = ?, updated_at = ?, updated_by = ?
            WHERE key = 'global_no_strike'
            """,
            (
                json.dumps(["203.0.113.9/32", "203.0.113.10/32"]),
                "2026-09-27T00:00:00+00:00",
                "legacy-operator",
            ),
        )
    poc._POC_STORAGE_READY.pop(str(db_path.resolve()), None)

    poc.init_poc_storage(db_path)
    state = get_global_no_strike(db_path)

    assert state["entries"] == ["203.0.113.9/32", "203.0.113.10/32"]
    assert state["revision"] == 2
    assert state["updated_by"] == "legacy-rollback-reconciliation"


def test_stale_removal_challenge_preserves_a_later_addition(tmp_path):
    db_path = tmp_path / "analyzer.db"
    add_global_no_strike(
        NoStrikeUpdate(entries=["192.0.2.1"], changed_by="admin"), db_path
    )
    challenge = issue_delete_challenge(
        "global-no-strike", "192.0.2.1/32"
    )["challenge"]
    add_global_no_strike(
        NoStrikeUpdate(entries=["192.0.2.2"], changed_by="analyst"), db_path
    )
    result = remove_global_no_strike(
        NoStrikeRemoval(
            entries=["192.0.2.1/32"], changed_by="admin", confirmation=challenge
        ),
        db_path,
    )

    assert result["entries"] == ["192.0.2.2/32"]
    assert result["revision"] == 3


def test_broad_global_no_strike_is_symbolic_and_can_stop_all_targets(tmp_path):
    db_path = tmp_path / "analyzer.db"
    saved = add_global_no_strike(
        NoStrikeUpdate(entries=["0.0.0.0/0"], changed_by="admin"), db_path
    )
    summary = scan_safety_summary(["203.0.113.0/30"], [], db_path)

    assert saved["entries"] == ["0.0.0.0/0"]
    assert summary["effective_address_count"] == 0
    assert summary["global_excluded_address_count"] == 4


def test_authenticated_actor_is_bound_and_only_admin_can_remove_global_rule(
    tmp_path, monkeypatch
):
    db_path = tmp_path / "analyzer.db"
    monkeypatch.setattr(poc, "DB_PATH", db_path)
    analyst_request = Request({"type": "http", "headers": []})
    analyst_request.state.analyst = {"username": "analyst.one", "role": "analyst"}
    saved = add_to_global_no_strike(
        NoStrikeUpdate(entries=["203.0.113.5"], changed_by="forged-name"),
        analyst_request,
    )
    assert saved["updated_by"] == "analyst.one"

    challenge = issue_delete_challenge(
        "global-no-strike", "203.0.113.5/32"
    )["challenge"]
    removal = NoStrikeRemoval(
        entries=["203.0.113.5/32"],
        changed_by="forged-name",
        confirmation=challenge,
    )
    with pytest.raises(HTTPException) as denied:
        remove_from_global_no_strike(removal, analyst_request)
    assert denied.value.status_code == 403

    admin_request = Request({"type": "http", "headers": []})
    admin_request.state.analyst = {"username": "admin.one", "role": "admin"}
    removed = remove_from_global_no_strike(removal, admin_request)
    assert removed["updated_by"] == "admin.one"
    assert removed["entries"] == []


def test_local_mode_ignores_client_supplied_safety_and_fallback_actor(
    tmp_path, monkeypatch
):
    db_path = tmp_path / "analyzer.db"
    monkeypatch.setattr(poc, "DB_PATH", db_path)
    local_request = Request({"type": "http", "headers": []})
    local_request.state.analyst = None
    saved = add_to_global_no_strike(
        NoStrikeUpdate(entries=["203.0.113.7"], changed_by="forged-remote-name"),
        local_request,
    )
    assert saved["updated_by"] == "local-operator"

    run_id = "c" * 32
    insert_scan_run_manifest(
        {
            "run_id": run_id,
            "created_at": "2026-09-27T00:00:00+00:00",
            "status": "awaiting_fallback_approval",
            "operator": "local-operator",
            "owner": "local-operator",
            "reason": "test",
            "originating_host": "test-host",
            "interface": "eth0",
            "profile": "Custom",
        },
        db_path,
    )
    control = RunControl()
    poc.ACTIVE_RUNS[run_id] = control
    try:
        decide_scan_fallback(
            run_id,
            FallbackDecision(
                decision="approve",
                decided_by="forged-remote-name",
                authorization_note="Authorized local test",
            ),
            local_request,
        )
        assert control.fallback_decided_by == "local-operator"
    finally:
        poc.ACTIVE_RUNS.pop(run_id, None)


def test_only_scan_owner_or_admin_can_decide_fallback(tmp_path, monkeypatch):
    db_path = tmp_path / "analyzer.db"
    monkeypatch.setattr(poc, "DB_PATH", db_path)
    run_id = "a" * 32
    manifest = {
        "run_id": run_id,
        "created_at": "2026-09-27T00:00:00+00:00",
        "status": "awaiting_fallback_approval",
        "operator": "owner.one",
        "owner": "owner.one",
        "reason": "test",
        "originating_host": "test-host",
        "interface": "eth0",
        "profile": "Custom",
    }
    insert_scan_run_manifest(manifest, db_path)
    control = RunControl()
    poc.ACTIVE_RUNS[run_id] = control
    decision = FallbackDecision(
        decision="approve", decided_by="forged", authorization_note="Authorized test"
    )
    other_request = Request({"type": "http", "headers": []})
    other_request.state.analyst = {"username": "other.one", "role": "analyst"}
    try:
        with pytest.raises(HTTPException) as denied:
            decide_scan_fallback(run_id, decision, other_request)
        assert denied.value.status_code == 403

        owner_request = Request({"type": "http", "headers": []})
        owner_request.state.analyst = {"username": "owner.one", "role": "analyst"}
        accepted = decide_scan_fallback(run_id, decision, owner_request)
        assert accepted["decision"] == "approve"
        assert control.fallback_decided_by == "owner.one"
    finally:
        poc.ACTIVE_RUNS.pop(run_id, None)


def test_new_global_rule_requests_cancellation_of_intersecting_active_run(tmp_path):
    db_path = tmp_path / "analyzer.db"
    run_id = "b" * 32
    manifest = {
        "run_id": run_id,
        "created_at": "2026-09-27T00:00:00+00:00",
        "status": "running",
        "operator": "owner.one",
        "owner": "owner.one",
        "reason": "test",
        "originating_host": "test-host",
        "interface": "eth0",
        "profile": "Custom",
        "targets": ["198.51.100.0/30"],
    }
    insert_scan_run_manifest(manifest, db_path)
    control = RunControl()
    poc.ACTIVE_RUNS[run_id] = control
    try:
        add_global_no_strike(
            NoStrikeUpdate(entries=["198.51.100.2"], changed_by="analyst"), db_path
        )
        assert control.cancel_event.is_set()
        updated = poc.get_scan_run_plan(run_id, db_path)
        assert updated["cancellation_cause"] == "global_no_strike"
        assert updated["safety_cancellation_requested"]["global_no_strike_revision"] == 1
        assert updated["safety_cancellation_requested"]["intersecting_exclusions"] == [
            "198.51.100.2/32"
        ]
        with connect_database(db_path, read_only=True) as db:
            event = db.execute(
                "SELECT event, actor, details FROM scan_run_audit WHERE run_id = ?",
                (run_id,),
            ).fetchone()
        assert event[0] == "safety_cancellation_requested"
        assert event[1] == "analyst"
        assert "revision 1" in event[2]
    finally:
        poc.ACTIVE_RUNS.pop(run_id, None)


def test_safety_signal_reaches_every_active_run_when_provenance_writes_fail(
    tmp_path, monkeypatch
):
    db_path = tmp_path / "analyzer.db"
    run_ids = ["d" * 32, "e" * 32]
    controls = {}
    for run_id in run_ids:
        insert_scan_run_manifest(
            {
                "run_id": run_id,
                "created_at": "2026-09-27T00:00:00+00:00",
                "status": "running",
                "operator": "owner.one",
                "owner": "owner.one",
                "reason": "test",
                "originating_host": "test-host",
                "interface": "eth0",
                "profile": "Custom",
                "targets": ["198.51.100.0/30"],
            },
            db_path,
        )
        controls[run_id] = RunControl()
        poc.ACTIVE_RUNS[run_id] = controls[run_id]
    monkeypatch.setattr(
        poc,
        "update_scan_run_manifest",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("write failed")),
    )
    monkeypatch.setattr(
        poc,
        "append_scan_audit",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("audit failed")),
    )
    try:
        saved = add_global_no_strike(
            NoStrikeUpdate(entries=["198.51.100.2"], changed_by="analyst"),
            db_path,
        )
        assert saved["entries"] == ["198.51.100.2/32"]
        assert all(control.cancel_event.is_set() for control in controls.values())
    finally:
        for run_id in run_ids:
            poc.ACTIVE_RUNS.pop(run_id, None)


def test_scheduled_manifest_keeps_global_and_schedule_exclusions_separate(tmp_path):
    db_path = tmp_path / "analyzer.db"
    add_global_no_strike(
        NoStrikeUpdate(entries=["192.0.2.1"], changed_by="analyst"), db_path
    )
    schedule = create_scan_schedule(
        ScanScheduleCreate(
            name="Safety provenance",
            created_by="analyst",
            profile_id="builtin-standard",
            profile_version=1,
            targets=["192.0.2.0/29"],
            no_strike=["192.0.2.2"],
            interface="eth0",
            cadence="daily",
            first_run_at=datetime(2026, 9, 28, tzinfo=timezone.utc),
        ),
        db_path,
    )
    request = poc._scheduled_request(
        schedule,
        ["192.0.2.0/29"],
        batch_id="c" * 32,
        chunk_number=1,
        chunk_count=1,
        batch_hosts_total=8,
        batch_hosts_completed_before=0,
        db_path=db_path,
    )
    manifest = poc.build_scan_run_manifest(request, db_path=db_path)

    assert manifest["coverage"]["global_no_strike"] == ["192.0.2.1/32"]
    assert manifest["coverage"]["additional_no_strike"] == ["192.0.2.2/32"]
    assert manifest["no_strike_submission"]["global"] == ["192.0.2.1/32"]
    assert manifest["no_strike_submission"]["additional"] == ["192.0.2.2/32"]
