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
    delete_scan_profile,
    effective_no_strike,
    execute_schedule_batch,
    get_global_no_strike,
    get_scan_profile,
    issue_delete_challenge,
    NoStrikeRemoval,
    NoStrikeUpdate,
    remove_global_no_strike,
    schedule_target_chunks,
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
