from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import pytest

from app.database import connect_database
from app.poc import (
    ScanOptions,
    ScanProfileClone,
    ScanProfileCreate,
    ScanProfileDependencyError,
    ScanProfileVersionCreate,
    ScanScheduleCreate,
    ScheduleProfileChange,
    change_scan_schedule_profile,
    clone_scan_profile,
    create_scan_profile,
    create_scan_profile_version,
    create_scan_schedule,
    delete_scan_profile,
    get_scan_profile,
    issue_delete_challenge,
    scan_profile_delete_review,
)


def profile_request(token: str, *, name: str = "Mission profile") -> ScanProfileCreate:
    return ScanProfileCreate(
        name=name,
        created_by="analyst01",
        settings=ScanOptions(protocol="tcp", tcp_scope="common"),
        request_token=token,
    )


def test_repeated_concurrent_profile_create_returns_one_durable_result(tmp_path):
    db_path = tmp_path / "analyzer.db"
    request = profile_request("create-repeat-profile-0001")

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _index: create_scan_profile(request, db_path), range(2)))

    assert {item["profile_id"] for item in results} == {results[0]["profile_id"]}
    assert {item["request_replayed"] for item in results} == {False, True}
    with connect_database(db_path) as db:
        custom_profiles = db.execute(
            "SELECT COUNT(*) FROM scan_profiles WHERE built_in = 0"
        ).fetchone()[0]
        receipts = db.execute(
            "SELECT COUNT(*) FROM app_settings WHERE key LIKE 'scan_profile_mutation:v1:%'"
        ).fetchone()[0]
    assert custom_profiles == 1
    assert receipts == 1


def test_profile_request_token_rejects_changed_content_or_actor(tmp_path):
    db_path = tmp_path / "analyzer.db"
    token = "create-conflict-profile-0001"
    create_scan_profile(profile_request(token), db_path)

    with pytest.raises(RuntimeError, match="different work"):
        create_scan_profile(profile_request(token, name="Different profile"), db_path)
    with pytest.raises(RuntimeError, match="different work"):
        create_scan_profile(
            ScanProfileCreate(
                name="Mission profile",
                created_by="analyst02",
                settings=ScanOptions(protocol="tcp", tcp_scope="common"),
                request_token=token,
            ),
            db_path,
        )


def test_concurrent_new_versions_require_the_reviewed_base_version(tmp_path):
    db_path = tmp_path / "analyzer.db"
    profile = create_scan_profile(
        profile_request("create-version-base-profile-0001"), db_path
    )
    requests = [
        ScanProfileVersionCreate(
            created_by="analyst01",
            description="First concurrent request",
            settings=ScanOptions(protocol="tcp", tcp_scope="top_1000"),
            expected_version=1,
            request_token="version-concurrent-request-0001",
        ),
        ScanProfileVersionCreate(
            created_by="analyst02",
            description="Second concurrent request",
            settings=ScanOptions(protocol="tcp_udp", tcp_scope="common", udp_scope="common"),
            expected_version=1,
            request_token="version-concurrent-request-0002",
        ),
    ]

    def attempt(request):
        try:
            return "saved", request, create_scan_profile_version(
                profile["profile_id"], request, db_path
            )
        except RuntimeError as exc:
            return "conflict", request, str(exc)

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(attempt, requests))

    saved = [item for item in outcomes if item[0] == "saved"]
    conflicts = [item for item in outcomes if item[0] == "conflict"]
    assert len(saved) == 1
    assert len(conflicts) == 1
    assert "changed from v1 to v2" in conflicts[0][2]
    assert saved[0][2]["version"] == 2

    replay = create_scan_profile_version(profile["profile_id"], saved[0][1], db_path)
    assert replay["version"] == 2
    assert replay["request_replayed"] is True
    with connect_database(db_path) as db:
        assert db.execute(
            "SELECT COUNT(*) FROM scan_profiles WHERE profile_id = ?",
            (profile["profile_id"],),
        ).fetchone()[0] == 2


def test_clone_retry_preserves_exact_source_provenance(tmp_path):
    db_path = tmp_path / "analyzer.db"
    source = create_scan_profile(
        profile_request("create-clone-source-profile-0001", name="Known baseline"),
        db_path,
    )
    request = ScanProfileClone(
        name="Mission copy",
        created_by="analyst01",
        source_version=1,
        request_token="clone-baseline-profile-request-0001",
    )

    first = clone_scan_profile(source["profile_id"], request, db_path)
    replay = clone_scan_profile(source["profile_id"], request, db_path)

    assert replay["profile_id"] == first["profile_id"]
    assert replay["request_replayed"] is True
    assert first["source_profile_id"] == source["profile_id"]
    assert first["source_profile_version"] == 1


def test_delete_review_names_paused_old_version_schedule_and_rechecks_at_delete(tmp_path):
    db_path = tmp_path / "analyzer.db"
    profile = create_scan_profile(
        profile_request("create-delete-review-profile-0001", name="Temporary profile"),
        db_path,
    )
    create_scan_profile_version(
        profile["profile_id"],
        ScanProfileVersionCreate(
            created_by="analyst01",
            description="Second version",
            settings=ScanOptions(protocol="tcp", tcp_scope="top_1000"),
            expected_version=1,
            request_token="version-delete-review-profile-0001",
        ),
        db_path,
    )
    challenge = issue_delete_challenge("profile", profile["profile_id"])["challenge"]
    schedule = create_scan_schedule(
        ScanScheduleCreate(
            name="Paused weekly perimeter check",
            created_by="analyst01",
            profile_id=profile["profile_id"],
            profile_version=1,
            targets=["192.0.2.0/30"],
            interface="eth0",
            cadence="weekly",
            first_run_at=datetime(2026, 10, 26, 2, 0, tzinfo=timezone.utc),
            enabled=False,
        ),
        db_path,
    )

    review = scan_profile_delete_review(profile["profile_id"], db_path)
    assert review["deletable"] is False
    assert review["version_count"] == 2
    assert review["blocking_schedules"] == [
        {
            "schedule_id": schedule["schedule_id"],
            "name": "Paused weekly perimeter check",
            "profile_version": 1,
            "enabled": False,
        }
    ]
    with pytest.raises(ScanProfileDependencyError, match="Paused weekly perimeter check"):
        delete_scan_profile(profile["profile_id"], challenge, db_path)

    change_scan_schedule_profile(
        schedule["schedule_id"],
        ScheduleProfileChange(
            profile_id="builtin-standard",
            profile_version=1,
            changed_by="analyst01",
        ),
        db_path,
    )
    deleted = delete_scan_profile(profile["profile_id"], challenge, db_path)
    assert deleted["versions_removed"] == 2
    assert deleted["retained_history_preserved"] is True
    assert get_scan_profile(profile["profile_id"], db_path=db_path) is None


def test_builtin_profile_delete_review_is_protected(tmp_path):
    review = scan_profile_delete_review("builtin-standard", tmp_path / "analyzer.db")
    assert review["built_in"] is True
    assert review["deletable"] is False
