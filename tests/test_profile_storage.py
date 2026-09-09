from __future__ import annotations

from app.poc import (
    ScanOptions,
    ScanProfileCreate,
    ScanProfileVersionCreate,
    ScanScheduleCreate,
    create_scan_profile,
    create_scan_profile_version,
    create_scan_schedule,
    get_scan_profile,
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
            cadence="weekly Monday 02:00 UTC",
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
    assert schedule["implementation_status"] == "definition_only"
