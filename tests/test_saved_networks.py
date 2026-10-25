from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import threading

import pytest

from app.poc import (
    ScanRunNetworkAttribution,
    ScanRunPlan,
    attribute_scan_run_networks,
    build_scan_run_manifest,
    get_scan_run_plan,
    group_scan_runs_by_saved_network,
    insert_scan_run_manifest,
)
from app.saved_networks import (
    SavedNetworkArchive,
    SavedNetworkCreate,
    SavedNetworkUpdate,
    archive_saved_network,
    create_saved_network,
    get_saved_network,
    list_saved_networks,
    update_saved_network,
)


def create_network(
    db_path: Path,
    *,
    name: str = "Lab",
    cidr: str = "192.0.2.7/30",
) -> dict:
    return create_saved_network(
        SavedNetworkCreate(
            name=name,
            cidr=cidr,
            description="Authorized lab segment",
            category="Lab",
            tags=["training", "Training", "blue"],
            created_by="operator",
        ),
        db_path,
    )


def scan_plan(**values) -> ScanRunPlan:
    return ScanRunPlan(
        operator="operator",
        name="Saved Network validation",
        reason="Authorized test",
        originating_host="test-host",
        interface="eth0",
        profile="Quick Discovery",
        profile_id="builtin-quick-discovery",
        profile_version=1,
        **values,
    )


def test_saved_network_normalizes_cidr_tags_and_warns_on_overlap(tmp_path: Path):
    db_path = tmp_path / "analyzer.db"
    parent = create_network(db_path)

    assert parent["cidr"] == "192.0.2.4/30"
    assert parent["tags"] == ["training", "blue"]
    assert parent["warnings"][0]["type"] == "normalized"

    child = create_network(db_path, name="Host", cidr="192.0.2.5/32")
    assert child["warnings"][0]["type"] == "overlap"
    assert child["warnings"][0]["saved_network_id"] == parent["saved_network_id"]


def test_saved_network_rejects_invalid_and_duplicate_values(tmp_path: Path):
    db_path = tmp_path / "analyzer.db"
    create_network(db_path)

    with pytest.raises(ValueError, match="name"):
        create_network(db_path, name="lab", cidr="198.51.100.0/24")
    with pytest.raises(ValueError, match="CIDR"):
        create_network(db_path, name="Different", cidr="192.0.2.4/30")
    with pytest.raises(ValueError, match="Invalid IPv4 CIDR"):
        create_network(db_path, name="Invalid", cidr="not-a-network")
    with pytest.raises(ValueError, match="IPv4 only"):
        create_network(db_path, name="IPv6", cidr="2001:db8::/64")
    with pytest.raises(ValueError, match="blank"):
        create_network(db_path, name="   ", cidr="198.51.100.0/24")


def test_saved_network_can_be_updated_and_archived_without_deletion(tmp_path: Path):
    db_path = tmp_path / "analyzer.db"
    record = create_network(db_path)

    updated = update_saved_network(
        record["saved_network_id"],
        SavedNetworkUpdate(
            name="Lab West",
            description="Updated description",
            category="Training",
            tags=["west"],
            expected_updated_at=record["updated_at"],
            updated_by="reviewer",
        ),
        db_path,
    )
    assert updated["name"] == "Lab West"
    assert updated["updated_by"] == "reviewer"

    with pytest.raises(RuntimeError, match="changed in another session"):
        update_saved_network(
            record["saved_network_id"],
            SavedNetworkUpdate(
                name="Stale overwrite",
                expected_updated_at=record["updated_at"],
                updated_by="other-reviewer",
            ),
            db_path,
        )
    assert get_saved_network(record["saved_network_id"], db_path)["name"] == "Lab West"

    archived = archive_saved_network(
        record["saved_network_id"],
        SavedNetworkArchive(changed_by="reviewer"),
        db_path,
    )
    assert archived["active"] is False
    assert list_saved_networks(db_path) == []
    assert list_saved_networks(db_path, include_archived=True)[0]["name"] == "Lab West"


def test_concurrent_saved_network_edits_with_one_token_allow_only_one_writer(
    tmp_path: Path,
):
    db_path = tmp_path / "analyzer.db"
    record = create_network(db_path)
    start = threading.Barrier(2)

    def attempt(name: str) -> tuple[str, str]:
        start.wait(timeout=5)
        try:
            updated = update_saved_network(
                record["saved_network_id"],
                SavedNetworkUpdate(
                    name=name,
                    expected_updated_at=record["updated_at"],
                    updated_by=name,
                ),
                db_path,
            )
            return "updated", updated["name"]
        except RuntimeError as exc:
            return "conflict", str(exc)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(attempt, ["First analyst", "Second analyst"]))

    assert [result[0] for result in results].count("updated") == 1
    assert [result[0] for result in results].count("conflict") == 1
    winner = next(result[1] for result in results if result[0] == "updated")
    assert get_saved_network(record["saved_network_id"], db_path)["name"] == winner


def test_archived_network_does_not_invisibly_reserve_name_or_cidr(tmp_path: Path):
    db_path = tmp_path / "analyzer.db"
    original = create_network(db_path)
    archive_saved_network(
        original["saved_network_id"],
        SavedNetworkArchive(changed_by="reviewer"),
        db_path,
    )

    replacement = create_network(db_path, name="Lab", cidr="192.0.2.4/30")

    assert replacement["saved_network_id"] != original["saved_network_id"]
    assert replacement["active"] is True
    assert len(list_saved_networks(db_path, include_archived=True)) == 2


def test_saved_manual_and_combined_targets_use_the_same_execution_scope(tmp_path: Path):
    db_path = tmp_path / "analyzer.db"
    saved = create_network(db_path)

    saved_only = build_scan_run_manifest(
        scan_plan(saved_network_ids=[saved["saved_network_id"]]), db_path=db_path
    )
    browser_saved_only = build_scan_run_manifest(
        scan_plan(
            targets=[saved["cidr"]],
            saved_network_ids=[saved["saved_network_id"]],
            manual_targets=[],
        ),
        db_path=db_path,
    )
    manual_only = build_scan_run_manifest(
        scan_plan(targets=["192.0.2.4/30"]), db_path=db_path
    )
    assert saved_only["targets"] == manual_only["targets"] == ["192.0.2.4/30"]
    assert browser_saved_only["targets"] == saved_only["targets"]
    assert browser_saved_only["manual_targets"] == []
    assert saved_only["saved_networks"][0]["name"] == "Lab"
    assert manual_only["saved_networks"] == []

    combined = build_scan_run_manifest(
        scan_plan(
            saved_network_ids=[saved["saved_network_id"]],
            manual_targets=["198.51.100.7/30"],
        ),
        db_path=db_path,
    )
    equivalent_manual = build_scan_run_manifest(
        scan_plan(targets=["192.0.2.4/30", "198.51.100.4/30"]),
        db_path=db_path,
    )
    assert combined["targets"] == equivalent_manual["targets"]
    assert combined["manual_targets"] == ["198.51.100.4/30"]
    assert combined["target_selection"]["saved_networks"][0]["cidr"] == "192.0.2.4/30"


def test_archived_saved_network_cannot_start_a_new_scan(tmp_path: Path):
    db_path = tmp_path / "analyzer.db"
    saved = create_network(db_path)
    archive_saved_network(
        saved["saved_network_id"],
        SavedNetworkArchive(changed_by="operator"),
        db_path,
    )

    with pytest.raises(ValueError, match="archived"):
        build_scan_run_manifest(
            scan_plan(saved_network_ids=[saved["saved_network_id"]]), db_path=db_path
        )


def test_scan_history_groups_preserve_saved_network_snapshots():
    saved_run = {
        "run_id": "a" * 32,
        "name": "Servers baseline",
        "created_at": "2026-09-10T10:00:00+00:00",
        "completed_at": "2026-09-10T10:10:00+00:00",
        "host_count": 12,
        "saved_networks": [{
            "saved_network_id": "servers-id",
            "name": "Mission Servers",
            "cidr": "10.10.10.0/24",
            "description": "Historical snapshot",
            "category": "Mission",
            "tags": ["servers"],
        }],
    }
    newer_saved_run = {
        **saved_run,
        "run_id": "b" * 32,
        "created_at": "2026-09-11T10:00:00+00:00",
        "completed_at": "2026-09-11T10:08:00+00:00",
        "host_count": 14,
    }
    multi_run = {
        "run_id": "c" * 32,
        "created_at": "2026-09-11T11:00:00+00:00",
        "host_count": 20,
        "saved_networks": [
            saved_run["saved_networks"][0],
            {
                "saved_network_id": "users-id",
                "name": "Mission Users",
                "cidr": "10.10.20.0/24",
            },
        ],
    }
    manual_run = {
        "run_id": "d" * 32,
        "created_at": "2026-09-11T12:00:00+00:00",
        "host_count": 3,
        "manual_targets": ["192.0.2.0/29"],
    }

    groups = group_scan_runs_by_saved_network(
        [manual_run, multi_run, newer_saved_run, saved_run]
    )

    assert [group["kind"] for group in groups] == [
        "saved_network",
        "multiple_saved_networks",
        "manual",
    ]
    saved_group = groups[0]
    assert saved_group["name"] == "Mission Servers"
    assert saved_group["cidr"] == "10.10.10.0/24"
    assert saved_group["scan_count"] == 2
    assert saved_group["latest_host_count"] == 14
    assert saved_group["runs"][0]["run_id"] == "b" * 32
    assert groups[1]["scan_count"] == 1
    assert groups[2]["name"] == "Ad Hoc / Manual Scans"


def test_completed_manual_scan_can_be_attributed_to_an_exact_saved_network(tmp_path: Path):
    db_path = tmp_path / "analyzer.db"
    saved = create_network(db_path)
    manifest = build_scan_run_manifest(
        scan_plan(targets=[saved["cidr"]]), status="completed", db_path=db_path
    )
    insert_scan_run_manifest(manifest, db_path)

    updated = attribute_scan_run_networks(
        manifest["run_id"],
        ScanRunNetworkAttribution(
            saved_network_ids=[saved["saved_network_id"]], changed_by="reviewer"
        ),
        db_path,
    )

    assert updated["saved_networks"][0]["name"] == "Lab"
    assert updated["manual_targets"] == []
    assert updated["targets"] == [saved["cidr"]]
    assert updated["network_attribution_history"][0]["changed_by"] == "reviewer"
    assert group_scan_runs_by_saved_network([updated])[0]["kind"] == "saved_network"


def test_saved_network_rename_does_not_rewrite_scan_snapshot_until_explicit_attribution(
    tmp_path: Path,
):
    db_path = tmp_path / "analyzer.db"
    saved = create_network(db_path, name="Original subnet name")
    manifest = build_scan_run_manifest(
        scan_plan(saved_network_ids=[saved["saved_network_id"]]),
        status="completed",
        db_path=db_path,
    )
    insert_scan_run_manifest(manifest, db_path)
    original_targets = list(manifest["targets"])
    original_scope = manifest.get("network_scope_context")

    renamed = update_saved_network(
        saved["saved_network_id"],
        SavedNetworkUpdate(
            name="Current subnet name",
            expected_updated_at=saved["updated_at"],
            updated_by="network-admin",
        ),
        db_path,
    )
    retained = get_scan_run_plan(manifest["run_id"], db_path)

    assert renamed["name"] == "Current subnet name"
    assert retained["saved_networks"][0]["name"] == "Original subnet name"
    assert retained["targets"] == original_targets
    assert retained.get("network_scope_context") == original_scope

    reviewed = attribute_scan_run_networks(
        manifest["run_id"],
        ScanRunNetworkAttribution(
            saved_network_ids=[saved["saved_network_id"]],
            changed_by="history-reviewer",
        ),
        db_path,
    )

    assert reviewed["saved_networks"][0]["name"] == "Current subnet name"
    assert reviewed["network_attribution_history"][-1]["previous_saved_networks"][0][
        "name"
    ] == "Original subnet name"
    assert reviewed["targets"] == original_targets
    assert reviewed.get("network_scope_context") == original_scope


def test_scan_attribution_rejects_a_saved_network_outside_executed_scope(tmp_path: Path):
    db_path = tmp_path / "analyzer.db"
    saved = create_network(db_path)
    manifest = build_scan_run_manifest(
        scan_plan(targets=["198.51.100.0/24"]), status="completed", db_path=db_path
    )
    insert_scan_run_manifest(manifest, db_path)

    with pytest.raises(ValueError, match="not an exact target"):
        attribute_scan_run_networks(
            manifest["run_id"],
            ScanRunNetworkAttribution(
                saved_network_ids=[saved["saved_network_id"]], changed_by="reviewer"
            ),
            db_path,
        )
