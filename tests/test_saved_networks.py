from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import json
from pathlib import Path
import threading

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app import poc
from app.database import connect_database
from app.poc import (
    ScanRunMetadataConflict,
    ScanRunNetworkAttribution,
    ScanRunPlan,
    attribute_scan_run_networks,
    build_scan_run_manifest,
    get_scan_run_plan,
    group_scan_runs_by_saved_network,
    insert_scan_run_manifest,
)
from app.scan_collaboration import scan_audit_history
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
            saved_network_ids=[saved["saved_network_id"]],
            changed_by="reviewer",
            expected_metadata_revision=0,
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
            expected_metadata_revision=0,
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
                saved_network_ids=[saved["saved_network_id"]],
                changed_by="reviewer",
                expected_metadata_revision=0,
            ),
            db_path,
        )


@pytest.mark.parametrize(
    ("status", "execution_method", "scheduled"),
    [
        ("completed", "manual", False),
        ("completed", "imported", False),
        ("completed", "scheduled", True),
        ("interrupted", "manual", False),
    ],
)
def test_terminal_scan_attribution_ignores_expired_worker_claims_and_preserves_run_truth(
    tmp_path: Path, status: str, execution_method: str, scheduled: bool
):
    db_path = tmp_path / "analyzer.db"
    saved = create_network(db_path)
    plan = scan_plan(
        targets=[saved["cidr"]],
        scheduled=scheduled,
        scheduled_by="scheduler" if scheduled else None,
    )
    manifest = build_scan_run_manifest(plan, status=status, db_path=db_path)
    manifest["execution_method"] = execution_method
    manifest["execution_claim"] = {"lease_id": "expired-execution"}
    manifest["work_claim"] = {"lease_id": "expired-schedule"}
    manifest["evidence_receipt"] = {"sha256": "retained"}
    manifest["target_selection"]["review_note"] = "preserve this field"
    insert_scan_run_manifest(manifest, db_path)
    before = deepcopy(get_scan_run_plan(manifest["run_id"], db_path))

    updated = attribute_scan_run_networks(
        manifest["run_id"],
        ScanRunNetworkAttribution(
            saved_network_ids=[saved["saved_network_id"]],
            changed_by="owner",
            expected_metadata_revision=0,
        ),
        db_path,
        actor="operator",
        role="analyst",
    )

    allowed = {
        "saved_network_ids",
        "saved_networks",
        "manual_targets",
        "target_selection",
        "network_attribution_changed_at",
        "network_attribution_changed_by",
        "network_attribution_history",
        "metadata_revision",
    }
    assert {key: value for key, value in updated.items() if key not in allowed} == {
        key: value for key, value in before.items() if key not in allowed
    }
    assert updated["target_selection"]["review_note"] == "preserve this field"
    assert updated["execution_claim"] == before["execution_claim"]
    assert updated["work_claim"] == before["work_claim"]
    assert updated["metadata_revision"] == 1
    assert updated["network_attribution_changed_by"] == "operator"
    audit = scan_audit_history(db_path, manifest["run_id"])
    assert audit[0]["event"] == "network_attribution_changed"
    assert audit[0]["actor"] == "operator"
    with connect_database(db_path) as db:
        membership = db.execute(
            "SELECT kind, name, cidr FROM scan_history_memberships WHERE run_id = ?",
            (manifest["run_id"],),
        ).fetchone()
        dirty = db.execute(
            "SELECT 1 FROM scan_history_index_dirty WHERE run_id = ?",
            (manifest["run_id"],),
        ).fetchone()
    assert tuple(membership) == ("subnet", saved["name"], saved["cidr"])
    assert dirty is None


@pytest.mark.parametrize(
    "status",
    ["planned", "queued", "dispatching", "running", "awaiting_fallback_approval", "recovering", "future_state"],
)
def test_active_or_unknown_scan_state_rejects_historical_attribution(
    tmp_path: Path, status: str
):
    db_path = tmp_path / "analyzer.db"
    saved = create_network(db_path)
    manifest = build_scan_run_manifest(
        scan_plan(targets=[saved["cidr"]]), status=status, db_path=db_path
    )
    insert_scan_run_manifest(manifest, db_path)

    with pytest.raises(ValueError, match="only after the scan has stopped"):
        attribute_scan_run_networks(
            manifest["run_id"],
            ScanRunNetworkAttribution(
                saved_network_ids=[saved["saved_network_id"]],
                changed_by="operator",
                expected_metadata_revision=0,
            ),
            db_path,
        )


@pytest.mark.parametrize("bad_revision", [-1, True, "0", 1.5, None])
def test_malformed_retained_metadata_revision_is_rejected(
    tmp_path: Path, bad_revision
):
    db_path = tmp_path / "analyzer.db"
    saved = create_network(db_path)
    manifest = build_scan_run_manifest(
        scan_plan(targets=[saved["cidr"]]), status="completed", db_path=db_path
    )
    manifest["metadata_revision"] = bad_revision
    insert_scan_run_manifest(manifest, db_path)

    with pytest.raises(ScanRunMetadataConflict, match="invalid historical-context"):
        attribute_scan_run_networks(
            manifest["run_id"],
            ScanRunNetworkAttribution(
                saved_network_ids=[saved["saved_network_id"]],
                changed_by="operator",
                expected_metadata_revision=0,
            ),
            db_path,
        )


def test_legacy_revision_zero_accepts_once_then_requires_current_revision(tmp_path: Path):
    db_path = tmp_path / "analyzer.db"
    saved = create_network(db_path)
    manifest = build_scan_run_manifest(
        scan_plan(targets=[saved["cidr"]]), status="completed", db_path=db_path
    )
    manifest.pop("metadata_revision")
    insert_scan_run_manifest(manifest, db_path)
    request = ScanRunNetworkAttribution(
        saved_network_ids=[saved["saved_network_id"]],
        changed_by="operator",
        expected_metadata_revision=0,
    )

    first = attribute_scan_run_networks(manifest["run_id"], request, db_path)
    assert first["metadata_revision"] == 1
    with pytest.raises(ScanRunMetadataConflict, match="Another analyst changed"):
        attribute_scan_run_networks(manifest["run_id"], request, db_path)
    second = attribute_scan_run_networks(
        manifest["run_id"],
        request.model_copy(update={"expected_metadata_revision": 1}),
        db_path,
    )
    assert second["metadata_revision"] == 2


def test_only_one_simultaneous_historical_attribution_wins(tmp_path: Path):
    db_path = tmp_path / "analyzer.db"
    saved = create_network(db_path)
    manifest = build_scan_run_manifest(
        scan_plan(targets=[saved["cidr"]]), status="completed", db_path=db_path
    )
    insert_scan_run_manifest(manifest, db_path)
    barrier = threading.Barrier(2)

    def apply_once():
        barrier.wait()
        try:
            return attribute_scan_run_networks(
                manifest["run_id"],
                ScanRunNetworkAttribution(
                    saved_network_ids=[saved["saved_network_id"]],
                    changed_by="operator",
                    expected_metadata_revision=0,
                ),
                db_path,
            )["metadata_revision"]
        except ScanRunMetadataConflict:
            return "conflict"

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _item: apply_once(), range(2)))
    assert sorted(results, key=str) == [1, "conflict"]


def test_historical_attribution_rechecks_current_owner_inside_transaction(tmp_path: Path):
    db_path = tmp_path / "analyzer.db"
    saved = create_network(db_path)
    manifest = build_scan_run_manifest(
        scan_plan(targets=[saved["cidr"]]), status="completed", db_path=db_path
    )
    insert_scan_run_manifest(manifest, db_path)
    with connect_database(db_path) as db:
        retained = json.loads(
            db.execute(
                "SELECT manifest_json FROM scan_runs WHERE run_id = ?",
                (manifest["run_id"],),
            ).fetchone()[0]
        )
        retained["owner"] = "new-owner"
        db.execute(
            "UPDATE scan_runs SET manifest_json = ? WHERE run_id = ?",
            (json.dumps(retained, sort_keys=True), manifest["run_id"]),
        )

    with pytest.raises(PermissionError, match="scan owner"):
        attribute_scan_run_networks(
            manifest["run_id"],
            ScanRunNetworkAttribution(
                saved_network_ids=[saved["saved_network_id"]],
                changed_by="old-owner",
                expected_metadata_revision=0,
            ),
            db_path,
            actor="old-owner",
            role="analyst",
        )
    admin = attribute_scan_run_networks(
        manifest["run_id"],
        ScanRunNetworkAttribution(
            saved_network_ids=[saved["saved_network_id"]],
            changed_by="administrator",
            expected_metadata_revision=0,
        ),
        db_path,
        actor="administrator",
        role="admin",
    )
    assert admin["network_attribution_changed_by"] == "administrator"


def test_history_index_failure_rolls_back_manifest_and_audit(tmp_path: Path, monkeypatch):
    db_path = tmp_path / "analyzer.db"
    saved = create_network(db_path)
    manifest = build_scan_run_manifest(
        scan_plan(targets=[saved["cidr"]]), status="completed", db_path=db_path
    )
    insert_scan_run_manifest(manifest, db_path)
    before = get_scan_run_plan(manifest["run_id"], db_path)
    monkeypatch.setattr(
        poc,
        "sync_scan_history_manifest",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("index failure")),
    )

    with pytest.raises(RuntimeError, match="index failure"):
        attribute_scan_run_networks(
            manifest["run_id"],
            ScanRunNetworkAttribution(
                saved_network_ids=[saved["saved_network_id"]],
                changed_by="operator",
                expected_metadata_revision=0,
            ),
            db_path,
        )
    after = get_scan_run_plan(manifest["run_id"], db_path)
    assert after["metadata_revision"] == before["metadata_revision"] == 0
    assert after["saved_network_ids"] == before["saved_network_ids"]
    assert scan_audit_history(db_path, manifest["run_id"]) == []
    with connect_database(db_path) as db:
        assert db.execute(
            "SELECT 1 FROM scan_history_index_dirty WHERE run_id = ?",
            (manifest["run_id"],),
        ).fetchone() is None


def test_audit_failure_rolls_back_manifest_and_history_index(tmp_path: Path):
    db_path = tmp_path / "analyzer.db"
    saved = create_network(db_path)
    manifest = build_scan_run_manifest(
        scan_plan(targets=[saved["cidr"]]), status="completed", db_path=db_path
    )
    insert_scan_run_manifest(manifest, db_path)
    with connect_database(db_path) as db:
        before_memberships = db.execute(
            "SELECT group_id, kind, name, cidr FROM scan_history_memberships WHERE run_id = ? ORDER BY group_id",
            (manifest["run_id"],),
        ).fetchall()
        db.execute(
            """CREATE TRIGGER reject_attribution_audit
               BEFORE INSERT ON scan_run_audit
               WHEN NEW.event = 'network_attribution_changed'
               BEGIN SELECT RAISE(ABORT, 'audit failure'); END"""
        )

    with pytest.raises(Exception, match="audit failure"):
        attribute_scan_run_networks(
            manifest["run_id"],
            ScanRunNetworkAttribution(
                saved_network_ids=[saved["saved_network_id"]],
                changed_by="operator",
                expected_metadata_revision=0,
            ),
            db_path,
        )
    retained = get_scan_run_plan(manifest["run_id"], db_path)
    assert retained["metadata_revision"] == 0
    assert retained["saved_network_ids"] == []
    with connect_database(db_path) as db:
        after_memberships = db.execute(
            "SELECT group_id, kind, name, cidr FROM scan_history_memberships WHERE run_id = ? ORDER BY group_id",
            (manifest["run_id"],),
        ).fetchall()
    assert after_memberships == before_memberships
    assert scan_audit_history(db_path, manifest["run_id"]) == []


def test_attribution_endpoint_keeps_stale_conflict_until_current_revision_is_reopened(
    tmp_path: Path, monkeypatch
):
    db_path = tmp_path / "analyzer.db"
    saved = create_network(db_path)
    manifest = build_scan_run_manifest(
        scan_plan(targets=[saved["cidr"]]), status="completed", db_path=db_path
    )
    insert_scan_run_manifest(manifest, db_path)
    monkeypatch.setattr(poc, "DB_PATH", db_path)
    api = FastAPI()
    api.include_router(poc.router)
    payload = {
        "saved_network_ids": [saved["saved_network_id"]],
        "changed_by": "client-supplied-name",
        "expected_metadata_revision": 0,
    }

    with TestClient(api) as client:
        first = client.put(
            f"/api/scan-runs/{manifest['run_id']}/network-attribution", json=payload
        )
        assert first.status_code == 200
        assert first.json()["metadata_revision"] == 1
        assert first.json()["network_attribution_changed_by"] == "local-operator"

        stale = client.put(
            f"/api/scan-runs/{manifest['run_id']}/network-attribution", json=payload
        )
        assert stale.status_code == 409
        assert "Your choice was not saved" in stale.json()["detail"]
        assert "reopen Review network context" in stale.json()["detail"]

        payload["expected_metadata_revision"] = get_scan_run_plan(
            manifest["run_id"], db_path
        )["metadata_revision"]
        current = client.put(
            f"/api/scan-runs/{manifest['run_id']}/network-attribution", json=payload
        )
        assert current.status_code == 200
        assert current.json()["metadata_revision"] == 2
