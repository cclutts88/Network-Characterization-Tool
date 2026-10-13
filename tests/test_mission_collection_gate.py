from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

import app.main as main
import app.poc as poc
from app.database import connect_database
from app.mission_environment import (
    MissionEnvironmentConflict,
    MissionEnvironmentProhibited,
    resolve_collection_mission_review,
    update_mission_tool,
    update_scope_context,
)
from app.network_scopes import create_network_scope
from app.poc import (
    ScanOptions,
    ScanRunRequest,
    ScanScheduleCreate,
    create_scan_schedule,
    dispatch_due_schedules,
    execute_scan_run,
    get_scan_run_plan,
    get_scan_schedule,
    init_poc_storage,
    prepare_scan_run,
    prepare_schedule_occurrence,
    set_scan_schedule_enabled,
)
from app.saved_network_scope_associations import (
    change_saved_network_scope_association,
)
from app.saved_networks import SavedNetworkCreate, create_saved_network


def reviewed_network(db_path, *, label="Engineering", cidr="192.0.2.0/30",
                     authorization="authorized", arkime_coverage="unknown"):
    init_poc_storage(db_path)
    network = create_saved_network(
        SavedNetworkCreate(name=f"{label} subnet", cidr=cidr, created_by="analyst"),
        db_path,
    )
    scope = create_network_scope(
        db_path, label=label, created_by="admin", reason="Reviewed mission scope",
    )
    association = change_saved_network_scope_association(
        db_path,
        network["saved_network_id"],
        scope_id=scope["scope_id"],
        expected_association_id=None,
        expected_revision=None,
        actor="analyst",
        reason="Select reviewed mission context",
    )
    mission = update_scope_context(
        db_path,
        scope["scope_id"],
        expected_version=0,
        nmap_coverage="available",
        arkime_coverage=arkime_coverage,
        kibana_coverage="unknown",
        config_coverage="unknown",
        nmap_authorization=authorization,
        device_evidence="unknown",
        blind_spots=[],
        notes="Reviewed for collection admission",
        actor="admin",
        reason="Record mission collection context",
    )
    return network, scope, association, mission


def active_request(network, association, mission):
    return ScanRunRequest(
        operator="analyst",
        created_by="analyst",
        name="Mission gate test",
        originating_host="nct-test",
        interface="eth0",
        profile="Standard",
        profile_id="builtin-standard",
        profile_version=2,
        targets=[network["cidr"]],
        manual_targets=[],
        saved_network_ids=[network["saved_network_id"]],
        reviewed_scope_associations=[{
            "association_id": association["association_id"],
            "revision": association["revision"],
        }],
        reviewed_mission_scopes=[{
            "scope_id": mission["scope_id"],
            "version": mission["version"],
        }],
        capture=True,
        timeout_seconds=30,
    )


def schedule_request(network, association, mission, *, enabled=False):
    return ScanScheduleCreate(
        name="Mission gate schedule",
        created_by="analyst",
        profile_id="builtin-standard",
        profile_version=2,
        targets=[network["cidr"]],
        manual_targets=[],
        saved_network_ids=[network["saved_network_id"]],
        reviewed_scope_associations=[{
            "association_id": association["association_id"],
            "revision": association["revision"],
        }],
        reviewed_mission_scopes=[{
            "scope_id": mission["scope_id"],
            "version": mission["version"],
        }],
        interface="eth0",
        first_run_at=datetime.now(timezone.utc) + timedelta(hours=1),
        enabled=enabled,
    )


def test_exact_scope_review_passes_and_manual_overlap_stays_unknown(tmp_path):
    db_path = tmp_path / "analyzer.db"
    network, _scope, _association, mission = reviewed_network(db_path)
    with connect_database(db_path) as db:
        db.execute("BEGIN IMMEDIATE")
        reviewed = resolve_collection_mission_review(
            db,
            saved_network_ids=[network["saved_network_id"]],
            manual_targets=[],
            reviewed_scopes=[{
                "scope_id": mission["scope_id"], "version": mission["version"],
            }],
        )
        manual = resolve_collection_mission_review(
            db,
            saved_network_ids=[],
            manual_targets=[network["cidr"]],
            reviewed_scopes=[],
        )

    assert reviewed["decision"] == "reviewed"
    assert reviewed["scopes"][0]["scope_id"] == mission["scope_id"]
    assert manual["decision"] == "unknown"
    assert manual["scopes"] == []
    assert manual["manual_targets_unknown"] is True


def test_stale_review_and_any_prohibited_scope_block_before_run_insert(tmp_path):
    db_path = tmp_path / "analyzer.db"
    network, _scope, association, mission = reviewed_network(
        db_path, authorization="prohibited",
    )
    request = active_request(network, association, mission)

    with pytest.raises(MissionEnvironmentProhibited, match="prohibited"):
        prepare_scan_run(request, db_path, interfaces={"eth0"})
    with connect_database(db_path) as db:
        assert db.execute("SELECT COUNT(*) FROM scan_runs").fetchone()[0] == 0

    stale = ScanRunRequest.model_validate({
        **request.model_dump(),
        "reviewed_mission_scopes": [{
            "scope_id": mission["scope_id"], "version": 0,
        }],
    })
    with pytest.raises(MissionEnvironmentConflict, match="changed after review"):
        prepare_scan_run(stale, db_path, interfaces={"eth0"})
    with connect_database(db_path) as db:
        assert db.execute("SELECT COUNT(*) FROM scan_runs").fetchone()[0] == 0


def test_passive_pivot_requires_available_tool_and_scope_coverage(tmp_path):
    db_path = tmp_path / "analyzer.db"
    network, _scope, _association, mission = reviewed_network(
        db_path, arkime_coverage="partial",
    )
    with connect_database(db_path) as db:
        db.execute("BEGIN IMMEDIATE")
        before = resolve_collection_mission_review(
            db,
            saved_network_ids=[network["saved_network_id"]],
            manual_targets=[],
            reviewed_scopes=[{
                "scope_id": mission["scope_id"], "version": mission["version"],
            }],
        )
    assert before["passive_pivots"] == []

    update_mission_tool(
        db_path,
        "arkime",
        expected_version=0,
        availability="available",
        version_text="5.5",
        access_method="Read-only analyst portal",
        notes="Reviewed passive source",
        actor="admin",
        reason="Record available passive source",
    )
    with connect_database(db_path) as db:
        db.execute("BEGIN IMMEDIATE")
        after = resolve_collection_mission_review(
            db,
            saved_network_ids=[network["saved_network_id"]],
            manual_targets=[],
            reviewed_scopes=[{
                "scope_id": mission["scope_id"], "version": mission["version"],
            }],
        )
    assert [(item["tool_key"], item["coverage"]) for item in after["passive_pivots"]] == [
        ("arkime", "partial")
    ]


def test_prohibited_schedule_can_be_saved_paused_but_not_enabled_or_started(tmp_path):
    db_path = tmp_path / "analyzer.db"
    network, _scope, association, mission = reviewed_network(
        db_path, authorization="prohibited",
    )
    schedule = create_scan_schedule(
        schedule_request(network, association, mission, enabled=False), db_path,
    )
    assert schedule["enabled"] is False
    assert schedule["mission_environment_status"] == "prohibited"

    with pytest.raises(MissionEnvironmentProhibited):
        set_scan_schedule_enabled(
            schedule["schedule_id"], True, changed_by="analyst", db_path=db_path,
        )
    with pytest.raises(MissionEnvironmentProhibited):
        prepare_schedule_occurrence(
            schedule["schedule_id"],
            advance_schedule=False,
            trigger_key="manual-review-request",
            actor="analyst",
            db_path=db_path,
        )
    with connect_database(db_path) as db:
        assert db.execute(
            "SELECT COUNT(*) FROM scan_schedule_occurrences"
        ).fetchone()[0] == 0


def test_prohibited_package_request_returns_conflict_without_writing_zip(
    tmp_path, monkeypatch,
):
    db_path = tmp_path / "analyzer.db"
    package_dir = tmp_path / "packages"
    package_dir.mkdir()
    network, _scope, association, mission = reviewed_network(
        db_path, authorization="prohibited",
    )
    monkeypatch.setattr(main, "DB_PATH", db_path)
    monkeypatch.setattr(main, "PACKAGE_DIR", package_dir)
    monkeypatch.setattr(main, "auth_enabled", lambda: False)
    payload = {
        "name": "Blocked package",
        "created_by": "analyst",
        "profile": "Custom",
        "scan_options": ScanOptions(protocol="tcp", tcp_scope="common").model_dump(),
        "terrain": [{"name": "Target scope", "targets": [network["cidr"]]}],
        "manual_targets": [],
        "saved_network_ids": [network["saved_network_id"]],
        "reviewed_scope_associations": [{
            "association_id": association["association_id"],
            "revision": association["revision"],
        }],
        "reviewed_mission_scopes": [{
            "scope_id": mission["scope_id"],
            "version": mission["version"],
        }],
        "no_strike_mode": "none",
        "no_strike": [],
    }
    with TestClient(main.app) as client:
        response = client.post("/api/packages", json=payload)

    assert response.status_code == 409
    assert "prohibited" in response.json()["detail"].lower()
    assert list(package_dir.iterdir()) == []


def test_package_rechecks_mission_after_build_before_writing_zip(
    tmp_path, monkeypatch,
):
    db_path = tmp_path / "analyzer.db"
    package_dir = tmp_path / "packages"
    package_dir.mkdir()
    network, _scope, association, mission = reviewed_network(db_path)
    monkeypatch.setattr(main, "DB_PATH", db_path)
    monkeypatch.setattr(main, "PACKAGE_DIR", package_dir)
    monkeypatch.setattr(main, "auth_enabled", lambda: False)
    original_build_scan_plan = main.build_scan_plan
    changed = False

    def change_declaration_during_build(spec, global_state=None):
        nonlocal changed
        if not changed:
            changed = True
            update_scope_context(
                db_path,
                mission["scope_id"],
                expected_version=mission["version"],
                nmap_coverage="available",
                arkime_coverage="unknown",
                kibana_coverage="unknown",
                config_coverage="unknown",
                nmap_authorization="prohibited",
                device_evidence="unknown",
                blind_spots=[],
                notes="Changed while the package was assembled",
                actor="admin",
                reason="Exercise the final package write gate",
            )
        return original_build_scan_plan(spec, global_state)

    monkeypatch.setattr(main, "build_scan_plan", change_declaration_during_build)
    payload = {
        "name": "Package race",
        "created_by": "analyst",
        "profile": "Custom",
        "scan_options": ScanOptions(protocol="tcp", tcp_scope="common").model_dump(),
        "terrain": [{"name": "Target scope", "targets": [network["cidr"]]}],
        "manual_targets": [],
        "saved_network_ids": [network["saved_network_id"]],
        "reviewed_scope_associations": [{
            "association_id": association["association_id"],
            "revision": association["revision"],
        }],
        "reviewed_mission_scopes": [{
            "scope_id": mission["scope_id"],
            "version": mission["version"],
        }],
        "no_strike_mode": "none",
        "no_strike": [],
    }
    with TestClient(main.app) as client:
        response = client.post("/api/packages", json=payload)

    assert response.status_code == 409
    assert "changed after review" in response.json()["detail"]
    assert list(package_dir.iterdir()) == []


def test_queued_run_rechecks_mission_before_any_network_process(
    tmp_path,
):
    db_path = tmp_path / "analyzer.db"
    data_dir = tmp_path / "data"
    network, _scope, association, mission = reviewed_network(db_path)
    manifest = prepare_scan_run(
        active_request(network, association, mission),
        db_path,
        interfaces={"eth0"},
    )
    update_scope_context(
        db_path,
        mission["scope_id"],
        expected_version=mission["version"],
        nmap_coverage="available",
        arkime_coverage="unknown",
        kibana_coverage="unknown",
        config_coverage="unknown",
        nmap_authorization="prohibited",
        device_evidence="unknown",
        blind_spots=[],
        notes="Changed while the run waited for analyzer capacity",
        actor="admin",
        reason="Exercise the final pre-contact gate",
    )
    launched = []

    execute_scan_run(
        manifest["run_id"],
        poc.RunControl(),
        db_path=db_path,
        data_dir=data_dir,
        popen_factory=lambda *args, **kwargs: launched.append((args, kwargs)),
        sleep_fn=lambda _seconds: None,
    )

    retained = get_scan_run_plan(manifest["run_id"], db_path)
    assert launched == []
    assert retained["status"] == "blocked_mission_environment"
    assert "started_at" not in retained
    assert "changed after review" in retained["execution_note"]
    with connect_database(db_path) as db:
        lease = db.execute(
            "SELECT state FROM work_leases WHERE work_kind = 'scan_execution' "
            "AND work_id = ?",
            (manifest["run_id"],),
        ).fetchone()
    assert lease is not None and lease[0] == "released"


def test_waiting_occurrence_rechecks_mission_before_worker_start(tmp_path, monkeypatch):
    db_path = tmp_path / "analyzer.db"
    network, _scope, association, mission = reviewed_network(db_path)
    schedule = create_scan_schedule(
        schedule_request(network, association, mission, enabled=True), db_path,
    )
    occurrence = prepare_schedule_occurrence(
        schedule["schedule_id"],
        advance_schedule=False,
        trigger_key="prepared-before-declaration-change",
        actor="analyst",
        db_path=db_path,
    )
    assert occurrence["status"] == "waiting"

    update_scope_context(
        db_path,
        mission["scope_id"],
        expected_version=mission["version"],
        nmap_coverage="available",
        arkime_coverage="unknown",
        kibana_coverage="unknown",
        config_coverage="unknown",
        nmap_authorization="prohibited",
        device_evidence="unknown",
        blind_spots=[],
        notes="Collection is now prohibited",
        actor="admin",
        reason="Change collection authorization",
    )
    started = []
    monkeypatch.setattr(
        poc,
        "_start_prepared_schedule_occurrence",
        lambda *_args, **_kwargs: started.append(True),
    )

    assert dispatch_due_schedules(db_path=db_path) == []
    assert started == []
    retained = get_scan_schedule(schedule["schedule_id"], db_path)
    assert retained["enabled"] is False
    assert retained["batch_status"] == "blocked_mission_environment"
    assert "changed after review" in retained["last_dispatch_note"]
