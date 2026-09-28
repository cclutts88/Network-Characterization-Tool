from datetime import datetime, timedelta, timezone
from pathlib import Path
import json
import os
import sqlite3

import pytest
from fastapi.testclient import TestClient

from app.artifacts import (
    init_artifact_storage,
    register_artifact_bytes,
    register_artifact_file,
)
from app.database import connect_database
from app.network_scopes import archive_network_scope, create_network_scope
from app.poc import (
    ScanRunRequest,
    ScanScheduleCreate,
    create_scan_schedule,
    init_poc_storage,
    prepare_scan_run,
)
from app.saved_networks import SavedNetworkCreate, create_saved_network
from app.saved_network_scope_associations import (
    SavedNetworkScopeConflict,
    change_saved_network_scope_association,
    current_saved_network_scope_association,
    get_run_scope_context,
    get_schedule_scope_context,
    init_saved_network_scope_storage,
    list_saved_network_scope_history,
)


def ready_database(tmp_path: Path) -> Path:
    db_path = tmp_path / "analyzer.db"
    init_artifact_storage(db_path)
    init_poc_storage(db_path)
    return db_path


def saved_network(db_path: Path, name: str, cidr: str) -> dict:
    return create_saved_network(
        SavedNetworkCreate(
            name=name,
            cidr=cidr,
            created_by="analyst",
        ),
        db_path,
    )


def scope(db_path: Path, label: str) -> dict:
    return create_network_scope(
        db_path,
        label=label,
        created_by="admin",
        reason="Approved network context",
    )


def assign(db_path: Path, network: dict, network_scope: dict, current=None):
    return change_saved_network_scope_association(
        db_path,
        network["saved_network_id"],
        scope_id=network_scope["scope_id"],
        expected_association_id=current["association_id"] if current else None,
        expected_revision=current["revision"] if current else None,
        actor="analyst",
        reason="Reviewed against the network authorization record",
    )


def scan_request(networks: list[dict], associations: list[dict], *, manual=None):
    return ScanRunRequest(
        operator="analyst",
        created_by="analyst",
        name="Context test",
        originating_host="nct-test",
        interface="eth0",
        profile="Standard",
        profile_id="builtin-standard",
        profile_version=2,
        targets=[item["cidr"] for item in networks] + list(manual or []),
        manual_targets=list(manual or []),
        saved_network_ids=[item["saved_network_id"] for item in networks],
        reviewed_scope_associations=[
            {"association_id": item["association_id"], "revision": item["revision"]}
            for item in associations
        ],
        capture=True,
        timeout_seconds=30,
    )


def test_association_history_is_append_only_and_stale_changes_lose(tmp_path):
    db_path = ready_database(tmp_path)
    network = saved_network(db_path, "Development servers", "10.50.15.0/24")
    first_scope = scope(db_path, "AFB Dev")
    second_scope = scope(db_path, "AFB Test")

    first = assign(db_path, network, first_scope)
    second = assign(db_path, network, second_scope, first)
    cleared = change_saved_network_scope_association(
        db_path,
        network["saved_network_id"],
        scope_id=None,
        expected_association_id=second["association_id"],
        expected_revision=second["revision"],
        actor="analyst",
        reason="Network was removed from this context",
    )

    assert [item["event"] for item in list_saved_network_scope_history(
        db_path, network["saved_network_id"]
    )] == ["assigned", "changed", "cleared"]
    assert cleared["scope"] is None
    with pytest.raises(SavedNetworkScopeConflict):
        assign(db_path, network, first_scope, first)
    with connect_database(db_path) as db:
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            db.execute(
                "UPDATE saved_network_scope_associations SET reason = 'rewritten' "
                "WHERE association_id = ?",
                (first["association_id"],),
            )
        with pytest.raises(sqlite3.IntegrityError):
            db.execute(
                """
                INSERT INTO saved_network_scope_associations (
                    association_id, saved_network_id, scope_id, revision, event,
                    predecessor_id, actor, reason, recorded_at
                ) VALUES ('branch', ?, ?, 2, 'changed', ?, 'attacker', 'branch', ?)
                """,
                (
                    network["saved_network_id"], second_scope["scope_id"],
                    first["association_id"], datetime.now(timezone.utc).isoformat(),
                ),
            )


def test_scan_submission_rechecks_review_and_retains_immutable_context(tmp_path):
    db_path = ready_database(tmp_path)
    network = saved_network(db_path, "Development servers", "10.50.15.0/24")
    first_scope = scope(db_path, "AFB Dev")
    second_scope = scope(db_path, "AFB Test")
    first = assign(db_path, network, first_scope)
    stale_request = scan_request([network], [first])

    changed = assign(db_path, network, second_scope, first)
    with pytest.raises(SavedNetworkScopeConflict, match="changed after review"):
        prepare_scan_run(stale_request, db_path, interfaces={"eth0"})

    run = prepare_scan_run(
        scan_request([network], [changed]), db_path, interfaces={"eth0"}
    )
    retained = get_run_scope_context(db_path, run["run_id"])
    assert retained["scope_id"] == second_scope["scope_id"]
    assert retained["scope_label"] == "AFB Test"

    cleared = change_saved_network_scope_association(
        db_path,
        network["saved_network_id"],
        scope_id=None,
        expected_association_id=changed["association_id"],
        expected_revision=changed["revision"],
        actor="analyst",
        reason="Future scans should be unscoped",
    )
    assert current_saved_network_scope_association(
        db_path, network["saved_network_id"]
    )["association_id"] == cleared["association_id"]
    assert get_run_scope_context(db_path, run["run_id"]) == retained


def test_manual_combined_and_mixed_scope_requests_remain_unscoped(tmp_path):
    db_path = ready_database(tmp_path)
    first_network = saved_network(db_path, "Dev", "10.50.15.0/24")
    second_network = saved_network(db_path, "Test", "10.50.16.0/24")
    first_association = assign(db_path, first_network, scope(db_path, "AFB Dev"))
    second_association = assign(db_path, second_network, scope(db_path, "AFB Test"))

    mixed = prepare_scan_run(
        scan_request(
            [first_network, second_network],
            [first_association, second_association],
        ),
        db_path,
        interfaces={"eth0"},
    )
    combined = prepare_scan_run(
        scan_request(
            [first_network], [first_association], manual=["10.60.1.1/32"]
        ),
        db_path,
        interfaces={"eth0"},
    )
    assert mixed["network_scope_status"] == "unscoped"
    assert combined["network_scope_status"] == "unscoped"
    assert get_run_scope_context(db_path, mixed["run_id"]) is None
    assert get_run_scope_context(db_path, combined["run_id"]) is None


def test_schedule_pins_context_and_archived_scope_blocks_dispatch(tmp_path):
    db_path = ready_database(tmp_path)
    network = saved_network(db_path, "Development servers", "10.50.15.0/24")
    network_scope = scope(db_path, "AFB Dev")
    association = assign(db_path, network, network_scope)
    schedule = create_scan_schedule(
        ScanScheduleCreate(
            name="Dev baseline",
            created_by="analyst",
            profile_id="builtin-standard",
            profile_version=2,
            targets=[network["cidr"]],
            saved_network_ids=[network["saved_network_id"]],
            reviewed_scope_associations=[
                {
                    "association_id": association["association_id"],
                    "revision": association["revision"],
                }
            ],
            interface="eth0",
            first_run_at=datetime.now(timezone.utc) + timedelta(hours=1),
        ),
        db_path,
    )
    pinned = get_schedule_scope_context(db_path, schedule["schedule_id"])
    assert pinned["scope_id"] == network_scope["scope_id"]
    replacement_scope = scope(db_path, "AFB Dev Replacement")
    assign(db_path, network, replacement_scope, association)
    scheduled_run = prepare_scan_run(
        ScanRunRequest(
            operator="analyst",
            created_by="analyst",
            scheduled=True,
            scheduled_by="analyst",
            executed_by="scheduler",
            schedule_id=schedule["schedule_id"],
            name="Dev baseline",
            originating_host="scheduler",
            interface="eth0",
            profile="Standard",
            profile_id="builtin-standard",
            profile_version=2,
            targets=[network["cidr"]],
            capture=True,
            timeout_seconds=30,
        ),
        db_path,
        interfaces={"eth0"},
    )
    assert get_run_scope_context(db_path, scheduled_run["run_id"]) == pinned

    archive_network_scope(
        db_path,
        network_scope["scope_id"],
        expected_version=network_scope["version"],
        archived_by="admin",
        reason="Context retired",
    )
    with pytest.raises(SavedNetworkScopeConflict, match="archived"):
        get_schedule_scope_context(
            db_path, schedule["schedule_id"], require_active=True
        )


def test_same_bytes_keep_separate_observation_scope_contexts_and_replay_is_exact(tmp_path):
    db_path = ready_database(tmp_path)
    first_network = saved_network(db_path, "Dev", "10.50.15.0/24")
    second_network = saved_network(db_path, "Test", "10.50.16.0/24")
    first_association = assign(db_path, first_network, scope(db_path, "AFB Dev"))
    second_association = assign(db_path, second_network, scope(db_path, "AFB Test"))
    first_run = prepare_scan_run(
        scan_request([first_network], [first_association]),
        db_path,
        interfaces={"eth0"},
    )
    second_run = prepare_scan_run(
        scan_request([second_network], [second_association]),
        db_path,
        interfaces={"eth0"},
    )
    evidence = tmp_path / "same.xml"
    evidence.write_text("<nmaprun/>", encoding="utf-8")

    records = []
    for run in (first_run, second_run):
        records.append(
            register_artifact_file(
                db_path=db_path,
                source_path=evidence,
                source_kind="nmap_scan",
                source_ref=run["run_id"],
                original_filename="scan.xml",
                actor="analyst",
                observed_at=run["created_at"],
                observation_key=f"nmap_scan:{run['run_id']}:scan.xml",
                run_id=run["run_id"],
                scope_context=get_run_scope_context(db_path, run["run_id"]),
            )
        )
    assert records[0]["sha256"] == records[1]["sha256"]
    assert records[0]["observation_id"] != records[1]["observation_id"]
    with connect_database(db_path) as db:
        contexts = db.execute(
            "SELECT scope_id FROM artifact_observation_scope_contexts "
            "ORDER BY observation_id"
        ).fetchall()
    assert len({item[0] for item in contexts}) == 2

    with pytest.raises(ValueError, match="replay"):
        register_artifact_file(
            db_path=db_path,
            source_path=evidence,
            source_kind="nmap_scan",
            source_ref=first_run["run_id"],
            original_filename="scan.xml",
            actor="different-actor",
            observed_at=first_run["created_at"],
            observation_key=f"nmap_scan:{first_run['run_id']}:scan.xml",
            run_id=first_run["run_id"],
            scope_context=get_run_scope_context(db_path, first_run["run_id"]),
        )


def test_storage_initializers_rebuild_after_database_replacement(tmp_path):
    db_path = ready_database(tmp_path)
    saved_network(db_path, "Before replacement", "10.50.15.0/24")
    replacement = tmp_path / "replacement.db"
    sqlite3.connect(replacement).close()
    os.replace(replacement, db_path)
    init_artifact_storage(db_path)
    init_poc_storage(db_path)
    init_saved_network_scope_storage(db_path)
    with connect_database(db_path) as db:
        tables = {
            row[0]
            for row in db.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
    assert {
        "saved_networks",
        "scan_runs",
        "saved_network_scope_associations",
        "scan_run_scope_contexts",
    }.issubset(tables)


def test_database_rejects_forged_scope_provenance_and_malformed_audit(tmp_path):
    db_path = ready_database(tmp_path)
    network = saved_network(db_path, "Development", "10.50.15.0/24")
    other_network = saved_network(db_path, "Other", "10.50.16.0/24")
    network_scope = scope(db_path, "AFB Dev")
    association = assign(db_path, network, network_scope)
    run = prepare_scan_run(
        scan_request([network], [association]), db_path, interfaces={"eth0"}
    )

    with connect_database(db_path) as db:
        for actor, reason, recorded_at in (
            (" padded ", "valid reason", datetime.now(timezone.utc).replace(microsecond=0).isoformat()),
            ("analyst", " padded reason ", datetime.now(timezone.utc).replace(microsecond=0).isoformat()),
            ("analyst", "valid reason", "not-a-time"),
        ):
            with pytest.raises(sqlite3.IntegrityError):
                db.execute(
                    """
                    INSERT INTO saved_network_scope_associations (
                        association_id, saved_network_id, scope_id, revision,
                        event, predecessor_id, actor, reason, recorded_at
                    ) VALUES (?, ?, ?, 1, 'assigned', NULL, ?, ?, ?)
                    """,
                    (
                        f"bad_{actor}_{recorded_at}", other_network["saved_network_id"],
                        network_scope["scope_id"], actor, reason, recorded_at,
                    ),
                )
        with pytest.raises(sqlite3.IntegrityError, match="does not match"):
            db.execute(
                """
                INSERT INTO scan_run_scope_sources (
                    run_id, saved_network_id, association_id, association_revision
                ) VALUES (?, ?, ?, ?)
                """,
                (
                    run["run_id"], other_network["saved_network_id"],
                    association["association_id"], association["revision"],
                ),
            )

    observation = register_artifact_bytes(
        db_path=db_path,
        content=b"independent observation",
        source_kind="nmap_scan",
        source_ref=run["run_id"],
        actor="analyst",
    )
    retained = get_run_scope_context(db_path, run["run_id"])
    with connect_database(db_path) as db:
        with pytest.raises(sqlite3.IntegrityError, match="does not match"):
            db.execute(
                """
                INSERT INTO artifact_observation_scope_contexts (
                    observation_id, run_id, scope_id, scope_label,
                    scope_version, recorded_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    observation["observation_id"], run["run_id"],
                    retained["scope_id"], "Forged label",
                    retained["scope_version"], retained["recorded_at"],
                ),
            )

    successor_scope = scope(db_path, "AFB Dev successor")
    assign(db_path, network, successor_scope, association)
    historical_run_id = "f" * 32
    historical_manifest = {
        "run_id": historical_run_id,
        "schedule_id": None,
        "network_scope_context": retained,
    }
    with connect_database(db_path) as db:
        db.execute(
            """
            INSERT INTO scan_runs (
                run_id, created_at, status, operator_name, reason,
                originating_host, interface_name, profile, manifest_json
            ) VALUES (?, ?, 'queued', 'attacker', 'probe', 'host', 'eth0', 'test', ?)
            """,
            (
                historical_run_id,
                datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
                json.dumps(historical_manifest),
            ),
        )
        db.execute(
            """
            INSERT INTO scan_run_scope_contexts (
                run_id, scope_id, scope_label, scope_version, recorded_at
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (
                historical_run_id, retained["scope_id"], retained["scope_label"],
                retained["scope_version"], retained["recorded_at"],
            ),
        )
        with pytest.raises(sqlite3.IntegrityError, match="does not match"):
            db.execute(
                """
                INSERT INTO scan_run_scope_sources (
                    run_id, saved_network_id, association_id, association_revision
                ) VALUES (?, ?, ?, ?)
                """,
                (
                    historical_run_id, network["saved_network_id"],
                    association["association_id"], association["revision"],
                ),
            )

    archive_network_scope(
        db_path,
        network_scope["scope_id"],
        expected_version=network_scope["version"],
        archived_by="admin",
        reason="Probe archived context",
    )
    archived_run_id = "e" * 32
    archived_manifest = {
        "run_id": archived_run_id,
        "schedule_id": None,
        "network_scope_context": retained,
    }
    with connect_database(db_path) as db:
        db.execute(
            """
            INSERT INTO scan_runs (
                run_id, created_at, status, operator_name, reason,
                originating_host, interface_name, profile, manifest_json
            ) VALUES (?, ?, 'queued', 'attacker', 'probe', 'host', 'eth0', 'test', ?)
            """,
            (
                archived_run_id,
                datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
                json.dumps(archived_manifest),
            ),
        )
        with pytest.raises(sqlite3.IntegrityError, match="not authoritative"):
            db.execute(
                """
                INSERT INTO scan_run_scope_contexts (
                    run_id, scope_id, scope_label, scope_version, recorded_at
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    archived_run_id, retained["scope_id"], retained["scope_label"],
                    retained["scope_version"], retained["recorded_at"],
                ),
            )


def test_contextual_save_is_atomic_and_local_cross_origin_is_blocked(
    tmp_path, monkeypatch,
):
    import app.main as main
    import app.poc as poc

    db_path = tmp_path / "route.db"
    monkeypatch.setattr(main, "DB_PATH", db_path)
    monkeypatch.setattr(poc, "DB_PATH", db_path)
    monkeypatch.setattr(main, "auth_enabled", lambda: False)
    active_scope = scope(db_path, "Active")
    archived_scope = scope(db_path, "Archived")
    archive_network_scope(
        db_path,
        archived_scope["scope_id"],
        expected_version=archived_scope["version"],
        archived_by="admin",
        reason="No longer eligible",
    )
    payload = {
        "name": "Atomic network",
        "cidr": "10.70.1.0/24",
        "scope_id": active_scope["scope_id"],
        "scope_reason": "Approved context",
    }
    with TestClient(main.app) as client:
        blocked = client.post(
            "/api/saved-networks/contextual-save",
            json=payload,
            headers={"Origin": "https://unrelated.example"},
        )
        assert blocked.status_code == 403
        rejected = client.post(
            "/api/saved-networks/contextual-save",
            json={**payload, "scope_id": archived_scope["scope_id"]},
        )
        assert rejected.status_code == 409
        assert client.get("/api/saved-networks").json() == []
        created = client.post(
            "/api/saved-networks/contextual-save", json=payload
        )
        assert created.status_code == 200
        original = created.json()

        replacement_scope = scope(db_path, "Replacement")
        changed = change_saved_network_scope_association(
            db_path,
            original["saved_network_id"],
            scope_id=replacement_scope["scope_id"],
            expected_association_id=original["network_scope_association"]["association_id"],
            expected_revision=original["network_scope_association"]["revision"],
            actor="other-analyst",
            reason="Concurrent reviewed change",
        )
        stale_edit = client.post(
            "/api/saved-networks/contextual-save",
            json={
                **payload,
                "saved_network_id": original["saved_network_id"],
                "name": "Name that must roll back",
                "expected_association_id": original["network_scope_association"]["association_id"],
                "expected_revision": original["network_scope_association"]["revision"],
            },
        )
        assert stale_edit.status_code == 409
        retained = client.get(
            f"/api/saved-networks/{original['saved_network_id']}"
        ).json()
    assert retained["name"] == "Atomic network"
    assert retained["network_scope_association"]["association_id"] == changed["association_id"]


def test_archived_scope_schedule_enable_returns_conflict_without_state_change(
    tmp_path, monkeypatch,
):
    import app.main as main
    import app.poc as poc

    db_path = tmp_path / "schedule-route.db"
    monkeypatch.setattr(main, "DB_PATH", db_path)
    monkeypatch.setattr(poc, "DB_PATH", db_path)
    monkeypatch.setattr(main, "auth_enabled", lambda: False)
    network = saved_network(db_path, "Development", "10.80.1.0/24")
    network_scope = scope(db_path, "Scheduled")
    association = assign(db_path, network, network_scope)
    schedule = create_scan_schedule(
        ScanScheduleCreate(
            name="Archived scope schedule",
            created_by="analyst",
            profile_id="builtin-standard",
            profile_version=2,
            targets=[network["cidr"]],
            saved_network_ids=[network["saved_network_id"]],
            reviewed_scope_associations=[{
                "association_id": association["association_id"],
                "revision": association["revision"],
            }],
            interface="eth0",
            first_run_at=datetime.now(timezone.utc) + timedelta(hours=1),
        ),
        db_path,
    )
    archive_network_scope(
        db_path,
        network_scope["scope_id"],
        expected_version=network_scope["version"],
        archived_by="admin",
        reason="Context retired",
    )
    with TestClient(main.app) as client:
        response = client.post(
            f"/api/scan-schedules/{schedule['schedule_id']}/state",
            json={"enabled": True, "changed_by": "analyst"},
        )
        stored = client.get("/api/scan-schedules").json()
    assert response.status_code == 409
    assert stored[0]["enabled"] is False
