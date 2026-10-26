from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor

import pytest

from app.database import connect_database
from app.network_scopes import create_network_scope
from app.poc import (
    ScanRunBatchPreviewRequest,
    ScanRunBatchRequest,
    init_poc_storage,
    launch_scan_run_batch,
    list_scan_profiles,
    preview_scan_run_batch,
)
from app.saved_networks import (
    SavedNetworkCreate,
    SavedNetworkUpdate,
    create_saved_network,
    update_saved_network,
)
from app.saved_network_scope_associations import change_saved_network_scope_association


def _reviewed_batch(tmp_path, *, count=3, template="Mission $subnet"):
    db_path = tmp_path / "analyzer.db"
    init_poc_storage(db_path)
    scope = create_network_scope(
        db_path, label="Mission", created_by="admin", reason="Reviewed mission context"
    )
    selections = []
    networks = []
    for index in range(count):
        network = create_saved_network(
            SavedNetworkCreate(
                name=f"Sector {index + 1}",
                cidr=f"10.44.{index + 1}.0/30",
                created_by="analyst",
            ),
            db_path,
        )
        association = change_saved_network_scope_association(
            db_path,
            network["saved_network_id"],
            scope_id=scope["scope_id"],
            expected_association_id=None,
            expected_revision=None,
            actor="analyst",
            reason="Reviewed for ordered batch",
        )
        selections.append({
            "saved_network_id": network["saved_network_id"],
            "expected_updated_at": network["updated_at"],
            "expected_association_id": association["association_id"],
            "expected_association_revision": association["revision"],
        })
        networks.append(network)
    profile = next(
        item for item in list_scan_profiles(db_path)
        if item["profile_id"] == "builtin-standard"
    )
    preview_request = ScanRunBatchPreviewRequest(
        request_token="batch-test-token-0001",
        operator="analyst",
        created_by="analyst",
        executed_by="analyst",
        name_template=template,
        originating_host="nct-test",
        interface="eth0",
        profile_id=profile["profile_id"],
        profile_version=profile["version"],
        selections=selections,
        reviewed_mission_scopes=[{"scope_id": scope["scope_id"], "version": 0}],
        timeout_seconds=30,
    )
    preview = preview_scan_run_batch(
        preview_request, db_path=db_path, interfaces={"eth0"}
    )
    submit_request = ScanRunBatchRequest(
        **preview_request.model_dump(),
        preview_digest=preview["preview_digest"],
        expected_global_no_strike_revision=preview["global_no_strike_revision"],
    )
    return db_path, networks, preview_request, preview, submit_request


def _run_rows(db_path):
    with connect_database(db_path) as db:
        return db.execute(
            "SELECT rowid, run_id, manifest_json FROM scan_runs ORDER BY rowid"
        ).fetchall()


def test_preview_and_atomic_submit_preserve_explicit_order_and_profile(tmp_path, monkeypatch):
    db_path, networks, _request, preview, submit = _reviewed_batch(tmp_path)
    dispatches = []
    monkeypatch.setattr(
        "app.poc.dispatch_next_queued_run",
        lambda **kwargs: dispatches.append(kwargs),
    )

    assert [item["saved_network_name"] for item in preview["runs"]] == [
        item["name"] for item in networks
    ]
    assert [item["generated_name"] for item in preview["runs"]] == [
        f"Mission {item['name']}" for item in networks
    ]
    assert all(
        item["profile_version"] == preview["profile"]["profile_version"]
        for item in preview["runs"]
    )
    assert _run_rows(db_path) == []

    result = launch_scan_run_batch(
        submit, db_path=db_path, data_dir=tmp_path / "data", interfaces={"eth0"}
    )

    assert result["all_accepted"] is True
    assert result["accepted_count"] == 3
    assert result["sequential_execution"] is True
    assert [item["selection_order"] for item in result["runs"]] == [1, 2, 3]
    assert [item["initial_queue_position"] for item in result["runs"]] == [1, 2, 3]
    rows = _run_rows(db_path)
    assert [row[1] for row in rows] == [item["run_id"] for item in result["runs"]]
    manifests = [json.loads(row[2]) for row in rows]
    assert [item["scan_batch"]["selection_order"] for item in manifests] == [1, 2, 3]
    assert [item["saved_networks"][0]["name"] for item in manifests] == [
        item["name"] for item in networks
    ]
    assert len({item["profile_version"] for item in manifests}) == 1
    assert len(dispatches) == 1


def test_retry_replays_same_runs_and_changed_content_conflicts(tmp_path, monkeypatch):
    db_path, _networks, _request, _preview, submit = _reviewed_batch(tmp_path)
    monkeypatch.setattr("app.poc.dispatch_next_queued_run", lambda **_kwargs: None)
    first = launch_scan_run_batch(
        submit, db_path=db_path, data_dir=tmp_path / "data", interfaces={"eth0"}
    )
    replay = launch_scan_run_batch(
        submit, db_path=db_path, data_dir=tmp_path / "data", interfaces={"eth0"}
    )
    assert replay["request_replayed"] is True
    assert [item["run_id"] for item in replay["runs"]] == [
        item["run_id"] for item in first["runs"]
    ]
    assert len(_run_rows(db_path)) == 3

    changed = submit.model_copy(update={"name_template": "Changed $subnet"})
    with pytest.raises(RuntimeError, match="different work"):
        launch_scan_run_batch(
            changed, db_path=db_path, data_dir=tmp_path / "data", interfaces={"eth0"}
        )
    assert len(_run_rows(db_path)) == 3


def test_concurrent_duplicate_submissions_create_one_batch(tmp_path, monkeypatch):
    db_path, _networks, _request, _preview, submit = _reviewed_batch(tmp_path)
    monkeypatch.setattr("app.poc.dispatch_next_queued_run", lambda **_kwargs: None)

    def submit_once():
        return launch_scan_run_batch(
            submit, db_path=db_path, data_dir=tmp_path / "data", interfaces={"eth0"}
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _value: submit_once(), range(2)))
    assert {tuple(item["run_id"] for item in result["runs"]) for result in results}.__len__() == 1
    assert sum(bool(result["request_replayed"]) for result in results) == 1
    assert len(_run_rows(db_path)) == 3


def test_stale_second_network_rolls_back_whole_batch(tmp_path, monkeypatch):
    db_path, networks, _request, _preview, submit = _reviewed_batch(tmp_path)
    monkeypatch.setattr("app.poc.dispatch_next_queued_run", lambda **_kwargs: None)
    update_saved_network(
        networks[1]["saved_network_id"],
        request=SavedNetworkUpdate(
            name="Sector 2 updated",
            expected_updated_at=networks[1]["updated_at"],
            updated_by="analyst",
        ),
        db_path=db_path,
    )
    with pytest.raises(Exception, match="changed after review"):
        launch_scan_run_batch(
            submit, db_path=db_path, data_dir=tmp_path / "data", interfaces={"eth0"}
        )
    assert _run_rows(db_path) == []


def test_failure_after_first_member_is_still_atomic(tmp_path, monkeypatch):
    db_path, networks, _request, _preview, submit = _reviewed_batch(tmp_path)
    monkeypatch.setattr("app.poc.dispatch_next_queued_run", lambda **_kwargs: None)
    changed = submit.model_copy(update={"no_strike": [networks[1]["cidr"]]})
    with pytest.raises(ValueError, match="No addresses remain"):
        launch_scan_run_batch(
            changed, db_path=db_path, data_dir=tmp_path / "data", interfaces={"eth0"}
        )
    assert _run_rows(db_path) == []


def test_cleared_scope_association_rejects_the_complete_batch(tmp_path, monkeypatch):
    db_path, networks, request, _preview, submit = _reviewed_batch(tmp_path)
    monkeypatch.setattr("app.poc.dispatch_next_queued_run", lambda **_kwargs: None)
    cleared = request.selections[1]
    change_saved_network_scope_association(
        db_path,
        networks[1]["saved_network_id"],
        scope_id=None,
        expected_association_id=cleared.expected_association_id,
        expected_revision=cleared.expected_association_revision,
        actor="analyst",
        reason="Clear context after review",
    )
    with pytest.raises(Exception, match="must be assigned to the active Network Scope"):
        launch_scan_run_batch(
            submit, db_path=db_path, data_dir=tmp_path / "data", interfaces={"eth0"}
        )
    assert _run_rows(db_path) == []


def test_existing_waiting_work_stays_ahead_of_the_reviewed_batch(tmp_path, monkeypatch):
    db_path, _networks, _request, _preview, submit = _reviewed_batch(tmp_path)
    monkeypatch.setattr("app.poc.dispatch_next_queued_run", lambda **_kwargs: None)
    with connect_database(db_path) as db:
        db.execute(
            """
            INSERT INTO scan_runs (
                run_id, created_at, status, operator_name, reason,
                originating_host, interface_name, profile, manifest_json
            ) VALUES (?, ?, 'queued', ?, ?, ?, ?, ?, ?)
            """,
            (
                "existing-waiting-run", "2026-10-25T00:00:00+00:00", "analyst",
                "Existing waiting work", "nct-test", "eth0", "Standard",
                json.dumps({"run_id": "existing-waiting-run", "status": "queued"}),
            ),
        )
    result = launch_scan_run_batch(
        submit, db_path=db_path, data_dir=tmp_path / "data", interfaces={"eth0"}
    )
    assert [item["initial_queue_position"] for item in result["runs"]] == [2, 3, 4]
    assert [row[1] for row in _run_rows(db_path)] == [
        "existing-waiting-run",
        *[item["run_id"] for item in result["runs"]],
    ]


def test_committed_batch_can_be_recovered_when_dispatch_response_is_lost(tmp_path, monkeypatch):
    db_path, _networks, _request, _preview, submit = _reviewed_batch(tmp_path)
    monkeypatch.setattr(
        "app.poc.dispatch_next_queued_run",
        lambda **_kwargs: (_ for _ in ()).throw(RuntimeError("dispatcher unavailable")),
    )
    with pytest.raises(RuntimeError, match="dispatcher unavailable"):
        launch_scan_run_batch(
            submit, db_path=db_path, data_dir=tmp_path / "data", interfaces={"eth0"}
        )
    assert len(_run_rows(db_path)) == 3

    monkeypatch.setattr("app.poc.dispatch_next_queued_run", lambda **_kwargs: None)
    replay = launch_scan_run_batch(
        submit, db_path=db_path, data_dir=tmp_path / "data", interfaces={"eth0"}
    )
    assert replay["request_replayed"] is True
    assert len(_run_rows(db_path)) == 3


def test_duplicate_selection_and_generated_name_limits_are_rejected(tmp_path):
    db_path, _networks, request, _preview, _submit = _reviewed_batch(tmp_path)
    duplicate = request.model_copy(update={
        "selections": [request.selections[0], request.selections[0]],
    })
    with pytest.raises(ValueError, match="only once"):
        preview_scan_run_batch(duplicate, db_path=db_path, interfaces={"eth0"})
    too_long = request.model_copy(update={"name_template": "x" * 95 + " $subnet"})
    with pytest.raises(ValueError, match="longer than 100"):
        preview_scan_run_batch(too_long, db_path=db_path, interfaces={"eth0"})
    assert _run_rows(db_path) == []
