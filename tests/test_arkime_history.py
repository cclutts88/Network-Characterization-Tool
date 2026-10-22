from __future__ import annotations

import json

import pytest

import app.arkime_connector as connector
import app.arkime_history as history_module
from app.arkime_connector import create_pull_profile, enqueue_pull_now, execute_one_pull, get_pull_run
from app.arkime_history import (
    ArkimeHistoryConflict,
    build_arkime_history,
    get_arkime_history,
    get_arkime_history_path_evidence,
    get_arkime_history_record_exclusions,
    list_arkime_history_streams,
    list_arkime_histories,
)
from app.database import connect_database
from app.network_scopes import archive_network_scope, create_network_scope


@pytest.fixture
def configured(monkeypatch, tmp_path):
    password = tmp_path / "arkime-password"
    password.write_text("test-only-password\n", encoding="utf-8")
    monkeypatch.setenv("NCT_ARKIME_API_ENABLED", "1")
    monkeypatch.setenv("NCT_ARKIME_API_URL", "https://arkime.invalid:8005")
    monkeypatch.setenv("NCT_ARKIME_API_USERNAME", "nct-reader")
    monkeypatch.setenv("NCT_ARKIME_API_PASSWORD_FILE", str(password))
    monkeypatch.setenv("NCT_ARKIME_DATASET_ID", "range-dataset-2026")
    monkeypatch.delenv("HTTPS_PROXY", raising=False)


def _profile(db, scope_id):
    return create_pull_profile(db, {
        "name": "Range passive stream", "scope_id": scope_id,
        "operator_sensor": "range-sensor", "query_expression": "vlan == 10",
        "bounding_mode": "both", "cadence_minutes": 60, "lookback_minutes": 60,
        "overlap_minutes": 5, "collection_delay_seconds": 60, "enabled": False,
    }, actor="admin")


def _row(session_id, *, packets=10, byte_count=4096, destination="198.51.100.20",
         port=443, node="range-sensor"):
    return {
        "id": session_id, "rootId": f"root-{session_id}", "node": node,
        "firstPacket": 1_700_000_000_000, "lastPacket": 1_700_000_060_000,
        "source.ip": "192.0.2.10", "source.port": 50000,
        "destination.ip": destination, "destination.port": port,
        "ipProtocol": 6, "network.packets": packets, "network.bytes": byte_count,
        "srcPackets": packets // 2, "dstPackets": packets - packets // 2,
        "protocol": ["tls", "tcp"], "vlan": [10],
    }


def _response(rows, *, filtered=None):
    count = len(rows) if filtered is None else filtered
    return json.dumps({
        "recordsFiltered": count, "recordsTotal": count, "data": rows,
    }, separators=(",", ":")).encode()


def _pull(db, profile_id, rows, *, filtered=None):
    queued = enqueue_pull_now(db, profile_id, actor="analyst")
    def fetch(_config, parameters):
        start = int(parameters["startTime"])
        adjusted = []
        for index, original in enumerate(rows):
            row = dict(original)
            row["firstPacket"] = (start + 120 + index) * 1000
            row["lastPacket"] = (start + 180 + index) * 1000
            adjusted.append(row)
        return _response(adjusted, filtered=filtered)
    execute_one_pull(db, fetcher=fetch)
    result = get_pull_run(db, queued["run_id"])
    assert result["state"] in {"complete", "partial"}, result
    return result


def test_history_deduplicates_exact_records_and_preserves_unknown_capture(
    configured, monkeypatch, tmp_path,
):
    db = tmp_path / "history.db"
    scope = create_network_scope(db, label="Range", created_by="admin")
    profile = _profile(db, scope["scope_id"])
    big = 5_000_000_000_000_000
    rows = [_row("segment-a", packets=big), _row("segment-b", packets=big, port=8443)]
    first = _pull(db, profile["profile_id"], rows)
    missing_id = _row(None, port=9443)
    missing_id.pop("id")
    _pull(db, profile["profile_id"], rows + [missing_id])
    partial = _pull(db, profile["profile_id"], [_row("partial")], filtered=2)
    assert partial["state"] == "partial"

    generated_times = iter(("2030-01-01T00:00:00+00:00", "2030-01-02T00:00:00+00:00"))
    monkeypatch.setattr("app.derived_results.utc_now", lambda: next(generated_times))
    history = build_arkime_history(db, first["run_id"], actor="analyst")
    assert history["included_source_count"] == 2
    assert history["excluded_source_count"] == 1
    assert history["retained_record_count"] == 2
    assert history["duplicate_encounter_count"] == 2
    assert history["excluded_record_count"] == 1
    assert {item["capture_coverage"] for item in history["sources"] if item["disposition"] == "included"} == {"unknown"}
    assert len(history["paths"]) == 2
    assert sum(int(item["known_packet_total"]) for item in history["paths"]) == big * 2
    assert all(isinstance(item["known_packet_total"], str) for item in history["paths"])
    evidence = get_arkime_history_path_evidence(
        db, history["result_id"], history["paths"][0]["path_key"],
    )
    assert evidence["pagination"]["total"] == 2
    assert {item["import_id"] for item in evidence["items"]} == {
        item["import_id"] for item in history["sources"] if item["disposition"] == "included"
    }

    replay = build_arkime_history(db, first["run_id"], actor="analyst")
    assert replay["result_id"] == history["result_id"]
    assert replay["generated_at"] == history["generated_at"]
    assert list_arkime_histories(db)["pagination"]["total"] == 1
    assert history["retained_window_gaps"] == []

    filtered = get_arkime_history(
        db, history["result_id"], path_filter="8443",
    )
    assert filtered["path_filter"] == "8443"
    assert filtered["unfiltered_path_total"] == 2
    assert filtered["pagination"]["total"] == 1
    assert filtered["paths"][0]["destination_port"] == 8443


def test_history_calculation_has_a_bounded_source_set(monkeypatch, tmp_path):
    monkeypatch.setattr(
        history_module, "_candidate_rows",
        lambda _db, _stream: [None] * (history_module.MAX_HISTORY_SOURCES + 1),
    )
    with connect_database(tmp_path / "bounded.db") as connection, pytest.raises(
        ArkimeHistoryConflict, match="retained pulls",
    ):
        history_module._snapshot(connection, {})


def test_conflicting_node_and_session_copy_blocks_new_generation(configured, tmp_path):
    db = tmp_path / "conflict.db"
    scope = create_network_scope(db, label="Range", created_by="admin")
    profile = _profile(db, scope["scope_id"])
    first = _pull(db, profile["profile_id"], [_row("segment-a")])
    previous = build_arkime_history(db, first["run_id"], actor="analyst")
    _pull(db, profile["profile_id"], [_row("segment-a", packets=11)])

    with pytest.raises(ArkimeHistoryConflict, match="Conflicting copies"):
        build_arkime_history(db, first["run_id"], actor="analyst")
    assert get_arkime_history(db, previous["result_id"])["retained_record_count"] == 1
    with connect_database(db, read_only=True) as connection:
        attempts = connection.execute(
            "SELECT status,detail FROM arkime_history_build_attempts ORDER BY requested_at,rowid"
        ).fetchall()
    assert attempts[-1][0] == "failed"
    assert "Receipt references" in attempts[-1][1]


def test_root_id_never_replaces_session_id(configured, tmp_path):
    db = tmp_path / "root-id.db"
    scope = create_network_scope(db, label="Range", created_by="admin")
    profile = _profile(db, scope["scope_id"])
    one = _row("segment-a")
    two = _row("segment-b")
    two["rootId"] = one["rootId"]
    run = _pull(db, profile["profile_id"], [one, two])
    history = build_arkime_history(db, run["run_id"], actor="analyst")
    assert history["retained_record_count"] == 2


def test_missing_dataset_identity_fails_closed_without_relabeling_old_pull(
    configured, monkeypatch, tmp_path,
):
    db = tmp_path / "dataset.db"
    scope = create_network_scope(db, label="Range", created_by="admin")
    profile = _profile(db, scope["scope_id"])
    monkeypatch.delenv("NCT_ARKIME_DATASET_ID")
    run = _pull(db, profile["profile_id"], [_row("segment-a")])
    assert run["dataset_identity"] == "unverified"
    monkeypatch.setenv("NCT_ARKIME_DATASET_ID", "later-dataset")
    with pytest.raises(ArkimeHistoryConflict, match="no frozen Arkime dataset identity"):
        build_arkime_history(db, run["run_id"], actor="analyst")


def test_dataset_change_after_queue_blocks_contact(configured, monkeypatch, tmp_path):
    db = tmp_path / "dataset-change.db"
    scope = create_network_scope(db, label="Range", created_by="admin")
    profile = _profile(db, scope["scope_id"])
    queued = enqueue_pull_now(db, profile["profile_id"], actor="analyst")
    monkeypatch.setenv("NCT_ARKIME_DATASET_ID", "replacement-dataset")
    contacted = False
    def fetch(*_args):
        nonlocal contacted
        contacted = True
        return _response([_row("segment-a")])
    execute_one_pull(db, fetcher=fetch)
    assert contacted is False
    assert get_pull_run(db, queued["run_id"])["state"] == "failed"


def test_archived_scope_blocks_history_publication(configured, tmp_path):
    db = tmp_path / "authority.db"
    scope = create_network_scope(db, label="Range", created_by="admin")
    profile = _profile(db, scope["scope_id"])
    run = _pull(db, profile["profile_id"], [_row("segment-a")])
    archive_network_scope(
        db, scope["scope_id"], expected_version=scope["version"],
        archived_by="admin", reason="retired",
    )
    with pytest.raises(ArkimeHistoryConflict, match="Scope authority changed"):
        build_arkime_history(db, run["run_id"], actor="analyst")


def test_normalized_child_tamper_is_detected_on_warm_replay(configured, tmp_path):
    db = tmp_path / "warm-replay.db"
    scope = create_network_scope(db, label="Range", created_by="admin")
    profile = _profile(db, scope["scope_id"])
    run = _pull(db, profile["profile_id"], [_row("segment-a")])
    history = build_arkime_history(db, run["run_id"], actor="analyst")
    with connect_database(db) as connection:
        connection.execute("DROP TRIGGER arkime_history_paths_no_update")
        connection.execute(
            "UPDATE arkime_history_paths SET known_packet_total_text='999' WHERE result_id=?",
            (history["result_id"],),
        )
    with pytest.raises(ArkimeHistoryConflict, match="arkime_history_paths"):
        build_arkime_history(db, run["run_id"], actor="analyst")


def test_extra_path_record_link_is_detected_on_warm_replay(configured, tmp_path):
    db = tmp_path / "warm-path-record-replay.db"
    scope = create_network_scope(db, label="Range", created_by="admin")
    profile = _profile(db, scope["scope_id"])
    run = _pull(db, profile["profile_id"], [
        _row("segment-a", port=443), _row("segment-b", port=8443),
    ])
    history = build_arkime_history(db, run["run_id"], actor="analyst")
    with connect_database(db) as connection:
        paths = connection.execute(
            "SELECT path_key FROM arkime_history_paths WHERE result_id=? ORDER BY path_key",
            (history["result_id"],),
        ).fetchall()
        record = connection.execute("""SELECT record_key FROM arkime_history_path_records
            WHERE result_id=? AND path_key=?""", (history["result_id"], paths[0][0])).fetchone()
        connection.execute("""INSERT INTO arkime_history_path_records
            (result_id,path_key,record_key) VALUES (?,?,?)""",
            (history["result_id"], paths[1][0], record[0]))
    with pytest.raises(ArkimeHistoryConflict, match="child rows"):
        build_arkime_history(db, run["run_id"], actor="analyst")


def test_receipt_identity_is_part_of_frozen_manifest(configured, tmp_path):
    db = tmp_path / "identity-manifest.db"
    scope = create_network_scope(db, label="Range", created_by="admin")
    profile = _profile(db, scope["scope_id"])
    run = _pull(db, profile["profile_id"], [_row("segment-a")])
    first = build_arkime_history(db, run["run_id"], actor="analyst")
    with connect_database(db) as connection:
        connection.execute("DROP TRIGGER arkime_session_receipts_no_update")
        connection.execute("""UPDATE arkime_session_receipts SET session_id='segment-mutated'
            WHERE import_id=?""", (run["import_id"],))
    second = build_arkime_history(db, run["run_id"], actor="analyst")
    assert second["result_id"] != first["result_id"]
    assert second["source_manifest_sha256"] != first["source_manifest_sha256"]


def test_stream_catalog_and_record_exclusions_are_paged(configured, tmp_path):
    db = tmp_path / "bounded-reads.db"
    scope = create_network_scope(db, label="Range", created_by="admin")
    first_profile = _profile(db, scope["scope_id"])
    second_profile = create_pull_profile(db, {
        "name": "Second stream", "scope_id": scope["scope_id"],
        "operator_sensor": "other-sensor", "query_expression": "vlan == 20",
        "bounding_mode": "both", "cadence_minutes": 60, "lookback_minutes": 60,
        "overlap_minutes": 5, "collection_delay_seconds": 60, "enabled": False,
    }, actor="admin")
    missing_one = _row(None, port=9443)
    missing_one.pop("id")
    missing_two = _row(None, port=10443)
    missing_two.pop("id")
    first_run = _pull(db, first_profile["profile_id"], [missing_one, missing_two])
    _pull(db, second_profile["profile_id"], [_row("second-stream")])
    catalog = list_arkime_history_streams(db, limit=1)
    assert len(catalog["items"]) == 1
    assert catalog["pagination"] == {
        "limit": 1, "offset": 0, "total": 2, "has_more": True,
    }
    built = build_arkime_history(db, first_run["run_id"], actor="analyst")
    first_page = get_arkime_history_record_exclusions(
        db, built["result_id"], limit=1,
    )
    assert len(first_page["items"]) == 1
    assert first_page["pagination"]["total"] == 2
    assert first_page["pagination"]["has_more"] is True


def test_history_detail_route_filters_all_retained_paths(configured, monkeypatch, tmp_path):
    import app.main as main
    from fastapi.testclient import TestClient

    db = tmp_path / "history-route.db"
    scope = create_network_scope(db, label="Range", created_by="admin")
    profile = _profile(db, scope["scope_id"])
    run = _pull(db, profile["profile_id"], [
        _row("segment-a", port=443), _row("segment-b", port=8443),
    ])
    built = build_arkime_history(db, run["run_id"], actor="analyst")
    monkeypatch.setattr(main, "DB_PATH", db)
    with TestClient(main.app) as client:
        response = client.get(
            f"/api/arkime/history/{built['result_id']}",
            params={"path_filter": "8443", "limit": 1},
        )
    assert response.status_code == 200
    assert response.json()["pagination"]["total"] == 1
    assert response.json()["unfiltered_path_total"] == 2
    assert response.json()["paths"][0]["destination_port"] == 8443
