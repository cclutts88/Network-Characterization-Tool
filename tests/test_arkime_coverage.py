from __future__ import annotations

from datetime import datetime
import json

import pytest

from app.arkime_connector import create_pull_profile
from app.arkime_coverage import (
    ArkimeCoverageConflict,
    ArkimeCoverageError,
    list_arkime_coverage_windows,
)
from app.arkime_evidence import ARKIME_PARSER_VERSION, import_arkime_sessions_json
from app.arkime_summary import SUMMARY_HEADERS, import_arkime_summary_csv
from app.database import connect_database
from app.network_scopes import create_network_scope


def _sessions(start: str, end: str, suffix: str = "1") -> bytes:
    first = int(datetime.fromisoformat(start).timestamp()) + 60
    last = min(first + 60, int(datetime.fromisoformat(end).timestamp()) - 1)
    return json.dumps({
        "recordsFiltered": 1,
        "recordsTotal": 1,
        "data": [{
            "id": f"session-{suffix}", "node": "range-sensor",
            "firstPacket": first * 1000, "lastPacket": last * 1000,
            "source.ip": "192.0.2.10", "source.port": 51000,
            "destination.ip": "198.51.100.20", "destination.port": 443,
            "network.transport": "tcp", "network.packets": 4,
            "network.bytes": 2048, "protocol": ["tls"], "vlan": [10],
        }],
    }, separators=(",", ":")).encode()


def _import_session(
    db, scope, start, end, suffix="1", *, capture="complete", api_run_id=None,
):
    source_metadata = None if api_run_id is None else {
        "import_tier": "tier_e_sessions_api",
        "pull_run_id": api_run_id,
        "connector_id": "range-arkime",
        "connector_contract": "arkime-sessions-api:1",
        "parser_version": ARKIME_PARSER_VERSION,
        "request_parameters": {},
        "exact_bytes": "decoded HTTP entity; transfer framing removed; content encoding identity",
    }
    return import_arkime_sessions_json(
        db, content=_sessions(start, end, suffix),
        original_filename=(f"arkime-api-{api_run_id}.json" if api_run_id else f"{suffix}.json"),
        media_type="application/json", scope_id=scope["scope_id"],
        operator_sensor="range-sensor", query_start=start, query_end=end,
        bounding_mode="both", operator_export_assessment="complete",
        capture_coverage=capture, query_expression="vlan == 10", actor="analyst",
        source_metadata=source_metadata,
    )


def _link_api(db, scope, imports, *, duplicate_first=False):
    profile = create_pull_profile(db, {
        "name": "Coverage pull", "scope_id": scope["scope_id"],
        "operator_sensor": "range-sensor", "query_expression": "vlan == 10",
        "bounding_mode": "both", "cadence_minutes": 60,
        "lookback_minutes": 60, "overlap_minutes": 0,
        "collection_delay_seconds": 60, "enabled": False,
    }, actor="admin")
    with connect_database(db) as connection:
        for index, item in enumerate(imports):
            repetitions = 2 if duplicate_first and index == 0 else 1
            for repetition in range(repetitions):
                connection.execute(
                    """INSERT INTO arkime_pull_runs (
                           run_id,profile_id,profile_version,request_kind,state,scope_id,
                           scope_label,scope_version,operator_sensor,query_expression,
                           bounding_mode,query_start,query_end,connector_id,
                           connector_contract,parser_version,advances_schedule,
                           request_parameters_json,actor,queued_at,completed_at,import_id
                       ) VALUES (?,?,1,'manual','complete',?,?,?,?,?,?,?,?,?,?,?,0,'{}',?,?,?,?)""",
                    (
                        f"run-{index}-{repetition}", profile["profile_id"],
                        scope["scope_id"], scope["label"], scope["version"],
                        "range-sensor", "vlan == 10", "both",
                        item["query_start"], item["query_end"], "range-arkime",
                        "arkime-sessions-api:1", ARKIME_PARSER_VERSION,
                        "analyst", item["imported_at"], item["imported_at"],
                        item["import_id"],
                    ),
                )


def test_unified_inventory_keeps_manual_and_summary_sources_separate(tmp_path):
    db = tmp_path / "nct.db"
    scope = create_network_scope(db, label="Range", created_by="admin")
    session = _import_session(
        db, scope, "2030-01-01T00:00:00+00:00", "2030-01-01T01:00:00+00:00",
    )
    header = ",".join(SUMMARY_HEADERS)
    summary = import_arkime_summary_csv(
        db,
        content=(header + "\n192.0.2.1,198.51.100.2,443,tcp,tls,10,2,5,800\n").encode(),
        original_filename="summary.csv", media_type="text/csv",
        scope_id=scope["scope_id"], operator_sensor="summary-label",
        query_start="2030-01-01T02:00:00+00:00",
        query_end="2030-01-01T03:00:00+00:00", bounding_mode="both",
        query_expression="", summary_basis="all_matching_groups", top_n_limit=None,
        operator_export_assessment="complete", capture_coverage="complete",
        actor="analyst",
    )

    result = list_arkime_coverage_windows(db)

    assert result["pagination"]["total"] == 2
    assert {item["import_id"] for item in result["items"]} == {
        session["import_id"], summary["import_id"],
    }
    assert all(item["continuity"] == "not_comparable" for item in result["items"])
    assert all(item["raw_url"].endswith("/raw") for item in result["items"])
    assert result["read_only"] is True


def test_exact_api_stream_uses_maximum_preceding_end_for_gap(tmp_path):
    db = tmp_path / "nct.db"
    scope = create_network_scope(db, label="Range", created_by="admin")
    imports = [
        _import_session(db, scope, "2030-01-01T00:00:00+00:00", "2030-01-01T03:00:00+00:00", "a", api_run_id="run-0-0"),
        _import_session(db, scope, "2030-01-01T01:00:00+00:00", "2030-01-01T02:00:00+00:00", "b", api_run_id="run-1-0"),
        _import_session(db, scope, "2030-01-01T04:00:00+00:00", "2030-01-01T05:00:00+00:00", "c", api_run_id="run-2-0"),
    ]
    _link_api(db, scope, imports)

    result = list_arkime_coverage_windows(db)
    by_id = {item["import_id"]: item for item in result["items"]}

    assert by_id[imports[0]["import_id"]]["continuity"] == "first_retained_comparable_window"
    assert by_id[imports[1]["import_id"]]["continuity"] == "continuous_or_overlapping"
    assert by_id[imports[2]["import_id"]]["continuity"] == "retained_window_gap"
    assert by_id[imports[2]["import_id"]]["gap_seconds"] == 3600
    assert "does not prove" in by_id[imports[2]["import_id"]]["continuity_detail"]


def test_partial_and_ambiguous_api_provenance_stay_visible_not_comparable(tmp_path):
    db = tmp_path / "nct.db"
    scope = create_network_scope(db, label="Range", created_by="admin")
    partial = _import_session(
        db, scope, "2030-01-01T00:00:00+00:00", "2030-01-01T01:00:00+00:00",
        capture="unknown", api_run_id="run-0-0",
    )
    ambiguous = _import_session(
        db, scope, "2030-01-01T01:00:00+00:00", "2030-01-01T02:00:00+00:00", "2",
        api_run_id="run-1-0",
    )
    _link_api(db, scope, [partial, ambiguous], duplicate_first=False)
    # Add a second retained-run claim for the second import to simulate malformed history.
    with connect_database(db) as connection:
        base = connection.execute(
            "SELECT * FROM arkime_pull_runs WHERE import_id=?", (ambiguous["import_id"],),
        ).fetchone()
        columns = [row[1] for row in connection.execute("PRAGMA table_info(arkime_pull_runs)")]
        values = dict(zip(columns, base))
        values["run_id"] = "ambiguous-extra"
        marks = ",".join("?" for _ in columns)
        connection.execute(
            f"INSERT INTO arkime_pull_runs ({','.join(columns)}) VALUES ({marks})",
            tuple(values[column] for column in columns),
        )

    by_id = {
        item["import_id"]: item for item in list_arkime_coverage_windows(db)["items"]
    }
    assert by_id[partial["import_id"]]["provenance_state"] == "exact_api_run"
    assert by_id[partial["import_id"]]["continuity"] == "not_comparable"
    assert by_id[ambiguous["import_id"]]["provenance_state"] == "ambiguous_api_runs"
    assert by_id[ambiguous["import_id"]]["continuity"] == "not_comparable"


def test_pull_run_link_cannot_promote_manual_observation_to_api_provenance(tmp_path):
    db = tmp_path / "nct.db"
    scope = create_network_scope(db, label="Range", created_by="admin")
    manual = _import_session(
        db, scope, "2030-01-01T00:00:00+00:00", "2030-01-01T01:00:00+00:00",
    )
    _link_api(db, scope, [manual])

    item = list_arkime_coverage_windows(db)["items"][0]
    assert item["source_method"] == "api_pull"
    assert item["provenance_state"] == "api_observation_mismatch"
    assert item["continuity"] == "not_comparable"
    assert item["eligible_for_continuity"] is False


def test_revision_binds_paging_and_missing_storage_is_not_created(tmp_path):
    missing = tmp_path / "missing.db"
    with pytest.raises(ArkimeCoverageError, match="storage is unavailable"):
        list_arkime_coverage_windows(missing)
    assert not missing.exists()

    db = tmp_path / "nct.db"
    scope = create_network_scope(db, label="Range", created_by="admin")
    _import_session(db, scope, "2030-01-01T00:00:00+00:00", "2030-01-01T01:00:00+00:00")
    first = list_arkime_coverage_windows(db, limit=1)
    _import_session(db, scope, "2030-01-01T02:00:00+00:00", "2030-01-01T03:00:00+00:00", "2")
    with pytest.raises(ArkimeCoverageConflict, match="changed while paging"):
        list_arkime_coverage_windows(db, limit=1, offset=1, revision=first["source_revision"])


def test_coverage_route_returns_revision_bound_page(tmp_path, monkeypatch):
    import app.main as main
    from fastapi.testclient import TestClient

    db = tmp_path / "route.db"
    scope = create_network_scope(db, label="Range", created_by="admin")
    _import_session(db, scope, "2030-01-01T00:00:00+00:00", "2030-01-01T01:00:00+00:00")
    monkeypatch.setattr(main, "DB_PATH", db)
    with TestClient(main.app) as client:
        response = client.get("/api/arkime/coverage-windows?limit=1")
    assert response.status_code == 200
    assert response.json()["pagination"]["total"] == 1
