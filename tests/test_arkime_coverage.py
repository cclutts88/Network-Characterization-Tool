from __future__ import annotations

from datetime import datetime, timezone
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
    sensor="range-sensor", query="vlan == 10", connector_id="range-arkime",
    connector_contract="arkime-sessions-api:1", content=None,
    operator_assessment="complete",
):
    source_metadata = None if api_run_id is None else {
        "import_tier": "tier_e_sessions_api",
        "pull_run_id": api_run_id,
        "connector_id": connector_id,
        "connector_contract": connector_contract,
        "parser_version": ARKIME_PARSER_VERSION,
        "request_parameters": {},
        "exact_bytes": "decoded HTTP entity; transfer framing removed; content encoding identity",
    }
    return import_arkime_sessions_json(
        db, content=content if content is not None else _sessions(start, end, suffix),
        original_filename=(f"arkime-api-{api_run_id}.json" if api_run_id else f"{suffix}.json"),
        media_type="application/json", scope_id=scope["scope_id"],
        operator_sensor=sensor, query_start=start, query_end=end,
        bounding_mode="both", operator_export_assessment=operator_assessment,
        capture_coverage=capture, query_expression=query, actor="analyst",
        source_metadata=source_metadata,
    )


def _link_api(
    db, scope, imports, *, duplicate_first=False, sensor="range-sensor",
    query="vlan == 10", connector_id="range-arkime",
    connector_contract="arkime-sessions-api:1", run_ids=None,
):
    profile = create_pull_profile(db, {
        "name": "Coverage pull", "scope_id": scope["scope_id"],
        "operator_sensor": sensor, "query_expression": query,
        "bounding_mode": "both", "cadence_minutes": 60,
        "lookback_minutes": 60, "overlap_minutes": 0,
        "collection_delay_seconds": 60, "enabled": False,
    }, actor="admin")
    with connect_database(db) as connection:
        for index, item in enumerate(imports):
            repetitions = 2 if duplicate_first and index == 0 else 1
            for repetition in range(repetitions):
                run_id = (
                    run_ids[index] if run_ids is not None
                    else f"run-{index}-0"
                )
                if repetition:
                    run_id = f"{run_id}-duplicate-{repetition}"
                connection.execute(
                    """INSERT INTO arkime_pull_runs (
                           run_id,profile_id,profile_version,request_kind,state,scope_id,
                           scope_label,scope_version,operator_sensor,query_expression,
                           bounding_mode,query_start,query_end,connector_id,
                           connector_contract,parser_version,advances_schedule,
                           request_parameters_json,actor,queued_at,completed_at,import_id
                       ) VALUES (?,?,1,'manual','complete',?,?,?,?,?,?,?,?,?,?,?,0,'{}',?,?,?,?)""",
                    (
                        run_id, profile["profile_id"],
                        scope["scope_id"], scope["label"], scope["version"],
                        sensor, query, "both",
                        item["query_start"], item["query_end"], connector_id,
                        connector_contract, ARKIME_PARSER_VERSION,
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


def test_touching_windows_are_continuous_and_partial_window_cannot_bridge_gap(tmp_path):
    db = tmp_path / "nct.db"
    scope = create_network_scope(db, label="Range", created_by="admin")
    first = _import_session(
        db, scope, "2030-01-01T00:00:00+00:00", "2030-01-01T01:00:00+00:00",
        "first", api_run_id="run-0-0",
    )
    touching = _import_session(
        db, scope, "2030-01-01T01:00:00+00:00", "2030-01-01T02:00:00+00:00",
        "touching", api_run_id="run-1-0",
    )
    partial = _import_session(
        db, scope, "2030-01-01T02:00:00+00:00", "2030-01-01T04:00:00+00:00",
        "partial", capture="partial", api_run_id="run-2-0",
    )
    after_gap = _import_session(
        db, scope, "2030-01-01T03:00:00+00:00", "2030-01-01T05:00:00+00:00",
        "after", api_run_id="run-3-0",
    )
    _link_api(db, scope, [first, touching, partial, after_gap])

    by_id = {
        item["import_id"]: item for item in list_arkime_coverage_windows(db)["items"]
    }
    assert by_id[touching["import_id"]]["continuity"] == "continuous_or_overlapping"
    assert by_id[partial["import_id"]]["continuity"] == "not_comparable"
    assert by_id[after_gap["import_id"]]["continuity"] == "retained_window_gap"
    assert by_id[after_gap["import_id"]]["gap_seconds"] == 3600


def test_duplicate_exact_bytes_remain_separate_source_receipts(tmp_path):
    db = tmp_path / "nct.db"
    scope = create_network_scope(db, label="Range", created_by="admin")
    content = _sessions(
        "2030-01-01T00:00:00+00:00", "2030-01-01T01:00:00+00:00", "same",
    )
    first = _import_session(
        db, scope, "2030-01-01T00:00:00+00:00", "2030-01-01T01:00:00+00:00",
        "first", content=content,
    )
    second = _import_session(
        db, scope, "2030-01-01T00:00:00+00:00", "2030-01-01T01:00:00+00:00",
        "second", content=content,
    )

    result = list_arkime_coverage_windows(db)
    assert result["pagination"]["total"] == 2
    assert {item["import_id"] for item in result["items"]} == {
        first["import_id"], second["import_id"],
    }
    assert first["sha256"] == second["sha256"]
    assert first["observation_id"] != second["observation_id"]
    assert second["artifact_duplicate"] is True


def test_exact_api_streams_stay_separate_by_scope_sensor_query_and_contract(tmp_path):
    db = tmp_path / "nct.db"
    scope_a = create_network_scope(db, label="Range A", created_by="admin")
    scope_b = create_network_scope(db, label="Range B", created_by="admin")
    streams = [
        (scope_a, "sensor-a", "vlan == 10", "arkime-sessions-api:1", "a"),
        (scope_b, "sensor-a", "vlan == 10", "arkime-sessions-api:1", "b"),
        (scope_a, "sensor-b", "vlan == 10", "arkime-sessions-api:1", "c"),
        (scope_a, "sensor-a", "vlan == 20", "arkime-sessions-api:1", "d"),
        (scope_a, "sensor-a", "vlan == 10", "arkime-sessions-api:2", "e"),
    ]
    imports = []
    for index, (scope, sensor, query, contract, suffix) in enumerate(streams):
        run_id = f"run-{index}-0"
        item = _import_session(
            db, scope, "2030-01-01T00:00:00+00:00", "2030-01-01T01:00:00+00:00",
            suffix, api_run_id=run_id, sensor=sensor, query=query,
            connector_contract=contract,
        )
        _link_api(
            db, scope, [item], sensor=sensor, query=query,
            connector_contract=contract, run_ids=[run_id],
        )
        imports.append(item)

    items = list_arkime_coverage_windows(db)["items"]
    selected = [item for item in items if item["import_id"] in {x["import_id"] for x in imports}]
    assert len({item["stream_identity"] for item in selected}) == len(streams)
    assert all(item["continuity"] == "first_retained_comparable_window" for item in selected)


def test_zero_session_api_window_remains_a_window_not_a_no_traffic_claim(tmp_path):
    db = tmp_path / "nct.db"
    scope = create_network_scope(db, label="Range", created_by="admin")
    empty = json.dumps({"recordsFiltered": 0, "recordsTotal": 0, "data": []}).encode()
    item = _import_session(
        db, scope, "2030-01-01T00:00:00+00:00", "2030-01-01T01:00:00+00:00",
        "empty", api_run_id="run-0-0", content=empty,
    )
    _link_api(db, scope, [item])

    retained = list_arkime_coverage_windows(db)["items"][0]
    assert retained["returned_count"] == 0
    assert retained["continuity"] == "first_retained_comparable_window"
    assert "absence of traffic" not in retained["continuity_detail"].lower()


def test_page_boundary_keeps_full_stream_continuity(tmp_path):
    db = tmp_path / "nct.db"
    scope = create_network_scope(db, label="Range", created_by="admin")
    imports = [
        _import_session(
            db, scope, f"2030-01-01T0{hour}:00:00+00:00",
            f"2030-01-01T0{hour + 1}:00:00+00:00", str(hour),
            api_run_id=f"run-{hour}-0",
        )
        for hour in range(3)
    ]
    _link_api(db, scope, imports)
    first_page = list_arkime_coverage_windows(db, limit=1)
    second_page = list_arkime_coverage_windows(
        db, limit=1, offset=1, revision=first_page["source_revision"],
    )

    assert first_page["items"][0]["continuity"] == "continuous_or_overlapping"
    assert second_page["items"][0]["continuity"] == "continuous_or_overlapping"


def test_malformed_retained_timestamp_fails_explicitly(tmp_path):
    db = tmp_path / "nct.db"
    scope = create_network_scope(db, label="Range", created_by="admin")
    item = _import_session(
        db, scope, "2030-01-01T00:00:00+00:00", "2030-01-01T01:00:00+00:00",
    )
    with connect_database(db) as connection:
        # Simulate a legacy/corrupted retained row that predates immutable guards.
        connection.execute("DROP TRIGGER arkime_imports_no_update")
        connection.execute(
            "UPDATE arkime_imports SET query_start='not-a-time' WHERE import_id=?",
            (item["import_id"],),
        )

    with pytest.raises(ArkimeCoverageError, match="invalid time metadata"):
        list_arkime_coverage_windows(db)


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
    operator_unknown = _import_session(
        db, scope, "2030-01-01T02:00:00+00:00", "2030-01-01T03:00:00+00:00", "3",
        api_run_id="run-2-0", operator_assessment="unknown",
    )
    _link_api(db, scope, [partial, ambiguous, operator_unknown], duplicate_first=False)
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
    assert by_id[operator_unknown["import_id"]]["provenance_state"] == "exact_api_run"
    assert by_id[operator_unknown["import_id"]]["continuity"] == "not_comparable"


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


def test_coverage_route_returns_read_only_forward_recommendation(tmp_path, monkeypatch):
    import app.main as main
    from fastapi.testclient import TestClient

    db = tmp_path / "route-recommend.db"
    scope = create_network_scope(db, label="Range", created_by="admin")
    item = _import_session(
        db, scope, "2020-01-01T00:00:00+00:00", "2020-01-01T01:00:00+00:00",
        api_run_id="run-0-0",
    )
    _link_api(db, scope, [item])
    listing = list_arkime_coverage_windows(db)
    stream = listing["exact_api_streams"][0]["stream_identity"]
    monkeypatch.setattr(main, "DB_PATH", db)
    with TestClient(main.app) as client:
        response = client.get("/api/arkime/coverage-windows", params={
            "recommend_stream_identity": stream,
            "overlap_minutes": 5,
            "cutoff": "2020-01-01T02:00:00Z",
            "revision": listing["source_revision"],
        })
    assert response.status_code == 200
    recommendation = response.json()["recommendation"]
    assert recommendation["status"] == "recommended"
    assert recommendation["window"]["start"] == "2020-01-01T00:55:00+00:00"
    assert recommendation["contacts_arkime"] is False


def test_next_forward_window_uses_terminal_complete_segment_and_keeps_all_anchors(tmp_path):
    db = tmp_path / "nct.db"
    scope = create_network_scope(db, label="Range", created_by="admin")
    windows = [
        ("2030-01-01T00:00:00+00:00", "2030-01-01T01:00:00+00:00", "old"),
        ("2030-01-01T03:00:00+00:00", "2030-01-01T04:00:00+00:00", "segment"),
        ("2030-01-01T03:30:00+00:00", "2030-01-01T05:00:00+00:00", "nested"),
        ("2030-01-01T05:00:00+00:00", "2030-01-01T06:00:00+00:00", "touching"),
    ]
    imports = [
        _import_session(db, scope, start, end, suffix, api_run_id=f"run-{index}-0")
        for index, (start, end, suffix) in enumerate(windows)
    ]
    imports.append(_import_session(
        db, scope, "2030-01-01T05:00:00+00:00", "2030-01-01T06:00:00+00:00",
        "duplicate", api_run_id="run-4-0",
        content=_sessions(
            "2030-01-01T05:00:00+00:00", "2030-01-01T06:00:00+00:00", "touching",
        ),
    ))
    later_partial = _import_session(
        db, scope, "2030-01-01T06:00:00+00:00", "2030-01-01T08:00:00+00:00",
        "partial", capture="partial", api_run_id="run-5-0",
    )
    _link_api(db, scope, [*imports, later_partial])
    listing = list_arkime_coverage_windows(db, limit=1)
    stream = listing["exact_api_streams"][0]

    result = list_arkime_coverage_windows(
        db, limit=1, offset=1, revision=listing["source_revision"],
        recommend_stream_identity=stream["stream_identity"], overlap_minutes=5,
        cutoff="2030-01-01T09:00:00+00:00",
        frozen_now=datetime(2030, 1, 1, 9, 5, tzinfo=timezone.utc),
    )["recommendation"]

    assert result["status"] == "recommended"
    assert result["window"] == {
        "start": "2030-01-01T05:55:00+00:00",
        "end": "2030-01-01T09:00:00+00:00",
    }
    assert {item["import_id"] for item in result["anchor_sources"]} == {
        item["import_id"] for item in imports[1:]
    }
    assert [item["import_id"] for item in result["later_noncomparable_sources"]] == [
        later_partial["import_id"]
    ]
    assert result["recollects_later_noncomparable_time"] is True
    assert result["repairs_historical_gaps"] is False
    assert result["deduplicates_observations"] is False
    assert result["contacts_arkime"] is False
    assert "1,000-session" in result["row_limit_warning"]

    changed = _import_session(
        db, scope, "2030-01-01T09:00:00+00:00", "2030-01-01T10:00:00+00:00",
        "changed", capture="partial", api_run_id="changed-run",
    )
    _link_api(db, scope, [changed], run_ids=["changed-run"])
    with pytest.raises(ArkimeCoverageConflict, match="changed while paging"):
        list_arkime_coverage_windows(
            db, revision=listing["source_revision"],
            recommend_stream_identity=stream["stream_identity"],
            cutoff="2030-01-01T11:00:00+00:00",
        )


def test_next_forward_window_requires_an_eligible_complete_api_anchor(tmp_path):
    db = tmp_path / "nct.db"
    scope = create_network_scope(db, label="Range", created_by="admin")
    unknown = _import_session(
        db, scope, "2030-01-01T00:00:00+00:00", "2030-01-01T01:00:00+00:00",
        "unknown", capture="unknown", api_run_id="run-0-0",
    )
    _link_api(db, scope, [unknown])
    listing = list_arkime_coverage_windows(db)
    stream = listing["exact_api_streams"][0]
    assert stream["eligible_window_count"] == 0

    result = list_arkime_coverage_windows(
        db, recommend_stream_identity=stream["stream_identity"],
        frozen_now=datetime(2030, 1, 1, 2, tzinfo=timezone.utc),
    )["recommendation"]
    assert result["status"] == "unavailable"
    assert result["reason"] == "no_eligible_anchor"
    assert "Complete" in result["detail"]


@pytest.mark.parametrize("overlap", [-1, 1440])
def test_next_forward_window_rejects_out_of_bounds_overlap(tmp_path, overlap):
    db = tmp_path / "nct.db"
    scope = create_network_scope(db, label="Range", created_by="admin")
    item = _import_session(
        db, scope, "2030-01-01T00:00:00+00:00", "2030-01-01T01:00:00+00:00",
        api_run_id="run-0-0",
    )
    _link_api(db, scope, [item])
    stream = list_arkime_coverage_windows(db)["exact_api_streams"][0]
    with pytest.raises(ArkimeCoverageError, match="overlap_minutes"):
        list_arkime_coverage_windows(
            db, recommend_stream_identity=stream["stream_identity"],
            overlap_minutes=overlap,
        )


def test_next_forward_window_freezes_delayed_cutoff_and_reports_nothing_due(tmp_path):
    db = tmp_path / "nct.db"
    scope = create_network_scope(db, label="Range", created_by="admin")
    item = _import_session(
        db, scope, "2030-01-01T00:00:00+00:00", "2030-01-01T02:00:00+00:00",
        api_run_id="run-0-0",
    )
    _link_api(db, scope, [item])
    stream = list_arkime_coverage_windows(db)["exact_api_streams"][0]
    result = list_arkime_coverage_windows(
        db, recommend_stream_identity=stream["stream_identity"],
        collection_delay_seconds=300,
        frozen_now=datetime(2030, 1, 1, 2, 5, tzinfo=timezone.utc),
    )["recommendation"]
    assert result["status"] == "nothing_due"
    assert result["cutoff"] == "2030-01-01T02:00:00+00:00"
    assert result["window"] is None

    future_anchor = list_arkime_coverage_windows(
        db, recommend_stream_identity=stream["stream_identity"],
        collection_delay_seconds=0,
        frozen_now=datetime(2030, 1, 1, 1, 59, tzinfo=timezone.utc),
    )["recommendation"]
    assert future_anchor["status"] == "nothing_due"
    assert future_anchor["reason"] == "cutoff_not_after_anchor"

    future_cutoff = list_arkime_coverage_windows(
        db, recommend_stream_identity=stream["stream_identity"],
        cutoff="2030-01-01T03:00:01+00:00",
        frozen_now=datetime(2030, 1, 1, 3, tzinfo=timezone.utc),
    )["recommendation"]
    assert future_cutoff["status"] == "unavailable"
    assert future_cutoff["reason"] == "cutoff_after_frozen_server_time"


def test_next_forward_window_keeps_exact_streams_separate(tmp_path):
    db = tmp_path / "nct.db"
    scope = create_network_scope(db, label="Range", created_by="admin")
    first = _import_session(
        db, scope, "2030-01-01T00:00:00+00:00", "2030-01-01T01:00:00+00:00",
        "first", api_run_id="stream-a", sensor="sensor-a",
    )
    second = _import_session(
        db, scope, "2030-01-01T10:00:00+00:00", "2030-01-01T11:00:00+00:00",
        "second", api_run_id="stream-b", sensor="sensor-b",
    )
    _link_api(db, scope, [first], sensor="sensor-a", run_ids=["stream-a"])
    _link_api(db, scope, [second], sensor="sensor-b", run_ids=["stream-b"])
    listing = list_arkime_coverage_windows(db)
    by_sensor = {item["operator_sensor"]: item for item in listing["exact_api_streams"]}
    result = list_arkime_coverage_windows(
        db, recommend_stream_identity=by_sensor["sensor-a"]["stream_identity"],
        cutoff="2030-01-01T12:00:00+00:00",
    )["recommendation"]
    assert [item["import_id"] for item in result["anchor_sources"]] == [first["import_id"]]
