from __future__ import annotations

import json

from fastapi.testclient import TestClient

from app.arkime_analytics import analyze_arkime_import
from app.arkime_evidence import import_arkime_sessions_json
from app.arkime_summary import SUMMARY_HEADERS, import_arkime_summary_csv
from app.network_scopes import create_network_scope


START = "2030-01-01T00:00:00+00:00"
END = "2030-01-01T02:00:00+00:00"


def _session(index, *, source, destination, port, packets="missing", byte_count="missing",
             applications=None, vlans=None, transport="tcp"):
    row = {
        "id": "duplicate-session-id", "node": "sensor",
        "firstPacket": (1893456000 + index * 60) * 1000,
        "lastPacket": (1893456030 + index * 60) * 1000,
        "source.ip": source, "source.port": 50000 + index,
        "destination.ip": destination, "destination.port": port,
        "network.transport": transport, "protocol": applications or [], "vlan": vlans or [],
    }
    if packets != "missing":
        row["network.packets"] = packets
    if byte_count != "missing":
        row["network.bytes"] = byte_count
    return row


def _import_sessions(db, scope):
    maximum = 9_000_000_000_000_000_000
    rows = [
        _session(1, source="10.0.0.5", destination="8.8.8.8", port=53,
                 packets=maximum, byte_count=maximum,
                 applications=["dns", "google"], vlans=[10, 20]),
        _session(2, source="10.0.0.5", destination="8.8.8.8", port=53,
                 packets=maximum, byte_count=0,
                 applications=["dns"], vlans=[10]),
        _session(3, source="10.0.0.7", destination="192.168.1.2", port=443),
    ]
    return import_arkime_sessions_json(
        db, content=json.dumps({"recordsFiltered": 3, "recordsTotal": 3, "data": rows}).encode(),
        original_filename="sessions.json", media_type="application/json",
        scope_id=scope["scope_id"], operator_sensor="sensor", query_start=START,
        query_end=END, bounding_mode="both", operator_export_assessment="complete",
        capture_coverage="complete", query_expression="", actor="analyst",
    )


def test_session_analysis_counts_rows_preserves_unknown_and_large_exact_totals(tmp_path):
    db = tmp_path / "nct.db"
    scope = create_network_scope(db, label="Range", created_by="admin")
    imported = _import_sessions(db, scope)

    result = analyze_arkime_import(db, imported["import_id"])

    source = result["top_source_addresses"][0]
    assert source["key"] == "10.0.0.5"
    assert source["retained_session_rows"] == 2
    assert source["known_packet_total"] == "18000000000000000000"
    assert source["known_byte_total"] == "9000000000000000000"
    assert source["byte_rows_missing"] == 0
    unknown = next(item for item in result["top_source_addresses"] if item["key"] == "10.0.0.7")
    assert unknown["known_packet_total"] == "0"
    assert unknown["packet_rows_missing"] == 1
    assert result["public_destination_addresses"][0]["key"] == "8.8.8.8"
    assert result["destination_port_activity"][0]["key"] == "tcp:53"
    assert result["destination_port_activity"][0]["filter_clauses"] == [
        {"field": "ipProtocol", "operator": "==", "value": "tcp"},
        {"field": "port.dst", "operator": "==", "value": 53},
    ]
    assert result["transport_activity"][0]["key"] == "tcp"
    assert next(item for item in result["application_activity"] if item["key"] == "dns")["retained_session_rows"] == 2
    assert next(item for item in result["vlan_activity"] if item["key"] == "10")["retained_session_rows"] == 2
    assert result["read_only"] is True


def test_session_analysis_applies_multiple_arkime_style_clauses_locally(tmp_path):
    db = tmp_path / "nct.db"
    scope = create_network_scope(db, label="Range", created_by="admin")
    imported = _import_sessions(db, scope)

    result = analyze_arkime_import(
        db, imported["import_id"],
        filters=[
            {"field": "ip.src", "operator": "==", "value": "10.0.0.5"},
            {"field": "protocols", "operator": "==", "value": "google"},
        ],
        match_mode="all",
    )

    assert result["unfiltered_row_count"] == 3
    assert result["filtered_row_count"] == 1
    assert result["filter_expression"] == (
        "(ip.src == 10.0.0.5) && (protocols == google)"
    )
    assert result["top_source_addresses"][0]["retained_session_rows"] == 1
    assert "does not contact Arkime" in result["filter_note"]


def test_session_analysis_supports_match_any_exclusion_and_unknown(tmp_path):
    db = tmp_path / "nct.db"
    scope = create_network_scope(db, label="Range", created_by="admin")
    imported = _import_sessions(db, scope)

    any_result = analyze_arkime_import(
        db, imported["import_id"],
        filters=[
            {"field": "ip.src", "operator": "==", "value": "10.0.0.7"},
            {"field": "protocols", "operator": "==", "value": "google"},
        ],
        match_mode="any",
    )
    excluded = analyze_arkime_import(
        db, imported["import_id"],
        filters=[{"field": "ip.dst", "operator": "!=", "value": "8.8.8.8"}],
    )
    unknown_vlan = analyze_arkime_import(
        db, imported["import_id"],
        filters=[{"field": "vlan", "operator": "==", "value": None}],
    )

    assert any_result["filtered_row_count"] == 2
    assert " || " in any_result["filter_expression"]
    assert excluded["filtered_row_count"] == 1
    assert unknown_vlan["filtered_row_count"] == 1
    assert unknown_vlan["filter_expression"] == "(vlan != EXISTS!)"


def test_port_group_filter_preserves_transport_for_include_exclude_and_or(tmp_path):
    db = tmp_path / "nct.db"
    scope = create_network_scope(db, label="Range", created_by="admin")
    rows = [
        _session(1, source="10.0.0.5", destination="8.8.8.8", port=53,
                 packets=1, byte_count=1, applications=["dns"], transport="tcp"),
        _session(2, source="10.0.0.6", destination="8.8.4.4", port=53,
                 packets=1, byte_count=1, applications=["dns"], transport="udp"),
        _session(3, source="10.0.0.7", destination="1.1.1.1", port=443,
                 packets=1, byte_count=1, applications=["tls"], transport="tcp"),
    ]
    imported = import_arkime_sessions_json(
        db, content=json.dumps({"recordsFiltered": 3, "recordsTotal": 3, "data": rows}).encode(),
        original_filename="mixed.json", media_type="application/json",
        scope_id=scope["scope_id"], operator_sensor="sensor", query_start=START,
        query_end=END, bounding_mode="both", operator_export_assessment="complete",
        capture_coverage="complete", query_expression="", actor="analyst",
    )
    tcp_53 = {
        "clauses": [
            {"field": "ipProtocol", "operator": "==", "value": "tcp"},
            {"field": "port.dst", "operator": "==", "value": 53},
        ],
        "match_mode": "all", "negated": False,
    }
    included = analyze_arkime_import(db, imported["import_id"], filters=[tcp_53])
    excluded = analyze_arkime_import(
        db, imported["import_id"], filters=[{**tcp_53, "negated": True}],
    )
    combined_or = analyze_arkime_import(
        db, imported["import_id"], match_mode="any",
        filters=[tcp_53, {"field": "port.dst", "operator": "==", "value": 443}],
    )
    assert included["filtered_row_count"] == 1
    assert included["filter_expression"] == (
        "((ipProtocol == tcp) && (port.dst == 53))"
    )
    assert excluded["filtered_row_count"] == 2
    assert excluded["filter_expression"].startswith("!((ipProtocol == tcp)")
    assert combined_or["filtered_row_count"] == 2


def test_literal_unknown_application_stays_distinct_from_missing_application(tmp_path):
    db = tmp_path / "nct.db"
    scope = create_network_scope(db, label="Range", created_by="admin")
    rows = [
        _session(1, source="10.0.0.5", destination="8.8.8.8", port=53,
                 packets=1, byte_count=1, applications=["unknown"]),
        _session(2, source="10.0.0.6", destination="1.1.1.1", port=443,
                 packets=1, byte_count=1, applications=[]),
    ]
    imported = import_arkime_sessions_json(
        db, content=json.dumps({"recordsFiltered": 2, "recordsTotal": 2, "data": rows}).encode(),
        original_filename="unknown.json", media_type="application/json",
        scope_id=scope["scope_id"], operator_sensor="sensor", query_start=START,
        query_end=END, bounding_mode="both", operator_export_assessment="complete",
        capture_coverage="complete", query_expression="", actor="analyst",
    )
    result = analyze_arkime_import(db, imported["import_id"])
    assert [(item["label"], item["retained_session_rows"]) for item in result["application_activity"]] == [
        ("Unknown application", 1), ("unknown", 1),
    ]
    literal = analyze_arkime_import(
        db, imported["import_id"],
        filters=[{"field": "protocols", "operator": "==", "value": "unknown"}],
    )
    missing = analyze_arkime_import(
        db, imported["import_id"],
        filters=[{"field": "protocols", "operator": "==", "value": None}],
    )
    assert literal["filtered_row_count"] == 1
    assert missing["filtered_row_count"] == 1


def test_summary_analysis_keeps_potentially_overlapping_groups_separate(tmp_path):
    db = tmp_path / "nct.db"
    scope = create_network_scope(db, label="Range", created_by="admin")
    header = ",".join(SUMMARY_HEADERS)
    content = (header + "\n"
               "10.0.0.5,8.8.8.8,443,tcp,tls,10,5,,100\n"
               "10.0.0.5,8.8.8.8,443,tcp,https,10,7,0,200\n").encode()
    imported = import_arkime_summary_csv(
        db, content=content, original_filename="summary.csv", media_type="text/csv",
        scope_id=scope["scope_id"], operator_sensor="sensor", query_start=START,
        query_end=END, bounding_mode="both", query_expression="",
        summary_basis="all_matching_groups", top_n_limit=None,
        operator_export_assessment="complete", capture_coverage="unknown", actor="analyst",
    )

    result = analyze_arkime_import(db, imported["import_id"])

    assert result["analysis_mode"] == "reported_summary_groups"
    assert result["top_source_addresses"] == []
    assert result["reported_group_count"] == 2
    assert {item["detected_protocol"] for item in result["reported_groups"]} == {"tls", "https"}
    assert {item["session_count"] for item in result["reported_groups"]} == {"5", "7"}
    assert {item["packet_count"] for item in result["reported_groups"]} == {None, "0"}
    assert all(item["public_destination"] for item in result["reported_groups"])
    assert "does not add groups" in result["metric_definition"]

    filtered = analyze_arkime_import(
        db, imported["import_id"],
        filters=[{"field": "protocols", "operator": "==", "value": "tls"}],
    )
    assert filtered["filtered_row_count"] == 1
    assert filtered["reported_groups"][0]["detected_protocol"] == "tls"


def test_traffic_analysis_route_uses_one_exact_import(tmp_path, monkeypatch):
    import app.main as main

    db = tmp_path / "route.db"
    scope = create_network_scope(db, label="Range", created_by="admin")
    imported = _import_sessions(db, scope)
    monkeypatch.setattr(main, "DB_PATH", db)
    with TestClient(main.app) as client:
        response = client.get(
            "/api/arkime/traffic-analysis",
            params={
                "import_id": imported["import_id"], "limit": 1,
                "filters": json.dumps([
                    {"field": "port.dst", "operator": "==", "value": 53},
                ]),
            },
        )
    assert response.status_code == 200
    assert response.json()["import_id"] == imported["import_id"]
    assert len(response.json()["top_source_addresses"]) == 1
    assert response.json()["filtered_row_count"] == 2


def test_traffic_analysis_route_rejects_invalid_filter_json(tmp_path, monkeypatch):
    import app.main as main

    monkeypatch.setattr(main, "DB_PATH", tmp_path / "route.db")
    with TestClient(main.app) as client:
        response = client.get(
            "/api/arkime/traffic-analysis",
            params={"import_id": "anything", "filters": "not-json"},
        )
    assert response.status_code == 422
    assert response.json()["detail"] == "filters must be valid JSON"

    with TestClient(main.app) as client:
        malformed = client.get(
            "/api/arkime/traffic-analysis",
            params={"import_id": "anything", "filters": json.dumps([
                {"field": [], "operator": "==", "value": "tcp"},
            ])},
        )
    assert malformed.status_code == 422
    assert "malformed" in malformed.json()["detail"]

    with TestClient(main.app) as client:
        malformed_group_mode = client.get(
            "/api/arkime/traffic-analysis",
            params={"import_id": "anything", "filters": json.dumps([{
                "clauses": [{"field": "port.dst", "operator": "==", "value": 53}],
                "match_mode": [],
            }])},
        )
        unicode_numeric = client.get(
            "/api/arkime/traffic-analysis",
            params={"import_id": "anything", "filters": json.dumps([
                {"field": "vlan", "operator": "==", "value": "²"},
            ])},
        )
    assert malformed_group_mode.status_code == 422
    assert "match_mode" in malformed_group_mode.json()["detail"]
    assert unicode_numeric.status_code == 422
    assert "non-negative integer" in unicode_numeric.json()["detail"]


def test_summary_template_route_still_returns_the_csv(tmp_path, monkeypatch):
    import app.main as main

    monkeypatch.setattr(main, "DB_PATH", tmp_path / "route.db")
    with TestClient(main.app) as client:
        response = client.get("/api/arkime/summary-template.csv")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/csv")
    assert "source_ip,destination_ip" in response.text
