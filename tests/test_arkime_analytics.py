from __future__ import annotations

import json

from fastapi.testclient import TestClient
import pytest

from app.artifacts import register_artifact_bytes
from app.assigned_nmap_ingestion import ingest_assigned_nmap_observation
from app.arkime_analytics import (
    ArkimeAnalyticsError,
    analyze_arkime_import,
    build_hunt_arkime_context,
    parse_arkime_filter_expression,
)
from app.arkime_evidence import import_arkime_sessions_json
from app.arkime_summary import SUMMARY_HEADERS, import_arkime_summary_csv
from app.database import connect_database
from app.evidence_scope_assignments import assign_artifact_scope, correct_artifact_scope
from app.foundation_evidence import get_foundation_scope_evidence
from app.network_scopes import archive_network_scope, create_network_scope


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


def _nmap_xml(
    requested_ports, services, *, address="192.0.2.10", start=1893450000,
    host_start=None, host_end=None, finish=None, omitted_state="closed",
):
    finish = finish if finish is not None else start + 10
    host_start = host_start if host_start is not None else start + 1
    host_end = host_end if host_end is not None else finish - 1
    explicit = {port for protocol, port, _ in services if protocol == "tcp"}
    omitted = len(set(requested_ports) - explicit)
    ports = "".join(
        f'<port protocol="{protocol}" portid="{port}"><state state="{state}"/>'
        f'<service name="service-{port}"/></port>'
        for protocol, port, state in services
    )
    extras = (
        f'<extraports state="{omitted_state}" count="{omitted}"/>' if omitted else ""
    )
    return (
        f'<nmaprun scanner="nmap" args="nmap -n {address}" start="{start}">'
        f'<scaninfo type="syn" protocol="tcp" numservices="{len(requested_ports)}" '
        f'services="{",".join(str(port) for port in requested_ports)}"/>'
        f'<host starttime="{host_start}" endtime="{host_end}"><status state="up"/>'
        f'<address addr="{address}" addrtype="ipv4"/><ports>{extras}{ports}</ports>'
        f'</host><runstats><finished time="{finish}" exit="success"/></runstats>'
        '</nmaprun>'
    ).encode()


def _process_nmap(db, scope, content, source_ref):
    observation = register_artifact_bytes(
        db_path=db, content=content, source_kind="nmap_import",
        source_ref=source_ref, original_filename=f"{source_ref}.xml",
        actor="analyst", observed_at="2030-01-01T03:00:00+00:00",
    )
    assignment = assign_artifact_scope(
        db, artifact_observation_id=observation["observation_id"],
        scope_id=scope["scope_id"], actor="analyst",
        reason="Confirmed exact whole-file context", whole_artifact_confirmed=True,
    )
    ingest_assigned_nmap_observation(
        db, expected_assignment_id=assignment["assignment_id"],
        linked_by="analyst", parser_version="nmap-endpoints:2",
    )
    return observation, assignment


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
    assert result["correlated_path_count"] == 2
    path = result["correlated_paths"][0]
    assert (path["source_ip"], path["destination_ip"], path["destination_port"], path["transport"]) == (
        "10.0.0.5", "8.8.8.8", 53, "tcp",
    )
    assert path["retained_session_rows"] == 2
    assert path["known_packet_total"] == "18000000000000000000"
    assert path["known_byte_total"] == "9000000000000000000"
    assert path["filter_clauses"] == [
        {"field": "ip.src", "operator": "==", "value": "10.0.0.5"},
        {"field": "ip.dst", "operator": "==", "value": "8.8.8.8"},
        {"field": "ipProtocol", "operator": "==", "value": "tcp"},
        {"field": "port.dst", "operator": "==", "value": 53},
    ]
    assert result["read_only"] is True


def test_session_paths_add_exact_scope_nmap_context_and_keep_windows_separate(tmp_path):
    db = tmp_path / "nct.db"
    range_scope = create_network_scope(db, label="Range", created_by="admin")
    observation, _ = _process_nmap(
        db, range_scope,
        _nmap_xml([443], [("tcp", 443, "open")], start=1893440000),
        "upload:range-open-443",
    )
    imported = import_arkime_sessions_json(
        db, content=json.dumps({"data": [
            _session(1, source="10.0.0.5", destination="192.0.2.10", port=443),
        ]}).encode(), original_filename="sessions.json", media_type="application/json",
        scope_id=range_scope["scope_id"], operator_sensor="sensor",
        query_start=START, query_end=END, bounding_mode="both",
        operator_export_assessment="complete", capture_coverage="complete",
        query_expression="", actor="analyst",
    )

    result = analyze_arkime_import(db, imported["import_id"])
    context = result["correlated_paths"][0]["active_context"]

    assert result["active_context_contract"] == "arkime-active-context:1"
    assert context["status"] == "reported_open_and_observed"
    assert context["passive_observation"]["status"] == "passively_observed"
    assert context["passive_observation"]["label"] == "Passively observed"
    assert context["active_validation"] is None
    assert context["reported_state"] == "open"
    assert context["reported_basis"] == "explicit"
    assert context["scope_id"] == range_scope["scope_id"]
    assert context["scope_version"] == imported["scope"]["version"]
    assert context["destination_endpoint"]["address"] == "192.0.2.10"
    assert context["active_sources"][0]["observation_id"] == observation["observation_id"]
    assert context["active_sources"][0]["source_url"]
    assert context["selection_revision"]
    assert context["evidence_windows"]["relationship"] == "active_before_passive"
    assert "different times" in context["evidence_windows"]["note"]
    assert context["claims"] == {
        "live_or_current_network_truth": False,
        "physical_device_identity": False,
        "connection_succeeded": False,
        "listener_open": False,
        "same_event": False,
    }
    archive_network_scope(
        db, range_scope["scope_id"], expected_version=range_scope["version"],
        archived_by="admin", reason="Retain historical scope evidence",
    )
    archived = analyze_arkime_import(db, imported["import_id"])
    assert archived["correlated_paths"][0]["active_context"]["status"] == (
        "reported_open_and_observed"
    )


def test_path_context_does_not_cross_scopes_and_preserves_scope_correction(tmp_path):
    db = tmp_path / "nct.db"
    first = create_network_scope(db, label="First", created_by="admin")
    second = create_network_scope(db, label="Second", created_by="admin")
    _, assignment = _process_nmap(
        db, second, _nmap_xml([443], [("tcp", 443, "open")]),
        "upload:second-only",
    )
    imported = import_arkime_sessions_json(
        db, content=json.dumps({"data": [
            _session(1, source="10.0.0.5", destination="192.0.2.10", port=443),
        ]}).encode(), original_filename="first-scope.json", media_type="application/json",
        scope_id=first["scope_id"], operator_sensor="sensor", query_start=START,
        query_end=END, bounding_mode="both", operator_export_assessment="complete",
        capture_coverage="complete", query_expression="", actor="analyst",
    )
    before = analyze_arkime_import(db, imported["import_id"])
    passive_only = before["correlated_paths"][0]["active_context"]
    assert passive_only["status"] == "passive_only_in_scope"
    assert passive_only["passive_observation"]["label"] == "Passively observed"
    assert passive_only["active_validation"]["status"] == "not_actively_validated"
    assert passive_only["active_validation"]["label"] == "Not actively validated"
    assert "same Network Scope" in passive_only["active_validation"]["reason"]
    with connect_database(db, read_only=True) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM endpoint_entities WHERE scope_id=?",
            (first["scope_id"],),
        ).fetchone()[0] == 0

    corrected = correct_artifact_scope(
        db, expected_assignment_id=assignment["assignment_id"],
        destination_scope_id=first["scope_id"], actor="analyst",
        reason="Corrected exact context", whole_artifact_confirmed=True,
    )
    ingest_assigned_nmap_observation(
        db, expected_assignment_id=corrected["assignment_id"],
        linked_by="analyst", parser_version="nmap-endpoints:2",
    )
    moved = analyze_arkime_import(db, imported["import_id"])
    context = moved["correlated_paths"][0]["active_context"]
    assert context["status"] == "reported_open_and_observed"
    assert context["scope_id"] == first["scope_id"]


def test_path_context_resolves_exact_service_beyond_page_and_aggregate_omission(tmp_path):
    db = tmp_path / "nct.db"
    range_scope = create_network_scope(db, label="Range", created_by="admin")
    ports = list(range(1, 101)) + [65000]
    _process_nmap(
        db, range_scope,
        _nmap_xml(ports, [("tcp", port, "open") for port in ports]),
        "upload:more-than-one-service-page",
    )
    imported = import_arkime_sessions_json(
        db, content=json.dumps({"data": [
            _session(1, source="10.0.0.5", destination="192.0.2.10", port=65000),
        ]}).encode(), original_filename="exact-port.json", media_type="application/json",
        scope_id=range_scope["scope_id"], operator_sensor="sensor", query_start=START,
        query_end=END, bounding_mode="both", operator_export_assessment="complete",
        capture_coverage="complete", query_expression="", actor="analyst",
    )
    exact = analyze_arkime_import(db, imported["import_id"])
    assert exact["correlated_paths"][0]["active_context"]["status"] == "reported_open_and_observed"

    later_scope = create_network_scope(db, label="Aggregate", created_by="admin")
    _process_nmap(
        db, later_scope, _nmap_xml([4444], [], omitted_state="closed"),
        "upload:aggregate-closed",
    )
    aggregate_import = import_arkime_sessions_json(
        db, content=json.dumps({"data": [
            _session(2, source="10.0.0.7", destination="192.0.2.10", port=4444),
        ]}).encode(), original_filename="aggregate.json", media_type="application/json",
        scope_id=later_scope["scope_id"], operator_sensor="sensor", query_start=START,
        query_end=END, bounding_mode="both", operator_export_assessment="complete",
        capture_coverage="complete", query_expression="", actor="analyst",
    )
    aggregate = analyze_arkime_import(db, aggregate_import["import_id"])
    aggregate_context = aggregate["correlated_paths"][0]["active_context"]
    assert aggregate_context["status"] == "observed_scan_mismatch"
    assert aggregate_context["passive_observation"]["label"] == "Passively observed"
    assert aggregate_context["active_validation"] is None
    assert aggregate_context["reported_state"] == "closed"
    assert aggregate_context["reported_basis"] == "aggregate"


@pytest.mark.parametrize(
    ("reported_state", "reason_text"),
    [("closed", "reported closed"), ("filtered", "reported filtered"),
     ("open|filtered", "ambiguous state (open|filtered)")],
)
def test_scan_mismatch_keeps_closed_filtered_and_ambiguous_states_distinct(
    tmp_path, reported_state, reason_text,
):
    db = tmp_path / "nct.db"
    range_scope = create_network_scope(db, label="Range", created_by="admin")
    _process_nmap(
        db, range_scope, _nmap_xml([443], [("tcp", 443, reported_state)]),
        f"upload:{reported_state}",
    )
    imported = import_arkime_sessions_json(
        db, content=json.dumps({"data": [
            _session(1, source="10.0.0.5", destination="192.0.2.10", port=443),
        ]}).encode(), original_filename="mismatch.json", media_type="application/json",
        scope_id=range_scope["scope_id"], operator_sensor="sensor", query_start=START,
        query_end=END, bounding_mode="both", operator_export_assessment="complete",
        capture_coverage="complete", query_expression="", actor="analyst",
    )
    context = analyze_arkime_import(db, imported["import_id"])["correlated_paths"][0][
        "active_context"
    ]
    assert context["status"] == "observed_scan_mismatch"
    assert context["reported_state"] == reported_state
    assert reason_text in context["reason"]
    assert "do not prove that a connection succeeded" in context["reason"]


def test_path_context_preserves_unresolved_sources_and_missing_fields(tmp_path):
    db = tmp_path / "nct.db"
    range_scope = create_network_scope(db, label="Range", created_by="admin")
    for index, (state, start, host_start, host_end) in enumerate([
        ("open", 1893450000, 1893450001, 1893450015),
        ("closed", 1893450005, 1893450010, 1893450020),
    ]):
        _process_nmap(
            db, range_scope,
            _nmap_xml(
                [443], [("tcp", 443, state)], start=start,
                host_start=host_start, host_end=host_end, finish=host_end + 1,
            ), f"upload:overlap-{index}",
        )
    imported = import_arkime_sessions_json(
        db, content=json.dumps({"data": [
            _session(1, source="10.0.0.5", destination="192.0.2.10", port=443),
            _session(2, source="10.0.0.5", destination="192.0.2.10", port=None),
            _session(3, source="10.0.0.5", destination="192.0.2.10", port=444,
                     transport=None),
        ]}).encode(), original_filename="unresolved.json", media_type="application/json",
        scope_id=range_scope["scope_id"], operator_sensor="sensor", query_start=START,
        query_end=END, bounding_mode="both", operator_export_assessment="complete",
        capture_coverage="complete", query_expression="", actor="analyst",
    )
    result = analyze_arkime_import(db, imported["import_id"])
    by_port = {item["destination_port"]: item["active_context"]
               for item in result["correlated_paths"]}
    assert by_port[443]["status"] == "active_state_unresolved"
    assert by_port[443]["active_validation"]["label"] == "Not actively validated"
    assert {item["source_ref"] for item in by_port[443]["active_sources"]} == {
        "upload:overlap-0", "upload:overlap-1",
    }
    assert by_port[None]["status"] == "insufficient_path_fields"
    assert by_port[None]["passive_observation"]["label"] == "Passively observed"
    assert by_port[None]["active_validation"]["label"] == "Not actively validated"
    assert by_port[None]["selection_revision"] is None
    assert by_port[444]["status"] == "insufficient_path_fields"


def test_path_context_keeps_unknown_nmap_time_unresolved(tmp_path):
    db = tmp_path / "nct.db"
    range_scope = create_network_scope(db, label="Range", created_by="admin")
    timed = _nmap_xml([443], [("tcp", 443, "open")], start=1893450000)
    unknown = _nmap_xml([443], [("tcp", 443, "closed")], start=1893450100)
    unknown = unknown.replace(
        b' starttime="1893450101" endtime="1893450109"', b"",
    )
    _process_nmap(db, range_scope, timed, "upload:timed")
    _process_nmap(db, range_scope, unknown, "upload:unknown-time")
    imported = import_arkime_sessions_json(
        db, content=json.dumps({"data": [
            _session(1, source="10.0.0.5", destination="192.0.2.10", port=443),
        ]}).encode(), original_filename="unknown-time.json", media_type="application/json",
        scope_id=range_scope["scope_id"], operator_sensor="sensor", query_start=START,
        query_end=END, bounding_mode="both", operator_export_assessment="complete",
        capture_coverage="complete", query_expression="", actor="analyst",
    )
    context = analyze_arkime_import(db, imported["import_id"])["correlated_paths"][0][
        "active_context"
    ]
    assert context["status"] == "active_state_unresolved"
    assert context["active_validation"]["status"] == "not_actively_validated"
    assert len(context["active_sources"]) == 2
    assert context["evidence_windows"]["relationship"] == "unknown"


def test_arkime_and_nmap_context_share_one_read_snapshot(tmp_path, monkeypatch):
    from app import arkime_analytics as analytics

    db = tmp_path / "nct.db"
    first = create_network_scope(db, label="First", created_by="admin")
    second = create_network_scope(db, label="Second", created_by="admin")
    _, assignment = _process_nmap(
        db, first, _nmap_xml([443], [("tcp", 443, "open")]),
        "upload:snapshot",
    )
    imported = import_arkime_sessions_json(
        db, content=json.dumps({"data": [
            _session(1, source="10.0.0.5", destination="192.0.2.10", port=443),
        ]}).encode(), original_filename="snapshot.json", media_type="application/json",
        scope_id=first["scope_id"], operator_sensor="sensor", query_start=START,
        query_end=END, bounding_mode="both", operator_export_assessment="complete",
        capture_coverage="complete", query_expression="", actor="analyst",
    )
    original = analytics.get_foundation_exact_service_states_snapshot
    changed = False

    def correct_during_selection(connection, scope_id, entity_id, services):
        nonlocal changed
        if not changed:
            changed = True
            corrected = correct_artifact_scope(
                db, expected_assignment_id=assignment["assignment_id"],
                destination_scope_id=second["scope_id"], actor="analyst",
                reason="Concurrent reviewed correction", whole_artifact_confirmed=True,
            )
            ingest_assigned_nmap_observation(
                db, expected_assignment_id=corrected["assignment_id"],
                linked_by="analyst", parser_version="nmap-endpoints:2",
            )
        return original(connection, scope_id, entity_id, services)

    monkeypatch.setattr(
        analytics, "get_foundation_exact_service_states_snapshot",
        correct_during_selection,
    )
    frozen = analyze_arkime_import(db, imported["import_id"])
    assert frozen["correlated_paths"][0]["active_context"]["status"] == (
        "reported_open_and_observed"
    )
    refreshed = analyze_arkime_import(db, imported["import_id"])
    assert refreshed["correlated_paths"][0]["active_context"]["status"] == (
        "not_actively_assessed"
    )


def test_typed_expression_parses_exact_fields_groups_quotes_and_unknown():
    filters, match_mode = parse_arkime_filter_expression(
        'ip.src == 10.0.0.5 && (port.dst == 53 || protocols == "domain name")'
    )
    assert match_mode == "all"
    assert filters == [
        {"field": "ip.src", "operator": "==", "value": "10.0.0.5"},
        {
            "clauses": [
                {"field": "port.dst", "operator": "==", "value": 53},
                {"field": "protocols", "operator": "==", "value": "domain name"},
            ],
            "match_mode": "any", "negated": False,
        },
    ]
    missing, missing_mode = parse_arkime_filter_expression("vlan != EXISTS!")
    assert missing_mode == "all"
    assert missing == [{"field": "vlan", "operator": "==", "value": None}]

    with pytest.raises(ValueError, match="one connector"):
        parse_arkime_filter_expression(
            "ip.src == 10.0.0.5 && port.dst == 53 || protocols == dns"
        )
    with pytest.raises(ValueError, match="unsupported or malformed"):
        parse_arkime_filter_expression("source.ip == 10.0.0.5")


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
    assert result["correlated_paths"] == []
    assert "can overlap" in result["correlation_note"]
    assert result["active_context_contract"] is None
    assert "not calculated" in result["active_context_note"]

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

    with TestClient(main.app) as client:
        typed = client.get(
            "/api/arkime/traffic-analysis",
            params={
                "import_id": imported["import_id"],
                "expression": "ip.src == 10.0.0.5 && protocols == google",
            },
        )
    assert typed.status_code == 200
    assert typed.json()["filtered_row_count"] == 1
    assert typed.json()["filter_expression"] == (
        "(ip.src == 10.0.0.5) && (protocols == google)"
    )


def test_hunt_context_keeps_exact_source_and_separate_claim_boundary(tmp_path):
    db = tmp_path / "hunt-context.db"
    scope = create_network_scope(db, label="Range", created_by="admin")
    imported = _import_sessions(db, scope)

    result = build_hunt_arkime_context(db, imported["import_id"], limit=1)

    assert result["contract"] == "arkime-hunt-context:1"
    assert result["import_id"] == imported["import_id"]
    assert result["scope"] == {
        "scope_id": scope["scope_id"], "label": "Range", "version": 1,
    }
    assert result["correlated_path_count"] == 2
    assert len(result["correlated_paths"]) == 1
    assert result["correlated_paths_truncated"] is True
    assert result["raw_url"].endswith(f'/{imported["import_id"]}/raw')
    assert result["claims"] == {
        "creates_current_hosts": False,
        "changes_candidate_matching": False,
        "changes_hunt_filters": False,
        "included_in_hunt_exports": False,
        "proves_live_service": False,
        "proves_connection_success": False,
        "changes_reach_or_map": False,
    }


def test_hunt_context_rejects_summary_source(tmp_path):
    db = tmp_path / "hunt-summary.db"
    scope = create_network_scope(db, label="Range", created_by="admin")
    content = (",".join(SUMMARY_HEADERS) + "\n"
               "10.0.0.5,8.8.8.8,443,tcp,tls,10,5,8,100\n").encode()
    imported = import_arkime_summary_csv(
        db, content=content, original_filename="summary.csv", media_type="text/csv",
        scope_id=scope["scope_id"], operator_sensor="sensor", query_start=START,
        query_end=END, bounding_mode="both", query_expression="",
        summary_basis="all_matching_groups", top_n_limit=None,
        operator_export_assessment="complete", capture_coverage="unknown", actor="analyst",
    )

    with pytest.raises(ArkimeAnalyticsError, match="Sessions JSON/API source"):
        build_hunt_arkime_context(db, imported["import_id"])


def test_hunt_passive_context_route_is_independent_and_rejects_bad_sources(
    tmp_path, monkeypatch,
):
    import app.main as main

    db = tmp_path / "hunt-route.db"
    scope = create_network_scope(db, label="Range", created_by="admin")
    sessions = _import_sessions(db, scope)
    content = (",".join(SUMMARY_HEADERS) + "\n"
               "10.0.0.5,8.8.8.8,443,tcp,tls,10,5,8,100\n").encode()
    summary = import_arkime_summary_csv(
        db, content=content, original_filename="summary.csv", media_type="text/csv",
        scope_id=scope["scope_id"], operator_sensor="sensor", query_start=START,
        query_end=END, bounding_mode="both", query_expression="",
        summary_basis="all_matching_groups", top_n_limit=None,
        operator_export_assessment="complete", capture_coverage="unknown", actor="analyst",
    )
    monkeypatch.setattr(main, "DB_PATH", db)
    network_calls = []
    monkeypatch.setattr(
        main, "_latest_network_evidence",
        lambda: network_calls.append(True) or {
            "hosts": [], "findings": [], "source": {"scope_summaries": []},
        },
    )
    monkeypatch.setattr(main, "list_saved_networks", lambda _path: [])
    monkeypatch.setattr(main, "_latest_device_reachability_evidence", lambda: [])
    monkeypatch.setattr(main, "load_retained_searchsploit_candidates", lambda *_args: [])
    monkeypatch.setattr(
        main, "classify_searchsploit_exposure",
        lambda *_args, **_kwargs: {"status": "complete", "matches": []},
    )

    with TestClient(main.app) as client:
        before = client.get("/api/hunting/network").json()
        valid = client.get(
            "/api/hunting/passive-context",
            params={"import_id": sessions["import_id"], "limit": 1},
        )
        missing = client.get(
            "/api/hunting/passive-context", params={"import_id": "deleted-source"},
        )
        rejected = client.get(
            "/api/hunting/passive-context", params={"import_id": summary["import_id"]},
        )
        after = client.get("/api/hunting/network").json()

    assert valid.status_code == 200
    assert valid.json()["import_id"] == sessions["import_id"]
    assert missing.status_code == 404
    assert rejected.status_code == 422
    assert "Sessions JSON/API source" in rejected.json()["detail"]
    assert before == after
    assert len(network_calls) == 2


def test_traffic_analysis_route_reports_active_context_candidate_bound(
    tmp_path, monkeypatch,
):
    import app.main as main
    from app import foundation_evidence as evidence

    db = tmp_path / "candidate-bound.db"
    scope = create_network_scope(db, label="Range", created_by="admin")
    for index in range(2):
        _process_nmap(
            db, scope,
            _nmap_xml(
                [443], [("tcp", 443, "open")],
                start=1893440000 + index * 100,
            ),
            f"upload:candidate-bound-{index}",
        )
    imported = import_arkime_sessions_json(
        db, content=json.dumps({"data": [
            _session(1, source="10.0.0.5", destination="192.0.2.10", port=443),
        ]}).encode(), original_filename="candidate-bound.json",
        media_type="application/json", scope_id=scope["scope_id"],
        operator_sensor="sensor", query_start=START, query_end=END,
        bounding_mode="both", operator_export_assessment="complete",
        capture_coverage="complete", query_expression="", actor="analyst",
    )
    monkeypatch.setattr(main, "DB_PATH", db)
    monkeypatch.setattr(evidence, "MAX_CURRENT_SERVICE_CANDIDATES", 1)

    with TestClient(main.app) as client:
        response = client.get(
            "/api/arkime/traffic-analysis",
            params={"import_id": imported["import_id"]},
        )

    assert response.status_code == 422
    assert response.json()["detail"].startswith("Active Nmap context is unavailable:")
    assert "source-record bound" in response.json()["detail"]
    assert "no partial result was produced" in response.json()["detail"]


def test_traffic_analysis_route_reports_active_context_unresolved_evidence_bound(
    tmp_path, monkeypatch,
):
    import app.main as main
    from app import foundation_evidence as evidence

    db = tmp_path / "unresolved-bound.db"
    scope = create_network_scope(db, label="Range", created_by="admin")
    for index, state in enumerate(("open", "closed")):
        content = _nmap_xml(
            [443], [("tcp", 443, state)], start=1893440000 + index * 100,
        ).replace(
            (
                f' starttime="{1893440001 + index * 100}" '
                f'endtime="{1893440009 + index * 100}"'
            ).encode(),
            b"",
        )
        _process_nmap(db, scope, content, f"upload:unresolved-bound-{index}")
    imported = import_arkime_sessions_json(
        db, content=json.dumps({"data": [
            _session(1, source="10.0.0.5", destination="192.0.2.10", port=443),
        ]}).encode(), original_filename="unresolved-bound.json",
        media_type="application/json", scope_id=scope["scope_id"],
        operator_sensor="sensor", query_start=START, query_end=END,
        bounding_mode="both", operator_export_assessment="complete",
        capture_coverage="complete", query_expression="", actor="analyst",
    )
    monkeypatch.setattr(main, "DB_PATH", db)
    monkeypatch.setattr(evidence, "MAX_CURRENT_SERVICE_EVIDENCE", 1)

    with TestClient(main.app) as client:
        response = client.get(
            "/api/arkime/traffic-analysis",
            params={"import_id": imported["import_id"]},
        )

    assert response.status_code == 422
    assert response.json()["detail"].startswith("Active Nmap context is unavailable:")
    assert "more than 1 unresolved latest source records" in response.json()["detail"]
    assert "no partial result was produced" in response.json()["detail"]


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

    with TestClient(main.app) as client:
        both_shapes = client.get(
            "/api/arkime/traffic-analysis",
            params={"import_id": "anything", "filters": "[]", "expression": "vlan == 10"},
        )
        unsupported_expression = client.get(
            "/api/arkime/traffic-analysis",
            params={"import_id": "anything", "expression": "source.ip == 10.0.0.5"},
        )
    assert both_shapes.status_code == 422
    assert "either a typed expression" in both_shapes.json()["detail"]
    assert unsupported_expression.status_code == 422
    assert "unsupported or malformed" in unsupported_expression.json()["detail"]


def test_summary_template_route_still_returns_the_csv(tmp_path, monkeypatch):
    import app.main as main

    monkeypatch.setattr(main, "DB_PATH", tmp_path / "route.db")
    with TestClient(main.app) as client:
        response = client.get("/api/arkime/summary-template.csv")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/csv")
    assert "source_ip,destination_ip" in response.text
