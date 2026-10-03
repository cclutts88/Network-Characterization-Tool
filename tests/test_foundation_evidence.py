from fastapi.testclient import TestClient
import pytest

from app.artifacts import register_artifact_bytes
from app.assigned_nmap_ingestion import ingest_assigned_nmap_observation
from app.entities import record_assessment
from app.evidence_scope_assignments import assign_artifact_scope, correct_artifact_scope
from app.foundation_evidence import (
    compare_foundation_receipt_services,
    get_foundation_endpoint_evidence,
    get_foundation_receipt_services,
    get_foundation_scope_evidence,
    list_foundation_evidence_scopes,
)
from app.network_scopes import archive_network_scope, create_network_scope


XML = b'''<nmaprun scanner="nmap" version="7.95" args="nmap -n -sS -sU 192.0.2.10" start="100">
<scaninfo type="syn" protocol="tcp" numservices="1" services="53"/>
<scaninfo type="udp" protocol="udp" numservices="1" services="53"/>
<host starttime="101" endtime="109"><status state="up" reason="syn-ack"/>
<address addr="192.0.2.10" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="53"><state state="open" reason="syn-ack"/><service name="domain"/></port>
<port protocol="udp" portid="53"><state state="open|filtered"/><service name="domain"/></port>
</ports></host><runstats><finished time="110" timestr="done"/><hosts up="1" down="0" total="1"/></runstats></nmaprun>'''


def comparison_xml(services, *, address="192.0.2.10", start="100", finish="110"):
    ports = []
    for protocol, port, state in services:
        state_xml = "" if state is None else f'<state state="{state}"/>'
        ports.append(
            f'<port protocol="{protocol}" portid="{port}">{state_xml}'
            f'<service name="service-{port}"/></port>'
        )
    return (
        f'<nmaprun scanner="nmap" args="nmap -n {address}" start="{start}">'
        f'<host starttime="{start}" endtime="{finish}"><status state="up"/>'
        f'<address addr="{address}" addrtype="ipv4"/><ports>{"".join(ports)}</ports>'
        f'</host><runstats><finished time="{finish}"/></runstats></nmaprun>'
    ).encode()


def lifecycle_xml(
    requested_ports, services, *, address="192.0.2.10", start=100,
    protocol="tcp", host_start=None, host_end=None, finish=None,
    omitted_state="closed",
):
    finish = finish if finish is not None else start + 10
    host_start = host_start if host_start is not None else start + 1
    host_end = host_end if host_end is not None else finish - 1
    ports = []
    explicit_requested = 0
    for item_protocol, port, state in services:
        if item_protocol == protocol and port in requested_ports:
            explicit_requested += 1
        state_xml = "" if state is None else f'<state state="{state}"/>'
        ports.append(
            f'<port protocol="{item_protocol}" portid="{port}">{state_xml}'
            f'<service name="service-{port}"/></port>'
        )
    omitted = len(requested_ports) - explicit_requested
    extras = f'<extraports state="{omitted_state}" count="{omitted}"/>' if omitted else ""
    service_list = ",".join(str(port) for port in requested_ports)
    return (
        f'<nmaprun scanner="nmap" args="nmap -n {address}" start="{start}">'
        f'<scaninfo type="{"syn" if protocol == "tcp" else protocol}" '
        f'protocol="{protocol}" numservices="{len(requested_ports)}" '
        f'services="{service_list}"/>'
        f'<host starttime="{host_start}" endtime="{host_end}"><status state="up" reason="syn-ack"/>'
        f'<address addr="{address}" addrtype="ipv4"/><ports>{extras}{"".join(ports)}</ports>'
        f'</host><runstats><finished time="{finish}" exit="success"/></runstats></nmaprun>'
    ).encode()


def scope(db, label):
    return create_network_scope(db, label=label, created_by="admin")


def observation(
    db, source_ref="upload:one", observed_at="2030-02-01T00:00:00+00:00",
    content=XML,
):
    return register_artifact_bytes(
        db_path=db,
        content=content,
        source_kind="nmap_import",
        source_ref=source_ref,
        original_filename=f"{source_ref.split(':')[-1]}.xml",
        actor="analyst",
        observed_at=observed_at,
    )


def assign(db, item, destination):
    return assign_artifact_scope(
        db,
        artifact_observation_id=item["observation_id"],
        scope_id=destination["scope_id"],
        actor="analyst",
        reason="Confirmed exact whole-file context",
        whole_artifact_confirmed=True,
    )


def process(db, assignment, parser_version="nmap-endpoints:2"):
    return ingest_assigned_nmap_observation(
        db,
        expected_assignment_id=assignment["assignment_id"],
        linked_by="analyst",
        parser_version=parser_version,
    )


def comparison_ids(receipt):
    return {
        "assignment_id": receipt["assignment"]["assignment_id"],
        "assessment_id": receipt["assessment"]["assessment_id"],
    }


def compare_records(db, scope_id, entity_id, record_a, record_b, **page):
    return compare_foundation_receipt_services(
        db, scope_id, entity_id,
        record_a_assignment_id=record_a["assignment_id"],
        record_a_assessment_id=record_a["assessment_id"],
        record_b_assignment_id=record_b["assignment_id"],
        record_b_assessment_id=record_b["assessment_id"],
        **page,
    )


def test_scope_and_endpoint_views_preserve_receipts_times_and_protocols(tmp_path):
    db = tmp_path / "nct.db"
    lab = scope(db, "Lab")
    item = observation(db)
    process(db, assign(db, item, lab))

    catalog = list_foundation_evidence_scopes(db)
    assert catalog["read_only"] is True
    assert catalog["items"] == [{
        "scope_id": lab["scope_id"], "label": "Lab", "description": "",
        "version": 1, "active": True, "assessment_count": 1,
        "endpoint_count": 1, "service_count": 2,
        "historical_link_count": 0, "pending_correction_count": 0,
        "pending_processing_count": 0,
    }]

    scoped = get_foundation_scope_evidence(db, lab["scope_id"])
    assert scoped["claims"] == {
        "current_truth": False, "physical_device_identity": False,
        "last_seen": False, "absence_or_disappearance": False,
    }
    assert scoped["endpoints"][0]["address"] == "192.0.2.10"
    assert scoped["endpoints"][0]["receipt_count"] == 1
    assert scoped["endpoints"][0]["service_count"] == 2

    detail = get_foundation_endpoint_evidence(
        db, lab["scope_id"], scoped["endpoints"][0]["entity_id"],
    )
    assert detail["separate_history_receipts"] == []
    receipt = detail["current_assignment_receipts"][0]
    assert receipt["source"]["observation_id"] == item["observation_id"]
    assert receipt["source"]["encountered_at"] == "2030-02-01T00:00:00+00:00"
    assert receipt["source"]["source_url"].endswith(f"/{item['sha256']}/raw")
    assert receipt["assessment"]["collection_window"]["start"]["utc"] == "1970-01-01T00:01:40+00:00"
    assert receipt["assessment"]["collection_window"]["end"]["utc"] == "1970-01-01T00:01:50+00:00"
    assert receipt["endpoint_facts"]["presence"]["classification"] == "confirmed"
    services = get_foundation_receipt_services(
        db, lab["scope_id"], scoped["endpoints"][0]["entity_id"],
        receipt["assignment"]["assignment_id"],
        receipt["assessment"]["assessment_id"],
    )
    assert [(service["protocol"], service["port"], service["facts"]["state"]["state"])
            for service in services["services"]] == [
        ("tcp", 53, "open"), ("udp", 53, "open|filtered"),
    ]


def test_corrections_pending_history_and_return_to_original_scope_do_not_double_count(tmp_path):
    db = tmp_path / "nct.db"
    first, second = scope(db, "First"), scope(db, "Second")
    item = observation(db)
    root = assign(db, item, first)
    process(db, root)
    corrected = correct_artifact_scope(
        db, expected_assignment_id=root["assignment_id"],
        destination_scope_id=second["scope_id"], actor="analyst",
        reason="Confirmed corrected context", whole_artifact_confirmed=True,
    )

    first_view = get_foundation_scope_evidence(db, first["scope_id"])
    second_pending = get_foundation_scope_evidence(db, second["scope_id"])
    assert first_view["endpoints"] == []
    assert len(first_view["separate_history"]) == 1
    assert second_pending["endpoints"] == []
    assert second_pending["pending"][0]["kind"] == "correction_pending"

    process(db, corrected)
    returned = correct_artifact_scope(
        db, expected_assignment_id=corrected["assignment_id"],
        destination_scope_id=first["scope_id"], actor="analyst",
        reason="Context reviewed again", whole_artifact_confirmed=True,
    )
    process(db, returned)
    final = get_foundation_scope_evidence(db, first["scope_id"])
    assert final["pagination"]["total"] == 1
    assert final["endpoints"][0]["receipt_count"] == 1
    detail = get_foundation_endpoint_evidence(
        db, first["scope_id"], final["endpoints"][0]["entity_id"],
    )
    assert len(detail["current_assignment_receipts"]) == 1
    assert len(detail["separate_history_receipts"]) == 1


def test_identical_bytes_and_overlapping_addresses_remain_separate_observations_and_scopes(tmp_path):
    db = tmp_path / "nct.db"
    first_scope, second_scope = scope(db, "First"), scope(db, "Second")
    first = observation(db, "upload:first")
    repeated = observation(db, "upload:repeat")
    other_scope = observation(db, "upload:other")
    assert len({first["sha256"], repeated["sha256"], other_scope["sha256"]}) == 1
    process(db, assign(db, first, first_scope))
    process(db, assign(db, repeated, first_scope))
    process(db, assign(db, other_scope, second_scope))

    first_view = get_foundation_scope_evidence(db, first_scope["scope_id"])
    second_view = get_foundation_scope_evidence(db, second_scope["scope_id"])
    assert first_view["endpoints"][0]["receipt_count"] == 2
    assert second_view["endpoints"][0]["receipt_count"] == 1
    assert first_view["endpoints"][0]["entity_id"] != second_view["endpoints"][0]["entity_id"]
    detail = get_foundation_endpoint_evidence(
        db, first_scope["scope_id"], first_view["endpoints"][0]["entity_id"],
    )
    assert {receipt["source"]["observation_id"] for receipt in detail["current_assignment_receipts"]} == {
        first["observation_id"], repeated["observation_id"],
    }


def test_other_parser_is_history_archived_scope_remains_readable_and_pages_are_bounded(tmp_path):
    db = tmp_path / "nct.db"
    lab = scope(db, "Lab")
    item = observation(db)
    assignment = assign(db, item, lab)
    process(db, assignment, parser_version="nmap-endpoints:1")

    view = get_foundation_scope_evidence(db, lab["scope_id"])
    assert view["endpoints"] == []
    assert view["separate_history"][0]["parser_version"] == "nmap-endpoints:1"
    process(db, assignment)
    archive_network_scope(
        db, lab["scope_id"], expected_version=1,
        archived_by="admin", reason="Historical scope",
    )
    catalog = list_foundation_evidence_scopes(db, limit=1, offset=0)
    assert catalog["items"][0]["active"] is False
    assert get_foundation_scope_evidence(db, lab["scope_id"], limit=1)["pagination"]["total"] == 1
    assert list_foundation_evidence_scopes(db, limit=1, offset=1)["pagination"] == {
        "limit": 1, "offset": 1, "total": 1, "has_more": False,
    }
    assert get_foundation_scope_evidence(
        db, lab["scope_id"], limit=1, offset=1,
    )["pagination"] == {
        "limit": 1, "offset": 1, "total": 1, "has_more": False,
    }
    with pytest.raises(ValueError):
        list_foundation_evidence_scopes(db, limit=101)
    with pytest.raises(KeyError):
        get_foundation_endpoint_evidence(db, "wrong-scope", "wrong-endpoint")


def test_routes_are_viewer_readable_and_do_not_expose_mutation_methods(tmp_path, monkeypatch):
    import app.main as main

    db = tmp_path / "nct.db"
    monkeypatch.setattr(main, "DB_PATH", db)
    monkeypatch.setattr(main, "auth_enabled", lambda: True)
    monkeypatch.setattr(
        main, "session_identity",
        lambda *args: {"username": "viewer", "display_name": "Viewer", "role": "viewer"},
    )
    lab = scope(db, "Lab")
    process(db, assign(db, observation(db), lab))
    process(db, assign(db, observation(db, "upload:route-second"), lab))
    scoped_view = get_foundation_scope_evidence(db, lab["scope_id"])
    entity_id = scoped_view["endpoints"][0]["entity_id"]
    receipt_detail = get_foundation_endpoint_evidence(db, lab["scope_id"], entity_id)
    record_a, record_b = [
        comparison_ids(item) for item in receipt_detail["current_assignment_receipts"][:2]
    ]
    with TestClient(main.app) as client:
        scopes = client.get("/api/foundation-evidence/scopes")
        detail = client.get(f"/api/foundation-evidence/scopes/{lab['scope_id']}")
        comparison = client.get(
            f"/api/foundation-evidence/scopes/{lab['scope_id']}"
            f"/endpoints/{entity_id}/service-comparison",
            params={
                "record_a_assignment_id": record_a["assignment_id"],
                "record_a_assessment_id": record_a["assessment_id"],
                "record_b_assignment_id": record_b["assignment_id"],
                "record_b_assessment_id": record_b["assessment_id"],
            },
        )
        missing = client.get("/api/foundation-evidence/scopes/missing")
        rejected = client.post("/api/foundation-evidence/scopes")
    assert scopes.status_code == 200
    assert detail.status_code == 200
    assert comparison.status_code == 200
    assert comparison.json()["read_only"] is True
    assert missing.status_code == 404
    # The shared viewer guard rejects all non-read methods before route matching.
    assert rejected.status_code == 403


def test_read_model_opens_database_read_only(tmp_path, monkeypatch):
    import app.foundation_evidence as evidence

    db = tmp_path / "nct.db"
    lab = scope(db, "Lab")
    process(db, assign(db, observation(db), lab))
    process(db, assign(db, observation(db, "upload:read-only-second"), lab))
    calls = []
    original = evidence.connect_database

    def checked(path, *, read_only=False):
        calls.append(read_only)
        return original(path, read_only=read_only)

    monkeypatch.setattr(evidence, "connect_database", checked)
    catalog = evidence.list_foundation_evidence_scopes(db)
    scoped = evidence.get_foundation_scope_evidence(db, lab["scope_id"])
    detail = evidence.get_foundation_endpoint_evidence(
        db, lab["scope_id"], scoped["endpoints"][0]["entity_id"],
    )
    record_a, record_b = [
        comparison_ids(item) for item in detail["current_assignment_receipts"][:2]
    ]
    compare_records(
        db, lab["scope_id"], scoped["endpoints"][0]["entity_id"],
        record_a, record_b,
    )
    assert catalog["read_only"] is True
    assert calls == [True, True, True, True]


def test_scope_read_is_one_snapshot_when_a_correction_commits_mid_read(tmp_path, monkeypatch):
    import app.foundation_evidence as evidence

    db = tmp_path / "nct.db"
    first, second = scope(db, "First"), scope(db, "Second")
    item = observation(db)
    root = assign(db, item, first)
    process(db, root)
    original = evidence.connect_database
    correction = []

    class ConnectionProxy:
        def __init__(self, connection):
            object.__setattr__(self, "connection", connection)

        def __enter__(self):
            self.connection.__enter__()
            return self

        def __exit__(self, *args):
            return self.connection.__exit__(*args)

        def __setattr__(self, name, value):
            setattr(self.connection, name, value)

        def execute(self, sql, values=()):
            if ", grouped AS (" in sql and not correction:
                correction.append(correct_artifact_scope(
                    db, expected_assignment_id=root["assignment_id"],
                    destination_scope_id=second["scope_id"], actor="analyst",
                    reason="Concurrent correction", whole_artifact_confirmed=True,
                ))
            return self.connection.execute(sql, values)

    monkeypatch.setattr(
        evidence, "connect_database",
        lambda path, *, read_only=False: ConnectionProxy(
            original(path, read_only=read_only)
        ),
    )
    during = evidence.get_foundation_scope_evidence(db, first["scope_id"])
    assert correction
    assert during["pagination"]["total"] == 1
    assert during["endpoints"][0]["address"] == "192.0.2.10"

    monkeypatch.setattr(evidence, "connect_database", original)
    after = evidence.get_foundation_scope_evidence(db, first["scope_id"])
    assert after["endpoints"] == []
    assert len(after["separate_history"]) == 1


def test_scope_catalog_and_pending_history_have_continuation_pages(tmp_path):
    db = tmp_path / "nct.db"
    scopes = [scope(db, f"Scope {index:03d}") for index in range(101)]
    items = [observation(db, f"upload:scope-{index}") for index in range(101)]
    for item, destination in zip(items, scopes):
        assign(db, item, destination)
    first_page = list_foundation_evidence_scopes(db, limit=100)
    last_page = list_foundation_evidence_scopes(db, limit=100, offset=100)
    assert first_page["pagination"] == {
        "limit": 100, "offset": 0, "total": 101, "has_more": True,
    }
    assert len(first_page["items"]) == 100
    assert last_page["pagination"] == {
        "limit": 100, "offset": 100, "total": 101, "has_more": False,
    }
    assert len(last_page["items"]) == 1

    source, destination = scopes[0], scopes[1]
    for index in range(55):
        item = observation(db, f"upload:history-{index}")
        root = assign(db, item, source)
        process(db, root)
        correct_artifact_scope(
            db, expected_assignment_id=root["assignment_id"],
            destination_scope_id=destination["scope_id"], actor="analyst",
            reason=f"Correction {index}", whole_artifact_confirmed=True,
        )
    source_first = get_foundation_scope_evidence(
        db, source["scope_id"], history_limit=25, history_offset=0,
    )
    source_last = get_foundation_scope_evidence(
        db, source["scope_id"], history_limit=25, history_offset=50,
    )
    destination_first = get_foundation_scope_evidence(
        db, destination["scope_id"], pending_limit=25, pending_offset=0,
    )
    destination_last = get_foundation_scope_evidence(
        db, destination["scope_id"], pending_limit=25, pending_offset=50,
    )
    assert source_first["history_pagination"]["total"] == 55
    assert source_first["history_pagination"]["has_more"] is True
    assert len(source_last["separate_history"]) == 5
    assert source_last["history_pagination"]["has_more"] is False
    assert source_first["historical_endpoints"][0]["address"] == "192.0.2.10"
    assert source_first["historical_endpoints"][0]["receipt_count"] == 55
    assert destination_first["pending_pagination"]["total"] == 56
    assert destination_first["pending_pagination"]["has_more"] is True
    assert len(destination_last["pending"]) == 6


def test_endpoint_receipts_and_reported_services_are_independently_paged(tmp_path):
    db = tmp_path / "nct.db"
    lab = scope(db, "Lab")
    ports = "".join(
        f'<port protocol="tcp" portid="{port}"><state state="open"/></port>'
        for port in range(1, 301)
    )
    large_xml = (
        '<nmaprun scanner="nmap" start="100"><host><status state="up"/>'
        '<address addr="192.0.2.10" addrtype="ipv4"/><ports>' + ports +
        '</ports></host><runstats><finished time="110"/></runstats></nmaprun>'
    ).encode()
    large = observation(db, "upload:large-services", content=large_xml)
    large_assignment = assign(db, large, lab)
    large_processing = process(db, large_assignment)
    for index in range(29):
        process(db, assign(db, observation(db, f"upload:receipt-{index}"), lab))

    scoped = get_foundation_scope_evidence(db, lab["scope_id"])
    entity_id = scoped["endpoints"][0]["entity_id"]
    first = get_foundation_endpoint_evidence(db, lab["scope_id"], entity_id, limit=10)
    last = get_foundation_endpoint_evidence(
        db, lab["scope_id"], entity_id, limit=10, offset=20,
    )
    assert first["pagination"] == {
        "limit": 10, "offset": 0, "total": 30, "has_more": True,
    }
    assert len(last["current_assignment_receipts"]) == 10
    service_first = get_foundation_receipt_services(
        db, lab["scope_id"], entity_id,
        large_assignment["assignment_id"], large_processing["assessment_id"],
        limit=250,
    )
    service_last = get_foundation_receipt_services(
        db, lab["scope_id"], entity_id,
        large_assignment["assignment_id"], large_processing["assessment_id"],
        limit=250, offset=250,
    )
    assert len(service_first["services"]) == 250
    assert service_first["pagination"]["has_more"] is True
    assert len(service_last["services"]) == 50
    assert service_last["pagination"]["has_more"] is False


def test_invalid_file_times_remain_unknown_with_raw_source_values(tmp_path):
    db = tmp_path / "nct.db"
    lab = scope(db, "Lab")
    invalid_xml = b'''<nmaprun scanner="nmap" start="not-an-epoch">
    <host starttime="also-invalid"><status state="up"/>
    <address addr="192.0.2.10" addrtype="ipv4"/></host>
    <runstats><finished time="bad-finish"/></runstats></nmaprun>'''
    item = observation(db, "upload:invalid-times", content=invalid_xml)
    process(db, assign(db, item, lab))
    scoped = get_foundation_scope_evidence(db, lab["scope_id"])
    detail = get_foundation_endpoint_evidence(
        db, lab["scope_id"], scoped["endpoints"][0]["entity_id"],
    )
    receipt = detail["current_assignment_receipts"][0]
    assert receipt["assessment"]["assessed_at"] is None
    assert receipt["assessment"]["collection_window"]["start"] == {
        "raw": "not-an-epoch", "valid": False, "utc": None,
    }
    assert receipt["assessment"]["collection_window"]["end"] == {
        "raw": "bad-finish", "valid": False, "utc": None,
    }
    assert receipt["endpoint_facts"]["evidence_time"]["host_start"] == {
        "raw": "also-invalid", "valid": False, "utc": None,
    }


def test_service_comparison_uses_neutral_evidence_labels_and_preserves_sources(tmp_path):
    db = tmp_path / "nct.db"
    lab = scope(db, "Lab")
    first_xml = comparison_xml([
        ("tcp", 22, "open"), ("tcp", 53, "open"),
        ("udp", 53, "open|filtered"), ("tcp", 80, "closed"),
        ("tcp", 999, None),
    ])
    second_xml = comparison_xml([
        ("tcp", 53, "open"), ("udp", 53, "unknown"),
        ("tcp", 80, "filtered"), ("tcp", 443, "open"),
        ("tcp", 999, None),
    ], start="200", finish="210")
    first_item = observation(db, "upload:record-a", content=first_xml)
    second_item = observation(db, "upload:record-b", content=second_xml)
    first_assignment, second_assignment = assign(db, first_item, lab), assign(db, second_item, lab)
    first_processing, second_processing = process(db, first_assignment), process(db, second_assignment)
    scoped = get_foundation_scope_evidence(db, lab["scope_id"])
    entity_id = scoped["endpoints"][0]["entity_id"]
    result = compare_records(
        db, lab["scope_id"], entity_id,
        {"assignment_id": first_assignment["assignment_id"],
         "assessment_id": first_processing["assessment_id"]},
        {"assignment_id": second_assignment["assignment_id"],
         "assessment_id": second_processing["assessment_id"]},
    )
    by_service = {
        (item["protocol"], item["port"]): item for item in result["services"]
    }
    assert by_service[("tcp", 22)]["comparison"] == "recorded_only_in_a"
    assert by_service[("tcp", 443)]["comparison"] == "recorded_only_in_b"
    assert by_service[("tcp", 53)]["comparison"] == "same_reported_state"
    assert by_service[("udp", 53)]["comparison"] == "different_reported_state"
    assert by_service[("tcp", 80)]["comparison"] == "different_reported_state"
    assert by_service[("tcp", 999)]["comparison"] == "comparison_unavailable"
    assert by_service[("udp", 53)]["record_a"]["reported_state"] == "open|filtered"
    assert by_service[("udp", 53)]["record_b"]["reported_state"] == "unknown"
    assert result["record_a"]["source"]["observation_id"] == first_item["observation_id"]
    assert result["record_a"]["endpoint_facts"]["port_coverage"]["contract"] == "nmap-coverage:1"
    assert result["record_b"]["assessment"]["collection_window"]["start"]["utc"] == (
        "1970-01-01T00:03:20+00:00"
    )
    assert result["claims"] == {
        "record_order_from_non_overlapping_host_intervals": False,
        "coverage_aware_lifecycle": True,
        "current_truth": False,
        "last_seen": False,
        "absence_or_disappearance": False,
    }
    archive_network_scope(
        db, lab["scope_id"], expected_version=1,
        archived_by="admin", reason="Retained history",
    )
    assert compare_records(
        db, lab["scope_id"], entity_id,
        {"assignment_id": first_assignment["assignment_id"],
         "assessment_id": first_processing["assessment_id"]},
        {"assignment_id": second_assignment["assignment_id"],
         "assessment_id": second_processing["assessment_id"]},
    )["scope"]["active"] is False


def _lifecycle_pair(db, lab, first_xml, second_xml):
    first_item = observation(db, "upload:lifecycle-earlier", content=first_xml)
    second_item = observation(db, "upload:lifecycle-later", content=second_xml)
    first_assignment, second_assignment = assign(db, first_item, lab), assign(db, second_item, lab)
    first_processing, second_processing = process(db, first_assignment), process(db, second_assignment)
    entity_id = get_foundation_scope_evidence(db, lab["scope_id"])["endpoints"][0]["entity_id"]
    first_record = {"assignment_id": first_assignment["assignment_id"],
                    "assessment_id": first_processing["assessment_id"]}
    second_record = {"assignment_id": second_assignment["assignment_id"],
                     "assessment_id": second_processing["assessment_id"]}
    return entity_id, first_record, second_record


def test_lifecycle_classifies_ordered_explicit_and_covered_omitted_services(tmp_path):
    db = tmp_path / "nct.db"
    lab = scope(db, "Lab")
    requested = [22, 443, 8443, 9443]
    earlier = lifecycle_xml(
        requested,
        [("tcp", 22, "open"), ("tcp", 443, "open"), ("tcp", 8443, "open")],
        start=100,
    )
    later = lifecycle_xml(
        requested,
        [("tcp", 22, "open"), ("tcp", 443, "closed"), ("tcp", 9443, "open")],
        start=200,
    )
    entity_id, first_record, second_record = _lifecycle_pair(db, lab, earlier, later)
    result = compare_records(db, lab["scope_id"], entity_id, first_record, second_record)
    lifecycle = {(item["protocol"], item["port"]): item["lifecycle"]
                 for item in result["services"]}
    assert result["chronology"] == {
        "status": "ordered", "earlier": "record_a", "later": "record_b",
        "reason": "Record A host collection ended before Record B began",
    }
    assert lifecycle[("tcp", 22)]["classification"] == "unchanged"
    assert lifecycle[("tcp", 443)]["classification"] == "no_longer_observed"
    assert lifecycle[("tcp", 8443)]["classification"] == "no_longer_observed"
    assert lifecycle[("tcp", 9443)]["classification"] == "new"
    assert result["claims"] == {
        "record_order_from_non_overlapping_host_intervals": True,
        "coverage_aware_lifecycle": True,
        "current_truth": False,
        "last_seen": False,
        "absence_or_disappearance": False,
    }

    reversed_result = compare_records(
        db, lab["scope_id"], entity_id, second_record, first_record,
    )
    reversed_lifecycle = {
        (item["protocol"], item["port"]): item["lifecycle"]["classification"]
        for item in reversed_result["services"]
    }
    assert reversed_result["chronology"]["earlier"] == "record_b"
    assert reversed_lifecycle == {
        (key[0], key[1]): value["classification"] for key, value in lifecycle.items()
    }


def test_top_100_after_broader_scan_marks_uncovered_earlier_port_not_assessed(tmp_path):
    db = tmp_path / "nct.db"
    lab = scope(db, "Lab")
    earlier = lifecycle_xml(
        [22, 443, 12345],
        [("tcp", 22, "open"), ("tcp", 443, "open"), ("tcp", 12345, "open")],
        start=100,
    )
    later = lifecycle_xml(
        list(range(1, 101)), [("tcp", 22, "open")], start=200,
    )
    entity_id, first_record, second_record = _lifecycle_pair(db, lab, earlier, later)
    result = compare_records(db, lab["scope_id"], entity_id, first_record, second_record)
    lifecycle = {item["port"]: item["lifecycle"] for item in result["services"]}
    assert lifecycle[22]["classification"] == "unchanged"
    assert lifecycle[443]["classification"] == "not_assessed"
    assert lifecycle[12345]["classification"] == "not_assessed"
    assert lifecycle[443]["reason"] == (
        "Port 443 was not included in the later record's selected TCP ports, "
        "so its later state is unknown"
    )


def test_overlapping_or_incomplete_records_keep_lifecycle_not_assessed(tmp_path):
    db = tmp_path / "nct.db"
    lab = scope(db, "Lab")
    earlier = lifecycle_xml([22], [("tcp", 22, "open")], start=100, host_end=109)
    overlapping = lifecycle_xml(
        [22], [("tcp", 22, "closed")], start=105, host_start=108, host_end=114,
        finish=115,
    )
    entity_id, first_record, second_record = _lifecycle_pair(db, lab, earlier, overlapping)
    result = compare_records(db, lab["scope_id"], entity_id, first_record, second_record)
    assert result["chronology"]["status"] == "unresolved"
    assert result["services"][0]["lifecycle"]["classification"] == "not_assessed"
    assert "overlap or touch" in result["services"][0]["lifecycle"]["reason"]


def test_explicit_service_outside_declared_protocol_coverage_is_not_assessed(tmp_path):
    db = tmp_path / "nct.db"
    lab = scope(db, "Lab")
    earlier = lifecycle_xml([22], [("tcp", 22, "open"), ("udp", 53, "open")], start=100)
    later = lifecycle_xml([22], [("tcp", 22, "open"), ("udp", 53, "closed")], start=200)
    entity_id, first_record, second_record = _lifecycle_pair(db, lab, earlier, later)
    result = compare_records(db, lab["scope_id"], entity_id, first_record, second_record)
    lifecycle = {(item["protocol"], item["port"]): item["lifecycle"]
                 for item in result["services"]}
    assert lifecycle[("tcp", 22)]["classification"] == "not_assessed"
    assert lifecycle[("udp", 53)]["classification"] == "not_assessed"
    assert "protocols not declared" in lifecycle[("tcp", 22)]["reason"]


@pytest.mark.parametrize(("earlier_services","later_services","aggregate_state"), [
    ([("tcp", 443, "closed")], [], "closed"),
    ([], [("tcp", 443, "closed")], "closed"),
    ([("tcp", 443, "open")], [], "open"),
    ([], [("tcp", 443, "open")], "open"),
])
def test_explicit_and_aggregate_same_state_is_unchanged(
    tmp_path, earlier_services, later_services, aggregate_state,
):
    db = tmp_path / "nct.db"
    lab = scope(db, "Lab")
    earlier = lifecycle_xml(
        [443], earlier_services, start=100, omitted_state=aggregate_state,
    )
    later = lifecycle_xml(
        [443], later_services, start=200, omitted_state=aggregate_state,
    )
    entity_id, first_record, second_record = _lifecycle_pair(db, lab, earlier, later)
    result = compare_records(db, lab["scope_id"], entity_id, first_record, second_record)
    assert result["services"][0]["lifecycle"]["classification"] == "unchanged"
    assert "aggregate" in result["services"][0]["lifecycle"]["reason"]


@pytest.mark.parametrize(
    ("earlier_services", "later_services", "earlier_aggregate", "later_aggregate", "expected"),
    [
        ([("tcp", 443, "closed")], [("tcp", 443, "open")], "closed", "closed", "new"),
        ([], [("tcp", 443, "open")], "closed", "closed", "new"),
        ([("tcp", 443, "closed")], [], "closed", "open", "new"),
        ([("tcp", 443, "open")], [("tcp", 443, "closed")], "closed", "closed", "no_longer_observed"),
        ([], [("tcp", 443, "closed")], "open", "closed", "no_longer_observed"),
        ([("tcp", 443, "open")], [], "closed", "closed", "no_longer_observed"),
        ([("tcp", 443, "open")], [("tcp", 443, "filtered")], "closed", "closed", "changed"),
        ([], [("tcp", 443, "filtered")], "open", "closed", "changed"),
        ([("tcp", 443, "filtered")], [], "closed", "open", "changed"),
    ],
)
def test_state_transition_label_does_not_depend_on_explicit_or_aggregate_format(
    tmp_path, earlier_services, later_services, earlier_aggregate, later_aggregate, expected,
):
    db = tmp_path / "nct.db"
    lab = scope(db, "Lab")
    earlier = lifecycle_xml(
        [443], earlier_services, start=100, omitted_state=earlier_aggregate,
    )
    later = lifecycle_xml(
        [443], later_services, start=200, omitted_state=later_aggregate,
    )
    entity_id, first_record, second_record = _lifecycle_pair(db, lab, earlier, later)
    result = compare_records(db, lab["scope_id"], entity_id, first_record, second_record)
    assert result["services"][0]["lifecycle"]["classification"] == expected


@pytest.mark.parametrize("aggregate_state", ["filtered", "open|filtered"])
def test_ambiguous_aggregate_state_does_not_support_loss(tmp_path, aggregate_state):
    db = tmp_path / "nct.db"
    lab = scope(db, "Lab")
    earlier = lifecycle_xml([443], [("tcp", 443, "open")], start=100)
    later = lifecycle_xml(
        [443], [], start=200, omitted_state=aggregate_state,
    )
    entity_id, first_record, second_record = _lifecycle_pair(db, lab, earlier, later)
    result = compare_records(db, lab["scope_id"], entity_id, first_record, second_record)
    lifecycle = result["services"][0]["lifecycle"]
    assert lifecycle["classification"] == "not_assessed"
    assert f"Aggregate {aggregate_state} does not establish an exact service state" == lifecycle["reason"]


def test_service_comparison_rejects_stale_cross_scope_parser_and_same_record(tmp_path):
    db = tmp_path / "nct.db"
    first_scope, second_scope = scope(db, "First"), scope(db, "Second")
    first_item = observation(db, "upload:first-compare")
    second_item = observation(db, "upload:second-compare")
    other_scope_item = observation(db, "upload:other-scope")
    unsupported_item = observation(db, "upload:unsupported")
    first_assignment, second_assignment = (
        assign(db, first_item, first_scope), assign(db, second_item, first_scope),
    )
    first_processing, second_processing = process(db, first_assignment), process(db, second_assignment)
    other_assignment = assign(db, other_scope_item, second_scope)
    other_processing = process(db, other_assignment)
    unsupported_assignment = assign(db, unsupported_item, first_scope)
    unsupported_processing = process(db, unsupported_assignment, parser_version="nmap-endpoints:3")
    scoped = get_foundation_scope_evidence(db, first_scope["scope_id"])
    entity_id = scoped["endpoints"][0]["entity_id"]
    first_record = {
        "assignment_id": first_assignment["assignment_id"],
        "assessment_id": first_processing["assessment_id"],
    }
    second_record = {
        "assignment_id": second_assignment["assignment_id"],
        "assessment_id": second_processing["assessment_id"],
    }
    with pytest.raises(ValueError):
        compare_records(db, first_scope["scope_id"], entity_id, first_record, first_record)
    with pytest.raises(KeyError):
        compare_records(
            db, first_scope["scope_id"], entity_id, first_record,
            {"assignment_id": other_assignment["assignment_id"],
             "assessment_id": other_processing["assessment_id"]},
        )
    with pytest.raises(KeyError):
        compare_records(
            db, first_scope["scope_id"], entity_id, first_record,
            {"assignment_id": unsupported_assignment["assignment_id"],
             "assessment_id": unsupported_processing["assessment_id"]},
        )
    corrected = correct_artifact_scope(
        db, expected_assignment_id=first_assignment["assignment_id"],
        destination_scope_id=second_scope["scope_id"], actor="analyst",
        reason="Corrected to second", whole_artifact_confirmed=True,
    )
    process(db, corrected)
    returned = correct_artifact_scope(
        db, expected_assignment_id=corrected["assignment_id"],
        destination_scope_id=first_scope["scope_id"], actor="analyst",
        reason="Returned after review", whole_artifact_confirmed=True,
    )
    returned_processing = process(db, returned)
    with pytest.raises(KeyError):
        compare_records(db, first_scope["scope_id"], entity_id, first_record, second_record)
    assert compare_records(
        db, first_scope["scope_id"], entity_id,
        {"assignment_id": returned["assignment_id"],
         "assessment_id": returned_processing["assessment_id"]},
        second_record,
    )["pagination"]["total"] == 2


def test_service_comparison_pages_union_without_missing_or_repeated_rows(tmp_path):
    db = tmp_path / "nct.db"
    lab = scope(db, "Lab")
    first_xml = comparison_xml([("tcp", port, "open") for port in range(1, 301)])
    second_xml = comparison_xml([("tcp", port, "closed") for port in range(151, 451)])
    first_assignment = assign(db, observation(db, "upload:page-a", content=first_xml), lab)
    second_assignment = assign(db, observation(db, "upload:page-b", content=second_xml), lab)
    first_processing, second_processing = process(db, first_assignment), process(db, second_assignment)
    entity_id = get_foundation_scope_evidence(db, lab["scope_id"])["endpoints"][0]["entity_id"]
    record_a = {"assignment_id": first_assignment["assignment_id"],
                "assessment_id": first_processing["assessment_id"]}
    record_b = {"assignment_id": second_assignment["assignment_id"],
                "assessment_id": second_processing["assessment_id"]}
    first = compare_records(db, lab["scope_id"], entity_id, record_a, record_b, limit=250)
    second = compare_records(
        db, lab["scope_id"], entity_id, record_a, record_b, limit=250, offset=250,
    )
    keys = [(item["protocol"], item["port"]) for item in first["services"] + second["services"]]
    assert first["pagination"] == {
        "limit": 250, "offset": 0, "total": 450, "has_more": True,
    }
    assert second["pagination"] == {
        "limit": 250, "offset": 250, "total": 450, "has_more": False,
    }
    assert len(keys) == len(set(keys)) == 450
    assert keys[0] == ("tcp", 1)
    assert keys[-1] == ("tcp", 450)


def test_service_comparison_is_one_read_only_snapshot_during_correction(tmp_path, monkeypatch):
    import app.foundation_evidence as evidence

    db = tmp_path / "nct.db"
    first_scope, second_scope = scope(db, "First"), scope(db, "Second")
    first_assignment = assign(db, observation(db, "upload:snapshot-a"), first_scope)
    second_assignment = assign(db, observation(db, "upload:snapshot-b"), first_scope)
    first_processing, second_processing = process(db, first_assignment), process(db, second_assignment)
    entity_id = get_foundation_scope_evidence(db, first_scope["scope_id"])["endpoints"][0]["entity_id"]
    original = evidence.connect_database
    correction = []

    class ConnectionProxy:
        def __init__(self, connection):
            self.connection = connection

        def __enter__(self):
            self.connection.__enter__()
            return self

        def __exit__(self, *args):
            return self.connection.__exit__(*args)

        def __setattr__(self, name, value):
            if name == "connection":
                object.__setattr__(self, name, value)
            else:
                setattr(self.connection, name, value)

        def execute(self, sql, values=()):
            if "SELECT assignment.assignment_id" in sql and not correction:
                correction.append(correct_artifact_scope(
                    db, expected_assignment_id=first_assignment["assignment_id"],
                    destination_scope_id=second_scope["scope_id"], actor="analyst",
                    reason="Concurrent correction", whole_artifact_confirmed=True,
                ))
            return self.connection.execute(sql, values)

    monkeypatch.setattr(
        evidence, "connect_database",
        lambda path, *, read_only=False: ConnectionProxy(original(path, read_only=read_only)),
    )
    during = evidence.compare_foundation_receipt_services(
        db, first_scope["scope_id"], entity_id,
        record_a_assignment_id=first_assignment["assignment_id"],
        record_a_assessment_id=first_processing["assessment_id"],
        record_b_assignment_id=second_assignment["assignment_id"],
        record_b_assessment_id=second_processing["assessment_id"],
    )
    assert correction
    assert during["pagination"]["total"] == 2
    monkeypatch.setattr(evidence, "connect_database", original)
    with pytest.raises(KeyError):
        evidence.compare_foundation_receipt_services(
            db, first_scope["scope_id"], entity_id,
            record_a_assignment_id=first_assignment["assignment_id"],
            record_a_assessment_id=first_processing["assessment_id"],
            record_b_assignment_id=second_assignment["assignment_id"],
            record_b_assessment_id=second_processing["assessment_id"],
        )
