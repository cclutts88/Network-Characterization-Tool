from fastapi.testclient import TestClient
import sqlite3
import pytest

from app.artifacts import register_artifact_bytes
from app.assigned_nmap_ingestion import ingest_assigned_nmap_observation
from app.entities import record_assessment
from app.evidence_scope_assignments import assign_artifact_scope, correct_artifact_scope
from app.foundation_evidence import (
    FoundationEvidenceConflict,
    compare_foundation_receipt_services,
    get_foundation_current_service_states,
    get_foundation_endpoint_evidence,
    get_foundation_latest_observations,
    get_foundation_mac_associations,
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


def mac_lifecycle_xml(
    *, address="192.0.2.10", mac="00:11:22:33:44:55", start=100,
    host_start=None, host_end=None, finish=None, successful=True,
):
    content = lifecycle_xml(
        [22], [("tcp", 22, "open")], address=address, start=start,
        host_start=host_start, host_end=host_end, finish=finish,
    )
    content = content.replace(
        f'<address addr="{address}" addrtype="ipv4"/>'.encode(),
        (
            f'<address addr="{address}" addrtype="ipv4"/>'
            f'<address addr="{mac}" addrtype="mac" vendor="Example Vendor"/>'
        ).encode(),
    )
    if not successful:
        content = content.replace(b'exit="success"', b'exit="error"')
    return content


def large_assessment_xml(host_count=1000):
    hosts = []
    for index in range(host_count):
        third, fourth = divmod(index, 250)
        address = f"10.20.{third}.{fourth + 1}"
        hosts.append(
            f'<host starttime="101" endtime="109"><status state="up" '
            f'reason="syn-ack"/><address addr="{address}" addrtype="ipv4"/>'
            f'<ports><port protocol="tcp" portid="22"><state state="open" '
            f'reason="syn-ack"/><service name="ssh"/></port></ports></host>'
        )
    return (
        '<nmaprun scanner="nmap" args="nmap -n -p22 10.20.0.0/16" start="100">'
        '<scaninfo type="syn" protocol="tcp" numservices="1" services="22"/>'
        + "".join(hosts)
        + '<runstats><finished time="110" exit="success"/>'
        f'<hosts up="{host_count}" down="0" total="{host_count}"/>'
        '</runstats></nmaprun>'
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
        latest = client.get(
            f"/api/foundation-evidence/scopes/{lab['scope_id']}"
            f"/endpoints/{entity_id}/latest-observations"
        )
        current_services = client.get(
            f"/api/foundation-evidence/scopes/{lab['scope_id']}"
            f"/endpoints/{entity_id}/current-service-states"
        )
        mac_associations = client.get(
            f"/api/foundation-evidence/scopes/{lab['scope_id']}/mac-associations",
            params={"mac": "00:11:22:33:44:55"},
        )
        missing = client.get("/api/foundation-evidence/scopes/missing")
        rejected = client.post("/api/foundation-evidence/scopes")
    assert scopes.status_code == 200
    assert detail.status_code == 200
    assert comparison.status_code == 200
    assert comparison.json()["read_only"] is True
    assert latest.status_code == 200
    assert latest.json()["contract"] == "latest-supported-nmap-observations:1"
    assert current_services.status_code == 200
    assert current_services.json()["contract"] == "current-reported-service-state:1"
    assert current_services.json()["read_only"] is True
    assert mac_associations.status_code == 200
    assert mac_associations.json()["read_only"] is True
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
    latest = evidence.get_foundation_latest_observations(
        db, lab["scope_id"], scoped["endpoints"][0]["entity_id"],
    )
    current_services = evidence.get_foundation_current_service_states(
        db, lab["scope_id"], scoped["endpoints"][0]["entity_id"],
    )
    associations = evidence.get_foundation_mac_associations(
        db, lab["scope_id"], "00:11:22:33:44:55",
    )
    assert catalog["read_only"] is True
    assert latest["read_only"] is True
    assert current_services["read_only"] is True
    assert associations["read_only"] is True
    assert calls == [True, True, True, True, True, True, True]


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


def _latest_for(db, destination):
    scoped = get_foundation_scope_evidence(db, destination["scope_id"])
    assert len(scoped["endpoints"]) == 1
    return get_foundation_latest_observations(
        db, destination["scope_id"], scoped["endpoints"][0]["entity_id"],
    )


def _current_for(db, destination, **page):
    scoped = get_foundation_scope_evidence(db, destination["scope_id"])
    assert len(scoped["endpoints"]) == 1
    return get_foundation_current_service_states(
        db, destination["scope_id"], scoped["endpoints"][0]["entity_id"],
        **page,
    )


def test_current_service_state_uses_latest_ordered_coverage_per_protocol_port(tmp_path):
    db = tmp_path / "nct.db"
    lab = scope(db, "Lab")
    earlier = observation(
        db, "upload:earlier-current", content=lifecycle_xml(
            [22, 443, 12345],
            [("tcp", 22, "open"), ("tcp", 443, "open"),
             ("tcp", 12345, "open")], start=100,
        ),
    )
    later = observation(
        db, "upload:later-current", content=lifecycle_xml(
            list(range(1, 101)), [("tcp", 22, "closed")], start=200,
        ),
    )
    for item in (earlier, later):
        process(db, assign(db, item, lab))

    result = _current_for(db, lab)
    by_service = {(item["protocol"], item["port"]): item
                  for item in result["services"]}
    assert result["contract"] == "current-reported-service-state:1"
    assert result["selection"]["status"] == "ordered"
    assert by_service[("tcp", 22)]["status"] == "reported"
    assert by_service[("tcp", 22)]["reported_state"] == "closed"
    assert by_service[("tcp", 22)]["basis"] == "explicit"
    assert by_service[("tcp", 443)]["status"] == "not_assessed"
    assert by_service[("tcp", 12345)]["status"] == "not_assessed"
    assert "not included" in by_service[("tcp", 443)]["reason"]
    assert all(
        row["evidence"][0]["source"]["observation_id"] == later["observation_id"]
        for row in by_service.values()
    )
    assert result["claims"] == {
        "latest_defensible_source_reported_state": True,
        "live_or_current_network_truth": False,
        "physical_device_identity": False,
        "exact_last_seen_timestamp": False,
        "absence_or_disappearance": False,
    }


def test_current_service_state_keeps_tcp_and_udp_separate(tmp_path):
    db = tmp_path / "nct.db"
    lab = scope(db, "Lab")
    successful = XML.replace(
        b'<finished time="110" timestr="done"/>',
        b'<finished time="110" timestr="done" exit="success"/>',
    )
    process(db, assign(db, observation(db, "upload:tcp-udp", content=successful), lab))
    result = _current_for(db, lab)
    by_service = {(item["protocol"], item["port"]): item
                  for item in result["services"]}
    assert by_service[("tcp", 53)]["reported_state"] == "open"
    assert by_service[("udp", 53)]["reported_state"] == "open|filtered"


def test_current_service_state_does_not_choose_overlapping_or_unknown_time(tmp_path):
    db = tmp_path / "nct.db"
    lab = scope(db, "Lab")
    overlapping = [
        lifecycle_xml([22], [("tcp", 22, "open")], start=100,
                      host_start=101, host_end=115, finish=116),
        lifecycle_xml([22], [("tcp", 22, "closed")], start=105,
                      host_start=110, host_end=120, finish=121),
    ]
    for index, content in enumerate(overlapping):
        process(db, assign(db, observation(
            db, f"upload:overlap-current-{index}", content=content,
        ), lab))
    result = _current_for(db, lab)
    assert result["selection"]["status"] == "unresolved"
    assert result["services"][0]["status"] == "unresolved"
    assert {item["reported_state"] for item in result["services"][0]["evidence"]} == {
        "open", "closed",
    }
    assert all(item["source"]["source_url"]
               for item in result["services"][0]["evidence"])

    unknown_xml = lifecycle_xml(
        [22], [("tcp", 22, "open")], start=300,
    ).replace(b' starttime="301" endtime="309"', b'')
    unknown = observation(db, "upload:unknown-current", content=unknown_xml)
    process(db, assign(db, unknown, lab))
    uncertain = _current_for(db, lab)
    assert uncertain["selection"]["status"] == "unresolved"
    assert uncertain["selection"]["unknown_time_count"] == 1
    assert unknown["observation_id"] in {
        item["source"]["observation_id"]
        for item in uncertain["services"][0]["evidence"]
    }


def test_current_service_state_keeps_duplicate_byte_encounters_distinct(tmp_path):
    db = tmp_path / "nct.db"
    lab = scope(db, "Lab")
    content = lifecycle_xml([22], [("tcp", 22, "open")], start=200)
    items = [
        observation(db, "upload:duplicate-current-one", content=content),
        observation(db, "upload:duplicate-current-two", content=content),
    ]
    for item in items:
        process(db, assign(db, item, lab))
    result = _current_for(db, lab)
    assert result["selection"]["status"] == "unresolved"
    assert len(result["services"][0]["evidence"]) == 2
    assert len({item["source"]["observation_id"]
                for item in result["services"][0]["evidence"]}) == 2
    assert len({item["source"]["sha256"]
                for item in result["services"][0]["evidence"]}) == 1


def test_current_service_state_pages_are_revision_bound_after_scope_correction(tmp_path):
    db = tmp_path / "nct.db"
    first, second = scope(db, "First"), scope(db, "Second")
    item = observation(db, "upload:revision-current", content=lifecycle_xml(
        [22, 443], [("tcp", 22, "open"), ("tcp", 443, "open")], start=100,
    ))
    assignment = assign(db, item, first)
    process(db, assignment)
    first_page = _current_for(db, first, limit=1)
    entity_id = first_page["endpoint"]["entity_id"]
    revision = first_page["pagination"]["selection_revision"]
    correct_artifact_scope(
        db, expected_assignment_id=assignment["assignment_id"],
        destination_scope_id=second["scope_id"], actor="analyst",
        reason="Corrected exact context", whole_artifact_confirmed=True,
    )
    with pytest.raises(FoundationEvidenceConflict):
        get_foundation_current_service_states(
            db, first["scope_id"], entity_id, limit=1, offset=1,
            expected_revision=revision,
        )


def test_current_service_state_enforces_candidate_bound_before_json_decode(
    tmp_path, monkeypatch,
):
    from app import foundation_evidence as evidence

    db = tmp_path / "nct.db"
    lab = scope(db, "Lab")
    for index in range(2):
        process(db, assign(db, observation(
            db, f"upload:bounded-current-{index}",
            content=lifecycle_xml([22], [("tcp", 22, "open")], start=100 + index * 20),
        ), lab))
    monkeypatch.setattr(evidence, "MAX_CURRENT_SERVICE_CANDIDATES", 1)
    monkeypatch.setattr(
        evidence, "_json",
        lambda raw: (_ for _ in ()).throw(AssertionError("JSON decoded before bound")),
    )
    with pytest.raises(ValueError, match="source-record bound"):
        _current_for(db, lab)


def test_latest_observation_uses_source_windows_not_import_or_processing_order(tmp_path):
    db = tmp_path / "nct.db"
    lab = scope(db, "Lab")
    later_source = observation(
        db, "upload:later-source", observed_at="2029-01-01T00:00:00+00:00",
        content=lifecycle_xml([22], [("tcp", 22, "open")], start=200),
    )
    earlier_source = observation(
        db, "upload:earlier-source", observed_at="2031-01-01T00:00:00+00:00",
        content=lifecycle_xml([22], [("tcp", 22, "open")], start=100),
    )
    process(db, assign(db, later_source, lab))
    process(db, assign(db, earlier_source, lab))

    result = _latest_for(db, lab)
    latest = result["latest_supported_observations"]
    confirmed = result["last_confirmed_observations"]
    assert latest["status"] == confirmed["status"] == "ordered"
    assert latest["records"][0]["source"]["observation_id"] == later_source["observation_id"]
    assert confirmed["records"][0]["collection_window"]["end"]["raw"] == "209"
    assert result["claims"]["last_confirmed_source_window"] is True
    assert result["claims"]["live_or_current_truth"] is False
    assert result["claims"]["exact_last_seen_timestamp"] is False


def test_latest_observation_keeps_overlapping_and_duplicate_encounters(tmp_path):
    db = tmp_path / "nct.db"
    lab = scope(db, "Lab")
    overlapping = lifecycle_xml(
        [22], [("tcp", 22, "open")], start=100,
        host_start=105, host_end=114, finish=115,
    )
    latest = lifecycle_xml(
        [22], [("tcp", 22, "open")], start=105,
        host_start=108, host_end=114, finish=115,
    )
    items = [
        observation(db, "upload:overlap", content=overlapping),
        observation(db, "upload:duplicate-one", content=latest),
        observation(db, "upload:duplicate-two", content=latest),
    ]
    for item in items:
        process(db, assign(db, item, lab))

    result = _latest_for(db, lab)
    group = result["last_confirmed_observations"]
    assert group["status"] == "overlapping"
    assert group["record_count"] == 3
    assert {item["source"]["observation_id"] for item in group["records"]} == {
        item["observation_id"] for item in items
    }
    assert all(item["source"]["source_url"] for item in group["records"])


def test_latest_observation_keeps_transitively_overlapping_windows_together(tmp_path):
    db = tmp_path / "nct.db"
    lab = scope(db, "Lab")
    windows = [(100, 120), (90, 105), (80, 95), (10, 20)]
    items = []
    for index, (host_start, host_end) in enumerate(windows):
        item = observation(
            db, f"upload:chain-{index}", content=lifecycle_xml(
                [22], [("tcp", 22, "open")], start=host_start - 1,
                host_start=host_start, host_end=host_end, finish=host_end + 1,
            ),
        )
        process(db, assign(db, item, lab))
        items.append(item)

    result = _latest_for(db, lab)
    group = result["last_confirmed_observations"]
    assert group["status"] == "overlapping"
    assert group["record_count"] == 3
    assert {record["source"]["observation_id"] for record in group["records"]} == {
        item["observation_id"] for item in items[:3]
    }


def test_unknown_source_time_blocks_latest_claim_and_remains_visible(tmp_path):
    db = tmp_path / "nct.db"
    lab = scope(db, "Lab")
    valid = observation(
        db, "upload:timed", content=lifecycle_xml(
            [22], [("tcp", 22, "open")], start=100,
        ),
    )
    unknown_xml = lifecycle_xml(
        [22], [("tcp", 22, "open")], start=200,
    ).replace(b' starttime="201" endtime="209"', b'')
    unknown = observation(db, "upload:unknown-time", content=unknown_xml)
    process(db, assign(db, valid, lab))
    process(db, assign(db, unknown, lab))

    result = _latest_for(db, lab)
    assert result["latest_supported_observations"]["status"] == "time_uncertain"
    assert result["last_confirmed_observations"]["status"] == "time_uncertain"
    assert result["unknown_time_pagination"]["total"] == 1
    assert result["unknown_time_records"][0]["source"]["observation_id"] == unknown["observation_id"]
    assert result["claims"]["last_confirmed_source_window"] is False


def test_only_unknown_source_times_report_uncertainty_instead_of_no_evidence(tmp_path):
    db = tmp_path / "nct.db"
    lab = scope(db, "Lab")
    unknown_xml = lifecycle_xml(
        [22], [("tcp", 22, "open")], start=200,
    ).replace(b' starttime="201" endtime="209"', b'')
    process(db, assign(db, observation(
        db, "upload:only-unknown-time", content=unknown_xml,
    ), lab))

    result = _latest_for(db, lab)
    assert result["latest_supported_observations"]["status"] == "time_uncertain"
    assert result["last_confirmed_observations"]["status"] == "time_uncertain"
    assert result["unknown_time_pagination"]["total"] == 1


def test_later_assumed_or_incomplete_record_does_not_erase_confirmed_evidence(tmp_path):
    db = tmp_path / "nct.db"
    lab = scope(db, "Lab")
    confirmed = observation(
        db, "upload:confirmed", content=lifecycle_xml(
            [22], [("tcp", 22, "open")], start=100,
        ),
    )
    assumed_xml = lifecycle_xml(
        [22], [], start=200, omitted_state="open|filtered",
    ).replace(
        b'<status state="up" reason="syn-ack"/>',
        b'<status state="up" reason="user-set"/>',
    )
    assumed = observation(db, "upload:assumed", content=assumed_xml)
    incomplete_xml = lifecycle_xml(
        [22], [("tcp", 22, "open")], start=300,
    ).replace(b'exit="success"', b'exit="error"')
    incomplete = observation(db, "upload:incomplete", content=incomplete_xml)
    for item in (confirmed, assumed, incomplete):
        process(db, assign(db, item, lab))

    result = _latest_for(db, lab)
    assert result["latest_supported_observations"]["records"][0]["presence"]["classification"] == "assumed"
    assert result["last_confirmed_observations"]["records"][0]["source"]["observation_id"] == confirmed["observation_id"]
    assert result["incomplete_record_count"] == 1
    assert result["claims"]["service_disappearance"] is False


def test_pending_failed_and_older_parser_records_do_not_replace_supported_latest(tmp_path):
    db = tmp_path / "nct.db"
    lab = scope(db, "Lab")
    supported = observation(
        db, "upload:supported", content=lifecycle_xml(
            [22], [("tcp", 22, "open")], start=100,
        ),
    )
    supported_assignment = assign(db, supported, lab)
    process(db, supported_assignment, parser_version="nmap-endpoints:legacy")
    process(db, supported_assignment)
    pending = observation(
        db, "upload:pending", content=lifecycle_xml(
            [22], [("tcp", 22, "open")], start=200,
        ),
    )
    assign(db, pending, lab)
    failed = observation(db, "upload:failed", content=b"<not-nmap />")
    failed_assignment = assign(db, failed, lab)
    with pytest.raises(ValueError):
        process(db, failed_assignment)

    result = _latest_for(db, lab)
    records = result["latest_supported_observations"]["records"]
    assert len(records) == 1
    assert records[0]["source"]["observation_id"] == supported["observation_id"]
    assert records[0]["assessment"]["parser_version"] == "nmap-endpoints:2"


def test_latest_observation_groups_and_unknown_times_have_independent_pages(tmp_path):
    db = tmp_path / "nct.db"
    lab = scope(db, "Lab")
    overlapping_ids = []
    unknown_ids = []
    for index in range(12):
        item = observation(
            db, f"upload:overlap-page-{index}", content=lifecycle_xml(
                [22], [("tcp", 22, "open")], start=100,
                host_start=101 + index, host_end=120, finish=121,
            ),
        )
        process(db, assign(db, item, lab))
        overlapping_ids.append(item["observation_id"])
    for index in range(12):
        content = lifecycle_xml(
            [22], [("tcp", 22, "open")], start=200 + index,
        ).replace(
            f' starttime="{201 + index}" endtime="{209 + index}"'.encode(), b"",
        )
        item = observation(db, f"upload:unknown-page-{index}", content=content)
        process(db, assign(db, item, lab))
        unknown_ids.append(item["observation_id"])

    scoped = get_foundation_scope_evidence(db, lab["scope_id"])
    entity_id = scoped["endpoints"][0]["entity_id"]
    first = get_foundation_latest_observations(
        db, lab["scope_id"], entity_id, limit=5,
    )
    second = get_foundation_latest_observations(
        db, lab["scope_id"], entity_id, limit=5,
        latest_offset=5, confirmed_offset=5, unknown_offset=5,
    )
    assert first["latest_supported_observations"]["pagination"] == {
        "limit": 5, "offset": 0, "total": 12, "has_more": True,
    }
    assert second["last_confirmed_observations"]["pagination"] == {
        "limit": 5, "offset": 5, "total": 12, "has_more": True,
    }
    assert first["unknown_time_pagination"] == {
        "limit": 5, "offset": 0, "total": 12, "has_more": True,
    }
    selected = {
        item["source"]["observation_id"]
        for result in (first, second)
        for item in result["unknown_time_records"]
    }
    assert len(selected) == 10
    assert selected.issubset(set(unknown_ids))


def test_latest_observation_preserves_scope_address_identity_and_corrections(tmp_path):
    db = tmp_path / "nct.db"
    first, second = scope(db, "First"), scope(db, "Second")
    ipv4_first = observation(
        db, "upload:first", content=lifecycle_xml(
            [22], [("tcp", 22, "open")], address="192.0.2.10", start=100,
        ),
    )
    ipv4_second = observation(
        db, "upload:second", content=lifecycle_xml(
            [22], [("tcp", 22, "open")], address="192.0.2.10", start=200,
        ),
    )
    ipv6_xml = lifecycle_xml(
        [22], [("tcp", 22, "open")], address="2001:db8::10", start=300,
    ).replace(b'addrtype="ipv4"', b'addrtype="ipv6"')
    ipv6 = observation(db, "upload:ipv6", content=ipv6_xml)
    root = assign(db, ipv4_first, first)
    process(db, root)
    moved = correct_artifact_scope(
        db, expected_assignment_id=root["assignment_id"],
        destination_scope_id=second["scope_id"], actor="analyst",
        reason="Corrected context", whole_artifact_confirmed=True,
    )
    process(db, moved)
    returned = correct_artifact_scope(
        db, expected_assignment_id=moved["assignment_id"],
        destination_scope_id=first["scope_id"], actor="analyst",
        reason="Confirmed original context", whole_artifact_confirmed=True,
    )
    process(db, returned)
    process(db, assign(db, ipv4_second, second))
    process(db, assign(db, ipv6, first))

    first_scope = get_foundation_scope_evidence(db, first["scope_id"])
    second_scope = get_foundation_scope_evidence(db, second["scope_id"])
    assert {item["address"] for item in first_scope["endpoints"]} == {
        "192.0.2.10", "2001:db8::10",
    }
    assert {item["address"] for item in second_scope["endpoints"]} == {"192.0.2.10"}
    first_v4 = next(item for item in first_scope["endpoints"] if item["address"] == "192.0.2.10")
    second_v4 = second_scope["endpoints"][0]
    assert first_v4["entity_id"] != second_v4["entity_id"]
    first_latest = get_foundation_latest_observations(
        db, first["scope_id"], first_v4["entity_id"],
    )
    assert first_latest["last_confirmed_observations"]["record_count"] == 1
    assert first_latest["last_confirmed_observations"]["records"][0]["assignment"]["assignment_id"] == returned["assignment_id"]
    archive_network_scope(
        db, first["scope_id"], expected_version=1,
        archived_by="admin", reason="Retained historical scope",
    )
    assert get_foundation_latest_observations(
        db, first["scope_id"], first_v4["entity_id"],
    )["scope"]["active"] is False


def test_latest_observation_is_one_read_only_snapshot_during_correction(tmp_path, monkeypatch):
    import app.foundation_evidence as evidence

    db = tmp_path / "nct.db"
    first, second = scope(db, "First"), scope(db, "Second")
    root = assign(db, observation(
        db, "upload:latest-snapshot", content=lifecycle_xml(
            [22], [("tcp", 22, "open")], start=100,
        ),
    ), first)
    process(db, root)
    entity_id = get_foundation_scope_evidence(
        db, first["scope_id"],
    )["endpoints"][0]["entity_id"]
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
            if "WITH current_assignments AS (" in sql and not correction:
                correction.append(correct_artifact_scope(
                    db, expected_assignment_id=root["assignment_id"],
                    destination_scope_id=second["scope_id"], actor="analyst",
                    reason="Concurrent latest correction",
                    whole_artifact_confirmed=True,
                ))
            return self.connection.execute(sql, values)

    monkeypatch.setattr(
        evidence, "connect_database",
        lambda path, *, read_only=False: ConnectionProxy(
            original(path, read_only=read_only)
        ),
    )
    during = evidence.get_foundation_latest_observations(
        db, first["scope_id"], entity_id,
    )
    assert correction
    assert during["last_confirmed_observations"]["record_count"] == 1

    monkeypatch.setattr(evidence, "connect_database", original)
    after = evidence.get_foundation_latest_observations(
        db, first["scope_id"], entity_id,
    )
    assert after["last_confirmed_observations"]["record_count"] == 0


def test_latest_observation_projects_small_metadata_from_large_assessment(tmp_path, monkeypatch):
    import app.foundation_evidence as evidence

    db = tmp_path / "nct.db"
    lab = scope(db, "Large Lab")
    process(db, assign(db, observation(
        db, "upload:large-assessment", content=large_assessment_xml(),
    ), lab))
    with sqlite3.connect(db) as connection:
        payload_size = connection.execute(
            "SELECT length(payload_json) FROM entity_assessments"
        ).fetchone()[0]
    assert payload_size > 500_000

    scoped = get_foundation_scope_evidence(db, lab["scope_id"], limit=1)
    entity_id = scoped["endpoints"][0]["entity_id"]
    projected_sizes = []
    original = evidence._supported_observation_candidate

    def checked(row):
        assert "payload_json" not in row.keys()
        projected_sizes.append(sum(
            len(str(row[key])) for key in row.keys() if row[key] is not None
        ))
        return original(row)

    monkeypatch.setattr(evidence, "_supported_observation_candidate", checked)
    result = evidence.get_foundation_latest_observations(
        db, lab["scope_id"], entity_id,
    )
    assert result["last_confirmed_observations"]["record_count"] == 1
    assert projected_sizes and max(projected_sizes) < 20_000


def test_latest_observation_treats_malformed_assessment_payload_as_incomplete(tmp_path):
    db = tmp_path / "nct.db"
    lab = scope(db, "Lab")
    process(db, assign(db, observation(
        db, "upload:malformed-payload", content=lifecycle_xml(
            [22], [("tcp", 22, "open")], start=100,
        ),
    ), lab))
    scoped = get_foundation_scope_evidence(db, lab["scope_id"])
    with sqlite3.connect(db) as connection:
        connection.execute("DROP TRIGGER entity_assessments_no_update")
        connection.execute("UPDATE entity_assessments SET payload_json = '{'")
        connection.commit()

    result = get_foundation_latest_observations(
        db, lab["scope_id"], scoped["endpoints"][0]["entity_id"],
    )
    assert result["latest_supported_observations"]["status"] == "unavailable"
    assert result["incomplete_record_count"] == 1


@pytest.mark.parametrize(
    ("replacement", "label"),
    [("1", "integer"), ("1.0", "decimal"), ('"true"', "true string"),
     ('"1"', "one string")],
)
def test_latest_observation_requires_boolean_true_completion(
    tmp_path, replacement, label,
):
    db = tmp_path / f"{label.replace(' ', '-')}.db"
    lab = scope(db, "Lab")
    process(db, assign(db, observation(
        db, f"upload:{label}", content=lifecycle_xml(
            [22], [("tcp", 22, "open")], start=100,
        ),
    ), lab))
    scoped = get_foundation_scope_evidence(db, lab["scope_id"])
    entity_id = scoped["endpoints"][0]["entity_id"]
    accepted = get_foundation_latest_observations(db, lab["scope_id"], entity_id)
    assert accepted["last_confirmed_observations"]["status"] == "ordered"

    with sqlite3.connect(db) as connection:
        connection.execute("DROP TRIGGER entity_assessments_no_update")
        connection.execute(
            """UPDATE entity_assessments
               SET payload_json = json_set(
                   payload_json,
                   '$.facts.coverage.completion.successful',
                   json(?)
               )""",
            (replacement,),
        )
        connection.commit()
    rejected = get_foundation_latest_observations(db, lab["scope_id"], entity_id)
    assert rejected["latest_supported_observations"]["status"] == "unavailable"
    assert rejected["incomplete_record_count"] == 1


def test_mac_associations_preserve_addresses_sources_and_overlapping_windows(tmp_path):
    db = tmp_path / "mac-associations.db"
    lab = scope(db, "Lab")
    first = observation(
        db, "upload:mac-first",
        content=mac_lifecycle_xml(
            address="192.0.2.10", start=100, host_start=101, host_end=110, finish=111,
        ),
    )
    second = observation(
        db, "upload:mac-second",
        content=mac_lifecycle_xml(
            address="192.0.2.25", start=105, host_start=106, host_end=115, finish=116,
        ),
    )
    for item in (first, second):
        process(db, assign(db, item, lab))

    result = get_foundation_mac_associations(
        db, lab["scope_id"], "00-11-22-33-44-55",
    )

    assert result["contract"] == "source-reported-mac-address-associations:1"
    assert result["mac"] == {
        "normalized": "00:11:22:33:44:55",
        "locally_administered": False,
        "warning": None,
    }
    assert {item["address"] for item in result["associations"]} == {
        "192.0.2.10", "192.0.2.25",
    }
    assert {item["source"]["observation_id"] for item in result["associations"]} == {
        first["observation_id"], second["observation_id"],
    }
    assert {item["source_window_status"] for item in result["associations"]} == {
        "overlapping_or_tied"
    }
    assert all(item["source"]["source_url"] for item in result["associations"])
    assert result["claims"] == {
        "physical_device_identity": False,
        "address_move": False,
        "dhcp_cause": False,
        "live_or_current_truth": False,
        "exact_last_seen_timestamp": False,
        "cross_scope_identity": False,
    }


def test_mac_associations_warn_for_local_and_reject_invalid_or_multicast(tmp_path):
    db = tmp_path / "mac-validation.db"
    lab = scope(db, "Lab")
    local = observation(
        db, "upload:local-mac",
        content=mac_lifecycle_xml(mac="02:11:22:33:44:55"),
    )
    malformed = observation(
        db, "upload:malformed-mac",
        content=mac_lifecycle_xml(
            address="192.0.2.11", mac="00ZZ11ZZ22ZZ33ZZ44ZZ55", start=200,
        ),
    )
    slashed = observation(
        db, "upload:slashed-mac",
        content=mac_lifecycle_xml(
            address="192.0.2.12", mac="00/11/22/33/44/55", start=220,
        ),
    )
    for item in (local, malformed, slashed):
        process(db, assign(db, item, lab))

    result = get_foundation_mac_associations(
        db, lab["scope_id"], "02:11:22:33:44:55",
    )
    assert result["pagination"]["total"] == 1
    assert result["mac"]["locally_administered"] is True
    assert "randomized" in result["mac"]["warning"]
    with pytest.raises(ValueError, match="valid unicast"):
        get_foundation_mac_associations(db, lab["scope_id"], "01:11:22:33:44:55")
    with pytest.raises(ValueError, match="valid unicast"):
        get_foundation_mac_associations(db, lab["scope_id"], "not-a-mac")
    with pytest.raises(ValueError, match="valid unicast"):
        get_foundation_mac_associations(
            db, lab["scope_id"], "00/11/22/33/44/55",
        )


def test_mac_associations_accept_only_the_documented_exact_source_formats(tmp_path):
    db = tmp_path / "mac-formats.db"
    lab = scope(db, "Lab")
    for index, mac in enumerate((
        "001122334455", "00:11:22:33:44:55", "00-11-22-33-44-55", "0011.2233.4455",
    )):
        item = observation(
            db, f"upload:format-{index}",
            content=mac_lifecycle_xml(
                address=f"192.0.2.{30 + index}", mac=mac, start=300 + index * 20,
            ),
        )
        process(db, assign(db, item, lab))

    result = get_foundation_mac_associations(
        db, lab["scope_id"], "0011.2233.4455",
    )
    assert result["pagination"]["total"] == 4


def test_mac_associations_exclude_other_scopes_old_parsers_unsuccessful_and_superseded(
    tmp_path,
):
    db = tmp_path / "mac-eligibility.db"
    first_scope, second_scope = scope(db, "First"), scope(db, "Second")
    moved_source = observation(
        db, "upload:moved-mac", content=mac_lifecycle_xml(),
    )
    original = assign(db, moved_source, first_scope)
    process(db, original)
    corrected = correct_artifact_scope(
        db,
        expected_assignment_id=original["assignment_id"],
        destination_scope_id=second_scope["scope_id"],
        actor="analyst",
        reason="Corrected exact context",
        whole_artifact_confirmed=True,
    )
    process(db, corrected)
    legacy = observation(
        db, "upload:legacy-mac",
        content=mac_lifecycle_xml(address="192.0.2.20", start=200),
    )
    process(db, assign(db, legacy, first_scope), parser_version="nmap-endpoints:legacy")
    failed = observation(
        db, "upload:failed-mac",
        content=mac_lifecycle_xml(
            address="192.0.2.30", start=300, successful=False,
        ),
    )
    process(db, assign(db, failed, first_scope))

    first = get_foundation_mac_associations(
        db, first_scope["scope_id"], "00:11:22:33:44:55",
    )
    second = get_foundation_mac_associations(
        db, second_scope["scope_id"], "00:11:22:33:44:55",
    )

    assert first["associations"] == []
    assert first["excluded_unsuccessful_receipts"] == 1
    assert [item["address"] for item in second["associations"]] == ["192.0.2.10"]
    assert second["associations"][0]["assignment"]["assignment_id"] == corrected["assignment_id"]


def test_mac_association_pages_are_revision_bound_and_candidate_work_is_bounded(
    tmp_path, monkeypatch,
):
    import app.foundation_evidence as evidence

    db = tmp_path / "mac-paging.db"
    first_scope, second_scope = scope(db, "First"), scope(db, "Second")
    assignments = []
    for index in range(3):
        item = observation(
            db, f"upload:mac-page-{index}",
            content=mac_lifecycle_xml(
                address=f"192.0.2.{10 + index}", start=100 + index * 20,
            ),
        )
        assignment = assign(db, item, first_scope)
        process(db, assignment)
        assignments.append(assignment)

    first_page = get_foundation_mac_associations(
        db, first_scope["scope_id"], "00:11:22:33:44:55", limit=1,
    )
    revision = first_page["pagination"]["selection_revision"]
    assert first_page["pagination"] == {
        "limit": 1, "offset": 0, "total": 3, "has_more": True,
        "selection_revision": revision,
    }
    correct_artifact_scope(
        db,
        expected_assignment_id=assignments[0]["assignment_id"],
        destination_scope_id=second_scope["scope_id"],
        actor="analyst",
        reason="Concurrent correction",
        whole_artifact_confirmed=True,
    )
    with pytest.raises(FoundationEvidenceConflict, match="refresh"):
        get_foundation_mac_associations(
            db, first_scope["scope_id"], "00:11:22:33:44:55",
            limit=1, offset=1, expected_revision=revision,
        )

    monkeypatch.setattr(evidence, "MAX_MAC_ASSOCIATION_CANDIDATES", 1)
    with pytest.raises(ValueError, match="more than 5,000 candidate source records"):
        evidence.get_foundation_mac_associations(
            db, first_scope["scope_id"], "00:11:22:33:44:55",
        )


def test_mac_associations_keep_duplicate_observations_and_unknown_time_visible(tmp_path):
    db = tmp_path / "mac-provenance.db"
    lab = scope(db, "Lab")
    content = mac_lifecycle_xml().replace(
        b'<host starttime="101" endtime="109">', b'<host>',
    )
    first = observation(db, "upload:duplicate-one", content=content)
    second = observation(db, "upload:duplicate-two", content=content)
    assert first["sha256"] == second["sha256"]
    assert first["observation_id"] != second["observation_id"]
    process(db, assign(db, first, lab))
    process(db, assign(db, second, lab))

    result = get_foundation_mac_associations(
        db, lab["scope_id"], "00:11:22:33:44:55",
    )

    assert result["pagination"]["total"] == 2
    assert {item["source"]["observation_id"] for item in result["associations"]} == {
        first["observation_id"], second["observation_id"],
    }
    assert {item["source_window_status"] for item in result["associations"]} == {
        "unknown",
    }
    assert all(item["source_window_group"] is None for item in result["associations"])


def test_mac_association_route_rejects_a_page_after_scope_correction(tmp_path, monkeypatch):
    import app.main as main

    db = tmp_path / "mac-route-conflict.db"
    monkeypatch.setattr(main, "DB_PATH", db)
    lab, corrected_scope = scope(db, "Lab"), scope(db, "Corrected")
    item = observation(db, "upload:route-mac", content=mac_lifecycle_xml())
    assignment = assign(db, item, lab)
    process(db, assignment)
    first_page = get_foundation_mac_associations(
        db, lab["scope_id"], "00:11:22:33:44:55", limit=1,
    )
    correct_artifact_scope(
        db,
        expected_assignment_id=assignment["assignment_id"],
        destination_scope_id=corrected_scope["scope_id"],
        actor="analyst",
        reason="Correct exact context",
        whole_artifact_confirmed=True,
    )

    with TestClient(main.app) as client:
        response = client.get(
            f"/api/foundation-evidence/scopes/{lab['scope_id']}/mac-associations",
            params={
                "mac": "00:11:22:33:44:55",
                "selection_revision": first_page["pagination"]["selection_revision"],
            },
        )

    assert response.status_code == 409
    assert "refresh address-association evidence" in response.json()["detail"]
