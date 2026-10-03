from fastapi.testclient import TestClient
import pytest

from app.artifacts import register_artifact_bytes
from app.assigned_nmap_ingestion import ingest_assigned_nmap_observation
from app.entities import record_assessment
from app.evidence_scope_assignments import assign_artifact_scope, correct_artifact_scope
from app.foundation_evidence import (
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


def process(db, assignment, parser_version="nmap-endpoints:1"):
    return ingest_assigned_nmap_observation(
        db,
        expected_assignment_id=assignment["assignment_id"],
        linked_by="analyst",
        parser_version=parser_version,
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
    process(db, assignment, parser_version="nmap-endpoints:2")

    view = get_foundation_scope_evidence(db, lab["scope_id"])
    assert view["endpoints"] == []
    assert view["separate_history"][0]["parser_version"] == "nmap-endpoints:2"
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
    with TestClient(main.app) as client:
        scopes = client.get("/api/foundation-evidence/scopes")
        detail = client.get(f"/api/foundation-evidence/scopes/{lab['scope_id']}")
        missing = client.get("/api/foundation-evidence/scopes/missing")
        rejected = client.post("/api/foundation-evidence/scopes")
    assert scopes.status_code == 200
    assert detail.status_code == 200
    assert missing.status_code == 404
    # The shared viewer guard rejects all non-read methods before route matching.
    assert rejected.status_code == 403


def test_read_model_opens_database_read_only(tmp_path, monkeypatch):
    import app.foundation_evidence as evidence

    db = tmp_path / "nct.db"
    lab = scope(db, "Lab")
    process(db, assign(db, observation(db), lab))
    calls = []
    original = evidence.connect_database

    def checked(path, *, read_only=False):
        calls.append(read_only)
        return original(path, read_only=read_only)

    monkeypatch.setattr(evidence, "connect_database", checked)
    catalog = evidence.list_foundation_evidence_scopes(db)
    scoped = evidence.get_foundation_scope_evidence(db, lab["scope_id"])
    evidence.get_foundation_endpoint_evidence(
        db, lab["scope_id"], scoped["endpoints"][0]["entity_id"],
    )
    assert catalog["read_only"] is True
    assert calls == [True, True, True]


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
