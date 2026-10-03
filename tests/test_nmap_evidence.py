from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.artifacts import get_artifact_observation, register_artifact_bytes
from app.database import connect_database
from app.nmap_evidence import (
    MAX_NMAP_XML_BYTES,
    NMAP_ENDPOINT_PARSER,
    ingest_nmap_observation,
)
from app.network_scopes import create_network_scope


XML = b'''<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.95" args="nmap -Pn -sS -sU -p T:443,U:53 192.0.2.0/24"
 start="1790208000" startstr="ignored display time">
 <scaninfo type="syn" protocol="tcp" numservices="1" services="443"/>
 <scaninfo type="udp" protocol="udp" numservices="1" services="53"/>
 <host starttime="1790208001" endtime="1790208002">
  <status state="up" reason="user-set" reason_ttl="0"/>
  <address addr="192.0.2.10" addrtype="ipv4"/>
  <address addr="2001:0db8::10" addrtype="ipv6"/>
  <hostnames><hostname name="edge.example" type="user"/></hostnames>
  <ports>
   <port protocol="tcp" portid="443"><state state="open|filtered" reason="no-response"/><service name="https" product="Example"/><script id="banner" output="retained"/></port>
   <port protocol="udp" portid="53"><state state="filtered" reason="admin-prohibited"/><service name="domain"/></port>
  </ports>
 </host>
 <host><status state="down" reason="host-unreach"/><address addr="192.0.2.20" addrtype="ipv4"/></host>
 <runstats><finished time="1790208003" timestr="ignored display time"/><hosts up="1" down="1" total="2"/></runstats>
</nmaprun>'''


def register(db: Path, content: bytes = XML, *, source_ref: str = "upload:one",
             observed_at: str = "2030-01-01T00:00:00+00:00") -> dict:
    return register_artifact_bytes(
        db_path=db, content=content, source_kind="nmap_import", source_ref=source_ref,
        original_filename="evidence.xml", media_type="application/xml",
        actor="analyst", observed_at=observed_at,
    )


def scope(db: Path, label: str = "Test network") -> str:
    return create_network_scope(db, label=label, created_by="tester")["scope_id"]


def table_count(db: Path, table: str) -> int:
    with connect_database(db) as connection:
        return connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]


def assessments(db: Path) -> list[dict]:
    with connect_database(db) as connection:
        return [json.loads(row[0]) for row in connection.execute(
            "SELECT payload_json FROM entity_assessments ORDER BY rowid")]


def test_verified_nmap_adapter_preserves_scope_times_presence_and_all_states(tmp_path):
    db = tmp_path / "nct.db"
    artifact = register(db)
    scope_id = scope(db)
    result = ingest_nmap_observation(db, observation_id=artifact["observation_id"],
                                     scope_id=scope_id)

    assert result == {
        "assessment_id": result["assessment_id"],
        "scope_id": scope_id,
        "artifact_observation_id": artifact["observation_id"],
        "parser_version": NMAP_ENDPOINT_PARSER,
        "address_count": 3,
        "service_receipt_count": 4,
        "assessed_at": "2026-09-24T00:00:03+00:00",
    }
    assert table_count(db, "endpoint_entities") == 3
    assert table_count(db, "service_entities") == 4
    payload = assessments(db)[0]
    assert payload["time_basis"] == "nmap runstats finished epoch"
    assert payload["facts"]["scope_assignment"] == "explicit_whole_artifact"
    assert payload["facts"]["source_ref"] == "upload:one"
    assert payload["facts"]["coverage"]["protocols"] == ["TCP", "UDP"]
    ipv6 = next(host for host in payload["hosts"] if host["address"] == "2001:db8::10")
    assert ipv6["facts"]["presence"]["classification"] == "assumed"
    assert ipv6["facts"]["evidence_time"]["host_end"]["utc"] == "2026-09-24T00:00:02+00:00"
    assert [service["facts"]["state"]["state"] for service in ipv6["services"]] == [
        "open|filtered", "filtered"]
    down = next(host for host in payload["hosts"] if host["address"] == "192.0.2.20")
    assert down["facts"]["presence"]["classification"] == "not_up"


def test_versioned_coverage_receipt_proves_complete_single_protocol_omissions(tmp_path):
    db = tmp_path / "nct.db"
    content = b'''<nmaprun scanner="nmap" start="100">
    <scaninfo type="syn" protocol="tcp" numservices="3" services="22,80,443"/>
    <host starttime="101" endtime="109"><status state="up" reason="syn-ack"/>
    <address addr="192.0.2.10" addrtype="ipv4"/><ports>
    <extraports state="closed" count="2"><extrareasons reason="reset" count="2"/></extraports>
    <port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/></port>
    </ports></host><runstats><finished time="110" exit="success"/></runstats></nmaprun>'''
    artifact = register(db, content)
    ingest_nmap_observation(
        db, observation_id=artifact["observation_id"], scope_id=scope(db),
    )
    payload = assessments(db)[0]
    coverage = payload["facts"]["coverage"]
    host_coverage = payload["hosts"][0]["facts"]["port_coverage"]
    assert coverage["coverage_contract"] == "nmap-coverage:1"
    assert coverage["completion"] == {
        "finished_present": True,
        "exit": "success",
        "successful": True,
        "reason": "Nmap recorded a successful finished state",
    }
    assert coverage["scan_types"][0]["service_intervals"] == [
        {"start": 22, "end": 22},
        {"start": 80, "end": 80},
        {"start": 443, "end": 443},
    ]
    assert host_coverage["contract"] == "nmap-coverage:1"
    assert host_coverage["protocols"]["tcp"] == {
        "requested_port_count": 3,
        "requested_intervals": coverage["scan_types"][0]["service_intervals"],
        "explicit_port_count": 1,
        "aggregate_omitted_port_count": 2,
        "accounted_port_count": 3,
        "explicit_observation_eligible": True,
        "explicit_observation_reasons": [],
        "omission_coverage_eligible": True,
        "reasons": [],
        "aggregate_states": ["closed"],
        "omitted_reported_state": "closed",
        "omitted_state_eligible": True,
        "omitted_state_reasons": [],
    }


@pytest.mark.parametrize(("finished","services","numservices","expected"), [
    ('<finished time="110" exit="error"/>', "22,80,443", "3", "successful completion"),
    ('<finished time="110" exit="success"/>', "22,invalid", "2", "port list is not exact"),
    ('<finished time="110" exit="success"/>', "22,80", "3", "port list is not exact"),
])
def test_coverage_receipt_explains_incomplete_or_ambiguous_port_evidence(
    tmp_path, finished, services, numservices, expected,
):
    db = tmp_path / "nct.db"
    content = f'''<nmaprun start="100"><scaninfo type="syn" protocol="tcp"
    numservices="{numservices}" services="{services}"/>
    <host starttime="101" endtime="109"><status state="up" reason="syn-ack"/>
    <address addr="192.0.2.10" addrtype="ipv4"/><ports>
    <extraports state="closed" count="1"/><port protocol="tcp" portid="22"><state state="open"/></port>
    </ports></host><runstats>{finished}</runstats></nmaprun>'''.encode()
    artifact = register(db, content)
    ingest_nmap_observation(
        db, observation_id=artifact["observation_id"], scope_id=scope(db),
    )
    receipt = assessments(db)[0]["hosts"][0]["facts"]["port_coverage"]["protocols"]["tcp"]
    assert receipt["omission_coverage_eligible"] is False
    assert any(expected in reason for reason in receipt["reasons"])


def test_multi_phase_aggregate_retains_provenance_and_blocks_omission_claims(tmp_path):
    db = tmp_path / "nct.db"
    content = b'''<nmaprun start="100" nct_source="protocol-phase-merge" nct_phase_count="2">
    <scaninfo type="syn" protocol="tcp" numservices="1" services="22"/>
    <scaninfo type="udp" protocol="udp" numservices="1" services="53"/>
    <host starttime="101" endtime="109"><status state="up" reason="syn-ack"/>
    <address addr="192.0.2.10" addrtype="ipv4"/><ports>
    <extraports state="closed" count="1"/><port protocol="tcp" portid="22"><state state="open"/></port>
    </ports></host><runstats><finished time="210" exit="success"/></runstats></nmaprun>'''
    artifact = register(db, content)
    ingest_nmap_observation(
        db, observation_id=artifact["observation_id"], scope_id=scope(db),
    )
    payload = assessments(db)[0]
    assert payload["facts"]["coverage"]["source_composition"] == {
        "kind": "protocol-phase-merge",
        "phase_count": 2,
        "timing_attribution": "ambiguous_across_phases",
        "provenance_valid": True,
        "reasons": [],
    }
    protocols = payload["hosts"][0]["facts"]["port_coverage"]["protocols"]
    assert protocols["tcp"]["omission_coverage_eligible"] is False
    assert protocols["udp"]["omission_coverage_eligible"] is False
    assert any("ambiguous host timing" in reason for reason in protocols["tcp"]["reasons"])


@pytest.mark.parametrize(("scaninfo","ports","reason"), [
    (
        '<scaninfo type="syn" protocol="tcp" numservices="2" services="22,23"/>',
        '<extraports state="closed" count="1"/>'
        '<port protocol="tcp" portid="80"><state state="open"/></port>',
        "explicit ports fall outside the requested list: 80",
    ),
    (
        '<scaninfo type="syn" protocol="tcp" numservices="2" services="22,23"/>',
        '<extraports state="closed" count="3"/>'
        '<extraports state="filtered" count="-1"/>',
        "aggregate omitted-port evidence is invalid or contradictory",
    ),
    (
        '<scaninfo type="syn" protocol="tcp" numservices="2" services="U:22,U:23"/>',
        '<extraports state="closed" count="2"/>',
        "requested port list is not exact",
    ),
])
def test_coverage_receipt_rejects_false_port_accounting(tmp_path, scaninfo, ports, reason):
    db = tmp_path / "nct.db"
    content = f'''<nmaprun start="100">{scaninfo}
    <host starttime="101" endtime="109"><status state="up" reason="syn-ack"/>
    <address addr="192.0.2.10" addrtype="ipv4"/><ports>{ports}</ports></host>
    <runstats><finished time="110" exit="success"/></runstats></nmaprun>'''.encode()
    artifact = register(db, content)
    ingest_nmap_observation(
        db, observation_id=artifact["observation_id"], scope_id=scope(db),
    )
    receipt = assessments(db)[0]["hosts"][0]["facts"]["port_coverage"]["protocols"]["tcp"]
    assert receipt["omission_coverage_eligible"] is False
    assert reason in receipt["reasons"]


@pytest.mark.parametrize("phase_count", ["bogus", "0", "-1"])
def test_marked_merge_with_invalid_phase_provenance_fails_closed(tmp_path, phase_count):
    db = tmp_path / "nct.db"
    content = f'''<nmaprun start="100" nct_source="protocol-phase-merge"
    nct_phase_count="{phase_count}"><scaninfo type="syn" protocol="tcp"
    numservices="2" services="22,23"/><host starttime="101" endtime="109">
    <status state="up" reason="syn-ack"/><address addr="192.0.2.10" addrtype="ipv4"/>
    <ports><extraports state="closed" count="2"/></ports></host>
    <runstats><finished time="110" exit="success"/></runstats></nmaprun>'''.encode()
    artifact = register(db, content)
    ingest_nmap_observation(
        db, observation_id=artifact["observation_id"], scope_id=scope(db),
    )
    payload = assessments(db)[0]
    assert payload["facts"]["coverage"]["source_composition"]["provenance_valid"] is False
    receipt = payload["hosts"][0]["facts"]["port_coverage"]["protocols"]["tcp"]
    assert receipt["omission_coverage_eligible"] is False
    assert "NCT phase count is missing or invalid" in receipt["reasons"]


def test_equal_host_interval_is_not_chronology_eligible(tmp_path):
    db = tmp_path / "nct.db"
    content = b'''<nmaprun start="100"><scaninfo type="syn" protocol="tcp"
    numservices="1" services="22"/><host starttime="105" endtime="105">
    <status state="up" reason="syn-ack"/><address addr="192.0.2.10" addrtype="ipv4"/>
    <ports><port protocol="tcp" portid="22"><state state="open"/></port></ports></host>
    <runstats><finished time="110" exit="success"/></runstats></nmaprun>'''
    artifact = register(db, content)
    ingest_nmap_observation(
        db, observation_id=artifact["observation_id"], scope_id=scope(db),
    )
    interval = assessments(db)[0]["hosts"][0]["facts"]["port_coverage"]["collection_interval"]
    assert interval["eligible"] is False
    assert interval["reasons"] == ["host collection interval is empty or reversed"]


def test_legacy_unmarked_automated_aggregate_does_not_gain_coverage_claims(tmp_path):
    db = tmp_path / "nct.db"
    content = b'''<nmaprun start="100"><scaninfo type="syn" protocol="tcp"
    numservices="2" services="22,23"/><host starttime="101" endtime="109">
    <status state="up" reason="syn-ack"/><address addr="192.0.2.10" addrtype="ipv4"/>
    <ports><extraports state="closed" count="2"/></ports></host>
    <runstats><finished time="110" exit="success"/></runstats></nmaprun>'''
    artifact = register_artifact_bytes(
        db_path=db, content=content, source_kind="nmap_scan", source_ref="run-legacy",
        original_filename="scan.xml", media_type="application/xml", actor="analyst",
        observed_at="2030-01-01T00:00:00+00:00",
    )
    ingest_nmap_observation(
        db, observation_id=artifact["observation_id"], scope_id=scope(db),
    )
    payload = assessments(db)[0]
    composition = payload["facts"]["coverage"]["source_composition"]
    assert composition["kind"] == "legacy_unmarked_automated_aggregate"
    assert composition["provenance_valid"] is False
    receipt = payload["hosts"][0]["facts"]["port_coverage"]["protocols"]["tcp"]
    assert receipt["omission_coverage_eligible"] is False
    assert any("lacks phase provenance" in reason for reason in receipt["reasons"])


def test_unexpected_explicit_protocol_blocks_aggregate_attribution(tmp_path):
    db = tmp_path / "nct.db"
    content = b'''<nmaprun start="100"><scaninfo type="syn" protocol="tcp"
    numservices="3" services="22,23,24"/><host starttime="101" endtime="109">
    <status state="up" reason="syn-ack"/><address addr="192.0.2.10" addrtype="ipv4"/>
    <ports><extraports state="closed" count="2"/>
    <port protocol="udp" portid="53"><state state="open"/></port></ports></host>
    <runstats><finished time="110" exit="success"/></runstats></nmaprun>'''
    artifact = register(db, content)
    ingest_nmap_observation(
        db, observation_id=artifact["observation_id"], scope_id=scope(db),
    )
    receipt = assessments(db)[0]["hosts"][0]["facts"]["port_coverage"]["protocols"]["tcp"]
    assert receipt["omission_coverage_eligible"] is False
    assert "explicit ports use protocols not declared by scaninfo: udp" in receipt["reasons"]


@pytest.mark.parametrize("extraports", [
    '<extraports count="2"/>',
    '<extraports state="closed" count="2"><extrareasons reason="reset" count="3"/></extraports>',
    '<extraports state="closed" count="2"><extrareasons reason="reset" count="bad"/></extraports>',
])
def test_contradictory_aggregate_summary_blocks_coverage(tmp_path, extraports):
    db = tmp_path / "nct.db"
    content = f'''<nmaprun start="100"><scaninfo type="syn" protocol="tcp"
    numservices="2" services="22,23"/><host starttime="101" endtime="109">
    <status state="up" reason="syn-ack"/><address addr="192.0.2.10" addrtype="ipv4"/>
    <ports>{extraports}</ports></host>
    <runstats><finished time="110" exit="success"/></runstats></nmaprun>'''.encode()
    artifact = register(db, content)
    ingest_nmap_observation(
        db, observation_id=artifact["observation_id"], scope_id=scope(db),
    )
    receipt = assessments(db)[0]["hosts"][0]["facts"]["port_coverage"]["protocols"]["tcp"]
    assert receipt["omission_coverage_eligible"] is False
    assert "aggregate omitted-port evidence is invalid or contradictory" in receipt["reasons"]


def test_multi_phase_host_interval_is_not_chronology_eligible(tmp_path):
    db = tmp_path / "nct.db"
    content = b'''<nmaprun start="100" nct_source="protocol-phase-merge" nct_phase_count="2">
    <scaninfo type="syn" protocol="tcp" numservices="1" services="22"/>
    <host starttime="101" endtime="109"><status state="up" reason="syn-ack"/>
    <address addr="192.0.2.10" addrtype="ipv4"/><ports>
    <port protocol="tcp" portid="22"><state state="open"/></port></ports></host>
    <runstats><finished time="210" exit="success"/></runstats></nmaprun>'''
    artifact = register(db, content)
    ingest_nmap_observation(
        db, observation_id=artifact["observation_id"], scope_id=scope(db),
    )
    interval = assessments(db)[0]["hosts"][0]["facts"]["port_coverage"]["collection_interval"]
    assert interval["eligible"] is False
    assert any("does not cover every merged phase" in reason
               for reason in interval["reasons"])


@pytest.mark.parametrize("count_attribute", ['count="-1"', 'count="bad"', 'count=""', ''])
def test_invalid_aggregate_count_retains_raw_invalid_state(tmp_path, count_attribute):
    db = tmp_path / "nct.db"
    content = b'''<nmaprun start="100"><scaninfo type="syn" protocol="tcp"
    numservices="1" services="22"/><host starttime="101" endtime="109">
    <status state="up" reason="syn-ack"/><address addr="192.0.2.10" addrtype="ipv4"/>
    <ports><extraports state="closed" {count_attribute}/></ports></host>
    <runstats><finished time="110" exit="success"/></runstats></nmaprun>'''
    content = content.replace(b"{count_attribute}", count_attribute.encode())
    artifact = register(db, content)
    ingest_nmap_observation(
        db, observation_id=artifact["observation_id"], scope_id=scope(db),
    )
    receipt = assessments(db)[0]["hosts"][0]["facts"]["port_coverage"]
    expected_raw = count_attribute.split('="', 1)[1][:-1] if count_attribute else None
    assert receipt["extraports"][0]["count_raw"] == expected_raw
    assert receipt["extraports"][0]["count"] == 0
    assert receipt["extraports"][0]["valid"] is False
    assert receipt["protocols"]["tcp"]["omission_coverage_eligible"] is False


def test_port_zero_is_not_dropped_from_protocol_consistency_check(tmp_path):
    db = tmp_path / "nct.db"
    content = b'''<nmaprun start="100"><scaninfo type="syn" protocol="tcp"
    numservices="1" services="22"/><host starttime="101" endtime="109">
    <status state="up" reason="syn-ack"/><address addr="192.0.2.10" addrtype="ipv4"/>
    <ports><extraports state="closed" count="1"/>
    <port protocol="udp" portid="0"><state state="open"/></port></ports></host>
    <runstats><finished time="110" exit="success"/></runstats></nmaprun>'''
    artifact = register(db, content)
    ingest_nmap_observation(
        db, observation_id=artifact["observation_id"], scope_id=scope(db),
    )
    receipt = assessments(db)[0]["hosts"][0]["facts"]["port_coverage"]["protocols"]["tcp"]
    assert receipt["omission_coverage_eligible"] is False
    assert "explicit ports use protocols not declared by scaninfo: udp" in receipt["reasons"]


def test_explicit_scopes_separate_same_addresses_and_replay_is_idempotent(tmp_path):
    db = tmp_path / "nct.db"
    artifact = register(db)
    first_scope, second_scope = scope(db, "First"), scope(db, "Second")
    first = ingest_nmap_observation(db, observation_id=artifact["observation_id"], scope_id=first_scope)
    assert ingest_nmap_observation(db, observation_id=artifact["observation_id"], scope_id=first_scope) == first
    ingest_nmap_observation(db, observation_id=artifact["observation_id"], scope_id=second_scope)
    assert table_count(db, "entity_assessments") == 2
    assert table_count(db, "endpoint_entities") == 6
    with connect_database(db) as connection:
        expected_scopes = [(value,) for value in sorted([first_scope, second_scope])]
        assert connection.execute(
            "SELECT DISTINCT scope_id FROM endpoint_entities ORDER BY scope_id"
        ).fetchall() == expected_scopes


def test_duplicate_bytes_keep_encounters_but_do_not_advance_source_time(tmp_path):
    db = tmp_path / "nct.db"
    first = register(db, source_ref="upload:first", observed_at="2030-01-01T00:00:00+00:00")
    second = register(db, source_ref="upload:second", observed_at="2040-01-01T00:00:00+00:00")
    scope_id = scope(db)
    ingest_nmap_observation(db, observation_id=first["observation_id"], scope_id=scope_id)
    ingest_nmap_observation(db, observation_id=second["observation_id"], scope_id=scope_id)
    assert table_count(db, "entity_assessments") == 2
    assert table_count(db, "endpoint_entities") == 3
    with connect_database(db) as connection:
        assert connection.execute("SELECT DISTINCT assessed_at FROM entity_assessments").fetchall() == [
            ("2026-09-24T00:00:03+00:00",)]
        assert connection.execute("SELECT COUNT(DISTINCT artifact_observation_id) FROM entity_assessments").fetchone()[0] == 2


@pytest.mark.parametrize("finished", ["", " time=\"bad\"", " time=\"NaN\"", " time=\"-1\""])
def test_missing_or_invalid_source_time_stays_unknown(tmp_path, finished):
    db = tmp_path / "nct.db"
    content = f'''<nmaprun start="bad"><host><status state="up" reason="user-set"/><address addr="192.0.2.1" addrtype="ipv4"/></host><runstats><finished{finished}/></runstats></nmaprun>'''.encode()
    artifact = register(db, content, observed_at="2099-12-31T23:59:59+00:00")
    result = ingest_nmap_observation(db, observation_id=artifact["observation_id"], scope_id=scope(db))
    assert result["assessed_at"] is None
    payload = assessments(db)[0]
    assert payload["assessed_at"] is None
    assert payload["time_basis"] is None
    assert payload["facts"]["scan_end"]["valid"] is False


def test_conflicting_source_times_are_retained_raw_but_never_promoted(tmp_path):
    db = tmp_path / "nct.db"
    content = b'''<nmaprun start="200"><host starttime="180" endtime="170"><status state="up"/><address addr="192.0.2.1" addrtype="ipv4"/></host><runstats><finished time="100"/></runstats></nmaprun>'''
    artifact = register(db, content)
    result = ingest_nmap_observation(db, observation_id=artifact["observation_id"], scope_id=scope(db))
    assert result["assessed_at"] is None
    payload = assessments(db)[0]
    scan = payload["facts"]
    host_time = payload["hosts"][0]["facts"]["evidence_time"]
    assert (scan["scan_start"]["raw"], scan["scan_end"]["raw"]) == ("200", "100")
    assert scan["scan_start"]["utc"] is scan["scan_end"]["utc"] is None
    assert host_time["host_start"]["utc"] is host_time["host_end"]["utc"] is None
    assert "precedes" in scan["scan_end"]["conflict"]


def test_host_times_outside_scan_window_are_not_validated(tmp_path):
    db = tmp_path / "nct.db"
    content = b'''<nmaprun start="100"><host starttime="90" endtime="210"><status state="up"/><address addr="192.0.2.1" addrtype="ipv4"/></host><runstats><finished time="200"/></runstats></nmaprun>'''
    artifact = register(db, content)
    ingest_nmap_observation(db, observation_id=artifact["observation_id"], scope_id=scope(db))
    evidence_time = assessments(db)[0]["hosts"][0]["facts"]["evidence_time"]
    assert evidence_time["host_start"]["raw"] == "90"
    assert evidence_time["host_start"]["utc"] is None
    assert evidence_time["host_end"]["raw"] == "210"
    assert evidence_time["host_end"]["utc"] is None


def test_option_values_are_not_claimed_as_scan_targets(tmp_path):
    db = tmp_path / "nct.db"
    content = b'''<nmaprun args="nmap --dns-servers 8.8.8.8 --data-length 32 192.0.2.0/24"><runstats><finished time="100"/></runstats></nmaprun>'''
    artifact = register(db, content)
    ingest_nmap_observation(db, observation_id=artifact["observation_id"], scope_id=scope(db))
    coverage = assessments(db)[0]["facts"]["coverage"]
    assert coverage["target_arguments"] is None
    assert coverage["target_arguments_basis"].startswith("unknown")
    assert coverage["command"] == "nmap --dns-servers 8.8.8.8 --data-length 32 192.0.2.0/24"


def test_command_without_options_retains_unambiguous_targets(tmp_path):
    db = tmp_path / "nct.db"
    content = b'''<nmaprun args="nmap 192.0.2.0/24 example.test"><runstats><finished time="100"/></runstats></nmaprun>'''
    artifact = register(db, content)
    ingest_nmap_observation(db, observation_id=artifact["observation_id"], scope_id=scope(db))
    assert assessments(db)[0]["facts"]["coverage"]["target_arguments"] == [
        "192.0.2.0/24", "example.test"]


def test_missing_host_status_remains_unknown(tmp_path):
    db = tmp_path / "nct.db"
    content = b'''<nmaprun><host><address addr="192.0.2.1" addrtype="ipv4"/></host></nmaprun>'''
    artifact = register(db, content)
    ingest_nmap_observation(db, observation_id=artifact["observation_id"], scope_id=scope(db))
    presence = assessments(db)[0]["hosts"][0]["facts"]["presence"]
    assert presence == {"classification": "unknown", "detail": "Nmap host status is missing"}


def test_canonical_tamper_blocks_ingestion_without_partial_assessment(tmp_path):
    db = tmp_path / "nct.db"
    artifact = register(db)
    scope_id = scope(db)
    Path(artifact["canonical_path"]).write_bytes(b"changed")
    with pytest.raises(ValueError, match="content verification"):
        ingest_nmap_observation(db, observation_id=artifact["observation_id"], scope_id=scope_id)
    with connect_database(db) as connection:
        assert not connection.execute(
            "SELECT name FROM sqlite_master WHERE name='entity_assessments'").fetchall()


def test_oversized_corrupted_canonical_file_is_rejected_before_read(tmp_path):
    db = tmp_path / "nct.db"
    artifact = register(db)
    scope_id = scope(db)
    canonical = Path(artifact["canonical_path"])
    with canonical.open("r+b") as evidence:
        evidence.truncate(MAX_NMAP_XML_BYTES + 1)
    with pytest.raises(ValueError, match="size limit"):
        ingest_nmap_observation(db, observation_id=artifact["observation_id"], scope_id=scope_id)
    with connect_database(db) as connection:
        assert not connection.execute(
            "SELECT name FROM sqlite_master WHERE name='entity_assessments'").fetchall()


@pytest.mark.parametrize("content,error", [
    (b"<other/>", "root"),
    (b"<!DOCTYPE nmaprun [<!ENTITY x 'unsafe'>]><nmaprun args='&x;'/>", "Invalid Nmap XML"),
    (b"<nmaprun><host><address addr='bad' addrtype='ipv4'/></host></nmaprun>", "IP address"),
    (b"<nmaprun><host><address addr='192.0.2.1' addrtype='ipv4'/><ports><port protocol='ip' portid='1'/></ports></host></nmaprun>", "transport"),
])
def test_invalid_evidence_publishes_no_partial_entities(tmp_path, content, error):
    db = tmp_path / "nct.db"
    artifact = register(db, content)
    scope_id = scope(db)
    with pytest.raises(ValueError, match=error):
        ingest_nmap_observation(db, observation_id=artifact["observation_id"], scope_id=scope_id)
    with connect_database(db) as connection:
        assert not connection.execute(
            "SELECT name FROM sqlite_master WHERE name='entity_assessments'").fetchall()


def test_observation_lookup_retains_source_and_canonical_identity(tmp_path):
    db = tmp_path / "nct.db"
    artifact = register(db)
    record = get_artifact_observation(db, artifact["observation_id"])
    assert record is not None
    assert record["sha256"] == artifact["sha256"]
    assert record["source_kind"] == "nmap_import"
    assert record["source_ref"] == "upload:one"
    assert record["actor"] == "analyst"
