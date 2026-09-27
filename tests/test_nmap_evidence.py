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
    result = ingest_nmap_observation(db, observation_id=artifact["observation_id"],
                                     scope_id="routing-domain-a")

    assert result == {
        "assessment_id": result["assessment_id"],
        "scope_id": "routing-domain-a",
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


def test_explicit_scopes_separate_same_addresses_and_replay_is_idempotent(tmp_path):
    db = tmp_path / "nct.db"
    artifact = register(db)
    first = ingest_nmap_observation(db, observation_id=artifact["observation_id"], scope_id="a")
    assert ingest_nmap_observation(db, observation_id=artifact["observation_id"], scope_id="a") == first
    ingest_nmap_observation(db, observation_id=artifact["observation_id"], scope_id="b")
    assert table_count(db, "entity_assessments") == 2
    assert table_count(db, "endpoint_entities") == 6
    with connect_database(db) as connection:
        assert connection.execute("SELECT DISTINCT scope_id FROM endpoint_entities ORDER BY scope_id").fetchall() == [
            ("a",), ("b",)]


def test_duplicate_bytes_keep_encounters_but_do_not_advance_source_time(tmp_path):
    db = tmp_path / "nct.db"
    first = register(db, source_ref="upload:first", observed_at="2030-01-01T00:00:00+00:00")
    second = register(db, source_ref="upload:second", observed_at="2040-01-01T00:00:00+00:00")
    ingest_nmap_observation(db, observation_id=first["observation_id"], scope_id="a")
    ingest_nmap_observation(db, observation_id=second["observation_id"], scope_id="a")
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
    result = ingest_nmap_observation(db, observation_id=artifact["observation_id"], scope_id="a")
    assert result["assessed_at"] is None
    payload = assessments(db)[0]
    assert payload["assessed_at"] is None
    assert payload["time_basis"] is None
    assert payload["facts"]["scan_end"]["valid"] is False


def test_conflicting_source_times_are_retained_raw_but_never_promoted(tmp_path):
    db = tmp_path / "nct.db"
    content = b'''<nmaprun start="200"><host starttime="180" endtime="170"><status state="up"/><address addr="192.0.2.1" addrtype="ipv4"/></host><runstats><finished time="100"/></runstats></nmaprun>'''
    artifact = register(db, content)
    result = ingest_nmap_observation(db, observation_id=artifact["observation_id"], scope_id="a")
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
    ingest_nmap_observation(db, observation_id=artifact["observation_id"], scope_id="a")
    evidence_time = assessments(db)[0]["hosts"][0]["facts"]["evidence_time"]
    assert evidence_time["host_start"]["raw"] == "90"
    assert evidence_time["host_start"]["utc"] is None
    assert evidence_time["host_end"]["raw"] == "210"
    assert evidence_time["host_end"]["utc"] is None


def test_option_values_are_not_claimed_as_scan_targets(tmp_path):
    db = tmp_path / "nct.db"
    content = b'''<nmaprun args="nmap --dns-servers 8.8.8.8 --data-length 32 192.0.2.0/24"><runstats><finished time="100"/></runstats></nmaprun>'''
    artifact = register(db, content)
    ingest_nmap_observation(db, observation_id=artifact["observation_id"], scope_id="a")
    coverage = assessments(db)[0]["facts"]["coverage"]
    assert coverage["target_arguments"] is None
    assert coverage["target_arguments_basis"].startswith("unknown")
    assert coverage["command"] == "nmap --dns-servers 8.8.8.8 --data-length 32 192.0.2.0/24"


def test_command_without_options_retains_unambiguous_targets(tmp_path):
    db = tmp_path / "nct.db"
    content = b'''<nmaprun args="nmap 192.0.2.0/24 example.test"><runstats><finished time="100"/></runstats></nmaprun>'''
    artifact = register(db, content)
    ingest_nmap_observation(db, observation_id=artifact["observation_id"], scope_id="a")
    assert assessments(db)[0]["facts"]["coverage"]["target_arguments"] == [
        "192.0.2.0/24", "example.test"]


def test_missing_host_status_remains_unknown(tmp_path):
    db = tmp_path / "nct.db"
    content = b'''<nmaprun><host><address addr="192.0.2.1" addrtype="ipv4"/></host></nmaprun>'''
    artifact = register(db, content)
    ingest_nmap_observation(db, observation_id=artifact["observation_id"], scope_id="a")
    presence = assessments(db)[0]["hosts"][0]["facts"]["presence"]
    assert presence == {"classification": "unknown", "detail": "Nmap host status is missing"}


def test_canonical_tamper_blocks_ingestion_without_partial_assessment(tmp_path):
    db = tmp_path / "nct.db"
    artifact = register(db)
    Path(artifact["canonical_path"]).write_bytes(b"changed")
    with pytest.raises(ValueError, match="content verification"):
        ingest_nmap_observation(db, observation_id=artifact["observation_id"], scope_id="a")
    with connect_database(db) as connection:
        assert not connection.execute(
            "SELECT name FROM sqlite_master WHERE name='entity_assessments'").fetchall()


def test_oversized_corrupted_canonical_file_is_rejected_before_read(tmp_path):
    db = tmp_path / "nct.db"
    artifact = register(db)
    canonical = Path(artifact["canonical_path"])
    with canonical.open("r+b") as evidence:
        evidence.truncate(MAX_NMAP_XML_BYTES + 1)
    with pytest.raises(ValueError, match="size limit"):
        ingest_nmap_observation(db, observation_id=artifact["observation_id"], scope_id="a")
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
    with pytest.raises(ValueError, match=error):
        ingest_nmap_observation(db, observation_id=artifact["observation_id"], scope_id="a")
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
