from __future__ import annotations

import json
from pathlib import Path

import app.network_map as network_map
import app.nmap_topology_analysis as nmap_topology
from app.artifacts import register_artifact_file
from app.database import connect_database
from app.nmap_topology_analysis import (
    NMAP_TOPOLOGY_FAMILY,
    analyze_scan_run_nmap_topology,
    parse_nmap_topology_bytes,
)
from app.poc import RUNS_DIR_NAME, insert_scan_run_manifest
from app.storage_health import backfill_storage


TOPOLOGY_XML = b'''<nmaprun>
<host><status state="up" reason="syn-ack"/><address addr="10.80.0.10" addrtype="ipv4"/>
<address addr="00:11:22:33:44:55" addrtype="mac" vendor="Example Networks"/>
<hostnames><hostname name="app01"/></hostnames><os><osmatch name="Example OS"/></os>
<ports><port protocol="tcp" portid="443"><state state="open"/><service name="https" product="Web" version="1"/></port>
<port protocol="tcp" portid="22"><service name="ssh"/></port>
<port protocol="tcp" portid="80"><state state="closed"/></port></ports>
<trace port="443" proto="tcp"><hop ttl="1" rtt="1.2" ipaddr="10.80.0.1" host="gw"/></trace></host>
<host><status state="up" reason="user-set"/><address addr="10.80.0.11" addrtype="ipv4"/></host>
<host><status state="down"/><address addr="10.80.0.12" addrtype="ipv4"/></host>
<host><address addr="10.80.0.13" addrtype="ipv4"/></host>
<host><status state="up"/><address addr="not-an-ip" addrtype="ipv4"/></host>
<host><status state="up"/><address addr="10.80.0.10" addrtype="ipv4"/></host>
</nmaprun>'''


def create_scan(
    db_path: Path,
    data_dir: Path,
    run_id: str,
    *,
    content: bytes = TOPOLOGY_XML,
    registered: bool = True,
    registration_marker: bool | None = None,
    status: str = "completed",
) -> tuple[dict, dict | None]:
    manifest = {
        "run_id": run_id,
        "created_at": "2026-10-03T00:00:00+00:00",
        "completed_at": "2026-10-03T00:01:00+00:00",
        "status": status,
        "operator": "analyst",
        "reason": "authorized test",
        "originating_host": "nct-test",
        "interface": "eth0",
        "profile": "safe",
        "display_name": "Users LAN verification",
    }
    insert_scan_run_manifest(manifest, db_path=db_path)
    run_dir = data_dir / RUNS_DIR_NAME / run_id
    run_dir.mkdir(parents=True)
    xml_path = run_dir / "scan.xml"
    xml_path.write_bytes(content)
    artifact = None
    if registered:
        artifact = register_artifact_file(
            db_path=db_path,
            source_path=xml_path,
            source_kind="nmap_scan",
            source_ref=run_id,
            original_filename="scan.xml",
            actor="analyst",
            observation_key=f"nmap_scan:{run_id}:scan.xml",
        )
    marker = registered if registration_marker is None else registration_marker
    if marker:
        manifest["artifact_registry"] = {
            "status": "complete",
            "files": [{
                "filename": "scan.xml",
                "sha256": artifact["sha256"] if artifact else "missing",
            }],
            "errors": [],
        }
    with connect_database(db_path) as db:
        db.execute(
            "UPDATE scan_runs SET status = ?, manifest_json = ? WHERE run_id = ?",
            (status, json.dumps(manifest, sort_keys=True), run_id),
        )
    (run_dir / "manifest.json").write_text(
        json.dumps(manifest, sort_keys=True), encoding="utf-8"
    )
    return manifest, artifact


def test_topology_parser_preserves_established_host_port_and_trace_contract():
    hosts = parse_nmap_topology_bytes(TOPOLOGY_XML)

    assert [host["ip"] for host in hosts] == [
        "10.80.0.10", "10.80.0.11", "10.80.0.12", "10.80.0.13", "10.80.0.10"
    ]
    assert [host["state"] for host in hosts] == ["up", "up", "down", None, "up"]
    first = hosts[0]
    assert first["hostname"] == "app01"
    assert first["mac"] == "00:11:22:33:44:55"
    assert first["vendor"] == "Example Networks"
    assert first["os"] == "Example OS"
    assert [port["port"] for port in first["ports"]] == [443, 22]
    assert first["ports"][1] == {
        "port": 22,
        "protocol": "tcp",
        "service": "ssh",
        "product": None,
        "version": None,
    }
    assert first["trace"] == {
        "port": "443",
        "protocol": "tcp",
        "hops": [{
            "ttl": 1, "rtt": "1.2", "ip": "10.80.0.1", "hostname": "gw"
        }],
    }


def test_map_cold_and_warm_reads_reuse_one_topology_result_per_exact_file(
    tmp_path, monkeypatch,
):
    data_dir = tmp_path / "data"
    db_path = data_dir / "nct.db"
    first, _ = create_scan(db_path, data_dir, "a" * 32)
    second, _ = create_scan(db_path, data_dir, "b" * 32)
    monkeypatch.setattr(network_map, "DB_PATH", db_path)
    monkeypatch.setattr(network_map, "DATA_DIR", data_dir)
    calls = []
    original = nmap_topology.parse_nmap_topology_bytes

    def counting_parser(content: bytes):
        calls.append(content)
        return original(content)

    monkeypatch.setattr(nmap_topology, "parse_nmap_topology_bytes", counting_parser)
    first_nodes, first_edges, first_warnings = {}, {}, []
    second_nodes, second_edges, second_warnings = {}, {}, []

    assert network_map.automated_scan_hosts(first_nodes, first_edges, first_warnings) == 10
    assert network_map.automated_scan_hosts(second_nodes, second_edges, second_warnings) == 10
    assert not first_warnings and not second_warnings
    assert first_nodes == second_nodes
    assert first_edges == second_edges
    assert len(calls) == 1

    writer = connect_database(db_path)
    try:
        writer.execute("BEGIN IMMEDIATE")
        writer.execute(
            "UPDATE scan_runs SET status = status WHERE run_id = ?",
            (first["run_id"],),
        )
        locked_nodes, locked_edges, locked_warnings = {}, {}, []
        assert network_map.automated_scan_hosts(
            locked_nodes, locked_edges, locked_warnings
        ) == 10
        assert locked_nodes == first_nodes
        assert locked_edges == first_edges
        assert not locked_warnings
    finally:
        writer.rollback()
        writer.close()
    assert len(calls) == 1

    with connect_database(db_path, read_only=True) as db:
        assert db.execute(
            "SELECT COUNT(*) FROM derived_results WHERE family = ?",
            (NMAP_TOPOLOGY_FAMILY,),
        ).fetchone()[0] == 1
        assert db.execute(
            "SELECT COUNT(*) FROM derived_result_observation_links"
        ).fetchone()[0] == 2
    assert first["run_id"] != second["run_id"]


def test_nonterminal_and_legacy_topology_reads_do_not_publish_until_eligible(
    tmp_path,
):
    data_dir = tmp_path / "data"
    db_path = data_dir / "nct.db"
    running, _ = create_scan(db_path, data_dir, "c" * 32, status="running")
    legacy, _ = create_scan(db_path, data_dir, "d" * 32, registered=False)

    for manifest in (running, legacy):
        path = data_dir / RUNS_DIR_NAME / manifest["run_id"] / "scan.xml"
        assert analyze_scan_run_nmap_topology(db_path, manifest["run_id"], path)["payload"]
    with connect_database(db_path, read_only=True) as db:
        assert db.execute("SELECT COUNT(*) FROM derived_results").fetchone()[0] == 0

    assert backfill_storage(db_path)["completed"] >= 1
    legacy_path = data_dir / RUNS_DIR_NAME / legacy["run_id"] / "scan.xml"
    cold = analyze_scan_run_nmap_topology(db_path, legacy["run_id"], legacy_path)
    warm = analyze_scan_run_nmap_topology(db_path, legacy["run_id"], legacy_path)
    assert cold["payload"] == warm["payload"]
    assert cold["reused"] is False
    assert warm["reused"] is True


def test_map_warns_and_omits_registered_scan_when_retained_bytes_change(
    tmp_path, monkeypatch,
):
    data_dir = tmp_path / "data"
    db_path = data_dir / "nct.db"
    manifest, _ = create_scan(db_path, data_dir, "e" * 32)
    path = data_dir / RUNS_DIR_NAME / manifest["run_id"] / "scan.xml"
    path.write_bytes(TOPOLOGY_XML.replace(b"10.80.0.10", b"10.80.0.20"))
    monkeypatch.setattr(network_map, "DB_PATH", db_path)
    monkeypatch.setattr(network_map, "DATA_DIR", data_dir)
    warnings = []

    assert network_map.automated_scan_hosts({}, {}, warnings) == 0
    assert len(warnings) == 1
    assert "does not match its registered artifact" in warnings[0]
    with connect_database(db_path, read_only=True) as db:
        assert db.execute("SELECT COUNT(*) FROM derived_results").fetchone()[0] == 0


def test_map_warns_when_backfilled_legacy_run_loses_its_run_local_xml(
    tmp_path, monkeypatch,
):
    data_dir = tmp_path / "data"
    db_path = data_dir / "nct.db"
    manifest, _ = create_scan(db_path, data_dir, "f" * 32, registered=False)
    assert "artifact_registry" not in manifest
    assert backfill_storage(db_path)["completed"] >= 1
    path = data_dir / RUNS_DIR_NAME / manifest["run_id"] / "scan.xml"
    path.unlink()
    monkeypatch.setattr(network_map, "DB_PATH", db_path)
    monkeypatch.setattr(network_map, "DATA_DIR", data_dir)
    warnings = []

    assert network_map.automated_scan_hosts({}, {}, warnings) == 0
    assert len(warnings) == 1
    assert "Run-local Nmap evidence is unavailable" in warnings[0]
