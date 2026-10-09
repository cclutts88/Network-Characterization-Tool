from __future__ import annotations

import hashlib
import json
from pathlib import Path
import os
import xml.etree.ElementTree as ET

import pytest

from app.device_configs import calculate_device_collection_summary
from app.comparison import compare_analyses
from app.main import parse_xml
from app.searchsploit import _search, enrich_hunting_with_searchsploit
from scripts.generate_phase0_benchmark_corpus import (
    MANIFEST_NAME,
    generate_corpus,
    verify_corpus,
)


def _digest_tree(root: Path) -> dict[str, str]:
    return {
        path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def test_phase0_corpus_is_deterministic_and_exactly_verifiable(tmp_path):
    first = tmp_path / "first"
    second = tmp_path / "second"

    first_manifest = generate_corpus(first)
    second_manifest = generate_corpus(second)

    assert _digest_tree(first) == _digest_tree(second)
    assert first_manifest == second_manifest
    assert verify_corpus(first)["file_count"] == 17
    assert first_manifest["network_access_required"] is False
    assert first_manifest["data_classification"].startswith("synthetic")


def test_phase0_corpus_refuses_overwrite_and_changed_content(tmp_path):
    root = tmp_path / "corpus"
    generate_corpus(root)

    with pytest.raises(ValueError, match="never overwritten"):
        generate_corpus(root)

    empty = tmp_path / "already-exists"
    empty.mkdir()
    with pytest.raises(ValueError, match="never overwritten"):
        generate_corpus(empty)

    changed = root / "nmap" / "small_tcp.xml"
    changed.write_bytes(changed.read_bytes() + b"changed")
    with pytest.raises(ValueError, match="exact-content verification"):
        verify_corpus(root)


def test_phase0_verifier_rejects_extra_and_unsafe_manifest_paths(tmp_path):
    root = tmp_path / "corpus"
    generate_corpus(root)
    (root / "unexpected.txt").write_text("not part of the corpus", encoding="utf-8")
    with pytest.raises(ValueError, match="missing or unexpected"):
        verify_corpus(root)
    (root / "unexpected.txt").unlink()

    manifest_path = root / MANIFEST_NAME
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"][0]["path"] = "../outside.xml"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ValueError, match="unsafe file path"):
        verify_corpus(root)


def test_phase0_verifier_rejects_changed_file_with_matching_edited_hash(tmp_path):
    root = tmp_path / "corpus"
    generate_corpus(root)
    changed = root / "nmap" / "small_tcp.xml"
    changed.write_bytes(changed.read_bytes() + b"changed")
    manifest_path = root / MANIFEST_NAME
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    entry = next(item for item in manifest["files"] if item["path"] == "nmap/small_tcp.xml")
    entry["size_bytes"] = changed.stat().st_size
    entry["sha256"] = hashlib.sha256(changed.read_bytes()).hexdigest()
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ValueError, match="exact schema, files, hashes, and oracle"):
        verify_corpus(root)


def test_phase0_manifest_has_safe_relative_paths_and_expected_oracle(tmp_path):
    root = tmp_path / "corpus"
    manifest = generate_corpus(root)

    assert all(not Path(item["path"]).is_absolute() for item in manifest["files"])
    large = {
        name: value for name, value in manifest["oracle"]["nmap_files"].items()
        if name.startswith("nmap/large_segment_")
    }
    assert len(large) == 4
    assert all(value["hosts"] == 1000 for value in large.values())
    assert manifest["oracle"]["history"]["exact_duplicate_files"] == [
        "nmap/history_before.xml", "nmap/history_before_duplicate.xml",
    ]
    assert manifest["oracle"]["enrichment"]["expected_cache_misses_first_pass"] == 24
    saved = json.loads((root / MANIFEST_NAME).read_text(encoding="utf-8"))
    assert saved == manifest


def test_phase0_nmap_workloads_match_parser_and_xml_oracle(tmp_path):
    root = tmp_path / "corpus"
    manifest = generate_corpus(root)

    small = parse_xml((root / "nmap" / "small_tcp.xml").read_bytes())
    medium = parse_xml((root / "nmap" / "medium_udp.xml").read_bytes())
    assert len(small["hosts"]) == manifest["oracle"]["nmap_files"]["nmap/small_tcp.xml"]["hosts"]
    assert {port["protocol"] for host in small["hosts"] for port in host["ports"]} == {"tcp"}
    assert len(medium["hosts"]) == manifest["oracle"]["nmap_files"]["nmap/medium_udp.xml"]["hosts"]
    assert sum(len(host["ports"]) for host in medium["hosts"]) == 160
    assert {port["protocol"] for host in medium["hosts"] for port in host["ports"]} == {"udp"}

    large_hosts = 0
    for relative_name, expected in manifest["oracle"]["nmap_files"].items():
        root_node = ET.parse(root / relative_name).getroot()
        assert root_node.find("./runstats/finished") is not None
        ports = root_node.findall("./host/ports/port")
        by_protocol = {}
        for port in ports:
            protocol = port.get("protocol") or "unknown"
            by_protocol[protocol] = by_protocol.get(protocol, 0) + 1
        actual = {
            "hosts": len(root_node.findall("host")),
            "service_observations": len(ports),
            "service_observations_by_protocol": dict(sorted(by_protocol.items())),
            "ipv4_addresses": len(root_node.findall('./host/address[@addrtype="ipv4"]')),
            "mac_addresses": len(root_node.findall('./host/address[@addrtype="mac"]')),
            "traces": len(root_node.findall("./host/trace")),
            "scan_protocols": sorted(node.get("protocol") for node in root_node.findall("scaninfo")),
        }
        assert actual == expected
        if relative_name.startswith("nmap/large_segment_"):
            large_hosts += expected["hosts"]
    assert large_hosts == 4000


def test_phase0_history_has_known_changes_and_exact_duplicate(tmp_path):
    root = tmp_path / "corpus"
    manifest = generate_corpus(root)
    before_bytes = (root / "nmap" / "history_before.xml").read_bytes()
    duplicate_bytes = (root / "nmap" / "history_before_duplicate.xml").read_bytes()
    before = parse_xml(before_bytes)
    after = parse_xml((root / "nmap" / "history_after.xml").read_bytes())

    assert before_bytes == duplicate_bytes
    assert len(before["hosts"]) == manifest["oracle"]["history"]["before_hosts"]
    assert len(after["hosts"]) == manifest["oracle"]["history"]["after_hosts"]
    before_by_ip = {host["ip"]: host for host in before["hosts"]}
    after_by_ip = {host["ip"]: host for host in after["hosts"]}
    assert sorted(after_by_ip.keys() - before_by_ip.keys()) == ["10.30.0.65"]
    assert sorted(before_by_ip.keys() - after_by_ip.keys()) == ["10.30.0.64"]
    assert len(after_by_ip["10.30.0.2"]["ports"]) - len(before_by_ip["10.30.0.2"]["ports"]) == 1
    assert len(before_by_ip["10.30.0.3"]["ports"]) - len(after_by_ip["10.30.0.3"]["ports"]) == 1
    assert len(after_by_ip["10.30.0.4"]["ports"]) - len(before_by_ip["10.30.0.4"]["ports"]) == 1
    comparison = compare_analyses(before, after)
    assert comparison["summary"]["hosts_added"] == 1
    assert comparison["summary"]["hosts_removed"] == 1
    assert comparison["summary"]["ports_added"] == manifest["oracle"]["history"]["ports_added"]
    assert comparison["summary"]["ports_removed"] == manifest["oracle"]["history"]["ports_no_longer_observed"]
    assert comparison["summary"]["service_changes"] == manifest["oracle"]["history"]["version_changes"]


def _device_summary(path: Path) -> dict:
    text = path.read_text(encoding="utf-8")
    return calculate_device_collection_summary(
        run_id="benchmark",
        configuration_text=text,
        source_filename=path.name,
        configuration_truncated=False,
        raw_output=text,
        raw_filename=path.name,
        raw_truncated=False,
        history_text="",
        history_attempted=False,
        vendor="cisco",
        commands=[],
        output_complete=True,
    )


def test_phase0_device_workloads_exercise_required_evidence(tmp_path):
    root = tmp_path / "corpus"
    generate_corpus(root)

    router = _device_summary(root / "devices" / "router.txt")
    firewall = _device_summary(root / "devices" / "firewall.txt")
    switch = _device_summary(root / "devices" / "switch.txt")
    boundary = _device_summary(root / "devices" / "switch_1000_interfaces.txt")

    summaries = {
        "devices/router.txt": router,
        "devices/firewall.txt": firewall,
        "devices/switch.txt": switch,
        "devices/switch_1000_interfaces.txt": boundary,
    }
    manifest = json.loads((root / MANIFEST_NAME).read_text(encoding="utf-8"))
    for name, expected in manifest["oracle"]["devices"]["parsed_counts"].items():
        assert summaries[name]["counts"] == expected


def test_phase0_enrichment_workload_has_repeated_frozen_queries(tmp_path, monkeypatch):
    root = tmp_path / "corpus"
    manifest = generate_corpus(root)
    findings = json.loads((root / "enrichment" / "findings.json").read_text(encoding="utf-8"))["findings"]
    queries = {(item["product"], item["version"]) for item in findings}

    assert len(findings) == manifest["oracle"]["enrichment"]["finding_count"]
    assert len(queries) == manifest["oracle"]["enrichment"]["unique_product_version_queries"]
    with (root / "enrichment" / "files_exploits.csv").open(newline="", encoding="utf-8") as source:
        rows = list(__import__("csv").DictReader(source))
    assert len(rows) == manifest["oracle"]["enrichment"]["candidate_rows"]

    if os.name != "nt":
        command = root / "enrichment" / "searchsploit"
        candidates, warning = _search(
            str(command), "NCT Benchmark Product 00 1.0.0", str(command.parent)
        )
        assert warning is None
        assert len(candidates) == manifest["oracle"]["enrichment"]["expected_candidates_per_query"]
        assert {item["cves"][0] for item in candidates} == {"CVE-2026-1000"}
        monkeypatch.setenv("ANALYZER_DATA_DIR", str(tmp_path / "cache-data"))
        provider = {
            "available": True,
            "command_path": str(command),
            "command_sha256": hashlib.sha256(command.read_bytes()).hexdigest(),
            "database_path": str(command.parent),
            "active_version": "phase0-corpus-v1",
            "archive_sha256": hashlib.sha256(
                (command.parent / "files_exploits.csv").read_bytes()
            ).hexdigest(),
            "database_updated_epoch": 1_800_000_000,
            "message": "Frozen Phase 0 benchmark provider",
        }
        workload = {"findings": findings}
        first = enrich_hunting_with_searchsploit(workload, provider_status=provider)
        second = enrich_hunting_with_searchsploit(workload, provider_status=provider)
        oracle = manifest["oracle"]["enrichment"]
        assert first["status"] == second["status"] == "searchsploit_complete"
        assert first["query_count"] == oracle["unique_product_version_queries"]
        assert first["cache_miss_count"] == oracle["expected_cache_misses_first_pass"]
        assert first["cache_hit_count"] == 0
        assert second["cache_miss_count"] == 0
        assert second["cache_hit_count"] == oracle["expected_cache_hits_second_pass"]
        assert first["match_count"] == second["match_count"] == 240
        assert first["cve_count"] == second["cve_count"] == 24
