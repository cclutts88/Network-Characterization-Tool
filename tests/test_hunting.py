from __future__ import annotations

from fastapi.testclient import TestClient

from app.hunting import (
    build_hunting_analysis,
    categorize_port,
    compare_hunting_results,
    correlate_hunting_identity,
    merge_hunting_analyses,
)
from app.main import app
from app.identity import enrich_analysis_macs


def host(ip: str, ports: list[dict]) -> dict:
    return {
        "ip": ip,
        "hostname": f"host-{ip.rsplit('.', 1)[-1]}",
        "state": "up",
        "os_group": "Linux server",
        "ports": ports,
    }


def port(number: int, service: str, product: str = "", version: str = "") -> dict:
    return {
        "protocol": "tcp",
        "port": number,
        "state": "open",
        "service": service,
        "product": product,
        "version": version,
    }


def test_category_rules_support_nonstandard_ports_and_multiple_categories():
    ssh = categorize_port(port(2222, "ssh", "OpenSSH"))
    mixed = categorize_port(port(443, "ldap", "Directory gateway"))

    assert ssh[0]["category"] == "Remote Access & Administration"
    assert ssh[0]["capability_state"] == "observed"
    assert ssh[0]["nonstandard_port"] is True
    assert ssh[1]["category"] == "File Transfer"
    assert ssh[1]["capability_state"] == "inferred"
    assert ssh[1]["evidence_states"] == ["exposed", "inferred"]
    assert ssh[1]["match_basis"] == [
        "capability inference: SSH may provide SCP/SFTP file transfer"
    ]
    assert {item["category"] for item in mixed} == {
        "Web Applications & APIs", "Directory & Identity",
    }
    assert {item["capability_state"] for item in mixed} == {"inferred", "observed"}


def test_explicit_sftp_is_observed_file_transfer_evidence():
    findings = categorize_port(port(22, "sftp", "OpenSSH"))
    file_transfer = next(
        item for item in findings if item["category"] == "File Transfer"
    )

    assert file_transfer["capability_state"] == "observed"
    assert "observed" in file_transfer["evidence_states"]
    assert any(
        basis.startswith("fingerprint:") for basis in file_transfer["match_basis"]
    )


def test_dataset_catalog_supports_authentication_and_only_activates_matches():
    result = build_hunting_analysis({
        "hosts": [host("10.0.0.10", [port(88, "kerberos-sec")])]
    })

    assert {item["name"] for item in result["datasets"]} == {"Authentication"}
    assert result["categories"] == result["datasets"]
    catalog = {item["name"]: item for item in result["dataset_catalog"]}
    assert len(catalog) == 26
    assert catalog["Authentication"]["active"] is True
    assert catalog["Routing & Network Control Plane"]["active"] is False
    assert catalog["Firewall, NAT & Policy"]["source_types"] == ["network_device"]


def test_hunting_analysis_distinguishes_capability_evidence_and_keeps_unknown_services():
    result = build_hunting_analysis(
        {
            "hosts": [
                host(
                    "10.0.0.10",
                    [
                        port(22, "ssh", "OpenSSH", "9.2"),
                        port(2222, "ssh", "OpenSSH", "8.9"),
                        port(31337, "unknown"),
                    ],
                )
            ],
            "warnings": ["Limited UDP coverage"],
        },
        evidence={"display_name": "Authorized test scan"},
    )

    assert result["host_count"] == 1
    assert result["finding_count"] == 5
    assert result["nonstandard_finding_count"] == 1
    assert result["categories"] == [
        {"name": "Remote Access & Administration", "finding_count": 2},
        {"name": "File Transfer", "finding_count": 2},
        {"name": "Unknown / Other Exposed Service", "finding_count": 1},
    ]
    assert result["capability_states"]["correlated"] == 1
    assert result["capability_states"]["observed"] == 2
    assert result["capability_states"]["inferred"] == 3
    assert result["capability_states"]["exposed"] == 5
    assert result["warnings"] == ["Limited UDP coverage"]
    unknown = next(item for item in result["findings"] if item["port"] == 31337)
    assert unknown["capability_state"] == "exposed"
    transfers = [
        item for item in result["findings"] if item["category"] == "File Transfer"
    ]
    assert len(transfers) == 2
    assert {item["capability_state"] for item in transfers} == {"inferred"}


def test_hunting_inventory_keeps_hosts_without_findings_and_builds_filter_facets():
    result = build_hunting_analysis(
        {
            "hosts": [
                host("10.0.0.10", [port(443, "https")]),
                {**host("10.0.0.20", []), "os": "Windows 11", "device_type": "workstation"},
            ]
        },
        evidence={"completed_at": "2026-09-11T12:00:00+00:00"},
        subnets=["10.0.0.0/24"],
    )

    assert result["host_count"] == 2
    assert result["hosts_with_findings_count"] == 1
    assert result["hosts"][1]["finding_count"] == 0
    assert {item["name"] for item in result["facets"]["subnets"]} == {"10.0.0.0/24"}
    assert {item["name"] for item in result["facets"]["device_types"]} >= {
        "Server", "Workstation",
    }


def test_hunting_exposes_service_based_os_inference_without_overwriting_os():
    result = build_hunting_analysis({
        "hosts": [{
            "ip": "10.0.0.100",
            "hostname": "",
            "state": "up",
            "os": "",
            "os_group": "Unclassified",
            "ports": [
                port(135, "msrpc", "Microsoft Windows RPC"),
                port(139, "netbios-ssn", "Microsoft Windows netbios-ssn"),
                port(445, "microsoft-ds"),
            ],
        }]
    })

    host_item = result["hosts"][0]
    assert host_item["os"] == ""
    assert host_item["os_inference"]["family"] == "Windows"
    assert host_item["os_filter"] == "Windows (inferred)"
    assert result["facets"]["operating_systems"] == [{
        "name": "Windows (inferred)", "host_count": 1,
    }]
    assert all(
        finding["os_inference"]["family"] == "Windows"
        for finding in result["findings"]
    )


def test_topology_vendor_enrichment_recalculates_os_inference():
    result = build_hunting_analysis({
        "hosts": [{
            "ip": "10.0.0.2",
            "state": "up",
            "os_group": "Unclassified",
            "ports": [port(22, "ssh", "Dropbear sshd")],
        }]
    })
    assert result["hosts"][0]["os_inference"]["family"] == "Linux / Unix-like"

    correlated = correlate_hunting_identity(result, {"nodes": [{
        "ip": "10.0.0.2",
        "addresses": ["10.0.0.2"],
        "vendor": "Ubiquiti",
    }]})

    assert correlated["hosts"][0]["os_inference"]["family"] == "Network appliance"
    assert all(
        finding["os_inference"]["family"] == "Network appliance"
        for finding in correlated["findings"]
    )


def test_network_hunt_merges_newest_first_without_duplicate_hosts_or_findings():
    newer = build_hunting_analysis(
        {"hosts": [host("10.0.0.10", [port(22, "ssh", "OpenSSH", "9.2")])]},
        evidence={"completed_at": "2026-09-11T12:00:00+00:00"},
        subnets=["10.0.0.0/24"],
    )
    older = build_hunting_analysis(
        {"hosts": [host("10.0.0.10", [port(22, "ssh", "OpenSSH", "8.9")])]},
        evidence={"completed_at": "2026-09-10T12:00:00+00:00"},
        subnets=["10.0.0.0/24"],
    )

    result = merge_hunting_analyses([newer, older])

    assert result["host_count"] == 1
    assert result["finding_count"] == 2
    assert {item["category"] for item in result["findings"]} == {
        "Remote Access & Administration", "File Transfer",
    }
    assert {item["version"] for item in result["findings"]} == {"9.2"}


def test_network_hunt_adds_configuration_devices_without_claiming_nmap_observation():
    result = build_hunting_analysis({
        "hosts": [host("10.0.0.10", [port(22, "ssh", "OpenSSH")])]
    })
    topology = {"nodes": [{
        "id": "ip:192.0.2.10",
        "kind": "device",
        "ip": "192.0.2.10",
        "addresses": ["192.0.2.10", "10.80.0.1"],
        "hostname": "Core router",
        "role": "router",
        "vendor": "cisco",
        "interfaces": [{"name": "Gi0/1", "address": "10.80.0.1/24"}],
        "routes": [],
        "sources": [{
            "kind": "device_configuration",
            "label": "cisco router configuration",
            "timestamp": "2026-09-11T12:00:00+00:00",
            "url": "/api/device-configs/config/files/manifest.json",
        }],
    }]}

    correlated = correlate_hunting_identity(
        result, topology, include_configuration_devices=True
    )

    assert correlated["host_count"] == 2
    assert correlated["nmap_host_count"] == 1
    assert correlated["configuration_device_count"] == 1
    assert correlated["configuration_only_device_count"] == 1
    device = next(item for item in correlated["hosts"] if item["device_type"] == "Router")
    assert device["evidence_origin"] == "configuration_only"
    assert device["subnet"] == "10.80.0.0/24"
    finding = next(
        item for item in correlated["findings"]
        if item["category"] == "Routing & Network Control Plane"
    )
    assert finding["port"] is None
    assert finding["evidence_states"] == ["configuration"]
    assert finding["evidence_kind"] == "device_configuration"


def test_network_hunt_correlates_matching_configuration_device_without_duplication():
    result = build_hunting_analysis({
        "hosts": [host("10.0.0.1", [port(443, "https")])]
    })
    topology = {"nodes": [{
        "id": "ip:10.0.0.1",
        "kind": "device",
        "ip": "10.0.0.1",
        "addresses": ["10.0.0.1"],
        "hostname": "Edge firewall",
        "role": "firewall",
        "vendor": "pfsense",
        "interfaces": [],
        "routes": [],
        "sources": [{
            "kind": "configuration_output",
            "label": "firewall config.xml",
            "timestamp": "2026-09-11T12:00:00+00:00",
            "url": "/api/device-configs/firewall/files/config.xml",
        }],
    }]}

    correlated = correlate_hunting_identity(
        result, topology, include_configuration_devices=True
    )

    assert correlated["host_count"] == 1
    assert correlated["nmap_host_count"] == 1
    assert correlated["configuration_device_count"] == 1
    assert correlated["configuration_only_device_count"] == 0
    assert correlated["hosts"][0]["evidence_origin"] == "nmap_and_configuration"
    assert {item["category"] for item in correlated["findings"]} == {
        "Web Applications & APIs", "Firewall, NAT & Policy",
    }


def test_analysis_mac_enrichment_prefers_router_neighbor_evidence_and_marks_provenance():
    analysis = {"hosts": [host("10.0.0.10", [])], "mac_count": 0}
    topology = {"nodes": [{
        "ip": "10.0.0.10",
        "addresses": ["10.0.0.10"],
        "mac_observations": [{
            "mac": "00:11:22:33:44:55",
            "vendor": "Example Vendor",
            "protocol": "arp",
            "interface": "lan0",
            "segment": "10.0.0.0/24",
            "source_kind": "arp_neighbor_table",
            "source_label": "Core firewall ARP table",
            "source_url": "/api/device-configs/abc/files/stdout.txt",
            "last_observed": "2026-09-11T12:00:00+00:00",
        }],
    }]}

    result = enrich_analysis_macs(analysis, topology)

    assert result["hosts"][0]["mac"] == "00:11:22:33:44:55"
    assert result["hosts"][0]["vendor"] == "Example Vendor"
    assert result["hosts"][0]["mac_provenance"]["indirect"] is True
    assert result["hosts"][0]["mac_provenance"]["origin"] == "Router/firewall neighbor table"
    assert result["correlated_mac_count"] == 1


def test_hunting_comparison_reports_added_removed_and_changed_capabilities():
    before = build_hunting_analysis(
        {"hosts": [host("10.0.0.10", [port(8080, "http", "nginx", "1.20")])]},
        evidence={"display_name": "Before"},
    )
    after = build_hunting_analysis(
        {
            "hosts": [
                host(
                    "10.0.0.10",
                    [
                        port(8080, "http", "nginx", "1.24"),
                        port(2222, "ssh", "OpenSSH", "9.2"),
                    ],
                )
            ]
        },
        evidence={"display_name": "After"},
    )

    result = compare_hunting_results(before, after)

    assert result["summary"] == {
        "findings_added": 2,
        "findings_removed": 0,
        "findings_changed": 1,
        "hosts_with_category_changes": 1,
    }
    assert {item["category"] for item in result["findings_added"]} == {
        "Remote Access & Administration", "File Transfer",
    }
    assert "version" in result["findings_changed"][0]["changes"]
    assert set(result["host_category_changes"][0]["categories_added"]) == {
        "Remote Access & Administration", "File Transfer",
    }


def test_hunting_api_uses_retained_scan_groups(tmp_path, monkeypatch):
    before_id, after_id = "a" * 32, "b" * 32
    manifests = [
        {
            "run_id": after_id,
            "display_name": "Current hunt",
            "created_at": "2026-09-11T12:00:00+00:00",
            "completed_at": "2026-09-11T12:05:00+00:00",
            "status": "completed",
            "targets": ["10.0.0.0/24"],
            "profile": "safe",
        },
        {
            "run_id": before_id,
            "display_name": "Baseline hunt",
            "created_at": "2026-09-10T12:00:00+00:00",
            "completed_at": "2026-09-10T12:05:00+00:00",
            "status": "completed",
            "targets": ["10.0.0.0/24"],
            "profile": "safe",
        },
    ]
    for manifest, ports in (
        (manifests[0], '<port protocol="tcp" portid="2222"><state state="open"/><service name="ssh" product="OpenSSH"/></port>'),
        (manifests[1], '<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="nginx"/></port>'),
    ):
        run_dir = tmp_path / manifest["run_id"]
        run_dir.mkdir()
        (run_dir / "scan.xml").write_text(
            f'<nmaprun args="nmap 10.0.0.10"><host><status state="up"/><address addr="10.0.0.10" addrtype="ipv4"/><ports>{ports}</ports></host><runstats><hosts up="1" down="0" total="1"/></runstats></nmaprun>',
            encoding="utf-8",
        )
    monkeypatch.setattr("app.main.list_scan_run_plans", lambda limit=5000: manifests)
    monkeypatch.setattr("app.main.run_directory", lambda run_id: tmp_path / run_id)
    monkeypatch.setattr("app.network_map.build_topology", lambda: {"nodes": []})

    with TestClient(app) as client:
        analysis = client.get(f"/api/hunting/{after_id}")
        network = client.get("/api/hunting/network")
        comparison = client.get(
            f"/api/hunting/compare?before={before_id}&after={after_id}"
        )

    assert analysis.status_code == 200
    findings = analysis.json()["findings"]
    remote = next(
        item for item in findings
        if item["category"] == "Remote Access & Administration"
    )
    transfer = next(item for item in findings if item["category"] == "File Transfer")
    assert remote["nonstandard_port"] is True
    assert transfer["capability_state"] == "inferred"
    assert analysis.json()["source"]["evidence"]["sources"][0]["url"].endswith(
        f"/{after_id}/artifacts/xml"
    )
    assert comparison.status_code == 200
    assert comparison.json()["summary"]["findings_added"] == 2
    assert comparison.json()["summary"]["findings_removed"] == 1
    assert network.status_code == 200
    assert network.json()["status"] == "hunting_network_complete"
    assert network.json()["source"]["scan_count"] == 1
    assert network.json()["facets"]["subnets"][0]["name"] == "10.0.0.0/24"
