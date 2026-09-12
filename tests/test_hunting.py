from __future__ import annotations

from fastapi.testclient import TestClient

from app.hunting import (
    build_hunting_analysis,
    categorize_port,
    compare_hunting_results,
    merge_hunting_analyses,
)
from app.main import app


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

    assert ssh[0]["category"] == "Remote Access"
    assert ssh[0]["capability_state"] == "observed"
    assert ssh[0]["nonstandard_port"] is True
    assert {item["category"] for item in mixed} == {"Web", "Identity"}
    assert {item["capability_state"] for item in mixed} == {"inferred", "observed"}


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
    assert result["finding_count"] == 3
    assert result["nonstandard_finding_count"] == 1
    assert result["categories"] == [
        {"name": "Remote Access", "finding_count": 2},
        {"name": "Other Exposed Service", "finding_count": 1},
    ]
    assert result["capability_states"]["correlated"] == 1
    assert result["capability_states"]["observed"] == 2
    assert result["capability_states"]["exposed"] == 3
    assert result["warnings"] == ["Limited UDP coverage"]
    unknown = next(item for item in result["findings"] if item["port"] == 31337)
    assert unknown["capability_state"] == "exposed"


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
    assert result["finding_count"] == 1
    assert result["findings"][0]["version"] == "9.2"


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
        "findings_added": 1,
        "findings_removed": 0,
        "findings_changed": 1,
        "hosts_with_category_changes": 1,
    }
    assert result["findings_added"][0]["category"] == "Remote Access"
    assert "version" in result["findings_changed"][0]["changes"]
    assert result["host_category_changes"][0]["categories_added"] == ["Remote Access"]


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

    with TestClient(app) as client:
        analysis = client.get(f"/api/hunting/{after_id}")
        network = client.get("/api/hunting/network")
        comparison = client.get(
            f"/api/hunting/compare?before={before_id}&after={after_id}"
        )

    assert analysis.status_code == 200
    assert analysis.json()["findings"][0]["nonstandard_port"] is True
    assert analysis.json()["source"]["evidence"]["sources"][0]["url"].endswith(
        f"/{after_id}/artifacts/xml"
    )
    assert comparison.status_code == 200
    assert comparison.json()["summary"]["findings_added"] == 1
    assert comparison.json()["summary"]["findings_removed"] == 1
    assert network.status_code == 200
    assert network.json()["status"] == "hunting_network_complete"
    assert network.json()["source"]["scan_count"] == 1
    assert network.json()["facets"]["subnets"][0]["name"] == "10.0.0.0/24"
