from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.network_evidence_cache import NetworkEvidenceSourceChanged
from app.network_inventory import (
    StaleNetworkEvidenceError,
    filtered_network_inventory_ips,
    network_inventory_outliers,
    page_network_inventory,
)


REVISION = "a" * 64


def _host(index: int, *, subnet: str | None = None) -> dict:
    group = subnet or ("10.0.0.0/24" if index % 2 else "10.0.1.0/24")
    port = 22 if index % 3 else 8080
    category = "Remote Access & Administration" if port == 22 else "Web Applications & APIs"
    return {
        "host_key": f"host-{index:04d}",
        "ip": f"10.{index // 65536}.{(index // 256) % 256}.{index % 256}",
        "hostname": f"node-{index}",
        "hostname_aliases": [f"asset-{index}"],
        "mac": f"02:00:00:{(index >> 16) & 255:02x}:{(index >> 8) & 255:02x}:{index & 255:02x}",
        "vendor": "Example Vendor",
        "os_display": "Linux / Unix-like (inferred)" if index % 2 else "Windows",
        "device_type": "Server",
        "subnet": group,
        "categories": [category],
        "services": [{
            "protocol": "tcp",
            "port": port,
            "service": "ssh" if port == 22 else "http-proxy",
            "product": "Dropbear" if port == 22 else "Example Proxy",
            "version": str(index),
        }],
        "source_refs": [{"url": f"/api/source/{index}"}],
        "scan_coverages": [{"protocols": ["tcp"], "targets": [group]}],
        "last_observed": f"2030-01-{(index % 28) + 1:02d}T00:00:00+00:00",
        "evidence_origin": "nmap",
        "finding_count": 1,
    }


def _model(count: int = 2500) -> dict:
    hosts = [_host(index) for index in range(1, count + 1)]
    findings = [{
        "host_key": host["host_key"],
        "ip": host["ip"],
        "category": host["categories"][0],
        "port": host["services"][0]["port"],
        "protocol": "tcp",
        "service": host["services"][0]["service"],
        "match_basis": ["test"],
    } for host in hosts]
    return {
        "status": "hunting_complete",
        "source_revision": REVISION,
        "source": {"scope_summaries": []},
        "host_count": len(hosts),
        "nmap_host_count": len(hosts),
        "configuration_device_count": 0,
        "finding_count": len(findings),
        "facets": {
            "subnets": [
                {"name": "10.0.0.0/24", "host_count": (count + 1) // 2},
                {"name": "10.0.1.0/24", "host_count": count // 2},
            ]
        },
        "hosts": hosts,
        "findings": findings,
        "warnings": [],
    }


def test_large_inventory_pages_are_bounded_complete_and_isolated():
    model = _model()
    first = page_network_inventory(model, limit=100, offset=0)
    second = page_network_inventory(
        model, limit=100, offset=100, expected_revision=REVISION
    )

    assert first["pagination"] == {
        "limit": 100, "offset": 0, "total": 2500,
        "has_more": True, "revision": REVISION,
    }
    assert len(first["hosts"]) == len(first["findings"]) == 100
    assert len(second["hosts"]) == len(second["findings"]) == 100
    first_keys = {item["host_key"] for item in first["hosts"]}
    second_keys = {item["host_key"] for item in second["hosts"]}
    assert first_keys.isdisjoint(second_keys)
    assert {item["host_key"] for item in first["findings"]} == first_keys
    assert {item["host_key"] for item in second["findings"]} == second_keys

    first["hosts"][0]["services"][0]["service"] = "caller mutation"
    repeat = page_network_inventory(model, limit=100, offset=0)
    assert repeat["hosts"][0]["services"][0]["service"] != "caller mutation"


@pytest.mark.parametrize("sort", ["ip", "port", "service", "mac", "hostname", "os", "last"])
def test_every_inventory_sort_is_stable_without_duplicates(sort):
    model = _model(211)
    pages = [
        page_network_inventory(model, limit=37, offset=offset, sort=sort)
        for offset in range(0, 222, 37)
    ]
    keys = [host["host_key"] for page in pages for host in page["hosts"]]
    assert len(keys) == len(set(keys)) == 211
    assert pages[-1]["pagination"]["has_more"] is False
    assert page_network_inventory(model, limit=37, offset=0, sort=sort)["hosts"] == pages[0]["hosts"]


def test_search_and_subnet_are_applied_before_paging():
    model = _model(300)
    result = page_network_inventory(
        model,
        limit=25,
        search="http-proxy example proxy",
        subnet="10.0.0.0/24",
        sort="port",
    )
    assert result["pagination"]["total"] == 50
    assert len(result["hosts"]) == 25
    assert all(host["subnet"] == "10.0.0.0/24" for host in result["hosts"])
    assert all(host["services"][0]["port"] == 8080 for host in result["hosts"])


def test_stale_revision_is_rejected_for_pages_lfa_and_export():
    model = _model(20)
    with pytest.raises(StaleNetworkEvidenceError):
        page_network_inventory(model, limit=10, expected_revision="b" * 64)
    with pytest.raises(StaleNetworkEvidenceError):
        network_inventory_outliers(
            model, threshold=20, expected_revision="b" * 64
        )
    with pytest.raises(StaleNetworkEvidenceError):
        filtered_network_inventory_ips(model, expected_revision="b" * 64)


def test_lfa_uses_complete_filtered_subnet_independent_of_page_size():
    model = _model(300)
    first_page = page_network_inventory(
        model, limit=1, subnet="10.0.0.0/24"
    )
    large_page = page_network_inventory(
        model, limit=100, subnet="10.0.0.0/24"
    )
    lfa = network_inventory_outliers(
        model, threshold=20, subnet="10.0.0.0/24"
    )
    assert len(first_page["hosts"]) == 1
    assert len(large_page["hosts"]) == 100
    assert sum(group["member_count"] for group in lfa["groups"]) == 150
    assert lfa == network_inventory_outliers(
        model, threshold=20, subnet="10.0.0.0/24"
    )


def test_filtered_export_includes_every_match_not_visible_page():
    model = _model(300)
    page = page_network_inventory(
        model, limit=25, search="dropbear", subnet="10.0.0.0/24"
    )
    exported = filtered_network_inventory_ips(
        model, search="dropbear", subnet="10.0.0.0/24"
    )
    assert page["pagination"]["total"] == exported["count"] == 100
    assert len(page["hosts"]) == 25
    assert len(exported["ips"]) == 100


def test_concurrent_pages_do_not_mutate_the_complete_model():
    model = _model(500)
    with ThreadPoolExecutor(max_workers=8) as pool:
        pages = list(pool.map(
            lambda offset: page_network_inventory(
                model, limit=50, offset=offset, expected_revision=REVISION
            ),
            range(0, 400, 50),
        ))
    assert all(len(page["hosts"]) == 50 for page in pages)
    assert model["hosts"][0]["services"][0]["service"] == "ssh"


def test_current_network_paging_routes_cap_validate_and_reject_stale(monkeypatch):
    model = _model(250)
    monkeypatch.setattr("app.main._latest_network_evidence", lambda: model)
    client = TestClient(app)

    page = client.get("/api/analysis/network/page?limit=100&offset=100&sort=hostname")
    assert page.status_code == 200
    payload = page.json()
    assert payload["status"] == "analysis_network_page_complete"
    assert len(payload["hosts"]) == 100
    assert payload["pagination"]["total"] == 250
    assert client.get("/api/analysis/network/page?limit=101").status_code == 422
    assert client.get("/api/analysis/network/page?sort=unsupported").status_code == 422
    assert client.get(
        "/api/analysis/network/page?revision=" + ("b" * 64)
    ).status_code == 409
    assert client.get(
        "/api/analysis/network/outliers?threshold=0"
    ).status_code == 422
    assert client.get(
        "/api/analysis/network/ips?revision=" + ("b" * 64)
    ).status_code == 409


def test_current_network_projection_routes_report_unstable_sources_as_conflicts(
    monkeypatch,
):
    def unstable():
        raise NetworkEvidenceSourceChanged(
            "Current Network inputs changed repeatedly; retry the request"
        )

    monkeypatch.setattr("app.main._latest_network_evidence", unstable)
    client = TestClient(app)
    for path in (
        "/api/analysis/network/page",
        "/api/analysis/network/outliers",
        "/api/analysis/network/ips",
    ):
        response = client.get(path)
        assert response.status_code == 409
        assert "changed repeatedly" in response.json()["detail"]
