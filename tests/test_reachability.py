from __future__ import annotations

import pytest

from app import main
from app.reachability import evaluate_reachability, parse_endpoint


SAVED = [
    {"saved_network_id": "users", "name": "Users", "cidr": "10.80.0.0/24"},
    {"saved_network_id": "servers", "name": "Servers", "cidr": "10.90.0.0/24"},
]

HUNTING = {
    "hosts": [{"ip": "10.90.0.10", "hostname": "app01"}],
    "findings": [{
        "ip": "10.90.0.10", "protocol": "tcp", "port": 443,
        "service": "https", "product": "nginx", "version": "1.24",
    }],
}

DEVICE = {
    "run_id": "a" * 32,
    "device": {"name": "Edge Firewall", "address": "10.80.0.1", "type": "firewall"},
    "interfaces": [{"name": "inside", "network": "10.80.0.0/24", "role": "internal"}],
    "route_analysis": {"routes": [{
        "network": "10.90.0.0/24", "via": "10.80.0.2",
        "interface": "inside", "protocol": "static",
        "line": "ip route 10.90.0.0 255.255.255.0 10.80.0.2",
    }]},
    "policy": {"firewall_acl": [{
        "evidence": "access-list 101 permit tcp any host 10.90.0.10 eq 443"
    }]},
}


def assess(**overrides):
    values = {
        "source_text": "10.80.0.25",
        "destination_text": "10.90.0.10",
        "protocol": "tcp",
        "port": 443,
        "hunting": HUNTING,
        "saved_networks": SAVED,
        "device_analyses": [DEVICE],
    }
    values.update(overrides)
    return evaluate_reachability(**values)


def test_explicit_acl_and_service_evidence_support_expected_allowed():
    result = assess()
    assert result["outcome"] == "Expected Allowed"
    assert result["confidence"] == "high"
    assert result["service_observation"] == "observed_exposed"
    assert result["counts"]["routes"] == 1
    assert {item["kind"] for item in result["evidence"]} >= {"route", "policy", "service"}


def test_same_saved_network_is_local_without_claiming_policy_decision():
    result = assess(
        source_text="10.80.0.25",
        destination_text="10.80.0.50",
        device_analyses=[],
        hunting={"hosts": [], "findings": []},
    )
    assert result["outcome"] == "Local"
    assert result["confidence"] == "medium"


def test_route_without_exact_policy_is_routed_not_allowed():
    device = {**DEVICE, "policy": {"firewall_acl": []}}
    result = assess(device_analyses=[device])
    assert result["outcome"] == "Routed"
    assert result["confidence"] == "medium"


def test_switch_management_default_route_is_not_transit_evidence():
    switch = {
        **DEVICE,
        "device": {"name": "Access Switch", "address": "10.80.0.2", "type": "switch"},
        "route_analysis": {"routes": [{"network": "0.0.0.0/0", "via": "10.80.0.1"}]},
        "policy": {"firewall_acl": []},
    }
    result = assess(destination_text="Internet", device_analyses=[switch])
    assert result["outcome"] == "Unknown"
    assert result["counts"]["routes"] == 0
    assert result["counts"]["excluded_non_transit_routes"] == 1


def test_missing_open_port_does_not_claim_blocked_or_not_exposed():
    result = assess(
        port=22,
        device_analyses=[],
        hunting={"hosts": HUNTING["hosts"], "findings": []},
    )
    assert result["outcome"] == "Unknown"
    assert result["service_observation"] == "not_observed"
    assert any("not proof" in item for item in result["caveats"])


def test_external_destination_uses_default_route():
    device = {
        **DEVICE,
        "route_analysis": {"routes": [{"network": "0.0.0.0/0", "via": "192.0.2.1"}]},
        "policy": {"firewall_acl": []},
    }
    result = assess(destination_text="Internet", device_analyses=[device])
    assert result["outcome"] == "Routed"


def test_invalid_endpoint_is_rejected():
    with pytest.raises(ValueError, match="Invalid IPv4"):
        parse_endpoint("not a network")


def test_latest_reachability_evidence_skips_failed_pull_and_uses_newest_success(monkeypatch):
    records = [
        {"run_id": "failed", "device_address": "10.80.0.1", "status": "failed"},
        {"run_id": "usable", "device_address": "10.80.0.1", "status": "completed"},
        {"run_id": "upload", "device_address": "10.80.0.2", "status": "uploaded"},
    ]
    monkeypatch.setattr(main, "device_collection_history", lambda limit: records)
    monkeypatch.setattr(
        main,
        "analyze_device_collection",
        lambda run_id: {"run_id": run_id},
    )

    result = main._latest_device_reachability_evidence()

    assert result == [{"run_id": "usable"}, {"run_id": "upload"}]
