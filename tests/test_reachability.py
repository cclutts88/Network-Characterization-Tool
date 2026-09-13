from __future__ import annotations

import pytest

from app import main
from app.iptables_policy import parse_iptables_policy
from app.reachability import evaluate_reachability, parse_endpoint
from app.vendor_policy import parse_vendor_policy


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


def test_ordered_iptables_sets_drive_expected_allowed_decision():
    policy = parse_iptables_policy("""*filter
:FORWARD DROP [0:0]
:LAN_TO_SERVERS - [0:0]
-A FORWARD -i inside -o servers -j LAN_TO_SERVERS
-A LAN_TO_SERVERS -p tcp -m set --match-set USERS src -m set --match-set HTTPS dst -j ACCEPT
-A LAN_TO_SERVERS -j DROP
COMMIT
create USERS hash:net family inet
add USERS 10.80.0.0/24
create HTTPS bitmap:port range 0-65535
add HTTPS 443
""")
    device = {
        **DEVICE,
        "interfaces": [
            {"name": "inside", "network": "10.80.0.0/24", "role": "internal"},
            {"name": "servers", "network": "10.90.0.0/24", "role": "internal"},
        ],
        "policy": {"firewall_acl": [], "iptables": policy},
    }

    result = assess(device_analyses=[device])

    assert result["outcome"] == "Expected Allowed"
    assert result["confidence"] == "high"
    assert result["counts"]["policy_decisions"] == 1
    policy_evidence = next(item for item in result["evidence"] if item["kind"] == "policy")
    assert policy_evidence["title"].startswith("Ordered permit")


def test_ordered_iptables_unsupported_match_remains_routed_with_caveat():
    policy = parse_iptables_policy("""*filter
:FORWARD ACCEPT [0:0]
-A FORWARD -m dpi32 --cat-app 4,112 -j DROP
COMMIT
""")
    device = {**DEVICE, "policy": {"firewall_acl": [], "iptables": policy}}

    result = assess(device_analyses=[device])

    assert result["outcome"] == "Routed"
    assert result["counts"]["policy_decisions"] == 0
    assert result["counts"]["policy_unresolved"] == 1
    assert any("unresolved match criteria" in item for item in result["caveats"])


def test_dnat_translation_uses_internal_target_for_service_route_and_policy():
    policy = parse_iptables_policy("""*nat
:PREROUTING ACCEPT [0:0]
-A PREROUTING -i outside -p tcp --dport 8443 -j DNAT --to-destination 10.90.0.10:443
COMMIT
*filter
:FORWARD DROP [0:0]
-A FORWARD -i outside -o servers -p tcp -d 10.90.0.10/32 --dport 443 -j ACCEPT
COMMIT
""")
    device = {
        **DEVICE,
        "interfaces": [
            {"name": "outside", "network": "198.51.100.0/24", "role": "external"},
            {"name": "servers", "network": "10.90.0.0/24", "role": "internal"},
        ],
        "route_analysis": {"routes": [
            {"network": "0.0.0.0/0", "via": "198.51.100.1", "interface": "outside"},
            {"network": "10.90.0.0/24", "interface": "servers", "direct": True},
        ]},
        "policy": {"firewall_acl": [], "iptables": policy},
    }

    result = assess(
        source_text="Internet", destination_text="198.51.100.10", port=8443,
        device_analyses=[device],
    )

    assert result["outcome"] == "Expected Allowed"
    assert result["query"]["effective_destination"] == "10.90.0.10"
    assert result["query"]["effective_port"] == 443
    assert result["service_observation"] == "observed_exposed"
    assert result["counts"]["nat_translations"] == 1
    assert any(item["kind"] == "nat" for item in result["evidence"])


def test_external_source_uses_default_route_interface_when_role_is_unclassified():
    policy = parse_iptables_policy("""*nat
:PREROUTING ACCEPT [0:0]
-A PREROUTING -i eth9 -p tcp --dport 8443 -j DNAT --to-destination 10.90.0.10:443
COMMIT
*filter
:FORWARD DROP [0:0]
-A FORWARD -i eth9 -o servers -p tcp --dport 443 -j ACCEPT
COMMIT
""")
    device = {
        **DEVICE,
        "interfaces": [
            {"name": "eth9", "network": "198.51.100.0/24", "role": "unclassified"},
            {"name": "servers", "network": "10.90.0.0/24", "role": "internal"},
        ],
        "route_analysis": {"routes": [
            {"network": "0.0.0.0/0", "via": "198.51.100.1", "interface": "eth9"},
            {"network": "10.90.0.0/24", "interface": "servers", "direct": True},
        ]},
        "policy": {"firewall_acl": [], "iptables": policy},
    }

    result = assess(
        source_text="Internet", destination_text="198.51.100.10", port=8443,
        device_analyses=[device],
    )

    assert result["outcome"] == "Expected Allowed"
    assert result["query"]["effective_destination"] == "10.90.0.10"


def test_external_source_skips_metadata_default_route_without_interface():
    policy = parse_iptables_policy("""*filter
:FORWARD DROP [0:0]
-A FORWARD -i outside -o inside -p tcp --dport 22 -j DROP
COMMIT
""")
    device = {
        **DEVICE,
        "interfaces": [
            {"name": "outside", "address": "198.51.100.2/24", "network": "198.51.100.0/24", "role": "unclassified"},
            {"name": "inside", "address": "10.80.0.1/24", "network": "10.80.0.0/24", "role": "internal"},
        ],
        "route_analysis": {"routes": [
            {"network": "0.0.0.0/0", "via": "127.0.0.1", "interface": None},
            {"network": "0.0.0.0/0", "via": "198.51.100.1", "interface": "outside"},
            {"network": "10.80.0.0/24", "interface": "inside", "direct": True},
        ]},
        "policy": {"firewall_acl": [], "iptables": policy},
    }

    result = assess(
        source_text="Internet", destination_text="10.80.0.0/24", port=22,
        device_analyses=[device], hunting={"hosts": [], "findings": []},
    )

    assert result["outcome"] == "Expected Blocked"
    assert result["counts"]["policy_decisions"] == 1


def test_source_masquerade_uses_outgoing_interface_address_in_reach():
    policy = parse_iptables_policy("""*nat
:POSTROUTING ACCEPT [0:0]
-A POSTROUTING -s 10.80.0.0/24 -o outside -j MASQUERADE
COMMIT
*filter
:FORWARD DROP [0:0]
-A FORWARD -i inside -o outside -p tcp --dport 443 -j ACCEPT
COMMIT
""")
    device = {
        **DEVICE,
        "interfaces": [
            {"name": "inside", "address": "10.80.0.1/24", "network": "10.80.0.0/24", "role": "internal"},
            {"name": "outside", "address": "198.51.100.2/24", "network": "198.51.100.0/24", "role": "external"},
        ],
        "route_analysis": {"routes": [
            {"network": "0.0.0.0/0", "via": "198.51.100.1", "interface": "outside"},
        ]},
        "policy": {"firewall_acl": [], "iptables": policy},
    }

    result = assess(
        destination_text="Internet", device_analyses=[device],
        hunting={"hosts": [], "findings": []},
    )

    assert result["outcome"] == "Expected Allowed"
    assert result["query"]["effective_source"] == "198.51.100.2"
    assert result["counts"]["source_nat_translations"] == 1
    assert result["counts"]["destination_nat_translations"] == 0
    assert any(item["title"].startswith("Masquerade on") for item in result["evidence"])
    assert any(item["label"].startswith("Masquerade on") for item in result["path"])


def test_unsupported_source_nat_target_forces_unknown():
    policy = parse_iptables_policy("""*nat
:POSTROUTING ACCEPT [0:0]
-A POSTROUTING -s 10.80.0.0/24 -j SNAT --to-source 198.51.100.10-198.51.100.20
COMMIT
*filter
:FORWARD ACCEPT [0:0]
COMMIT
""")
    device = {
        **DEVICE,
        "interfaces": [{"name": "inside", "network": "10.80.0.0/24", "role": "internal"}],
        "route_analysis": {"routes": [{"network": "0.0.0.0/0", "interface": "outside"}]},
        "policy": {"firewall_acl": [], "iptables": policy},
    }

    result = assess(
        destination_text="Internet", device_analyses=[device],
        hunting={"hosts": [], "findings": []},
    )

    assert result["outcome"] == "Unknown"
    assert result["counts"]["nat_unresolved"] == 1
    assert any("single IPv4 address" in item for item in result["caveats"])


def test_applied_cisco_acl_drives_reachability_but_unbound_acl_does_not():
    text = """ip access-list extended USERS_TO_SERVERS
 permit tcp any host 10.90.0.10 eq 443
 deny ip any any
!
interface inside
 ip access-group USERS_TO_SERVERS in
"""
    device = {
        **DEVICE,
        "interfaces": [
            {"name": "inside", "network": "10.80.0.0/24", "role": "internal"},
            {"name": "servers", "network": "10.90.0.0/24", "role": "internal"},
        ],
        "policy": {
            "firewall_acl": [{"evidence": "access-list unrelated permit tcp any host 10.90.0.10 eq 443"}],
            "applied": parse_vendor_policy(text),
        },
    }

    result = assess(device_analyses=[device])
    assert result["outcome"] == "Expected Allowed"
    assert next(item for item in result["evidence"] if item["kind"] == "policy")["title"].startswith("Applied permit")

    unbound = {**device, "policy": {**device["policy"], "applied": parse_vendor_policy(text.replace(" ip access-group USERS_TO_SERVERS in", ""))}}
    result = assess(device_analyses=[unbound])
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
