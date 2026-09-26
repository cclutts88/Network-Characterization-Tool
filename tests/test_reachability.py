from __future__ import annotations

import pytest

from app import main
from app.iptables_policy import parse_iptables_policy
from app.reachability import (
    build_vendor_policy_rule,
    build_source_exposure_report,
    classify_searchsploit_exposure,
    evaluate_reachability,
    evaluate_reachability_range,
    parse_endpoint,
    policy_rule_context,
    simulate_proposed_policy_control,
    simulate_proposed_route_control,
    validate_vendor_policy_rule,
)
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


def covered_hunting(*, services: str = "1-1024", scan_type: str = "syn", observed_ports=None):
    return {
        "hosts": [{
            "ip": "10.90.0.10",
            "hostname": "app01",
            "state": "up",
            "observed_ports": observed_ports or [],
            "scan_coverages": [{
                "source": "nmap_xml",
                "scan_types": [{
                    "type": scan_type,
                    "protocol": "TCP",
                    "services": services,
                    "service_count": 1024,
                }],
                "command": "nmap -sS -p 1-1024 10.90.0.10",
                "observed_at": "2026-09-12T12:00:00+00:00",
            }],
        }],
        "findings": [],
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


def range_device(*, policy=None, connected="10.20.0.0/16", extra_routes=None):
    return {
        "run_id": "f" * 32,
        "device": {"name": "Range edge", "address": "198.51.100.1", "type": "firewall"},
        "interfaces": [
            {"name": "outside", "network": "198.51.100.0/24", "role": "external"},
            {"name": "inside", "network": connected, "role": "internal"},
        ],
        "route_analysis": {"routes": [
            {"network": connected, "interface": "inside", "direct": True, "protocol": "connected"},
            {"network": "0.0.0.0/0", "interface": "outside", "via": "198.51.100.254"},
            *(extra_routes or []),
        ]},
        "policy": policy or {"firewall_acl": []},
    }


def range_assess(**overrides):
    values = {
        "source_text": "Internet",
        "destination_text": "10.0.0.0/8",
        "protocol": "tcp",
        "port": 22,
        "hunting": {"hosts": [], "findings": []},
        "saved_networks": [],
        "device_analyses": [range_device()],
    }
    values.update(overrides)
    return evaluate_reachability_range(**values)


def test_range_coverage_uses_connected_networks_not_static_routes_to_create_targets():
    result = range_assess(device_analyses=[range_device(extra_routes=[{
        "network": "10.30.0.0/16", "via": "198.51.100.2", "protocol": "static",
    }])])

    assert result["status"] == "reachability_range_analysis_complete"
    assert result["grouping_prefix"] == 16
    assert [item["network"] for item in result["candidates"]] == ["10.20.0.0/16"]
    assert result["candidates"][0]["evidence_counts"]["interface"] == 1
    assert result["evidence_counts"]["interface"] == 1
    assert result["evidence_counts"]["connected_route"] == 1
    assert all(item["network"] != "10.30.0.0/16" for item in result["candidates"])


def test_range_coverage_drills_from_a_16_to_only_identified_24s():
    device = range_device(connected="10.20.1.0/24", extra_routes=[{
        "network": "10.20.3.0/24", "via": "198.51.100.2", "protocol": "static",
    }])
    hunting = {
        "hosts": [{"ip": "10.20.2.5", "hostname": "observed-host"}],
        "findings": [],
    }
    result = range_assess(
        destination_text="10.20.0.0/16", hunting=hunting, device_analyses=[device]
    )

    assert result["grouping_prefix"] == 24
    assert [item["network"] for item in result["candidates"]] == [
        "10.20.1.0/24", "10.20.2.0/24",
    ]
    assert result["candidates"][0]["outcome"] == "Routed"
    assert result["candidates"][0]["drill_down"] is True
    assert result["candidates"][0]["detail_target"] == "10.20.1.0/24"
    assert result["candidates"][1]["outcome"] == "Mixed"
    assert result["candidates"][1]["evidence_counts"]["observed_host"] == 1


def test_range_coverage_allows_a_uniform_24_to_open_observed_hosts():
    hunting = {
        "hosts": [{"ip": "10.20.4.9", "hostname": "observed-host"}],
        "findings": [],
    }
    parent = range_assess(
        destination_text="10.20.4.0/24",
        hunting=hunting,
        device_analyses=[range_device(connected="10.20.4.0/24")],
    )

    row = parent["candidates"][0]
    assert row["network"] == "10.20.4.9/32"
    assert row["drill_down"] is False


def test_range_coverage_applies_uniform_ssh_block_to_connected_segment():
    policy = parse_iptables_policy("""*filter
:FORWARD ACCEPT [0:0]
-A FORWARD -i outside -o inside -p tcp -d 10.20.0.0/16 --dport 22 -j DROP
COMMIT
""")
    result = range_assess(device_analyses=[range_device(policy={
        "firewall_acl": [], "iptables": policy,
    })])

    assert result["candidate_count"] == 1
    assert result["candidates"][0]["outcome"] == "Expected Blocked"
    assert result["candidates"][0]["policy_boundary_count"] == 1


def test_range_coverage_marks_more_specific_policy_difference_for_drilldown():
    policy = parse_iptables_policy("""*filter
:FORWARD ACCEPT [0:0]
-A FORWARD -i outside -o inside -p tcp -d 10.20.8.0/24 --dport 22 -j DROP
COMMIT
""")
    result = range_assess(device_analyses=[range_device(policy={
        "firewall_acl": [], "iptables": policy,
    })])

    row = result["candidates"][0]
    assert row["outcome"] == "Mixed"
    assert row["drill_down"] is True
    assert row["detail_target"] == "10.20.0.0/16"
    assert row["policy_boundary_count"] == 1


@pytest.mark.parametrize(
    "vendor,policy",
    [
        (
            "cisco",
            {"firewall_acl": [], "applied": parse_vendor_policy("""access-list OUTSIDE_IN extended permit tcp host 203.0.113.5 host 10.90.0.10 eq 443
access-group OUTSIDE_IN in interface outside
""")},
        ),
        (
            "vyos",
            {"firewall_acl": [], "applied": parse_vendor_policy("""set firewall ipv4 forward filter rule 10 action 'accept'
set firewall ipv4 forward filter rule 10 inbound-interface name 'outside'
set firewall ipv4 forward filter rule 10 outbound-interface name 'servers'
set firewall ipv4 forward filter rule 10 protocol 'tcp'
set firewall ipv4 forward filter rule 10 source address '203.0.113.5/32'
set firewall ipv4 forward filter rule 10 destination address '10.90.0.10/32'
set firewall ipv4 forward filter rule 10 destination port '443'
set firewall ipv4 forward filter default-action 'drop'
""")},
        ),
        (
            "pfsense",
            {"firewall_acl": [], "applied": parse_vendor_policy(
                "pass in quick on outside inet proto tcp from 203.0.113.5 to 10.90.0.10 port = 443"
            )},
        ),
        (
            "unifi",
            {"firewall_acl": [], "iptables": parse_iptables_policy("""*filter
:FORWARD DROP [0:0]
-A FORWARD -i outside -o servers -p tcp -s 203.0.113.5/32 -d 10.90.0.10/32 --dport 443 -j ACCEPT
COMMIT
""")},
        ),
    ],
)
def test_exact_external_source_matches_wan_policy_for_current_vendors(vendor, policy):
    device = {
        **DEVICE,
        "device": {"name": f"{vendor} edge", "address": "10.80.0.1", "type": "firewall"},
        "interfaces": [
            {"name": "outside", "network": "198.51.100.0/24", "role": "external"},
            {"name": "servers", "network": "10.90.0.0/24", "role": "internal"},
        ],
        "route_analysis": {"routes": [
            {"network": "10.90.0.0/24", "interface": "servers", "direct": True},
        ]},
        "policy": policy,
    }

    result = assess(
        source_text="203.0.113.5", source_external=True,
        device_analyses=[device],
    )

    assert result["outcome"] == "Expected Allowed"
    assert result["query"]["source_external"] is True
    assert result["path"][0]["detail"] == "External address / range"
    assert any("analyst-supplied" in item for item in result["caveats"])


def test_external_cidr_preserves_range_for_exact_policy_matching():
    endpoint = parse_endpoint("203.0.113.0/24", external=True)

    assert endpoint.kind == "network"
    assert endpoint.external is True
    assert str(endpoint.value) == "203.0.113.0/24"


def test_proposed_exact_deny_compares_against_current_permit_without_device_changes():
    result = simulate_proposed_policy_control(
        source_text="10.80.0.25", destination_text="10.90.0.10",
        protocol="tcp", port=443, hunting=HUNTING,
        saved_networks=SAVED, device_analyses=[DEVICE],
        action="deny", device_key="10.80.0.1",
    )

    assert result["status"] == "reachability_policy_simulation_complete"
    assert result["comparison"]["before"] == "Expected Allowed"
    assert result["comparison"]["after"] == "Expected Blocked"
    assert result["comparison"]["outcome_changed"] is True
    assert result["comparison"]["scope"] == {
        "source_addresses": 1,
        "destination_addresses": 1,
        "address_pairs": 1,
        "protocol": "tcp",
        "port": 443,
    }
    assert result["comparison"]["path_changed"] is False
    assert result["comparison"]["collateral_impact"]["address_pairs"] == 1
    assert result["comparison"]["collateral_impact"]["evaluated_flows"] == 1
    assert result["projected"]["simulated"] is True
    assert result["projected"]["retained_objects"]["policy"][0]["simulated"] is True
    assert "changes no device configuration" in result["disclaimer"]


def test_proposed_permit_replaces_selected_device_deny_in_projection():
    policy = parse_iptables_policy("""*filter
:FORWARD DROP [0:0]
-A FORWARD -i inside -o servers -p tcp -s 10.80.0.0/24 -d 10.90.0.10/32 --dport 443 -j DROP
COMMIT
""")
    device = {
        **DEVICE,
        "interfaces": [
            {"name": "inside", "network": "10.80.0.0/24", "role": "internal"},
            {"name": "servers", "network": "10.90.0.0/24", "role": "internal"},
        ],
        "policy": {"firewall_acl": [], "iptables": policy},
    }

    result = simulate_proposed_policy_control(
        source_text="10.80.0.25", destination_text="10.90.0.10",
        protocol="tcp", port=443, hunting=HUNTING,
        saved_networks=SAVED, device_analyses=[device],
        action="permit", device_key="Edge Firewall",
    )

    assert result["comparison"]["before"] == "Expected Blocked"
    assert result["comparison"]["after"] == "Expected Allowed"
    assert result["projected"]["confidence"] == "medium"
    proposal = next(item for item in result["projected"]["evidence"] if item["kind"] == "proposal")
    assert proposal["title"] == "Proposed permit on Edge Firewall"


def test_proposed_control_stays_unknown_when_selected_device_is_not_source_attached():
    detached = {
        **DEVICE,
        "device": {"name": "Detached Edge", "address": "10.70.0.1", "type": "firewall"},
        "interfaces": [{"name": "other", "network": "10.70.0.0/24", "role": "internal"}],
        "policy": {"firewall_acl": []},
    }

    result = simulate_proposed_policy_control(
        source_text="10.80.0.25", destination_text="10.90.0.10",
        protocol="tcp", port=443, hunting=HUNTING,
        saved_networks=SAVED, device_analyses=[detached],
        action="deny", device_key="10.70.0.1",
    )

    assert result["comparison"]["source_attached"] is False
    assert result["projected"]["outcome"] == "Unknown"
    assert "not attached" in result["projected"]["explanation"]


def test_proposed_cidr_control_reports_address_pair_scope():
    result = simulate_proposed_policy_control(
        source_text="10.80.0.0/24", destination_text="10.90.0.0/24",
        protocol="tcp", port=443, hunting={"hosts": [], "findings": []},
        saved_networks=SAVED, device_analyses=[DEVICE],
        action="deny", device_key="10.80.0.1",
    )

    assert result["comparison"]["scope"]["source_addresses"] == 256
    assert result["comparison"]["scope"]["destination_addresses"] == 256
    assert result["comparison"]["scope"]["address_pairs"] == 65536


@pytest.mark.parametrize("vendor", ["cisco", "vyos", "pfsense", "juniper", "unifi"])
def test_vendor_policy_templates_parse_and_validate_on_selected_interface(vendor):
    device = {
        **DEVICE,
        "device": {**DEVICE["device"], "vendor": vendor},
        "interfaces": [
            {"name": "inside", "network": "10.80.0.0/24", "role": "internal"},
            {"name": "servers", "network": "10.90.0.0/24", "role": "internal"},
        ],
        "route_analysis": {"routes": [{
            "network": "10.90.0.0/24", "interface": "servers", "direct": True,
        }]},
        "policy": {"firewall_acl": []},
    }

    template = build_vendor_policy_rule(
        analysis=device,
        source_text="10.80.0.25",
        destination_text="10.90.0.10",
        protocol="tcp",
        port=443,
        action="permit",
        interface_name="inside",
        insertion_index=0,
    )
    validation = validate_vendor_policy_rule(
        analysis=device,
        rule_text=template["rule_text"],
        source_text="10.80.0.25",
        destination_text="10.90.0.10",
        protocol="tcp",
        port=443,
        action="permit",
        interface_name="inside",
    )

    assert template["vendor"] == vendor
    assert template["interface"] == "inside"
    assert validation["valid"] is True
    assert validation["verdict"] == "allow"


def test_policy_context_preserves_rule_order_and_offers_vendor_templates():
    applied = parse_vendor_policy("""ip access-list extended USERS
 10 deny tcp host 10.80.0.25 host 10.90.0.20 eq 443
 20 permit tcp host 10.80.0.25 host 10.90.0.10 eq 443
!
interface inside
 ip access-group USERS in
""")
    context = policy_rule_context({
        **DEVICE,
        "device": {**DEVICE["device"], "vendor": "cisco"},
        "policy": {"firewall_acl": [], "applied": applied},
    })

    assert [item["position"] for item in context["rules"]] == [1, 2]
    assert [item["order"] for item in context["rules"]] == [10, 20]
    assert [item["action"] for item in context["rules"]] == ["deny", "permit"]
    assert context["rules"][0]["interface"] == "inside"
    assert context["positions"][-1]["index"] == 2
    assert {item["id"] for item in context["templates"]} == {
        "exact-service", "interface-service",
    }


def test_proposed_rule_after_existing_match_is_valid_but_does_not_override_it():
    result = simulate_proposed_policy_control(
        source_text="10.80.0.25", destination_text="10.90.0.10",
        protocol="tcp", port=443, hunting=HUNTING,
        saved_networks=SAVED, device_analyses=[DEVICE],
        action="deny", device_key="10.80.0.1",
        interface_name="inside", insertion_index=1,
    )

    assert result["proposal"]["validation"]["valid"] is True
    assert result["comparison"]["proposal_effective"] is False
    assert result["comparison"]["before"] == "Expected Allowed"
    assert result["comparison"]["after"] == "Expected Allowed"
    assert "already decides this flow" in result["projected"]["explanation"]


def test_proposed_route_addition_is_read_only_and_uses_a_retained_interface():
    device = {**DEVICE, "route_analysis": {"routes": []}}

    result = simulate_proposed_route_control(
        source_text="10.80.0.25", destination_text="10.90.0.10",
        protocol="tcp", port=443, hunting=HUNTING,
        saved_networks=SAVED, device_analyses=[device],
        action="add", device_key="10.80.0.1",
        route_network="10.90.0.0/24", route_interface="inside",
        next_hop="10.80.0.2",
    )

    assert result["status"] == "reachability_route_simulation_complete"
    assert result["proposal"] == {
        "action": "add",
        "device": "Edge Firewall",
        "device_address": "10.80.0.1",
        "network": "10.90.0.0/24",
        "interface": "inside",
        "next_hop": "10.80.0.2",
        "changed_route_count": 1,
        "priority_kind": None,
        "priority_value": None,
    }
    assert result["comparison"]["baseline_route_count"] == 0
    assert result["comparison"]["projected_route_count"] == 1
    assert result["comparison"]["network_addresses"] == 256
    assert result["projected"]["simulated"] is True
    assert any(item["kind"] == "proposal" for item in result["projected"]["evidence"])
    assert "changes no device configuration" in result["disclaimer"]


def test_proposed_route_removal_preserves_a_broader_retained_fallback():
    device = {
        **DEVICE,
        "route_analysis": {"routes": [
            *DEVICE["route_analysis"]["routes"],
            {"network": "0.0.0.0/0", "interface": "inside", "via": "10.80.0.254"},
        ]},
    }

    result = simulate_proposed_route_control(
        source_text="10.80.0.25", destination_text="10.90.0.10",
        protocol="tcp", port=443, hunting=HUNTING,
        saved_networks=SAVED, device_analyses=[device],
        action="remove", device_key="Edge Firewall",
        route_network="10.90.0.0/24",
    )

    assert result["proposal"]["changed_route_count"] == 1
    assert result["comparison"]["baseline_route_count"] == 2
    assert result["comparison"]["projected_route_count"] == 1
    projected_routes = result["projected"]["retained_objects"]["routes"]
    assert [item["network"] for item in projected_routes] == ["0.0.0.0/0"]
    assert any("dynamic convergence" in item for item in result["projected"]["caveats"])


def test_proposed_route_requires_destination_coverage_and_exact_remove_match():
    values = {
        "source_text": "10.80.0.25", "destination_text": "10.90.0.10",
        "protocol": "tcp", "port": 443, "hunting": HUNTING,
        "saved_networks": SAVED, "device_analyses": [DEVICE],
        "device_key": "10.80.0.1",
    }
    with pytest.raises(ValueError, match="does not cover"):
        simulate_proposed_route_control(
            **values, action="add", route_network="192.0.2.0/24",
            route_interface="inside",
        )
    with pytest.raises(ValueError, match="no retained route"):
        simulate_proposed_route_control(
            **values, action="remove", route_network="10.90.0.10/32",
        )


@pytest.mark.parametrize("priority_kind", ["metric", "preference"])
def test_proposed_route_priority_change_can_change_selected_equal_prefix_path(priority_kind):
    first = {
        "network": "10.90.0.0/24", "via": "10.80.0.2",
        "interface": "inside", "line": "route path-a metric 100",
        priority_kind: 100,
    }
    second = {
        "network": "10.90.0.0/24", "via": "10.80.0.3",
        "interface": "inside", "line": "route path-b metric 200",
        priority_kind: 200,
    }
    device = {**DEVICE, "route_analysis": {"routes": [first, second]}}

    result = simulate_proposed_route_control(
        source_text="10.80.0.25", destination_text="10.90.0.10",
        protocol="tcp", port=443, hunting=HUNTING,
        saved_networks=SAVED, device_analyses=[device],
        action="set_priority", device_key="10.80.0.1",
        route_network="10.90.0.0/24", route_interface="inside",
        next_hop="10.80.0.2", priority_kind=priority_kind,
        priority_value=300,
    )

    comparison = result["comparison"]
    assert comparison["path_changed"] is True
    assert comparison["selected_route_before"]["via"] == "10.80.0.2"
    assert comparison["selected_route_after"]["via"] == "10.80.0.3"
    assert comparison["selected_route_before"][priority_kind] == 100
    assert comparison["selected_route_after"][priority_kind] == 200
    assert len(comparison["alternate_routes_before"]) == 1
    assert len(comparison["alternate_routes_after"]) == 1
    assert comparison["collateral_impact"]["destination_addresses"] == 256
    assert comparison["collateral_impact"]["evaluated_flows"] == 1
    assert result["proposal"]["priority_kind"] == priority_kind
    assert result["proposal"]["priority_value"] == 300


def test_equal_prefix_routes_without_comparable_priority_remain_explicitly_unresolved():
    device = {
        **DEVICE,
        "route_analysis": {"routes": [
            {"network": "10.90.0.0/24", "via": "10.80.0.2", "interface": "inside"},
            {"network": "10.90.0.0/24", "via": "10.80.0.3", "interface": "inside", "metric": 20},
        ]},
    }

    result = assess(device_analyses=[device])

    assert result["retained_objects"]["routes"][0]["priority_comparable"] is False
    assert any("cannot establish the active path" in item for item in result["caveats"])


def test_explicit_acl_and_service_evidence_support_expected_allowed():
    result = assess()
    assert result["outcome"] == "Expected Allowed"
    assert result["confidence"] == "high"
    assert result["service_observation"] == "observed_exposed"
    assert result["counts"]["routes"] == 1
    assert {item["kind"] for item in result["evidence"]} >= {"route", "policy", "service"}
    route = next(item for item in result["evidence"] if item["kind"] == "route")
    policy = next(item for item in result["evidence"] if item["kind"] == "policy")
    assert "does not by itself allow or block TCP/443" in route["effect"]
    assert policy["effect"] == (
        "This retained ACL entry is expected to allow "
        "10.80.0.25 → 10.90.0.10 TCP/443."
    )
    assert policy["source_url"] == f"/device-analysis?run={'a' * 32}&focus=policy"


def test_same_saved_network_is_local_without_claiming_policy_decision():
    result = assess(
        source_text="10.80.0.25",
        destination_text="10.80.0.50",
        device_analyses=[],
        hunting={"hosts": [], "findings": []},
    )
    assert result["outcome"] == "Local"
    assert result["confidence"] == "medium"


def test_partial_route_without_exact_policy_is_unknown():
    device = {**DEVICE, "policy": {"firewall_acl": []}}
    result = assess(device_analyses=[device])
    assert result["outcome"] == "Unknown"
    assert result["confidence"] == "low"


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


def test_exact_host_port_coverage_supports_not_exposed():
    hunting = covered_hunting()
    hunting["hosts"][0]["scan_coverages"][0]["source_refs"] = [{
        "url": f"/api/scan-runs/{'b' * 32}/artifacts/xml",
    }]
    result = assess(port=22, device_analyses=[], hunting=hunting)

    assert result["outcome"] == "Not Exposed"
    assert result["confidence"] == "high"
    assert result["service_observation"] == "not_exposed"
    assert result["counts"]["coverage_proofs"] == 1
    coverage = next(item for item in result["evidence"] if item["kind"] == "coverage")
    assert coverage["title"] == "TCP/22 assessed — not exposed"
    assert "did not observe an exposed service from the NCT host" in coverage["effect"]
    assert coverage["source_url"] == (
        f"/analysis?run={'b' * 32}&focus=host&host=10.90.0.10&protocol=tcp&port=22"
    )
    assert "NCT host at scan time" in " ".join(result["caveats"])


def test_uncovered_port_and_non_service_scan_do_not_support_not_exposed():
    uncovered = assess(port=2049, device_analyses=[], hunting=covered_hunting())
    ack_only = assess(
        port=22,
        device_analyses=[],
        hunting=covered_hunting(scan_type="ack"),
    )

    assert uncovered["outcome"] == "Unknown"
    assert uncovered["service_observation"] == "not_observed"
    assert ack_only["outcome"] == "Unknown"
    assert ack_only["service_observation"] == "not_observed"


def test_open_filtered_observation_does_not_support_not_exposed():
    hunting = covered_hunting(observed_ports=[{
        "protocol": "tcp", "port": 22, "state": "open|filtered",
    }])

    result = assess(port=22, device_analyses=[], hunting=hunting)

    assert result["outcome"] == "Unknown"
    assert result["service_observation"] == "observed_inconclusive"
    assert any("open|filtered" in item for item in result["caveats"])

    result = assess(
        port=22,
        device_analyses=[],
        hunting={
            **covered_hunting(),
            "findings": [{
                "ip": "10.90.0.10", "protocol": "tcp", "port": 22,
                "state": "open|filtered", "service": "unknown",
            }],
        },
    )
    assert result["outcome"] == "Unknown"
    assert result["service_observation"] == "observed_inconclusive"


def test_explicit_deny_remains_expected_blocked_when_service_is_not_exposed():
    device = {
        **DEVICE,
        "policy": {"firewall_acl": [{
            "evidence": "access-list 101 deny tcp any host 10.90.0.10 eq 22"
        }]},
    }

    result = assess(port=22, device_analyses=[device], hunting=covered_hunting())

    assert result["outcome"] == "Expected Blocked"
    assert result["service_observation"] == "not_exposed"
    assert {item["kind"] for item in result["evidence"]} >= {"policy", "coverage"}
    policy = next(item for item in result["evidence"] if item["kind"] == "policy")
    assert policy["action"] == "deny"
    assert policy["effect"] == (
        "This retained ACL entry is expected to block "
        "10.80.0.25 → 10.90.0.10 TCP/22."
    )


def test_external_destination_with_unresolved_next_hop_is_unknown():
    device = {
        **DEVICE,
        "route_analysis": {"routes": [{"network": "0.0.0.0/0", "via": "192.0.2.1"}]},
        "policy": {"firewall_acl": []},
    }
    result = assess(destination_text="Internet", device_analyses=[device])
    assert result["outcome"] == "Unknown"
    assert any("Path is partial" in item for item in result["caveats"])


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


def test_established_flow_state_is_evaluated_and_reported():
    policy = parse_iptables_policy("""*filter
:FORWARD DROP [0:0]
-A FORWARD -i servers -o inside -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
-A FORWARD -i servers -o inside -m conntrack --ctstate NEW -j DROP
COMMIT
""")
    device = {
        **DEVICE,
        "interfaces": [
            {"name": "inside", "network": "10.80.0.0/24", "role": "internal"},
            {"name": "servers", "network": "10.90.0.0/24", "role": "internal"},
        ],
        "route_analysis": {"routes": [{
            "network": "10.80.0.0/24", "interface": "inside", "direct": True,
        }]},
        "policy": {"firewall_acl": [], "iptables": policy},
    }

    result = assess(
        source_text="10.90.0.10", destination_text="10.80.0.25",
        device_analyses=[device], flow_state="established",
        hunting={"hosts": [], "findings": []},
    )

    assert result["outcome"] == "Expected Allowed"
    assert result["query"]["flow_state"] == "established"
    assert "established or related flow" in result["explanation"]
    assert any("does not prove" in caveat for caveat in result["caveats"])


def test_ordered_iptables_unsupported_match_with_partial_path_remains_unknown():
    policy = parse_iptables_policy("""*filter
:FORWARD ACCEPT [0:0]
-A FORWARD -m dpi32 --cat-app 4,112 -j DROP
COMMIT
""")
    device = {**DEVICE, "policy": {"firewall_acl": [], "iptables": policy}}

    result = assess(device_analyses=[device])

    assert result["outcome"] == "Unknown"
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
    route_evidence = [item for item in result["evidence"] if item["kind"] == "route"]
    assert not any("127.0.0.1" in str(item.get("detail")) for item in route_evidence)
    assert any(item["title"].startswith("Fallback route — not selected") for item in route_evidence)
    assert any(item.get("route_role") == "selected" for item in route_evidence)
    assert any(item.get("route_role") == "fallback" for item in route_evidence)


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


def test_applied_vyos_destination_nat_drives_effective_target():
    applied = parse_vendor_policy("""set nat destination rule 10 inbound-interface name 'outside'
set nat destination rule 10 protocol 'tcp'
set nat destination rule 10 destination address '198.51.100.10'
set nat destination rule 10 destination port '8443'
set nat destination rule 10 translation address '10.90.0.10'
set nat destination rule 10 translation port '443'
set firewall ipv4 forward filter rule 10 action 'accept'
set firewall ipv4 forward filter rule 10 inbound-interface name 'outside'
set firewall ipv4 forward filter rule 10 outbound-interface name 'servers'
set firewall ipv4 forward filter rule 10 protocol 'tcp'
set firewall ipv4 forward filter rule 10 destination address '10.90.0.10/32'
set firewall ipv4 forward filter rule 10 destination port '443'
set firewall ipv4 forward filter default-action 'drop'
""")
    device = {
        **DEVICE,
        "interfaces": [
            {"name": "outside", "network": "198.51.100.0/24", "role": "external"},
            {"name": "servers", "network": "10.90.0.0/24", "role": "internal"},
        ],
        "route_analysis": {"routes": [
            {"network": "0.0.0.0/0", "interface": "outside"},
            {"network": "10.90.0.0/24", "interface": "servers", "direct": True},
        ]},
        "policy": {"firewall_acl": [], "applied": applied},
    }

    result = assess(
        source_text="Internet", destination_text="198.51.100.10", port=8443,
        device_analyses=[device],
    )

    assert result["outcome"] == "Expected Allowed"
    assert result["query"]["effective_destination"] == "10.90.0.10"
    assert result["query"]["effective_port"] == 443
    assert result["counts"]["destination_nat_translations"] == 1
    assert result["retained_objects"]["nat"][0]["engine"] == "applied vyos"


def test_sequential_destination_nat_is_carried_across_two_devices():
    edge = {
        "run_id": "e" * 32,
        "device": {"name": "Edge NAT", "address": "172.16.0.1", "type": "firewall"},
        "interfaces": [
            {"name": "outside", "network": "198.51.100.0/24", "role": "external"},
            {"name": "transit", "network": "172.16.0.0/24", "role": "internal"},
        ],
        "route_analysis": {"routes": [{"network": "10.90.0.0/24", "interface": "transit"}]},
        "policy": {"firewall_acl": [], "applied": parse_vendor_policy("""set nat destination rule 10 inbound-interface name 'outside'
set nat destination rule 10 protocol 'tcp'
set nat destination rule 10 destination address '198.51.100.10'
set nat destination rule 10 destination port '8443'
set nat destination rule 10 translation address '172.16.0.10'
set nat destination rule 10 translation port '8443'
""")},
    }
    inner = {
        "run_id": "i" * 32,
        "device": {"name": "Inner NAT", "address": "172.16.0.2", "type": "firewall"},
        "interfaces": [
            {"name": "transit", "network": "172.16.0.0/24", "role": "external"},
            {"name": "servers", "network": "10.90.0.0/24", "role": "internal"},
        ],
        "route_analysis": {"routes": [{"network": "10.90.0.0/24", "interface": "servers", "direct": True}]},
        "policy": {"firewall_acl": [], "applied": parse_vendor_policy("""set nat destination rule 20 inbound-interface name 'transit'
set nat destination rule 20 protocol 'tcp'
set nat destination rule 20 destination address '172.16.0.10'
set nat destination rule 20 destination port '8443'
set nat destination rule 20 translation address '10.90.0.10'
set nat destination rule 20 translation port '443'
""")},
    }

    result = assess(
        source_text="Internet", destination_text="198.51.100.10", port=8443,
        device_analyses=[edge, inner],
    )

    assert result["query"]["effective_destination"] == "10.90.0.10"
    assert result["query"]["effective_port"] == 443
    assert result["counts"]["destination_nat_translations"] == 2
    assert [item["device"] for item in result["retained_objects"]["nat"]] == [
        "Edge NAT", "Inner NAT",
    ]
    nat_path = [item for item in result["path"] if item["kind"] == "nat"]
    assert [item["label"] for item in nat_path] == [
        "DNAT on Edge NAT", "DNAT on Inner NAT",
    ]


def test_sequential_source_nat_is_carried_across_two_devices():
    inner = {
        "run_id": "i" * 32,
        "device": {"name": "Inner NAT", "address": "10.80.0.1", "type": "router"},
        "interfaces": [
            {"name": "users", "network": "10.80.0.0/24", "role": "internal"},
            {"name": "transit", "network": "172.16.0.0/24", "role": "external"},
        ],
        "route_analysis": {"routes": [{"network": "0.0.0.0/0", "interface": "transit"}]},
        "policy": {"firewall_acl": [], "applied": parse_vendor_policy("""set nat source rule 10 outbound-interface name 'transit'
set nat source rule 10 source address '10.80.0.0/24'
set nat source rule 10 translation address '172.16.0.2'
""")},
    }
    edge = {
        "run_id": "e" * 32,
        "device": {"name": "Edge NAT", "address": "172.16.0.1", "type": "firewall"},
        "interfaces": [
            {"name": "transit", "network": "172.16.0.0/24", "role": "internal"},
            {"name": "outside", "address": "198.51.100.2/24", "network": "198.51.100.0/24", "role": "external"},
        ],
        "route_analysis": {"routes": [{"network": "0.0.0.0/0", "interface": "outside"}]},
        "policy": {"firewall_acl": [], "applied": parse_vendor_policy("""set nat source rule 20 outbound-interface name 'outside'
set nat source rule 20 source address '172.16.0.2/32'
set nat source rule 20 translation address '198.51.100.2'
""")},
    }

    result = assess(
        destination_text="Internet", device_analyses=[inner, edge],
        hunting={"hosts": [], "findings": []},
    )

    assert result["query"]["effective_source"] == "198.51.100.2"
    assert result["counts"]["source_nat_translations"] == 2
    assert [item["device"] for item in result["retained_objects"]["nat"]] == [
        "Inner NAT", "Edge NAT",
    ]
    assert [item["detail"] for item in result["path"] if item["kind"] == "nat"] == [
        "10.80.0.25 → 172.16.0.2",
        "172.16.0.2 → 198.51.100.2",
    ]


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
    assert result["outcome"] == "Unknown"


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
    analyzed = []

    def analyze(run_id):
        analyzed.append(run_id)
        return {"run_id": run_id}

    monkeypatch.setattr(main, "analyze_device_collection", analyze)
    monkeypatch.setattr(main, "_DEVICE_EVIDENCE_CACHE_KEY", None)
    monkeypatch.setattr(main, "_DEVICE_EVIDENCE_CACHE_VALUE", [])

    monkeypatch.setattr(main, "get_external_wan_gateways", lambda db_path: [])
    result = main._latest_device_reachability_evidence()
    cached = main._latest_device_reachability_evidence()

    assert result == [{"run_id": "usable"}, {"run_id": "upload"}]
    assert cached is result
    assert analyzed == ["usable", "upload"]


def test_reach_follows_each_retained_next_hop_without_inventing_devices():
    edge = {
        "run_id": "edge",
        "device": {"name": "edge-wan-rtr", "address": "10.0.0.1", "type": "router"},
        "interfaces": [
            {"name": "outside", "network": "198.51.100.0/24", "role": "external"},
            {"name": "transit", "network": "10.0.12.0/30", "address": "10.0.12.1"},
        ],
        "external_wan_gateway": {"node_id": "ip:10.0.0.1"},
        "route_analysis": {"routes": [{
            "network": "10.90.0.0/24", "via": "10.0.12.2", "interface": "transit",
            "line": "ip route 10.90.0.0 255.255.255.0 10.0.12.2",
        }]},
        "policy": {"firewall_acl": []},
    }
    distribution = {
        "run_id": "distribution",
        "device": {"name": "distribution-rtr", "address": "10.0.12.2", "type": "router"},
        "interfaces": [
            {"name": "uplink", "network": "10.0.12.0/30", "address": "10.0.12.2"},
            {"name": "servers", "network": "10.90.0.0/24", "address": "10.90.0.1"},
        ],
        "route_analysis": {"routes": [{
            "network": "10.90.0.0/24", "interface": "servers", "direct": True,
            "line": "C 10.90.0.0/24 is directly connected",
        }]},
        "policy": {"firewall_acl": []},
    }

    result = assess(
        source_text="Internet",
        device_analyses=[edge, distribution],
    )

    assert [item["device"] for item in result["retained_objects"]["selected_path_routes"]] == [
        "edge-wan-rtr", "distribution-rtr",
    ]
    assert [item["label"] for item in result["path"] if item["kind"] == "device"] == [
        "edge-wan-rtr", "distribution-rtr",
    ]
    assert result["outcome"] == "Routed"
    assert not any("Path is partial" in item for item in result["caveats"])


def test_external_reach_does_not_guess_between_multiple_site_edges():
    mako = {
        "run_id": "mako",
        "device": {
            "name": "MAKO-ENG-EDGE-RTR", "address": "175.0.92.22", "type": "router",
        },
        "interfaces": [{"name": "uplink", "network": "175.0.92.20/30"}],
        "route_analysis": {"routes": [
            {"network": "33.107.4.0/24", "via": "175.0.92.21"},
            {"network": "0.0.0.0/0", "via": "175.0.92.21", "interface": "uplink"},
        ]},
        "policy": {"firewall_acl": []},
    }
    other_site = {
        "run_id": "other",
        "device": {"name": "NY-FW", "address": "125.64.15.50", "type": "firewall"},
        "interfaces": [{"name": "outside", "network": "125.64.15.48/30"}],
        "route_analysis": {"routes": [
            {"network": "0.0.0.0/0", "via": "125.64.15.49", "interface": "outside"},
        ]},
        "policy": {"firewall_acl": []},
    }

    result = assess(
        source_text="Internet", destination_text="33.107.4.2",
        device_analyses=[mako, other_site],
    )

    assert result["outcome"] == "Unknown"
    assert result["retained_objects"]["routes"] == []
    assert result["retained_objects"]["selected_path_routes"] == []
    assert "MAKO-ENG-EDGE-RTR" not in [
        item["label"] for item in result["path"] if item["kind"] == "device"
    ]
    assert any("External WAN gateway" in item for item in result["caveats"])


def test_external_reach_starts_only_at_designated_wan_gateway():
    mako = {
        "run_id": "mako",
        "device": {
            "name": "MAKO-ENG-EDGE-RTR", "address": "175.0.92.22", "type": "router",
        },
        "interfaces": [{"name": "uplink", "network": "175.0.92.20/30"}],
        "route_analysis": {"routes": [
            {"network": "33.107.4.0/24", "via": "175.0.92.21"},
            {"network": "0.0.0.0/0", "via": "175.0.92.21", "interface": "uplink"},
        ]},
        "policy": {"firewall_acl": []},
    }
    afb_gateway = {
        "run_id": "na",
        "device": {"name": "NA-RTR", "address": "97.98.208.2", "type": "router"},
        "external_wan_gateway": {"node_id": "ip:97.98.208.2"},
        "interfaces": [
            {"name": "wan", "network": "97.98.208.0/30", "role": "external"},
            {"name": "afb", "network": "33.107.244.0/30"},
        ],
        "route_analysis": {"routes": [
            {"network": "33.107.4.0/24", "via": "33.107.244.1", "interface": "afb"},
        ]},
        "policy": {"firewall_acl": []},
    }
    afb_edge = {
        "run_id": "afb",
        "device": {"name": "AFB-EDGE-RTR", "address": "33.107.244.1", "type": "router"},
        "interfaces": [
            {"name": "upstream", "network": "33.107.244.0/30", "address": "33.107.244.1"},
            {"name": "inside", "network": "33.107.4.0/24"},
        ],
        "route_analysis": {"routes": [
            {"network": "33.107.4.0/24", "interface": "inside", "direct": True},
        ]},
        "policy": {"firewall_acl": []},
    }

    result = assess(
        source_text="Internet", destination_text="33.107.4.2",
        device_analyses=[mako, afb_gateway, afb_edge],
    )

    devices = [item["label"] for item in result["path"] if item["kind"] == "device"]
    assert devices == ["NA-RTR", "AFB-EDGE-RTR"]
    assert "MAKO-ENG-EDGE-RTR" not in devices


def test_external_reach_uses_a_single_internet_labeled_interface():
    na_gateway = {
        "run_id": "na",
        "device": {"name": "NA-RTR", "address": "97.98.208.2", "type": "router"},
        "interfaces": [
            {
                "name": "eth0", "network": "97.98.208.0/30",
                "zone": "Inet to NA rtr",
            },
            {"name": "eth1", "network": "33.107.244.0/30"},
        ],
        "route_analysis": {"routes": [{
            "network": "33.107.4.0/24", "via": "33.107.244.1", "interface": "eth1",
        }]},
        "policy": {"firewall_acl": []},
    }
    mako = {
        "run_id": "mako",
        "device": {
            "name": "MAKO-ENG-EDGE-RTR", "address": "175.0.92.22", "type": "router",
        },
        "interfaces": [{"name": "uplink", "network": "175.0.92.20/30"}],
        "route_analysis": {"routes": [
            {"network": "33.107.4.0/24", "via": "175.0.92.21"},
            {"network": "0.0.0.0/0", "via": "175.0.92.21", "interface": "uplink"},
        ]},
        "policy": {"firewall_acl": []},
    }

    result = assess(
        source_text="Internet", destination_text="33.107.4.2",
        device_analyses=[mako, na_gateway],
    )

    devices = [item["label"] for item in result["path"] if item["kind"] == "device"]
    assert devices == ["NA-RTR"]
    assert "MAKO-ENG-EDGE-RTR" not in devices


def test_reach_uses_a_matching_route_after_the_legacy_500_route_boundary():
    filler_routes = [
        {
            "network": f"172.{index // 256}.{index % 256}.0/24",
            "via": "10.80.0.2",
            "interface": "inside",
            "protocol": "static",
        }
        for index in range(500)
    ]
    matching_route = {
        "network": "10.90.0.0/24",
        "via": "10.80.0.2",
        "interface": "inside",
        "protocol": "static",
        "line": "ip route 10.90.0.0 255.255.255.0 10.80.0.2",
    }
    device = {
        **DEVICE,
        "route_analysis": {"routes": [*filler_routes, matching_route]},
    }

    result = assess(device_analyses=[device])

    assert result["outcome"] == "Expected Allowed"
    assert result["retained_objects"]["routes"][0]["network"] == "10.90.0.0/24"


def test_reach_reports_a_partial_path_when_next_hop_evidence_is_missing():
    edge = {
        **DEVICE,
        "device": {"name": "edge-wan-rtr", "address": "10.0.0.1", "type": "router"},
        "interfaces": [{"name": "outside", "network": "198.51.100.0/24", "role": "external"}],
        "external_wan_gateway": {"node_id": "ip:10.0.0.1"},
        "policy": {"firewall_acl": []},
    }

    result = assess(source_text="Internet", device_analyses=[edge])

    assert result["outcome"] == "Unknown"
    assert result["confidence"] == "low"
    assert "only a partial path" in result["explanation"]
    assert any("Path is partial" in item for item in result["caveats"])


def test_reach_keeps_equal_cost_paths_separate():
    edge = {
        "run_id": "edge",
        "device": {"name": "edge-rtr", "address": "10.80.0.1", "type": "router"},
        "interfaces": [{"name": "users", "network": "10.80.0.0/24"}],
        "route_analysis": {"routes": [
            {
                "network": "10.90.0.0/24", "via": "10.0.12.2",
                "interface": "path-a", "metric": 10,
            },
            {
                "network": "10.90.0.0/24", "via": "10.0.13.2",
                "interface": "path-b", "metric": 10,
            },
        ]},
        "policy": {"firewall_acl": []},
    }
    path_a = {
        "run_id": "path-a",
        "device": {"name": "path-a-rtr", "address": "10.0.12.2", "type": "router"},
        "interfaces": [{"name": "servers", "address": "10.0.12.2", "network": "10.0.12.0/30"}],
        "route_analysis": {"routes": [{"network": "10.90.0.0/24", "interface": "servers"}]},
        "policy": {"firewall_acl": []},
    }
    path_b = {
        "run_id": "path-b",
        "device": {"name": "path-b-rtr", "address": "10.0.13.2", "type": "router"},
        "interfaces": [{"name": "servers", "address": "10.0.13.2", "network": "10.0.13.0/30"}],
        "route_analysis": {"routes": [{"network": "10.90.0.0/24", "interface": "servers"}]},
        "policy": {"firewall_acl": []},
    }

    result = assess(device_analyses=[edge, path_a, path_b])

    assert [item["role"] for item in result["path_options"]] == ["active", "equal_cost"]
    assert [
        item["label"] for item in result["path_options"][0]["path"]
        if item["kind"] == "device"
    ] == ["edge-rtr", "path-a-rtr"]
    assert [
        item["label"] for item in result["path_options"][1]["path"]
        if item["kind"] == "device"
    ] == ["edge-rtr", "path-b-rtr"]


def test_reach_marks_higher_metric_path_as_standby():
    device = {
        **DEVICE,
        "route_analysis": {"routes": [
            {"network": "10.90.0.0/24", "interface": "primary", "metric": 10},
            {"network": "10.90.0.0/24", "interface": "backup", "metric": 50},
        ]},
        "policy": {"firewall_acl": []},
    }

    result = assess(device_analyses=[device])

    assert [item["role"] for item in result["path_options"]] == ["active", "standby"]
    assert "less-preferred" in result["path_options"][1]["reason"]


def test_reach_uses_secondary_wan_when_primary_path_is_incomplete():
    primary = {
        "run_id": "primary",
        "device": {"name": "primary-wan", "address": "198.51.100.1", "type": "router"},
        "external_wan_gateway": {"slot": "primary", "node_id": "ip:198.51.100.1"},
        "interfaces": [{"name": "wan", "network": "198.51.100.0/30", "role": "external"}],
        "route_analysis": {"routes": [{
            "network": "10.90.0.0/24", "via": "10.0.12.2", "interface": "inside",
        }]},
        "policy": {"firewall_acl": []},
    }
    secondary = {
        "run_id": "secondary",
        "device": {"name": "secondary-wan", "address": "203.0.113.1", "type": "router"},
        "external_wan_gateway": {"slot": "secondary", "node_id": "ip:203.0.113.1"},
        "interfaces": [
            {"name": "wan", "network": "203.0.113.0/30", "role": "external"},
            {"name": "inside", "network": "10.90.0.0/24"},
        ],
        "route_analysis": {"routes": [{"network": "10.90.0.0/24", "interface": "inside"}]},
        "policy": {"firewall_acl": []},
    }

    result = assess(source_text="Internet", device_analyses=[primary, secondary])

    assert result["routing_path"]["status"] == "complete"
    assert result["retained_objects"]["selected_path_routes"][0]["device"] == "secondary-wan"
    roles = {(item["gateway_slot"], item["role"]) for item in result["path_options"]}
    assert ("primary", "unavailable") in roles
    assert ("secondary", "active_failover") in roles


def test_reach_fails_over_when_spanning_tree_blocks_selected_interface():
    device = {
        **DEVICE,
        "route_analysis": {"routes": [
            {"network": "10.90.0.0/24", "interface": "path-a", "metric": 10},
            {"network": "10.90.0.0/24", "interface": "path-b", "metric": 20},
        ]},
        "switch_detail": {"spanning_tree": [{
            "interface": "path-a", "state": "blocking",
            "evidence": "Gi0/1 Altn BLK",
        }]},
        "policy": {"firewall_acl": []},
    }

    result = assess(device_analyses=[device])

    assert result["routing_path"]["status"] == "complete"
    assert result["retained_objects"]["selected_path_routes"][0]["interface"] == "path-b"
    assert [item["role"] for item in result["path_options"]] == [
        "active_failover", "blocked",
    ]
    assert any(
        item["kind"] == "switching"
        for item in result["path_options"][1]["evidence"]
    )


def test_reach_infers_unmapped_source_as_external_but_keeps_known_source_internal():
    edge = {
        "run_id": "edge",
        "device": {"name": "edge-wan-rtr", "address": "10.0.0.1", "type": "router"},
        "interfaces": [
            {"name": "outside", "network": "198.51.100.0/24", "role": "external"},
            {"name": "inside", "network": "10.90.0.0/24", "role": "internal"},
        ],
        "external_wan_gateway": {"node_id": "ip:10.0.0.1"},
        "route_analysis": {"routes": [{
            "network": "10.90.0.0/24", "interface": "inside", "direct": True,
        }]},
        "policy": {"firewall_acl": []},
    }

    outside = assess(
        source_text="203.0.113.77",
        device_analyses=[edge],
    )
    inside = assess(
        source_text="10.90.0.25",
        device_analyses=[edge],
    )

    assert outside["query"]["source_external"] is True
    assert outside["query"]["source_external_basis"] == "inferred_outside_retained_network"
    assert any("inferred this source is external" in item for item in outside["caveats"])
    assert inside["query"]["source_external"] is False
    assert inside["query"]["source_external_basis"] == "retained_internal_context"


def test_searchsploit_exposure_requires_internal_permit_and_external_deny_for_internal_only():
    policy = parse_iptables_policy("""*filter
:FORWARD DROP [0:0]
-A FORWARD -i outside -o servers -p tcp -d 10.90.0.10/32 --dport 443 -j DROP
-A FORWARD -i users -o servers -p tcp -d 10.90.0.10/32 --dport 443 -j ACCEPT
COMMIT
""")
    device = {
        **DEVICE,
        "interfaces": [
            {"name": "outside", "network": "198.51.100.0/24", "role": "external"},
            {"name": "users", "network": "10.80.0.0/24", "role": "internal"},
            {"name": "servers", "network": "10.90.0.0/24", "role": "internal"},
        ],
        "route_analysis": {"routes": [
            {"network": "10.90.0.0/24", "interface": "servers", "direct": True},
        ]},
        "policy": {"firewall_acl": [], "iptables": policy},
    }
    enrichment = {
        "status": "searchsploit_complete",
        "matches": [{
            "match_key": "match-1",
            "host_key": "ip:10.90.0.10",
            "ip": "10.90.0.10",
            "protocol": "tcp",
            "port": 443,
            "candidate_count": 2,
            "candidates": [{"edb_id": "1"}, {"edb_id": "2"}],
        }],
    }

    result = classify_searchsploit_exposure(
        enrichment,
        hunting=HUNTING,
        saved_networks=SAVED,
        device_analyses=[device],
    )

    exposure = result["matches"][0]["exposure"]
    assert exposure["classification"] == "internal_only"
    assert exposure["label"] == "Internal only"
    assert exposure["external"]["outcome"] == "Expected Blocked"
    internal = {item["source"]["name"]: item["outcome"] for item in exposure["internal"]}
    assert internal == {"Users": "Expected Allowed", "Servers": "Local"}
    assert result["exposure_facets"] == [{
        "classification": "internal_only",
        "label": "Internal only",
        "match_count": 1,
        "candidate_count": 2,
    }]


def test_searchsploit_exposure_labels_external_permit_without_claiming_vulnerability():
    policy = parse_iptables_policy("""*filter
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
        "policy": {"firewall_acl": [], "iptables": policy},
    }
    enrichment = {"matches": [{
        "ip": "10.90.0.10", "protocol": "tcp", "port": 443,
        "candidate_count": 1, "candidates": [{"edb_id": "1"}],
    }]}

    result = classify_searchsploit_exposure(
        enrichment,
        hunting=HUNTING,
        saved_networks=SAVED,
        device_analyses=[device],
    )

    assert result["matches"][0]["exposure"]["classification"] == "external_reachable"
    assert "not proof" in result["exposure_disclaimer"]


def test_source_exposure_report_groups_unique_services_and_preserves_evidence_objects():
    hunting = {
        **HUNTING,
        "findings": [
            {**HUNTING["findings"][0], "category": "Web"},
            {**HUNTING["findings"][0], "category": "Authentication"},
        ],
    }
    searchsploit = {
        "status": "searchsploit_complete",
        "provider": {"available": True, "active_version": "test"},
        "warnings": [],
        "disclaimer": "Potential matches require validation.",
        "matches": [{
            "ip": "10.90.0.10",
            "protocol": "tcp",
            "port": 443,
            "candidates": [{
                "edb_id": "12345",
                "title": "Example candidate",
                "cves": ["CVE-2026-12345"],
            }],
        }],
    }

    result = build_source_exposure_report(
        hunting=hunting,
        saved_networks=SAVED,
        device_analyses=[DEVICE],
        searchsploit=searchsploit,
    )

    assert result["status"] == "source_exposure_report_complete"
    assert result["service_count"] == 1
    assert result["source_count"] == 3
    assert result["evaluated_path_count"] == 3
    assert result["searchsploit_candidate_count"] == 1
    service = result["services"][0]
    assert service["categories"] == ["Authentication", "Web"]
    assert service["searchsploit"]["cves"] == ["CVE-2026-12345"]
    sources = {item["name"]: item for item in result["sources"]}
    assert sources["Servers"]["results"][0]["outcome"] == "Local"
    users_path = sources["Users"]["results"][0]
    assert users_path["outcome"] == "Expected Allowed"
    assert users_path["retained_objects"]["routes"]
    assert users_path["retained_objects"]["policy"]
    assert "sends no network traffic" in result["disclaimer"]
