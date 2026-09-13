from app.iptables_policy import (
    evaluate_iptables_flow,
    evaluate_iptables_nat,
    parse_iptables_policy,
)


POLICY = """*filter
:FORWARD DROP [0:0]
:USER_POLICY - [0:0]
-A FORWARD -i br0 -o br5 -j USER_POLICY
-A USER_POLICY -p tcp -m set --match-set CLIENTS src -m set --match-set WEB_PORTS dst -j ACCEPT
-A USER_POLICY -j DROP
COMMIT
create CLIENTS hash:net family inet
add CLIENTS 10.0.0.0/24
create WEB_PORTS bitmap:port range 0-65535
add WEB_PORTS 443
"""


def test_ipset_definitions_members_and_ordered_chains_are_parsed():
    policy = parse_iptables_policy(POLICY)

    assert policy["complete"] is True
    assert policy["counts"] == {
        "rules": 3, "nat_rules": 0, "chains": 2, "nat_chains": 0,
        "ipsets": 2, "ipset_members": 2,
    }
    assert policy["chain_policies"]["FORWARD"] == "DROP"
    assert policy["ipsets"][0]["members"][0]["value"] == "10.0.0.0/24"


def test_ordered_policy_resolves_ip_and_port_sets_to_allow():
    result = evaluate_iptables_flow(
        parse_iptables_policy(POLICY),
        source="10.0.0.25", destination="10.0.50.10",
        protocol="tcp", port=443, input_interface="br0", output_interface="br5",
    )

    assert result["status"] == "decided"
    assert result["verdict"] == "allow"
    assert result["rule"]["chain"] == "USER_POLICY"
    assert result["rule"]["rule_order"] == 1
    assert set(result["match_basis"]) == {"CLIENTS matched", "WEB_PORTS matched"}


def test_established_flow_matches_retained_conntrack_state_rule():
    policy = parse_iptables_policy("""*filter
:FORWARD DROP [0:0]
-A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
-A FORWARD -m conntrack --ctstate NEW -j DROP
COMMIT
""")

    established = evaluate_iptables_flow(
        policy,
        source="10.90.0.10", destination="10.80.0.25",
        protocol="tcp", port=443, flow_state="established",
    )
    new = evaluate_iptables_flow(
        policy,
        source="10.90.0.10", destination="10.80.0.25",
        protocol="tcp", port=443, flow_state="new",
    )

    assert established["verdict"] == "allow"
    assert "Connection state ESTABLISHED/RELATED matched" in established["match_basis"]
    assert new["verdict"] == "deny"


def test_ordered_policy_continues_to_later_deny_when_set_does_not_match():
    result = evaluate_iptables_flow(
        parse_iptables_policy(POLICY),
        source="10.0.1.25", destination="10.0.50.10",
        protocol="tcp", port=443, input_interface="br0", output_interface="br5",
    )

    assert result["status"] == "decided"
    assert result["verdict"] == "deny"
    assert result["rule"]["rule_order"] == 2


def test_subnet_query_and_earlier_drop_or_continue_branch_converge_on_deny():
    policy = parse_iptables_policy("""*filter
:FORWARD ACCEPT [0:0]
:THREAT_CHECK - [0:0]
:WAN_TO_LAN - [0:0]
-A FORWARD -j THREAT_CHECK
-A FORWARD -i wan -o lan -j WAN_TO_LAN
-A THREAT_CHECK -m set --match-set THREAT_SOURCES src -j DROP
-A WAN_TO_LAN -m set --match-set DEFAULT_NET dst -m set --match-set SSH_PORT dst -j DROP
COMMIT
create THREAT_SOURCES hash:net family inet
add THREAT_SOURCES 203.0.113.0/24
create DEFAULT_NET hash:net family inet
add DEFAULT_NET 10.0.0.0/24
create SSH_PORT bitmap:port range 0-65535
add SSH_PORT 22
""")

    result = evaluate_iptables_flow(
        policy,
        source=None, destination="10.0.0.0/24",
        protocol="tcp", port=22, source_external=True,
        input_interface="wan", output_interface="lan",
    )

    assert result["status"] == "decided"
    assert result["verdict"] == "deny"
    assert result["rule"]["chain"] == "WAN_TO_LAN"
    assert "same verdict" in " ".join(result["match_basis"])


def test_subnet_query_only_matches_when_fully_covered_by_policy_network():
    policy = parse_iptables_policy("""*filter
:FORWARD DROP [0:0]
-A FORWARD -d 10.0.0.0/24 -j ACCEPT
COMMIT
""")

    covered = evaluate_iptables_flow(
        policy, source="192.0.2.10", destination="10.0.0.0/25",
        protocol="tcp", port=443,
    )
    partial = evaluate_iptables_flow(
        policy, source="192.0.2.10", destination="10.0.0.0/23",
        protocol="tcp", port=443,
    )

    assert covered["verdict"] == "allow"
    assert partial["status"] == "unknown"


def test_external_source_never_matches_unspecified_ipv4_sentinel():
    policy = parse_iptables_policy("""*filter
:FORWARD DROP [0:0]
-A FORWARD -s 0.0.0.0/32 -j RETURN
-A FORWARD -p tcp --dport 22 -j DROP
COMMIT
""")

    result = evaluate_iptables_flow(
        policy, source=None, destination="10.0.0.2",
        protocol="tcp", port=22, source_external=True,
    )

    assert result["status"] == "decided"
    assert result["verdict"] == "deny"
    assert result["rule"]["rule_order"] == 2


def test_uncertain_return_or_drop_precheck_converges_on_later_deny():
    policy = parse_iptables_policy("""*filter
:FORWARD ACCEPT [0:0]
:GEO_PRECHECK - [0:0]
:WAN_TO_LAN - [0:0]
-A FORWARD -i wan -j GEO_PRECHECK
-A FORWARD -i wan -o lan -j WAN_TO_LAN
-A GEO_PRECHECK -s 198.51.100.0/24 -j RETURN
-A GEO_PRECHECK -m geoip --source-country ZZ -j DROP
-A GEO_PRECHECK -j RETURN
-A WAN_TO_LAN -p tcp --dport 22 -j DROP
COMMIT
""")

    result = evaluate_iptables_flow(
        policy, source=None, destination="10.0.0.2",
        protocol="tcp", port=22, source_external=True,
        input_interface="wan", output_interface="lan",
    )

    assert result["status"] == "decided"
    assert result["verdict"] == "deny"
    assert result["rule"]["chain"] == "WAN_TO_LAN"


def test_unsupported_drop_match_can_converge_with_later_drop():
    text = POLICY.replace(
        "-A USER_POLICY -p tcp -m set --match-set CLIENTS src -m set --match-set WEB_PORTS dst -j ACCEPT",
        "-A USER_POLICY -m set --match-set CLIENTS src -m dpi32 --cat-app 4,112 -j DROP",
    )
    result = evaluate_iptables_flow(
        parse_iptables_policy(text),
        source="10.0.0.25", destination="10.0.50.10",
        protocol="tcp", port=443, input_interface="br0", output_interface="br5",
    )

    assert result["status"] == "decided"
    assert result["verdict"] == "deny"
    assert "same verdict" in " ".join(result["match_basis"])


def test_incomplete_retained_membership_never_returns_a_verdict():
    policy = parse_iptables_policy(POLICY, source_truncated=True)
    result = evaluate_iptables_flow(
        policy,
        source="10.0.0.25", destination="10.0.50.10",
        protocol="tcp", port=443, input_interface="br0", output_interface="br5",
    )

    assert result["status"] == "unknown"
    assert "incomplete" in result["reason"]


def test_ordered_nat_chain_resolves_dnat_address_and_port():
    policy = parse_iptables_policy("""*nat
:PREROUTING ACCEPT [0:0]
:PORT_FORWARD - [0:0]
-A PREROUTING -i eth9 -j PORT_FORWARD
-A PORT_FORWARD -p tcp --dport 8443 -j DNAT --to-destination 10.90.0.10:443
COMMIT
""")

    result = evaluate_iptables_nat(
        policy,
        source=None, destination=None, protocol="tcp", port=8443,
        source_external=True, input_interface="eth9",
    )

    assert result["status"] == "translated"
    assert result["destination"] == "10.90.0.10"
    assert result["port"] == 443
    assert [item["chain"] for item in result["trace"]] == ["PREROUTING", "PORT_FORWARD"]


def test_ordered_nat_mismatch_reports_no_translation():
    policy = parse_iptables_policy("""*nat
:PREROUTING ACCEPT [0:0]
-A PREROUTING -i eth9 -p tcp --dport 8443 -j DNAT --to-destination 10.90.0.10:443
COMMIT
""")

    result = evaluate_iptables_nat(
        policy,
        source=None, destination=None, protocol="tcp", port=22,
        source_external=True, input_interface="eth9",
    )

    assert result["status"] == "no_translation"


def test_ordered_nat_unsupported_match_never_guesses():
    policy = parse_iptables_policy("""*nat
:PREROUTING ACCEPT [0:0]
-A PREROUTING -m addrtype --dst-type LOCAL -p tcp --dport 8443 -j DNAT --to-destination 10.90.0.10:443
COMMIT
""")

    result = evaluate_iptables_nat(
        policy,
        source=None, destination=None, protocol="tcp", port=8443,
        source_external=True, input_interface="eth9",
    )

    assert result["status"] == "unknown"
    assert "unresolved match criteria" in result["reason"]


def test_ordered_nat_resolves_exact_source_nat_in_postrouting():
    policy = parse_iptables_policy("""*nat
:POSTROUTING ACCEPT [0:0]
:SNAT_OUT - [0:0]
-A POSTROUTING -s 10.80.0.0/24 -o outside -j SNAT_OUT
-A SNAT_OUT -p tcp --dport 443 -j SNAT --to-source 198.51.100.10
COMMIT
""")

    result = evaluate_iptables_nat(
        policy,
        source="10.80.0.25", destination="203.0.113.20",
        protocol="tcp", port=443, input_interface="inside",
        output_interface="outside", stage="source",
    )

    assert result["status"] == "translated"
    assert result["translation"] == "snat"
    assert result["source"] == "198.51.100.10"
    assert [item["chain"] for item in result["trace"]] == ["POSTROUTING", "SNAT_OUT"]


def test_ordered_nat_resolves_masquerade_to_egress_interface_address():
    policy = parse_iptables_policy("""*nat
:POSTROUTING ACCEPT [0:0]
-A POSTROUTING -s 10.80.0.0/24 -o outside -j MASQUERADE
COMMIT
""")

    result = evaluate_iptables_nat(
        policy,
        source="10.80.0.25", destination=None,
        protocol="tcp", port=443, destination_external=True,
        input_interface="inside", output_interface="outside",
        stage="source", masquerade_source="198.51.100.2",
    )

    assert result["status"] == "translated"
    assert result["translation"] == "masquerade"
    assert result["source"] == "198.51.100.2"
    assert result["dynamic"] is True


def test_ordered_nat_source_range_remains_unknown():
    policy = parse_iptables_policy("""*nat
:POSTROUTING ACCEPT [0:0]
-A POSTROUTING -s 10.80.0.0/24 -j SNAT --to-source 198.51.100.10-198.51.100.20
COMMIT
""")

    result = evaluate_iptables_nat(
        policy,
        source="10.80.0.25", destination="203.0.113.20",
        protocol="tcp", port=443, stage="source",
    )

    assert result["status"] == "unknown"
    assert "single IPv4 address" in result["reason"]
