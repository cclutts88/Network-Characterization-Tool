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


def test_ordered_policy_continues_to_later_deny_when_set_does_not_match():
    result = evaluate_iptables_flow(
        parse_iptables_policy(POLICY),
        source="10.0.1.25", destination="10.0.50.10",
        protocol="tcp", port=443, input_interface="br0", output_interface="br5",
    )

    assert result["status"] == "decided"
    assert result["verdict"] == "deny"
    assert result["rule"]["rule_order"] == 2


def test_unsupported_application_match_stops_without_guessing():
    text = POLICY.replace(
        "-A USER_POLICY -p tcp -m set --match-set CLIENTS src -m set --match-set WEB_PORTS dst -j ACCEPT",
        "-A USER_POLICY -m set --match-set CLIENTS src -m dpi32 --cat-app 4,112 -j DROP",
    )
    result = evaluate_iptables_flow(
        parse_iptables_policy(text),
        source="10.0.0.25", destination="10.0.50.10",
        protocol="tcp", port=443, input_interface="br0", output_interface="br5",
    )

    assert result["status"] == "unknown"
    assert "unresolved match criteria" in result["reason"]
    assert "Unsupported match: dpi32" in result["match_basis"]


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
