from app.vendor_policy import evaluate_vendor_policy, parse_vendor_policy


def evaluate(text: str, *, input_interface: str, output_interface: str):
    return evaluate_vendor_policy(
        parse_vendor_policy(text),
        source="10.80.0.25", destination="10.90.0.10",
        protocol="tcp", port=443,
        input_interface=input_interface, output_interface=output_interface,
    )


def test_cisco_ios_acl_requires_and_uses_interface_binding():
    text = """ip access-list extended USERS_TO_SERVERS
 permit tcp 10.80.0.0 0.0.0.255 host 10.90.0.10 eq 443
 deny ip any any
!
interface GigabitEthernet0/1
 ip access-group USERS_TO_SERVERS in
"""
    result = evaluate(text, input_interface="GigabitEthernet0/1", output_interface="GigabitEthernet0/2")
    assert result["status"] == "decided"
    assert result["verdict"] == "allow"

    unbound = evaluate(text, input_interface="GigabitEthernet0/3", output_interface="GigabitEthernet0/2")
    assert unbound["status"] == "not_applied"


def test_cisco_asa_access_group_binding_is_supported():
    text = """access-list OUTSIDE_IN extended permit tcp any host 10.90.0.10 eq https
access-group OUTSIDE_IN in interface outside
"""
    result = evaluate_vendor_policy(
        parse_vendor_policy(text),
        source=None, destination="10.90.0.10", protocol="tcp", port=443,
        source_external=True, input_interface="outside", output_interface="inside",
    )
    assert result["status"] == "decided"
    assert result["verdict"] == "allow"


def test_vyos_policy_requires_interface_attachment_and_rule_order():
    text = """set firewall ipv4 name USERS-SERVERS rule 10 action drop
set firewall ipv4 name USERS-SERVERS rule 10 protocol tcp
set firewall ipv4 name USERS-SERVERS rule 10 destination address 10.90.0.20/32
set firewall ipv4 name USERS-SERVERS rule 20 action accept
set firewall ipv4 name USERS-SERVERS rule 20 protocol tcp
set firewall ipv4 name USERS-SERVERS rule 20 destination address 10.90.0.10/32
set firewall ipv4 name USERS-SERVERS rule 20 destination port 443
set interfaces ethernet eth0 firewall in name USERS-SERVERS
"""
    result = evaluate(text, input_interface="eth0", output_interface="eth1")
    assert result["status"] == "decided"
    assert result["verdict"] == "allow"
    assert result["rule"]["order"] == 20


def test_current_vyos_forward_base_chain_and_jump_are_applied():
    text = """set firewall ipv4 forward filter rule 10 action 'jump'
set firewall ipv4 forward filter rule 10 inbound-interface name 'eth0'
set firewall ipv4 forward filter rule 10 jump-target 'OUTSIDE-IN'
set firewall ipv4 name OUTSIDE-IN rule 10 action 'accept'
set firewall ipv4 name OUTSIDE-IN rule 10 protocol 'tcp'
set firewall ipv4 name OUTSIDE-IN rule 10 destination address '10.90.0.10/32'
set firewall ipv4 name OUTSIDE-IN rule 10 destination port '443'
set firewall ipv4 name OUTSIDE-IN default-action 'drop'
set firewall ipv4 forward filter default-action 'drop'
"""
    result = evaluate(text, input_interface="eth0", output_interface="eth1")
    assert result["status"] == "decided"
    assert result["verdict"] == "allow"
    assert result["rule"]["policy"] == "OUTSIDE-IN"


def test_current_vyos_new_flow_skips_established_only_rule():
    text = """set firewall ipv4 forward filter rule 5 action 'accept'
set firewall ipv4 forward filter rule 5 state 'established'
set firewall ipv4 forward filter rule 10 action 'drop'
set firewall ipv4 forward filter default-action 'accept'
"""
    result = evaluate(text, input_interface="eth0", output_interface="eth1")
    assert result["status"] == "decided"
    assert result["verdict"] == "deny"
    assert result["rule"]["order"] == 10


def test_pfsense_active_pf_rule_is_evaluated_on_its_interface():
    text = "pass in quick on em1 inet proto tcp from 10.80.0.0/24 to 10.90.0.10 port = 443"
    result = evaluate(text, input_interface="em1", output_interface="em2")
    assert result["status"] == "decided"
    assert result["verdict"] == "allow"


def test_juniper_zone_policy_resolves_builtin_application():
    text = """set security zones security-zone trust interfaces ge-0/0/1.0
set security zones security-zone servers interfaces ge-0/0/2.0
set security policies from-zone trust to-zone servers policy web match source-address any
set security policies from-zone trust to-zone servers policy web match destination-address 10.90.0.10/32
set security policies from-zone trust to-zone servers policy web match application junos-https
set security policies from-zone trust to-zone servers policy web then permit
"""
    result = evaluate(text, input_interface="ge-0/0/1.0", output_interface="ge-0/0/2.0")
    assert result["status"] == "decided"
    assert result["verdict"] == "allow"


def test_unresolved_applied_object_stays_unknown():
    text = """access-list OUTSIDE_IN extended permit tcp object-group CLIENTS host 10.90.0.10 eq 443
access-group OUTSIDE_IN in interface outside
"""
    result = evaluate_vendor_policy(
        parse_vendor_policy(text),
        source=None, destination="10.90.0.10", protocol="tcp", port=443,
        source_external=True, input_interface="outside", output_interface="inside",
    )
    assert result["status"] == "unknown"
