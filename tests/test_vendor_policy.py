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


def test_cisco_nested_network_and_service_objects_are_resolved():
    text = """object network WEB1
 host 10.90.0.10
object-group network SERVERS
 network-object object WEB1
object-group network USERS
 network-object 10.80.0.0 255.255.255.0
object service HTTPS
 service tcp destination eq 443
object-group service WEB-SERVICES
 service-object object HTTPS
access-list USERS_TO_WEB extended permit object-group WEB-SERVICES object-group USERS object-group SERVERS
access-group USERS_TO_WEB in interface inside
"""
    policy = parse_vendor_policy(text)
    result = evaluate_vendor_policy(
        policy,
        source="10.80.0.25", destination="10.90.0.10",
        protocol="tcp", port=443, input_interface="inside", output_interface="servers",
    )
    assert result["status"] == "decided"
    assert result["verdict"] == "allow"
    assert set(result["match_basis"]) >= {
        "Resolved object USERS", "Resolved object SERVERS", "Resolved object WEB-SERVICES",
    }
    assert policy["counts"]["address_objects"] == 3
    assert policy["counts"]["service_objects"] == 2
    assert policy["counts"]["objects"] == 5
    assert {item["name"] for item in policy["object_inventory"]} == {
        "WEB1", "SERVERS", "USERS", "HTTPS", "WEB-SERVICES",
    }
    assert all(item["complete"] for item in policy["object_inventory"])


def test_missing_cisco_object_definition_remains_unknown():
    text = """access-list OUTSIDE_IN extended permit tcp object-group MISSING host 10.90.0.10 eq 443
access-group OUTSIDE_IN in interface outside
"""
    result = evaluate_vendor_policy(
        parse_vendor_policy(text),
        source=None, destination="10.90.0.10", protocol="tcp", port=443,
        source_external=True, input_interface="outside", output_interface="inside",
    )
    assert result["status"] == "unknown"


def test_vyos_address_port_and_interface_groups_are_resolved():
    text = """set firewall group network-group USERS network '10.80.0.0/24'
set firewall group address-group SERVERS address '10.90.0.10'
set firewall group port-group HTTPS port '443'
set firewall group interface-group USERS-IF interface 'eth0'
set firewall ipv4 forward filter rule 10 action 'accept'
set firewall ipv4 forward filter rule 10 protocol 'tcp'
set firewall ipv4 forward filter rule 10 source group network-group 'USERS'
set firewall ipv4 forward filter rule 10 destination group address-group 'SERVERS'
set firewall ipv4 forward filter rule 10 destination group port-group 'HTTPS'
set firewall ipv4 forward filter rule 10 inbound-interface group 'USERS-IF'
set firewall ipv4 forward filter default-action 'drop'
"""
    result = evaluate(text, input_interface="eth0", output_interface="eth1")
    assert result["status"] == "decided"
    assert result["verdict"] == "allow"
    assert set(result["match_basis"]) >= {
        "Resolved object USERS", "Resolved object SERVERS",
        "Resolved object HTTPS", "Resolved object USERS-IF",
    }


def test_pfsense_static_and_nested_aliases_are_resolved_from_config_xml():
    text = """<aliases>
<alias><name>USERS</name><type>network</type><address>10.80.0.0/24</address></alias>
<alias><name>WEB1</name><type>host</type><address>10.90.0.10</address></alias>
<alias><name>SERVERS</name><type>host</type><address>WEB1</address></alias>
<alias><name>HTTPS</name><type>port</type><address>443</address></alias>
</aliases>
pass in quick on em1 inet proto tcp from &lt;USERS&gt; to &lt;SERVERS&gt; port = &lt;HTTPS&gt;
"""
    result = evaluate(text, input_interface="em1", output_interface="em2")
    assert result["status"] == "decided"
    assert result["verdict"] == "allow"


def test_juniper_zone_address_sets_and_custom_application_sets_are_resolved():
    text = """set security zones security-zone trust interfaces ge-0/0/1.0
set security zones security-zone servers interfaces ge-0/0/2.0
set security address-book users address USERS-NET 10.80.0.0/24
set security address-book users attach zone trust
set security address-book server-book address WEB1 10.90.0.10/32
set security address-book server-book address-set WEB-SERVERS address WEB1
set security address-book server-book attach zone servers
set applications application APP-HTTPS protocol tcp
set applications application APP-HTTPS destination-port 8443
set applications application-set WEB-APPS application APP-HTTPS
set security policies from-zone trust to-zone servers policy web match source-address USERS-NET
set security policies from-zone trust to-zone servers policy web match destination-address WEB-SERVERS
set security policies from-zone trust to-zone servers policy web match application WEB-APPS
set security policies from-zone trust to-zone servers policy web then permit
"""
    result = evaluate_vendor_policy(
        parse_vendor_policy(text),
        source="10.80.0.25", destination="10.90.0.10", protocol="tcp", port=8443,
        input_interface="ge-0/0/1.0", output_interface="ge-0/0/2.0",
    )
    assert result["status"] == "decided"
    assert result["verdict"] == "allow"
    assert set(result["match_basis"]) >= {
        "Resolved object USERS-NET", "Resolved object WEB-SERVERS", "Resolved object WEB-APPS",
    }


def test_nested_object_cycle_never_guesses():
    text = """object-group network A
 group-object B
object-group network B
 group-object A
access-list LOOP extended permit tcp object-group A host 10.90.0.10 eq 443
access-group LOOP in interface inside
"""
    result = evaluate(text, input_interface="inside", output_interface="servers")
    assert result["status"] == "unknown"


def test_resolved_object_mismatch_continues_to_later_terminal_rule():
    text = """object-group network ADMINS
 network-object 10.70.0.0 255.255.255.0
access-list USERS_TO_WEB extended permit tcp object-group ADMINS host 10.90.0.10 eq 443
access-list USERS_TO_WEB extended deny ip any any
access-group USERS_TO_WEB in interface inside
"""
    result = evaluate(text, input_interface="inside", output_interface="servers")
    assert result["status"] == "decided"
    assert result["verdict"] == "deny"
    assert result["rule"]["order"] == 2


def test_unsupported_source_port_inside_service_object_stays_unknown():
    text = """object service ADMIN-HTTPS
 service tcp source eq 1024 destination eq 443
access-list USERS_TO_WEB extended permit tcp any host 10.90.0.10 object ADMIN-HTTPS
access-group USERS_TO_WEB in interface inside
"""
    result = evaluate(text, input_interface="inside", output_interface="servers")
    assert result["status"] == "unknown"
    inventory = parse_vendor_policy(text)["object_inventory"]
    assert inventory[0]["complete"] is False
