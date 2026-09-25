from app.vendor_policy import evaluate_vendor_nat, evaluate_vendor_policy, parse_vendor_policy


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


def test_cisco_show_access_lists_output_preserves_rule_order_and_type():
    text = """Extended IP access list USERS_TO_SERVERS
    10 permit tcp 10.80.0.0 0.0.0.255 host 10.90.0.10 eq 443 (25 matches)
    20 deny ip any any
Standard IP access list MANAGEMENT
    10 permit 10.70.0.0 0.0.0.255
"""

    policy = parse_vendor_policy(text)

    assert [rule["order"] for rule in policy["rules"][:2]] == [1, 2]
    assert policy["rules"][0] | {
        "policy": "USERS_TO_SERVERS",
        "sequence": 10,
        "action": "permit",
        "protocol": "tcp",
        "source": "10.80.0.0/24",
        "destination": "10.90.0.10/32",
        "destination_port": 443,
    } == policy["rules"][0]
    management = next(rule for rule in policy["rules"] if rule["policy"] == "MANAGEMENT")
    assert management["protocol"] == "ip"
    assert management["source"] == "10.70.0.0/24"


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


def test_current_vyos_established_flow_uses_state_rule():
    text = """set firewall ipv4 forward filter rule 5 action 'accept'
set firewall ipv4 forward filter rule 5 state 'established'
set firewall ipv4 forward filter rule 10 action 'drop'
set firewall ipv4 forward filter default-action 'drop'
"""
    result = evaluate_vendor_policy(
        parse_vendor_policy(text),
        source="10.90.0.10", destination="10.80.0.25",
        protocol="tcp", port=443,
        input_interface="eth1", output_interface="eth0",
        flow_state="established",
    )

    assert result["status"] == "decided"
    assert result["verdict"] == "allow"
    assert result["rule"]["order"] == 5
    assert "Connection state established matched" in result["match_basis"]


def test_pfsense_active_pf_rule_is_evaluated_on_its_interface():
    text = "pass in quick on em1 inet proto tcp from 10.80.0.0/24 to 10.90.0.10 port = 443"
    result = evaluate(text, input_interface="em1", output_interface="em2")
    assert result["status"] == "decided"
    assert result["verdict"] == "allow"


def test_pfsense_ipv4_flow_skips_ipv6_rules_without_crashing():
    text = """block in quick on em1 inet6 from fe80::/64 to any
pass in quick on em1 inet proto tcp from 10.80.0.0/24 to 10.90.0.10 port = 443"""
    result = evaluate(text, input_interface="em1", output_interface="em2")
    assert result["status"] == "decided"
    assert result["verdict"] == "allow"
    assert result["rule"]["order"] == 2


def test_pfsense_ipv6_flow_skips_ipv4_rules_without_crashing():
    text = """block in quick on em1 inet from 10.80.0.0/24 to any
pass in quick on em1 inet6 proto tcp from 2001:db8:1::/64 to 2001:db8:2::10 port = 443"""
    result = evaluate_vendor_policy(
        parse_vendor_policy(text),
        source="2001:db8:1::25", destination="2001:db8:2::10",
        protocol="tcp", port=443,
        input_interface="em1", output_interface="em2",
    )
    assert result["status"] == "decided"
    assert result["verdict"] == "allow"
    assert result["rule"]["order"] == 2


def test_pfsense_active_rules_use_family_interface_addresses_and_quick_order():
    text = """vmx1: flags=1008943<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST>
    inet 192.168.1.205 netmask 0xffffff00 broadcast 192.168.1.255
__NCT_PF_TABLE__ sshguard
===== next section =====
block drop in log inet all label "Default deny rule IPv4"
block drop in log quick on vmx1 inet6 from fe80::/64 to any
pass in quick on vmx1 inet proto tcp from any to (vmx1) port = https"""
    result = evaluate_vendor_policy(
        parse_vendor_policy(text),
        source="203.0.113.5", destination="192.168.1.205",
        protocol="tcp", port=443,
        input_interface="vmx1", output_interface=None,
    )
    assert result["status"] == "decided"
    assert result["verdict"] == "allow"
    assert result["rule"]["quick"] is True
    assert result["rule"]["destination"] == "(vmx1)"


def test_pfsense_quick_block_wins_before_later_interface_allow():
    text = """vmx1: flags=1008943<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST>
    inet 192.168.1.205 netmask 0xffffff00 broadcast 192.168.1.255
block drop in log quick inet from 169.254.0.0/16 to any
block drop in log inet all label "Default deny rule IPv4"
pass in quick on vmx1 inet proto tcp from any to (vmx1) port = https"""
    result = evaluate_vendor_policy(
        parse_vendor_policy(text),
        source="169.254.1.1", destination="192.168.1.205",
        protocol="tcp", port=443,
        input_interface="vmx1", output_interface=None,
    )
    assert result["status"] == "decided"
    assert result["verdict"] == "deny"
    assert result["rule"]["source"] == "169.254.0.0/16"


def test_pfsense_negated_interface_rule_is_skipped_on_excluded_interface():
    text = """block drop in log quick on ! vmx1 inet from 192.168.1.0/24 to any
pass in quick on vmx1 inet from 192.168.1.0/24 to any"""
    result = evaluate_vendor_policy(
        parse_vendor_policy(text),
        source="192.168.1.10", destination="8.8.8.8",
        protocol="tcp", port=443,
        input_interface="vmx1", output_interface="vmx0",
    )
    assert result["status"] == "decided"
    assert result["verdict"] == "allow"
    assert result["rule"]["interface"] == "vmx1"


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


def test_pfsense_dns_alias_uses_retained_runtime_table_snapshot():
    text = """<aliases>
<alias><name>WEB_FQDN</name><type>host</type><address>app.example.test</address></alias>
</aliases>
__NCT_PF_TABLE__ WEB_FQDN
10.90.0.10
pass in quick on em1 inet proto tcp from any to &lt;WEB_FQDN&gt; port = 443
"""
    policy = parse_vendor_policy(text)
    result = evaluate_vendor_policy(
        policy,
        source="10.80.0.25", destination="10.90.0.10",
        protocol="tcp", port=443,
        input_interface="em1", output_interface="em2",
    )

    assert result["status"] == "decided"
    assert result["verdict"] == "allow"
    assert any("Resolved dynamic object WEB_FQDN" in item for item in result["match_basis"])
    inventory = {item["name"]: item for item in policy["object_inventory"]}
    assert inventory["WEB_FQDN"]["dynamic"] is True
    assert inventory["WEB_FQDN"]["complete"] is True
    assert inventory["WEB_FQDN"]["resolution_source"] == "Retained pfctl runtime table snapshot"


def test_dns_alias_without_retained_runtime_membership_remains_unknown():
    text = """<aliases>
<alias><name>WEB_FQDN</name><type>host</type><address>app.example.test</address></alias>
</aliases>
pass in quick on em1 inet proto tcp from any to &lt;WEB_FQDN&gt; port = 443
"""
    result = evaluate_vendor_policy(
        parse_vendor_policy(text),
        source="10.80.0.25", destination="10.90.0.10",
        protocol="tcp", port=443,
        input_interface="em1", output_interface="em2",
    )

    assert result["status"] == "unknown"


def test_cisco_fqdn_object_is_retained_but_not_guessed_without_runtime_membership():
    text = """object network WEB_FQDN
 fqdn v4 app.example.test
access-list OUTSIDE_IN extended permit tcp any object WEB_FQDN eq 443
access-group OUTSIDE_IN in interface outside
"""
    policy = parse_vendor_policy(text)
    result = evaluate_vendor_policy(
        policy,
        source=None, destination="10.90.0.10", protocol="tcp", port=443,
        source_external=True, input_interface="outside", output_interface="inside",
    )

    assert result["status"] == "unknown"
    inventory = {item["name"]: item for item in policy["object_inventory"]}
    assert inventory["WEB_FQDN"]["dynamic"] is True
    assert inventory["WEB_FQDN"]["complete"] is False


def test_cisco_static_port_forward_is_normalized_and_evaluated():
    policy = parse_vendor_policy(
        "ip nat inside source static tcp 10.90.0.10 443 198.51.100.10 8443"
    )
    result = evaluate_vendor_nat(
        policy,
        source=None, destination="198.51.100.10", protocol="tcp", port=8443,
        source_external=True, input_interface="outside", output_interface="inside",
    )

    assert policy["counts"]["nat_rules"] == 1
    assert result["status"] == "translated"
    assert result["destination"] == "10.90.0.10"
    assert result["port"] == 443


def test_vyos_destination_nat_is_normalized_and_evaluated():
    text = """set nat destination rule 10 inbound-interface name 'eth0'
set nat destination rule 10 protocol 'tcp'
set nat destination rule 10 destination address '198.51.100.10'
set nat destination rule 10 destination port '8443'
set nat destination rule 10 translation address '10.90.0.10'
set nat destination rule 10 translation port '443'
"""
    policy = parse_vendor_policy(text)
    result = evaluate_vendor_nat(
        policy,
        source=None, destination="198.51.100.10", protocol="tcp", port=8443,
        source_external=True, input_interface="eth0", output_interface="eth1",
    )

    assert result["status"] == "translated"
    assert result["destination"] == "10.90.0.10"
    assert result["port"] == 443


def test_pfsense_active_rdr_and_interface_nat_are_evaluated():
    text = """rdr on em0 inet proto tcp from any to 198.51.100.10 port = 8443 -> 10.90.0.10 port 443
nat on em0 inet from 10.90.0.0/24 to any -> (em0)
"""
    policy = parse_vendor_policy(text)
    destination = evaluate_vendor_nat(
        policy,
        source=None, destination="198.51.100.10", protocol="tcp", port=8443,
        source_external=True, input_interface="em0", output_interface="em1",
    )
    source = evaluate_vendor_nat(
        policy,
        source="10.90.0.10", destination=None, protocol="tcp", port=443,
        destination_external=True, input_interface="em1", output_interface="em0",
        stage="source", masquerade_source="198.51.100.2",
    )

    assert destination["destination"] == "10.90.0.10"
    assert destination["port"] == 443
    assert source["translation"] == "masquerade"
    assert source["source"] == "198.51.100.2"


def test_cisco_policy_nat_is_retained_as_unknown_instead_of_guessed():
    policy = parse_vendor_policy(
        "ip nat inside source route-map POLICY-NAT interface GigabitEthernet0/0 overload"
    )
    result = evaluate_vendor_nat(
        policy,
        source="10.80.0.25", destination="203.0.113.10",
        protocol="tcp", port=443, output_interface="GigabitEthernet0/0",
        stage="source", masquerade_source="198.51.100.2",
    )

    assert result["status"] == "unknown"
    assert "unresolved" in result["reason"]


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
