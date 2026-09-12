from app.switching import merge_switch_interfaces, parse_switch_evidence


CISCO_SWITCH = """
interface GigabitEthernet1/0/10
 description Finance workstation
 switchport mode access
 switchport access vlan 80
 spanning-tree portfast
interface GigabitEthernet1/0/48
 description Core uplink
 switchport mode trunk
 switchport trunk native vlan 10
 switchport trunk allowed vlan 10,80,90
 channel-group 1 mode active
80    0011.2233.4455    DYNAMIC     Gi1/0/10
10    00aa.bbcc.ddee    DYNAMIC     Gi1/0/48
80 USERS active Gi1/0/10
1 Po1(SU) LACP Gi1/0/47(P) Gi1/0/48(P)
Gi1/0/48 Root FWD 4 128.48 P2p
"""


def test_cisco_switch_evidence_is_structured():
    result = parse_switch_evidence(CISCO_SWITCH, ["show mac address-table"])

    assert result["mac_table"][0] == {
        "mac": "00:11:22:33:44:55",
        "vlan_id": 80,
        "interface": "Gi1/0/10",
        "entry_type": "dynamic",
        "line_number": 13,
        "evidence": "80    0011.2233.4455    DYNAMIC     Gi1/0/10",
    }
    ports = {item["interface"]: item for item in result["ports"]}
    assert ports["GigabitEthernet1/0/10"]["mode"] == "access"
    assert ports["GigabitEthernet1/0/10"]["access_vlan"] == 80
    assert ports["GigabitEthernet1/0/48"]["mode"] == "trunk"
    assert ports["GigabitEthernet1/0/48"]["uplink"] is True
    assert ports["Gi1/0/48"]["port_channel"] == "Po1"
    assert result["port_channels"][0]["members"] == ["Gi1/0/47", "Gi1/0/48"]
    assert result["vlans"][0]["vlan_id"] == 80


def test_unifi_bridge_fdb_vlan_and_command_status_are_retained():
    result = parse_switch_evidence(
        """
===== bridge fdb show =====
00:11:22:33:44:66 dev eth2 master br0 vlan 20
===== lldpcli show neighbors details =====
sh: lldpcli: not found
[NCT] Command unavailable or returned a non-zero status.
===== bridge vlan show =====
eth2 20 PVID Egress Untagged
eth3 20
""",
        ["bridge fdb show", "lldpcli show neighbors details", "bridge vlan show"],
    )

    assert result["mac_table"][0]["interface"] == "eth2"
    assert result["mac_table"][0]["vlan_id"] == 20
    ports = {item["interface"]: item for item in result["ports"]}
    assert ports["eth2"]["mode"] == "access"
    statuses = {item["command"]: item["status"] for item in result["command_results"]}
    assert statuses["bridge fdb show"] == "completed"
    assert statuses["lldpcli show neighbors details"] == "unavailable"


def test_switch_ports_merge_with_routed_interfaces():
    detail = parse_switch_evidence("interface ge-0/0/1\n switchport mode trunk")
    merged = merge_switch_interfaces([{"name": "vlan.80", "address": "10.80.0.1/24"}], detail)

    assert merged[0]["address"] == "10.80.0.1/24"
    assert merged[1]["name"] == "ge-0/0/1"
    assert merged[1]["switching"]["mode"] == "trunk"


def test_unlabeled_cli_output_does_not_claim_per_command_success():
    result = parse_switch_evidence("combined CLI output", ["show vlan brief"])

    assert result["command_results"][0]["status"] == "not_individually_reported"
