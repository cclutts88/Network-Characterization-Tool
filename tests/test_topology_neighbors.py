from __future__ import annotations

from app.device_configs import TEMPLATES
from app.topology_neighbors import parse_topology_neighbors


def test_cisco_cdp_detail_retains_interface_and_remote_device_identity():
    observations = parse_topology_neighbors(
        """
Device ID: core-sw1.example
Entry address(es):
  IP address: 10.20.30.2
Platform: cisco WS-C3850, Capabilities: Router Switch IGMP
Interface: GigabitEthernet0/1, Port ID (outgoing port): GigabitEthernet1/0/24
Holdtime : 131 sec
"""
    )

    assert observations == [{
        "protocol": "cdp",
        "local_interface": "GigabitEthernet0/1",
        "remote_port": "GigabitEthernet1/0/24",
        "neighbor_name": "core-sw1.example",
        "management_ip": "10.20.30.2",
        "chassis_id": None,
        "chassis_mac": None,
        "platform": "cisco WS-C3850",
        "capabilities": "Router Switch IGMP",
        "confidence": "confirmed",
        "evidence": observations[0]["evidence"],
    }]


def test_lldp_detail_retains_chassis_mac_ports_and_management_ip():
    observations = parse_topology_neighbors(
        """
Local interface: ge-0/0/0
Chassis ID: 00:11:22:33:44:55
Port ID: ge-0/0/1
System Name: edge-fw
Management address: 10.20.30.3
System Capabilities: Bridge Router
"""
    )

    assert observations[0]["protocol"] == "lldp"
    assert observations[0]["local_interface"] == "ge-0/0/0"
    assert observations[0]["remote_port"] == "ge-0/0/1"
    assert observations[0]["neighbor_name"] == "edge-fw"
    assert observations[0]["management_ip"] == "10.20.30.3"
    assert observations[0]["chassis_mac"] == "00:11:22:33:44:55"


def test_lldpctl_style_multiple_neighbors_are_separate_observations():
    observations = parse_topology_neighbors(
        """
Interface: eth0, via: LLDP, RID: 1
  Chassis:
    ChassisID: mac aa:bb:cc:dd:ee:10
    SysName: switch-a
    MgmtIP: 192.0.2.10
  Port:
    PortID: ifname Ethernet1
Interface: eth1, via: LLDP, RID: 2
  Chassis:
    ChassisID: mac aa:bb:cc:dd:ee:20
    SysName: switch-b
    MgmtIP: 192.0.2.20
  Port:
    PortID: ifname Ethernet2
"""
    )

    assert [item["neighbor_name"] for item in observations] == ["switch-a", "switch-b"]
    assert [item["local_interface"] for item in observations] == ["eth0", "eth1"]
    assert [item["remote_port"] for item in observations] == ["Ethernet1", "Ethernet2"]


def test_supported_network_device_templates_collect_neighbor_detail():
    for vendor in ("vyos", "cisco", "juniper"):
        for device_type in ("router", "firewall"):
            commands = "\n".join(TEMPLATES[vendor][device_type]).lower()
            assert "lldp neighbors detail" in commands
    for device_type in ("router", "firewall"):
        commands = "\n".join(TEMPLATES["cisco"][device_type]).lower()
        assert "cdp neighbors detail" in commands
