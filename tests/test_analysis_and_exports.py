from __future__ import annotations

import json

from app.exports import host_summary_rows, port_level_rows, rows_to_csv, PORT_LEVEL_FIELDS
from app.main import parse_xml
from app.network_map import (
    add_analysis_hosts,
    add_edge,
    add_membership_edges,
    annotate_subnet_scan_observations,
    apply_saved_network_names,
    apply_subnet_zone,
    configuration_network_candidates,
    configuration_devices,
    ensure_ip_node,
    ensure_interface_node,
    ensure_subnet_node,
    ensure_topology_neighbor_node,
    merge_device_alias,
    parse_config_text,
)
from app.saved_networks import SavedNetworkCreate, create_saved_network


SAMPLE_XML = b'''<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.95" args="nmap -n -sS -sU --traceroute -p T:502,U:47808 10.20.30.0/24" startstr="Wed Sep 9 14:30:00 2026">
  <scaninfo type="syn" protocol="tcp" numservices="1" services="502"/>
  <scaninfo type="udp" protocol="udp" numservices="1" services="47808"/>
  <host>
    <status state="up" reason="arp-response"/>
    <address addr="10.20.30.15" addrtype="ipv4"/>
    <address addr="3C:52:82:11:22:33" addrtype="mac" vendor="Dell"/>
    <hostnames><hostname name="plc-15" type="PTR"/></hostnames>
    <ports>
      <port protocol="tcp" portid="502"><state state="open" reason="syn-ack"/><service name="modbus" product="Modbus device" version="1"/></port>
      <port protocol="udp" portid="47808"><state state="open" reason="udp-response"/><service name="bacnet"/></port>
    </ports>
    <os><osmatch name="Linux 5.x" accuracy="90"><osclass type="general purpose" vendor="Linux" osfamily="Linux" osgen="5.X"/></osmatch></os>
    <trace port="502" proto="tcp"><hop ttl="1" rtt="0.85" ipaddr="10.20.30.1" host="range-gateway"/><hop ttl="2" rtt="1.40" ipaddr="10.20.30.15" host="plc-15"/></trace>
  </host>
  <runstats><finished timestr="Wed Sep 9 14:31:00 2026"/><hosts up="1" down="0" total="1"/></runstats>
</nmaprun>'''


def test_parser_surfaces_mac_hostname_protocol_and_coverage():
    analysis = parse_xml(SAMPLE_XML)
    host = analysis["hosts"][0]
    assert host["mac"] == "3C:52:82:11:22:33"
    assert host["vendor"] == "Dell"
    assert host["hostname"] == "plc-15"
    assert {port["protocol"] for port in host["ports"]} == {"tcp", "udp"}
    assert all(port["state"] == "open" for port in host["ports"])
    assert analysis["mac_count"] == 1
    assert analysis["coverage"]["protocols"] == ["TCP", "UDP"]
    assert analysis["coverage"]["dns_resolution_disabled"] is True
    assert analysis["coverage"]["traceroute"] is True
    assert host["trace"]["hops"][0]["ip"] == "10.20.30.1"
    assert host["trace"]["hops"][0]["ttl"] == 1
    assert len(host["observed_ports"]) == 2


def test_parser_warns_when_reset_responses_make_an_entire_subnet_look_online():
    hosts = "".join(
        f'''<host><status state="up" reason="reset" reason_ttl="63"/>
        <address addr="10.0.0.{index}" addrtype="ipv4"/></host>'''
        for index in range(1, 65)
    )
    xml = f'''<?xml version="1.0"?>
    <nmaprun scanner="nmap" version="7.95" args="nmap -n -sS 10.0.0.0/26">
      <scaninfo type="syn" protocol="tcp" numservices="1" services="80"/>
      {hosts}
      <runstats><finished timestr="done"/><hosts up="64" down="0" total="64"/></runstats>
    </nmaprun>'''.encode()

    analysis = parse_xml(xml)

    assert analysis["discovery_reason_counts"] == {"reset": 64}
    assert analysis["hosts"][0]["state_reason"] == "reset"
    assert analysis["hosts"][0]["state_reason_ttl"] == "63"
    assert any("Docker Desktop NAT" in warning for warning in analysis["warnings"])


def test_parser_does_not_warn_for_a_small_directly_observed_scan():
    analysis = parse_xml(SAMPLE_XML)

    assert analysis["discovery_reason_counts"] == {"arp-response": 1}
    assert not any("Scan-quality warning" in warning for warning in analysis["warnings"])


def test_parser_retains_non_open_port_observations_for_comparison():
    xml = SAMPLE_XML.replace(
        b'<state state="open" reason="syn-ack"/>',
        b'<state state="filtered" reason="no-response"/>',
        1,
    )
    host = parse_xml(xml)["hosts"][0]

    assert len(host["ports"]) == 1
    assert len(host["observed_ports"]) == 2
    filtered = next(item for item in host["observed_ports"] if item["port"] == 502)
    assert filtered["state"] == "filtered"
    assert filtered["reason"] == "no-response"


def test_normalized_export_has_one_row_per_ip_protocol_port():
    analysis = parse_xml(SAMPLE_XML)
    port_rows = port_level_rows(analysis)
    assert len(port_rows) == 2
    assert {(row["ip"], row["protocol"], row["port"]) for row in port_rows} == {
        ("10.20.30.15", "tcp", 502),
        ("10.20.30.15", "udp", 47808),
    }
    assert len(host_summary_rows(analysis)) == 1
    csv_bytes = rows_to_csv(port_rows, PORT_LEVEL_FIELDS)
    assert b"protocol,port,port_state" in csv_bytes
    assert b"10.20.30.15" in csv_bytes


def test_traceroute_hops_become_observed_map_relationships():
    analysis = parse_xml(SAMPLE_XML)
    nodes, edges = {}, {}
    count = add_analysis_hosts(
        nodes,
        analysis,
        {"kind": "test", "label": "sample", "timestamp": "2026-09-09"},
        edges,
    )
    assert count == 1
    assert nodes["ip:10.20.30.15"]["kind"] == "host"
    assert nodes["ip:10.20.30.15"]["mac"] == "3C:52:82:11:22:33"
    assert nodes["ip:10.20.30.15"]["mac_observations"][0]["vendor"] == "Dell"
    assert nodes["ip:10.20.30.15"]["mac_observations"][0]["source_kind"] == "test"
    assert nodes["ip:10.20.30.1"]["kind"] == "gateway"
    assert nodes["ip:10.20.30.15"]["paths"][0]["hops"][0]["ttl"] == 1
    assert any(edge["relation"] == "trace_hop" for edge in edges.values())


def test_docker_bridge_gateway_stays_in_path_but_out_of_mission_map(monkeypatch):
    monkeypatch.setattr(
        "app.network_map.container_default_gateway", lambda: "172.17.0.1"
    )
    nodes, edges = {}, {}
    add_analysis_hosts(
        nodes,
        {
            "hosts": [
                {
                    "ip": "10.0.0.20",
                    "ports": [],
                    "trace": {
                        "hops": [
                            {"ttl": 1, "ip": "172.17.0.1", "rtt": "0.10"},
                            {"ttl": 2, "ip": "10.0.0.1", "rtt": "0.50"},
                            {"ttl": 3, "ip": "10.0.0.20", "rtt": "0.90"},
                        ]
                    },
                }
            ]
        },
        {"kind": "automated_nmap", "label": "container scan"},
        edges,
    )

    assert "ip:172.17.0.1" not in nodes
    path = nodes["ip:10.0.0.20"]["paths"][0]
    assert path["hops"][0]["ip"] == "172.17.0.1"
    assert path["hops"][0]["tool_local"] is True
    assert any(
        edge["source"] == "ip:10.0.0.1"
        and edge["target"] == "ip:10.0.0.20"
        for edge in edges.values()
    )


def test_scanned_infrastructure_counts_as_subnet_characterization():
    nodes, edges = {}, {}
    scan_source = {
        "kind": "automated_nmap",
        "label": "Automated scan test",
        "timestamp": "2026-09-10T00:25:46+00:00",
        "url": "/api/scan-runs/test/artifacts/xml",
    }
    add_analysis_hosts(
        nodes,
        {
            "hosts": [
                {"ip": "172.22.255.1", "state": "up", "ports": []},
                {"ip": "172.22.255.2", "state": "up", "ports": []},
            ]
        },
        scan_source,
        edges,
    )
    config_source = {
        "kind": "device_configuration",
        "label": "device configuration",
        "timestamp": "2026-09-09T23:00:00+00:00",
        "url": None,
    }
    firewall = ensure_ip_node(
        nodes, "172.22.70.1", role="firewall", source=config_source
    )
    merge_device_alias(nodes, edges, firewall, "172.22.255.1", {})
    ensure_ip_node(nodes, "172.22.255.2", role="router", source=config_source)
    subnet = ensure_subnet_node(nodes, "172.22.255.0/30", config_source)

    add_membership_edges(nodes, edges)
    annotate_subnet_scan_observations(nodes)

    assert subnet["infrastructure_count"] == 2
    assert {item["ip"] for item in subnet["infrastructure_observations"]} == {
        "172.22.255.1",
        "172.22.255.2",
    }
    assert all(
        item["source_kind"] == "automated_nmap"
        for item in subnet["infrastructure_observations"]
    )


def test_configuration_zone_names_label_subnets_without_hiding_cidr():
    interfaces, _ = parse_config_text(
        """
interface GigabitEthernet0/1
 description OPERATIONS-LAN
 ip address 10.40.0.1 255.255.255.0
interface GigabitEthernet0/2
 nameif DMZ
 ip address 10.50.0.1 255.255.255.0
set security zones security-zone TRUST interfaces ge-0/0/3.0
set interfaces ge-0/0/3 unit 0 family inet address 10.60.0.1/24
"""
    )
    by_name = {item["name"]: item for item in interfaces}
    assert by_name["GigabitEthernet0/1"]["zone"] == "OPERATIONS-LAN"
    assert by_name["GigabitEthernet0/2"]["zone"] == "DMZ"
    assert by_name["ge-0/0/3.0"]["zone"] == "TRUST"

    subnet = ensure_subnet_node({}, "10.40.0.0/24")
    apply_subnet_zone(subnet, "OPERATIONS-LAN")
    assert subnet["label"] == "OPERATIONS-LAN · 10.40.0.0/24"
    assert subnet["zone_names"] == ["OPERATIONS-LAN"]


def test_saved_network_name_labels_matching_map_subnet_without_hiding_cidr():
    subnet = ensure_subnet_node({}, "10.40.0.0/24")
    apply_subnet_zone(subnet, "OPERATIONS-LAN")

    apply_saved_network_names(
        {subnet["id"]: subnet},
        [{"name": "Plant Operations", "cidr": "10.40.0.0/24", "active": True}],
    )

    assert subnet["label"] == "Plant Operations · 10.40.0.0/24"
    assert subnet["saved_network_name"] == "Plant Operations"
    assert subnet["zone_names"] == ["OPERATIONS-LAN"]


def test_switch_role_promotes_scanned_ip_to_map_device():
    node = ensure_ip_node({}, "10.40.0.2", role="switch")

    assert node["kind"] == "device"
    assert node["role"] == "switch"


def test_configuration_parser_associates_hardware_addresses_with_interfaces():
    interfaces, _ = parse_config_text(
        """
interface GigabitEthernet0/1
 ip address 10.40.0.1 255.255.255.0
GigabitEthernet0/1 is up, line protocol is up
  Hardware is Gigabit Ethernet, address is 0011.2233.4455 (bia 0011.2233.4455)
set interfaces ethernet eth0 address '10.50.0.1/24'
set interfaces ethernet eth0 hw-id '00:11:22:33:44:66'
set interfaces ge-0/0/3 unit 0 family inet address 10.60.0.1/24
Physical interface: ge-0/0/3, Enabled, Physical link is Up
  Current address: 00:11:22:33:44:77, Hardware address: 00:11:22:33:44:77
vtnet0: flags=8863<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> metric 0 mtu 1500
  ether 00:11:22:33:44:88
  inet 10.70.0.1 netmask 0xffffff00 broadcast 10.70.0.255
"""
    )

    by_name = {item["name"]: item for item in interfaces}
    assert by_name["GigabitEthernet0/1"]["mac"] == "00:11:22:33:44:55"
    assert by_name["eth0"]["mac"] == "00:11:22:33:44:66"
    assert by_name["ge-0/0/3.0"]["mac"] == "00:11:22:33:44:77"
    assert by_name["vtnet0"]["mac"] == "00:11:22:33:44:88"
    assert all(item.get("mac_evidence") for item in by_name.values())


def test_configuration_parser_reads_unifi_linux_interfaces_connected_and_default_routes():
    interfaces, routes = parse_config_text(
        """
2: br0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP
    link/ether 00:11:22:33:44:99 brd ff:ff:ff:ff:ff:ff
    inet 10.80.0.1/24 brd 10.80.0.255 scope global br0
10.80.0.0/24 dev br0 proto kernel scope link src 10.80.0.1
default via 192.0.2.254 dev eth8 proto static
"""
    )

    by_name = {item["name"]: item for item in interfaces}
    assert by_name["br0"]["address"] == "10.80.0.1/24"
    assert by_name["br0"]["mac"] == "00:11:22:33:44:99"
    by_network = {item["network"]: item for item in routes}
    assert by_network["10.80.0.0/24"]["interface"] == "br0"
    assert by_network["10.80.0.0/24"]["direct"] is True
    assert by_network["0.0.0.0/0"]["via"] == "192.0.2.254"
    assert by_network["0.0.0.0/0"]["interface"] == "eth8"


def test_lldp_neighbor_becomes_confirmed_device_to_device_map_link():
    nodes, edges, aliases = {}, {}, {}
    source = {
        "kind": "lldp_cdp_neighbor",
        "label": "Cisco LLDP/CDP neighbor evidence",
        "timestamp": "2026-09-09T20:00:00+00:00",
        "url": "/api/device-configs/example/files/stdout.txt",
    }
    local = ensure_ip_node(nodes, "10.20.30.1", hostname="edge-router", role="router", source=source)
    interface = ensure_interface_node(nodes, local, "GigabitEthernet0/1", "10.20.30.1/24", source)
    observation = {
        "protocol": "lldp",
        "local_interface": "GigabitEthernet0/1",
        "remote_port": "GigabitEthernet1/0/24",
        "neighbor_name": "core-switch",
        "management_ip": "10.20.30.2",
        "chassis_id": "00:11:22:33:44:55",
        "chassis_mac": "00:11:22:33:44:55",
        "platform": "Cisco C3850",
        "capabilities": "Bridge Router",
        "evidence": "retained LLDP detail",
    }

    neighbor = ensure_topology_neighbor_node(nodes, observation, source, aliases)
    add_edge(
        edges, interface["id"], neighbor["id"], "topology_neighbor",
        "GigabitEthernet0/1 ↔ GigabitEthernet1/0/24 (LLDP)",
        "confirmed", observation["evidence"], True,
    )

    assert neighbor["kind"] == "device"
    assert neighbor["role"] == "switch"
    assert neighbor["vendor"] == "cisco"
    assert neighbor["hostname"] == "core-switch"
    assert neighbor["mac"] == "00:11:22:33:44:55"
    assert neighbor["topology_observations"][0]["remote_port"] == "GigabitEthernet1/0/24"
    edge = next(iter(edges.values()))
    assert edge["relation"] == "topology_neighbor"
    assert edge["confidence"] == "confirmed"
    assert edge["interface_label"] is True


def test_collected_configuration_adds_lldp_link_to_complete_topology(tmp_path, monkeypatch):
    run_id = "a" * 32
    run_dir = tmp_path / run_id
    run_dir.mkdir()
    manifest = {
        "run_id": run_id,
        "operation": "interactive_configuration_pull",
        "device_address": "10.20.30.1",
        "device_name": "edge-router",
        "vendor": "cisco",
        "device_type": "router",
        "status": "completed",
        "created_at": "2026-09-09T20:00:00+00:00",
        "completed_at": "2026-09-09T20:01:00+00:00",
    }
    (run_dir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    (run_dir / "stdout.txt").write_text(
        """
interface GigabitEthernet0/1
 description TRANSIT
 ip address 10.20.30.1 255.255.255.0
GigabitEthernet0/1 is up, line protocol is up
  Hardware is Gigabit Ethernet, address is 0011.2233.4499 (bia 0011.2233.4499)
Local interface: GigabitEthernet0/1
Chassis ID: 00:11:22:33:44:55
Port ID: GigabitEthernet1/0/24
System Name: core-switch
Management address: 10.20.30.2
System Capabilities: Bridge Router
""",
        encoding="utf-8",
    )
    monkeypatch.setattr("app.network_map.CONFIG_DIR", tmp_path)
    nodes, edges, warnings = {}, {}, []

    assert configuration_devices(nodes, edges, warnings) == 1

    assert nodes["ip:10.20.30.1"]["hostname"] == "edge-router"
    assert nodes["ip:10.20.30.1"]["interfaces"][0]["mac"] == "00:11:22:33:44:99"
    assert nodes["interface:10.20.30.1:GigabitEthernet0-1"]["mac"] == "00:11:22:33:44:99"
    assert nodes["ip:10.20.30.2"]["hostname"] == "core-switch"
    links = [edge for edge in edges.values() if edge["relation"] == "topology_neighbor"]
    assert len(links) == 1
    assert links[0]["label"] == "GigabitEthernet0/1 ↔ GigabitEthernet1/0/24 (LLDP)"
    assert links[0]["evidence"].startswith("Local interface: GigabitEthernet0/1")


def test_switch_mac_table_correlates_known_nmap_mac_to_physical_port(tmp_path, monkeypatch):
    run_id = "b" * 32
    run_dir = tmp_path / run_id
    run_dir.mkdir()
    (run_dir / "manifest.json").write_text(json.dumps({
        "run_id": run_id,
        "operation": "configuration_pull",
        "device_address": "10.80.0.2",
        "device_name": "access-switch",
        "vendor": "cisco",
        "device_type": "switch",
        "status": "completed",
        "commands": ["show interfaces switchport", "show mac address-table"],
        "created_at": "2026-09-12T20:00:00+00:00",
    }), encoding="utf-8")
    (run_dir / "stdout.txt").write_text(
        """
interface GigabitEthernet1/0/10
 switchport mode access
 switchport access vlan 80
80 0011.2233.4455 DYNAMIC Gi1/0/10
""",
        encoding="utf-8",
    )
    monkeypatch.setattr("app.network_map.CONFIG_DIR", tmp_path)
    source = {
        "kind": "automated_nmap", "label": "Nmap", "timestamp": "2026-09-12T19:00:00+00:00", "url": "/scan.xml",
    }
    nodes, edges, warnings = {}, {}, []
    host = ensure_ip_node(nodes, "10.80.0.25", mac="00:11:22:33:44:55", source=source)

    assert configuration_devices(nodes, edges, warnings) == 1

    switch = nodes["ip:10.80.0.2"]
    assert switch["switching"]["mac_table"][0]["interface"] == "Gi1/0/10"
    assert host["switchport_observations"][0]["switch_label"] == "access-switch"
    link = next(edge for edge in edges.values() if edge["relation"] == "switchport_learning")
    assert link["source"] == "interface:10.80.0.2:GigabitEthernet1-0-10"
    assert link["target"] == "ip:10.80.0.25"
    assert link["label"] == "Gi1/0/10 · VLAN 80 · learned MAC"


def test_pfsense_self_arp_entry_does_not_spawn_endpoint(tmp_path, monkeypatch):
    run_id = "c" * 32
    run_dir = tmp_path / run_id
    run_dir.mkdir()
    manifest = {
        "run_id": run_id,
        "operation": "interactive_configuration_pull",
        "device_address": "172.22.70.1",
        "device_name": "Core_Firewall",
        "vendor": "pfsense",
        "device_type": "firewall",
        "status": "completed",
        "created_at": "2026-09-10T02:19:00+00:00",
    }
    (run_dir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    (run_dir / "stdout.txt").write_text(
        """
vtnet3: flags=8863<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> metric 0 mtu 1500
  ether bc:24:11:3a:d4:c2
  inet 172.22.70.1 netmask 0xffffff00 broadcast 172.22.70.255
em0: flags=8863<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> metric 0 mtu 1500
  ether bc:24:11:01:a1:79
  inet 172.22.255.1 netmask 0xfffffffc broadcast 172.22.255.3
? (172.22.255.1) at bc:24:11:01:a1:79 on em0 permanent [ethernet]
""",
        encoding="utf-8",
    )
    monkeypatch.setattr("app.network_map.CONFIG_DIR", tmp_path)
    nodes, edges, warnings = {}, {}, []

    assert configuration_devices(nodes, edges, warnings) == 1

    firewall = nodes["ip:172.22.70.1"]
    assert "172.22.255.1" in firewall["addresses"]
    assert "ip:172.22.255.1" not in nodes
    assert not any(edge["relation"] == "arp_neighbor" for edge in edges.values())
    em0 = nodes["interface:172.22.70.1:em0"]
    assert em0["mac"] == "BC:24:11:01:A1:79"


def test_config_identified_subnet_disappears_after_it_is_saved(tmp_path):
    db_path = tmp_path / "analyzer.db"
    config_dir = tmp_path / "device-configs"
    run_dir = config_dir / ("a" * 32)
    run_dir.mkdir(parents=True)
    (run_dir / "manifest.json").write_text(
        json.dumps(
            {
                "run_id": "a" * 32,
                "status": "uploaded",
                "device_name": "Core Firewall",
                "device_address": "192.0.2.1",
                "vendor": "cisco",
                "completed_at": "2026-09-11T12:00:00+00:00",
            }
        )
    )
    (run_dir / "uploaded-config.txt").write_text(
        """interface GigabitEthernet0/1
description OPERATIONS-LAN
ip address 10.40.0.1 255.255.255.0
ip route 10.50.0.0/24 192.0.2.2
ip route 0.0.0.0/0 192.0.2.254
"""
    )

    candidates = configuration_network_candidates(
        config_dir=config_dir, db_path=db_path
    )
    assert [item["cidr"] for item in candidates] == ["10.40.0.0/24", "10.50.0.0/24"]
    interface_candidate = candidates[0]
    assert interface_candidate["suggested_name"] == "OPERATIONS-LAN · 10.40.0.0/24"
    assert interface_candidate["sources"][0]["device_name"] == "Core Firewall"

    create_saved_network(
        SavedNetworkCreate(
            name=interface_candidate["suggested_name"],
            cidr=interface_candidate["cidr"],
            created_by="operator",
        ),
        db_path,
    )
    remaining = configuration_network_candidates(config_dir=config_dir, db_path=db_path)
    assert [item["cidr"] for item in remaining] == ["10.50.0.0/24"]
