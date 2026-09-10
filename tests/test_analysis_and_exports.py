from __future__ import annotations

from app.exports import host_summary_rows, port_level_rows, rows_to_csv, PORT_LEVEL_FIELDS
from app.main import parse_xml
from app.network_map import (
    add_analysis_hosts,
    add_membership_edges,
    annotate_subnet_scan_observations,
    ensure_ip_node,
    ensure_subnet_node,
    merge_device_alias,
)


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
