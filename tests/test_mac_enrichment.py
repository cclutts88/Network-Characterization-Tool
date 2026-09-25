from __future__ import annotations

from app.device_configs import TEMPLATES
from app.mac_enrichment import (
    lookup_oui_vendor,
    normalize_mac,
    parse_neighbor_text,
)


def test_mac_normalization_accepts_common_device_formats():
    assert normalize_mac("0011.2233.4455") == "00:11:22:33:44:55"
    assert normalize_mac("00-11-22-33-44-55") == "00:11:22:33:44:55"
    assert normalize_mac("00:11:22:33:44:55") == "00:11:22:33:44:55"
    assert normalize_mac("ff:ff:ff:ff:ff:ff") is None
    assert normalize_mac("not-a-mac") is None


def test_neighbor_parser_handles_multiple_formats_and_excludes_incomplete():
    text = """
192.0.2.10 dev eth0 lladdr 00:11:22:33:44:55 REACHABLE
? (192.0.2.11) at 00:11:22:33:44:66 on vtnet0 expires in 1187 seconds
Internet  192.0.2.12  0  0011.2233.4477  ARPA  GigabitEthernet0/1
Internet  192.0.2.13  0  Incomplete  ARPA  GigabitEthernet0/1
? (192.0.2.14) at (incomplete) on vtnet0
172.22.255.1 ether bc:24:11:aa:bb:cc C * eth0
bc:24:11:aa:bb:dd 192.0.2.16 ge-0/0/0.0 none
inside 192.0.2.17 00:11:22:33:44:88 123
eth0 172.22.255.2/30 bc:24:11:2b:f1:fa default 1500 u/u
"""
    observations = parse_neighbor_text(text)

    assert {(item["ip"], item["mac"], item["interface"]) for item in observations} == {
        ("192.0.2.10", "00:11:22:33:44:55", "eth0"),
        ("192.0.2.11", "00:11:22:33:44:66", "vtnet0"),
        ("192.0.2.12", "00:11:22:33:44:77", "GigabitEthernet0/1"),
        ("172.22.255.1", "BC:24:11:AA:BB:CC", "eth0"),
        ("192.0.2.16", "BC:24:11:AA:BB:DD", "ge-0/0/0.0"),
        ("192.0.2.17", "00:11:22:33:44:88", "inside"),
    }
    assert all(item["protocol"] == "arp" for item in observations)
    assert all(item["confidence"] == "confirmed" for item in observations)


def test_offline_oui_lookup_uses_nmap_prefix_database_format(tmp_path):
    database = tmp_path / "nmap-mac-prefixes"
    database.write_text("001122 Example Networks\nAABBCC Example Controls\n", encoding="utf-8")

    result = lookup_oui_vendor("00:11:22:33:44:55", (database,))

    assert result["vendor"] == "Example Networks"
    assert result["source"] == "offline_nmap_oui"
    assert result["database"] == str(database)


def test_device_collection_templates_request_neighbor_evidence():
    for vendor, device_types in TEMPLATES.items():
        for device_type, commands in device_types.items():
            command_text = "\n".join(commands).lower()
            assert any(term in command_text for term in ("arp", "ip -4 neigh", "ip neigh")), (
                f"{vendor} {device_type} is missing ARP collection"
            )
            assert any(term in command_text for term in ("ipv6 neighbor", "ndp", "ip -6 neigh", "ip neigh")), (
                f"{vendor} {device_type} is missing IPv6-neighbor collection"
            )
