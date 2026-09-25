from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from app.device_configs import TEMPLATES
from app.host_identities import list_host_identities, select_host_identity
from app.hostname_evidence import (
    build_hostname_workspace,
    parse_retained_hostname_evidence,
)
from app.hostname_ui import hostname_page


def test_retained_hostname_parser_reads_dns_dhcp_and_config_sources():
    expiry = int((datetime.now(timezone.utc) + timedelta(hours=2)).timestamp())
    evidence = parse_retained_hostname_evidence(
        f"""
===== show hosts =====
core-dns.example          None  (perm, OK)  0   IP    10.20.30.5
===== show running-config =====
hostname edge-router
ip host app-static.example 10.20.30.10
===== cat /run/dnsmasq.leases =====
{expiry} aa:bb:cc:dd:ee:ff 10.20.30.20 workstation-20 01:aa:bb
""",
        device_ip="10.20.30.1",
    )

    by_source = {(item["source"], item["ip"]): item for item in evidence}
    assert by_source[("dns", "10.20.30.5")]["hostname"] == "core-dns.example"
    assert by_source[("dns", "10.20.30.10")]["hostname"] == "app-static.example"
    assert by_source[("dhcp", "10.20.30.20")]["hostname"] == "workstation-20"
    assert by_source[("dhcp", "10.20.30.20")]["lease_time_left_seconds"] > 0
    assert by_source[("config", "10.20.30.1")]["hostname"] == "edge-router"


def test_hostname_workspace_reuses_topology_device_output_and_operator_selection(tmp_path):
    db_path = tmp_path / "analyzer.db"
    config_dir = tmp_path / "device-configs"
    run_dir = config_dir / ("a" * 32)
    run_dir.mkdir(parents=True)
    (run_dir / "manifest.json").write_text(json.dumps({
        "run_id": "a" * 32,
        "vendor": "cisco",
        "device_address": "10.20.30.1",
        "completed_at": "2026-09-24T20:00:00+00:00",
    }))
    (run_dir / "stdout.txt").write_text(
        "hostname edge-router\nip host dns-name.example 10.20.30.9\n"
    )
    topology = {"nodes": [
        {
            "kind": "host",
            "ip": "10.20.30.9",
            "addresses": ["10.20.30.9"],
            "hostname": "nmap-name.example",
            "sources": [{
                "kind": "automated_nmap",
                "timestamp": "2026-09-24T19:00:00+00:00",
                "url": "/evidence/nmap.xml",
            }],
        },
        {
            "kind": "device",
            "ip": "10.20.30.2",
            "addresses": ["10.20.30.2"],
            "hostname": "switch-from-lldp",
            "sources": [],
            "topology_observations": [{
                "protocol": "lldp",
                "management_ip": "10.20.30.2",
                "neighbor_name": "switch-from-lldp",
            }],
        },
    ]}
    select_host_identity(
        db_path,
        ip="10.20.30.9",
        hostname="approved-name.example",
        selection_source="operator_input",
        imported_by="analyst",
    )

    result = build_hostname_workspace(
        db_path, topology=topology, config_dir=config_dir
    )
    rows = {item["ip"]: item for item in result["rows"]}

    assert result["network_contacted"] is False
    assert rows["10.20.30.9"]["candidates"]["nmap"][0]["hostname"] == "nmap-name.example"
    assert rows["10.20.30.9"]["candidates"]["dns"][0]["hostname"] == "dns-name.example"
    assert rows["10.20.30.9"]["selected_hostname"] == "approved-name.example"
    assert rows["10.20.30.9"]["selection_persisted"] is True
    assert rows["10.20.30.2"]["candidates"]["lldp"][0]["hostname"] == "switch-from-lldp"
    assert rows["10.20.30.1"]["candidates"]["config"][0]["hostname"] == "edge-router"


def test_hostname_selection_keeps_source_and_version_history(tmp_path):
    db_path = tmp_path / "analyzer.db"
    first = select_host_identity(
        db_path,
        ip="10.10.10.1",
        hostname="dhcp-name",
        selection_source="dhcp",
        imported_by="analyst",
    )
    second = select_host_identity(
        db_path,
        ip="10.10.10.1",
        hostname="dns-name",
        selection_source="dns",
        imported_by="analyst",
    )

    retained = list_host_identities(db_path)[0]
    assert first["version"] == 1
    assert second["version"] == 2
    assert retained["hostname"] == "dns-name"
    assert retained["selection_source"] == "dns"


def test_hostname_page_moves_import_and_explains_zero_touch_refresh():
    html = hostname_page().body.decode()

    assert 'href="/hostnames" aria-current="page"' in html
    assert html.index('>Nmap</a>') < html.index('>Hostnames</a>') < html.index('>Analyze</a>')
    assert "No network contact" in html
    assert "Import operator hostname lists" in html
    assert 'id="identityFile"' in html
    assert "/api/hostnames/import" in html
    assert "/api/hostnames/select" in html
    assert "/api/hostnames/select-source" in html
    assert "DHCP / lease" in html
    assert "LLDP / CDP" in html
    assert "SNMP" not in html
    assert "Use source where available" in html
    assert "operator_input:'Operator'" in html


def test_normal_device_pulls_include_hostname_recovery_commands():
    assert "show ip dhcp binding" in TEMPLATES["cisco"]["router"]
    assert "show hosts" in TEMPLATES["cisco"]["router"]
    assert "show dhcp server leases" in TEMPLATES["vyos"]["router"]
    assert "cat /var/dhcpd/var/db/dhcpd.leases" in TEMPLATES["pfsense"]["firewall"]
    assert "cat /run/dnsmasq.leases" in TEMPLATES["unifi"]["router"]
