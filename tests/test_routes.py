from __future__ import annotations

import io
import zipfile

from fastapi.testclient import TestClient

from app.main import app


ROUTE_XML = b'''<nmaprun scanner="nmap" version="7.95" args="nmap -n -sS 192.0.2.10">
<scaninfo type="syn" protocol="tcp" numservices="1" services="443"/>
<host><status state="up"/><address addr="192.0.2.10" addrtype="ipv4"/>
<address addr="00:11:22:33:44:55" addrtype="mac" vendor="Example"/>
<ports><port protocol="tcp" portid="443"><state state="open" reason="syn-ack"/><service name="https"/></port></ports></host>
<runstats><finished timestr="done"/><hosts up="1" down="0" total="1"/></runstats></nmaprun>'''


def test_primary_pages_and_profiles_are_available():
    with TestClient(app) as client:
        scan_page = client.get("/")
        analysis_page = client.get("/analysis")
        profiles = client.get("/api/scan-profiles")

    assert scan_page.status_code == 200
    assert "Build scan" in scan_page.text
    assert analysis_page.status_code == 200
    assert "Previous scans" in analysis_page.text
    assert profiles.status_code == 200
    assert {item["profile_id"] for item in profiles.json()} >= {
        "builtin-standard",
        "builtin-comprehensive",
        "builtin-quick-discovery",
        "builtin-ics-safe",
    }


def test_preview_and_package_use_the_same_udp_settings_and_required_n():
    body = {
        "name": "UDP Baseline",
        "created_by": "analyst01",
        "profile": "Custom",
        "scan_options": {
            "protocol": "udp",
            "udp_scope": "custom",
            "udp_ports": "53,161,47808",
            "tcp_scope": "common",
            "timing": "conservative",
        },
        "terrain": [{"name": "ICS", "targets": ["192.0.2.0/30"]}],
        "no_strike_mode": "none",
        "no_strike": [],
        "chunk_size": 16,
    }
    with TestClient(app) as client:
        preview = client.post("/api/preview", json=body)
        package = client.post("/api/packages", json=body)

    assert preview.status_code == 200
    assert "sudo nmap -n -sU" in preview.json()["copy_text"]
    assert "53,161,47808" in preview.json()["copy_text"]
    assert package.status_code == 200
    assert "UDP_Baseline_" in package.headers["content-disposition"]


def test_combined_tcp_udp_package_supports_fping_and_traceroute():
    body = {
        "name": "ICS Combined",
        "created_by": "analyst01",
        "profile": "Custom",
        "scan_options": {
            "protocol": "tcp_udp",
            "tcp_scope": "common",
            "udp_scope": "ics",
            "discovery_mode": "fping",
            "traceroute": True,
            "timing": "conservative",
        },
        "terrain": [{"name": "ICS", "targets": ["192.0.2.0/30"]}],
        "no_strike_mode": "none",
        "no_strike": [],
        "chunk_size": 16,
    }
    with TestClient(app) as client:
        preview = client.post("/api/preview", json=body)
        package = client.post("/api/packages", json=body)

    assert preview.status_code == 200
    command = preview.json()["copy_text"]
    assert "-n -sS -sU" in command
    assert "--traceroute" in command
    assert "T:" in command and ",U:2222,47808" in command
    assert package.status_code == 200
    with zipfile.ZipFile(io.BytesIO(package.content)) as archive:
        linux_script = archive.read("run-linux.sh").decode()
        manifest = archive.read("manifest.json").decode()
    assert "fping -a -q -f" in linux_script
    assert "-n -sS -sU" in linux_script
    assert '"discovery_mode": "fping"' in manifest
    assert '"traceroute": true' in manifest


def test_import_history_raw_xml_and_both_csv_exports():
    with TestClient(app) as client:
        imported = client.post(
            "/api/import", files={"file": ("baseline.xml", ROUTE_XML, "application/xml")}
        )
        digest = imported.json()["sha256"]
        history = client.get("/api/imports")
        detail = client.get(f"/api/imports/{digest}")
        raw = client.get(f"/api/imports/{digest}/raw")
        hosts = client.get(f"/api/imports/{digest}/exports/hosts.csv")
        ports = client.get(f"/api/imports/{digest}/exports/ports.csv")

    assert imported.status_code == 200
    assert history.status_code == 200
    assert history.json()[0]["summary"]["mac_count"] == 1
    assert detail.status_code == 200
    assert detail.json()["analysis"]["hosts"][0]["mac"] == "00:11:22:33:44:55"
    assert raw.content == ROUTE_XML
    assert "open_services" in hosts.text
    assert "protocol,port,port_state" in ports.text
    assert "192.0.2.10" in ports.text
