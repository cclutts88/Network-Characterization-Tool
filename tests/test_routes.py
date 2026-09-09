from __future__ import annotations

import io
import zipfile
from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app
from app.device_configs import DeviceConfigPlan, _interactive_master_args


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


def test_global_no_strike_is_applied_to_packages_and_requires_confirmed_removal():
    body = {
        "name": "Protected Baseline",
        "created_by": "analyst01",
        "profile": "standard",
        "terrain": [{"name": "Protected", "targets": ["192.0.2.0/30"]}],
        "no_strike_mode": "none",
        "no_strike": [],
        "chunk_size": 16,
    }
    with TestClient(app) as client:
        added = client.post(
            "/api/safety/no-strike",
            json={"entries": ["192.0.2.1"], "changed_by": "safety-officer"},
        )
        package = client.post("/api/packages", json=body)

        assert added.status_code == 201
        assert added.json()["entries"] == ["192.0.2.1/32"]
        assert package.status_code == 200
        with zipfile.ZipFile(io.BytesIO(package.content)) as archive:
            targets = archive.read("targets/001-Protected.txt").decode().splitlines()
            no_strike = archive.read("no-strike.txt").decode().splitlines()
        assert "192.0.2.1" not in targets
        assert no_strike == ["192.0.2.1"]

        challenge = client.post(
            "/api/safety/no-strike/remove-challenge", json=["192.0.2.1/32"]
        )
        rejected = client.post(
            "/api/safety/no-strike/remove",
            json={
                "entries": ["192.0.2.1/32"],
                "changed_by": "safety-officer",
                "confirmation": "WRONG",
            },
        )
        removed = client.post(
            "/api/safety/no-strike/remove",
            json={
                "entries": ["192.0.2.1/32"],
                "changed_by": "safety-officer",
                "confirmation": challenge.json()["challenge"],
            },
        )

    assert challenge.status_code == 200
    assert rejected.status_code == 403
    assert removed.status_code == 200
    assert removed.json()["entries"] == []


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
    assert "fping -a -f" in linux_script
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


def device_password_plan() -> dict:
    return {
        "operator": "analyst01",
        "reason": "Authorized configuration baseline",
        "originating_host": "collector01",
        "vendor": "vyos",
        "device_type": "router",
        "device_address": "192.0.2.1",
        "username": "admin",
        "ssh_port": 22,
        "key_path": None,
        "authentication_mode": "password_prompt",
        "accountability_interface": "eth0",
    }


def test_interactive_device_preview_starts_with_plain_ssh_and_never_contains_a_password():
    with TestClient(app) as client:
        response = client.post("/api/device-configs/preview", json=device_password_plan())

    assert response.status_code == 200
    data = response.json()
    assert data["ssh_command"].endswith("admin@192.0.2.1")
    assert "BatchMode=yes" not in data["ssh_command"]
    assert data["authentication_mode"] == "password_prompt"
    assert "password" not in data["ssh_command"].lower()


def test_device_name_labels_the_ip_without_changing_the_ssh_target():
    body = device_password_plan()
    body["device_name"] = "Core Router"
    with TestClient(app) as client:
        response = client.post("/api/device-configs/preview", json=body)

    assert response.status_code == 200
    data = response.json()
    assert data["device_name"] == "Core Router"
    assert data["device_address"] == "192.0.2.1"
    assert data["ssh_command"].endswith("admin@192.0.2.1")
    assert data["local_output_name"].startswith("Core-Router-")


def test_device_preview_appends_auditable_operator_commands_and_describes_cleanup():
    body = device_password_plan()
    body["additional_commands"] = ["show arp", "show lldp neighbors | include edge"]
    with TestClient(app) as client:
        response = client.post("/api/device-configs/preview", json=body)

    assert response.status_code == 200
    data = response.json()
    assert data["commands"][-2:] == body["additional_commands"]
    assert data["additional_commands"] == body["additional_commands"]
    assert "delete the remote file" in data["cleanup_plan"]


def test_device_preview_rejects_configuration_and_shell_control_commands():
    for command in ("configure", "show version; reboot", "show version | sh"):
        body = device_password_plan()
        body["additional_commands"] = [command]
        with TestClient(app) as client:
            response = client.post("/api/device-configs/preview", json=body)

        assert response.status_code == 422


def test_interactive_password_workflow_requires_https_before_starting_ssh():
    with TestClient(app) as client:
        response = client.post("/api/device-configs/interactive/start", json=device_password_plan())

    assert response.status_code == 400
    assert "HTTPS" in response.json()["detail"]


def test_interactive_ssh_uses_the_pty_as_its_controlling_terminal():
    plan = DeviceConfigPlan.model_validate(device_password_plan())
    command = _interactive_master_args(plan, Path("/tmp/control.sock"))

    assert command[:3] == ["setsid", "--ctty", "ssh"]
    assert "PreferredAuthentications=keyboard-interactive,password" in command
    assert command[-1] == "admin@192.0.2.1"


def test_device_page_has_one_time_password_dialog_and_history_presets():
    with TestClient(app) as client:
        response = client.get("/device-config")

    assert response.status_code == 200
    assert 'autocomplete="new-password"' in response.text
    assert "Start SSH and collect" in response.text
    assert "Use preset" in response.text
    assert "Additional read-only commands" in response.text
    assert "Cleanup status" in response.text
    assert "Device name (optional)" in response.text
    assert "Choose a device found by Nmap" in response.text
    assert "loadDiscoveredDevices" in response.text
    assert "credentials_stored" not in response.text
