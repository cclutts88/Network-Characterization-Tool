from __future__ import annotations

import json
import sys

import pytest
from fastapi.testclient import TestClient

from app.device_configs import (
    _collect_cisco_command_outputs,
    _limit_retained_collection_file,
    _run_cisco_command_sequence,
    _run_cisco_command_sequence_to_file,
    artifact_records,
    delete_device_collection,
    device_collection_directory,
    device_collection_summary,
)
from app.poc import issue_delete_challenge
from app.main import app


SAMPLE_CONFIG = """interface GigabitEthernet0/1
 description USERS
 ip address 10.80.0.1 255.255.255.0
ip route 0.0.0.0 0.0.0.0 192.0.2.1
Internet 10.80.0.2 5 0011.2233.4455 ARPA GigabitEthernet0/1
vlan 80
 name USERS
interface GigabitEthernet0/2
 switchport mode access
 switchport access vlan 80
 spanning-tree portfast
 channel-group 1 mode active
access-list 101 permit tcp any host 10.80.0.10 eq 443
ip nat inside source list 1 interface GigabitEthernet0/0 overload
object network WEB_SERVER
 host 10.80.0.10
"""


def test_uploaded_collection_does_not_require_a_reason_note(tmp_path, monkeypatch):
    from app import device_configs

    monkeypatch.setattr(device_configs, "CONFIG_DIR", tmp_path / "device-configs")
    with TestClient(app) as client:
        response = client.post(
            "/api/device-configs/upload",
            data={
                "operator": "analyst",
                "originating_host": "nct-test",
                "vendor": "cisco",
                "device_type": "router",
                "device_address": "192.0.2.10",
            },
            files={"result_file": ("router.txt", SAMPLE_CONFIG, "text/plain")},
        )

    assert response.status_code == 200
    assert response.json()["reason"] == ""


def make_collection(config_dir, run_id="d" * 32):
    run_dir = config_dir / run_id
    run_dir.mkdir(parents=True)
    (run_dir / "manifest.json").write_text(
        json.dumps(
            {
                "run_id": run_id,
                "status": "uploaded",
                "device_name": "Distribution Router",
                "device_address": "192.0.2.10",
                "commands": ["show running-config", "show ip route"],
            }
        )
    )
    (run_dir / "uploaded-router-config.txt").write_text(SAMPLE_CONFIG)
    return run_dir


def test_structured_collection_summary_parses_review_sections(tmp_path):
    config_dir = tmp_path / "device-configs"
    make_collection(config_dir)

    result = device_collection_summary("d" * 32, config_dir=config_dir)

    assert result["source_filename"] == "uploaded-router-config.txt"
    assert result["counts"]["interfaces"] == 2
    assert result["interfaces"][0]["address"] == "10.80.0.1/24"
    assert result["counts"]["routes"] == 1
    assert result["routes"][0]["network"] == "0.0.0.0/0"
    assert result["routes"][0]["route_type"] == "default"
    assert result["neighbors"][0]["ip"] == "10.80.0.2"
    assert result["vlans"][0]["evidence"] == "vlan 80"
    assert result["counts"]["switching"] >= 4
    assert any("switchport access vlan 80" in item["evidence"] for item in result["switching"])
    assert any("channel-group 1" in item["evidence"] for item in result["switching"])
    assert result["counts"]["switch_ports"] == 1
    assert result["switch_detail"]["ports"][0]["interface"] == "GigabitEthernet0/2"
    assert result["switch_detail"]["ports"][0]["access_vlan"] == 80
    assert result["command_results"][0]["status"] == "not_individually_reported"
    assert "access-list 101" in result["firewall_acl"][0]["evidence"]
    assert "ip nat inside" in result["nat"][0]["evidence"]
    assert result["counts"]["network_objects"] == 2
    assert result["network_objects"][0]["evidence"] == "object network WEB_SERVER"
    assert result["commands"] == ["show running-config", "show ip route"]


def test_collection_summary_parses_cisco_show_access_lists_output(tmp_path):
    config_dir = tmp_path / "device-configs"
    run_dir = make_collection(config_dir, "a" * 32)
    (run_dir / "uploaded-router-config.txt").write_text(
        """Extended IP access list USERS_TO_SERVERS
    10 permit tcp 10.80.0.0 0.0.0.255 host 10.90.0.10 eq 443
    20 deny ip any any
"""
    )

    result = device_collection_summary("a" * 32, config_dir=config_dir)

    assert result["firewall_acl"][0]["evidence"] == (
        "Extended IP access list USERS_TO_SERVERS"
    )
    assert [rule["sequence"] for rule in result["vendor_policy"]["rules"]] == [10, 20]


def test_collection_summary_retains_routes_beyond_legacy_500_item_limit(tmp_path):
    config_dir = tmp_path / "device-configs"
    run_dir = make_collection(config_dir, "c" * 32)
    route_lines = [
        f"ip route 10.{index // 256}.{index % 256}.0 255.255.255.0 192.0.2.1"
        for index in range(600)
    ]
    (run_dir / "uploaded-router-config.txt").write_text("\n".join(route_lines))

    result = device_collection_summary("c" * 32, config_dir=config_dir)

    assert result["counts"]["routes"] == 600
    assert len(result["routes"]) == 600
    assert result["routes"][-1]["network"] == "10.2.87.0/24"


def test_unifi_saved_rules_are_classified_by_iptables_table(tmp_path):
    config_dir = tmp_path / "device-configs"
    run_dir = make_collection(config_dir, "b" * 32)
    (run_dir / "uploaded-router-config.txt").write_text(
        """*nat
:PREROUTING ACCEPT [0:0]
-A POSTROUTING -o eth9 -j MASQUERADE
COMMIT
*filter
:INPUT ACCEPT [0:0]
:FORWARD DROP [0:0]
-A FORWARD -s 10.80.0.0/24 -o eth9 -j ACCEPT
COMMIT
create USERS hash:net family inet
add USERS 10.80.0.0/24
"""
    )

    result = device_collection_summary("b" * 32, config_dir=config_dir)

    assert any("-A FORWARD" in item["evidence"] for item in result["firewall_acl"])
    assert any("MASQUERADE" in item["evidence"] for item in result["nat"])
    forward = next(item for item in result["firewall_acl"] if "-A FORWARD" in item["evidence"])
    assert forward | {
        "table": "filter",
        "chain": "FORWARD",
        "rule_order": 1,
        "action": "ACCEPT",
        "source": "10.80.0.0/24",
    } == forward
    masquerade = next(item for item in result["nat"] if "MASQUERADE" in item["evidence"])
    assert masquerade | {
        "table": "nat",
        "chain": "POSTROUTING",
        "rule_order": 1,
        "action": "MASQUERADE",
    } == masquerade
    assert {item["evidence"] for item in result["network_objects"]} >= {
        "create USERS hash:net family inet", "add USERS 10.80.0.0/24"
    }
    assert result["counts"]["policy_sets"] == 1
    assert result["counts"]["policy_set_members"] == 1
    assert result["counts"]["network_objects_total"] == 2
    assert result["iptables_policy"]["ipsets"][0]["members"][0]["value"] == "10.80.0.0/24"


def test_large_streamed_collection_file_is_bounded_and_reports_truncation(tmp_path, monkeypatch):
    monkeypatch.setattr("app.device_configs.MAX_RETAINED_COLLECTION_BYTES", 10)
    retained = tmp_path / "retained.txt"
    retained.write_text("0123456789extra")

    truncated = _limit_retained_collection_file(retained)

    assert truncated is True
    assert retained.read_text() == "0123456789"


def test_collection_summary_reads_routes_after_the_previous_five_megabyte_boundary(tmp_path):
    config_dir = tmp_path / "device-configs"
    run_dir = make_collection(config_dir, "9" * 32)
    padding_line = "! " + ("x" * 1021) + "\n"
    evidence = SAMPLE_CONFIG + (padding_line * 5121) + "ip route 203.0.113.0 255.255.255.0 192.0.2.2\n"
    assert len(evidence.encode()) > 5 * 1024 * 1024
    (run_dir / "uploaded-router-config.txt").write_text(evidence)

    result = device_collection_summary("9" * 32, config_dir=config_dir)

    assert result["configuration_truncated"] is False
    assert result["counts"]["routes"] == 2
    assert result["routes"][-1]["network"] == "203.0.113.0/24"


def test_cisco_collection_runs_one_session_and_requires_running_config(monkeypatch):
    calls = []

    def collected(args, commands):
        calls.append((args, commands))
        return (
            {
                "show version": "Cisco IOS XE Software, Version 17.12",
                "show running-config": "hostname mako-eng-core-rtr\ninterface GigabitEthernet1",
            },
            {"terminal length 0", "show version", "show running-config"},
            "",
            0,
            None,
        )

    monkeypatch.setattr("app.device_configs._collect_cisco_command_outputs", collected)

    output, stderr, exit_code, failed, fatal_error = _run_cisco_command_sequence(
        ["ssh", "admin@192.0.2.1"],
        ["terminal length 0", "show version", "show running-config"],
    )

    assert len(calls) == 1
    assert calls[0][0] == ["ssh", "admin@192.0.2.1"]
    assert calls[0][1] == ["terminal length 0", "show version", "show running-config"]
    assert "===== show version =====" in output
    assert "===== show running-config =====" in output
    assert "hostname mako-eng-core-rtr" in output
    assert "mako#show running-config" not in output
    assert stderr == ""
    assert exit_code == 0
    assert failed == []
    assert fatal_error is None


def test_cisco_collection_never_reports_success_with_blank_running_config(monkeypatch):
    def collected(_args, _commands):
        return (
            {"show version": "Cisco IOS XE Software, Version 17.12" * 2, "show running-config": ""},
            {"terminal length 0", "show version", "show running-config"},
            "",
            0,
            None,
        )

    monkeypatch.setattr("app.device_configs._collect_cisco_command_outputs", collected)

    output, stderr, exit_code, failed, fatal_error = _run_cisco_command_sequence(
        ["ssh", "admin@192.0.2.1"],
        ["terminal length 0", "show version", "show running-config"],
    )

    assert "===== show version =====" in output
    assert stderr == ""
    assert exit_code == 0
    assert failed == ["show running-config"]
    assert "running configuration" in fatal_error


def test_cisco_collection_never_reports_success_after_unclean_ssh_exit(monkeypatch):
    def collected(_args, _commands):
        return (
            {
                "show version": "Cisco IOS XE Software, Version 17.12",
                "show running-config": "hostname mako-eng-core-rtr\ninterface GigabitEthernet1",
            },
            {"terminal length 0", "show version", "show running-config"},
            "",
            255,
            None,
        )

    monkeypatch.setattr("app.device_configs._collect_cisco_command_outputs", collected)

    _output, stderr, exit_code, failed, fatal_error = _run_cisco_command_sequence(
        ["ssh", "admin@192.0.2.1"],
        ["terminal length 0", "show version", "show running-config"],
    )

    assert stderr == ""
    assert exit_code == 255
    assert failed == ["show version", "show running-config"]
    assert "clean collection completion" in fatal_error


def test_cisco_collection_streams_cleaned_commands_to_retained_file(tmp_path, monkeypatch):
    calls = []

    def collected(args, commands):
        calls.append((args, commands))
        return (
            {
                "show version": "Cisco IOS XE Software, Version 17.12",
                "show running-config": "hostname mako-eng-core-rtr\ninterface GigabitEthernet1",
                "show ip route": "S 10.0.0.0/8 [1/0] via 192.0.2.1",
            },
            {"terminal length 0", "show version", "show running-config", "show ip route"},
            "",
            0,
            None,
        )

    monkeypatch.setattr("app.device_configs._collect_cisco_command_outputs", collected)
    retained = tmp_path / "router-config.txt"

    stderr, exit_code, failed, fatal_error, truncated = _run_cisco_command_sequence_to_file(
        ["ssh", "admin@192.0.2.1"],
        ["terminal length 0", "show version", "show running-config", "show ip route"],
        retained,
    )

    output = retained.read_text()
    assert len(calls) == 1
    assert calls[0][1] == [
        "terminal length 0", "show version", "show running-config", "show ip route",
    ]
    assert "===== show ip route =====" in output
    assert "S 10.0.0.0/8 [1/0] via 192.0.2.1" in output
    assert "mako#show ip route" not in output
    assert stderr == ""
    assert exit_code == 0
    assert failed == []
    assert fatal_error is None
    assert truncated is False


def test_cisco_collector_waits_for_each_prompt_before_sending_the_next_command(tmp_path):
    fake_device = tmp_path / "fake_cisco.py"
    fake_device.write_text(
        """import select
import sys
import time

print('mako#', end='', flush=True)
for raw in sys.stdin:
    command = raw.strip()
    print(command, flush=True)
    if command == 'terminal length 0':
        print('Terminal length set', flush=True)
    elif command == 'show version':
        print('Cisco IOS XE Software, Version 17.12', flush=True)
    elif command == 'show running-config':
        print('hostname mako-eng-core-rtr', flush=True)
        print('interface GigabitEthernet1', flush=True)
    elif command == 'show ip route':
        time.sleep(0.15)
        if select.select([sys.stdin], [], [], 0)[0]:
            print('COMMANDS_QUEUED_TOO_EARLY', flush=True)
            break
        for index in range(2000):
            print(f'S 10.{index // 256}.{index % 256}.0/24 via 192.0.2.1', flush=True)
    elif command == 'show access-lists':
        print('Extended IP access list OUTSIDE-IN', flush=True)
        print('10 permit tcp any host 192.0.2.10 eq 443', flush=True)
    elif command == 'exit':
        break
    print('mako#', end='', flush=True)
""",
        encoding="utf-8",
    )

    outputs, responded, transcript, exit_code, error = _collect_cisco_command_outputs(
        [sys.executable, str(fake_device), "admin@192.0.2.1"],
        [
            "terminal length 0",
            "show version",
            "show running-config",
            "show ip route",
            "show access-lists",
        ],
    )

    assert exit_code == 0
    assert error is None
    assert "COMMANDS_QUEUED_TOO_EARLY" not in transcript
    assert "S 10.7.207.0/24 via 192.0.2.1" in outputs["show ip route"]
    assert "Extended IP access list OUTSIDE-IN" in outputs["show access-lists"]
    assert responded == {
        "terminal length 0",
        "show version",
        "show running-config",
        "show ip route",
        "show access-lists",
    }


def test_collection_artifacts_are_not_duplicated_when_upload_matches_config_suffix(tmp_path):
    config_dir = tmp_path / "device-configs"
    run_dir = make_collection(config_dir)

    names = [item["name"] for item in artifact_records("d" * 32, run_dir)]

    assert names.count("uploaded-router-config.txt") == 1


def test_collection_delete_requires_valid_challenge_and_removes_only_that_run(tmp_path):
    config_dir = tmp_path / "device-configs"
    run_dir = make_collection(config_dir)
    other_run = make_collection(config_dir, "e" * 32)
    challenge = issue_delete_challenge("device-collection", "d" * 32)["challenge"]

    with pytest.raises(PermissionError):
        delete_device_collection("d" * 32, "WRONG", config_dir=config_dir)
    assert run_dir.is_dir()

    result = delete_device_collection("d" * 32, challenge, config_dir=config_dir)

    assert result == {"deleted": True, "run_id": "d" * 32}
    assert not run_dir.exists()
    assert other_run.is_dir()


def test_collection_summary_and_delete_routes(tmp_path, monkeypatch):
    config_dir = tmp_path / "device-configs"
    run_id = "a" * 32
    run_dir = make_collection(config_dir, run_id)
    monkeypatch.setattr("app.device_configs.CONFIG_DIR", config_dir)

    with TestClient(app) as client:
        summary = client.get(f"/api/device-configs/{run_id}/summary")
        challenge = client.post(f"/api/device-configs/{run_id}/delete-challenge")
        rejected = client.post(
            f"/api/device-configs/{run_id}/delete", json={"confirmation": "WRONG"}
        )
        deleted = client.post(
            f"/api/device-configs/{run_id}/delete",
            json={"confirmation": challenge.json()["challenge"]},
        )

    assert summary.status_code == 200
    assert summary.json()["counts"]["routes"] == 1
    assert challenge.status_code == 200
    assert rejected.status_code == 400
    assert run_dir.is_dir() is False
    assert deleted.json() == {"deleted": True, "run_id": run_id}


@pytest.mark.parametrize("run_id", ["../escape", "not-a-run", "f" * 31])
def test_collection_directory_rejects_invalid_identifiers(tmp_path, run_id):
    with pytest.raises(ValueError):
        device_collection_directory(run_id, config_dir=tmp_path / "device-configs")
