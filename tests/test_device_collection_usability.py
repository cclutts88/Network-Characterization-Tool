from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from app.device_configs import (
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
    assert result["counts"]["interfaces"] == 1
    assert result["interfaces"][0]["address"] == "10.80.0.1/24"
    assert result["counts"]["routes"] == 1
    assert result["routes"][0]["network"] == "0.0.0.0/0"
    assert result["routes"][0]["route_type"] == "default"
    assert result["neighbors"][0]["ip"] == "10.80.0.2"
    assert result["vlans"][0]["evidence"] == "vlan 80"
    assert result["counts"]["switching"] >= 4
    assert any("switchport access vlan 80" in item["evidence"] for item in result["switching"])
    assert any("channel-group 1" in item["evidence"] for item in result["switching"])
    assert "access-list 101" in result["firewall_acl"][0]["evidence"]
    assert "ip nat inside" in result["nat"][0]["evidence"]
    assert result["counts"]["network_objects"] == 2
    assert result["network_objects"][0]["evidence"] == "object network WEB_SERVER"
    assert result["commands"] == ["show running-config", "show ip route"]


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
