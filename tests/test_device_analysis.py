from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from app.device_analysis import analyze_device_collection, compare_device_analyses
from app.main import app
from app.poc import RUNS_DIR_NAME, insert_scan_run_manifest
from app.saved_networks import SavedNetworkCreate, create_saved_network


def make_collection(config_dir: Path, run_id: str, config: str) -> None:
    run_dir = config_dir / run_id
    run_dir.mkdir(parents=True)
    (run_dir / "manifest.json").write_text(
        json.dumps(
            {
                "run_id": run_id,
                "status": "uploaded",
                "operation": "manual_upload",
                "device_name": "Edge Firewall",
                "device_address": "192.0.2.10",
                "vendor": "cisco",
                "device_type": "firewall",
                "operator": "analyst",
                "reason": "authorized test",
                "originating_host": "nct-test",
                "created_at": "2026-09-11T12:00:00+00:00",
                "completed_at": "2026-09-11T12:01:00+00:00",
            }
        ),
        encoding="utf-8",
    )
    (run_dir / "uploaded-edge-config.txt").write_text(config, encoding="utf-8")


CURRENT_CONFIG = """interface GigabitEthernet0/0
 description OUTSIDE
 ip address 192.0.2.10 255.255.255.0
interface GigabitEthernet0/1
 description USERS_LAN
 ip address 10.80.0.1 255.255.255.0
ip route 0.0.0.0 0.0.0.0 192.0.2.1
ip route 10.90.0.0 255.255.0.0 10.80.0.2
ip route 10.90.0.0 255.255.0.0 10.80.0.3
access-list 101 permit tcp any host 10.80.0.10 eq 443
ip nat inside source list 1 interface GigabitEthernet0/0 overload
object network APP_SERVER
 host 10.80.0.10
"""


BASELINE_CONFIG = """interface GigabitEthernet0/0
 description OUTSIDE
 ip address 192.0.2.10 255.255.255.0
interface GigabitEthernet0/1
 description USERS_LAN
 ip address 10.80.0.254 255.255.255.0
ip route 0.0.0.0 0.0.0.0 192.0.2.1
access-list 101 permit tcp any host 10.80.0.20 eq 443
object network OLD_SERVER
 host 10.80.0.20
"""


def add_nmap_run(db_path: Path, data_dir: Path) -> str:
    run_id = "c" * 32
    manifest = {
        "run_id": run_id,
        "created_at": "2026-09-11T11:00:00+00:00",
        "completed_at": "2026-09-11T11:05:00+00:00",
        "status": "completed",
        "operator": "analyst",
        "reason": "authorized test",
        "originating_host": "nct-test",
        "interface": "eth0",
        "profile": "safe",
        "display_name": "Users LAN verification",
    }
    insert_scan_run_manifest(manifest, db_path=db_path)
    run_dir = data_dir / RUNS_DIR_NAME / run_id
    run_dir.mkdir(parents=True)
    (run_dir / "scan.xml").write_text(
        """<nmaprun><host><status state="up"/><address addr="10.80.0.10" addrtype="ipv4"/><hostnames><hostname name="app01"/></hostnames><ports><port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port></ports></host></nmaprun>""",
        encoding="utf-8",
    )
    return run_id


def test_device_analysis_summarizes_and_correlates_retained_evidence(tmp_path):
    config_dir = tmp_path / "device-configs"
    data_dir = tmp_path / "data"
    db_path = data_dir / "nct.db"
    run_id = "a" * 32
    make_collection(config_dir, run_id, CURRENT_CONFIG)
    create_saved_network(
        SavedNetworkCreate(
            name="Users LAN", cidr="10.80.0.0/24", created_by="analyst"
        ),
        db_path,
    )
    nmap_run_id = add_nmap_run(db_path, data_dir)

    result = analyze_device_collection(
        run_id, config_dir=config_dir, db_path=db_path, data_dir=data_dir
    )

    assert result["counts"]["default_routes"] == 1
    assert result["counts"]["next_hops"] == 3
    assert result["counts"]["multipath_destinations"] == 1
    assert result["route_analysis"]["protocol_counts"]["static"] == 3
    assert result["saved_network_correlations"][0]["confidence"] == "high"
    assert "parsed policy, NAT, or object evidence" in result["saved_network_correlations"][0]["provenance"]
    host = result["nmap_host_correlations"][0]
    assert host["ip"] == "10.80.0.10"
    assert host["confidence"] == "high"
    assert host["sources"][0]["url"].endswith(f"/{nmap_run_id}/artifacts/xml")
    assert host["policy_evidence"]
    assert result["counts"]["network_objects"] == 2
    assert result["evidence"][-1]["filename"] == "manifest.json"


def test_device_collection_comparison_covers_interface_route_and_policy_changes(tmp_path):
    config_dir = tmp_path / "device-configs"
    data_dir = tmp_path / "data"
    db_path = data_dir / "nct.db"
    before_id, after_id = "b" * 32, "a" * 32
    make_collection(config_dir, before_id, BASELINE_CONFIG)
    make_collection(config_dir, after_id, CURRENT_CONFIG)

    before = analyze_device_collection(
        before_id, config_dir=config_dir, db_path=db_path, data_dir=data_dir
    )
    after = analyze_device_collection(
        after_id, config_dir=config_dir, db_path=db_path, data_dir=data_dir
    )
    result = compare_device_analyses(before, after)

    assert result["identity_mismatch"] is False
    assert result["summary"]["interfaces_changed"] == 1
    assert result["interfaces_changed"][0]["name"] == "GigabitEthernet0/1"
    assert result["summary"]["routes_added"] == 2
    assert result["summary"]["firewall_acl_added"] == 1
    assert result["summary"]["firewall_acl_removed"] == 1
    assert result["summary"]["nat_added"] == 1
    assert result["summary"]["network_objects_added"] >= 1
    assert result["policy_changes"]["network_objects_removed"]


def test_device_analysis_routes_use_runtime_storage_paths(tmp_path, monkeypatch):
    config_dir = tmp_path / "device-configs"
    data_dir = tmp_path / "data"
    db_path = data_dir / "nct.db"
    run_id = "a" * 32
    make_collection(config_dir, run_id, CURRENT_CONFIG)
    monkeypatch.setattr("app.device_analysis.CONFIG_DIR", config_dir)
    monkeypatch.setattr("app.device_analysis.DATA_DIR", data_dir)
    monkeypatch.setattr("app.device_analysis.DB_PATH", db_path)

    with TestClient(app) as client:
        analysis = client.get(f"/api/device-analysis/{run_id}")
        comparison = client.get(
            f"/api/device-analysis/compare?before={run_id}&after={run_id}"
        )

    assert analysis.status_code == 200
    assert analysis.json()["counts"]["routes"] == 3
    assert comparison.status_code == 200
    assert not any(comparison.json()["summary"].values())
