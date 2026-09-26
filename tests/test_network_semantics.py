from __future__ import annotations

import sqlite3

from fastapi.testclient import TestClient

from app.main import _wan_gateway_suggestions, app
from app.network_semantics import (
    apply_external_gateway_role,
    clear_external_wan_gateway,
    get_external_wan_gateway,
    get_external_wan_gateways,
    set_external_wan_gateway,
)


def test_external_wan_gateway_round_trip_and_role_application(tmp_path):
    db_path = tmp_path / "analyzer.db"
    gateway = set_external_wan_gateway(
        db_path,
        node_id="ip:10.0.0.1",
        device_name="edge-wan-rtr",
        device_address="10.0.0.1",
        interface_name="GigabitEthernet0/0",
        changed_by="operator",
    )

    assert get_external_wan_gateway(db_path) == gateway
    analyses = [{
        "device": {
            "name": "edge-wan-rtr",
            "address": "10.0.0.1",
            "type": "router",
        },
        "interfaces": [
            {"name": "GigabitEthernet0/0", "network": "198.51.100.0/24"},
            {"name": "GigabitEthernet0/1", "network": "10.0.0.0/24"},
        ],
    }]

    result = apply_external_gateway_role(analyses, gateway)

    assert result[0]["interfaces"][0]["role"] == "external"
    assert result[0]["interfaces"][0]["role_source"] == "analyst_map_designation"
    assert result[0]["external_wan_gateway"]["interface_matched"] is True
    assert clear_external_wan_gateway(db_path)["cleared"] is True
    assert get_external_wan_gateway(db_path) is None


def test_external_gateway_does_not_mark_a_different_device(tmp_path):
    db_path = tmp_path / "analyzer.db"
    gateway = set_external_wan_gateway(
        db_path,
        node_id="ip:10.0.0.1",
        device_name="edge-wan-rtr",
        device_address="10.0.0.1",
        interface_name="outside",
        changed_by="operator",
    )
    analyses = [{
        "device": {"name": "unrelated", "address": "10.0.0.2", "type": "router"},
        "interfaces": [{"name": "outside", "network": "198.51.100.0/24"}],
    }]

    result = apply_external_gateway_role(analyses, gateway)

    assert "external_wan_gateway" not in result[0]
    assert "role" not in result[0]["interfaces"][0]


def test_primary_and_secondary_wan_gateways_coexist_without_changing_legacy_primary(tmp_path):
    db_path = tmp_path / "analyzer.db"
    primary = set_external_wan_gateway(
        db_path,
        node_id="ip:10.0.0.1",
        device_name="edge-a",
        device_address="10.0.0.1",
        interface_name="outside",
        changed_by="operator",
    )
    secondary = set_external_wan_gateway(
        db_path,
        node_id="ip:10.0.0.2",
        device_name="edge-b",
        device_address="10.0.0.2",
        interface_name="outside",
        changed_by="operator",
        slot="secondary",
    )

    assert get_external_wan_gateway(db_path) == primary
    assert secondary["slot"] == "secondary"
    assert [item["node_id"] for item in get_external_wan_gateways(db_path)] == [
        "ip:10.0.0.1", "ip:10.0.0.2",
    ]
    assert clear_external_wan_gateway(db_path, slot="secondary")["cleared"] is True
    assert get_external_wan_gateway(db_path) == primary


def test_same_device_cannot_fill_both_wan_gateway_slots(tmp_path):
    db_path = tmp_path / "analyzer.db"
    values = {
        "node_id": "ip:10.0.0.1",
        "device_name": "edge-a",
        "device_address": "10.0.0.1",
        "interface_name": "outside",
        "changed_by": "operator",
    }
    set_external_wan_gateway(db_path, **values)
    set_external_wan_gateway(db_path, **values, slot="secondary")

    assert get_external_wan_gateway(db_path) is None
    assert [item["slot"] for item in get_external_wan_gateways(db_path)] == ["secondary"]


def test_multiple_wan_interfaces_round_trip_and_all_are_applied(tmp_path):
    db_path = tmp_path / "analyzer.db"
    gateway = set_external_wan_gateway(
        db_path,
        node_id="ip:198.51.100.2",
        device_name="edge-a",
        device_address="198.51.100.2",
        interface_name="stale-legacy-value",
        interface_names=["eth1", "eth0", "eth1"],
        changed_by="operator",
    )

    assert gateway["interface_name"] == "eth1"
    assert gateway["interface_names"] == ["eth1", "eth0"]
    analyses = [{
        "device": {"name": "edge-a", "address": "198.51.100.2"},
        "interfaces": [
            {"name": "eth0", "network": "198.51.100.0/30"},
            {"name": "eth1", "network": "203.0.113.0/30"},
            {"name": "inside", "network": "10.0.0.0/24"},
        ],
    }]

    result = apply_external_gateway_role(analyses, gateway)

    assert [item.get("role") for item in result[0]["interfaces"]] == [
        "external", "external", None,
    ]
    semantic = result[0]["external_wan_gateway"]
    assert semantic["matched_interface_names"] == ["eth0", "eth1"]
    assert semantic["unmatched_interface_names"] == []


def test_missing_saved_wan_interface_is_reported_without_losing_selection(tmp_path):
    db_path = tmp_path / "analyzer.db"
    gateway = set_external_wan_gateway(
        db_path,
        node_id="ip:198.51.100.2",
        device_name="edge-a",
        device_address="198.51.100.2",
        interface_names=["eth0", "old-uplink"],
        changed_by="operator",
    )
    analyses = [{
        "device": {"name": "edge-a", "address": "198.51.100.2"},
        "interfaces": [{"name": "eth0", "network": "198.51.100.0/30"}],
    }]

    result = apply_external_gateway_role(analyses, gateway)

    assert result[0]["external_wan_gateway"]["unmatched_interface_names"] == [
        "old-uplink"
    ]
    assert get_external_wan_gateway(db_path)["interface_names"] == [
        "eth0", "old-uplink"
    ]


def test_gateway_address_identity_wins_over_duplicate_device_name(tmp_path):
    db_path = tmp_path / "analyzer.db"
    gateway = set_external_wan_gateway(
        db_path,
        node_id="ip:198.51.100.2",
        device_name="edge",
        device_address="198.51.100.2",
        interface_name="outside",
        changed_by="operator",
    )
    analyses = [{
        "device": {"name": "edge", "address": "198.51.100.3"},
        "interfaces": [{"name": "outside"}],
    }]

    result = apply_external_gateway_role(analyses, gateway)

    assert "external_wan_gateway" not in result[0]


def test_external_wan_gateway_api_accepts_multiple_interfaces(tmp_path, monkeypatch):
    db_path = tmp_path / "analyzer.db"
    monkeypatch.setattr("app.main.DB_PATH", db_path)

    with TestClient(app) as client:
        response = client.put(
            "/api/network-semantics/external-wan-gateway",
            json={
                "node_id": "ip:198.51.100.2",
                "device_name": "edge-a",
                "device_address": "198.51.100.2",
                "interface_name": "eth0",
                "interface_names": ["eth0", "eth1", "eth0"],
                "slot": "primary",
            },
        )

    assert response.status_code == 200
    assert response.json()["gateway"]["interface_names"] == ["eth0", "eth1"]


def test_external_wan_gateway_api_uses_stable_hostname_and_ipv6_identities(
    tmp_path, monkeypatch
):
    db_path = tmp_path / "analyzer.db"
    monkeypatch.setattr("app.main.DB_PATH", db_path)

    with TestClient(app) as client:
        hostname = client.put(
            "/api/network-semantics/external-wan-gateway",
            json={
                "node_id": "ip:edge-router.example",
                "device_name": "Edge Router",
                "device_address": "edge-router.example",
                "interface_names": ["pppoe0"],
            },
        )
        ipv6 = client.put(
            "/api/network-semantics/external-wan-gateway",
            json={
                "node_id": "ip:2001:0db8:0000:0000:0000:0000:0000:0001",
                "device_name": "IPv6 Edge",
                "device_address": "2001:0db8:0000:0000:0000:0000:0000:0001",
                "interface_names": ["wan6"],
            },
        )

    assert hostname.status_code == 200
    assert hostname.json()["gateway"]["node_id"] == "device:edge-router"
    assert ipv6.status_code == 200
    assert ipv6.json()["gateway"]["node_id"] == "ip:2001:db8::1"
    assert ipv6.json()["gateway"]["device_address"] == "2001:db8::1"


def test_legacy_single_interface_row_is_read_as_one_item_list(tmp_path):
    db_path = tmp_path / "analyzer.db"
    with sqlite3.connect(db_path) as db:
        db.execute(
            """CREATE TABLE network_semantics (
                   role TEXT PRIMARY KEY, node_id TEXT NOT NULL,
                   device_name TEXT NOT NULL DEFAULT '',
                   device_address TEXT NOT NULL DEFAULT '',
                   interface_name TEXT NOT NULL DEFAULT '',
                   changed_at TEXT NOT NULL, changed_by TEXT NOT NULL
               )"""
        )
        db.execute(
            """INSERT INTO network_semantics VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                "external_wan_gateway", "ip:192.0.2.2", "legacy-edge",
                "192.0.2.2", "outside", "2026-09-26T00:00:00+00:00", "operator",
            ),
        )

    gateway = get_external_wan_gateway(db_path)

    assert gateway["interface_name"] == "outside"
    assert gateway["interface_names"] == ["outside"]


def test_legacy_writer_change_wins_over_stale_multi_interface_rows(tmp_path):
    db_path = tmp_path / "analyzer.db"
    set_external_wan_gateway(
        db_path,
        node_id="ip:192.0.2.2",
        device_name="edge",
        device_address="192.0.2.2",
        interface_names=["wan-a", "wan-b"],
        changed_by="new-build",
    )
    with sqlite3.connect(db_path) as db:
        db.execute(
            """UPDATE network_semantics SET interface_name = ?, changed_by = ?
               WHERE role = 'external_wan_gateway'""",
            ("wan-after-rollback", "old-build"),
        )

    gateway = get_external_wan_gateway(db_path)

    assert gateway["interface_name"] == "wan-after-rollback"
    assert gateway["interface_names"] == ["wan-after-rollback"]


def test_legacy_writer_resaving_same_first_interface_clears_extra_children(tmp_path):
    db_path = tmp_path / "analyzer.db"
    set_external_wan_gateway(
        db_path,
        node_id="ip:192.0.2.2",
        device_name="edge",
        device_address="192.0.2.2",
        interface_names=["wan-a", "wan-b"],
        changed_by="new-build",
    )
    with sqlite3.connect(db_path) as db:
        db.execute(
            """UPDATE network_semantics
               SET node_id = ?, device_name = ?, device_address = ?,
                   interface_name = ?, changed_at = ?, changed_by = ?
               WHERE role = 'external_wan_gateway'""",
            (
                "ip:192.0.2.2", "edge", "192.0.2.2", "wan-a",
                "2026-09-27T00:00:00+00:00", "old-build",
            ),
        )

    gateway = get_external_wan_gateway(db_path)

    assert gateway["interface_names"] == ["wan-a"]


def test_network_wan_suggestions_prefer_device_whose_default_leaves_known_graph():
    devices = [
        {
            "run_id": "core",
            "device": {"name": "Core", "address": "10.0.0.1", "type": "router"},
            "interfaces": [
                {"name": "uplink", "address": "10.0.0.1/30"},
            ],
            "route_analysis": {"default_routes": [
                {"network": "0.0.0.0/0", "via": "10.0.0.2", "interface": "uplink"}
            ]},
            "wan_candidates": [{
                "name": "uplink", "addresses": ["10.0.0.1/30"], "score": 100,
                "confidence": "high", "recommended": True,
                "reasons": ["A retained default route explicitly exits this interface."],
                "evidence": ["ip route 0.0.0.0 0.0.0.0 10.0.0.2"],
            }],
        },
        {
            "run_id": "edge",
            "device": {"name": "Edge", "address": "10.0.0.2", "type": "firewall"},
            "interfaces": [
                {"name": "inside", "address": "10.0.0.2/30"},
                {"name": "outside", "address": "198.51.100.2/30"},
            ],
            "route_analysis": {"default_routes": [
                {"network": "0.0.0.0/0", "via": "198.51.100.1", "interface": "outside"}
            ]},
            "wan_candidates": [{
                "name": "outside", "addresses": ["198.51.100.2/30"], "score": 145,
                "confidence": "high", "recommended": True,
                "reasons": ["A retained default route explicitly exits this interface."],
                "evidence": ["route outside 0.0.0.0 0.0.0.0 198.51.100.1"],
            }],
        },
    ]

    suggestions = _wan_gateway_suggestions(devices)

    assert suggestions[0]["device_name"] == "Edge"
    assert suggestions[0]["recommended"] is True
    core = next(item for item in suggestions if item["device_name"] == "Core")
    assert core["recommended"] is False
    assert any("another pulled device" in reason for reason in core["reasons"])
