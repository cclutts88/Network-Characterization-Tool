from __future__ import annotations

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
