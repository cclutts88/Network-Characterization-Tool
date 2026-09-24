from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def init_network_semantics_storage(db_path: Path) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(db_path) as db:
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS network_semantics (
                role TEXT PRIMARY KEY,
                node_id TEXT NOT NULL,
                device_name TEXT NOT NULL DEFAULT '',
                device_address TEXT NOT NULL DEFAULT '',
                interface_name TEXT NOT NULL DEFAULT '',
                changed_at TEXT NOT NULL,
                changed_by TEXT NOT NULL
            )
            """
        )


def get_external_wan_gateway(db_path: Path) -> dict | None:
    init_network_semantics_storage(db_path)
    with sqlite3.connect(db_path) as db:
        row = db.execute(
            """SELECT node_id, device_name, device_address, interface_name,
                      changed_at, changed_by
               FROM network_semantics WHERE role = 'external_wan_gateway'"""
        ).fetchone()
    if row is None:
        return None
    return {
        "role": "external_wan_gateway",
        "node_id": row[0],
        "device_name": row[1],
        "device_address": row[2],
        "interface_name": row[3],
        "changed_at": row[4],
        "changed_by": row[5],
    }


def set_external_wan_gateway(
    db_path: Path,
    *,
    node_id: str,
    device_name: str,
    device_address: str,
    interface_name: str,
    changed_by: str,
) -> dict:
    changed_at = utc_now()
    init_network_semantics_storage(db_path)
    with sqlite3.connect(db_path) as db:
        db.execute(
            """
            INSERT INTO network_semantics (
                role, node_id, device_name, device_address, interface_name,
                changed_at, changed_by
            ) VALUES ('external_wan_gateway', ?, ?, ?, ?, ?, ?)
            ON CONFLICT(role) DO UPDATE SET
                node_id = excluded.node_id,
                device_name = excluded.device_name,
                device_address = excluded.device_address,
                interface_name = excluded.interface_name,
                changed_at = excluded.changed_at,
                changed_by = excluded.changed_by
            """,
            (
                node_id.strip(), device_name.strip(), device_address.strip(),
                interface_name.strip(), changed_at, changed_by.strip(),
            ),
        )
    return get_external_wan_gateway(db_path)


def clear_external_wan_gateway(db_path: Path) -> dict:
    init_network_semantics_storage(db_path)
    with sqlite3.connect(db_path) as db:
        removed = db.execute(
            "DELETE FROM network_semantics WHERE role = 'external_wan_gateway'"
        ).rowcount
    return {"cleared": bool(removed), "role": "external_wan_gateway"}


def gateway_matches_analysis(gateway: dict | None, analysis: dict) -> bool:
    if not gateway:
        return False
    device = analysis.get("device") or {}
    address = str(device.get("address") or "").casefold()
    name = str(device.get("name") or "").casefold()
    gateway_address = str(gateway.get("device_address") or "").casefold()
    gateway_name = str(gateway.get("device_name") or "").casefold()
    node_id = str(gateway.get("node_id") or "")
    node_address = node_id[3:].casefold() if node_id.startswith("ip:") else ""
    return bool(
        (gateway_address and address == gateway_address)
        or (node_address and address == node_address)
        or (gateway_name and name == gateway_name)
    )


def apply_external_gateway_role(
    device_analyses: list[dict], gateway: dict | None
) -> list[dict]:
    """Mark the analyst-selected outside interface as semantic reach evidence."""
    if not gateway:
        return device_analyses
    for analysis in device_analyses:
        if not gateway_matches_analysis(gateway, analysis):
            continue
        interface_name = str(gateway.get("interface_name") or "")
        interfaces = analysis.get("interfaces") or []
        matched = False
        for interface in interfaces:
            if interface_name and str(interface.get("name") or "") != interface_name:
                continue
            interface["role"] = "external"
            interface["role_source"] = "analyst_map_designation"
            matched = True
            if interface_name:
                break
        analysis["external_wan_gateway"] = {**gateway, "interface_matched": matched}
        break
    return device_analyses
