from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from app.database import connect_database


EXTERNAL_WAN_ROLES = {
    "primary": "external_wan_gateway",
    "secondary": "external_wan_gateway_secondary",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def init_network_semantics_storage(db_path: Path) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with connect_database(db_path) as db:
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
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS network_wan_interfaces (
                role TEXT NOT NULL,
                node_id TEXT NOT NULL,
                interface_name TEXT NOT NULL,
                position INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (role, interface_name)
            )
            """
        )
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS network_environment_settings (
                setting TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                changed_at TEXT NOT NULL,
                changed_by TEXT NOT NULL
            )
            """
        )
        columns = {
            str(row[1])
            for row in db.execute("PRAGMA table_info(network_wan_interfaces)").fetchall()
        }
        if "position" not in columns:
            db.execute(
                "ALTER TABLE network_wan_interfaces "
                "ADD COLUMN position INTEGER NOT NULL DEFAULT 0"
            )
        # Older NCT builds only write the parent table. These triggers make an
        # older single-interface change authoritative during rollback by
        # removing child rows it cannot know how to update. The current writer
        # performs its parent upsert first and then recreates the selected rows.
        db.execute(
            """CREATE TRIGGER IF NOT EXISTS network_semantics_wan_insert
               AFTER INSERT ON network_semantics
               BEGIN
                   DELETE FROM network_wan_interfaces WHERE role = NEW.role;
               END"""
        )
        db.execute(
            """CREATE TRIGGER IF NOT EXISTS network_semantics_wan_update
               AFTER UPDATE OF node_id, interface_name ON network_semantics
               BEGIN
                   DELETE FROM network_wan_interfaces WHERE role = NEW.role;
               END"""
        )
        db.execute(
            """CREATE TRIGGER IF NOT EXISTS network_semantics_wan_delete
               AFTER DELETE ON network_semantics
               BEGIN
                   DELETE FROM network_wan_interfaces WHERE role = OLD.role;
               END"""
        )


def _interface_names_for_gateway(
    db_path: Path, role: str, node_id: str, legacy_name: str
) -> list[str]:
    init_network_semantics_storage(db_path)
    with connect_database(db_path) as db:
        rows = db.execute(
            """SELECT interface_name FROM network_wan_interfaces
               WHERE role = ? AND node_id = ?
               ORDER BY position, interface_name COLLATE NOCASE""",
            (role, node_id),
        ).fetchall()
    names = [str(row[0]) for row in rows if str(row[0]).strip()]
    # An older NCT build knows only the legacy parent column. If it changed the
    # selection during a rollback, stale child rows from a newer build remain.
    # The legacy value is also written by every new multi-interface save, so a
    # mismatch is reliable evidence that the older writer made a later change.
    if names and legacy_name.strip() and legacy_name.strip() not in names:
        return [legacy_name.strip()]
    if not names and legacy_name.strip():
        names = [legacy_name.strip()]
    return names


def get_external_wan_gateway(db_path: Path) -> dict | None:
    init_network_semantics_storage(db_path)
    with connect_database(db_path) as db:
        row = db.execute(
            """SELECT node_id, device_name, device_address, interface_name,
                      changed_at, changed_by
               FROM network_semantics WHERE role = 'external_wan_gateway'"""
        ).fetchone()
    if row is None:
        return None
    interface_names = _interface_names_for_gateway(
        db_path, "external_wan_gateway", row[0], row[3]
    )
    return {
        "role": "external_wan_gateway",
        "node_id": row[0],
        "device_name": row[1],
        "device_address": row[2],
        "interface_name": row[3],
        "interface_names": interface_names,
        "changed_at": row[4],
        "changed_by": row[5],
    }


def get_external_wan_gateways(db_path: Path) -> list[dict]:
    """Return the shared WAN gateways in stable primary/secondary order."""
    gateways: list[dict] = []
    primary = get_external_wan_gateway(db_path)
    if primary:
        gateways.append({**primary, "slot": "primary"})
    init_network_semantics_storage(db_path)
    with connect_database(db_path) as db:
        row = db.execute(
            """SELECT node_id, device_name, device_address, interface_name,
                      changed_at, changed_by
               FROM network_semantics
               WHERE role = 'external_wan_gateway_secondary'"""
        ).fetchone()
    if row is not None:
        interface_names = _interface_names_for_gateway(
            db_path, "external_wan_gateway_secondary", row[0], row[3]
        )
        gateways.append({
            "role": "external_wan_gateway_secondary",
            "slot": "secondary",
            "node_id": row[0],
            "device_name": row[1],
            "device_address": row[2],
            "interface_name": row[3],
            "interface_names": interface_names,
            "changed_at": row[4],
            "changed_by": row[5],
        })
    return gateways


def get_air_gapped_designation(db_path: Path) -> dict:
    """Return the shared operator designation for an intentionally isolated network."""
    init_network_semantics_storage(db_path)
    with connect_database(db_path) as db:
        row = db.execute(
            """SELECT value, changed_at, changed_by
               FROM network_environment_settings WHERE setting = 'air_gapped'"""
        ).fetchone()
    return {
        "air_gapped": bool(row and str(row[0]).casefold() == "true"),
        "changed_at": row[1] if row else None,
        "changed_by": row[2] if row else None,
    }


def set_air_gapped_designation(
    db_path: Path, *, air_gapped: bool, changed_by: str
) -> dict:
    """Persist a shared air-gap designation without changing retained evidence."""
    changed_at = utc_now()
    init_network_semantics_storage(db_path)
    with connect_database(db_path) as db:
        db.execute(
            """
            INSERT INTO network_environment_settings (
                setting, value, changed_at, changed_by
            ) VALUES ('air_gapped', ?, ?, ?)
            ON CONFLICT(setting) DO UPDATE SET
                value = excluded.value,
                changed_at = excluded.changed_at,
                changed_by = excluded.changed_by
            """,
            ("true" if air_gapped else "false", changed_at, changed_by.strip()),
        )
    return get_air_gapped_designation(db_path)


def set_external_wan_gateway(
    db_path: Path,
    *,
    node_id: str,
    device_name: str,
    device_address: str,
    changed_by: str,
    interface_name: str = "",
    interface_names: list[str] | None = None,
    slot: str = "primary",
) -> dict:
    if slot not in EXTERNAL_WAN_ROLES:
        raise ValueError("WAN gateway slot must be primary or secondary")
    role = EXTERNAL_WAN_ROLES[slot]
    if interface_names is not None and len(interface_names) > 32:
        raise ValueError("No more than 32 WAN interfaces can be selected")
    selected_names = []
    for value in interface_names or []:
        clean = str(value).strip()
        if len(clean) > 255:
            raise ValueError("WAN interface names cannot exceed 255 characters")
        if clean and clean not in selected_names:
            selected_names.append(clean)
    legacy_name = interface_name.strip()
    if len(legacy_name) > 255:
        raise ValueError("WAN interface names cannot exceed 255 characters")
    if not selected_names and legacy_name:
        selected_names = [legacy_name]
    legacy_name = selected_names[0] if selected_names else ""
    changed_at = utc_now()
    init_network_semantics_storage(db_path)
    with connect_database(db_path) as db:
        db.execute(
            """
            INSERT INTO network_semantics (
                role, node_id, device_name, device_address, interface_name,
                changed_at, changed_by
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(role) DO UPDATE SET
                node_id = excluded.node_id,
                device_name = excluded.device_name,
                device_address = excluded.device_address,
                interface_name = excluded.interface_name,
                changed_at = excluded.changed_at,
                changed_by = excluded.changed_by
            """,
            (
                role, node_id.strip(), device_name.strip(), device_address.strip(),
                legacy_name, changed_at, changed_by.strip(),
            ),
        )
        db.execute("DELETE FROM network_wan_interfaces WHERE role = ?", (role,))
        db.executemany(
            """INSERT INTO network_wan_interfaces (
                   role, node_id, interface_name, position
               ) VALUES (?, ?, ?, ?)""",
            [
                (role, node_id.strip(), name, position)
                for position, name in enumerate(selected_names)
            ],
        )
        other_role = EXTERNAL_WAN_ROLES[
            "secondary" if slot == "primary" else "primary"
        ]
        db.execute(
            "DELETE FROM network_semantics WHERE role = ? AND node_id = ?",
            (
                other_role,
                node_id.strip(),
            ),
        )
        db.execute(
            "DELETE FROM network_wan_interfaces WHERE role = ? AND node_id = ?",
            (other_role, node_id.strip()),
        )
    if slot == "primary":
        return get_external_wan_gateway(db_path)
    return next(
        gateway for gateway in get_external_wan_gateways(db_path)
        if gateway["slot"] == slot
    )


def clear_external_wan_gateway(db_path: Path, slot: str = "primary") -> dict:
    if slot not in EXTERNAL_WAN_ROLES:
        raise ValueError("WAN gateway slot must be primary or secondary")
    role = EXTERNAL_WAN_ROLES[slot]
    init_network_semantics_storage(db_path)
    with connect_database(db_path) as db:
        removed = db.execute(
            "DELETE FROM network_semantics WHERE role = ?", (role,)
        ).rowcount
        db.execute("DELETE FROM network_wan_interfaces WHERE role = ?", (role,))
    return {"cleared": bool(removed), "role": role, "slot": slot}


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
    address_identities = {
        value for value in (gateway_address, node_address) if value
    }
    if address_identities:
        return address in address_identities
    return bool(gateway_name and name == gateway_name)


def apply_external_gateway_role(
    device_analyses: list[dict], gateway: dict | None
) -> list[dict]:
    """Mark the analyst-selected outside interface as semantic reach evidence."""
    if not gateway:
        return device_analyses
    for analysis in device_analyses:
        if not gateway_matches_analysis(gateway, analysis):
            continue
        interface_names = [
            str(value) for value in gateway.get("interface_names") or [] if str(value)
        ]
        interface_name = str(gateway.get("interface_name") or "")
        if not interface_names and interface_name:
            interface_names = [interface_name]
        interfaces = analysis.get("interfaces") or []
        matched = False
        matched_names: list[str] = []
        for interface in interfaces:
            if interface_names and str(interface.get("name") or "") not in interface_names:
                continue
            interface["role"] = "external"
            interface["role_source"] = "analyst_map_designation"
            matched = True
            name = str(interface.get("name") or "")
            if name and name not in matched_names:
                matched_names.append(name)
        analysis["external_wan_gateway"] = {
            **gateway,
            "interface_matched": matched,
            "matched_interface_names": matched_names,
            "unmatched_interface_names": [
                name for name in interface_names if name not in matched_names
            ],
        }
        break
    return device_analyses
