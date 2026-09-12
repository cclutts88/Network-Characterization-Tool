from __future__ import annotations

from datetime import datetime, timezone
import ipaddress
import re
import sqlite3
from pathlib import Path


UNKNOWN_OS = {"", "unknown", "unknown os", "unclassified", "none", "n/a"}


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def normalize_mac(value: object) -> str | None:
    compact = re.sub(r"[^0-9a-f]", "", str(value or "").lower())
    if len(compact) != 12:
        return None
    return ":".join(compact[index:index + 2] for index in range(0, 12, 2))


def normalize_ip(value: object) -> str | None:
    try:
        return str(ipaddress.ip_address(str(value or "").strip()))
    except ValueError:
        return None


def identity_key(ip: object = None, mac: object = None) -> str:
    normalized_mac = normalize_mac(mac)
    if normalized_mac:
        return f"mac:{normalized_mac}"
    normalized_ip = normalize_ip(ip)
    if normalized_ip:
        return f"ip:{normalized_ip}"
    raise ValueError("A valid host IP or MAC address is required")


def init_os_override_storage(db_path: Path) -> None:
    with sqlite3.connect(db_path) as db:
        db.execute(
            """CREATE TABLE IF NOT EXISTS host_os_overrides (
                identity_key TEXT PRIMARY KEY,
                ip TEXT,
                mac TEXT,
                os_name TEXT NOT NULL,
                analyst TEXT NOT NULL,
                reason TEXT NOT NULL,
                scanner_os_at_change TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )"""
        )
        db.execute(
            """CREATE TABLE IF NOT EXISTS host_os_override_audit (
                audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
                identity_key TEXT NOT NULL,
                action TEXT NOT NULL,
                ip TEXT,
                mac TEXT,
                os_name TEXT,
                analyst TEXT NOT NULL,
                reason TEXT NOT NULL,
                scanner_os_at_change TEXT,
                changed_at TEXT NOT NULL
            )"""
        )


def _row(row: sqlite3.Row | None) -> dict | None:
    return dict(row) if row is not None else None


def _clean_required(value: object, label: str, maximum: int) -> str:
    text = str(value or "").strip()
    if not text:
        raise ValueError(f"{label} is required")
    if len(text) > maximum:
        raise ValueError(f"{label} must be {maximum} characters or fewer")
    return text


def set_os_override(
    db_path: Path,
    *,
    ip: object = None,
    mac: object = None,
    os_name: object,
    analyst: object,
    reason: object,
    scanner_os: object = None,
) -> dict:
    key = identity_key(ip, mac)
    normalized_ip, normalized_mac = normalize_ip(ip), normalize_mac(mac)
    clean_os = _clean_required(os_name, "Known operating system", 120)
    clean_analyst = _clean_required(analyst, "Analyst", 100)
    clean_reason = _clean_required(reason, "Reason", 500)
    clean_scanner = str(scanner_os or "").strip()[:240] or None
    changed_at = utc_now()
    init_os_override_storage(db_path)
    with sqlite3.connect(db_path) as db:
        db.row_factory = sqlite3.Row
        existing = db.execute(
            "SELECT created_at FROM host_os_overrides WHERE identity_key = ?", (key,)
        ).fetchone()
        created_at = existing["created_at"] if existing else changed_at
        db.execute(
            """INSERT INTO host_os_overrides (
                identity_key, ip, mac, os_name, analyst, reason,
                scanner_os_at_change, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(identity_key) DO UPDATE SET
                ip=excluded.ip, mac=excluded.mac, os_name=excluded.os_name,
                analyst=excluded.analyst, reason=excluded.reason,
                scanner_os_at_change=excluded.scanner_os_at_change,
                updated_at=excluded.updated_at
            """,
            (
                key, normalized_ip, normalized_mac, clean_os, clean_analyst,
                clean_reason, clean_scanner, created_at, changed_at,
            ),
        )
        db.execute(
            """INSERT INTO host_os_override_audit (
                identity_key, action, ip, mac, os_name, analyst, reason,
                scanner_os_at_change, changed_at
            ) VALUES (?, 'set', ?, ?, ?, ?, ?, ?, ?)""",
            (
                key, normalized_ip, normalized_mac, clean_os, clean_analyst,
                clean_reason, clean_scanner, changed_at,
            ),
        )
        result = dict(db.execute(
            "SELECT * FROM host_os_overrides WHERE identity_key = ?", (key,)
        ).fetchone())
        result["disagrees_with_scanner"] = _disagrees(clean_scanner, clean_os)
        return result


def delete_os_override(
    db_path: Path, key: str, *, analyst: object, reason: object
) -> dict:
    clean_analyst = _clean_required(analyst, "Analyst", 100)
    clean_reason = _clean_required(reason, "Reason", 500)
    init_os_override_storage(db_path)
    with sqlite3.connect(db_path) as db:
        db.row_factory = sqlite3.Row
        existing = db.execute(
            "SELECT * FROM host_os_overrides WHERE identity_key = ?", (key,)
        ).fetchone()
        if existing is None:
            raise KeyError(key)
        changed_at = utc_now()
        db.execute(
            """INSERT INTO host_os_override_audit (
                identity_key, action, ip, mac, os_name, analyst, reason,
                scanner_os_at_change, changed_at
            ) VALUES (?, 'delete', ?, ?, ?, ?, ?, ?, ?)""",
            (
                key, existing["ip"], existing["mac"], existing["os_name"],
                clean_analyst, clean_reason, existing["scanner_os_at_change"],
                changed_at,
            ),
        )
        db.execute("DELETE FROM host_os_overrides WHERE identity_key = ?", (key,))
        return {"status": "deleted", "identity_key": key, "changed_at": changed_at}


def list_os_overrides(db_path: Path) -> list[dict]:
    init_os_override_storage(db_path)
    with sqlite3.connect(db_path) as db:
        db.row_factory = sqlite3.Row
        return [dict(row) for row in db.execute(
            "SELECT * FROM host_os_overrides ORDER BY updated_at DESC, identity_key"
        ).fetchall()]


def os_override_history(db_path: Path, key: str) -> list[dict]:
    init_os_override_storage(db_path)
    with sqlite3.connect(db_path) as db:
        db.row_factory = sqlite3.Row
        return [dict(row) for row in db.execute(
            """SELECT * FROM host_os_override_audit
               WHERE identity_key = ? ORDER BY audit_id DESC""",
            (key,),
        ).fetchall()]


def _meaningful_os(value: object) -> str | None:
    text = str(value or "").strip()
    return text if text.lower() not in UNKNOWN_OS else None


def _disagrees(scanner_os: object, analyst_os: object) -> bool:
    scanner = _meaningful_os(scanner_os)
    analyst = _meaningful_os(analyst_os)
    if not scanner or not analyst:
        return False
    normalized_scanner = re.sub(r"[^a-z0-9]+", " ", scanner.lower()).strip()
    normalized_analyst = re.sub(r"[^a-z0-9]+", " ", analyst.lower()).strip()
    return not (
        normalized_scanner == normalized_analyst
        or normalized_scanner in normalized_analyst
        or normalized_analyst in normalized_scanner
    )


def apply_os_overrides(records: list[dict], db_path: Path) -> list[dict]:
    overrides = list_os_overrides(db_path)
    by_key = {item["identity_key"]: item for item in overrides}
    by_ip = {item["ip"]: item for item in overrides if item.get("ip")}
    for record in records:
        mac = normalize_mac(record.get("mac"))
        ip = normalize_ip(record.get("ip") or record.get("address"))
        override = by_key.get(f"mac:{mac}") if mac else None
        override = override or (by_ip.get(ip) if ip else None)
        scanner_os = record.get("scanner_os") or record.get("os")
        record["scanner_os"] = scanner_os
        if override:
            value = dict(override)
            value["disagrees_with_scanner"] = _disagrees(scanner_os, value["os_name"])
            record["analyst_os_override"] = value
            record["effective_os"] = value["os_name"]
            record["os_display"] = value["os_name"]
            record["os_source"] = "analyst"
            record["os_disagreement"] = value["disagrees_with_scanner"]
        else:
            record.pop("analyst_os_override", None)
            record["effective_os"] = scanner_os
            record["os_source"] = "scanner" if _meaningful_os(scanner_os) else "unclassified"
            record["os_disagreement"] = False
    return records


def apply_analysis_os_overrides(analysis: dict, db_path: Path) -> dict:
    apply_os_overrides(analysis.get("hosts") or [], db_path)
    return analysis
