from __future__ import annotations

import csv
import io
import ipaddress
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path


_HOSTNAME = re.compile(r"^[A-Za-z0-9_](?:[A-Za-z0-9_.-]{0,251}[A-Za-z0-9_])?\.?$")
_IP_HEADERS = {"ip", "ip_address", "ip address", "address", "host_ip"}
_HOST_HEADERS = {"hostname", "host_name", "host name", "name", "dns_name", "dns name"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def init_host_identity_storage(db_path: Path) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(db_path) as db:
        db.execute(
            """CREATE TABLE IF NOT EXISTS analyst_host_identities (
                   ip TEXT PRIMARY KEY,
                   hostname TEXT NOT NULL,
                   source_filename TEXT NOT NULL,
                   imported_by TEXT NOT NULL,
                   imported_at TEXT NOT NULL,
                   version INTEGER NOT NULL DEFAULT 1
               )"""
        )


def _clean_hostname(value: object) -> str:
    hostname = str(value or "").strip().rstrip(".")
    if not hostname:
        raise ValueError("hostname is missing")
    if len(hostname) > 253 or not _HOSTNAME.fullmatch(hostname):
        raise ValueError("hostname contains unsupported characters")
    if any(len(label) > 63 for label in hostname.split(".")):
        raise ValueError("hostname label exceeds 63 characters")
    return hostname


def _clean_ip(value: object) -> str:
    try:
        address = ipaddress.ip_address(str(value or "").strip())
    except ValueError as exc:
        raise ValueError("invalid IP address") from exc
    if address.version != 4:
        raise ValueError("IPv6 is not supported in this release")
    return str(address)


def _rows(text: str, filename: str) -> list[tuple[int, list[str]]]:
    meaningful = [
        (number, line)
        for number, raw in enumerate(text.splitlines(), start=1)
        if (line := raw.strip()) and not line.startswith("#")
    ]
    if not meaningful:
        return []
    comma_mode = Path(filename).suffix.casefold() == ".csv" or any(
        "," in line for _, line in meaningful[:3]
    )
    parsed = []
    for number, line in meaningful:
        if comma_mode:
            values = next(csv.reader([line], skipinitialspace=True))
        elif "\t" in line:
            values = next(csv.reader([line], delimiter="\t", skipinitialspace=True))
        else:
            values = re.split(r"\s+", line, maxsplit=1)
        parsed.append((number, [value.strip() for value in values]))
    return parsed


def parse_host_identity_file(content: bytes, filename: str) -> dict:
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValueError("Host identity files must use UTF-8 text") from exc
    if "\x00" in text:
        raise ValueError("The uploaded file does not appear to be text")
    rows = _rows(text, filename)
    if not rows:
        raise ValueError("The uploaded file contains no IP and hostname rows")

    ip_index, hostname_index, start = 0, 1, 0
    header = [value.casefold().strip() for value in rows[0][1]]
    for index, value in enumerate(header):
        if value in _IP_HEADERS:
            ip_index = index
        if value in _HOST_HEADERS:
            hostname_index = index
    if any(value in _IP_HEADERS for value in header) and any(
        value in _HOST_HEADERS for value in header
    ):
        start = 1

    identities: dict[str, dict] = {}
    errors = []
    duplicate_count = 0
    for number, values in rows[start:]:
        try:
            if max(ip_index, hostname_index) >= len(values):
                raise ValueError("expected both IP address and hostname")
            ip = _clean_ip(values[ip_index])
            hostname = _clean_hostname(values[hostname_index])
        except ValueError as exc:
            if len(errors) < 100:
                errors.append({"line": number, "reason": str(exc)})
            continue
        if ip in identities:
            duplicate_count += 1
        identities[ip] = {"ip": ip, "hostname": hostname, "line": number}
    if not identities:
        raise ValueError("No valid IPv4 and hostname pairs were found")
    return {
        "identities": list(identities.values()),
        "valid_count": len(identities),
        "skipped_count": len(rows) - start - len(identities) - duplicate_count,
        "duplicate_count": duplicate_count,
        "errors": errors,
    }


def import_host_identities(
    db_path: Path, content: bytes, *, filename: str, imported_by: str
) -> dict:
    parsed = parse_host_identity_file(content, filename)
    init_host_identity_storage(db_path)
    imported_at = _now()
    created = updated = unchanged = 0
    with sqlite3.connect(db_path) as db:
        for identity in parsed["identities"]:
            row = db.execute(
                "SELECT hostname, source_filename, imported_by FROM analyst_host_identities WHERE ip = ?",
                (identity["ip"],),
            ).fetchone()
            if row is None:
                db.execute(
                    """INSERT INTO analyst_host_identities
                       (ip, hostname, source_filename, imported_by, imported_at, version)
                       VALUES (?, ?, ?, ?, ?, 1)""",
                    (
                        identity["ip"], identity["hostname"], filename,
                        imported_by, imported_at,
                    ),
                )
                created += 1
            elif row == (identity["hostname"], filename, imported_by):
                unchanged += 1
            else:
                db.execute(
                    """UPDATE analyst_host_identities
                       SET hostname = ?, source_filename = ?, imported_by = ?,
                           imported_at = ?, version = version + 1
                       WHERE ip = ?""",
                    (
                        identity["hostname"], filename, imported_by,
                        imported_at, identity["ip"],
                    ),
                )
                updated += 1
    return {
        **parsed,
        "created_count": created,
        "updated_count": updated,
        "unchanged_count": unchanged,
        "source_filename": filename,
        "imported_by": imported_by,
        "imported_at": imported_at,
        "retained_count": len(list_host_identities(db_path)),
    }


def list_host_identities(db_path: Path) -> list[dict]:
    init_host_identity_storage(db_path)
    with sqlite3.connect(db_path) as db:
        db.row_factory = sqlite3.Row
        rows = db.execute(
            "SELECT * FROM analyst_host_identities ORDER BY length(ip), ip"
        ).fetchall()
    return [dict(row) for row in rows]


def apply_analysis_host_identities(analysis: dict, db_path: Path) -> dict:
    identities = {item["ip"]: item for item in list_host_identities(db_path)}
    for host in analysis.get("hosts") or []:
        identity = identities.get(str(host.get("ip") or ""))
        if not identity:
            continue
        evidence = {
            "hostname": identity["hostname"],
            "source_filename": identity["source_filename"],
            "imported_by": identity["imported_by"],
            "imported_at": identity["imported_at"],
            "version": identity["version"],
        }
        observed = str(host.get("hostname") or "").strip()
        host["analyst_hostname"] = evidence
        aliases = list(dict.fromkeys([
            *(host.get("hostname_aliases") or []), identity["hostname"]
        ]))
        host["hostname_aliases"] = aliases
        if not observed:
            host["hostname"] = identity["hostname"]
            host["hostname_origin"] = "analyst_import"
        elif observed.casefold() != identity["hostname"].casefold():
            host["hostname_conflict"] = True
    return analysis


def apply_topology_host_identities(nodes: dict[str, dict], db_path: Path) -> None:
    identities = {item["ip"]: item for item in list_host_identities(db_path)}
    for node in nodes.values():
        ip = str(node.get("ip") or node.get("address") or "")
        identity = identities.get(ip)
        if not identity:
            continue
        observed = str(node.get("hostname") or "").strip()
        node["analyst_hostname"] = dict(identity)
        node["hostname_aliases"] = list(dict.fromkeys([
            *(node.get("hostname_aliases") or []), identity["hostname"]
        ]))
        if not observed:
            node["hostname"] = identity["hostname"]
            node["hostname_origin"] = "analyst_import"
            if node.get("kind") == "host" and str(node.get("label") or "") == ip:
                node["label"] = identity["hostname"]
        elif observed.casefold() != identity["hostname"].casefold():
            node["hostname_conflict"] = True
        sources = node.setdefault("sources", [])
        if not any(
            item.get("kind") == "analyst_host_identity" and item.get("ip") == ip
            for item in sources
        ):
            sources.append({
                "kind": "analyst_host_identity",
                "ip": ip,
                "label": f"Analyst hostname import · {identity['source_filename']}",
                "timestamp": identity["imported_at"],
                "imported_by": identity["imported_by"],
            })
