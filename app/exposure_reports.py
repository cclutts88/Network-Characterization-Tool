from __future__ import annotations

import ipaddress
import json
from pathlib import Path

from app.database import connect_database


def init_exposure_report_storage(db_path: Path) -> None:
    with connect_database(db_path) as db:
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS reach_exposure_reports (
                saved_network_id TEXT PRIMARY KEY,
                target_name TEXT NOT NULL,
                target_cidr TEXT NOT NULL,
                generated_at TEXT NOT NULL,
                generated_by TEXT NOT NULL DEFAULT '',
                port_snapshot_json TEXT NOT NULL,
                report_json TEXT NOT NULL
            )
            """
        )


def exposure_port_snapshot(hunting: dict, cidr: str) -> list[str]:
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return []
    if network.version != 4:
        return []
    snapshot: set[str] = set()
    for finding in hunting.get("findings") or []:
        if finding.get("evidence_kind") == "device_configuration":
            continue
        try:
            address = ipaddress.ip_address(str(finding.get("ip") or ""))
            port = int(finding.get("port"))
        except (ValueError, TypeError):
            continue
        protocol = str(finding.get("protocol") or "").strip().lower()
        if address.version != 4 or address not in network or not protocol:
            continue
        state = str(finding.get("state") or "open").strip().lower()
        snapshot.add(f"{address}|{protocol}|{port}|{state}")
    return sorted(snapshot)


def snapshot_changes(previous: list[str], current: list[str]) -> dict:
    previous_set = set(previous)
    current_set = set(current)
    added = sorted(current_set - previous_set)
    removed = sorted(previous_set - current_set)
    return {
        "changed": bool(added or removed),
        "added_count": len(added),
        "removed_count": len(removed),
        "added": added,
        "removed": removed,
    }


def save_exposure_report(
    db_path: Path,
    *,
    saved_network: dict,
    generated_by: str,
    port_snapshot: list[str],
    report: dict,
) -> None:
    init_exposure_report_storage(db_path)
    with connect_database(db_path) as db:
        db.execute(
            """
            INSERT INTO reach_exposure_reports (
                saved_network_id, target_name, target_cidr, generated_at,
                generated_by, port_snapshot_json, report_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(saved_network_id) DO UPDATE SET
                target_name = excluded.target_name,
                target_cidr = excluded.target_cidr,
                generated_at = excluded.generated_at,
                generated_by = excluded.generated_by,
                port_snapshot_json = excluded.port_snapshot_json,
                report_json = excluded.report_json
            """,
            (
                saved_network["saved_network_id"],
                saved_network.get("name") or saved_network["cidr"],
                saved_network["cidr"],
                report["generated_at"],
                generated_by,
                json.dumps(port_snapshot, separators=(",", ":")),
                json.dumps(report, separators=(",", ":")),
            ),
        )


def _row_to_record(row: tuple) -> dict:
    return {
        "saved_network_id": row[0],
        "target_name": row[1],
        "target_cidr": row[2],
        "generated_at": row[3],
        "generated_by": row[4],
        "port_snapshot": json.loads(row[5]),
        "report": json.loads(row[6]),
    }


def get_exposure_report(db_path: Path, saved_network_id: str) -> dict | None:
    with connect_database(db_path) as db:
        row = db.execute(
            """
            SELECT saved_network_id, target_name, target_cidr, generated_at,
                   generated_by, port_snapshot_json, report_json
            FROM reach_exposure_reports
            WHERE saved_network_id = ?
            """,
            (saved_network_id,),
        ).fetchone()
    return _row_to_record(row) if row else None


def _all_exposure_reports(db_path: Path) -> dict[str, dict]:
    with connect_database(db_path) as db:
        rows = db.execute(
            """
            SELECT saved_network_id, target_name, target_cidr, generated_at,
                   generated_by, port_snapshot_json, report_json
            FROM reach_exposure_reports
            """
        ).fetchall()
    return {row[0]: _row_to_record(row) for row in rows}


def exposure_report_status(record: dict, current_snapshot: list[str]) -> dict:
    changes = snapshot_changes(record["port_snapshot"], current_snapshot)
    return {
        "has_report": True,
        "freshness": "out_of_date" if changes["changed"] else "current",
        "generated_at": record["generated_at"],
        "generated_by": record["generated_by"],
        "service_count": int(record["report"].get("service_count") or 0),
        "source_count": int(record["report"].get("source_count") or 0),
        "evaluated_path_count": int(record["report"].get("evaluated_path_count") or 0),
        "changes": changes,
    }


def list_exposure_report_summaries(
    db_path: Path,
    saved_networks: list[dict],
    hunting: dict,
) -> list[dict]:
    summaries: list[dict] = []
    retained_reports = _all_exposure_reports(db_path)
    for network in saved_networks:
        saved_network_id = str(network.get("saved_network_id") or "")
        base = {
            "saved_network_id": saved_network_id,
            "name": network.get("name") or network.get("cidr"),
            "cidr": network.get("cidr"),
            "has_report": False,
            "freshness": "not_generated",
            "generated_at": None,
            "generated_by": "",
            "service_count": 0,
            "source_count": 0,
            "evaluated_path_count": 0,
            "changes": {
                "changed": False,
                "added_count": 0,
                "removed_count": 0,
                "added": [],
                "removed": [],
            },
        }
        record = retained_reports.get(saved_network_id)
        if record:
            current = exposure_port_snapshot(hunting, str(network.get("cidr") or ""))
            base.update(exposure_report_status(record, current))
        summaries.append(base)
    return summaries
