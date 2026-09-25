from __future__ import annotations

import json
from pathlib import Path
import sqlite3


class DraftConflict(RuntimeError):
    pass


def utc_now() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def init_scan_collaboration_storage(db_path: Path) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(db_path) as db:
        db.execute(
            """CREATE TABLE IF NOT EXISTS analyst_scan_drafts (
                owner TEXT PRIMARY KEY,
                snapshot_json TEXT NOT NULL,
                version INTEGER NOT NULL,
                updated_at TEXT NOT NULL
            )"""
        )
        db.execute(
            """CREATE TABLE IF NOT EXISTS scan_run_audit (
                event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT NOT NULL,
                event TEXT NOT NULL,
                actor TEXT NOT NULL,
                changed_at TEXT NOT NULL,
                details TEXT NOT NULL DEFAULT ''
            )"""
        )
        db.execute(
            "CREATE INDEX IF NOT EXISTS scan_run_audit_run ON scan_run_audit(run_id, event_id)"
        )


def get_scan_draft(db_path: Path, owner: str) -> dict | None:
    init_scan_collaboration_storage(db_path)
    with sqlite3.connect(db_path) as db:
        row = db.execute(
            "SELECT snapshot_json, version, updated_at FROM analyst_scan_drafts WHERE owner = ?",
            (owner,),
        ).fetchone()
    if row is None:
        return None
    return {
        "owner": owner,
        "snapshot": json.loads(row[0]),
        "version": int(row[1]),
        "updated_at": row[2],
    }


def save_scan_draft(
    db_path: Path,
    *,
    owner: str,
    snapshot: dict,
    expected_version: int | None = None,
) -> dict:
    init_scan_collaboration_storage(db_path)
    changed_at = utc_now()
    payload = json.dumps(snapshot, sort_keys=True)
    with sqlite3.connect(db_path) as db:
        row = db.execute(
            "SELECT version FROM analyst_scan_drafts WHERE owner = ?", (owner,)
        ).fetchone()
        if row is None:
            if expected_version not in {None, 0}:
                raise DraftConflict("This draft changed in another browser. Reload it before saving.")
            version = 1
            db.execute(
                "INSERT INTO analyst_scan_drafts (owner, snapshot_json, version, updated_at) VALUES (?, ?, ?, ?)",
                (owner, payload, version, changed_at),
            )
        else:
            current = int(row[0])
            if expected_version is not None and expected_version != current:
                raise DraftConflict("This draft changed in another browser. Reload it before saving.")
            version = current + 1
            db.execute(
                "UPDATE analyst_scan_drafts SET snapshot_json = ?, version = ?, updated_at = ? WHERE owner = ?",
                (payload, version, changed_at, owner),
            )
    return {
        "owner": owner,
        "snapshot": snapshot,
        "version": version,
        "updated_at": changed_at,
    }


def delete_scan_draft(db_path: Path, owner: str) -> bool:
    init_scan_collaboration_storage(db_path)
    with sqlite3.connect(db_path) as db:
        removed = db.execute(
            "DELETE FROM analyst_scan_drafts WHERE owner = ?", (owner,)
        ).rowcount
    return bool(removed)


def append_scan_audit(
    db_path: Path,
    *,
    run_id: str,
    event: str,
    actor: str,
    details: str = "",
    changed_at: str | None = None,
) -> dict:
    init_scan_collaboration_storage(db_path)
    changed_at = changed_at or utc_now()
    actor = str(actor or "system").strip()[:100] or "system"
    event = str(event or "update").strip()[:64] or "update"
    details = str(details or "").strip()[:500]
    with sqlite3.connect(db_path) as db:
        cursor = db.execute(
            "INSERT INTO scan_run_audit (run_id, event, actor, changed_at, details) VALUES (?, ?, ?, ?, ?)",
            (run_id, event, actor, changed_at, details),
        )
    return {
        "event_id": int(cursor.lastrowid),
        "run_id": run_id,
        "event": event,
        "actor": actor,
        "changed_at": changed_at,
        "details": details,
    }


def scan_audit_history(db_path: Path, run_id: str, limit: int = 200) -> list[dict]:
    init_scan_collaboration_storage(db_path)
    limit = max(1, min(int(limit), 1000))
    with sqlite3.connect(db_path) as db:
        db.row_factory = sqlite3.Row
        return [
            dict(row)
            for row in db.execute(
                """SELECT event_id, run_id, event, actor, changed_at, details
                   FROM scan_run_audit WHERE run_id = ?
                   ORDER BY event_id DESC LIMIT ?""",
                (run_id, limit),
            ).fetchall()
        ]
