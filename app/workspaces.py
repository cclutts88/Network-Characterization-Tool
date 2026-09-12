from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
import uuid


class WorkspaceConflict(ValueError):
    pass


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def init_workspace_storage(db_path: Path) -> None:
    with sqlite3.connect(db_path) as db:
        db.execute(
            """CREATE TABLE IF NOT EXISTS analyst_workspace_layouts (
                layout_id TEXT PRIMARY KEY,
                owner TEXT NOT NULL,
                name TEXT NOT NULL,
                snapshot_json TEXT NOT NULL,
                version INTEGER NOT NULL,
                visibility TEXT NOT NULL DEFAULT 'personal',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(owner, name)
            )"""
        )
        db.execute(
            """CREATE TABLE IF NOT EXISTS analyst_workspace_layout_audit (
                audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
                layout_id TEXT NOT NULL,
                owner TEXT NOT NULL,
                action TEXT NOT NULL,
                version INTEGER NOT NULL,
                actor TEXT NOT NULL,
                changed_at TEXT NOT NULL
            )"""
        )


def _layout(row: sqlite3.Row) -> dict:
    value = dict(row)
    value["snapshot"] = json.loads(value.pop("snapshot_json"))
    return value


def list_layouts(db_path: Path, owner: str) -> list[dict]:
    init_workspace_storage(db_path)
    with sqlite3.connect(db_path) as db:
        db.row_factory = sqlite3.Row
        rows = db.execute(
            """SELECT * FROM analyst_workspace_layouts
               WHERE owner = ? OR visibility = 'shared'
               ORDER BY CASE WHEN owner = ? THEN 0 ELSE 1 END, lower(name), owner""",
            (owner, owner),
        ).fetchall()
    return [_layout(row) for row in rows]


def save_layout(
    db_path: Path,
    *,
    owner: str,
    name: object,
    snapshot: dict,
    layout_id: str | None = None,
    expected_version: int | None = None,
) -> dict:
    name = str(name or "").strip()
    if not name or len(name) > 100:
        raise ValueError("Layout name is required and must be 100 characters or fewer")
    if not isinstance(snapshot, dict):
        raise ValueError("Layout snapshot must be an object")
    encoded = json.dumps(snapshot, sort_keys=True, separators=(",", ":"))
    if len(encoded) > 2_000_000:
        raise ValueError("Layout snapshot exceeds the 2 MB limit")
    changed_at = utc_now()
    init_workspace_storage(db_path)
    with sqlite3.connect(db_path) as db:
        db.row_factory = sqlite3.Row
        if layout_id:
            existing = db.execute(
                "SELECT * FROM analyst_workspace_layouts WHERE layout_id = ? AND owner = ?",
                (layout_id, owner),
            ).fetchone()
            if existing is None:
                raise KeyError(layout_id)
            if expected_version != existing["version"]:
                raise WorkspaceConflict("Layout changed in another session; reload it before replacing")
            version = int(existing["version"]) + 1
            try:
                db.execute(
                    """UPDATE analyst_workspace_layouts
                       SET name = ?, snapshot_json = ?, version = ?, updated_at = ?
                       WHERE layout_id = ? AND owner = ?""",
                    (name, encoded, version, changed_at, layout_id, owner),
                )
            except sqlite3.IntegrityError as exc:
                raise ValueError("A personal layout with that name already exists") from exc
            action = "update"
        else:
            layout_id, version, action = uuid.uuid4().hex, 1, "create"
            try:
                db.execute(
                    """INSERT INTO analyst_workspace_layouts (
                        layout_id, owner, name, snapshot_json, version,
                        visibility, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, 1, 'personal', ?, ?)""",
                    (layout_id, owner, name, encoded, changed_at, changed_at),
                )
            except sqlite3.IntegrityError as exc:
                raise ValueError("A personal layout with that name already exists") from exc
        db.execute(
            """INSERT INTO analyst_workspace_layout_audit
               (layout_id, owner, action, version, actor, changed_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (layout_id, owner, action, version, owner, changed_at),
        )
        row = db.execute(
            "SELECT * FROM analyst_workspace_layouts WHERE layout_id = ?", (layout_id,)
        ).fetchone()
    return _layout(row)


def delete_layout(
    db_path: Path, *, owner: str, layout_id: str, expected_version: int
) -> dict:
    init_workspace_storage(db_path)
    with sqlite3.connect(db_path) as db:
        db.row_factory = sqlite3.Row
        row = db.execute(
            "SELECT * FROM analyst_workspace_layouts WHERE layout_id = ? AND owner = ?",
            (layout_id, owner),
        ).fetchone()
        if row is None:
            raise KeyError(layout_id)
        if expected_version != row["version"]:
            raise WorkspaceConflict("Layout changed in another session; reload before deleting")
        changed_at = utc_now()
        db.execute("DELETE FROM analyst_workspace_layouts WHERE layout_id = ?", (layout_id,))
        db.execute(
            """INSERT INTO analyst_workspace_layout_audit
               (layout_id, owner, action, version, actor, changed_at)
               VALUES (?, ?, 'delete', ?, ?, ?)""",
            (layout_id, owner, row["version"], owner, changed_at),
        )
    return {"status": "deleted", "layout_id": layout_id, "version": row["version"]}


def publish_layout(
    db_path: Path, *, layout_id: str, actor: str, shared: bool
) -> dict:
    init_workspace_storage(db_path)
    with sqlite3.connect(db_path) as db:
        db.row_factory = sqlite3.Row
        row = db.execute(
            "SELECT * FROM analyst_workspace_layouts WHERE layout_id = ?", (layout_id,)
        ).fetchone()
        if row is None:
            raise KeyError(layout_id)
        version = int(row["version"]) + 1
        visibility = "shared" if shared else "personal"
        changed_at = utc_now()
        db.execute(
            "UPDATE analyst_workspace_layouts SET visibility = ?, version = ?, updated_at = ? WHERE layout_id = ?",
            (visibility, version, changed_at, layout_id),
        )
        db.execute(
            """INSERT INTO analyst_workspace_layout_audit
               (layout_id, owner, action, version, actor, changed_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (layout_id, row["owner"], visibility, version, actor, changed_at),
        )
        updated = db.execute(
            "SELECT * FROM analyst_workspace_layouts WHERE layout_id = ?", (layout_id,)
        ).fetchone()
    return _layout(updated)
