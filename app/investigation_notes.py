from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
import uuid


class NoteConflict(ValueError):
    pass


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def init_note_storage(db_path: Path) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(db_path) as db:
        db.execute(
            """CREATE TABLE IF NOT EXISTS analyst_investigation_notes (
                note_id TEXT PRIMARY KEY,
                owner TEXT NOT NULL,
                parent_id TEXT,
                kind TEXT NOT NULL CHECK(kind IN ('folder', 'note')),
                title TEXT NOT NULL,
                content TEXT NOT NULL DEFAULT '',
                context_json TEXT NOT NULL DEFAULT '{}',
                position INTEGER NOT NULL DEFAULT 0,
                version INTEGER NOT NULL DEFAULT 1,
                visibility TEXT NOT NULL DEFAULT 'personal'
                    CHECK(visibility IN ('personal', 'shared')),
                shared_page TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )"""
        )
        columns = {
            row[1]
            for row in db.execute(
                "PRAGMA table_info(analyst_investigation_notes)"
            ).fetchall()
        }
        if "shared_page" not in columns:
            db.execute(
                "ALTER TABLE analyst_investigation_notes ADD COLUMN shared_page TEXT"
            )
        db.execute(
            """CREATE INDEX IF NOT EXISTS analyst_notes_owner_parent
               ON analyst_investigation_notes(owner, parent_id, position)"""
        )
        db.execute(
            """CREATE TABLE IF NOT EXISTS analyst_investigation_note_audit (
                audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
                note_id TEXT NOT NULL,
                owner TEXT NOT NULL,
                action TEXT NOT NULL,
                version INTEGER NOT NULL,
                actor TEXT NOT NULL,
                changed_at TEXT NOT NULL,
                details TEXT NOT NULL DEFAULT ''
            )"""
        )


def _decode(row: sqlite3.Row) -> dict:
    item = dict(row)
    try:
        item["context"] = json.loads(item.pop("context_json"))
    except (TypeError, json.JSONDecodeError):
        item["context"] = {}
    return item


def list_notes(db_path: Path, owner: str, page: str | None = None) -> list[dict]:
    init_note_storage(db_path)
    with sqlite3.connect(db_path) as db:
        db.row_factory = sqlite3.Row
        rows = db.execute(
            """SELECT * FROM analyst_investigation_notes
               WHERE owner = ? OR (visibility = 'shared' AND shared_page = ?)
               ORDER BY position, lower(title), created_at""",
            (owner, page),
        ).fetchall()
    items = [_decode(row) for row in rows]
    visible_ids = {item["note_id"] for item in items}
    for item in items:
        if item["parent_id"] not in visible_ids:
            item["parent_id"] = None
        item["writable"] = item["owner"] == owner
    return items


def _validate_parent(
    db: sqlite3.Connection, *, owner: str, parent_id: str | None, note_id: str | None
) -> None:
    if not parent_id:
        return
    parent = db.execute(
        "SELECT note_id, parent_id, kind FROM analyst_investigation_notes WHERE note_id = ? AND owner = ?",
        (parent_id, owner),
    ).fetchone()
    if parent is None or parent[2] != "folder":
        raise ValueError("The selected parent folder is not available")
    cursor = parent
    visited: set[str] = set()
    while cursor is not None:
        current_id = str(cursor[0])
        if current_id == note_id:
            raise ValueError("A folder cannot be moved inside itself")
        if current_id in visited or not cursor[1]:
            break
        visited.add(current_id)
        cursor = db.execute(
            "SELECT note_id, parent_id, kind FROM analyst_investigation_notes WHERE note_id = ? AND owner = ?",
            (cursor[1], owner),
        ).fetchone()


def save_note(
    db_path: Path,
    *,
    owner: str,
    title: object,
    kind: str,
    content: object = "",
    context: dict | None = None,
    parent_id: str | None = None,
    note_id: str | None = None,
    expected_version: int | None = None,
) -> dict:
    title = str(title or "").strip()
    content = str(content or "")
    parent_id = str(parent_id or "").strip() or None
    if kind not in {"folder", "note"}:
        raise ValueError("Note type must be folder or note")
    if not title or len(title) > 140:
        raise ValueError("A title between 1 and 140 characters is required")
    if len(content) > 250_000:
        raise ValueError("A note cannot exceed 250,000 characters")
    if context is None:
        context = {}
    if not isinstance(context, dict):
        raise ValueError("Note context must be an object")
    context_json = json.dumps(context, sort_keys=True, separators=(",", ":"))
    if len(context_json) > 32_000:
        raise ValueError("Note context is too large")
    changed_at = utc_now()
    init_note_storage(db_path)
    with sqlite3.connect(db_path) as db:
        db.row_factory = sqlite3.Row
        _validate_parent(db, owner=owner, parent_id=parent_id, note_id=note_id)
        if note_id:
            existing = db.execute(
                "SELECT * FROM analyst_investigation_notes WHERE note_id = ? AND owner = ?",
                (note_id, owner),
            ).fetchone()
            if existing is None:
                raise KeyError(note_id)
            if expected_version != int(existing["version"]):
                raise NoteConflict("This note changed in another session; reload it before saving")
            version = int(existing["version"]) + 1
            db.execute(
                """UPDATE analyst_investigation_notes
                   SET parent_id = ?, kind = ?, title = ?, content = ?, context_json = ?,
                       version = ?, updated_at = ? WHERE note_id = ? AND owner = ?""",
                (
                    parent_id,
                    kind,
                    title,
                    content if kind == "note" else "",
                    context_json,
                    version,
                    changed_at,
                    note_id,
                    owner,
                ),
            )
            action = "update"
        else:
            note_id = uuid.uuid4().hex
            position = db.execute(
                """SELECT COALESCE(MAX(position), -1) + 1
                   FROM analyst_investigation_notes
                   WHERE owner = ? AND parent_id IS ?""",
                (owner, parent_id),
            ).fetchone()[0]
            version, action = 1, "create"
            db.execute(
                """INSERT INTO analyst_investigation_notes
                   (note_id, owner, parent_id, kind, title, content, context_json,
                    position, version, visibility, shared_page, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, 'personal', NULL, ?, ?)""",
                (
                    note_id,
                    owner,
                    parent_id,
                    kind,
                    title,
                    content if kind == "note" else "",
                    context_json,
                    position,
                    changed_at,
                    changed_at,
                ),
            )
        db.execute(
            """INSERT INTO analyst_investigation_note_audit
               (note_id, owner, action, version, actor, changed_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (note_id, owner, action, version, owner, changed_at),
        )
        row = db.execute(
            "SELECT * FROM analyst_investigation_notes WHERE note_id = ?", (note_id,)
        ).fetchone()
    result = _decode(row)
    result["writable"] = True
    return result


def delete_note(
    db_path: Path, *, owner: str, note_id: str, expected_version: int
) -> dict:
    init_note_storage(db_path)
    with sqlite3.connect(db_path) as db:
        db.row_factory = sqlite3.Row
        row = db.execute(
            "SELECT * FROM analyst_investigation_notes WHERE note_id = ? AND owner = ?",
            (note_id, owner),
        ).fetchone()
        if row is None:
            raise KeyError(note_id)
        if expected_version != int(row["version"]):
            raise NoteConflict("This note changed in another session; reload it before deleting")
        descendants = db.execute(
            """WITH RECURSIVE branch(note_id) AS (
                 SELECT note_id FROM analyst_investigation_notes WHERE note_id = ? AND owner = ?
                 UNION ALL
                 SELECT child.note_id FROM analyst_investigation_notes child
                 JOIN branch ON child.parent_id = branch.note_id WHERE child.owner = ?
               ) SELECT note_id FROM branch""",
            (note_id, owner, owner),
        ).fetchall()
        ids = [item[0] for item in descendants]
        placeholders = ",".join("?" for _ in ids)
        db.execute(
            f"DELETE FROM analyst_investigation_notes WHERE note_id IN ({placeholders})",
            ids,
        )
        changed_at = utc_now()
        db.execute(
            """INSERT INTO analyst_investigation_note_audit
               (note_id, owner, action, version, actor, changed_at, details)
               VALUES (?, ?, 'delete', ?, ?, ?, ?)""",
            (
                note_id,
                owner,
                row["version"],
                owner,
                changed_at,
                f"Deleted {len(ids)} item(s)",
            ),
        )
    return {"deleted": True, "note_id": note_id, "items_removed": len(ids)}


def share_note(
    db_path: Path,
    *,
    owner: str,
    note_id: str,
    expected_version: int,
    shared: bool,
    page: str | None = None,
) -> dict:
    init_note_storage(db_path)
    with sqlite3.connect(db_path) as db:
        db.row_factory = sqlite3.Row
        row = db.execute(
            "SELECT * FROM analyst_investigation_notes WHERE note_id = ? AND owner = ?",
            (note_id, owner),
        ).fetchone()
        if row is None:
            raise KeyError(note_id)
        if expected_version != int(row["version"]):
            raise NoteConflict("This note changed in another session; reload it before sharing")
        branch = db.execute(
            """WITH RECURSIVE branch(note_id) AS (
                 SELECT note_id FROM analyst_investigation_notes WHERE note_id = ? AND owner = ?
                 UNION ALL
                 SELECT child.note_id FROM analyst_investigation_notes child
                 JOIN branch ON child.parent_id = branch.note_id WHERE child.owner = ?
               ) SELECT note_id FROM branch""",
            (note_id, owner, owner),
        ).fetchall()
        ids = [item[0] for item in branch]
        placeholders = ",".join("?" for _ in ids)
        visibility = "shared" if shared else "personal"
        page = str(page or "").strip().lower() or None
        if shared and page not in {"device", "nmap", "analyze", "hunt", "map"}:
            raise ValueError("Choose the NCT page where this note should be shared")
        changed_at = utc_now()
        db.execute(
            f"""UPDATE analyst_investigation_notes
                SET visibility = ?, shared_page = ?, version = version + 1, updated_at = ?
                WHERE note_id IN ({placeholders})""",
            [visibility, page if shared else None, changed_at, *ids],
        )
        updated = db.execute(
            "SELECT * FROM analyst_investigation_notes WHERE note_id = ?", (note_id,)
        ).fetchone()
        db.execute(
            """INSERT INTO analyst_investigation_note_audit
               (note_id, owner, action, version, actor, changed_at, details)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                note_id,
                owner,
                "share" if shared else "unshare",
                updated["version"],
                owner,
                changed_at,
                f"Updated {len(ids)} item(s)",
            ),
        )
    result = _decode(updated)
    result["writable"] = True
    return result


def export_note_markdown(
    db_path: Path, *, viewer: str, note_id: str, page: str | None = None
) -> tuple[str, str]:
    items = list_notes(db_path, viewer, page)
    by_id = {item["note_id"]: item for item in items}
    root = by_id.get(note_id)
    if root is None:
        raise KeyError(note_id)
    children: dict[str | None, list[dict]] = {}
    for item in items:
        children.setdefault(item["parent_id"], []).append(item)
    for values in children.values():
        values.sort(key=lambda item: (int(item["position"]), item["title"].lower()))

    lines = [
        f"# {root['title'].replace(chr(10), ' ').replace(chr(13), ' ')}",
        "",
        f"Exported from NCT investigation notes · owner: {root['owner']} · visibility: {root['visibility']}",
        "",
    ]

    def append_item(item: dict, level: int, include_heading: bool = True) -> None:
        if include_heading:
            title = item["title"].replace("\n", " ").replace("\r", " ")
            lines.extend([f"{'#' * min(level, 6)} {title}", ""])
        if item["kind"] == "note" and item["content"]:
            lines.extend([item["content"].rstrip(), ""])
        context = item.get("context") or {}
        if context.get("source_url"):
            label = context.get("source_label") or context.get("source_page") or "NCT view"
            lines.extend([f"Context: [{label}]({context['source_url']})", ""])
        for child in children.get(item["note_id"], []):
            append_item(child, level + 1)

    append_item(root, 2, include_heading=False)
    return root["title"], "\n".join(lines).rstrip() + "\n"
