from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
import uuid

from app.database import connect_database, initialize_once_per_database


class NoteConflict(ValueError):
    pass


MAX_NOTE_PARENT_DEPTH = 128
MAX_NOTE_MOVE_ITEMS = 1_000


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


@initialize_once_per_database
def init_note_storage(db_path: Path) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with connect_database(db_path) as db:
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
            """CREATE INDEX IF NOT EXISTS analyst_notes_parent
               ON analyst_investigation_notes(parent_id)"""
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
    with connect_database(db_path) as db:
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


def _branch_revision(note_id: str, rows: list[sqlite3.Row]) -> str:
    payload = {
        "schema": 1,
        "root": note_id,
        "items": [
            [str(row["note_id"]), str(row["parent_id"] or ""), int(row["version"])]
            for row in sorted(rows, key=lambda item: str(item["note_id"]))
        ],
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _read_branch_snapshot(
    db: sqlite3.Connection, *, owner: str, note_id: str
) -> dict:
    db.row_factory = sqlite3.Row
    rows = db.execute(
        """WITH RECURSIVE branch(
               note_id, owner, parent_id, kind, title, version, visibility, shared_page
           ) AS (
             SELECT note_id, owner, parent_id, kind, title, version, visibility, shared_page
             FROM analyst_investigation_notes WHERE note_id = ? AND owner = ?
             UNION
             SELECT child.note_id, child.owner, child.parent_id, child.kind, child.title,
                    child.version, child.visibility, child.shared_page
             FROM analyst_investigation_notes child
             JOIN branch ON child.parent_id = branch.note_id
             WHERE child.owner = ?
           )
           SELECT * FROM branch ORDER BY note_id""",
        (note_id, owner, owner),
    ).fetchall()
    if not rows:
        raise KeyError(note_id)
    by_id = {str(row["note_id"]): row for row in rows}
    root = by_id[note_id]
    if root["parent_id"] in by_id:
        raise NoteConflict("This folder structure contains a cycle and cannot be changed")
    for row in rows:
        if row["note_id"] == note_id:
            continue
        parent = by_id.get(str(row["parent_id"] or ""))
        if parent is None or parent["kind"] != "folder":
            raise NoteConflict("This folder structure is inconsistent and cannot be changed")

    path_rows = [root]
    parent_id = root["parent_id"]
    visited = {note_id}
    while parent_id:
        if parent_id in visited:
            raise NoteConflict("This folder structure contains a cycle and cannot be changed")
        visited.add(parent_id)
        parent = db.execute(
            """SELECT note_id, parent_id, kind, title
               FROM analyst_investigation_notes WHERE note_id = ? AND owner = ?""",
            (parent_id, owner),
        ).fetchone()
        if parent is None:
            break
        path_rows.append(parent)
        parent_id = parent["parent_id"]

    folder_count = sum(1 for row in rows if row["kind"] == "folder")
    note_count = len(rows) - folder_count
    shared_page_counts: dict[str, int] = {}
    for row in rows:
        if row["visibility"] != "shared":
            continue
        page = str(row["shared_page"] or "unknown")
        shared_page_counts[page] = shared_page_counts.get(page, 0) + 1
    return {
        "note_id": note_id,
        "title": str(root["title"]),
        "kind": str(root["kind"]),
        "root_version": int(root["version"]),
        "path": [str(row["title"]) for row in reversed(path_rows)],
        "items_total": len(rows),
        "folder_count": folder_count,
        "note_count": note_count,
        "shared_items": sum(shared_page_counts.values()),
        "shared_page_counts": dict(sorted(shared_page_counts.items())),
        "branch_revision": _branch_revision(note_id, rows),
        "rows": rows,
    }


def preview_note_branch(db_path: Path, *, owner: str, note_id: str) -> dict:
    init_note_storage(db_path)
    with connect_database(db_path, read_only=True) as db:
        db.execute("BEGIN")
        snapshot = _read_branch_snapshot(db, owner=owner, note_id=note_id)
    return {key: value for key, value in snapshot.items() if key != "rows"}


def _stage_branch_rows(db: sqlite3.Connection, rows: list[sqlite3.Row]) -> None:
    db.execute(
        """CREATE TEMP TABLE nct_note_branch_stage (
               note_id TEXT PRIMARY KEY,
               owner TEXT NOT NULL,
               parent_id TEXT,
               kind TEXT NOT NULL,
               version INTEGER NOT NULL
           ) WITHOUT ROWID"""
    )
    db.executemany(
        """INSERT INTO nct_note_branch_stage
           (note_id, owner, parent_id, kind, version) VALUES (?, ?, ?, ?, ?)""",
        [
            (
                row["note_id"],
                row["owner"],
                row["parent_id"],
                row["kind"],
                row["version"],
            )
            for row in rows
        ],
    )
    db.commit()


def _prepare_branch_mutation(
    db_path: Path,
    *,
    owner: str,
    note_id: str,
    expected_version: int,
    branch_revision: str | None,
    action: str,
) -> tuple[sqlite3.Connection, dict]:
    init_note_storage(db_path)
    with connect_database(db_path, read_only=True) as reader:
        reader.execute("BEGIN")
        snapshot = _read_branch_snapshot(reader, owner=owner, note_id=note_id)
    if expected_version != snapshot["root_version"]:
        raise NoteConflict(
            f"This {snapshot['kind']} changed in another session; reload it before {action}"
        )
    if snapshot["kind"] == "folder" and branch_revision != snapshot["branch_revision"]:
        raise NoteConflict(
            f"This folder or something inside it changed in another session; "
            f"reload it before {action}"
        )
    if branch_revision is not None and branch_revision != snapshot["branch_revision"]:
        raise NoteConflict(
            f"This note changed in another session; reload it before {action}"
        )

    db = connect_database(db_path)
    db.row_factory = sqlite3.Row
    try:
        _stage_branch_rows(db, snapshot["rows"])
        return db, snapshot
    except Exception:
        db.close()
        raise


def _unstaged_child_sql(stage_table: str) -> str:
    if stage_table not in {"nct_note_branch_stage", "nct_note_move_branch"}:
        raise ValueError("Unsupported note staging table")
    return f"""SELECT EXISTS(
                 SELECT 1
                 FROM {stage_table} parent
                 CROSS JOIN analyst_investigation_notes AS child
                   INDEXED BY analyst_notes_parent
                 WHERE child.parent_id = parent.note_id
                   AND NOT EXISTS (
                     SELECT 1 FROM {stage_table} staged_child
                     WHERE staged_child.note_id = child.note_id
                   )
                 LIMIT 1
               )"""


def _has_unstaged_child(db: sqlite3.Connection, stage_table: str) -> bool:
    return bool(db.execute(_unstaged_child_sql(stage_table)).fetchone()[0])


def _revalidate_staged_branch(
    db: sqlite3.Connection, *, owner: str, note_id: str, snapshot: dict, action: str
) -> sqlite3.Row:
    root = db.execute(
        "SELECT * FROM analyst_investigation_notes WHERE note_id = ? AND owner = ?",
        (note_id, owner),
    ).fetchone()
    if root is None:
        raise NoteConflict(f"This item is no longer available; reload before {action}")
    if int(root["version"]) != snapshot["root_version"]:
        raise NoteConflict(
            f"This {snapshot['kind']} changed in another session; reload it before {action}"
        )
    mismatch = db.execute(
        """SELECT COUNT(*)
           FROM nct_note_branch_stage staged
           LEFT JOIN analyst_investigation_notes current
             ON current.note_id = staged.note_id
           WHERE current.note_id IS NULL
              OR current.owner != staged.owner
              OR current.parent_id IS NOT staged.parent_id
              OR current.kind != staged.kind
              OR current.version != staged.version"""
    ).fetchone()[0]
    added = _has_unstaged_child(db, "nct_note_branch_stage")
    if mismatch or added:
        raise NoteConflict(
            f"This folder or something inside it changed in another session; "
            f"nothing was changed. Reload before {action}"
        )
    return root


def _read_parent_snapshot(
    db: sqlite3.Connection,
    *,
    owner: str,
    parent_id: str | None,
    note_id: str | None,
) -> list[sqlite3.Row]:
    if not parent_id:
        return []
    db.row_factory = sqlite3.Row
    rows = db.execute(
        """WITH RECURSIVE ancestors(
               note_id, owner, parent_id, kind, depth, path, cycle
           ) AS (
             SELECT note_id, owner, parent_id, kind, 1,
                    ',' || note_id || ',', 0
             FROM analyst_investigation_notes WHERE note_id = ?
             UNION ALL
             SELECT parent.note_id, parent.owner, parent.parent_id, parent.kind,
                    ancestors.depth + 1,
                    ancestors.path || parent.note_id || ',',
                    instr(ancestors.path, ',' || parent.note_id || ',') > 0
             FROM analyst_investigation_notes parent
             JOIN ancestors ON parent.note_id = ancestors.parent_id
             WHERE ancestors.cycle = 0 AND ancestors.depth <= ?
           )
           SELECT note_id, owner, parent_id, kind, depth, cycle
           FROM ancestors ORDER BY depth""",
        (parent_id, MAX_NOTE_PARENT_DEPTH),
    ).fetchall()
    if not rows:
        raise ValueError("The selected parent folder is not available")
    for row in rows:
        if bool(row["cycle"]):
            raise ValueError("The selected folder structure contains a cycle")
        if int(row["depth"]) > MAX_NOTE_PARENT_DEPTH:
            raise ValueError(
                f"Folders can be nested under at most {MAX_NOTE_PARENT_DEPTH} parent folders"
            )
        if str(row["owner"]) != owner:
            raise ValueError("The selected folder structure crosses analyst ownership")
        if str(row["kind"]) != "folder":
            raise ValueError("Every item in the selected parent path must be a folder")
        if str(row["note_id"]) == note_id:
            raise ValueError("A folder cannot be moved inside itself")
    if rows[-1]["parent_id"]:
        raise ValueError("The selected folder structure has a missing ancestor")
    return rows


def _stage_parent_rows(db: sqlite3.Connection, rows: list[sqlite3.Row]) -> None:
    db.execute(
        """CREATE TEMP TABLE nct_note_parent_stage (
               note_id TEXT PRIMARY KEY,
               owner TEXT NOT NULL,
               parent_id TEXT,
               kind TEXT NOT NULL,
               depth INTEGER NOT NULL
           ) WITHOUT ROWID"""
    )
    db.executemany(
        """INSERT INTO nct_note_parent_stage
           (note_id, owner, parent_id, kind, depth) VALUES (?, ?, ?, ?, ?)""",
        [
            (
                row["note_id"],
                row["owner"],
                row["parent_id"],
                row["kind"],
                row["depth"],
            )
            for row in rows
        ],
    )


def _read_save_target(
    db: sqlite3.Connection, *, owner: str, note_id: str | None
) -> sqlite3.Row | None:
    if not note_id:
        return None
    row = db.execute(
        """SELECT note_id, owner, parent_id, kind
           FROM analyst_investigation_notes WHERE note_id = ?""",
        (note_id,),
    ).fetchone()
    if row is None or str(row["owner"]) != owner:
        raise KeyError(note_id)
    return row


def _read_descendant_snapshot(
    db: sqlite3.Connection, *, owner: str, note_id: str
) -> list[sqlite3.Row]:
    rows = db.execute(
        """WITH RECURSIVE descendants(
               note_id, owner, parent_id, kind, depth, path, cycle
           ) AS (
             SELECT note_id, owner, parent_id, kind, 0,
                    ',' || note_id || ',', 0
             FROM analyst_investigation_notes WHERE note_id = ?
             UNION ALL
             SELECT child.note_id, child.owner, child.parent_id, child.kind,
                    descendants.depth + 1,
                    descendants.path || child.note_id || ',',
                    instr(descendants.path, ',' || child.note_id || ',') > 0
             FROM analyst_investigation_notes child
             JOIN descendants ON child.parent_id = descendants.note_id
             WHERE descendants.cycle = 0 AND descendants.depth <= ?
           )
           SELECT note_id, owner, parent_id, kind, depth, cycle
           FROM descendants LIMIT ?""",
        (note_id, MAX_NOTE_PARENT_DEPTH, MAX_NOTE_MOVE_ITEMS + 1),
    ).fetchall()
    if not rows or str(rows[0]["note_id"]) != note_id:
        raise KeyError(note_id)
    if len(rows) > MAX_NOTE_MOVE_ITEMS:
        raise ValueError(
            f"A single folder move supports at most {MAX_NOTE_MOVE_ITEMS:,} items, "
            "counting the folder and everything inside it"
        )
    by_id = {str(row["note_id"]): row for row in rows}
    for row in rows:
        if bool(row["cycle"]):
            raise ValueError("This folder structure contains a cycle")
        if int(row["depth"]) > MAX_NOTE_PARENT_DEPTH:
            raise ValueError(
                f"Folders can be nested under at most {MAX_NOTE_PARENT_DEPTH} parent folders"
            )
        if str(row["owner"]) != owner:
            raise ValueError("This folder structure crosses analyst ownership")
        if str(row["note_id"]) == note_id:
            continue
        parent = by_id.get(str(row["parent_id"] or ""))
        if parent is None or str(parent["kind"]) != "folder":
            raise ValueError("Every item in a moved branch must be inside a folder")
    return rows


def _stage_save_target(
    db: sqlite3.Connection,
    target: sqlite3.Row | None,
    descendants: list[sqlite3.Row],
) -> None:
    db.execute(
        """CREATE TEMP TABLE nct_note_save_target (
               note_id TEXT PRIMARY KEY,
               owner TEXT NOT NULL,
               parent_id TEXT,
               kind TEXT NOT NULL
           ) WITHOUT ROWID"""
    )
    if target is not None:
        db.execute(
            """INSERT INTO nct_note_save_target
               (note_id, owner, parent_id, kind) VALUES (?, ?, ?, ?)""",
            (target["note_id"], target["owner"], target["parent_id"], target["kind"]),
        )
    db.execute(
        """CREATE TEMP TABLE nct_note_move_branch (
               note_id TEXT PRIMARY KEY,
               owner TEXT NOT NULL,
               parent_id TEXT,
               kind TEXT NOT NULL,
               depth INTEGER NOT NULL
           ) WITHOUT ROWID"""
    )
    db.executemany(
        """INSERT INTO nct_note_move_branch
           (note_id, owner, parent_id, kind, depth) VALUES (?, ?, ?, ?, ?)""",
        [
            (
                row["note_id"],
                row["owner"],
                row["parent_id"],
                row["kind"],
                row["depth"],
            )
            for row in descendants
        ],
    )


def _prepare_parent_save(
    db_path: Path,
    *,
    owner: str,
    parent_id: str | None,
    note_id: str | None,
) -> sqlite3.Connection:
    init_note_storage(db_path)
    db = connect_database(db_path)
    db.row_factory = sqlite3.Row
    try:
        rows = _read_parent_snapshot(
            db, owner=owner, parent_id=parent_id, note_id=note_id
        )
        target = _read_save_target(db, owner=owner, note_id=note_id)
        moving = target is not None and target["parent_id"] != parent_id
        descendants = (
            _read_descendant_snapshot(db, owner=owner, note_id=note_id)
            if moving and note_id
            else []
        )
        if descendants:
            deepest = max(int(row["depth"]) for row in descendants)
            if len(rows) + deepest > MAX_NOTE_PARENT_DEPTH:
                raise ValueError(
                    f"This move would nest an item inside more than "
                    f"{MAX_NOTE_PARENT_DEPTH} parent folders"
                )
        _stage_parent_rows(db, rows)
        _stage_save_target(db, target, descendants)
        db.commit()
        return db
    except Exception:
        db.rollback()
        db.close()
        raise


def _revalidate_parent_stage(
    db: sqlite3.Connection,
    *,
    owner: str,
    parent_id: str | None,
    note_id: str | None,
) -> None:
    target_count = int(
        db.execute("SELECT COUNT(*) FROM nct_note_save_target").fetchone()[0]
    )
    if note_id:
        if target_count != 1:
            raise NoteConflict("This note changed in another session; reload before saving")
        target_mismatch = int(
            db.execute(
                """SELECT COUNT(*) FROM nct_note_save_target staged
                   LEFT JOIN analyst_investigation_notes current
                     ON current.note_id = staged.note_id
                   WHERE current.note_id IS NULL
                      OR current.owner != staged.owner
                      OR current.parent_id IS NOT staged.parent_id
                      OR current.kind != staged.kind"""
            ).fetchone()[0]
        )
        if target_mismatch:
            raise NoteConflict(
                "This note or folder moved or changed type in another session; "
                "nothing was saved. Reload before saving"
            )
    elif target_count:
        raise NoteConflict("The selected note structure changed; reload before saving")
    staged_count = int(
        db.execute("SELECT COUNT(*) FROM nct_note_parent_stage").fetchone()[0]
    )
    if not parent_id:
        if staged_count:
            raise NoteConflict("The selected folder structure changed; reload before saving")
    else:
        direct = db.execute(
            "SELECT note_id FROM nct_note_parent_stage WHERE depth = 1"
        ).fetchone()
        if direct is None or str(direct[0]) != parent_id:
            raise NoteConflict("The selected folder structure changed; reload before saving")
        mismatch = int(
            db.execute(
                """SELECT COUNT(*)
                   FROM nct_note_parent_stage staged
                   LEFT JOIN analyst_investigation_notes current
                     ON current.note_id = staged.note_id
                   WHERE current.note_id IS NULL
                      OR current.owner != staged.owner
                      OR current.parent_id IS NOT staged.parent_id
                      OR current.kind != staged.kind"""
            ).fetchone()[0]
        )
        if mismatch:
            raise NoteConflict(
                "The selected folder structure changed in another session; "
                "nothing was saved. Reload before saving"
            )
    moved_count = int(
        db.execute("SELECT COUNT(*) FROM nct_note_move_branch").fetchone()[0]
    )
    if not moved_count:
        return
    branch_mismatch = int(
        db.execute(
            """SELECT COUNT(*)
               FROM nct_note_move_branch staged
               LEFT JOIN analyst_investigation_notes current
                 ON current.note_id = staged.note_id
               WHERE current.note_id IS NULL
                  OR current.owner != staged.owner
                  OR current.parent_id IS NOT staged.parent_id
                  OR current.kind != staged.kind"""
        ).fetchone()[0]
    )
    added = _has_unstaged_child(db, "nct_note_move_branch")
    if branch_mismatch or added:
        raise NoteConflict(
            "This folder or something inside it changed in another session; "
            "nothing was saved. Reload before saving"
        )


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
    db = _prepare_parent_save(
        db_path, owner=owner, parent_id=parent_id, note_id=note_id
    )
    try:
        db.execute("BEGIN IMMEDIATE")
        _revalidate_parent_stage(
            db, owner=owner, parent_id=parent_id, note_id=note_id
        )
        if note_id:
            existing = db.execute(
                "SELECT * FROM analyst_investigation_notes WHERE note_id = ? AND owner = ?",
                (note_id, owner),
            ).fetchone()
            if existing is None:
                raise KeyError(note_id)
            if expected_version != int(existing["version"]):
                raise NoteConflict("This note changed in another session; reload it before saving")
            if existing["kind"] == "folder" and kind == "note":
                has_children = db.execute(
                    """SELECT 1 FROM analyst_investigation_notes
                       WHERE parent_id = ? LIMIT 1""",
                    (note_id,),
                ).fetchone()
                if has_children is not None:
                    raise ValueError(
                        "A folder with items inside it cannot be changed into a note"
                    )
            version = int(existing["version"]) + 1
            updated = db.execute(
                """UPDATE analyst_investigation_notes
                   SET parent_id = ?, kind = ?, title = ?, content = ?, context_json = ?,
                       version = ?, updated_at = ?
                   WHERE note_id = ? AND owner = ? AND version = ?""",
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
                    expected_version,
                ),
            )
            if updated.rowcount != 1:
                raise NoteConflict(
                    "This note changed in another session; reload it before saving"
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
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
    result = _decode(row)
    result["writable"] = True
    return result


def delete_note(
    db_path: Path,
    *,
    owner: str,
    note_id: str,
    expected_version: int,
    branch_revision: str | None = None,
) -> dict:
    db, snapshot = _prepare_branch_mutation(
        db_path,
        owner=owner,
        note_id=note_id,
        expected_version=expected_version,
        branch_revision=branch_revision,
        action="deleting",
    )
    try:
        db.execute("BEGIN IMMEDIATE")
        row = _revalidate_staged_branch(
            db, owner=owner, note_id=note_id, snapshot=snapshot, action="deleting"
        )
        deleted = db.execute(
            """DELETE FROM analyst_investigation_notes
               WHERE owner = ?
                 AND note_id IN (SELECT note_id FROM nct_note_branch_stage)""",
            (owner,),
        ).rowcount
        if deleted != snapshot["items_total"]:
            raise NoteConflict("The complete folder could not be deleted; nothing was changed")
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
                f"Deleted {snapshot['items_total']} item(s)",
            ),
        )
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
    return {
        "deleted": True,
        "note_id": note_id,
        "title": snapshot["title"],
        "items_removed": snapshot["items_total"],
        "folders_removed": snapshot["folder_count"],
        "notes_removed": snapshot["note_count"],
    }


def share_note(
    db_path: Path,
    *,
    owner: str,
    note_id: str,
    expected_version: int,
    shared: bool,
    page: str | None = None,
    branch_revision: str | None = None,
) -> dict:
    page = str(page or "").strip().lower() or None
    if shared and page not in {"device", "nmap", "analyze", "hunt", "reach", "map"}:
        raise ValueError("Choose the NCT page where this note should be shared")
    db, snapshot = _prepare_branch_mutation(
        db_path,
        owner=owner,
        note_id=note_id,
        expected_version=expected_version,
        branch_revision=branch_revision,
        action="changing its sharing",
    )
    try:
        db.execute("BEGIN IMMEDIATE")
        _revalidate_staged_branch(
            db,
            owner=owner,
            note_id=note_id,
            snapshot=snapshot,
            action="changing its sharing",
        )
        visibility = "shared" if shared else "personal"
        changed_at = utc_now()
        updated_count = db.execute(
            """UPDATE analyst_investigation_notes
                SET visibility = ?, shared_page = ?, version = version + 1, updated_at = ?
                WHERE owner = ?
                  AND note_id IN (SELECT note_id FROM nct_note_branch_stage)""",
            (visibility, page if shared else None, changed_at, owner),
        ).rowcount
        if updated_count != snapshot["items_total"]:
            raise NoteConflict("The complete folder could not be updated; nothing was changed")
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
                f"Updated {snapshot['items_total']} item(s)",
            ),
        )
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
    result = _decode(updated)
    result["writable"] = True
    result["items_updated"] = snapshot["items_total"]
    result["folders_updated"] = snapshot["folder_count"]
    result["notes_updated"] = snapshot["note_count"]
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
