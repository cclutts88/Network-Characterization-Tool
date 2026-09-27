"""Operator-managed network contexts for evidence identity.

Labels are editable display metadata. Opaque scope IDs are the identity and are
never derived from a CIDR, Saved Network, target, filename, or artifact.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
import unicodedata
import uuid

from app.database import connect_database, initialize_once_per_database


class NetworkScopeConflict(ValueError):
    pass


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _text(value, field: str, maximum: int) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be text")
    cleaned = value.strip()
    if not cleaned:
        raise ValueError(f"{field} cannot be blank")
    if len(cleaned) > maximum:
        raise ValueError(f"{field} exceeds {maximum} characters")
    return cleaned


def _description(value) -> str:
    if not isinstance(value, str):
        raise ValueError("description must be text")
    cleaned = value.strip()
    if len(cleaned) > 500:
        raise ValueError("description exceeds 500 characters")
    return cleaned


def _label_key(label: str) -> str:
    return unicodedata.normalize("NFKC", label).casefold()


def _snapshot(row: sqlite3.Row | None) -> dict | None:
    if row is None:
        return None
    return {
        "scope_id": row["scope_id"], "label": row["label"],
        "description": row["description"], "version": int(row["version"]),
        "active": bool(row["active"]), "created_at": row["created_at"],
        "created_by": row["created_by"], "updated_at": row["updated_at"],
        "updated_by": row["updated_by"], "archived_at": row["archived_at"],
        "archived_by": row["archived_by"], "legacy": bool(row["legacy"]),
    }


def _scope_row(db: sqlite3.Connection, scope_id: str) -> sqlite3.Row | None:
    db.row_factory = sqlite3.Row
    return db.execute("SELECT * FROM network_scopes WHERE scope_id = ?", (scope_id,)).fetchone()


def _audit(db: sqlite3.Connection, *, scope_id: str, event: str, actor: str,
           reason: str, before: dict | None, after: dict) -> None:
    sequence = db.execute(
        "SELECT COALESCE(MAX(sequence), 0) + 1 FROM network_scope_audit WHERE scope_id = ?",
        (scope_id,),
    ).fetchone()[0]
    db.execute(
        """INSERT INTO network_scope_audit (
               audit_id, scope_id, sequence, event, actor, reason, previous_version,
               new_version, before_json, after_json, recorded_at
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (uuid.uuid4().hex, scope_id, sequence, event, actor, reason,
         before["version"] if before else None, after["version"],
         json.dumps(before, sort_keys=True) if before else None,
         json.dumps(after, sort_keys=True), utc_now()),
    )


@initialize_once_per_database
def init_network_scope_storage(db_path: Path) -> None:
    with connect_database(db_path) as db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS network_scopes (
                scope_id TEXT PRIMARY KEY,
                label TEXT NOT NULL,
                label_key TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                version INTEGER NOT NULL CHECK(version >= 1),
                active INTEGER NOT NULL CHECK(active IN (0, 1)),
                created_at TEXT NOT NULL,
                created_by TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                updated_by TEXT NOT NULL,
                archived_at TEXT,
                archived_by TEXT,
                legacy INTEGER NOT NULL DEFAULT 0 CHECK(legacy IN (0, 1))
            );
            CREATE UNIQUE INDEX IF NOT EXISTS network_scopes_active_label
                ON network_scopes(label_key) WHERE active = 1;
            CREATE TABLE IF NOT EXISTS network_scope_audit (
                audit_id TEXT PRIMARY KEY,
                scope_id TEXT NOT NULL REFERENCES network_scopes(scope_id),
                sequence INTEGER NOT NULL,
                event TEXT NOT NULL,
                actor TEXT NOT NULL,
                reason TEXT NOT NULL,
                previous_version INTEGER,
                new_version INTEGER NOT NULL,
                before_json TEXT,
                after_json TEXT NOT NULL,
                recorded_at TEXT NOT NULL,
                UNIQUE(scope_id, sequence)
            );
            CREATE INDEX IF NOT EXISTS network_scope_audit_scope
                ON network_scope_audit(scope_id, recorded_at, audit_id);
            CREATE TRIGGER IF NOT EXISTS network_scopes_no_delete
                BEFORE DELETE ON network_scopes
                BEGIN SELECT RAISE(ABORT, 'network scopes cannot be deleted'); END;
            CREATE TRIGGER IF NOT EXISTS network_scopes_id_immutable
                BEFORE UPDATE OF scope_id ON network_scopes
                BEGIN SELECT RAISE(ABORT, 'network scope identity is immutable'); END;
            CREATE TRIGGER IF NOT EXISTS network_scope_audit_no_update
                BEFORE UPDATE ON network_scope_audit
                BEGIN SELECT RAISE(ABORT, 'network scope audit is immutable'); END;
            CREATE TRIGGER IF NOT EXISTS network_scope_audit_no_delete
                BEFORE DELETE ON network_scope_audit
                BEGIN SELECT RAISE(ABORT, 'network scope audit is immutable'); END;
        """)
        # Register explicit IDs retained by the earlier internal endpoint slice.
        # They remain inactive until a future reviewed correction/assignment flow.
        tables = {row[0] for row in db.execute(
            "SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        sources = []
        if "entity_assessments" in tables:
            sources.append("SELECT DISTINCT scope_id FROM entity_assessments")
        if "endpoint_entities" in tables:
            sources.append("SELECT DISTINCT scope_id FROM endpoint_entities")
        legacy_ids = [] if not sources else [row[0] for row in db.execute(
            " UNION ".join(sources) + " ORDER BY scope_id").fetchall()]
        for scope_id in legacy_ids:
            if db.execute("SELECT 1 FROM network_scopes WHERE scope_id = ?", (scope_id,)).fetchone():
                continue
            timestamp = utc_now()
            label = f"Legacy scope {scope_id}"
            db.execute(
                """INSERT INTO network_scopes VALUES (?, ?, ?, '', 1, 0, ?, ?, ?, ?, ?, ?, 1)""",
                (scope_id, label, _label_key(label), timestamp, "system:migration",
                 timestamp, "system:migration", timestamp, "system:migration"),
            )
            after = _snapshot(_scope_row(db, scope_id))
            _audit(db, scope_id=scope_id, event="migrated", actor="system:migration",
                   reason="Registered pre-existing explicit scope ID as inactive legacy context",
                   before=None, after=after)


def create_network_scope(db_path: Path, *, label: str, description: str = "",
                         created_by: str, reason: str = "Scope created") -> dict:
    init_network_scope_storage(db_path)
    label = _text(label, "label", 100)
    description = _description(description)
    actor = _text(created_by, "created_by", 100)
    reason = _text(reason, "reason", 500)
    scope_id = f"scope_{uuid.uuid4().hex}"
    timestamp = utc_now()
    try:
        with connect_database(db_path) as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute(
                """INSERT INTO network_scopes (
                       scope_id, label, label_key, description, version, active,
                       created_at, created_by, updated_at, updated_by, legacy
                   ) VALUES (?, ?, ?, ?, 1, 1, ?, ?, ?, ?, 0)""",
                (scope_id, label, _label_key(label), description,
                 timestamp, actor, timestamp, actor),
            )
            after = _snapshot(_scope_row(db, scope_id))
            _audit(db, scope_id=scope_id, event="created", actor=actor,
                   reason=reason, before=None, after=after)
    except sqlite3.IntegrityError as exc:
        if "network_scopes.label_key" in str(exc):
            raise ValueError("An active network scope already uses this label") from exc
        raise
    return get_network_scope(db_path, scope_id)


def get_network_scope(db_path: Path, scope_id: str) -> dict | None:
    init_network_scope_storage(db_path)
    with connect_database(db_path) as db:
        return _snapshot(_scope_row(db, scope_id))


def list_network_scopes(db_path: Path, *, include_archived: bool = False) -> list[dict]:
    init_network_scope_storage(db_path)
    with connect_database(db_path) as db:
        db.row_factory = sqlite3.Row
        rows = db.execute(
            "SELECT * FROM network_scopes" + ("" if include_archived else " WHERE active = 1")
            + " ORDER BY active DESC, label_key, scope_id"
        ).fetchall()
    return [_snapshot(row) for row in rows]


def update_network_scope(db_path: Path, scope_id: str, *, expected_version: int,
                         updated_by: str, reason: str, label: str | None = None,
                         description: str | None = None) -> dict:
    init_network_scope_storage(db_path)
    actor = _text(updated_by, "updated_by", 100)
    reason = _text(reason, "reason", 500)
    label = _text(label, "label", 100) if label is not None else None
    description = _description(description) if description is not None else None
    try:
        with connect_database(db_path) as db:
            db.execute("BEGIN IMMEDIATE")
            before = _snapshot(_scope_row(db, scope_id))
            if before is None:
                raise KeyError("Network scope not found")
            if not before["active"]:
                raise ValueError("Archived network scopes cannot be changed")
            if before["version"] != expected_version:
                raise NetworkScopeConflict("Network scope changed in another session")
            next_label = label if label is not None else before["label"]
            next_description = description if description is not None else before["description"]
            if next_label == before["label"] and next_description == before["description"]:
                return before
            timestamp = utc_now()
            changed = db.execute(
                """UPDATE network_scopes SET label = ?, label_key = ?, description = ?,
                       version = version + 1, updated_at = ?, updated_by = ?
                   WHERE scope_id = ? AND version = ? AND active = 1""",
                (next_label, _label_key(next_label), next_description, timestamp, actor,
                 scope_id, expected_version),
            ).rowcount
            if changed != 1:
                raise NetworkScopeConflict("Network scope changed in another session")
            after = _snapshot(_scope_row(db, scope_id))
            _audit(db, scope_id=scope_id, event="updated", actor=actor,
                   reason=reason, before=before, after=after)
    except sqlite3.IntegrityError as exc:
        if "network_scopes.label_key" in str(exc):
            raise ValueError("An active network scope already uses this label") from exc
        raise
    return get_network_scope(db_path, scope_id)


def archive_network_scope(db_path: Path, scope_id: str, *, expected_version: int,
                          archived_by: str, reason: str) -> dict:
    init_network_scope_storage(db_path)
    actor = _text(archived_by, "archived_by", 100)
    reason = _text(reason, "reason", 500)
    with connect_database(db_path) as db:
        db.execute("BEGIN IMMEDIATE")
        before = _snapshot(_scope_row(db, scope_id))
        if before is None:
            raise KeyError("Network scope not found")
        if not before["active"]:
            raise ValueError("Network scope is already archived")
        if before["version"] != expected_version:
            raise NetworkScopeConflict("Network scope changed in another session")
        timestamp = utc_now()
        changed = db.execute(
            """UPDATE network_scopes SET active = 0, version = version + 1,
                   updated_at = ?, updated_by = ?, archived_at = ?, archived_by = ?
               WHERE scope_id = ? AND version = ? AND active = 1""",
            (timestamp, actor, timestamp, actor, scope_id, expected_version),
        ).rowcount
        if changed != 1:
            raise NetworkScopeConflict("Network scope changed in another session")
        after = _snapshot(_scope_row(db, scope_id))
        _audit(db, scope_id=scope_id, event="archived", actor=actor,
               reason=reason, before=before, after=after)
    return get_network_scope(db_path, scope_id)


def list_network_scope_history(db_path: Path, scope_id: str) -> list[dict]:
    init_network_scope_storage(db_path)
    with connect_database(db_path) as db:
        db.row_factory = sqlite3.Row
        rows = db.execute(
            "SELECT * FROM network_scope_audit WHERE scope_id = ? ORDER BY sequence",
            (scope_id,),
        ).fetchall()
    return [{**dict(row),
             "before": json.loads(row["before_json"]) if row["before_json"] else None,
             "after": json.loads(row["after_json"])} for row in rows]
