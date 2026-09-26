from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
import uuid

from app.database import connect_database


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def init_shell_preference_storage(db_path: Path) -> None:
    with connect_database(db_path) as db:
        db.execute(
            """CREATE TABLE IF NOT EXISTS analyst_shell_preferences (
                owner TEXT PRIMARY KEY,
                snapshot_json TEXT NOT NULL,
                version INTEGER NOT NULL DEFAULT 1,
                updated_at TEXT NOT NULL
            )"""
        )
        db.execute(
            """CREATE TABLE IF NOT EXISTS shared_analyst_themes (
                theme_id TEXT PRIMARY KEY,
                source_theme_id TEXT NOT NULL,
                owner TEXT NOT NULL,
                name TEXT NOT NULL,
                snapshot_json TEXT NOT NULL,
                version INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(owner, source_theme_id)
            )"""
        )


def _snapshot(value: object) -> tuple[dict, str]:
    if not isinstance(value, dict):
        raise ValueError("Shell preference snapshot must be an object")
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"))
    if len(encoded) > 32_000:
        raise ValueError("Shell preference snapshot exceeds the 32 KB limit")
    return value, encoded


def _decode(row: sqlite3.Row | None) -> dict | None:
    if row is None:
        return None
    item = dict(row)
    item["snapshot"] = json.loads(item.pop("snapshot_json"))
    return item


def get_shell_preference(db_path: Path, *, owner: str) -> dict | None:
    init_shell_preference_storage(db_path)
    with connect_database(db_path) as db:
        db.row_factory = sqlite3.Row
        row = db.execute(
            "SELECT * FROM analyst_shell_preferences WHERE owner = ?", (owner,)
        ).fetchone()
    return _decode(row)


def save_shell_preference(db_path: Path, *, owner: str, snapshot: dict) -> dict:
    _, encoded = _snapshot(snapshot)
    changed_at = utc_now()
    init_shell_preference_storage(db_path)
    with connect_database(db_path) as db:
        db.row_factory = sqlite3.Row
        db.execute(
            """INSERT INTO analyst_shell_preferences
               (owner, snapshot_json, version, updated_at)
               VALUES (?, ?, 1, ?)
               ON CONFLICT(owner) DO UPDATE SET
                 snapshot_json = excluded.snapshot_json,
                 version = analyst_shell_preferences.version + 1,
                 updated_at = excluded.updated_at""",
            (owner, encoded, changed_at),
        )
        row = db.execute(
            "SELECT * FROM analyst_shell_preferences WHERE owner = ?", (owner,)
        ).fetchone()
    return _decode(row)


def list_shared_themes(db_path: Path) -> list[dict]:
    init_shell_preference_storage(db_path)
    with connect_database(db_path) as db:
        db.row_factory = sqlite3.Row
        rows = db.execute(
            """SELECT * FROM shared_analyst_themes
               ORDER BY lower(name), lower(owner), updated_at DESC"""
        ).fetchall()
    return [_decode(row) for row in rows]


def publish_shared_theme(
    db_path: Path,
    *,
    owner: str,
    source_theme_id: str,
    name: str,
    snapshot: dict,
) -> dict:
    clean_source = source_theme_id.strip()[:64]
    clean_name = name.strip()[:48]
    if not clean_source or not clean_name:
        raise ValueError("Shared themes require a source id and name")
    _, encoded = _snapshot(snapshot)
    changed_at = utc_now()
    init_shell_preference_storage(db_path)
    with connect_database(db_path) as db:
        db.row_factory = sqlite3.Row
        existing = db.execute(
            """SELECT theme_id FROM shared_analyst_themes
               WHERE owner = ? AND source_theme_id = ?""",
            (owner, clean_source),
        ).fetchone()
        theme_id = existing["theme_id"] if existing else uuid.uuid4().hex
        db.execute(
            """INSERT INTO shared_analyst_themes
               (theme_id, source_theme_id, owner, name, snapshot_json,
                version, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, 1, ?, ?)
               ON CONFLICT(owner, source_theme_id) DO UPDATE SET
                 name = excluded.name,
                 snapshot_json = excluded.snapshot_json,
                 version = shared_analyst_themes.version + 1,
                 updated_at = excluded.updated_at""",
            (
                theme_id,
                clean_source,
                owner,
                clean_name,
                encoded,
                changed_at,
                changed_at,
            ),
        )
        row = db.execute(
            """SELECT * FROM shared_analyst_themes
               WHERE owner = ? AND source_theme_id = ?""",
            (owner, clean_source),
        ).fetchone()
    return _decode(row)


def delete_shared_theme(db_path: Path, *, owner: str, theme_id: str) -> bool:
    init_shell_preference_storage(db_path)
    with connect_database(db_path) as db:
        deleted = db.execute(
            "DELETE FROM shared_analyst_themes WHERE theme_id = ? AND owner = ?",
            (theme_id, owner),
        ).rowcount
    return bool(deleted)
