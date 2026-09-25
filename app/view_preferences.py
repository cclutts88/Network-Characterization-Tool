from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
import uuid


VALID_PAGES = {"hunt", "analyze"}


class ViewPreferenceConflict(ValueError):
    pass


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def init_view_preference_storage(db_path: Path) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(db_path) as db:
        db.execute(
            """CREATE TABLE IF NOT EXISTS analyst_view_preferences (
                owner TEXT NOT NULL,
                page TEXT NOT NULL,
                snapshot_json TEXT NOT NULL,
                version INTEGER NOT NULL DEFAULT 1,
                updated_at TEXT NOT NULL,
                PRIMARY KEY(owner, page)
            )"""
        )
        db.execute(
            """CREATE TABLE IF NOT EXISTS analyst_filter_presets (
                preset_id TEXT PRIMARY KEY,
                owner TEXT NOT NULL,
                page TEXT NOT NULL,
                name TEXT NOT NULL,
                snapshot_json TEXT NOT NULL,
                version INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(owner, page, name)
            )"""
        )
        db.execute(
            """CREATE INDEX IF NOT EXISTS analyst_filter_presets_owner_page
               ON analyst_filter_presets(owner, page, lower(name))"""
        )


def _page(value: object) -> str:
    page = str(value or "").strip().lower()
    if page not in VALID_PAGES:
        raise ValueError("View preferences are available only for Hunt and Analyze")
    return page


def _snapshot(value: object) -> tuple[dict, str]:
    if not isinstance(value, dict):
        raise ValueError("View snapshot must be an object")
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"))
    if len(encoded) > 128_000:
        raise ValueError("View snapshot exceeds the 128 KB limit")
    return value, encoded


def _decode(row: sqlite3.Row | None) -> dict | None:
    if row is None:
        return None
    item = dict(row)
    item["snapshot"] = json.loads(item.pop("snapshot_json"))
    return item


def get_view_workspace(db_path: Path, *, owner: str, page: str) -> dict:
    page = _page(page)
    init_view_preference_storage(db_path)
    with sqlite3.connect(db_path) as db:
        db.row_factory = sqlite3.Row
        preference = db.execute(
            "SELECT * FROM analyst_view_preferences WHERE owner = ? AND page = ?",
            (owner, page),
        ).fetchone()
        presets = db.execute(
            """SELECT * FROM analyst_filter_presets
               WHERE owner = ? AND page = ? ORDER BY lower(name), created_at""",
            (owner, page),
        ).fetchall()
    return {
        "owner": owner,
        "page": page,
        "preference": _decode(preference),
        "presets": [_decode(row) for row in presets],
    }


def save_view_preference(
    db_path: Path,
    *,
    owner: str,
    page: str,
    snapshot: dict,
    expected_version: int | None,
) -> dict:
    page = _page(page)
    _, encoded = _snapshot(snapshot)
    changed_at = utc_now()
    init_view_preference_storage(db_path)
    with sqlite3.connect(db_path) as db:
        db.row_factory = sqlite3.Row
        existing = db.execute(
            "SELECT * FROM analyst_view_preferences WHERE owner = ? AND page = ?",
            (owner, page),
        ).fetchone()
        if existing is None:
            if expected_version not in {None, 0}:
                raise ViewPreferenceConflict("This personal view was reset in another session; reload it")
            db.execute(
                """INSERT INTO analyst_view_preferences
                   (owner, page, snapshot_json, version, updated_at)
                   VALUES (?, ?, ?, 1, ?)""",
                (owner, page, encoded, changed_at),
            )
        else:
            if expected_version != int(existing["version"]):
                raise ViewPreferenceConflict(
                    "This personal view changed in another session; reload before saving"
                )
            db.execute(
                """UPDATE analyst_view_preferences
                   SET snapshot_json = ?, version = ?, updated_at = ?
                   WHERE owner = ? AND page = ?""",
                (encoded, int(existing["version"]) + 1, changed_at, owner, page),
            )
        row = db.execute(
            "SELECT * FROM analyst_view_preferences WHERE owner = ? AND page = ?",
            (owner, page),
        ).fetchone()
    return _decode(row)


def save_filter_preset(
    db_path: Path,
    *,
    owner: str,
    page: str,
    name: object,
    snapshot: dict,
    preset_id: str | None = None,
    expected_version: int | None = None,
) -> dict:
    page = _page(page)
    name = str(name or "").strip()
    if not name or len(name) > 100:
        raise ValueError("Preset name is required and must be 100 characters or fewer")
    _, encoded = _snapshot(snapshot)
    changed_at = utc_now()
    init_view_preference_storage(db_path)
    with sqlite3.connect(db_path) as db:
        db.row_factory = sqlite3.Row
        if preset_id:
            existing = db.execute(
                "SELECT * FROM analyst_filter_presets WHERE preset_id = ? AND owner = ? AND page = ?",
                (preset_id, owner, page),
            ).fetchone()
            if existing is None:
                raise KeyError(preset_id)
            if expected_version != int(existing["version"]):
                raise ViewPreferenceConflict("This preset changed in another session; reload it")
            try:
                db.execute(
                    """UPDATE analyst_filter_presets
                       SET name = ?, snapshot_json = ?, version = ?, updated_at = ?
                       WHERE preset_id = ? AND owner = ?""",
                    (
                        name,
                        encoded,
                        int(existing["version"]) + 1,
                        changed_at,
                        preset_id,
                        owner,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise ValueError("A personal preset with that name already exists") from exc
        else:
            preset_id = uuid.uuid4().hex
            try:
                db.execute(
                    """INSERT INTO analyst_filter_presets
                       (preset_id, owner, page, name, snapshot_json, version, created_at, updated_at)
                       VALUES (?, ?, ?, ?, ?, 1, ?, ?)""",
                    (preset_id, owner, page, name, encoded, changed_at, changed_at),
                )
            except sqlite3.IntegrityError as exc:
                raise ValueError("A personal preset with that name already exists") from exc
        row = db.execute(
            "SELECT * FROM analyst_filter_presets WHERE preset_id = ?", (preset_id,)
        ).fetchone()
    return _decode(row)


def delete_filter_preset(
    db_path: Path,
    *,
    owner: str,
    page: str,
    preset_id: str,
    expected_version: int,
) -> dict:
    page = _page(page)
    init_view_preference_storage(db_path)
    with sqlite3.connect(db_path) as db:
        db.row_factory = sqlite3.Row
        row = db.execute(
            "SELECT * FROM analyst_filter_presets WHERE preset_id = ? AND owner = ? AND page = ?",
            (preset_id, owner, page),
        ).fetchone()
        if row is None:
            raise KeyError(preset_id)
        if expected_version != int(row["version"]):
            raise ViewPreferenceConflict("This preset changed in another session; reload it")
        db.execute("DELETE FROM analyst_filter_presets WHERE preset_id = ?", (preset_id,))
    return {"status": "deleted", "preset_id": preset_id, "version": row["version"]}
