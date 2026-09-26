from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3

from app.database import connect_database


ACHIEVEMENTS = {
    "first_scan": {
        "title": "First Contact",
        "category": "Scanning",
        "description": "Start or import the first Nmap scan.",
        "message": "The network has introduced itself. It was not especially forthcoming.",
    },
    "device_collection": {
        "title": "Configuration Whisperer",
        "category": "Collection",
        "description": "Retain a successful network-device collection.",
        "message": "You persuaded a network device to reveal its side of the story.",
    },
    "hostname_confirmed": {
        "title": "Identity Confirmed",
        "category": "Identity",
        "description": "Confirm a hostname from retained evidence or operator review.",
        "message": "An address has a name. The evidence picture just became more human.",
    },
    "reach_evaluated": {
        "title": "Pathfinder",
        "category": "Reach",
        "description": "Complete an evidence-backed Reach evaluation.",
        "message": "A path was tested against evidence instead of optimism.",
    },
    "policy_simulated": {
        "title": "Rules Lawyer",
        "category": "Reach",
        "description": "Validate a proposed policy or route change.",
        "message": "The proposed change survived questioning without touching the network.",
    },
    "map_saved": {
        "title": "Cartographer",
        "category": "Map",
        "description": "Save a personal network-map layout.",
        "message": "You turned retained evidence into a view another human can navigate.",
    },
    "note_created": {
        "title": "Case Builder",
        "category": "Investigation",
        "description": "Create an investigation note.",
        "message": "Future you now has context. Future you is cautiously grateful.",
    },
    "theme_shared": {
        "title": "Interior Decorator",
        "category": "Workspace",
        "description": "Share a personal theme with other analysts.",
        "message": "Operational evidence remains unchanged. Team morale may have improved.",
    },
}


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def init_achievement_storage(db_path: Path) -> None:
    with connect_database(db_path) as db:
        db.execute(
            """CREATE TABLE IF NOT EXISTS analyst_achievements (
                owner TEXT NOT NULL,
                achievement_id TEXT NOT NULL,
                context_json TEXT NOT NULL DEFAULT '{}',
                unlocked_at TEXT NOT NULL,
                PRIMARY KEY(owner, achievement_id)
            )"""
        )


def list_achievements(db_path: Path, *, owner: str) -> list[dict]:
    init_achievement_storage(db_path)
    with connect_database(db_path) as db:
        db.row_factory = sqlite3.Row
        rows = db.execute(
            "SELECT * FROM analyst_achievements WHERE owner = ?", (owner,)
        ).fetchall()
    unlocked = {row["achievement_id"]: dict(row) for row in rows}
    result = []
    for achievement_id, definition in ACHIEVEMENTS.items():
        row = unlocked.get(achievement_id)
        result.append(
            {
                "achievement_id": achievement_id,
                **definition,
                "unlocked": row is not None,
                "unlocked_at": row["unlocked_at"] if row else None,
                "context": json.loads(row["context_json"]) if row else {},
            }
        )
    return result


def unlock_achievement(
    db_path: Path, *, owner: str, achievement_id: str, context: dict | None = None
) -> tuple[dict, bool]:
    if achievement_id not in ACHIEVEMENTS:
        raise KeyError(achievement_id)
    encoded = json.dumps(context or {}, sort_keys=True, separators=(",", ":"))
    if len(encoded) > 4_000:
        raise ValueError("Achievement context exceeds the 4 KB limit")
    init_achievement_storage(db_path)
    unlocked_at = utc_now()
    with connect_database(db_path) as db:
        inserted = db.execute(
            """INSERT OR IGNORE INTO analyst_achievements
               (owner, achievement_id, context_json, unlocked_at)
               VALUES (?, ?, ?, ?)""",
            (owner, achievement_id, encoded, unlocked_at),
        ).rowcount
        db.row_factory = sqlite3.Row
        row = db.execute(
            """SELECT * FROM analyst_achievements
               WHERE owner = ? AND achievement_id = ?""",
            (owner, achievement_id),
        ).fetchone()
    definition = ACHIEVEMENTS[achievement_id]
    return (
        {
            "achievement_id": achievement_id,
            **definition,
            "unlocked": True,
            "unlocked_at": row["unlocked_at"],
            "context": json.loads(row["context_json"]),
        },
        bool(inserted),
    )
