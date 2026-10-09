"""Disposable, rollback-safe indexes for retained scan history."""
from __future__ import annotations

import json
from pathlib import Path

from app.database import connect_database, initialize_once_per_database
from app.scan_history import (
    decode_scan_history_cursor,
    encode_scan_history_cursor,
    scan_history_memberships,
)


INDEX_VERSION = 2
METADATA_EXPRESSION = (
    "json_remove(r.manifest_json, '$.artifacts', '$.commands', "
    "'$.execution_steps', '$.stdout', '$.stderr', '$.profile_settings', "
    "'$.command', '$.exact_execution_command')"
)


@initialize_once_per_database
def init_scan_history_index_storage(db_path: Path) -> None:
    """Create and backfill a disposable index without changing scan evidence."""
    with connect_database(db_path) as db:
        # Version 1 used application-defined SQL functions inside persistent
        # triggers. Remove them before creating rollback-compatible triggers so
        # an older build can continue writing to this database.
        db.executescript(
            """
            DROP TRIGGER IF EXISTS scan_history_run_insert;
            DROP TRIGGER IF EXISTS scan_history_run_update;
            """
        )
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS scan_history_memberships (
                run_id TEXT NOT NULL,
                group_id TEXT NOT NULL,
                kind TEXT NOT NULL,
                name TEXT NOT NULL,
                cidr TEXT NOT NULL,
                description TEXT NOT NULL,
                category TEXT NOT NULL,
                tags_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                latest_scan_at TEXT NOT NULL,
                latest_scan_name TEXT,
                host_count INTEGER,
                PRIMARY KEY (run_id, group_id),
                FOREIGN KEY (run_id) REFERENCES scan_runs(run_id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS scan_history_memberships_group_page
                ON scan_history_memberships(group_id, created_at DESC, run_id DESC);
            CREATE INDEX IF NOT EXISTS scan_history_memberships_run
                ON scan_history_memberships(run_id, group_id);

            CREATE TABLE IF NOT EXISTS scan_history_groups (
                group_id TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                name TEXT NOT NULL,
                cidr TEXT NOT NULL,
                description TEXT NOT NULL,
                category TEXT NOT NULL,
                tags_json TEXT NOT NULL,
                scan_count INTEGER NOT NULL,
                latest_created_at TEXT NOT NULL,
                latest_run_id TEXT NOT NULL,
                latest_scan_at TEXT NOT NULL,
                latest_scan_name TEXT,
                latest_host_count INTEGER
            );
            CREATE INDEX IF NOT EXISTS scan_history_groups_catalog
                ON scan_history_groups(kind, name COLLATE NOCASE, cidr, group_id);

            CREATE TABLE IF NOT EXISTS scan_history_index_meta (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                version INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS scan_history_index_dirty (
                run_id TEXT PRIMARY KEY,
                changed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (run_id) REFERENCES scan_runs(run_id) ON DELETE CASCADE
            );

            CREATE TRIGGER IF NOT EXISTS scan_history_membership_group_insert
            AFTER INSERT ON scan_history_memberships
            BEGIN
                INSERT INTO scan_history_groups (
                    group_id, kind, name, cidr, description, category, tags_json,
                    scan_count, latest_created_at, latest_run_id, latest_scan_at,
                    latest_scan_name, latest_host_count
                ) VALUES (
                    NEW.group_id, NEW.kind, NEW.name, NEW.cidr, NEW.description,
                    NEW.category, NEW.tags_json, 1, NEW.created_at, NEW.run_id,
                    NEW.latest_scan_at, NEW.latest_scan_name, NEW.host_count
                )
                ON CONFLICT(group_id) DO UPDATE SET
                    scan_count = scan_history_groups.scan_count + 1,
                    kind = CASE WHEN excluded.latest_created_at > scan_history_groups.latest_created_at
                                   OR (excluded.latest_created_at = scan_history_groups.latest_created_at
                                       AND excluded.latest_run_id > scan_history_groups.latest_run_id)
                                THEN excluded.kind ELSE scan_history_groups.kind END,
                    name = CASE WHEN excluded.latest_created_at > scan_history_groups.latest_created_at
                                   OR (excluded.latest_created_at = scan_history_groups.latest_created_at
                                       AND excluded.latest_run_id > scan_history_groups.latest_run_id)
                                THEN excluded.name ELSE scan_history_groups.name END,
                    cidr = CASE WHEN excluded.latest_created_at > scan_history_groups.latest_created_at
                                   OR (excluded.latest_created_at = scan_history_groups.latest_created_at
                                       AND excluded.latest_run_id > scan_history_groups.latest_run_id)
                                THEN excluded.cidr ELSE scan_history_groups.cidr END,
                    description = CASE WHEN excluded.latest_created_at > scan_history_groups.latest_created_at
                                   OR (excluded.latest_created_at = scan_history_groups.latest_created_at
                                       AND excluded.latest_run_id > scan_history_groups.latest_run_id)
                                THEN excluded.description ELSE scan_history_groups.description END,
                    category = CASE WHEN excluded.latest_created_at > scan_history_groups.latest_created_at
                                   OR (excluded.latest_created_at = scan_history_groups.latest_created_at
                                       AND excluded.latest_run_id > scan_history_groups.latest_run_id)
                                THEN excluded.category ELSE scan_history_groups.category END,
                    tags_json = CASE WHEN excluded.latest_created_at > scan_history_groups.latest_created_at
                                   OR (excluded.latest_created_at = scan_history_groups.latest_created_at
                                       AND excluded.latest_run_id > scan_history_groups.latest_run_id)
                                THEN excluded.tags_json ELSE scan_history_groups.tags_json END,
                    latest_scan_at = CASE WHEN excluded.latest_created_at > scan_history_groups.latest_created_at
                                   OR (excluded.latest_created_at = scan_history_groups.latest_created_at
                                       AND excluded.latest_run_id > scan_history_groups.latest_run_id)
                                THEN excluded.latest_scan_at ELSE scan_history_groups.latest_scan_at END,
                    latest_scan_name = CASE WHEN excluded.latest_created_at > scan_history_groups.latest_created_at
                                   OR (excluded.latest_created_at = scan_history_groups.latest_created_at
                                       AND excluded.latest_run_id > scan_history_groups.latest_run_id)
                                THEN excluded.latest_scan_name ELSE scan_history_groups.latest_scan_name END,
                    latest_host_count = CASE WHEN excluded.latest_created_at > scan_history_groups.latest_created_at
                                   OR (excluded.latest_created_at = scan_history_groups.latest_created_at
                                       AND excluded.latest_run_id > scan_history_groups.latest_run_id)
                                THEN excluded.latest_host_count ELSE scan_history_groups.latest_host_count END,
                    latest_created_at = MAX(scan_history_groups.latest_created_at, excluded.latest_created_at),
                    latest_run_id = CASE WHEN excluded.latest_created_at > scan_history_groups.latest_created_at
                                   OR (excluded.latest_created_at = scan_history_groups.latest_created_at
                                       AND excluded.latest_run_id > scan_history_groups.latest_run_id)
                                THEN excluded.latest_run_id ELSE scan_history_groups.latest_run_id END;
            END;

            CREATE TRIGGER IF NOT EXISTS scan_history_membership_group_delete
            AFTER DELETE ON scan_history_memberships
            BEGIN
                UPDATE scan_history_groups
                   SET scan_count = scan_count - 1
                 WHERE group_id = OLD.group_id;
                DELETE FROM scan_history_groups
                 WHERE group_id = OLD.group_id AND scan_count <= 0;
                UPDATE scan_history_groups
                   SET (kind, name, cidr, description, category, tags_json,
                        latest_created_at, latest_run_id, latest_scan_at,
                        latest_scan_name, latest_host_count) = (
                       SELECT kind, name, cidr, description, category, tags_json,
                              created_at, run_id, latest_scan_at,
                              latest_scan_name, host_count
                         FROM scan_history_memberships
                        WHERE group_id = OLD.group_id
                        ORDER BY created_at DESC, run_id DESC
                        LIMIT 1
                   )
                 WHERE group_id = OLD.group_id AND latest_run_id = OLD.run_id;
            END;

            CREATE TRIGGER IF NOT EXISTS scan_history_run_dirty_insert
            AFTER INSERT ON scan_runs
            BEGIN
                INSERT INTO scan_history_index_dirty (run_id, changed_at)
                VALUES (NEW.run_id, CURRENT_TIMESTAMP)
                ON CONFLICT(run_id) DO UPDATE SET changed_at = excluded.changed_at;
            END;

            CREATE TRIGGER IF NOT EXISTS scan_history_run_dirty_update
            AFTER UPDATE OF manifest_json ON scan_runs
            BEGIN
                INSERT INTO scan_history_index_dirty (run_id, changed_at)
                VALUES (NEW.run_id, CURRENT_TIMESTAMP)
                ON CONFLICT(run_id) DO UPDATE SET changed_at = excluded.changed_at;
            END;

            CREATE TRIGGER IF NOT EXISTS scan_history_run_index_delete
            AFTER DELETE ON scan_runs
            BEGIN
                DELETE FROM scan_history_memberships WHERE run_id = OLD.run_id;
                DELETE FROM scan_history_index_dirty WHERE run_id = OLD.run_id;
            END;
            """
        )
        version_row = db.execute(
            "SELECT version FROM scan_history_index_meta WHERE singleton = 1"
        ).fetchone()
        if version_row is None or int(version_row[0]) != INDEX_VERSION:
            db.execute("DELETE FROM scan_history_memberships")
            db.execute("DELETE FROM scan_history_groups")
            db.execute(
                """INSERT OR REPLACE INTO scan_history_index_dirty (run_id, changed_at)
                   SELECT run_id, CURRENT_TIMESTAMP FROM scan_runs"""
            )
            db.execute(
                """INSERT INTO scan_history_index_meta (singleton, version)
                   VALUES (1, ?)
                   ON CONFLICT(singleton) DO UPDATE SET version = excluded.version""",
                (INDEX_VERSION,),
            )
        _reconcile_scan_history_index(db)


def sync_scan_history_manifest(
    db, manifest: dict, *, run_id: str | None = None, created_at: str | None = None
) -> None:
    """Synchronize one derived index entry inside the caller's transaction."""
    resolved_run_id = str(run_id or manifest["run_id"])
    resolved_created_at = str(created_at or manifest.get("created_at") or "")
    latest_scan_at = str(
        manifest.get("completed_at") or manifest.get("created_at") or resolved_created_at
    )
    latest_scan_name = manifest.get("display_name") or manifest.get("name")
    host_count = manifest.get("host_count")
    if not isinstance(host_count, int):
        host_count = None
    db.execute(
        "DELETE FROM scan_history_memberships WHERE run_id = ?",
        (resolved_run_id,),
    )
    rows = []
    for membership in scan_history_memberships(manifest):
        rows.append(
            (
                resolved_run_id,
                membership["group_id"],
                membership["kind"],
                membership["name"],
                membership.get("cidr") or "",
                membership.get("description") or "",
                membership.get("category") or "",
                json.dumps(membership.get("tags") or [], separators=(",", ":")),
                resolved_created_at,
                latest_scan_at,
                latest_scan_name,
                host_count,
            )
        )
    db.executemany(
        """INSERT INTO scan_history_memberships (
               run_id, group_id, kind, name, cidr, description, category,
               tags_json, created_at, latest_scan_at, latest_scan_name, host_count
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        rows,
    )
    db.execute(
        "DELETE FROM scan_history_index_dirty WHERE run_id = ?",
        (resolved_run_id,),
    )


def _reconcile_scan_history_index(db) -> None:
    rows = db.execute(
        """SELECT d.run_id, r.created_at, r.manifest_json
             FROM scan_history_index_dirty d
             JOIN scan_runs r ON r.run_id = d.run_id
            ORDER BY d.run_id"""
    ).fetchall()
    for run_id, created_at, manifest_json in rows:
        try:
            manifest = json.loads(manifest_json)
        except (TypeError, ValueError, json.JSONDecodeError):
            manifest = None
        if isinstance(manifest, dict):
            sync_scan_history_manifest(
                db, manifest, run_id=run_id, created_at=created_at
            )
        else:
            db.execute(
                "DELETE FROM scan_history_memberships WHERE run_id = ?", (run_id,)
            )
            db.execute(
                "DELETE FROM scan_history_index_dirty WHERE run_id = ?", (run_id,)
            )


def reconcile_scan_history_index(db_path: Path) -> None:
    """Repair index entries marked by writes from a rollback build."""
    with connect_database(db_path) as db:
        _reconcile_scan_history_index(db)


def scan_history_catalog_page(
    db_path: Path, *, limit: int, offset: int
) -> dict:
    with connect_database(db_path, read_only=True) as db:
        db.execute("BEGIN")
        total = int(db.execute("SELECT COUNT(*) FROM scan_history_groups").fetchone()[0])
        rows = db.execute(
            """
            SELECT group_id, kind, name, cidr, description, category, tags_json,
                   scan_count, latest_scan_at, latest_scan_name, latest_host_count
              FROM scan_history_groups
             ORDER BY CASE kind
                        WHEN 'subnet' THEN 0 WHEN 'host_targets' THEN 1
                        WHEN 'legacy_targets' THEN 2 WHEN 'missing_targets' THEN 3
                        ELSE 99 END,
                      name COLLATE NOCASE, cidr, group_id
             LIMIT ? OFFSET ?
            """,
            (limit, offset),
        ).fetchall()
    groups = [
        {
            "group_id": row[0], "kind": row[1], "name": row[2], "cidr": row[3],
            "description": row[4], "category": row[5],
            "tags": json.loads(row[6]), "scan_count": int(row[7]),
            "latest_scan_at": row[8], "latest_scan_name": row[9],
            "latest_host_count": row[10],
        }
        for row in rows
    ]
    return {
        "groups": groups, "total": total, "limit": limit, "offset": offset,
        "has_more": offset + len(groups) < total,
    }


def scan_history_group_page_from_index(
    db_path: Path, group_id: str, *, limit: int, cursor: str | None = None
) -> dict | None:
    before = decode_scan_history_cursor(cursor)
    with connect_database(db_path, read_only=True) as db:
        db.execute("BEGIN")
        group = db.execute(
            """SELECT group_id, kind, name, cidr, description, category, tags_json,
                      scan_count
                 FROM scan_history_groups WHERE group_id = ?""",
            (group_id,),
        ).fetchone()
        if group is None:
            return None
        parameters: list[object] = [group_id]
        cursor_sql = ""
        if before is not None:
            cursor_sql = " AND (m.created_at < ? OR (m.created_at = ? AND m.run_id < ?))"
            parameters.extend([before[0], before[0], before[1]])
        parameters.append(limit + 1)
        rows = db.execute(
            f"""
            SELECT m.run_id, m.created_at, {METADATA_EXPRESSION}
              FROM scan_history_memberships m
              JOIN scan_runs r ON r.run_id = m.run_id
             WHERE m.group_id = ?{cursor_sql}
             ORDER BY m.created_at DESC, m.run_id DESC
             LIMIT ?
            """,
            tuple(parameters),
        ).fetchall()
        page_rows = rows[:limit]
        run_ids = [row[0] for row in page_rows]
        other_rows = []
        if run_ids:
            placeholders = ",".join("?" for _ in run_ids)
            other_rows = db.execute(
                f"""SELECT run_id, group_id, name, cidr
                       FROM scan_history_memberships
                      WHERE run_id IN ({placeholders}) AND group_id != ?
                      ORDER BY run_id, name COLLATE NOCASE, cidr, group_id""",
                (*run_ids, group_id),
            ).fetchall()
    others: dict[str, list[dict]] = {run_id: [] for run_id in run_ids}
    for run_id, other_id, name, cidr in other_rows:
        others[run_id].append({"group_id": other_id, "name": name, "cidr": cidr})
    runs = []
    for run_id, _created_at, manifest_json in page_rows:
        manifest = json.loads(manifest_json)
        # The row key and sort value are authoritative. Early retained
        # manifests did not always embed them, but cursors still need the exact
        # values used by the indexed ORDER BY clause.
        manifest["run_id"] = run_id
        manifest["created_at"] = _created_at
        manifest["history_also_covers"] = others.get(run_id, [])
        runs.append(manifest)
    has_more = len(rows) > limit
    return {
        "group": {
            "group_id": group[0], "kind": group[1], "name": group[2],
            "cidr": group[3], "description": group[4], "category": group[5],
            "tags": json.loads(group[6]),
        },
        "runs": runs,
        "total": int(group[7]),
        "limit": limit,
        "next_cursor": encode_scan_history_cursor(runs[-1]) if runs and has_more else None,
        "has_more": has_more,
    }
