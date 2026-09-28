"""Reviewed Saved Network context and immutable scan evidence snapshots."""
from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
import uuid

from app.database import connect_database, initialize_once_per_database
from app.network_scopes import init_network_scope_storage
from app.saved_networks import init_saved_network_storage


class SavedNetworkScopeConflict(ValueError):
    pass


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _clean_text(value: str, field: str, maximum: int) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be text")
    cleaned = value.strip()
    if not cleaned:
        raise ValueError(f"{field} cannot be blank")
    if len(cleaned) > maximum:
        raise ValueError(f"{field} exceeds {maximum} characters")
    return cleaned


@initialize_once_per_database
def init_saved_network_scope_storage(db_path: Path) -> None:
    init_saved_network_storage(db_path)
    init_network_scope_storage(db_path)
    with connect_database(db_path) as db:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS saved_network_scope_associations (
                association_id TEXT PRIMARY KEY,
                saved_network_id TEXT NOT NULL REFERENCES saved_networks(saved_network_id),
                scope_id TEXT REFERENCES network_scopes(scope_id),
                revision INTEGER NOT NULL CHECK(revision >= 1),
                event TEXT NOT NULL CHECK(event IN ('assigned', 'changed', 'cleared')),
                predecessor_id TEXT REFERENCES saved_network_scope_associations(association_id),
                actor TEXT NOT NULL CHECK(length(trim(actor)) > 0),
                reason TEXT NOT NULL CHECK(length(trim(reason)) > 0),
                recorded_at TEXT NOT NULL,
                CHECK(
                    (event = 'cleared' AND scope_id IS NULL) OR
                    (event IN ('assigned', 'changed') AND scope_id IS NOT NULL)
                ),
                UNIQUE(saved_network_id, revision)
            );
            CREATE UNIQUE INDEX IF NOT EXISTS saved_network_scope_one_root
                ON saved_network_scope_associations(saved_network_id)
                WHERE predecessor_id IS NULL;
            CREATE UNIQUE INDEX IF NOT EXISTS saved_network_scope_one_successor
                ON saved_network_scope_associations(predecessor_id)
                WHERE predecessor_id IS NOT NULL;
            CREATE INDEX IF NOT EXISTS saved_network_scope_current
                ON saved_network_scope_associations(saved_network_id, revision DESC);

            CREATE TRIGGER IF NOT EXISTS saved_network_scope_validate_insert
            BEFORE INSERT ON saved_network_scope_associations
            BEGIN
                SELECT CASE WHEN NEW.actor != trim(NEW.actor)
                    OR length(NEW.actor) < 1 OR length(NEW.actor) > 100
                THEN RAISE(ABORT, 'association actor must be canonical text') END;
                SELECT CASE WHEN NEW.reason != trim(NEW.reason)
                    OR length(NEW.reason) < 1 OR length(NEW.reason) > 500
                THEN RAISE(ABORT, 'association reason must be canonical text') END;
                SELECT CASE WHEN datetime(NEW.recorded_at) IS NULL
                    OR NEW.recorded_at != strftime(
                        '%Y-%m-%dT%H:%M:%S+00:00', NEW.recorded_at
                    )
                THEN RAISE(ABORT, 'association time must be canonical UTC') END;
                SELECT CASE WHEN NOT EXISTS (
                    SELECT 1 FROM saved_networks
                    WHERE saved_network_id = NEW.saved_network_id AND active = 1
                ) THEN RAISE(ABORT, 'Saved Network must exist and be active') END;
                SELECT CASE WHEN NEW.scope_id IS NOT NULL AND NOT EXISTS (
                    SELECT 1 FROM network_scopes
                    WHERE scope_id = NEW.scope_id AND active = 1
                ) THEN RAISE(ABORT, 'Network Scope must exist and be active') END;
                SELECT CASE WHEN NEW.predecessor_id IS NULL AND
                    (NEW.revision != 1 OR NEW.event != 'assigned')
                THEN RAISE(ABORT, 'association root must be an assignment at revision 1') END;
                SELECT CASE WHEN NEW.predecessor_id IS NOT NULL AND NOT EXISTS (
                    SELECT 1 FROM saved_network_scope_associations previous
                    WHERE previous.association_id = NEW.predecessor_id
                      AND previous.saved_network_id = NEW.saved_network_id
                      AND NEW.revision = previous.revision + 1
                ) THEN RAISE(ABORT, 'association predecessor or revision is invalid') END;
                SELECT CASE WHEN NEW.predecessor_id IS NOT NULL AND EXISTS (
                    SELECT 1 FROM saved_network_scope_associations child
                    WHERE child.predecessor_id = NEW.predecessor_id
                ) THEN RAISE(ABORT, 'association predecessor is not the current revision') END;
                SELECT CASE WHEN NEW.predecessor_id IS NOT NULL AND NEW.event = 'assigned'
                    AND NOT EXISTS (
                        SELECT 1 FROM saved_network_scope_associations previous
                        WHERE previous.association_id = NEW.predecessor_id
                          AND previous.scope_id IS NULL
                    )
                THEN RAISE(ABORT, 'assigned event must follow a cleared association') END;
                SELECT CASE WHEN NEW.predecessor_id IS NOT NULL AND NEW.event = 'changed'
                    AND NOT EXISTS (
                        SELECT 1 FROM saved_network_scope_associations previous
                        WHERE previous.association_id = NEW.predecessor_id
                          AND previous.scope_id IS NOT NULL
                          AND previous.scope_id != NEW.scope_id
                    )
                THEN RAISE(ABORT, 'changed event must select a different scope') END;
                SELECT CASE WHEN NEW.predecessor_id IS NOT NULL AND NEW.event = 'cleared'
                    AND NOT EXISTS (
                        SELECT 1 FROM saved_network_scope_associations previous
                        WHERE previous.association_id = NEW.predecessor_id
                          AND previous.scope_id IS NOT NULL
                    )
                THEN RAISE(ABORT, 'cleared event must follow an assigned scope') END;
            END;
            CREATE TRIGGER IF NOT EXISTS saved_network_scope_no_update
                BEFORE UPDATE ON saved_network_scope_associations
                BEGIN SELECT RAISE(ABORT, 'Saved Network scope history is immutable'); END;
            CREATE TRIGGER IF NOT EXISTS saved_network_scope_no_delete
                BEFORE DELETE ON saved_network_scope_associations
                BEGIN SELECT RAISE(ABORT, 'Saved Network scope history is immutable'); END;
            """
        )


@initialize_once_per_database
def init_scan_scope_context_storage(db_path: Path) -> None:
    init_saved_network_scope_storage(db_path)
    with connect_database(db_path) as db:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS scan_run_scope_contexts (
                run_id TEXT PRIMARY KEY REFERENCES scan_runs(run_id) ON DELETE CASCADE,
                scope_id TEXT NOT NULL REFERENCES network_scopes(scope_id),
                scope_label TEXT NOT NULL,
                scope_version INTEGER NOT NULL CHECK(scope_version >= 1),
                recorded_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS scan_run_scope_sources (
                run_id TEXT NOT NULL REFERENCES scan_run_scope_contexts(run_id) ON DELETE CASCADE,
                saved_network_id TEXT NOT NULL REFERENCES saved_networks(saved_network_id),
                association_id TEXT NOT NULL REFERENCES saved_network_scope_associations(association_id),
                association_revision INTEGER NOT NULL CHECK(association_revision >= 1),
                PRIMARY KEY(run_id, saved_network_id)
            );
            CREATE TABLE IF NOT EXISTS scan_schedule_scope_contexts (
                schedule_id TEXT PRIMARY KEY REFERENCES scan_schedules(schedule_id) ON DELETE CASCADE,
                scope_id TEXT NOT NULL REFERENCES network_scopes(scope_id),
                scope_label TEXT NOT NULL,
                scope_version INTEGER NOT NULL CHECK(scope_version >= 1),
                recorded_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS scan_schedule_scope_sources (
                schedule_id TEXT NOT NULL REFERENCES scan_schedule_scope_contexts(schedule_id) ON DELETE CASCADE,
                saved_network_id TEXT NOT NULL REFERENCES saved_networks(saved_network_id),
                association_id TEXT NOT NULL REFERENCES saved_network_scope_associations(association_id),
                association_revision INTEGER NOT NULL CHECK(association_revision >= 1),
                PRIMARY KEY(schedule_id, saved_network_id)
            );
            CREATE TABLE IF NOT EXISTS artifact_observation_scope_contexts (
                observation_id TEXT PRIMARY KEY REFERENCES artifact_observations(observation_id) ON DELETE CASCADE,
                run_id TEXT NOT NULL REFERENCES scan_run_scope_contexts(run_id) ON DELETE CASCADE,
                scope_id TEXT NOT NULL REFERENCES network_scopes(scope_id),
                scope_label TEXT NOT NULL,
                scope_version INTEGER NOT NULL CHECK(scope_version >= 1),
                recorded_at TEXT NOT NULL
            );

            CREATE TRIGGER IF NOT EXISTS scan_run_scope_context_validate_insert
            BEFORE INSERT ON scan_run_scope_contexts
            BEGIN
                SELECT CASE WHEN NEW.scope_label != trim(NEW.scope_label)
                    OR length(NEW.scope_label) < 1
                THEN RAISE(ABORT, 'scan scope label must be canonical text') END;
                SELECT CASE WHEN datetime(NEW.recorded_at) IS NULL
                    OR NEW.recorded_at != strftime(
                        '%Y-%m-%dT%H:%M:%S+00:00', NEW.recorded_at
                    )
                THEN RAISE(ABORT, 'scan scope time must be canonical UTC') END;
                SELECT CASE WHEN NOT EXISTS (
                    SELECT 1
                    FROM network_scopes scope
                    JOIN scan_runs run ON run.run_id = NEW.run_id
                    WHERE scope.scope_id = NEW.scope_id
                      AND scope.active = 1
                      AND json_extract(
                        run.manifest_json, '$.network_scope_context.scope_id'
                      ) = NEW.scope_id
                      AND json_extract(
                        run.manifest_json, '$.network_scope_context.scope_label'
                      ) = NEW.scope_label
                      AND json_extract(
                        run.manifest_json, '$.network_scope_context.scope_version'
                      ) = NEW.scope_version
                      AND json_extract(
                        run.manifest_json, '$.network_scope_context.recorded_at'
                      ) = NEW.recorded_at
                      AND (
                        (scope.label = NEW.scope_label
                         AND scope.version = NEW.scope_version)
                        OR EXISTS (
                            SELECT 1
                            FROM scan_runs run
                            JOIN scan_schedule_scope_contexts scheduled
                              ON scheduled.schedule_id = json_extract(
                                run.manifest_json, '$.schedule_id'
                              )
                            WHERE run.run_id = NEW.run_id
                              AND scheduled.scope_id = NEW.scope_id
                              AND scheduled.scope_label = NEW.scope_label
                              AND scheduled.scope_version = NEW.scope_version
                              AND scheduled.recorded_at = NEW.recorded_at
                        )
                      )
                ) THEN RAISE(ABORT, 'scan scope snapshot is not authoritative') END;
            END;
            CREATE TRIGGER IF NOT EXISTS scan_run_scope_source_validate_insert
            BEFORE INSERT ON scan_run_scope_sources
            BEGIN
                SELECT CASE WHEN NOT EXISTS (
                    SELECT 1
                    FROM saved_network_scope_associations association
                    JOIN scan_run_scope_contexts context
                      ON context.run_id = NEW.run_id
                    WHERE association.association_id = NEW.association_id
                      AND association.saved_network_id = NEW.saved_network_id
                      AND association.revision = NEW.association_revision
                      AND association.scope_id = context.scope_id
                      AND (
                        NOT EXISTS (
                            SELECT 1
                            FROM saved_network_scope_associations successor
                            WHERE successor.predecessor_id = association.association_id
                        )
                        OR EXISTS (
                            SELECT 1
                            FROM scan_runs run
                            JOIN scan_schedule_scope_sources scheduled_source
                              ON scheduled_source.schedule_id = json_extract(
                                run.manifest_json, '$.schedule_id'
                              )
                            WHERE run.run_id = NEW.run_id
                              AND scheduled_source.saved_network_id = NEW.saved_network_id
                              AND scheduled_source.association_id = NEW.association_id
                              AND scheduled_source.association_revision = NEW.association_revision
                        )
                      )
                ) THEN RAISE(ABORT, 'scan scope source does not match its association') END;
            END;
            CREATE TRIGGER IF NOT EXISTS scan_schedule_scope_context_validate_insert
            BEFORE INSERT ON scan_schedule_scope_contexts
            BEGIN
                SELECT CASE WHEN NEW.scope_label != trim(NEW.scope_label)
                    OR length(NEW.scope_label) < 1
                THEN RAISE(ABORT, 'schedule scope label must be canonical text') END;
                SELECT CASE WHEN datetime(NEW.recorded_at) IS NULL
                    OR NEW.recorded_at != strftime(
                        '%Y-%m-%dT%H:%M:%S+00:00', NEW.recorded_at
                    )
                THEN RAISE(ABORT, 'schedule scope time must be canonical UTC') END;
                SELECT CASE WHEN NOT EXISTS (
                    SELECT 1
                    FROM network_scopes scope
                    JOIN scan_schedules schedule
                      ON schedule.schedule_id = NEW.schedule_id
                    WHERE scope.scope_id = NEW.scope_id
                      AND scope.active = 1
                      AND scope.label = NEW.scope_label
                      AND scope.version = NEW.scope_version
                      AND json_extract(
                        schedule.definition_json,
                        '$.network_scope_context.scope_id'
                      ) = NEW.scope_id
                      AND json_extract(
                        schedule.definition_json,
                        '$.network_scope_context.scope_label'
                      ) = NEW.scope_label
                      AND json_extract(
                        schedule.definition_json,
                        '$.network_scope_context.scope_version'
                      ) = NEW.scope_version
                      AND json_extract(
                        schedule.definition_json,
                        '$.network_scope_context.recorded_at'
                      ) = NEW.recorded_at
                ) THEN RAISE(ABORT, 'schedule scope snapshot is not authoritative') END;
            END;
            CREATE TRIGGER IF NOT EXISTS scan_schedule_scope_source_validate_insert
            BEFORE INSERT ON scan_schedule_scope_sources
            BEGIN
                SELECT CASE WHEN NOT EXISTS (
                    SELECT 1
                    FROM saved_network_scope_associations association
                    JOIN scan_schedule_scope_contexts context
                      ON context.schedule_id = NEW.schedule_id
                    WHERE association.association_id = NEW.association_id
                      AND association.saved_network_id = NEW.saved_network_id
                      AND association.revision = NEW.association_revision
                      AND association.scope_id = context.scope_id
                      AND NOT EXISTS (
                        SELECT 1
                        FROM saved_network_scope_associations successor
                        WHERE successor.predecessor_id = association.association_id
                      )
                ) THEN RAISE(ABORT, 'schedule scope source does not match its association') END;
            END;
            CREATE TRIGGER IF NOT EXISTS artifact_scope_context_validate_insert
            BEFORE INSERT ON artifact_observation_scope_contexts
            BEGIN
                SELECT CASE WHEN NOT EXISTS (
                    SELECT 1
                    FROM scan_run_scope_contexts context
                    JOIN artifact_observations observation
                      ON observation.observation_id = NEW.observation_id
                    WHERE context.run_id = NEW.run_id
                      AND observation.source_ref = NEW.run_id
                      AND context.scope_id = NEW.scope_id
                      AND context.scope_label = NEW.scope_label
                      AND context.scope_version = NEW.scope_version
                      AND context.recorded_at = NEW.recorded_at
                ) THEN RAISE(ABORT, 'artifact scope snapshot does not match its scan run') END;
            END;

            CREATE TRIGGER IF NOT EXISTS scan_run_scope_context_no_update
                BEFORE UPDATE ON scan_run_scope_contexts
                BEGIN SELECT RAISE(ABORT, 'scan scope context is immutable'); END;
            CREATE TRIGGER IF NOT EXISTS scan_run_scope_context_no_delete
                BEFORE DELETE ON scan_run_scope_contexts
                WHEN EXISTS (SELECT 1 FROM scan_runs WHERE run_id = OLD.run_id)
                BEGIN SELECT RAISE(ABORT, 'scan scope context is immutable'); END;
            CREATE TRIGGER IF NOT EXISTS scan_run_scope_source_no_update
                BEFORE UPDATE ON scan_run_scope_sources
                BEGIN SELECT RAISE(ABORT, 'scan scope sources are immutable'); END;
            CREATE TRIGGER IF NOT EXISTS scan_run_scope_source_no_delete
                BEFORE DELETE ON scan_run_scope_sources
                WHEN EXISTS (SELECT 1 FROM scan_runs WHERE run_id = OLD.run_id)
                BEGIN SELECT RAISE(ABORT, 'scan scope sources are immutable'); END;
            CREATE TRIGGER IF NOT EXISTS scan_schedule_scope_context_no_update
                BEFORE UPDATE ON scan_schedule_scope_contexts
                BEGIN SELECT RAISE(ABORT, 'schedule scope context is immutable'); END;
            CREATE TRIGGER IF NOT EXISTS scan_schedule_scope_context_no_delete
                BEFORE DELETE ON scan_schedule_scope_contexts
                WHEN EXISTS (SELECT 1 FROM scan_schedules WHERE schedule_id = OLD.schedule_id)
                BEGIN SELECT RAISE(ABORT, 'schedule scope context is immutable'); END;
            CREATE TRIGGER IF NOT EXISTS scan_schedule_scope_source_no_update
                BEFORE UPDATE ON scan_schedule_scope_sources
                BEGIN SELECT RAISE(ABORT, 'schedule scope sources are immutable'); END;
            CREATE TRIGGER IF NOT EXISTS scan_schedule_scope_source_no_delete
                BEFORE DELETE ON scan_schedule_scope_sources
                WHEN EXISTS (SELECT 1 FROM scan_schedules WHERE schedule_id = OLD.schedule_id)
                BEGIN SELECT RAISE(ABORT, 'schedule scope sources are immutable'); END;
            CREATE TRIGGER IF NOT EXISTS artifact_scope_context_no_update
                BEFORE UPDATE ON artifact_observation_scope_contexts
                BEGIN SELECT RAISE(ABORT, 'artifact scope context is immutable'); END;
            CREATE TRIGGER IF NOT EXISTS artifact_scope_context_no_delete
                BEFORE DELETE ON artifact_observation_scope_contexts
                WHEN EXISTS (
                    SELECT 1 FROM artifact_observations
                    WHERE observation_id = OLD.observation_id
                )
                BEGIN SELECT RAISE(ABORT, 'artifact scope context is immutable'); END;
            """
        )


def _association_row(db: sqlite3.Connection, saved_network_id: str):
    db.row_factory = sqlite3.Row
    return db.execute(
        """
        SELECT association_id, saved_network_id, scope_id, revision, event,
               predecessor_id, actor, reason, recorded_at
        FROM saved_network_scope_associations current
        WHERE saved_network_id = ?
          AND NOT EXISTS (
              SELECT 1 FROM saved_network_scope_associations successor
              WHERE successor.predecessor_id = current.association_id
          )
        """,
        (saved_network_id,),
    ).fetchone()


def _association_dict(row: sqlite3.Row | None) -> dict | None:
    return dict(row) if row is not None else None


def current_scope_association_in_transaction(
    db: sqlite3.Connection, saved_network_id: str
) -> dict | None:
    return _association_dict(_association_row(db, saved_network_id))


def current_saved_network_scope_association(
    db_path: Path, saved_network_id: str
) -> dict | None:
    init_saved_network_scope_storage(db_path)
    with connect_database(db_path) as db:
        row = _association_row(db, saved_network_id)
        if row is None:
            return None
        result = dict(row)
        if result["scope_id"]:
            scope = db.execute(
                "SELECT label, description, version, active FROM network_scopes WHERE scope_id = ?",
                (result["scope_id"],),
            ).fetchone()
            result["scope"] = {
                "scope_id": result["scope_id"],
                "label": scope[0],
                "description": scope[1],
                "version": int(scope[2]),
                "active": bool(scope[3]),
            }
        else:
            result["scope"] = None
        return result


def attach_scope_associations(db_path: Path, records: list[dict]) -> list[dict]:
    init_saved_network_scope_storage(db_path)
    return [
        {
            **record,
            "network_scope_association": current_saved_network_scope_association(
                db_path, record["saved_network_id"]
            ),
        }
        for record in records
    ]


def change_saved_network_scope_association(
    db_path: Path,
    saved_network_id: str,
    *,
    scope_id: str | None,
    expected_association_id: str | None,
    expected_revision: int | None,
    actor: str,
    reason: str,
) -> dict:
    init_saved_network_scope_storage(db_path)
    actor = _clean_text(actor, "actor", 100)
    reason = _clean_text(reason, "reason", 500)
    if scope_id is not None:
        scope_id = _clean_text(scope_id, "scope_id", 100)
    try:
        with connect_database(db_path) as db:
            db.execute("BEGIN IMMEDIATE")
            insert_saved_network_scope_association(
                db,
                saved_network_id,
                scope_id=scope_id,
                expected_association_id=expected_association_id,
                expected_revision=expected_revision,
                actor=actor,
                reason=reason,
            )
    except sqlite3.IntegrityError as exc:
        raise SavedNetworkScopeConflict(str(exc)) from exc
    result = current_saved_network_scope_association(db_path, saved_network_id)
    if result is None:
        raise RuntimeError("Saved Network context was not retained")
    return result


def insert_saved_network_scope_association(
    db: sqlite3.Connection,
    saved_network_id: str,
    *,
    scope_id: str | None,
    expected_association_id: str | None,
    expected_revision: int | None,
    actor: str,
    reason: str,
) -> str:
    """Append a scope change inside the caller's write transaction."""
    actor = _clean_text(actor, "actor", 100)
    reason = _clean_text(reason, "reason", 500)
    if scope_id is not None:
        scope_id = _clean_text(scope_id, "scope_id", 100)
    current = _association_row(db, saved_network_id)
    if current is None:
        if expected_association_id is not None or expected_revision is not None:
            raise SavedNetworkScopeConflict(
                "Saved Network context changed in another session"
            )
        if scope_id is None:
            raise ValueError("The Saved Network does not have a context to clear")
        event = "assigned"
        revision = 1
        predecessor_id = None
    else:
        if (
            expected_association_id != current["association_id"]
            or expected_revision != int(current["revision"])
        ):
            raise SavedNetworkScopeConflict(
                "Saved Network context changed in another session"
            )
        if current["scope_id"] == scope_id:
            raise ValueError("Choose a different Network Scope or leave it unchanged")
        event = (
            "cleared" if scope_id is None
            else "assigned" if current["scope_id"] is None
            else "changed"
        )
        revision = int(current["revision"]) + 1
        predecessor_id = current["association_id"]
    association_id = f"sna_{uuid.uuid4().hex}"
    db.execute(
        """
        INSERT INTO saved_network_scope_associations (
            association_id, saved_network_id, scope_id, revision, event,
            predecessor_id, actor, reason, recorded_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            association_id, saved_network_id, scope_id, revision, event,
            predecessor_id, actor, reason, utc_now(),
        ),
    )
    return association_id


def list_saved_network_scope_history(db_path: Path, saved_network_id: str) -> list[dict]:
    init_saved_network_scope_storage(db_path)
    with connect_database(db_path) as db:
        db.row_factory = sqlite3.Row
        rows = db.execute(
            """
            SELECT association_id, saved_network_id, scope_id, revision, event,
                   predecessor_id, actor, reason, recorded_at
            FROM saved_network_scope_associations
            WHERE saved_network_id = ? ORDER BY revision
            """,
            (saved_network_id,),
        ).fetchall()
    return [dict(row) for row in rows]


def resolve_reviewed_scope_context(
    db: sqlite3.Connection,
    *,
    saved_network_ids: list[str],
    manual_targets: list[str],
    reviewed_associations: list[dict],
) -> dict | None:
    """Recheck the exact UI-reviewed leaves while the caller holds a write lock."""
    unique_ids = list(dict.fromkeys(saved_network_ids))
    submitted = {
        str(item["association_id"]): int(item["revision"])
        for item in reviewed_associations
    }
    leaves = []
    for saved_network_id in unique_ids:
        active = db.execute(
            "SELECT active FROM saved_networks WHERE saved_network_id = ?",
            (saved_network_id,),
        ).fetchone()
        if active is None or not bool(active[0]):
            raise SavedNetworkScopeConflict(
                "A selected Saved Network was removed or changed; review the scan again"
            )
        leaf = _association_row(db, saved_network_id)
        if leaf is not None:
            leaves.append(leaf)
    current = {
        str(row["association_id"]): int(row["revision"])
        for row in leaves
    }
    if submitted != current:
        raise SavedNetworkScopeConflict(
            "Saved Network context changed after review; review the scan again"
        )
    scoped = [row for row in leaves if row["scope_id"] is not None]
    for row in scoped:
        scope = db.execute(
            "SELECT active FROM network_scopes WHERE scope_id = ?",
            (row["scope_id"],),
        ).fetchone()
        if scope is None or not bool(scope[0]):
            raise SavedNetworkScopeConflict(
                "A selected Network Scope was archived; choose an active context"
            )
    if manual_targets or not unique_ids or len(scoped) != len(unique_ids):
        return None
    scope_ids = {str(row["scope_id"]) for row in scoped}
    if len(scope_ids) != 1:
        return None
    scope_id = next(iter(scope_ids))
    scope = db.execute(
        "SELECT label, version, active FROM network_scopes WHERE scope_id = ?",
        (scope_id,),
    ).fetchone()
    if scope is None or not bool(scope[2]):
        raise SavedNetworkScopeConflict(
            "The reviewed Network Scope is no longer active"
        )
    return {
        "scope_id": scope_id,
        "scope_label": scope[0],
        "scope_version": int(scope[1]),
        "recorded_at": utc_now(),
        "sources": [
            {
                "saved_network_id": row["saved_network_id"],
                "association_id": row["association_id"],
                "association_revision": int(row["revision"]),
            }
            for row in scoped
        ],
    }


def insert_run_scope_context(
    db: sqlite3.Connection, run_id: str, context: dict | None
) -> None:
    if context is None:
        return
    db.execute(
        """
        INSERT INTO scan_run_scope_contexts (
            run_id, scope_id, scope_label, scope_version, recorded_at
        ) VALUES (?, ?, ?, ?, ?)
        """,
        (
            run_id, context["scope_id"], context["scope_label"],
            context["scope_version"], context["recorded_at"],
        ),
    )
    db.executemany(
        """
        INSERT INTO scan_run_scope_sources (
            run_id, saved_network_id, association_id, association_revision
        ) VALUES (?, ?, ?, ?)
        """,
        [
            (
                run_id, item["saved_network_id"], item["association_id"],
                item["association_revision"],
            )
            for item in context["sources"]
        ],
    )


def insert_schedule_scope_context(
    db: sqlite3.Connection, schedule_id: str, context: dict | None
) -> None:
    if context is None:
        return
    db.execute(
        """
        INSERT INTO scan_schedule_scope_contexts (
            schedule_id, scope_id, scope_label, scope_version, recorded_at
        ) VALUES (?, ?, ?, ?, ?)
        """,
        (
            schedule_id, context["scope_id"], context["scope_label"],
            context["scope_version"], context["recorded_at"],
        ),
    )
    db.executemany(
        """
        INSERT INTO scan_schedule_scope_sources (
            schedule_id, saved_network_id, association_id, association_revision
        ) VALUES (?, ?, ?, ?)
        """,
        [
            (
                schedule_id, item["saved_network_id"], item["association_id"],
                item["association_revision"],
            )
            for item in context["sources"]
        ],
    )


def _context_from_rows(parent, sources) -> dict | None:
    if parent is None:
        return None
    return {
        "scope_id": parent[0],
        "scope_label": parent[1],
        "scope_version": int(parent[2]),
        "recorded_at": parent[3],
        "sources": [
            {
                "saved_network_id": row[0],
                "association_id": row[1],
                "association_revision": int(row[2]),
            }
            for row in sources
        ],
    }


def get_run_scope_context(db_path: Path, run_id: str) -> dict | None:
    init_scan_scope_context_storage(db_path)
    with connect_database(db_path, read_only=True) as db:
        parent = db.execute(
            "SELECT scope_id, scope_label, scope_version, recorded_at "
            "FROM scan_run_scope_contexts WHERE run_id = ?",
            (run_id,),
        ).fetchone()
        sources = db.execute(
            "SELECT saved_network_id, association_id, association_revision "
            "FROM scan_run_scope_sources WHERE run_id = ? ORDER BY saved_network_id",
            (run_id,),
        ).fetchall()
    return _context_from_rows(parent, sources)


def get_schedule_scope_context(
    db_path: Path, schedule_id: str, *, require_active: bool = False
) -> dict | None:
    init_scan_scope_context_storage(db_path)
    with connect_database(db_path, read_only=True) as db:
        parent = db.execute(
            "SELECT scope_id, scope_label, scope_version, recorded_at "
            "FROM scan_schedule_scope_contexts WHERE schedule_id = ?",
            (schedule_id,),
        ).fetchone()
        if parent is not None and require_active:
            active = db.execute(
                "SELECT active FROM network_scopes WHERE scope_id = ?", (parent[0],)
            ).fetchone()
            if active is None or not bool(active[0]):
                raise SavedNetworkScopeConflict(
                    "This schedule's pinned Network Scope was archived; review the schedule before running it"
                )
        sources = db.execute(
            "SELECT saved_network_id, association_id, association_revision "
            "FROM scan_schedule_scope_sources WHERE schedule_id = ? ORDER BY saved_network_id",
            (schedule_id,),
        ).fetchall()
    return _context_from_rows(parent, sources)


def resolve_schedule_scope_context_in_transaction(
    db: sqlite3.Connection, schedule_id: str
) -> dict | None:
    parent = db.execute(
        "SELECT scope_id, scope_label, scope_version, recorded_at "
        "FROM scan_schedule_scope_contexts WHERE schedule_id = ?",
        (schedule_id,),
    ).fetchone()
    if parent is None:
        return None
    active = db.execute(
        "SELECT active FROM network_scopes WHERE scope_id = ?", (parent[0],)
    ).fetchone()
    if active is None or not bool(active[0]):
        raise SavedNetworkScopeConflict(
            "This schedule's pinned Network Scope was archived; review the schedule before running it"
        )
    sources = db.execute(
        "SELECT saved_network_id, association_id, association_revision "
        "FROM scan_schedule_scope_sources WHERE schedule_id = ? ORDER BY saved_network_id",
        (schedule_id,),
    ).fetchall()
    return _context_from_rows(parent, sources)


def insert_artifact_observation_scope_context(
    db: sqlite3.Connection,
    *,
    observation_id: str,
    run_id: str,
    context: dict,
) -> None:
    expected = (
        run_id, context["scope_id"], context["scope_label"],
        int(context["scope_version"]), context["recorded_at"],
    )
    existing = db.execute(
        """
        SELECT run_id, scope_id, scope_label, scope_version, recorded_at
        FROM artifact_observation_scope_contexts WHERE observation_id = ?
        """,
        (observation_id,),
    ).fetchone()
    if existing is not None:
        if tuple(existing) != expected:
            raise ValueError("Artifact observation replay does not match retained scope context")
        return
    db.execute(
        """
        INSERT INTO artifact_observation_scope_contexts (
            observation_id, run_id, scope_id, scope_label, scope_version, recorded_at
        ) VALUES (?, ?, ?, ?, ?, ?)
        """,
        (observation_id, *expected),
    )
