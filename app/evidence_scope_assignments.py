"""Immutable operator assignment of one artifact observation to one network scope.

Assignments are observation-level and whole-artifact only. They never infer scope
from content, targets, CIDRs, filenames, hashes, or Saved Networks.
"""
from __future__ import annotations

from pathlib import Path
import sqlite3
import uuid

from app.database import connect_database, initialize_once_per_database
from app.entities import init_entity_storage
from app.network_scopes import utc_now


class EvidenceScopeConflict(ValueError):
    pass


def _text(value, field: str, maximum: int = 500) -> str:
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise ValueError(f"{field} must be nonblank trimmed text")
    if len(value) > maximum:
        raise ValueError(f"{field} exceeds {maximum} characters")
    return value


def _row(row: sqlite3.Row | None) -> dict | None:
    if row is None:
        return None
    return {
        "assignment_id": row["assignment_id"],
        "artifact_observation_id": row["artifact_observation_id"],
        "scope_id": row["scope_id"],
        "revision": int(row["revision"]),
        "event_kind": row["event_kind"],
        "supersedes_assignment_id": row["supersedes_assignment_id"],
        "assignment_mode": row["assignment_mode"],
        "actor": row["actor"],
        "reason": row["reason"],
        "assigned_at": row["assigned_at"],
    }


@initialize_once_per_database
def init_evidence_scope_assignment_storage(db_path: Path) -> None:
    init_entity_storage(db_path)
    with connect_database(db_path) as db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS artifact_scope_assignments (
                assignment_id TEXT PRIMARY KEY,
                artifact_observation_id TEXT NOT NULL
                    REFERENCES artifact_observations(observation_id),
                scope_id TEXT NOT NULL REFERENCES network_scopes(scope_id),
                revision INTEGER NOT NULL CHECK(revision >= 1),
                event_kind TEXT NOT NULL CHECK(event_kind IN ('assigned', 'corrected')),
                supersedes_assignment_id TEXT UNIQUE
                    REFERENCES artifact_scope_assignments(assignment_id),
                assignment_mode TEXT NOT NULL DEFAULT 'whole_artifact'
                    CHECK(assignment_mode = 'whole_artifact'),
                actor TEXT NOT NULL
                    CHECK(length(actor) BETWEEN 1 AND 100 AND actor = trim(actor)),
                reason TEXT NOT NULL
                    CHECK(length(reason) BETWEEN 1 AND 500 AND reason = trim(reason)),
                assigned_at TEXT NOT NULL CHECK(
                    length(assigned_at) = 25
                    AND substr(assigned_at, 11, 1) = 'T'
                    AND substr(assigned_at, 20, 6) = '+00:00'
                    AND datetime(assigned_at) IS NOT NULL
                ),
                UNIQUE(artifact_observation_id, revision)
            );
            CREATE UNIQUE INDEX IF NOT EXISTS artifact_scope_assignment_root
                ON artifact_scope_assignments(artifact_observation_id)
                WHERE supersedes_assignment_id IS NULL;
            CREATE INDEX IF NOT EXISTS artifact_scope_assignment_observation
                ON artifact_scope_assignments(artifact_observation_id, revision);
            CREATE TABLE IF NOT EXISTS assessment_scope_assignment_links (
                assignment_id TEXT NOT NULL
                    REFERENCES artifact_scope_assignments(assignment_id),
                assessment_id TEXT NOT NULL REFERENCES entity_assessments(assessment_id),
                linked_at TEXT NOT NULL CHECK(
                    length(linked_at) = 25
                    AND substr(linked_at, 11, 1) = 'T'
                    AND substr(linked_at, 20, 6) = '+00:00'
                    AND datetime(linked_at) IS NOT NULL
                ),
                linked_by TEXT NOT NULL CHECK(
                    length(linked_by) BETWEEN 1 AND 100 AND linked_by = trim(linked_by)
                ),
                PRIMARY KEY(assignment_id, assessment_id)
            );
            CREATE TRIGGER IF NOT EXISTS artifact_scope_assignments_no_update
                BEFORE UPDATE ON artifact_scope_assignments
                BEGIN SELECT RAISE(ABORT, 'artifact scope assignments are immutable'); END;
            CREATE TRIGGER IF NOT EXISTS artifact_scope_assignments_no_delete
                BEFORE DELETE ON artifact_scope_assignments
                BEGIN SELECT RAISE(ABORT, 'artifact scope assignments are immutable'); END;
            CREATE TRIGGER IF NOT EXISTS artifact_scope_assignments_active_scope
                BEFORE INSERT ON artifact_scope_assignments
                WHEN NOT EXISTS (
                    SELECT 1 FROM network_scopes
                    WHERE scope_id = NEW.scope_id AND active = 1
                )
                BEGIN SELECT RAISE(ABORT, 'assignment scope is missing or archived'); END;
            CREATE TRIGGER IF NOT EXISTS artifact_scope_assignments_valid_root
                BEFORE INSERT ON artifact_scope_assignments
                WHEN NEW.supersedes_assignment_id IS NULL
                     AND (NEW.revision != 1 OR NEW.event_kind != 'assigned')
                BEGIN SELECT RAISE(ABORT, 'invalid assignment root'); END;
            CREATE TRIGGER IF NOT EXISTS artifact_scope_assignments_valid_successor
                BEFORE INSERT ON artifact_scope_assignments
                WHEN NEW.supersedes_assignment_id IS NOT NULL AND (
                    NEW.event_kind != 'corrected'
                    OR NOT EXISTS (
                        SELECT 1 FROM artifact_scope_assignments previous
                        WHERE previous.assignment_id = NEW.supersedes_assignment_id
                          AND previous.artifact_observation_id = NEW.artifact_observation_id
                          AND previous.revision + 1 = NEW.revision
                          AND previous.scope_id != NEW.scope_id
                    )
                    OR EXISTS (
                        SELECT 1 FROM artifact_scope_assignments successor
                        WHERE successor.supersedes_assignment_id = NEW.supersedes_assignment_id
                    )
                )
                BEGIN SELECT RAISE(ABORT, 'invalid assignment successor'); END;
            CREATE TRIGGER IF NOT EXISTS artifact_scope_assignments_no_legacy_root
                BEFORE INSERT ON artifact_scope_assignments
                WHEN NEW.supersedes_assignment_id IS NULL AND EXISTS (
                    SELECT 1 FROM entity_assessments
                    WHERE artifact_observation_id = NEW.artifact_observation_id
                )
                BEGIN SELECT RAISE(ABORT, 'legacy assessment requires reconciliation'); END;
            CREATE TRIGGER IF NOT EXISTS assessment_scope_assignment_links_match
                BEFORE INSERT ON assessment_scope_assignment_links
                WHEN NOT EXISTS (
                    SELECT 1
                    FROM artifact_scope_assignments assignment
                    JOIN entity_assessments assessment
                      ON assessment.assessment_id = NEW.assessment_id
                    WHERE assignment.assignment_id = NEW.assignment_id
                      AND assignment.artifact_observation_id = assessment.artifact_observation_id
                      AND assignment.scope_id = assessment.scope_id
                )
                BEGIN SELECT RAISE(ABORT, 'assignment and assessment do not match'); END;
            CREATE TRIGGER IF NOT EXISTS assessment_scope_assignment_links_no_update
                BEFORE UPDATE ON assessment_scope_assignment_links
                BEGIN SELECT RAISE(ABORT, 'assessment assignment links are immutable'); END;
            CREATE TRIGGER IF NOT EXISTS assessment_scope_assignment_links_no_delete
                BEFORE DELETE ON assessment_scope_assignment_links
                BEGIN SELECT RAISE(ABORT, 'assessment assignment links are immutable'); END;
        """)


def _scope_is_active(db: sqlite3.Connection, scope_id: str) -> bool:
    row = db.execute(
        "SELECT active FROM network_scopes WHERE scope_id = ?", (scope_id,)
    ).fetchone()
    if row is None:
        raise ValueError("Network scope does not exist")
    if not bool(row[0]):
        raise ValueError("Network scope is archived")
    return True


def assign_artifact_scope(
    db_path: Path, *, artifact_observation_id: str, scope_id: str,
    actor: str, reason: str, whole_artifact_confirmed: bool,
) -> dict:
    """Append the root assignment without ingesting or changing evidence."""
    observation_id = _text(artifact_observation_id, "artifact_observation_id", 200)
    scope_id = _text(scope_id, "scope_id", 200)
    actor = _text(actor, "actor", 100)
    reason = _text(reason, "reason")
    if whole_artifact_confirmed is not True:
        raise ValueError("Whole-artifact scope confirmation is required")
    init_evidence_scope_assignment_storage(db_path)
    with connect_database(db_path) as db:
        db.execute("BEGIN IMMEDIATE")
        if not db.execute(
            "SELECT 1 FROM artifact_observations WHERE observation_id = ?", (observation_id,)
        ).fetchone():
            raise ValueError("Artifact observation does not exist")
        _scope_is_active(db, scope_id)
        if db.execute(
            "SELECT 1 FROM artifact_scope_assignments WHERE artifact_observation_id = ?",
            (observation_id,),
        ).fetchone():
            raise EvidenceScopeConflict("Artifact observation is already assigned")
        if db.execute(
            "SELECT 1 FROM entity_assessments WHERE artifact_observation_id = ?",
            (observation_id,),
        ).fetchone():
            raise EvidenceScopeConflict(
                "Existing unassigned assessments require explicit migration reconciliation"
            )
        assignment_id = f"assignment_{uuid.uuid4().hex}"
        db.execute(
            """INSERT INTO artifact_scope_assignments (
                   assignment_id, artifact_observation_id, scope_id, revision,
                   event_kind, supersedes_assignment_id, assignment_mode,
                   actor, reason, assigned_at
               ) VALUES (?, ?, ?, 1, 'assigned', NULL, 'whole_artifact', ?, ?, ?)""",
            (assignment_id, observation_id, scope_id, actor, reason, utc_now()),
        )
        db.row_factory = sqlite3.Row
        return _row(db.execute(
            "SELECT * FROM artifact_scope_assignments WHERE assignment_id = ?",
            (assignment_id,),
        ).fetchone())


def correct_artifact_scope(
    db_path: Path, *, expected_assignment_id: str, destination_scope_id: str,
    actor: str, reason: str, whole_artifact_confirmed: bool,
) -> dict:
    """Append one correction to the current leaf; prior assignments remain intact."""
    expected_id = _text(expected_assignment_id, "expected_assignment_id", 200)
    destination_scope_id = _text(destination_scope_id, "destination_scope_id", 200)
    actor = _text(actor, "actor", 100)
    reason = _text(reason, "reason")
    if whole_artifact_confirmed is not True:
        raise ValueError("Whole-artifact scope confirmation is required")
    init_evidence_scope_assignment_storage(db_path)
    with connect_database(db_path) as db:
        db.execute("BEGIN IMMEDIATE")
        db.row_factory = sqlite3.Row
        previous = db.execute(
            "SELECT * FROM artifact_scope_assignments WHERE assignment_id = ?",
            (expected_id,),
        ).fetchone()
        if previous is None:
            raise EvidenceScopeConflict("Expected assignment does not exist")
        if db.execute(
            "SELECT 1 FROM artifact_scope_assignments WHERE supersedes_assignment_id = ?",
            (expected_id,),
        ).fetchone():
            raise EvidenceScopeConflict("Artifact scope assignment changed in another session")
        if previous["scope_id"] == destination_scope_id:
            raise ValueError("Correction must select a different network scope")
        _scope_is_active(db, destination_scope_id)
        assignment_id = f"assignment_{uuid.uuid4().hex}"
        try:
            db.execute(
                """INSERT INTO artifact_scope_assignments (
                       assignment_id, artifact_observation_id, scope_id, revision,
                       event_kind, supersedes_assignment_id, assignment_mode,
                       actor, reason, assigned_at
                   ) VALUES (?, ?, ?, ?, 'corrected', ?, 'whole_artifact', ?, ?, ?)""",
                (assignment_id, previous["artifact_observation_id"], destination_scope_id,
                 int(previous["revision"]) + 1, expected_id, actor, reason, utc_now()),
            )
        except sqlite3.IntegrityError as exc:
            raise EvidenceScopeConflict(
                "Artifact scope assignment changed in another session"
            ) from exc
        return _row(db.execute(
            "SELECT * FROM artifact_scope_assignments WHERE assignment_id = ?",
            (assignment_id,),
        ).fetchone())


def list_artifact_scope_assignments(
    db_path: Path, artifact_observation_id: str,
) -> list[dict]:
    observation_id = _text(artifact_observation_id, "artifact_observation_id", 200)
    init_evidence_scope_assignment_storage(db_path)
    with connect_database(db_path, read_only=True) as db:
        db.row_factory = sqlite3.Row
        rows = db.execute(
            """SELECT * FROM artifact_scope_assignments
               WHERE artifact_observation_id = ? ORDER BY revision""",
            (observation_id,),
        ).fetchall()
    return [_row(row) for row in rows]
