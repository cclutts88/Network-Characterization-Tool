"""Explicit foundation processing for one finalized, already-scoped scan run."""
from __future__ import annotations

import json
from pathlib import Path
import sqlite3
import uuid

from app.assigned_nmap_ingestion import ingest_assigned_nmap_observation
from app.database import connect_database, initialize_once_per_database
from app.evidence_scope_assignments import init_evidence_scope_assignment_storage
from app.network_scopes import utc_now
from app.nmap_evidence import NMAP_ENDPOINT_PARSER
from app.saved_network_scope_associations import init_scan_scope_context_storage


class AutomatedNmapFoundationConflict(ValueError):
    """The retained run cannot safely enter foundation processing."""


@initialize_once_per_database
def init_automated_nmap_foundation_storage(db_path: Path) -> None:
    init_scan_scope_context_storage(db_path)
    init_evidence_scope_assignment_storage(db_path)
    with connect_database(db_path) as db:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS scan_inherited_scope_assignments (
                assignment_id TEXT PRIMARY KEY
                    REFERENCES artifact_scope_assignments(assignment_id),
                observation_id TEXT NOT NULL UNIQUE
                    REFERENCES artifact_observations(observation_id),
                run_id TEXT NOT NULL UNIQUE
                    REFERENCES scan_run_scope_contexts(run_id),
                scope_id TEXT NOT NULL REFERENCES network_scopes(scope_id),
                inherited_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS scan_foundation_processing_attempts (
                attempt_id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL REFERENCES scan_runs(run_id),
                observation_id TEXT NOT NULL REFERENCES artifact_observations(observation_id),
                assignment_id TEXT NOT NULL REFERENCES artifact_scope_assignments(assignment_id),
                actor TEXT NOT NULL,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                status TEXT NOT NULL
                    CHECK(status IN ('running', 'complete', 'error', 'interrupted')),
                error TEXT
            );
            CREATE INDEX IF NOT EXISTS scan_foundation_attempt_run
                ON scan_foundation_processing_attempts(run_id, started_at DESC);
            CREATE TRIGGER IF NOT EXISTS scan_inherited_scope_assignment_validate
            BEFORE INSERT ON scan_inherited_scope_assignments
            WHEN NOT EXISTS (
                SELECT 1
                FROM artifact_scope_assignments assignment
                JOIN artifact_observations observation
                  ON observation.observation_id = NEW.observation_id
                JOIN artifact_observation_scope_contexts artifact_context
                  ON artifact_context.observation_id = NEW.observation_id
                JOIN scan_run_scope_contexts run_context
                  ON run_context.run_id = NEW.run_id
                JOIN scan_runs run ON run.run_id = NEW.run_id
                WHERE assignment.assignment_id = NEW.assignment_id
                  AND assignment.artifact_observation_id = NEW.observation_id
                  AND assignment.scope_id = NEW.scope_id
                  AND assignment.revision = 1
                  AND assignment.event_kind = 'assigned'
                  AND assignment.supersedes_assignment_id IS NULL
                  AND observation.source_kind = 'nmap_scan'
                  AND observation.source_ref = NEW.run_id
                  AND observation.original_filename = 'scan.xml'
                  AND artifact_context.run_id = NEW.run_id
                  AND artifact_context.scope_id = NEW.scope_id
                  AND run_context.scope_id = NEW.scope_id
                  AND run.status = 'completed'
            )
            BEGIN SELECT RAISE(ABORT, 'inherited scan assignment is not authoritative'); END;
            CREATE TRIGGER IF NOT EXISTS scan_inherited_scope_assignment_no_update
                BEFORE UPDATE ON scan_inherited_scope_assignments
                BEGIN SELECT RAISE(ABORT, 'inherited scan assignment is immutable'); END;
            CREATE TRIGGER IF NOT EXISTS scan_inherited_scope_assignment_no_delete
                BEFORE DELETE ON scan_inherited_scope_assignments
                BEGIN SELECT RAISE(ABORT, 'inherited scan assignment is immutable'); END;
            """
        )


def recover_interrupted_automated_scan_foundation(db_path: Path) -> int:
    """Mark work left running by a stopped application as safely retryable."""
    with connect_database(db_path) as db:
        recovered = db.execute(
            """UPDATE scan_foundation_processing_attempts
               SET status = 'interrupted', finished_at = ?,
                   error = 'Processing stopped before completion; safe to retry.'
               WHERE status = 'running'""",
            (utc_now(),),
        ).rowcount
    return int(recovered)


def _run_evidence(db: sqlite3.Connection, run_id: str) -> dict:
    db.row_factory = sqlite3.Row
    run = db.execute(
        "SELECT status, manifest_json FROM scan_runs WHERE run_id = ?", (run_id,)
    ).fetchone()
    if run is None:
        raise KeyError("Scan run not found")
    try:
        manifest = json.loads(run["manifest_json"])
    except (TypeError, json.JSONDecodeError) as exc:
        raise AutomatedNmapFoundationConflict("The retained scan record is unreadable") from exc
    observations = db.execute(
        """SELECT observation.observation_id, observation.sha256,
                  artifact_context.scope_id, artifact_context.scope_label,
                  artifact_context.scope_version, artifact_context.recorded_at,
                  scope.active,
                  (SELECT COUNT(*) FROM scan_run_scope_sources source
                   WHERE source.run_id = run.run_id) AS source_count
           FROM scan_runs run
           JOIN artifact_observations observation
             ON observation.source_kind = 'nmap_scan'
            AND observation.source_ref = run.run_id
            AND observation.original_filename = 'scan.xml'
           JOIN artifact_observation_scope_contexts artifact_context
             ON artifact_context.observation_id = observation.observation_id
            AND artifact_context.run_id = run.run_id
           JOIN scan_run_scope_contexts run_context
             ON run_context.run_id = run.run_id
            AND run_context.scope_id = artifact_context.scope_id
            AND run_context.scope_label = artifact_context.scope_label
            AND run_context.scope_version = artifact_context.scope_version
            AND run_context.recorded_at = artifact_context.recorded_at
           JOIN network_scopes scope ON scope.scope_id = artifact_context.scope_id
           WHERE run.run_id = ?""",
        (run_id,),
    ).fetchall()
    reasons: list[str] = []
    if run["status"] != "completed" or manifest.get("status") != "completed":
        reasons.append("Only completed scans with aggregate Nmap XML are eligible")
    if manifest.get("manual_targets") or (manifest.get("target_selection") or {}).get("manual_targets"):
        reasons.append("Scans containing manual targets remain explicitly unscoped")
    if len(observations) != 1:
        reasons.append("One registered aggregate scan.xml with retained scope context is required")
    observation = observations[0] if len(observations) == 1 else None
    if observation is not None and int(observation["source_count"] or 0) < 1:
        reasons.append("The retained scope has no authoritative Saved Network source")
    return {
        "run_id": run_id,
        "run_status": run["status"],
        "eligible": not reasons,
        "eligibility_reasons": reasons,
        "observation_id": observation["observation_id"] if observation else None,
        "sha256": observation["sha256"] if observation else None,
        "scope_id": observation["scope_id"] if observation else None,
        "scope_label": observation["scope_label"] if observation else None,
        "scope_version": int(observation["scope_version"]) if observation else None,
        "scope_recorded_at": observation["recorded_at"] if observation else None,
        "scope_active": bool(observation["active"]) if observation else False,
    }


def _assignment_state(db: sqlite3.Connection, evidence: dict) -> dict:
    observation_id = evidence.get("observation_id")
    if not observation_id:
        return {"assignment_id": None, "current_assignment_id": None,
                "processing_complete": False, "assignment_conflict": False}
    db.row_factory = sqlite3.Row
    assignments = db.execute(
        """SELECT assignment.*, inherited.assignment_id IS NOT NULL AS inherited
           FROM artifact_scope_assignments assignment
           LEFT JOIN scan_inherited_scope_assignments inherited
             ON inherited.assignment_id = assignment.assignment_id
           WHERE assignment.artifact_observation_id = ?
           ORDER BY assignment.revision""",
        (observation_id,),
    ).fetchall()
    if not assignments:
        return {"assignment_id": None, "current_assignment_id": None,
                "processing_complete": False, "assignment_conflict": False}
    root = assignments[0]
    if not bool(root["inherited"]):
        return {"assignment_id": root["assignment_id"], "current_assignment_id": None,
                "processing_complete": False, "assignment_conflict": True}
    superseded = {row["supersedes_assignment_id"] for row in assignments if row["supersedes_assignment_id"]}
    current = next(row for row in assignments if row["assignment_id"] not in superseded)
    complete = db.execute(
        """SELECT 1 FROM assessment_scope_assignment_links link
           JOIN entity_assessments assessment ON assessment.assessment_id = link.assessment_id
           WHERE link.assignment_id = ? AND assessment.parser_version = ?""",
        (current["assignment_id"], NMAP_ENDPOINT_PARSER),
    ).fetchone() is not None
    return {
        "assignment_id": root["assignment_id"],
        "current_assignment_id": current["assignment_id"],
        "current_scope_id": current["scope_id"],
        "assignment_revision": int(current["revision"]),
        "processing_complete": complete,
        "assignment_conflict": False,
    }


def get_automated_scan_foundation_status(db_path: Path, run_id: str) -> dict:
    """Return durable status using read-only queries and no parsing or schema work."""
    with connect_database(db_path, read_only=True) as db:
        evidence = _run_evidence(db, run_id)
        assignment = _assignment_state(db, evidence)
        attempt = db.execute(
            """SELECT status, started_at, finished_at, error, actor
               FROM scan_foundation_processing_attempts
               WHERE run_id = ? ORDER BY rowid DESC LIMIT 1""",
            (run_id,),
        ).fetchone()
    state = "ineligible"
    if evidence["eligible"]:
        state = "ready"
        if assignment["assignment_conflict"]:
            state = "review_required"
        elif assignment["processing_complete"]:
            state = "foundation_complete"
        elif attempt is not None and attempt[0] == "error":
            state = "processing_error"
        elif attempt is not None and attempt[0] == "running":
            state = "processing_running"
        elif attempt is not None and attempt[0] == "interrupted":
            state = "processing_interrupted"
        elif assignment["current_assignment_id"]:
            state = "foundation_pending"
    return {
        **evidence,
        **assignment,
        "state": state,
        "latest_attempt": None if attempt is None else {
            "status": attempt[0], "started_at": attempt[1], "finished_at": attempt[2],
            "error": attempt[3], "actor": attempt[4],
        },
        "current_views_changed": False,
        "network_contact": False,
    }


def _ensure_inherited_assignment(db: sqlite3.Connection, evidence: dict, actor: str) -> str:
    if not evidence["eligible"]:
        raise AutomatedNmapFoundationConflict("; ".join(evidence["eligibility_reasons"]))
    state = _assignment_state(db, evidence)
    if state["assignment_conflict"]:
        raise AutomatedNmapFoundationConflict(
            "This observation already has assignment history that requires review"
        )
    if state["current_assignment_id"]:
        return str(state["current_assignment_id"])
    if not evidence["scope_active"]:
        raise AutomatedNmapFoundationConflict("The retained Network Scope is archived")
    assignment_id = f"assignment_{uuid.uuid4().hex}"
    assigned_at = utc_now()
    try:
        db.execute(
            """INSERT INTO artifact_scope_assignments (
                   assignment_id, artifact_observation_id, scope_id, revision,
                   event_kind, supersedes_assignment_id, assignment_mode,
                   actor, reason, assigned_at
               ) VALUES (?, ?, ?, 1, 'assigned', NULL, 'whole_artifact', ?, ?, ?)""",
            (assignment_id, evidence["observation_id"], evidence["scope_id"], actor,
             "Inherited from the immutable scan run Network Scope context", assigned_at),
        )
        db.execute(
            """INSERT INTO scan_inherited_scope_assignments
               (assignment_id, observation_id, run_id, scope_id, inherited_at)
               VALUES (?, ?, ?, ?, ?)""",
            (assignment_id, evidence["observation_id"], evidence["run_id"],
             evidence["scope_id"], assigned_at),
        )
    except sqlite3.IntegrityError as exc:
        state = _assignment_state(db, evidence)
        if state["current_assignment_id"] and not state["assignment_conflict"]:
            return str(state["current_assignment_id"])
        raise AutomatedNmapFoundationConflict(
            "The inherited assignment changed in another request"
        ) from exc
    return assignment_id


def process_automated_scan_foundation(db_path: Path, run_id: str, actor: str) -> dict:
    """Create/reuse the inherited assignment, then run the atomic coordinator."""
    actor = str(actor or "").strip()
    if not actor or len(actor) > 100:
        raise ValueError("A valid server-owned operator identity is required")
    init_automated_nmap_foundation_storage(db_path)
    attempt_id = uuid.uuid4().hex
    with connect_database(db_path) as db:
        db.execute("BEGIN IMMEDIATE")
        evidence = _run_evidence(db, run_id)
        assignment_id = _ensure_inherited_assignment(db, evidence, actor)
        db.execute(
            """INSERT INTO scan_foundation_processing_attempts
               (attempt_id, run_id, observation_id, assignment_id, actor,
                started_at, status)
               VALUES (?, ?, ?, ?, ?, ?, 'running')""",
            (attempt_id, run_id, evidence["observation_id"], assignment_id,
             actor, utc_now()),
        )
    try:
        processing = ingest_assigned_nmap_observation(
            db_path, expected_assignment_id=assignment_id, linked_by=actor,
        )
    except Exception as exc:
        try:
            with connect_database(db_path) as db:
                db.execute(
                    """UPDATE scan_foundation_processing_attempts
                       SET status = 'error', finished_at = ?, error = ?
                       WHERE attempt_id = ? AND status = 'running'""",
                    (utc_now(), str(exc)[:1000], attempt_id),
                )
        except sqlite3.Error:
            pass
        raise
    with connect_database(db_path) as db:
        db.execute(
            """UPDATE scan_foundation_processing_attempts
               SET status = 'complete', finished_at = ?, error = NULL
               WHERE attempt_id = ? AND status = 'running'""",
            (utc_now(), attempt_id),
        )
    return {"processing": processing,
            "status": get_automated_scan_foundation_status(db_path, run_id)}
