"""Read-only status views and eligibility checks for manual Nmap scope assignment."""
from __future__ import annotations

import json
from pathlib import Path
import sqlite3

from app.database import connect_database
from app.nmap_evidence import NMAP_ENDPOINT_PARSER


def _observation_row(db: sqlite3.Connection, observation_id: str):
    return db.execute(
        """SELECT observation.observation_id, observation.sha256,
                  observation.source_kind, observation.observed_at,
                  observation.original_filename, observation.actor,
                  observation.metadata_json, artifact.size_bytes,
                  artifact.media_type
           FROM artifact_observations observation
           JOIN artifact_registry artifact ON artifact.sha256 = observation.sha256
           WHERE observation.observation_id = ?""",
        (observation_id,),
    ).fetchone()


def _manual_observation(row) -> dict:
    if row is None:
        raise KeyError("Artifact observation does not exist")
    if row[2] != "nmap_import":
        raise ValueError("Only manual Nmap upload observations are eligible")
    return {
        "observation_id": row[0],
        "sha256": row[1],
        "source_kind": row[2],
        "observed_at": row[3],
        "original_filename": row[4],
        "actor": row[5],
        "metadata": json.loads(row[6] or "{}"),
        "size_bytes": int(row[7]),
        "media_type": row[8],
    }


def _status_on_connection(db: sqlite3.Connection, observation_id: str) -> dict:
    observation = _manual_observation(_observation_row(db, observation_id))
    db.row_factory = sqlite3.Row
    assignment_rows = db.execute(
        """SELECT assignment.*, scope.label AS scope_label,
                  scope.description AS scope_description, scope.active AS scope_active
           FROM artifact_scope_assignments assignment
           JOIN network_scopes scope ON scope.scope_id = assignment.scope_id
           WHERE assignment.artifact_observation_id = ?
           ORDER BY assignment.revision""",
        (observation_id,),
    ).fetchall()
    link_rows = db.execute(
        """SELECT link.assignment_id, link.assessment_id, link.linked_at,
                  link.linked_by, assessment.parser_version,
                  assessment.assessed_at, assessment.recorded_at
           FROM assessment_scope_assignment_links link
           JOIN entity_assessments assessment
             ON assessment.assessment_id = link.assessment_id
           JOIN artifact_scope_assignments assignment
             ON assignment.assignment_id = link.assignment_id
           WHERE assignment.artifact_observation_id = ?
           ORDER BY assignment.revision, assessment.parser_version""",
        (observation_id,),
    ).fetchall()
    links_by_assignment: dict[str, list[dict]] = {}
    for row in link_rows:
        links_by_assignment.setdefault(row["assignment_id"], []).append({
            "assessment_id": row["assessment_id"],
            "parser_version": row["parser_version"],
            "assessed_at": row["assessed_at"],
            "recorded_at": row["recorded_at"],
            "linked_at": row["linked_at"],
            "linked_by": row["linked_by"],
        })
    superseded = {
        row["supersedes_assignment_id"] for row in assignment_rows
        if row["supersedes_assignment_id"]
    }
    assignments = []
    for row in assignment_rows:
        links = links_by_assignment.get(row["assignment_id"], [])
        current = row["assignment_id"] not in superseded
        completed = any(
            item["parser_version"] == NMAP_ENDPOINT_PARSER for item in links
        )
        assignments.append({
            "assignment_id": row["assignment_id"],
            "scope_id": row["scope_id"],
            "scope_label": row["scope_label"],
            "scope_description": row["scope_description"],
            "scope_active": bool(row["scope_active"]),
            "revision": int(row["revision"]),
            "event_kind": row["event_kind"],
            "supersedes_assignment_id": row["supersedes_assignment_id"],
            "assignment_mode": row["assignment_mode"],
            "actor": row["actor"],
            "reason": row["reason"],
            "assigned_at": row["assigned_at"],
            "current": current,
            "processing_complete": completed,
            "processing": links,
        })
    current = next((item for item in assignments if item["current"]), None)
    processing_job = None
    if current is not None and db.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'pipeline_jobs'"
    ).fetchone():
        job_rows = db.execute(
            """SELECT job.job_id, job.definition_json, attempt.attempt_id,
                      attempt.attempt_number, attempt.state, attempt.requested_by,
                      attempt.requested_at, attempt.started_at, attempt.finished_at,
                      attempt.error, attempt.output_kind, attempt.output_id
               FROM pipeline_jobs job
               JOIN pipeline_job_attempts attempt ON attempt.job_id = job.job_id
               WHERE job.job_type = 'nmap_scope_assessment'
                 AND job.source_observation_id = ?
                 AND attempt.attempt_number = (
                     SELECT MAX(newest.attempt_number) FROM pipeline_job_attempts newest
                     WHERE newest.job_id = job.job_id
                 )
               ORDER BY job.requested_at DESC, job.job_id DESC""",
            (observation_id,),
        ).fetchall()
        for row in job_rows:
            if json.loads(row["definition_json"] or "{}").get("assignment_id") == current["assignment_id"]:
                processing_job = {
                    "job_id": row["job_id"],
                    "latest_attempt": {
                        "attempt_id": row["attempt_id"],
                        "attempt_number": int(row["attempt_number"]),
                        "state": row["state"],
                        "requested_by": row["requested_by"],
                        "requested_at": row["requested_at"],
                        "started_at": row["started_at"],
                        "finished_at": row["finished_at"],
                        "error": row["error"],
                        "output_kind": row["output_kind"],
                        "output_id": row["output_id"],
                    },
                }
                break
    if current is None:
        state = "unassigned"
    elif current["processing_complete"]:
        state = "foundation_complete"
    elif current["event_kind"] == "corrected":
        state = "correction_pending"
    else:
        state = "assigned_pending"
    return {
        **observation,
        "assignment_state": state,
        "current_assignment_id": current["assignment_id"] if current else None,
        "current_assignment": current,
        "assignments": assignments,
        "processing_job": processing_job,
        "processing_state": (
            processing_job["latest_attempt"]["state"] if processing_job else None
        ),
        "current_views_changed": False,
    }


def get_manual_nmap_assignment_status(db_path: Path, observation_id: str) -> dict:
    """Read one observation's durable assignment and processing history without writes."""
    with connect_database(db_path, read_only=True) as db:
        return _status_on_connection(db, observation_id)


def list_manual_nmap_assignment_statuses(db_path: Path, limit: int = 50) -> list[dict]:
    """List recent manual observations by encounter, never collapsed by content hash."""
    with connect_database(db_path, read_only=True) as db:
        rows = db.execute(
            """SELECT observation_id FROM artifact_observations
               WHERE source_kind = 'nmap_import'
               ORDER BY observed_at DESC, observation_id DESC LIMIT ?""",
            (limit,),
        ).fetchall()
        return [_status_on_connection(db, row[0]) for row in rows]


def manual_nmap_assignment_for_processing(
    db_path: Path, assignment_id: str,
) -> dict:
    """Resolve an assignment only when it belongs to an eligible manual observation."""
    with connect_database(db_path, read_only=True) as db:
        row = db.execute(
            """SELECT assignment.artifact_observation_id
               FROM artifact_scope_assignments assignment
               JOIN artifact_observations observation
                 ON observation.observation_id = assignment.artifact_observation_id
               WHERE assignment.assignment_id = ?
                 AND observation.source_kind = 'nmap_import'""",
            (assignment_id,),
        ).fetchone()
    if row is None:
        raise KeyError("Eligible manual Nmap assignment does not exist")
    return {"assignment_id": assignment_id, "artifact_observation_id": row[0]}


def active_assignment_scope_options(db_path: Path) -> list[dict]:
    """Return minimal active scope choices without exposing registry mutation APIs."""
    with connect_database(db_path, read_only=True) as db:
        rows = db.execute(
            """SELECT scope_id, label, description, version
               FROM network_scopes WHERE active = 1
               ORDER BY label_key, scope_id"""
        ).fetchall()
    return [
        {"scope_id": row[0], "label": row[1], "description": row[2],
         "version": int(row[3])}
        for row in rows
    ]
