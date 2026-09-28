"""Atomic bridge from a reviewed scope assignment to an Nmap assessment.

Scope and observation always come from the immutable assignment selected by its
exact identity. Manual imports and explicit automated-scan processing both reuse
this coordinator; ordinary analysis consumers do not.
"""
from __future__ import annotations

from pathlib import Path
import sqlite3

from app.database import connect_database
from app.entities import record_prepared_assessment_on_connection
from app.evidence_scope_assignments import init_evidence_scope_assignment_storage
from app.network_scopes import utc_now
from app.nmap_evidence import NMAP_ENDPOINT_PARSER, prepare_nmap_observation


class AssignedNmapConflict(ValueError):
    """The reviewed assignment is missing, stale, inactive, or inconsistent."""


def _text(value, field: str, maximum: int = 200) -> str:
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise ValueError(f"{field} must be nonblank trimmed text")
    if len(value) > maximum:
        raise ValueError(f"{field} exceeds {maximum} characters")
    return value


def _assignment(db: sqlite3.Connection, assignment_id: str):
    return db.execute(
        """SELECT assignment_id, artifact_observation_id, scope_id
           FROM artifact_scope_assignments WHERE assignment_id = ?""",
        (assignment_id,),
    ).fetchone()


def ingest_assigned_nmap_observation(
    db_path: Path, *, expected_assignment_id: str, linked_by: str,
    parser_version: str = NMAP_ENDPOINT_PARSER,
) -> dict:
    """Process one reviewed assignment and atomically publish all derived records.

    Canonical bytes are verified and parsed before taking the writer lock. The exact
    assignment and active destination are then rechecked inside the same transaction
    that creates or reuses the assessment and appends its immutable assignment link.
    """
    assignment_id = _text(expected_assignment_id, "expected_assignment_id")
    linked_by = _text(linked_by, "linked_by", 100)
    parser_version = _text(parser_version, "parser_version")

    # Complete every possible schema mutation before canonical-byte parsing and the
    # deliberately short all-or-nothing writer transaction below.
    init_evidence_scope_assignment_storage(db_path)
    with connect_database(db_path, read_only=True) as db:
        initial = _assignment(db, assignment_id)
    if initial is None:
        raise AssignedNmapConflict("Expected assignment does not exist")

    observation_id, scope_id = initial[1], initial[2]
    prepared, result = prepare_nmap_observation(
        db_path,
        observation_id=observation_id,
        scope_id=scope_id,
        parser_version=parser_version,
    )

    with connect_database(db_path) as db:
        db.execute("BEGIN IMMEDIATE")
        current = _assignment(db, assignment_id)
        if current is None:
            raise AssignedNmapConflict("Expected assignment does not exist")
        if current[1] != observation_id or current[2] != scope_id:
            raise AssignedNmapConflict("Expected assignment changed unexpectedly")

        linked = db.execute(
            """SELECT assessment.assessment_id, assessment.payload_json
               FROM assessment_scope_assignment_links link
               JOIN entity_assessments assessment
                 ON assessment.assessment_id = link.assessment_id
               WHERE link.assignment_id = ? AND assessment.parser_version = ?""",
            (assignment_id, parser_version),
        ).fetchone()
        if linked is not None:
            if linked[0] != prepared.assessment_id or linked[1] != prepared.payload_json:
                raise ValueError(
                    "Completed assignment replay has different facts; use a new parser version"
                )
            return {
                **result,
                "assignment_id": assignment_id,
                "assessment_created": False,
                "link_created": False,
                "completed_replay": True,
            }

        if db.execute(
            "SELECT 1 FROM artifact_scope_assignments WHERE supersedes_assignment_id = ?",
            (assignment_id,),
        ).fetchone():
            raise AssignedNmapConflict("Expected assignment is no longer current")
        active = db.execute(
            "SELECT active FROM network_scopes WHERE scope_id = ?", (scope_id,)
        ).fetchone()
        if active is None or not bool(active[0]):
            raise AssignedNmapConflict("Expected assignment scope is archived")

        assessment_id, assessment_created = record_prepared_assessment_on_connection(
            db, prepared,
        )
        db.execute(
            """INSERT INTO assessment_scope_assignment_links
               (assignment_id, assessment_id, linked_at, linked_by)
               VALUES (?, ?, ?, ?)""",
            (assignment_id, assessment_id, utc_now(), linked_by),
        )
    return {
        **result,
        "assignment_id": assignment_id,
        "assessment_created": assessment_created,
        "link_created": True,
        "completed_replay": False,
    }
