"""Read-only, bounded status view for evidence handled by the supported pipeline."""
from __future__ import annotations

import json
from pathlib import Path
import sqlite3
from urllib.parse import quote

from app.database import connect_database
from app.device_observations import DEVICE_INTERFACE_JOB_TYPE
from app.pipeline_intake import (
    AUTOMATED_NMAP_INTENT,
    AUTOMATED_NMAP_SOURCE,
    COLLECTED_DEVICE_INTENT,
    COLLECTED_DEVICE_SOURCE,
    DEVICE_OBSERVATION_INTENT,
    DEVICE_SUMMARY_JOB_TYPE,
    MANUAL_DEVICE_INTENT,
    MANUAL_DEVICE_SOURCE,
    MANUAL_NMAP_INTENT,
    MANUAL_NMAP_SOURCE,
    NMAP_SCOPE_JOB_TYPE,
)


_SOURCE_LABELS = {
    MANUAL_NMAP_SOURCE: "Imported Nmap evidence",
    AUTOMATED_NMAP_SOURCE: "Completed Nmap scan",
    MANUAL_DEVICE_SOURCE: "Uploaded device configuration",
    COLLECTED_DEVICE_SOURCE: "Collected device configuration",
}


def _table(db: sqlite3.Connection, name: str) -> bool:
    return db.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (name,)
    ).fetchone() is not None


def _one(db: sqlite3.Connection, sql: str, values: tuple = ()) -> sqlite3.Row | None:
    return db.execute(sql, values).fetchone()


def _json_object(raw: str | None, label: str) -> dict:
    try:
        value = json.loads(raw or "{}")
    except (TypeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is not readable JSON") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value


def _stage(key: str, label: str, state: str, detail: str, **extra) -> dict:
    labels = {
        "completed": "Complete", "needs_scope": "Needs scope",
        "waiting": "Waiting", "retrying": "Retrying", "paused": "Paused",
        "queued": "Queued", "running": "Running", "failed": "Failed",
        "interrupted": "Interrupted", "blocked": "Needs attention",
        "unavailable": "Unavailable", "not_applicable": "Not required",
    }
    return {
        "key": key, "label": label, "state": state,
        "state_label": labels.get(state, state.replace("_", " ").title()),
        "detail": detail, **extra,
    }


def _intent(db: sqlite3.Connection, kind: str, source_id: str) -> sqlite3.Row | None:
    if not _table(db, "pipeline_admission_intents"):
        return None
    return _one(
        db,
        """SELECT * FROM pipeline_admission_intents
           WHERE intent_kind = ? AND source_id = ?""",
        (kind, source_id),
    )


def _attempt(db: sqlite3.Connection, job_id: str) -> sqlite3.Row | None:
    return _one(
        db,
        """SELECT * FROM pipeline_job_attempts WHERE job_id = ?
           ORDER BY attempt_number DESC LIMIT 1""",
        (job_id,),
    )


def _job_matches_intent(intent: sqlite3.Row, job: sqlite3.Row) -> bool:
    contract = _json_object(intent["contract_json"], "Intake contract")
    definition = _json_object(job["definition_json"], "Work definition")
    expected_type = {
        MANUAL_NMAP_INTENT: NMAP_SCOPE_JOB_TYPE,
        AUTOMATED_NMAP_INTENT: NMAP_SCOPE_JOB_TYPE,
        MANUAL_DEVICE_INTENT: DEVICE_SUMMARY_JOB_TYPE,
        COLLECTED_DEVICE_INTENT: DEVICE_SUMMARY_JOB_TYPE,
        DEVICE_OBSERVATION_INTENT: DEVICE_INTERFACE_JOB_TYPE,
    }.get(intent["intent_kind"])
    if expected_type is None or job["job_type"] != expected_type:
        return False
    if intent["observation_id"] != job["source_observation_id"]:
        return False
    for contract_key, job_key in (
        ("source_sha256", "source_sha256"),
        ("source_size_bytes", "source_size_bytes"),
        ("target_family", "target_family"),
        ("target_analysis_version", "target_analysis_version"),
        ("target_payload_schema_version", "target_payload_schema_version"),
    ):
        expected = contract.get(contract_key)
        if expected is not None and str(expected) != str(job[job_key]):
            return False
    if (
        contract.get("target_parameters") is not None
        and contract["target_parameters"] != _json_object(
            job["target_parameters_json"], "Work settings",
        )
    ):
        return False
    kind = intent["intent_kind"]
    if kind == MANUAL_NMAP_INTENT:
        return (
            definition.get("assignment_id") == intent["assignment_id"] == intent["source_id"]
            and definition.get("scope_id") == intent["scope_id"]
            and job["source_ref"] == contract.get("source_ref")
        )
    if kind == AUTOMATED_NMAP_INTENT:
        return (
            job["source_run_id"] == job["source_ref"] == intent["source_id"]
            and definition.get("assignment_id") == intent["resolved_assignment_id"]
            and definition.get("scope_id") == intent["scope_id"]
        )
    if kind in {MANUAL_DEVICE_INTENT, COLLECTED_DEVICE_INTENT}:
        return (
            job["source_run_id"] == job["source_ref"] == intent["source_id"]
            and definition == contract
        )
    assignment = contract.get("assignment") or {}
    if not isinstance(assignment, dict):
        raise ValueError("Device assignment contract must be a JSON object")
    return (
        job["source_run_id"] == assignment.get("run_id")
        and job["source_ref"] == intent["assignment_id"] == intent["source_id"]
        and definition.get("assignment_contract") == contract
    )


def _completed_device_summary_exists(
    db: sqlite3.Connection, job: sqlite3.Row, output_id: str,
    contract: dict,
) -> bool:
    required = {
        "derived_results", "derived_result_inputs",
        "derived_result_observation_links",
    }
    if any(not _table(db, name) for name in required):
        return False
    result = _one(
        db,
        """SELECT family, analysis_version, payload_schema_version,
                  parameters_json, inputs_json FROM derived_results WHERE result_id = ?""",
        (output_id,),
    )
    if result is None or tuple(result[:4]) != (
        job["target_family"], job["target_analysis_version"],
        int(job["target_payload_schema_version"]), job["target_parameters_json"],
    ):
        return False
    saved_inputs = json.loads(result[4] or "[]")
    if not isinstance(saved_inputs, list) or any(not isinstance(item, dict) for item in saved_inputs):
        raise ValueError("Saved result input manifest must be a JSON array of objects")
    manifest_inputs = {
        item.get("role"): (
            item.get("kind"), item.get("identity"), item.get("metadata"),
        )
        for item in saved_inputs
    }
    if None in manifest_inputs or len(manifest_inputs) != len(saved_inputs):
        raise ValueError("Saved result input manifest has invalid or duplicate roles")
    input_rows = db.execute(
            """SELECT input_role, input_kind, input_identity, input_metadata_json
               FROM derived_result_inputs WHERE result_id = ?""",
            (output_id,),
        ).fetchall()
    inputs = {
        row[0]: (row[1], row[2], json.loads(row[3] or "{}")) for row in input_rows
    }
    if set(inputs) != {
        "configuration", "raw_output", "command_history",
        "manifest_semantics", "selection_shape",
    }:
        return False
    if inputs != manifest_inputs:
        return False
    if inputs["manifest_semantics"][:2] != (
        "canonical_json_sha256", contract.get("semantic_manifest_sha256"),
    ):
        return False
    authority_inputs = contract.get("authority_inputs") or []
    if not isinstance(authority_inputs, list) or any(
        not isinstance(item, dict) for item in authority_inputs
    ):
        raise ValueError("Device authority inputs must be a JSON array of objects")
    by_role = {item.get("role"): item for item in authority_inputs}
    if contract.get("intent_kind") == MANUAL_DEVICE_INTENT:
        combined = by_role.get("configuration_and_raw_output") or {}
        expected_inputs = {
            "configuration": ("artifact_sha256", combined.get("identity")),
            "raw_output": ("artifact_sha256", combined.get("identity")),
        }
        expected_links = {
            ("configuration", combined.get("observation_id")),
            ("raw_output", combined.get("observation_id")),
        }
    else:
        expected_inputs = {
            role: (
                "artifact_sha256" if item.get("source_kind") == "artifact_file"
                else "embedded_config_section" if item.get("source_kind") == "embedded_section"
                else "absence_descriptor",
                item.get("identity"),
            )
            for role, item in by_role.items()
        }
        expected_links = {
            (role, item.get("observation_id")) for role, item in by_role.items()
            if item.get("source_kind") == "artifact_file"
        }
    if any(
        inputs.get(role, (None, None))[:2] != expected
        for role, expected in expected_inputs.items()
    ):
        return False
    actual_links = {
        (row[0], row[1]) for row in db.execute(
            """SELECT input_role, observation_id
               FROM derived_result_observation_links WHERE result_id = ?""",
            (output_id,),
        ).fetchall()
    }
    return expected_links.issubset(actual_links)


def _completed_output_exists(
    db: sqlite3.Connection, job: sqlite3.Row, attempt: sqlite3.Row,
    intent: sqlite3.Row,
) -> bool:
    output_kind, output_id = attempt["output_kind"], attempt["output_id"]
    if not output_kind or not output_id:
        return False
    definition = _json_object(job["definition_json"], "Work definition")
    contract = _json_object(intent["contract_json"], "Intake contract")
    if job["job_type"] == NMAP_SCOPE_JOB_TYPE and output_kind == "entity_assessment":
        if not _table(db, "entity_assessments") or not _table(db, "assessment_scope_assignment_links"):
            return False
        assignment_id = definition.get("assignment_id")
        return _one(
            db,
            """SELECT 1 FROM entity_assessments assessment
               JOIN assessment_scope_assignment_links link
                 ON link.assessment_id = assessment.assessment_id
               WHERE assessment.assessment_id = ?
                 AND assessment.artifact_observation_id = ?
                 AND assessment.scope_id = ?
                 AND assessment.parser_version = ?
                 AND link.assignment_id = ?""",
            (
                output_id, job["source_observation_id"], definition.get("scope_id"),
                job["target_analysis_version"],
                assignment_id,
            ),
        ) is not None
    if job["job_type"] == DEVICE_SUMMARY_JOB_TYPE and output_kind == "derived_result":
        return _completed_device_summary_exists(db, job, output_id, contract)
    if (
        job["job_type"] == DEVICE_INTERFACE_JOB_TYPE
        and output_kind == "device_interface_assessment"
    ):
        if not _table(db, "device_interface_assessments"):
            return False
        return _one(
            db,
            """SELECT 1 FROM device_interface_assessments
               WHERE assessment_id = ? AND assignment_id = ?
                 AND configuration_sha256 = ?""",
            (output_id, job["source_ref"], job["source_sha256"]),
        ) is not None
    return False


def _work_stage(
    db: sqlite3.Connection, intent: sqlite3.Row | None, *, key: str, label: str,
    waiting_detail: str,
) -> dict:
    if intent is None:
        return _stage(key, label, "waiting", waiting_detail)
    state = intent["state"]
    activity = intent["activity_state"]
    error = intent["last_error"]
    if state == "needs_scope":
        return _stage(key, label, "needs_scope", error or "Choose a Network Scope before this stage can run.")
    if state == "blocked":
        return _stage(key, label, "blocked", error or "The saved evidence did not meet this stage's requirements.")
    if state == "pending":
        pending = activity if activity in {"waiting", "retrying", "paused"} else "waiting"
        return _stage(key, label, pending, error or waiting_detail)
    job_id = intent["admitted_job_id"]
    if not job_id or not _table(db, "pipeline_jobs") or not _table(db, "pipeline_job_attempts"):
        return _stage(key, label, "blocked", "Queue admission is recorded, but the matching work record is unavailable.")
    job = _one(db, "SELECT * FROM pipeline_jobs WHERE job_id = ?", (job_id,))
    if job is None:
        return _stage(key, label, "blocked", "Queue admission points to a missing work record.")
    if not _job_matches_intent(intent, job):
        return _stage(
            key, label, "blocked",
            "Queue admission does not match this exact evidence encounter and processing contract.",
            job_id=job_id,
        )
    latest = _attempt(db, job_id)
    if latest is None:
        return _stage(key, label, "blocked", "The work record has no execution attempt.", job_id=job_id)
    job_state = latest["state"]
    if job_state == "completed":
        if not _completed_output_exists(db, job, latest, intent):
            return _stage(
                key, label, "blocked",
                "Processing says it completed, but its exact saved output cannot be verified.",
                job_id=job_id,
            )
        return _stage(
            key, label, "completed", "The exact saved output is present and linked to this evidence encounter.",
            job_id=job_id,
            output={"kind": latest["output_kind"], "id": latest["output_id"]},
        )
    detail = latest["error"] or {
        "queued": "Saved evidence is queued and will continue automatically.",
        "running": "Saved evidence is being processed locally.",
        "failed": "Local processing failed. The saved evidence remains available.",
        "interrupted": "Processing stopped during a restart and requires an explicit retry.",
    }.get(job_state, "The saved work state is not recognized.")
    return _stage(key, label, job_state if job_state in {
        "queued", "running", "failed", "interrupted"
    } else "blocked", detail, job_id=job_id)


def _current_artifact_assignment(db: sqlite3.Connection, observation_id: str):
    if not _table(db, "artifact_scope_assignments"):
        return None
    return _one(
        db,
        """SELECT assignment.*, scope.label AS scope_label
           FROM artifact_scope_assignments assignment
           LEFT JOIN network_scopes scope ON scope.scope_id = assignment.scope_id
           WHERE assignment.artifact_observation_id = ?
             AND NOT EXISTS (
                 SELECT 1 FROM artifact_scope_assignments successor
                 WHERE successor.supersedes_assignment_id = assignment.assignment_id
             )
           ORDER BY assignment.revision DESC LIMIT 1""",
        (observation_id,),
    )


def _current_device_assignment(db: sqlite3.Connection, run_id: str):
    if not _table(db, "device_scope_assignments"):
        return None
    return _one(
        db,
        """SELECT assignment.*, scope.label AS scope_label
           FROM device_scope_assignments assignment
           LEFT JOIN network_scopes scope ON scope.scope_id = assignment.scope_id
           WHERE assignment.run_id = ?
             AND NOT EXISTS (
                 SELECT 1 FROM device_scope_assignments successor
                 WHERE successor.supersedes_assignment_id = assignment.assignment_id
             )
           ORDER BY assignment.revision DESC LIMIT 1""",
        (run_id,),
    )


def _manual_nmap(db: sqlite3.Connection, marker: sqlite3.Row) -> dict:
    source_id = marker["source_id"]
    observation = _one(
        db,
        """SELECT observation.*, artifact.size_bytes FROM artifact_observations observation
           LEFT JOIN artifact_registry artifact ON artifact.sha256 = observation.sha256
           WHERE observation.observation_id = ?""",
        (source_id,),
    )
    if observation is None:
        stages = [_stage("retained", "Evidence retained", "blocked", "The intake marker points to a missing evidence record.")]
        return _item(marker, source_id, "Missing imported Nmap record", None, None, None, stages, [])
    assignment = _current_artifact_assignment(db, source_id)
    scope_stage = (
        _stage("scope", "Network Scope", "completed", f"Assigned to {assignment['scope_label'] or assignment['scope_id']}.")
        if assignment else
        _stage("scope", "Network Scope", "needs_scope", "Choose the Network Scope that gives these addresses their meaning.")
    )
    work = _work_stage(
        db, _intent(db, MANUAL_NMAP_INTENT, assignment["assignment_id"]) if assignment else None,
        key="scoped_observations", label="Scoped Nmap observations",
        waiting_detail="Waiting for the reviewed scope decision to enter local processing.",
    ) if assignment else _stage(
        "scoped_observations", "Scoped Nmap observations", "needs_scope",
        "Processing starts after a Network Scope is assigned.",
    )
    digest = observation["sha256"]
    links = [
        {"label": "Open retained source", "url": f"/api/imports/{digest}/raw"},
        {"label": "Assign or review scope", "url": "/analysis#xmlImport"},
    ]
    return _item(
        marker, source_id, observation["original_filename"] or "Imported Nmap XML",
        observation["observed_at"], observation["actor"], observation["size_bytes"],
        [_stage("retained", "Evidence retained", "completed", "The imported XML is registered as this separate encounter."), scope_stage, work], links,
    )


def _automated_nmap(db: sqlite3.Connection, marker: sqlite3.Row) -> dict:
    run_id = marker["source_id"]
    run = _one(db, "SELECT * FROM scan_runs WHERE run_id = ?", (run_id,)) if _table(db, "scan_runs") else None
    if run is None:
        return _item(marker, run_id, "Missing Nmap scan record", None, None, None,
                     [_stage("retained", "Scan record retained", "blocked", "The intake marker points to a missing scan record.")], [])
    manifest = json.loads(run["manifest_json"] or "{}")
    intent = _intent(db, AUTOMATED_NMAP_INTENT, run_id)
    received = manifest.get("completed_at") or run["created_at"]
    name = manifest.get("name") or manifest.get("scan_name") or f"Nmap scan {run_id[:8]}"
    actor = manifest.get("executed_by") or manifest.get("created_by") or run["operator_name"]
    terminal_failure = run["status"] in {
        "failed", "cancelled", "timed_out", "completed_without_nmap", "interrupted",
    }
    if terminal_failure:
        failure_state = "interrupted" if run["status"] == "interrupted" else "failed"
        detail = {
            "failed": "The scan ended in failure before one finalized aggregate Nmap source became available.",
            "cancelled": "The scan was cancelled before one finalized aggregate Nmap source became available.",
            "timed_out": "The scan timed out before one finalized aggregate Nmap source became available.",
            "completed_without_nmap": "Collection finished without a supported finalized Nmap source.",
            "interrupted": "The scan was interrupted before one finalized aggregate Nmap source became available.",
        }[run["status"]]
        return _item(
            marker, run_id, name, received, actor, None,
            [
                _stage("retained", "Scan outcome retained", failure_state, detail),
                _stage("scope", "Network Scope", "not_applicable", "Scope assignment cannot make an incomplete scan source processable."),
                _stage("scoped_observations", "Scoped Nmap observations", "not_applicable", "No supported aggregate Nmap evidence is available to process."),
            ],
            [{"label": "Open scan history", "url": f"/scans?run={quote(run_id)}#scanHistory"}],
        )
    retained_state = "completed" if run["status"] == "completed" else "waiting"
    retained_detail = (
        "The finalized aggregate Nmap evidence is retained."
        if retained_state == "completed" else
        f"The scan record is {run['status']}; finalized evidence is not available yet."
    )
    if intent and intent["scope_id"]:
        scope = _one(db, "SELECT label FROM network_scopes WHERE scope_id = ?", (intent["scope_id"],))
        scope_stage = _stage("scope", "Network Scope", "completed", f"Uses the reviewed scope {scope[0] if scope else intent['scope_id']}.")
    elif intent and intent["state"] == "blocked":
        scope_stage = _stage("scope", "Network Scope", "blocked", intent["last_error"] or "The retained scope context cannot be used.")
    else:
        scope_stage = _stage("scope", "Network Scope", "needs_scope", (intent["last_error"] if intent else None) or "This scan does not have one authoritative reviewed Network Scope.")
    work = _work_stage(
        db, intent, key="scoped_observations", label="Scoped Nmap observations",
        waiting_detail="Waiting for finalized evidence and its reviewed scope context.",
    )
    links = [
        {"label": "Open scan history", "url": f"/scans?run={quote(run_id)}#scanHistory"},
        {"label": "Open retained source", "url": f"/api/scan-runs/{quote(run_id)}/artifacts/xml"},
    ]
    return _item(marker, run_id, name, received, actor, None,
                 [_stage("retained", "Scan evidence retained", retained_state, retained_detail), scope_stage, work], links)


def _device(db: sqlite3.Connection, marker: sqlite3.Row) -> dict:
    run_id = marker["source_id"]
    authority = _one(db, "SELECT * FROM device_collection_authority WHERE run_id = ?", (run_id,)) if _table(db, "device_collection_authority") else None
    collection = _one(db, "SELECT * FROM device_collections WHERE run_id = ?", (run_id,)) if _table(db, "device_collections") else None
    name = (
        (collection["device_name"] or collection["device_address"])
        if collection else f"Device evidence {run_id[:8]}"
    )
    received = (authority["activated_at"] or authority["created_at"]) if authority else (collection["completed_at"] or collection["created_at"] if collection else None)
    actor = marker["marked_by"]
    if authority is None:
        retained = _stage("retained", "Evidence authority", "blocked", "The intake marker points to a missing device evidence authority.")
    elif authority["state"] == "active":
        retained = _stage("retained", "Evidence authority", "completed", "The selected retained files and their roles were verified.")
    elif authority["state"] == "preparing":
        retained = _stage("retained", "Evidence authority", "waiting", "Local verification is still preparing the evidence authority.")
    else:
        retained = _stage("retained", "Evidence authority", "unavailable", "This collection was deleted after its retained authority record was created.")
    summary_kind = MANUAL_DEVICE_INTENT if marker["source_kind"] == MANUAL_DEVICE_SOURCE else COLLECTED_DEVICE_INTENT
    summary = _work_stage(
        db, _intent(db, summary_kind, run_id), key="summary",
        label="Reusable device summary",
        waiting_detail="Waiting for verified retained files to enter local summary processing.",
    )
    assignment = _current_device_assignment(db, run_id)
    if assignment:
        scope_stage = _stage("scope", "Network Scope", "completed", f"Assigned to {assignment['scope_label'] or assignment['scope_id']}.")
        observations = _work_stage(
            db, _intent(db, DEVICE_OBSERVATION_INTENT, assignment["assignment_id"]),
            key="scoped_observations", label="Scoped device addresses",
            waiting_detail="Waiting for the reviewed scope decision to enter local normalization.",
        )
    else:
        scope_stage = _stage("scope", "Network Scope", "needs_scope", "Choose the Network Scope that gives the reported addresses their meaning.")
        observations = _stage("scoped_observations", "Scoped device addresses", "needs_scope", "Address receipts start after a Network Scope is assigned.")
    links = [{"label": "Open device history", "url": f"/device-config?run={quote(run_id)}#deviceHistory"}]
    if authority and authority["state"] == "active" and authority["retained_filename"]:
        links.insert(0, {"label": "Open retained source", "url": f"/api/device-configs/{quote(run_id)}/files/{quote(authority['retained_filename'])}"})
    return _item(marker, run_id, name, received, actor, None,
                 [retained, summary, scope_stage, observations], links)


def _item(
    marker: sqlite3.Row, source_id: str, name: str, received_at: str | None,
    actor: str | None, size_bytes: int | None, stages: list[dict], links: list[dict],
) -> dict:
    states = {stage["state"] for stage in stages}
    if states & {"blocked", "failed", "interrupted", "paused", "unavailable"}:
        code, label = "needs_attention", "Needs attention"
    elif "needs_scope" in states:
        code, label = "needs_scope", "Needs scope"
    elif states & {"waiting", "retrying", "queued", "running"}:
        code, label = "processing", "Processing"
    else:
        code, label = "ready", "Ready"
    next_action = {
        "ready": "Open the saved result or source evidence.",
        "needs_scope": "Open the source workflow and assign a Network Scope.",
        "processing": "No action is needed while queued or running work continues.",
        "needs_attention": "Open the source workflow to review the reason and retry when available.",
    }[code]
    return {
        "encounter_id": f"{marker['source_kind']}:{source_id}",
        "source_kind": marker["source_kind"],
        "source_label": _SOURCE_LABELS.get(marker["source_kind"], marker["source_kind"]),
        "source_id": source_id, "name": name, "received_at": received_at,
        "actor": actor, "size_bytes": size_bytes, "status": code,
        "status_label": label, "next_action": next_action,
        "stages": stages, "links": links,
    }


def _historical_counts(db: sqlite3.Connection) -> dict:
    counts = {"manual_nmap": 0, "automated_nmap": 0, "device": 0}
    if _table(db, "artifact_observations"):
        counts["manual_nmap"] = int(db.execute(
            """SELECT COUNT(*) FROM artifact_observations observation
               WHERE observation.source_kind = 'nmap_import'
                 AND NOT EXISTS (SELECT 1 FROM pipeline_intake_sources marker
                   WHERE marker.source_kind = ? AND marker.source_id = observation.observation_id)""",
            (MANUAL_NMAP_SOURCE,),
        ).fetchone()[0])
    if _table(db, "scan_runs"):
        counts["automated_nmap"] = int(db.execute(
            """SELECT COUNT(*) FROM scan_runs run WHERE run.status = 'completed'
                 AND NOT EXISTS (SELECT 1 FROM pipeline_intake_sources marker
                   WHERE marker.source_kind = ? AND marker.source_id = run.run_id)""",
            (AUTOMATED_NMAP_SOURCE,),
        ).fetchone()[0])
    if _table(db, "device_collection_authority"):
        counts["device"] = int(db.execute(
            """SELECT COUNT(*) FROM device_collection_authority authority
               WHERE NOT EXISTS (SELECT 1 FROM pipeline_intake_sources marker
                 WHERE marker.source_kind IN (?, ?) AND marker.source_id = authority.run_id)""",
            (MANUAL_DEVICE_SOURCE, COLLECTED_DEVICE_SOURCE),
        ).fetchone()[0])
    counts["total"] = sum(counts.values())
    return counts


def list_ingestion_status(db_path: Path, *, limit: int = 25, offset: int = 0) -> dict:
    """Return one metadata-only SQLite snapshot of supported evidence intake."""
    limit = max(1, min(int(limit), 100))
    offset = max(0, int(offset))
    empty = {
        "items": [], "total": 0, "limit": limit, "offset": offset,
        "has_more": False, "counts": {"ready": 0, "processing": 0, "needs_scope": 0, "needs_attention": 0},
        "historical_unadopted": {"manual_nmap": 0, "automated_nmap": 0, "device": 0, "total": 0},
        "snapshot": "read-only metadata transaction",
    }
    if not Path(db_path).is_file():
        return empty
    with connect_database(db_path, read_only=True) as db:
        db.row_factory = sqlite3.Row
        db.execute("BEGIN")
        if not _table(db, "pipeline_intake_sources"):
            return empty
        total = int(db.execute("SELECT COUNT(*) FROM pipeline_intake_sources").fetchone()[0])
        markers = db.execute(
            """SELECT source_kind, source_id, policy_version, marked_by, marked_at
               FROM pipeline_intake_sources
               ORDER BY marked_at DESC, source_kind, source_id LIMIT ? OFFSET ?""",
            (limit, offset),
        ).fetchall()
        builders = {
            MANUAL_NMAP_SOURCE: _manual_nmap,
            AUTOMATED_NMAP_SOURCE: _automated_nmap,
            MANUAL_DEVICE_SOURCE: _device,
            COLLECTED_DEVICE_SOURCE: _device,
        }
        items = []
        for marker in markers:
            builder = builders.get(marker["source_kind"])
            if builder:
                try:
                    items.append(builder(db, marker))
                except (KeyError, TypeError, ValueError, json.JSONDecodeError, sqlite3.Error) as exc:
                    items.append(_item(
                        marker, marker["source_id"], "Evidence status integrity issue",
                        marker["marked_at"], marker["marked_by"], None,
                        [_stage(
                            "integrity", "Saved status metadata", "blocked",
                            f"NCT could not reconcile this record: {str(exc)[:500] or exc.__class__.__name__}.",
                        )], [],
                    ))
            else:
                items.append(_item(
                    marker, marker["source_id"], "Unsupported intake marker",
                    marker["marked_at"], marker["marked_by"], None,
                    [_stage("retained", "Evidence intake", "blocked", "This build does not recognize the recorded intake type.")], [],
                ))
        counts = {key: 0 for key in ("ready", "processing", "needs_scope", "needs_attention")}
        for item in items:
            counts[item["status"]] += 1
        historical = _historical_counts(db)
    return {
        "items": items, "total": total, "limit": limit, "offset": offset,
        "has_more": offset + len(markers) < total, "counts": counts,
        "historical_unadopted": historical,
        "snapshot": "read-only metadata transaction",
    }
