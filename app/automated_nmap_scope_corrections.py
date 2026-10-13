"""Explicit repair of the scoped-artifact handoff for one affected scan run."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import uuid

from app.artifacts import (
    artifact_root_for,
    canonical_artifact_path,
    sha256_file,
)
from app.database import connect_database, initialize_once_per_database
from app.derived_jobs import (
    _automated_contract_from_evidence,
    _enqueue_automated_nmap_scope_job,
    _request_token,
    _run_local_path,
    init_derived_job_storage,
    start_derived_job_worker,
)
from app.network_scopes import utc_now
from app.pipeline_intake import (
    AUTOMATED_NMAP_INTENT,
    NMAP_INGESTION_POLICY_VERSION,
    NMAP_SCOPE_PAYLOAD_SCHEMA_VERSION,
    NMAP_SCOPE_TARGET_FAMILY,
    admission_intent_on_connection,
)
from app.nmap_evidence import NMAP_ENDPOINT_PARSER
from app.saved_network_scope_associations import (
    insert_artifact_observation_scope_context,
)


class AutomatedNmapScopeCorrectionConflict(ValueError):
    """The retained scan cannot receive the narrow handoff correction."""


def _canonical_json(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


@initialize_once_per_database
def init_automated_nmap_scope_correction_storage(db_path: Path) -> None:
    with connect_database(db_path) as db:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS automated_nmap_scope_corrections (
                correction_id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL UNIQUE REFERENCES scan_runs(run_id),
                observation_id TEXT NOT NULL UNIQUE
                    REFERENCES artifact_observations(observation_id),
                prior_intent_id TEXT NOT NULL UNIQUE
                    REFERENCES pipeline_admission_intents(intent_id),
                prior_intent_sha256 TEXT NOT NULL CHECK(length(prior_intent_sha256) = 64),
                corrected_contract_json TEXT NOT NULL,
                actor TEXT NOT NULL,
                reason TEXT NOT NULL,
                request_token TEXT NOT NULL UNIQUE,
                requested_at TEXT NOT NULL,
                assignment_id TEXT NOT NULL UNIQUE
                    REFERENCES artifact_scope_assignments(assignment_id),
                job_id TEXT NOT NULL UNIQUE REFERENCES pipeline_jobs(job_id)
            );
            CREATE TRIGGER IF NOT EXISTS automated_nmap_scope_correction_no_update
                BEFORE UPDATE ON automated_nmap_scope_corrections
                BEGIN SELECT RAISE(ABORT, 'automated Nmap scope corrections are append-only'); END;
            CREATE TRIGGER IF NOT EXISTS automated_nmap_scope_correction_no_delete
                BEFORE DELETE ON automated_nmap_scope_corrections
                BEGIN SELECT RAISE(ABORT, 'automated Nmap scope corrections are append-only'); END;
            """
        )


def _existing_correction(db, run_id: str) -> dict | None:
    available = db.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' "
        "AND name='automated_nmap_scope_corrections'"
    ).fetchone()
    if available is None:
        return None
    row = db.execute(
        """SELECT correction_id, run_id, observation_id, prior_intent_id,
                  prior_intent_sha256, corrected_contract_json, actor, reason,
                  request_token, requested_at, assignment_id, job_id
           FROM automated_nmap_scope_corrections WHERE run_id = ?""",
        (run_id,),
    ).fetchone()
    if row is None:
        return None
    return {
        "correction_id": row[0], "run_id": row[1], "observation_id": row[2],
        "prior_intent_id": row[3], "prior_intent_sha256": row[4],
        "corrected_contract": json.loads(row[5]), "actor": row[6],
        "reason": row[7], "request_token": row[8], "requested_at": row[9],
        "assignment_id": row[10], "job_id": row[11],
    }


def _candidate_on_connection(db, run_id: str) -> dict:
    existing = _existing_correction(db, run_id)
    if existing is not None:
        return {"available": False, "state": "corrected", "correction": existing}
    run = db.execute(
        "SELECT status, manifest_json FROM scan_runs WHERE run_id = ?", (run_id,)
    ).fetchone()
    if run is None:
        raise KeyError("Scan run not found")
    try:
        manifest = json.loads(run[1])
    except (TypeError, json.JSONDecodeError) as exc:
        raise AutomatedNmapScopeCorrectionConflict(
            "The retained scan record is unreadable"
        ) from exc
    reasons: list[str] = []
    if run[0] != "completed" or manifest.get("status") != "completed":
        reasons.append("The scan is not completed in both retained records")
    manual_targets = manifest.get("manual_targets") or (
        manifest.get("target_selection") or {}
    ).get("manual_targets")
    if manual_targets:
        reasons.append("Scans containing manual targets cannot use this correction")
    context = db.execute(
        """SELECT context.scope_id, context.scope_label, context.scope_version,
                  context.recorded_at, scope.active,
                  (SELECT COUNT(*) FROM scan_run_scope_sources source
                   WHERE source.run_id = context.run_id)
           FROM scan_run_scope_contexts context
           JOIN network_scopes scope ON scope.scope_id = context.scope_id
           WHERE context.run_id = ?""",
        (run_id,),
    ).fetchone()
    if context is None:
        reasons.append("The run has no retained Network Scope context")
    else:
        retained_context = manifest.get("network_scope_context") or {}
        expected_context = {
            "scope_id": context[0], "scope_label": context[1],
            "scope_version": int(context[2]), "recorded_at": context[3],
        }
        if any(retained_context.get(key) != value for key, value in expected_context.items()):
            reasons.append("The manifest and retained Network Scope context differ")
        if not bool(context[4]):
            reasons.append("The retained Network Scope is archived")
        if int(context[5] or 0) < 1:
            reasons.append("The retained Network Scope has no frozen Saved Network source")
    observations = db.execute(
        """SELECT observation.observation_id, observation.sha256, artifact.size_bytes,
                  artifact.canonical_path, observation.metadata_json
           FROM artifact_observations observation
           JOIN artifact_registry artifact ON artifact.sha256 = observation.sha256
           WHERE observation.source_kind = 'nmap_scan'
             AND observation.source_ref = ?
             AND observation.original_filename = 'scan.xml'""",
        (run_id,),
    ).fetchall()
    if len(observations) != 1:
        reasons.append("Exactly one aggregate scan.xml observation is required")
    observation = observations[0] if len(observations) == 1 else None
    observation_metadata: dict = {}
    if observation is not None:
        try:
            observation_metadata = json.loads(observation[4] or "{}")
            if not isinstance(observation_metadata, dict):
                raise ValueError
        except (TypeError, ValueError, json.JSONDecodeError):
            reasons.append("The aggregate scan.xml retained path metadata is unreadable")
            observation_metadata = {}
        if db.execute(
            "SELECT 1 FROM artifact_observation_scope_contexts WHERE observation_id = ?",
            (observation[0],),
        ).fetchone() is not None:
            reasons.append("The aggregate scan.xml already has scope context")
        if db.execute(
            "SELECT 1 FROM artifact_scope_assignments WHERE artifact_observation_id = ?",
            (observation[0],),
        ).fetchone() is not None:
            reasons.append("The aggregate scan.xml already has assignment history")
        jobs_table = db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='pipeline_jobs'"
        ).fetchone()
        if jobs_table is not None and db.execute(
            "SELECT 1 FROM pipeline_jobs WHERE source_observation_id = ?",
            (observation[0],),
        ).fetchone() is not None:
            reasons.append("The aggregate scan.xml already has processing history")
    intent = admission_intent_on_connection(
        db, intent_kind=AUTOMATED_NMAP_INTENT, source_id=run_id,
    )
    if intent is None:
        reasons.append("The failed automatic admission record is unavailable")
    elif not (
        intent["state"] == "needs_scope"
        and intent["activity_state"] == "needs_scope"
        and intent["scope_id"] is None
        and intent["assignment_id"] is None
        and intent["admitted_job_id"] is None
        and intent["resolved_assignment_id"] is None
        and int(intent["policy_version"]) == NMAP_INGESTION_POLICY_VERSION
    ):
        reasons.append("The retained automatic admission is not the expected failed handoff")
    if intent is not None and observation is not None:
        expected_contract = {
            "intent_kind": AUTOMATED_NMAP_INTENT,
            "source_kind": "nmap_scan",
            "run_id": run_id,
            "source_status": "completed",
            "observation_id": observation[0],
            "source_sha256": observation[1],
            "source_size_bytes": int(observation[2]),
            "scope_id": None,
            "scope_label": None,
            "scope_version": None,
            "scope_recorded_at": None,
            "target_family": NMAP_SCOPE_TARGET_FAMILY,
            "target_analysis_version": NMAP_ENDPOINT_PARSER,
            "target_payload_schema_version": NMAP_SCOPE_PAYLOAD_SCHEMA_VERSION,
            "target_parameters": {},
            "eligibility_reasons": ["A retained authoritative Network Scope is required"],
        }
        if intent.get("observation_id") != observation[0] or intent.get("contract") != expected_contract:
            reasons.append("The retained failed admission contract is not the known defect shape")
    return {
        "available": not reasons,
        "state": "available" if not reasons else "unavailable",
        "reasons": reasons,
        "manifest": manifest,
        "context": None if context is None else {
            "scope_id": context[0], "scope_label": context[1],
            "scope_version": int(context[2]), "recorded_at": context[3],
        },
        "observation": None if observation is None else {
            "observation_id": observation[0], "sha256": observation[1],
            "size_bytes": int(observation[2]), "canonical_path": observation[3],
            "metadata": observation_metadata,
        },
        "intent": intent,
    }


def scope_handoff_correction_status_on_connection(db, run_id: str) -> dict:
    candidate = _candidate_on_connection(db, run_id)
    return {
        key: value for key, value in candidate.items()
        if key not in {"manifest", "context", "observation", "intent"}
    }


def correct_automated_nmap_scope_handoff(
    db_path: Path,
    data_dir: Path,
    run_id: str,
    *,
    actor: str,
    reason: str,
    request_token: str,
) -> dict:
    actor = str(actor or "").strip()
    reason = str(reason or "").strip()
    token = _request_token(request_token)
    if not actor or len(actor) > 100:
        raise ValueError("A valid administrator identity is required")
    if not reason or len(reason) > 500:
        raise ValueError("A correction reason is required")
    try:
        local = _run_local_path(data_dir, run_id)
    except ValueError as exc:
        raise AutomatedNmapScopeCorrectionConflict(str(exc)) from exc
    init_derived_job_storage(db_path)
    init_automated_nmap_scope_correction_storage(db_path)
    with connect_database(db_path) as db:
        db.execute("BEGIN IMMEDIATE")
        existing = _existing_correction(db, run_id)
        if existing is not None:
            if (
                existing["request_token"] == token
                and existing["actor"] == actor
                and existing["reason"] == reason
            ):
                result = existing
            else:
                raise AutomatedNmapScopeCorrectionConflict(
                    "This scan already has an attributed scope-handoff correction"
                )
        else:
            candidate = _candidate_on_connection(db, run_id)
            if not candidate["available"]:
                raise AutomatedNmapScopeCorrectionConflict("; ".join(candidate["reasons"]))
            observation = candidate["observation"]
            context = candidate["context"]
            intent = candidate["intent"]
            canonical = Path(observation["canonical_path"])
            expected_canonical = canonical_artifact_path(
                artifact_root_for(db_path), observation["sha256"],
            )
            if (
                canonical != expected_canonical
                or canonical.is_symlink()
                or not canonical.is_file()
                or sha256_file(canonical)
                != (observation["sha256"], observation["size_bytes"])
            ):
                raise AutomatedNmapScopeCorrectionConflict(
                    "The canonical aggregate scan.xml does not match its retained identity"
                )
            relative_path = observation["metadata"].get("relative_path")
            expected_relative = Path("scan-runs") / run_id / "scan.xml"
            if relative_path and Path(relative_path) != expected_relative:
                raise AutomatedNmapScopeCorrectionConflict(
                    "The aggregate scan.xml retained path does not match this scan run"
                )
            if (
                local.is_symlink()
                or not local.is_file()
                or sha256_file(local) != (observation["sha256"], observation["size_bytes"])
            ):
                raise AutomatedNmapScopeCorrectionConflict(
                    "The run-local aggregate scan.xml does not match its retained identity"
                )
            insert_artifact_observation_scope_context(
                db,
                observation_id=observation["observation_id"],
                run_id=run_id,
                context=context,
            )
            from app.automated_nmap_foundation import _run_evidence

            evidence = _run_evidence(db, run_id)
            corrected_contract = _automated_contract_from_evidence(evidence)
            job, assignment_id = _enqueue_automated_nmap_scope_job(
                db,
                run_id,
                request_token=token,
                requested_by=actor,
                allow_retry=False,
            )
            prior_digest = hashlib.sha256(_canonical_json(intent).encode()).hexdigest()
            correction_id = f"scan_scope_correction_{uuid.uuid4().hex}"
            requested_at = utc_now()
            db.execute(
                """INSERT INTO automated_nmap_scope_corrections (
                       correction_id, run_id, observation_id, prior_intent_id,
                       prior_intent_sha256, corrected_contract_json, actor, reason,
                       request_token, requested_at, assignment_id, job_id
                   ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    correction_id, run_id, observation["observation_id"],
                    intent["intent_id"], prior_digest,
                    _canonical_json(corrected_contract), actor, reason, token,
                    requested_at, assignment_id, job["job_id"],
                ),
            )
            result = _existing_correction(db, run_id)
    start_derived_job_worker(db_path, data_dir)
    return result
