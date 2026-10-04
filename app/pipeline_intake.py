"""Explicit intake markers and durable admission intents for new pipeline evidence."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sqlite3

from app.database import connect_database, initialize_once_per_database
from app.derived_contracts import (
    DEVICE_SUMMARY_FAMILY,
    DEVICE_SUMMARY_PARAMETERS,
    DEVICE_SUMMARY_SCHEMA_VERSION,
    DEVICE_SUMMARY_VERSION,
)
from app.nmap_evidence import NMAP_ENDPOINT_PARSER


NMAP_INGESTION_POLICY_VERSION = 1
NMAP_SCOPE_JOB_TYPE = "nmap_scope_assessment"
NMAP_SCOPE_TARGET_FAMILY = "scoped_nmap_assessment"
NMAP_SCOPE_PAYLOAD_SCHEMA_VERSION = 1

MANUAL_NMAP_SOURCE = "nmap_import_observation"
AUTOMATED_NMAP_SOURCE = "nmap_scan_run"
MANUAL_NMAP_INTENT = "manual_nmap_scope"
AUTOMATED_NMAP_INTENT = "automated_nmap_scope"

DEVICE_INGESTION_POLICY_VERSION = 1
DEVICE_SUMMARY_JOB_TYPE = "device_summary"
MANUAL_DEVICE_SOURCE = "device_manual_upload_authority"
COLLECTED_DEVICE_SOURCE = "device_collected_authority"
MANUAL_DEVICE_INTENT = "manual_device_summary"
COLLECTED_DEVICE_INTENT = "collected_device_summary"
DEVICE_OBSERVATION_INTENT = "device_interface_observation"

_INTENT_KINDS = (
    MANUAL_NMAP_INTENT,
    AUTOMATED_NMAP_INTENT,
    MANUAL_DEVICE_INTENT,
    COLLECTED_DEVICE_INTENT,
    DEVICE_OBSERVATION_INTENT,
)
_INTENT_COLUMNS = (
    "intent_id", "intent_kind", "source_kind", "source_id", "policy_version",
    "observation_id", "assignment_id", "scope_id", "actor", "request_token",
    "contract_json", "state", "created_at", "updated_at", "admitted_job_id",
    "resolved_assignment_id", "activity_state", "last_error",
)


def _canonical_json(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _intent_id(intent_kind: str, source_id: str) -> str:
    digest = hashlib.sha256(f"{intent_kind}:{source_id}".encode()).hexdigest()
    return f"intake_intent_{digest}"


def _create_intent_table(db: sqlite3.Connection, name: str) -> None:
    allowed = ", ".join(f"'{value}'" for value in _INTENT_KINDS)
    db.execute(
        f"""CREATE TABLE {name} (
                intent_id TEXT PRIMARY KEY,
                intent_kind TEXT NOT NULL CHECK (intent_kind IN ({allowed})),
                source_kind TEXT NOT NULL,
                source_id TEXT NOT NULL,
                policy_version INTEGER NOT NULL,
                observation_id TEXT,
                assignment_id TEXT,
                scope_id TEXT,
                actor TEXT NOT NULL,
                request_token TEXT NOT NULL UNIQUE,
                contract_json TEXT NOT NULL,
                state TEXT NOT NULL CHECK (
                    state IN ('pending', 'admitted', 'needs_scope', 'blocked')
                ),
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                admitted_job_id TEXT,
                resolved_assignment_id TEXT,
                activity_state TEXT NOT NULL CHECK (
                    activity_state IN (
                        'waiting', 'retrying', 'paused', 'complete',
                        'needs_scope', 'blocked'
                    )
                ),
                last_error TEXT,
                UNIQUE (intent_kind, source_id)
            )"""
    )


def _create_intent_guards(db: sqlite3.Connection) -> None:
    db.execute(
        """CREATE INDEX pipeline_admission_intents_state
               ON pipeline_admission_intents(state, created_at, intent_id)"""
    )
    db.execute(
        """CREATE TRIGGER pipeline_admission_intents_identity_immutable
               BEFORE UPDATE ON pipeline_admission_intents
               WHEN OLD.intent_kind != NEW.intent_kind
                 OR OLD.source_kind != NEW.source_kind
                 OR OLD.source_id != NEW.source_id
                 OR OLD.policy_version != NEW.policy_version
                 OR IFNULL(OLD.observation_id, '') != IFNULL(NEW.observation_id, '')
                 OR IFNULL(OLD.assignment_id, '') != IFNULL(NEW.assignment_id, '')
                 OR IFNULL(OLD.scope_id, '') != IFNULL(NEW.scope_id, '')
                 OR OLD.actor != NEW.actor
                 OR OLD.request_token != NEW.request_token
                 OR OLD.contract_json != NEW.contract_json
                 OR OLD.created_at != NEW.created_at
               BEGIN SELECT RAISE(ABORT, 'pipeline admission intent identity is immutable'); END"""
    )
    db.execute(
        """CREATE TRIGGER pipeline_admission_intents_state_guard
               BEFORE UPDATE ON pipeline_admission_intents
               WHEN OLD.state != NEW.state
                AND NOT (
                   OLD.state = 'pending'
                   AND NEW.state IN ('admitted', 'blocked')
                )
               BEGIN SELECT RAISE(ABORT, 'invalid pipeline admission transition'); END"""
    )
    db.execute(
        """CREATE TRIGGER pipeline_admission_intents_no_delete
               BEFORE DELETE ON pipeline_admission_intents
               BEGIN SELECT RAISE(ABORT, 'pipeline admission intents are retained'); END"""
    )


def _after_intent_migration_copy(db: sqlite3.Connection) -> None:
    """Test hook for proving that a failed table replacement rolls back."""


def _migrate_intent_table(db: sqlite3.Connection) -> None:
    table = db.execute(
        """SELECT sql FROM sqlite_master
           WHERE type = 'table' AND name = 'pipeline_admission_intents'"""
    ).fetchone()
    if table is None:
        _create_intent_table(db, "pipeline_admission_intents")
        _create_intent_guards(db)
        return
    columns = [
        row[1] for row in db.execute("PRAGMA table_info(pipeline_admission_intents)")
    ]
    current_sql = str(table[0] or "")
    if (
        set(_INTENT_COLUMNS).issubset(columns)
        and MANUAL_DEVICE_INTENT in current_sql
        and COLLECTED_DEVICE_INTENT in current_sql
        and DEVICE_OBSERVATION_INTENT in current_sql
    ):
        return
    retained_columns = [name for name in _INTENT_COLUMNS if name in columns]
    select_expressions = []
    for name in _INTENT_COLUMNS:
        if name in retained_columns:
            select_expressions.append(name)
        elif name == "activity_state":
            select_expressions.append(
                "CASE WHEN state = 'admitted' THEN 'complete' "
                "WHEN state = 'needs_scope' THEN 'needs_scope' "
                "WHEN state = 'blocked' THEN 'blocked' "
                "WHEN last_error IS NOT NULL THEN 'paused' ELSE 'waiting' END"
            )
        else:
            select_expressions.append("NULL")
    before = db.execute(
        f"SELECT {', '.join(retained_columns)} FROM pipeline_admission_intents "
        "ORDER BY intent_id"
    ).fetchall()
    _create_intent_table(db, "pipeline_admission_intents_replacement")
    db.execute(
        f"""INSERT INTO pipeline_admission_intents_replacement
               ({', '.join(_INTENT_COLUMNS)})
             SELECT {', '.join(select_expressions)}
               FROM pipeline_admission_intents"""
    )
    copied = db.execute(
        f"SELECT {', '.join(retained_columns)} "
        "FROM pipeline_admission_intents_replacement ORDER BY intent_id"
    ).fetchall()
    if copied != before:
        raise RuntimeError("Pipeline admission intents did not copy exactly")
    _after_intent_migration_copy(db)
    for name in (
        "pipeline_admission_intents_identity_immutable",
        "pipeline_admission_intents_state_guard",
        "pipeline_admission_intents_no_delete",
    ):
        db.execute(f"DROP TRIGGER IF EXISTS {name}")
    db.execute("DROP TABLE pipeline_admission_intents")
    db.execute(
        "ALTER TABLE pipeline_admission_intents_replacement "
        "RENAME TO pipeline_admission_intents"
    )
    _create_intent_guards(db)
    after = db.execute(
        f"SELECT {', '.join(retained_columns)} FROM pipeline_admission_intents "
        "ORDER BY intent_id"
    ).fetchall()
    if after != before:
        raise RuntimeError("Pipeline admission intent replacement changed retained values")


@initialize_once_per_database
def init_pipeline_intake_storage(db_path: Path) -> None:
    with connect_database(db_path) as db:
        db.execute("BEGIN IMMEDIATE")
        db.execute(
            """CREATE TABLE IF NOT EXISTS pipeline_intake_sources (
                source_kind TEXT NOT NULL,
                source_id TEXT NOT NULL,
                policy_version INTEGER NOT NULL,
                marked_by TEXT NOT NULL,
                marked_at TEXT NOT NULL,
                PRIMARY KEY (source_kind, source_id)
            )"""
        )
        db.execute(
            """CREATE TRIGGER IF NOT EXISTS pipeline_intake_sources_no_update
                BEFORE UPDATE ON pipeline_intake_sources
                BEGIN SELECT RAISE(ABORT, 'pipeline intake source markers are immutable'); END"""
        )
        db.execute(
            """CREATE TRIGGER IF NOT EXISTS pipeline_intake_sources_no_delete
                BEFORE DELETE ON pipeline_intake_sources
                BEGIN SELECT RAISE(ABORT, 'pipeline intake source markers are immutable'); END"""
        )
        _migrate_intent_table(db)


def mark_pipeline_source(
    db: sqlite3.Connection,
    *,
    source_kind: str,
    source_id: str,
    marked_by: str,
    marked_at: str,
    policy_version: int = NMAP_INGESTION_POLICY_VERSION,
) -> None:
    values = (source_kind, source_id, int(policy_version), marked_by, marked_at)
    inserted = db.execute(
        """INSERT OR IGNORE INTO pipeline_intake_sources
           (source_kind, source_id, policy_version, marked_by, marked_at)
           VALUES (?, ?, ?, ?, ?)""",
        values,
    ).rowcount
    if not inserted:
        retained = db.execute(
            """SELECT source_kind, source_id, policy_version, marked_by, marked_at
               FROM pipeline_intake_sources
               WHERE source_kind = ? AND source_id = ?""",
            (source_kind, source_id),
        ).fetchone()
        if retained is None or tuple(retained) != values:
            raise ValueError("Pipeline intake source marker replay does not match")


def source_policy_version(
    db: sqlite3.Connection, source_kind: str, source_id: str,
) -> int | None:
    table_exists = db.execute(
        """SELECT 1 FROM sqlite_master
           WHERE type = 'table' AND name = 'pipeline_intake_sources'"""
    ).fetchone()
    if table_exists is None:
        return None
    row = db.execute(
        """SELECT policy_version FROM pipeline_intake_sources
           WHERE source_kind = ? AND source_id = ?""",
        (source_kind, source_id),
    ).fetchone()
    return int(row[0]) if row is not None else None


_INTENT_IDENTITY_COLUMNS = (
    "intent_id", "intent_kind", "source_kind", "source_id", "policy_version",
    "observation_id", "assignment_id", "scope_id", "actor", "request_token",
    "contract_json", "state", "created_at", "updated_at", "admitted_job_id",
    "resolved_assignment_id", "activity_state", "last_error",
)


def _intent_dict(row) -> dict | None:
    if row is None:
        return None
    item = dict(zip(_INTENT_IDENTITY_COLUMNS, row))
    item["contract"] = json.loads(item.pop("contract_json") or "{}")
    item["policy_version"] = int(item["policy_version"])
    return item


def _insert_intent(
    db: sqlite3.Connection,
    *,
    intent_kind: str,
    source_kind: str,
    source_id: str,
    policy_version: int,
    observation_id: str | None,
    assignment_id: str | None,
    scope_id: str | None,
    actor: str,
    contract: dict,
    state: str,
    created_at: str,
    last_error: str | None = None,
) -> dict:
    intent_id = _intent_id(intent_kind, source_id)
    request_token = f"auto-{intent_id}"
    contract_json = _canonical_json(contract)
    activity_state = {
        "pending": "waiting",
        "admitted": "complete",
        "needs_scope": "needs_scope",
        "blocked": "blocked",
    }[state]
    values = (
        intent_id, intent_kind, source_kind, source_id, int(policy_version),
        observation_id, assignment_id, scope_id, actor, request_token,
        contract_json, state, created_at, created_at, activity_state, last_error,
    )
    inserted = db.execute(
        """INSERT OR IGNORE INTO pipeline_admission_intents (
               intent_id, intent_kind, source_kind, source_id, policy_version,
               observation_id, assignment_id, scope_id, actor, request_token,
               contract_json, state, created_at, updated_at, activity_state,
               last_error
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        values,
    ).rowcount
    if not inserted:
        retained = db.execute(
            """SELECT intent_id, intent_kind, source_kind, source_id, policy_version,
                      observation_id, assignment_id, scope_id, actor, request_token,
                      contract_json, state, created_at, updated_at, admitted_job_id,
                      resolved_assignment_id, activity_state, last_error
               FROM pipeline_admission_intents WHERE intent_id = ?""",
            (intent_id,),
        ).fetchone()
        if retained is None:
            raise ValueError("Pipeline admission intent replay is unavailable")
        identity = tuple(retained[:11]) + (retained[12],)
        expected = values[:11] + (values[12],)
        if identity != expected:
            raise ValueError("Pipeline admission intent replay does not match")
    row = db.execute(
        """SELECT intent_id, intent_kind, source_kind, source_id, policy_version,
                  observation_id, assignment_id, scope_id, actor, request_token,
                  contract_json, state, created_at, updated_at, admitted_job_id,
                  resolved_assignment_id, activity_state, last_error
           FROM pipeline_admission_intents WHERE intent_id = ?""",
        (intent_id,),
    ).fetchone()
    return _intent_dict(row)


def record_manual_nmap_intent(
    db: sqlite3.Connection, assignment_id: str,
) -> dict | None:
    row = db.execute(
        """SELECT assignment.assignment_id, assignment.artifact_observation_id,
                  assignment.scope_id, assignment.revision, assignment.event_kind,
                  assignment.assignment_mode, assignment.actor, assignment.assigned_at,
                  observation.sha256, observation.source_kind, observation.source_ref,
                  artifact.size_bytes, scope.active
           FROM artifact_scope_assignments assignment
           JOIN artifact_observations observation
             ON observation.observation_id = assignment.artifact_observation_id
           JOIN artifact_registry artifact ON artifact.sha256 = observation.sha256
           JOIN network_scopes scope ON scope.scope_id = assignment.scope_id
           WHERE assignment.assignment_id = ?""",
        (assignment_id,),
    ).fetchone()
    if row is None or row[9] != "nmap_import":
        raise ValueError("Manual Nmap admission requires an upload assignment")
    policy = source_policy_version(db, MANUAL_NMAP_SOURCE, row[1])
    if policy is None:
        return None
    if not bool(row[12]):
        raise ValueError("The assigned Network Scope is archived")
    contract = {
        "intent_kind": MANUAL_NMAP_INTENT,
        "source_kind": row[9],
        "source_ref": row[10],
        "observation_id": row[1],
        "source_sha256": row[8],
        "source_size_bytes": int(row[11]),
        "assignment_id": row[0],
        "scope_id": row[2],
        "assignment_revision": int(row[3]),
        "assignment_event_kind": row[4],
        "assignment_mode": row[5],
        "target_family": NMAP_SCOPE_TARGET_FAMILY,
        "target_analysis_version": NMAP_ENDPOINT_PARSER,
        "target_payload_schema_version": NMAP_SCOPE_PAYLOAD_SCHEMA_VERSION,
        "target_parameters": {},
    }
    return _insert_intent(
        db,
        intent_kind=MANUAL_NMAP_INTENT,
        source_kind=MANUAL_NMAP_SOURCE,
        source_id=row[0],
        policy_version=policy,
        observation_id=row[1],
        assignment_id=row[0],
        scope_id=row[2],
        actor=row[6],
        contract=contract,
        state="pending",
        created_at=row[7],
    )


def record_automated_nmap_intent(
    db: sqlite3.Connection, run_id: str,
) -> dict | None:
    policy = source_policy_version(db, AUTOMATED_NMAP_SOURCE, run_id)
    if policy is None:
        return None
    run = db.execute(
        "SELECT status, manifest_json FROM scan_runs WHERE run_id = ?", (run_id,)
    ).fetchone()
    if run is None:
        raise ValueError("Marked scan run is unavailable")
    if run[0] != "completed":
        return None
    try:
        manifest = json.loads(run[1])
    except (TypeError, json.JSONDecodeError) as exc:
        raise ValueError("The retained scan record is unreadable") from exc
    observations = db.execute(
        """SELECT observation.observation_id, observation.sha256,
                  artifact.size_bytes, artifact_context.scope_id,
                  artifact_context.scope_label, artifact_context.scope_version,
                  artifact_context.recorded_at, scope.active,
                  run_context.scope_id,
                  (SELECT COUNT(*) FROM scan_run_scope_sources source
                   WHERE source.run_id = ?) AS source_count
           FROM artifact_observations observation
           JOIN artifact_registry artifact ON artifact.sha256 = observation.sha256
           LEFT JOIN artifact_observation_scope_contexts artifact_context
             ON artifact_context.observation_id = observation.observation_id
            AND artifact_context.run_id = ?
           LEFT JOIN scan_run_scope_contexts run_context
             ON run_context.run_id = ?
            AND run_context.scope_id = artifact_context.scope_id
            AND run_context.scope_label = artifact_context.scope_label
            AND run_context.scope_version = artifact_context.scope_version
            AND run_context.recorded_at = artifact_context.recorded_at
           LEFT JOIN network_scopes scope ON scope.scope_id = artifact_context.scope_id
           WHERE observation.source_kind = 'nmap_scan'
             AND observation.source_ref = ?
             AND observation.original_filename = 'scan.xml'""",
        (run_id, run_id, run_id, run_id),
    ).fetchall()
    reasons: list[str] = []
    state = "pending"
    manual_targets = manifest.get("manual_targets") or (
        manifest.get("target_selection") or {}
    ).get("manual_targets")
    if manual_targets:
        state = "needs_scope"
        reasons.append("Scans containing manual targets remain explicitly unscoped")
    if len(observations) != 1:
        state = "blocked"
        reasons.append("One registered aggregate scan.xml is required")
    observation = observations[0] if len(observations) == 1 else None
    if observation is not None and state == "pending":
        if not observation[3] or not observation[8] or int(observation[9] or 0) < 1:
            state = "needs_scope"
            reasons.append("A retained authoritative Network Scope is required")
        elif not bool(observation[7]):
            state = "blocked"
            reasons.append("The retained Network Scope is archived")
    actor = str(
        manifest.get("executed_by") or manifest.get("owner")
        or manifest.get("created_by") or manifest.get("operator") or "system"
    )
    completed_at = str(manifest.get("completed_at") or manifest.get("created_at"))
    contract = {
        "intent_kind": AUTOMATED_NMAP_INTENT,
        "source_kind": "nmap_scan",
        "run_id": run_id,
        "source_status": run[0],
        "observation_id": observation[0] if observation else None,
        "source_sha256": observation[1] if observation else None,
        "source_size_bytes": int(observation[2]) if observation else None,
        "scope_id": observation[3] if observation else None,
        "scope_label": observation[4] if observation else None,
        "scope_version": int(observation[5]) if observation and observation[5] is not None else None,
        "scope_recorded_at": observation[6] if observation else None,
        "target_family": NMAP_SCOPE_TARGET_FAMILY,
        "target_analysis_version": NMAP_ENDPOINT_PARSER,
        "target_payload_schema_version": NMAP_SCOPE_PAYLOAD_SCHEMA_VERSION,
        "target_parameters": {},
        "eligibility_reasons": reasons,
    }
    return _insert_intent(
        db,
        intent_kind=AUTOMATED_NMAP_INTENT,
        source_kind=AUTOMATED_NMAP_SOURCE,
        source_id=run_id,
        policy_version=policy,
        observation_id=observation[0] if observation else None,
        assignment_id=None,
        scope_id=observation[3] if observation else None,
        actor=actor,
        contract=contract,
        state=state,
        created_at=completed_at,
        last_error="; ".join(reasons) if reasons else None,
    )


def _device_authority_contract(
    db: sqlite3.Connection, run_id: str, *, intent_kind: str,
) -> tuple[dict, tuple]:
    authority = db.execute(
        """SELECT authority.run_id, authority.state, authority.revision,
                  authority.artifact_observation_id, authority.artifact_sha256,
                  authority.retained_filename, authority.selection_contract,
                  authority.semantic_manifest_sha256, authority.activated_at,
                  observation.source_kind, observation.source_ref,
                  observation.actor, observation.observed_at, artifact.size_bytes
           FROM device_collection_authority authority
           JOIN artifact_observations observation
             ON observation.observation_id = authority.artifact_observation_id
           JOIN artifact_registry artifact ON artifact.sha256 = authority.artifact_sha256
           WHERE authority.run_id = ?""",
        (run_id,),
    ).fetchone()
    if authority is None or authority[1] != "active":
        raise ValueError("Device summary admission requires active evidence authority")
    expected = {
        MANUAL_DEVICE_INTENT: (
            MANUAL_DEVICE_SOURCE, "device_config_upload", "manual-upload-single-file:1",
        ),
        COLLECTED_DEVICE_INTENT: (
            COLLECTED_DEVICE_SOURCE, "device_collection", "collected-device-multi-file:1",
        ),
    }.get(intent_kind)
    if expected is None:
        raise ValueError("Device summary intent type is unsupported")
    source_kind, observation_kind, selection_contract = expected
    if (
        authority[6] != selection_contract
        or authority[9] != observation_kind
        or authority[10] != run_id
    ):
        raise ValueError("Device evidence authority does not match its intake type")
    rows = db.execute(
        """SELECT input_role, position, source_kind, identity, filename,
                  artifact_observation_id, artifact_sha256, size_bytes, metadata_json
           FROM device_collection_authority_inputs
           WHERE run_id = ? ORDER BY input_role, position""",
        (run_id,),
    ).fetchall()
    authority_inputs = [
        {
            "role": row[0], "position": int(row[1]), "source_kind": row[2],
            "identity": row[3], "filename": row[4], "observation_id": row[5],
            "sha256": row[6], "size_bytes": row[7],
            "metadata": json.loads(row[8]),
        }
        for row in rows
    ]
    if intent_kind == MANUAL_DEVICE_INTENT:
        if authority_inputs:
            raise ValueError("Manual device authority contains unexpected frozen inputs")
        authority_inputs = [{
            "role": "configuration_and_raw_output",
            "position": 0,
            "source_kind": "artifact_file",
            "identity": authority[4],
            "filename": authority[5],
            "observation_id": authority[3],
            "sha256": authority[4],
            "size_bytes": int(authority[13]),
            "metadata": {"selection_rule": selection_contract},
        }]
    contract = {
        "intent_kind": intent_kind,
        "run_id": run_id,
        "authority_revision": int(authority[2]),
        "selection_contract": selection_contract,
        "semantic_manifest_sha256": authority[7],
        "authority_inputs": authority_inputs,
        "source_observation_id": authority[3],
        "source_sha256": authority[4],
        "source_size_bytes": int(authority[13]),
        "target_family": DEVICE_SUMMARY_FAMILY,
        "target_analysis_version": DEVICE_SUMMARY_VERSION,
        "target_payload_schema_version": DEVICE_SUMMARY_SCHEMA_VERSION,
        "target_parameters": dict(DEVICE_SUMMARY_PARAMETERS),
    }
    return contract, (
        source_kind, authority[3], str(authority[11] or "local-operator"),
        str(authority[8] or authority[12]),
    )


def record_device_summary_intent(
    db: sqlite3.Connection, run_id: str, *, intent_kind: str,
) -> dict | None:
    contract, context = _device_authority_contract(
        db, run_id, intent_kind=intent_kind,
    )
    source_kind, observation_id, actor, activated_at = context
    policy = source_policy_version(db, source_kind, run_id)
    if policy is None:
        return None
    if policy != DEVICE_INGESTION_POLICY_VERSION:
        raise ValueError("Device intake policy version is not supported")
    return _insert_intent(
        db,
        intent_kind=intent_kind,
        source_kind=source_kind,
        source_id=run_id,
        policy_version=policy,
        observation_id=observation_id,
        assignment_id=None,
        scope_id=None,
        actor=actor,
        contract=contract,
        state="pending",
        created_at=activated_at,
    )


def record_device_observation_intent(
    db: sqlite3.Connection, assignment_id: str,
) -> dict | None:
    """Freeze one explicit device-scope decision for durable normalization."""
    from app.device_observations import assignment_contract_on_connection

    contract = assignment_contract_on_connection(db, assignment_id)
    assignment = contract["assignment"]
    source_kind = (
        MANUAL_DEVICE_SOURCE
        if contract["intent_kind"] == MANUAL_DEVICE_INTENT
        else COLLECTED_DEVICE_SOURCE
    )
    policy = source_policy_version(db, source_kind, assignment["run_id"])
    if policy is None:
        return None
    if policy != DEVICE_INGESTION_POLICY_VERSION:
        raise ValueError("Device intake policy version is not supported")
    configuration = next(
        (
            item for item in contract["authority"]["authority_inputs"]
            if item["role"] in {"configuration", "configuration_and_raw_output"}
            and item["source_kind"] == "artifact_file"
        ),
        None,
    )
    if configuration is None:
        raise ValueError("Device authority has no selected configuration artifact")
    return _insert_intent(
        db,
        intent_kind=DEVICE_OBSERVATION_INTENT,
        source_kind=source_kind,
        source_id=assignment_id,
        policy_version=policy,
        observation_id=configuration["observation_id"],
        assignment_id=assignment_id,
        scope_id=assignment["scope_id"],
        actor=assignment["actor"],
        contract=contract,
        state="pending",
        created_at=assignment["assigned_at"],
    )


def admission_intent_on_connection(
    db: sqlite3.Connection, *, intent_kind: str, source_id: str,
) -> dict | None:
    available = db.execute(
        """SELECT 1 FROM sqlite_master
           WHERE type = 'table' AND name = 'pipeline_admission_intents'"""
    ).fetchone()
    if available is None:
        return None
    row = db.execute(
        """SELECT intent_id, intent_kind, source_kind, source_id, policy_version,
                  observation_id, assignment_id, scope_id, actor, request_token,
                  contract_json, state, created_at, updated_at, admitted_job_id,
                  resolved_assignment_id, activity_state, last_error
           FROM pipeline_admission_intents
           WHERE intent_kind = ? AND source_id = ?""",
        (intent_kind, source_id),
    ).fetchone()
    return _intent_dict(row)


def get_admission_intent(
    db_path: Path, *, intent_kind: str, source_id: str,
) -> dict | None:
    if not Path(db_path).is_file():
        return None
    with connect_database(db_path, read_only=True) as db:
        return admission_intent_on_connection(
            db, intent_kind=intent_kind, source_id=source_id,
        )
