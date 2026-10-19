"""Immutable storage contract for scoped VLAN evidence.

This module owns only the versioned schema at the first migration gate. Extraction,
publication, and read APIs are added after the schema boundary independently clears.
"""
from __future__ import annotations

from pathlib import Path
import sqlite3

from app.database import connect_database, initialize_once_per_database
from app.device_collection_authority import init_device_collection_authority_storage
from app.device_observations import init_device_observation_storage
from app.derived_results import init_derived_result_storage
from app.network_scopes import init_network_scope_storage


DEVICE_VLAN_EXTRACTOR = "device-vlan-observations:1"
DEVICE_VLAN_JOB_TYPE = "device_vlan_observations"
DEVICE_VLAN_TARGET_FAMILY = "scoped_device_vlan_observations"
DEVICE_VLAN_SCHEMA_VERSION = 1
DEVICE_VLAN_POLICY_VERSION = 1

DEVICE_VLAN_SCHEMA_OBJECTS = frozenset({
    "device_vlan_assessments",
    "device_vlan_assessments_scope",
    "device_vlan_assessments_version",
    "device_vlan_receipts",
    "device_vlan_receipts_assessment",
    "device_vlan_assessments_no_update",
    "device_vlan_assessments_no_delete",
    "device_vlan_receipts_no_update",
    "device_vlan_receipts_no_delete",
    "device_vlan_admission_intents",
    "device_vlan_admission_intents_state",
    "device_vlan_admission_intents_identity_immutable",
    "device_vlan_admission_intents_state_guard",
    "device_vlan_admission_intents_no_delete",
})


def create_device_vlan_schema(db: sqlite3.Connection) -> None:
    """Create the v6 VLAN schema on the caller's transaction."""
    statements = (
        """CREATE TABLE IF NOT EXISTS device_vlan_assessments (
            assessment_id TEXT PRIMARY KEY,
            assignment_id TEXT NOT NULL
                REFERENCES device_scope_assignments(assignment_id),
            run_id TEXT NOT NULL,
            authority_revision INTEGER NOT NULL CHECK(authority_revision >= 1),
            assignment_revision INTEGER NOT NULL CHECK(assignment_revision >= 1),
            scope_id TEXT NOT NULL REFERENCES network_scopes(scope_id),
            configuration_observation_id TEXT NOT NULL
                REFERENCES artifact_observations(observation_id),
            configuration_sha256 TEXT NOT NULL CHECK(length(configuration_sha256) = 64),
            configuration_size_bytes INTEGER NOT NULL CHECK(configuration_size_bytes >= 0),
            configuration_filename TEXT NOT NULL,
            summary_result_id TEXT NOT NULL REFERENCES derived_results(result_id),
            extractor_version TEXT NOT NULL,
            collection_contract TEXT NOT NULL,
            source_contract_json TEXT NOT NULL,
            coverage_json TEXT NOT NULL,
            recorded_at TEXT NOT NULL,
            UNIQUE(assignment_id, extractor_version, collection_contract)
        )""",
        """CREATE INDEX IF NOT EXISTS device_vlan_assessments_scope
            ON device_vlan_assessments(scope_id, recorded_at, assessment_id)""",
        """CREATE INDEX IF NOT EXISTS device_vlan_assessments_version
            ON device_vlan_assessments(
                assignment_id, extractor_version, collection_contract,
                recorded_at DESC, assessment_id DESC
            )""",
        """CREATE TABLE IF NOT EXISTS device_vlan_receipts (
            receipt_id TEXT PRIMARY KEY,
            assessment_id TEXT NOT NULL REFERENCES device_vlan_assessments(assessment_id),
            source_observation_id TEXT NOT NULL
                REFERENCES artifact_observations(observation_id),
            source_role TEXT NOT NULL CHECK(
                source_role IN ('configuration', 'raw_output', 'configuration_and_raw_output')
            ),
            source_filename TEXT NOT NULL,
            device_context TEXT NOT NULL,
            bridge_context TEXT,
            vlan_id INTEGER NOT NULL CHECK(vlan_id BETWEEN 0 AND 4095),
            vlan_name TEXT,
            interface_name TEXT,
            membership_relation TEXT NOT NULL CHECK(
                membership_relation IN (
                    'declaration', 'declared_member', 'access', 'native', 'allowed',
                    'tagged', 'untagged', 'pvid'
                )
            ),
            evidence_state TEXT NOT NULL CHECK(
                evidence_state IN ('configured', 'observed')
            ),
            source_line_number INTEGER NOT NULL CHECK(source_line_number >= 1),
            source_line TEXT NOT NULL,
            related_line_number INTEGER CHECK(related_line_number IS NULL OR related_line_number >= 1),
            related_source_line TEXT,
            source_command TEXT,
            source_section TEXT,
            source_syntax TEXT NOT NULL,
            facts_json TEXT NOT NULL,
            UNIQUE(
                assessment_id, source_observation_id, source_line_number,
                membership_relation, vlan_id, device_context,
                interface_name, bridge_context
            )
        )""",
        """CREATE INDEX IF NOT EXISTS device_vlan_receipts_assessment
            ON device_vlan_receipts(
                assessment_id, vlan_id, source_line_number, receipt_id
            )""",
        """CREATE TRIGGER IF NOT EXISTS device_vlan_assessments_no_update
            BEFORE UPDATE ON device_vlan_assessments
            BEGIN SELECT RAISE(ABORT, 'device VLAN assessments are immutable'); END""",
        """CREATE TRIGGER IF NOT EXISTS device_vlan_assessments_no_delete
            BEFORE DELETE ON device_vlan_assessments
            BEGIN SELECT RAISE(ABORT, 'device VLAN assessments are immutable'); END""",
        """CREATE TRIGGER IF NOT EXISTS device_vlan_receipts_no_update
            BEFORE UPDATE ON device_vlan_receipts
            BEGIN SELECT RAISE(ABORT, 'device VLAN receipts are immutable'); END""",
        """CREATE TRIGGER IF NOT EXISTS device_vlan_receipts_no_delete
            BEFORE DELETE ON device_vlan_receipts
            BEGIN SELECT RAISE(ABORT, 'device VLAN receipts are immutable'); END""",
        """CREATE TABLE IF NOT EXISTS device_vlan_admission_intents (
            intent_id TEXT PRIMARY KEY,
            assignment_id TEXT NOT NULL UNIQUE
                REFERENCES device_scope_assignments(assignment_id),
            policy_version INTEGER NOT NULL CHECK(policy_version >= 1),
            source_observation_id TEXT NOT NULL
                REFERENCES artifact_observations(observation_id),
            scope_id TEXT NOT NULL REFERENCES network_scopes(scope_id),
            actor TEXT NOT NULL,
            request_token TEXT NOT NULL UNIQUE,
            contract_json TEXT NOT NULL,
            state TEXT NOT NULL CHECK(state IN ('pending', 'admitted', 'blocked')),
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            admitted_job_id TEXT UNIQUE REFERENCES pipeline_jobs(job_id),
            activity_state TEXT NOT NULL CHECK(
                activity_state IN ('waiting', 'retrying', 'paused', 'complete', 'blocked')
            ),
            last_error TEXT,
            CHECK(
                (state = 'pending' AND admitted_job_id IS NULL
                    AND activity_state IN ('waiting', 'retrying', 'paused'))
                OR (state = 'admitted' AND admitted_job_id IS NOT NULL
                    AND activity_state = 'complete' AND last_error IS NULL)
                OR (state = 'blocked' AND admitted_job_id IS NULL
                    AND activity_state = 'blocked'
                    AND length(trim(last_error)) >= 1)
            )
        )""",
        """CREATE INDEX IF NOT EXISTS device_vlan_admission_intents_state
            ON device_vlan_admission_intents(state, created_at, intent_id)""",
        """CREATE TRIGGER IF NOT EXISTS device_vlan_admission_intents_identity_immutable
            BEFORE UPDATE ON device_vlan_admission_intents
            WHEN OLD.assignment_id != NEW.assignment_id
              OR OLD.policy_version != NEW.policy_version
              OR OLD.source_observation_id != NEW.source_observation_id
              OR OLD.scope_id != NEW.scope_id
              OR OLD.actor != NEW.actor
              OR OLD.request_token != NEW.request_token
              OR OLD.contract_json != NEW.contract_json
              OR OLD.created_at != NEW.created_at
              OR (OLD.admitted_job_id IS NOT NULL
                  AND IFNULL(NEW.admitted_job_id, '') != OLD.admitted_job_id)
            BEGIN SELECT RAISE(ABORT, 'device VLAN admission identity is immutable'); END""",
        """CREATE TRIGGER IF NOT EXISTS device_vlan_admission_intents_state_guard
            BEFORE UPDATE ON device_vlan_admission_intents
            WHEN OLD.state != NEW.state
             AND NOT (OLD.state = 'pending' AND NEW.state IN ('admitted', 'blocked'))
            BEGIN SELECT RAISE(ABORT, 'invalid device VLAN admission transition'); END""",
        """CREATE TRIGGER IF NOT EXISTS device_vlan_admission_intents_no_delete
            BEFORE DELETE ON device_vlan_admission_intents
            BEGIN SELECT RAISE(ABORT, 'device VLAN admission intents are retained'); END""",
    )
    for statement in statements:
        db.execute(statement)


@initialize_once_per_database
def init_device_vlan_observation_storage(db_path: Path) -> None:
    init_network_scope_storage(db_path)
    init_device_collection_authority_storage(db_path)
    init_device_observation_storage(db_path)
    init_derived_result_storage(db_path)
    from app.pipeline_intake import init_pipeline_intake_storage

    init_pipeline_intake_storage(db_path)
    with connect_database(db_path) as db:
        create_device_vlan_schema(db)


def current_device_vlan_assessment_on_connection(
    db: sqlite3.Connection, *, assignment_id: str, collection_contract: str,
) -> dict | None:
    """Return only the assessment produced by the image's supported extractor contract."""
    db.row_factory = sqlite3.Row
    row = db.execute(
        """SELECT * FROM device_vlan_assessments
           WHERE assignment_id = ? AND extractor_version = ?
             AND collection_contract = ?
           ORDER BY recorded_at DESC, assessment_id DESC LIMIT 1""",
        (assignment_id, DEVICE_VLAN_EXTRACTOR, collection_contract),
    ).fetchone()
    return dict(row) if row is not None else None


def record_device_vlan_observation_intent(
    db: sqlite3.Connection, assignment_id: str,
) -> dict:
    """Freeze a separate VLAN job request beside the interface-observation request."""
    import hashlib
    import json

    from app.device_observations import (
        _completed_summary_result,
        assignment_contract_on_connection,
    )
    from app.pipeline_intake import (
        COLLECTED_DEVICE_SOURCE,
        DEVICE_INGESTION_POLICY_VERSION,
        MANUAL_DEVICE_INTENT,
        MANUAL_DEVICE_SOURCE,
        source_policy_version,
    )

    assignment_contract = assignment_contract_on_connection(db, assignment_id)
    assignment = assignment_contract["assignment"]
    summary_result_id = _completed_summary_result(db, assignment["run_id"])
    source_kind = (
        MANUAL_DEVICE_SOURCE
        if assignment_contract["intent_kind"] == MANUAL_DEVICE_INTENT
        else COLLECTED_DEVICE_SOURCE
    )
    policy = source_policy_version(db, source_kind, assignment["run_id"])
    if policy != DEVICE_INGESTION_POLICY_VERSION:
        raise ValueError("Device VLAN intake policy version is not supported")
    configuration = next((
        item for item in assignment_contract["authority"]["authority_inputs"]
        if item["role"] in {"configuration", "configuration_and_raw_output"}
        and item["source_kind"] == "artifact_file"
    ), None)
    if configuration is None:
        raise ValueError("Device authority has no selected configuration artifact")
    job_definition = {
        "assignment_contract": assignment_contract,
        "summary_result_id": summary_result_id,
        "vlan_extractor_version": DEVICE_VLAN_EXTRACTOR,
    }
    contract = {
        "assignment_id": assignment_id,
        "run_id": assignment["run_id"],
        "authority_revision": int(assignment["authority_revision"]),
        "assignment_revision": int(assignment["revision"]),
        "scope_id": assignment["scope_id"],
        "assignment_contract": assignment_contract,
        "summary_result_id": summary_result_id,
        "collection_contract": assignment_contract["authority"]["selection_contract"],
        "source_coverage": assignment_contract["authority"]["authority_inputs"],
        "source_observation_id": configuration["observation_id"],
        "source_sha256": configuration["sha256"],
        "source_size_bytes": int(configuration["size_bytes"]),
        "source_status": "assigned",
        "source_kind": "device_configuration",
        "source_ref": assignment_id,
        "target_job_type": DEVICE_VLAN_JOB_TYPE,
        "target_family": DEVICE_VLAN_TARGET_FAMILY,
        "target_analysis_version": DEVICE_VLAN_EXTRACTOR,
        "target_payload_schema_version": DEVICE_VLAN_SCHEMA_VERSION,
        "target_parameters": {},
        "target_result_id": summary_result_id,
        "job_definition": job_definition,
    }
    contract_json = json.dumps(
        contract, sort_keys=True, separators=(",", ":"), allow_nan=False,
    )
    digest = hashlib.sha256(f"device-vlan:{assignment_id}".encode()).hexdigest()
    intent_id = f"device_vlan_intent_{digest}"
    request_token = f"auto-{intent_id}"
    values = (
        intent_id, assignment_id, DEVICE_VLAN_POLICY_VERSION,
        configuration["observation_id"], assignment["scope_id"],
        assignment["actor"], request_token, contract_json,
        assignment["assigned_at"], assignment["assigned_at"],
    )
    inserted = db.execute(
        """INSERT OR IGNORE INTO device_vlan_admission_intents(
               intent_id, assignment_id, policy_version, source_observation_id,
               scope_id, actor, request_token, contract_json, state,
               created_at, updated_at, activity_state
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, 'waiting')""",
        values,
    ).rowcount
    row = db.execute(
        """SELECT intent_id, assignment_id, policy_version, source_observation_id,
                  scope_id, actor, request_token, contract_json, state,
                  created_at, updated_at, admitted_job_id, activity_state, last_error
           FROM device_vlan_admission_intents WHERE assignment_id = ?""",
        (assignment_id,),
    ).fetchone()
    if row is None:
        raise ValueError("Device VLAN admission intent is unavailable")
    retained = tuple(row)
    expected_identity = values[:8] + values[8:10]
    retained_identity = retained[:8] + retained[9:11]
    if not inserted and retained_identity != expected_identity:
        raise ValueError("Device VLAN admission intent replay does not match")
    keys = (
        "intent_id", "assignment_id", "policy_version", "source_observation_id",
        "scope_id", "actor", "request_token", "contract_json", "state",
        "created_at", "updated_at", "admitted_job_id", "activity_state", "last_error",
    )
    result = dict(zip(keys, retained))
    result["contract"] = json.loads(result.pop("contract_json"))
    return result


def admit_device_vlan_observation_intent(
    db: sqlite3.Connection, *, assignment_id: str, job_id: str, admitted_at: str,
) -> dict:
    """Bind one durable VLAN intent to its separately keyed pipeline job."""
    if not db.in_transaction:
        db.execute("BEGIN IMMEDIATE")
    row = db.execute(
        """SELECT state, admitted_job_id, contract_json
             FROM device_vlan_admission_intents
           WHERE assignment_id = ?""",
        (assignment_id,),
    ).fetchone()
    if row is None:
        raise ValueError("Device VLAN admission intent is unavailable")
    if row[0] == "admitted":
        if row[1] != job_id:
            raise ValueError("Device VLAN admission intent already names another job")
    elif row[0] == "pending":
        import json

        from app.device_observations import (
            _completed_summary_result,
            assignment_contract_on_connection,
        )

        contract = json.loads(row[2])
        try:
            current_contract = assignment_contract_on_connection(db, assignment_id)
        except (KeyError, ValueError) as exc:
            raise ValueError("Device VLAN scope assignment is no longer current") from exc
        if current_contract != contract["assignment_contract"]:
            raise ValueError("Device VLAN assignment or authority contract changed")
        if _completed_summary_result(db, contract["run_id"]) != contract["summary_result_id"]:
            raise ValueError("Completed reusable device summary changed before VLAN admission")
        job = db.execute(
            """SELECT job_type, source_run_id, source_observation_id, source_status,
                      source_sha256, source_size_bytes, target_family,
                      target_analysis_version, target_payload_schema_version,
                      target_parameters_json, target_result_id, source_kind, source_ref,
                      definition_json
                 FROM pipeline_jobs WHERE job_id = ?""",
            (job_id,),
        ).fetchone()
        expected = (
            contract["target_job_type"], contract["run_id"],
            contract["source_observation_id"], contract["source_status"],
            contract["source_sha256"], int(contract["source_size_bytes"]),
            contract["target_family"], contract["target_analysis_version"],
            int(contract["target_payload_schema_version"]),
            json.dumps(contract["target_parameters"], sort_keys=True, separators=(",", ":")),
            contract["target_result_id"], contract["source_kind"], contract["source_ref"],
            json.dumps(contract["job_definition"], sort_keys=True, separators=(",", ":")),
        )
        if job is None or tuple(job) != expected:
            raise ValueError("Pipeline job does not match the frozen device VLAN contract")
        _before_device_vlan_admission_bind(db)
        updated = db.execute(
            """UPDATE device_vlan_admission_intents
                  SET state = 'admitted', admitted_job_id = ?, updated_at = ?,
                      activity_state = 'complete', last_error = NULL
                WHERE assignment_id = ? AND state = 'pending'""",
            (job_id, admitted_at, assignment_id),
        ).rowcount
        if updated != 1:
            raise ValueError("Device VLAN admission intent changed concurrently")
    else:
        raise ValueError("Blocked device VLAN admission cannot be admitted")
    retained = db.execute(
        """SELECT intent_id, assignment_id, state, admitted_job_id, activity_state
           FROM device_vlan_admission_intents WHERE assignment_id = ?""",
        (assignment_id,),
    ).fetchone()
    return dict(zip(
        ("intent_id", "assignment_id", "state", "admitted_job_id", "activity_state"),
        retained,
    ))


def _before_device_vlan_admission_bind(db: sqlite3.Connection) -> None:
    """Test hook for proving the write lock spans validation and durable binding."""
