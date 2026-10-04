"""Durable, operator-requested jobs for verified saved calculations."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import sqlite3
import threading
import uuid

from app.artifacts import get_artifact_observation, sha256_file, utc_now
from app.assigned_nmap_ingestion import ingest_assigned_nmap_observation
from app.database import connect_database, initialize_once_per_database
from app.derived_contracts import (
    NMAP_BASE_ANALYSIS_FAMILY,
    NMAP_BASE_ANALYSIS_VERSION,
    NMAP_BASE_PARAMETERS,
    NMAP_BASE_PAYLOAD_SCHEMA_VERSION,
)
from app.derived_results import derived_result_identity, init_derived_result_storage
from app.nmap_base_analysis import (
    NMAP_ANALYSIS_TERMINAL_STATES,
    _parse_nmap_xml,
    _scan_authority_guard,
    _scan_xml_rows,
    _verify_run_local_artifact,
    analyze_registered_nmap_result,
)
from app.nmap_evidence import NMAP_ENDPOINT_PARSER
from app.pipeline_intake import (
    AUTOMATED_NMAP_INTENT,
    MANUAL_NMAP_INTENT,
    NMAP_INGESTION_POLICY_VERSION,
    NMAP_SCOPE_JOB_TYPE,
    NMAP_SCOPE_PAYLOAD_SCHEMA_VERSION,
    NMAP_SCOPE_TARGET_FAMILY,
    init_pipeline_intake_storage,
)


JOB_TYPE = "nmap_base_analysis"
_ACTIVE_STATES = {"queued", "running"}
_RUN_ID = re.compile(r"^[0-9a-f]{32}$")
_INTAKE_RETRY_DELAYS = (0.25, 1.0, 5.0)
_WORKERS: dict[Path, tuple[threading.Event, threading.Thread]] = {}
_WORKERS_LOCK = threading.RLock()


class DerivedJobConflict(ValueError):
    """The request conflicts with retained job identity or state."""


def _canonical_json(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _job_key(payload: dict) -> str:
    return hashlib.sha256(_canonical_json(payload).encode()).hexdigest()


def _request_token(value: str) -> str:
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise ValueError("A request token is required")
    if len(value) > 200:
        raise ValueError("Request token is too long")
    return value


def _run_local_path(data_dir: Path, run_id: str) -> Path:
    if not _RUN_ID.fullmatch(run_id):
        raise ValueError("Invalid scan run identifier")
    data_root = Path(data_dir).resolve()
    scan_root = data_root / "scan-runs"
    run_root = scan_root / run_id
    candidate = run_root / "scan.xml"
    if scan_root.is_symlink() or run_root.is_symlink() or candidate.is_symlink():
        raise ValueError("Run-local Nmap evidence cannot use symbolic links")
    if run_root.parent != scan_root or candidate.parent != run_root:
        raise ValueError("Run-local Nmap evidence is outside the scan storage area")
    return candidate


def _validate_supplied_run_path(path: Path, run_id: str) -> Path:
    candidate = Path(path)
    if (
        candidate.name != "scan.xml"
        or candidate.parent.name != run_id
        or candidate.is_symlink()
        or candidate.parent.is_symlink()
    ):
        raise ValueError("Run-local Nmap evidence has an unsafe path")
    return candidate


@initialize_once_per_database
def init_derived_job_storage(db_path: Path) -> None:
    init_pipeline_intake_storage(db_path)
    init_derived_result_storage(db_path)
    with connect_database(db_path) as db:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS pipeline_jobs (
                job_id TEXT PRIMARY KEY,
                job_key TEXT NOT NULL UNIQUE,
                job_type TEXT NOT NULL,
                source_run_id TEXT,
                source_observation_id TEXT NOT NULL,
                source_status TEXT NOT NULL,
                source_sha256 TEXT NOT NULL,
                source_size_bytes INTEGER NOT NULL CHECK(source_size_bytes >= 0),
                target_family TEXT,
                target_analysis_version TEXT,
                target_payload_schema_version INTEGER,
                target_parameters_json TEXT,
                target_computation_key TEXT,
                target_result_id TEXT,
                source_kind TEXT NOT NULL DEFAULT 'scan_run',
                source_ref TEXT,
                definition_json TEXT NOT NULL DEFAULT '{}',
                requested_by TEXT NOT NULL,
                requested_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS pipeline_job_requests (
                request_token TEXT PRIMARY KEY,
                job_id TEXT NOT NULL REFERENCES pipeline_jobs(job_id) ON DELETE RESTRICT,
                request_kind TEXT NOT NULL CHECK(request_kind IN ('initial', 'retry')),
                requested_by TEXT NOT NULL,
                requested_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS pipeline_job_attempts (
                attempt_id TEXT PRIMARY KEY,
                job_id TEXT NOT NULL REFERENCES pipeline_jobs(job_id) ON DELETE RESTRICT,
                attempt_number INTEGER NOT NULL CHECK(attempt_number >= 1),
                state TEXT NOT NULL CHECK(state IN (
                    'queued', 'running', 'completed', 'failed', 'interrupted'
                )),
                claim_token TEXT,
                requested_by TEXT NOT NULL,
                requested_at TEXT NOT NULL,
                started_at TEXT,
                finished_at TEXT,
                outcome TEXT CHECK(outcome IS NULL OR outcome IN ('created', 'reused')),
                result_id TEXT,
                output_kind TEXT,
                output_id TEXT,
                error TEXT,
                UNIQUE(job_id, attempt_number)
            );
            CREATE UNIQUE INDEX IF NOT EXISTS pipeline_job_one_active_attempt
                ON pipeline_job_attempts(job_id)
                WHERE state IN ('queued', 'running');
            CREATE INDEX IF NOT EXISTS pipeline_job_attempt_queue
                ON pipeline_job_attempts(state, requested_at, attempt_id);
            CREATE INDEX IF NOT EXISTS pipeline_job_run_lookup
                ON pipeline_jobs(source_run_id, requested_at DESC);
            CREATE INDEX IF NOT EXISTS pipeline_job_source_lookup
                ON pipeline_jobs(source_kind, source_ref, requested_at DESC);
            CREATE TABLE IF NOT EXISTS pipeline_job_migrations (
                migration_id TEXT PRIMARY KEY,
                legacy_jobs_count INTEGER NOT NULL,
                legacy_requests_count INTEGER NOT NULL,
                legacy_attempts_count INTEGER NOT NULL,
                legacy_jobs_digest TEXT NOT NULL,
                legacy_requests_digest TEXT NOT NULL,
                legacy_attempts_digest TEXT NOT NULL,
                completed_at TEXT NOT NULL
            );
            """
        )
        db.execute("BEGIN IMMEDIATE")
        _migrate_legacy_derived_jobs(db)


_LEGACY_MIGRATION_ID = "derived-analysis-jobs-to-pipeline-v1"
_LEGACY_TABLES = {
    "jobs": (
        "derived_analysis_jobs",
        ("job_id", "job_key", "job_type", "source_run_id",
         "source_observation_id", "source_status", "source_sha256",
         "source_size_bytes", "target_family", "target_analysis_version",
         "target_payload_schema_version", "target_parameters_json",
         "target_computation_key", "target_result_id", "requested_by",
         "requested_at"),
        "job_id",
    ),
    "requests": (
        "derived_analysis_job_requests",
        ("request_token", "job_id", "request_kind", "requested_by",
         "requested_at"),
        "request_token",
    ),
    "attempts": (
        "derived_analysis_job_attempts",
        ("attempt_id", "job_id", "attempt_number", "state",
         "claim_token", "requested_by", "requested_at", "started_at",
         "finished_at", "outcome", "result_id", "error"),
        "attempt_id",
    ),
}


def _table_exists(db: sqlite3.Connection, name: str) -> bool:
    return db.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (name,)
    ).fetchone() is not None


def _projected_rows(
    db: sqlite3.Connection, table: str, columns: tuple[str, ...], order: str,
) -> list[tuple]:
    if not _table_exists(db, table):
        return []
    available = {row[1] for row in db.execute(f"PRAGMA table_info({table})")}
    if not set(columns).issubset(available):
        raise RuntimeError(f"Legacy queue table {table} has an unexpected schema")
    selected = ", ".join(columns)
    return db.execute(f"SELECT {selected} FROM {table} ORDER BY {order}").fetchall()


def _rows_digest(rows: list[tuple]) -> str:
    digest = hashlib.sha256()
    for row in rows:
        digest.update(_canonical_json(list(row)).encode())
        digest.update(b"\n")
    return digest.hexdigest()


def _legacy_snapshot(db: sqlite3.Connection) -> dict[str, tuple[list[tuple], str]]:
    present = {
        label: _table_exists(db, table)
        for label, (table, _columns, _order) in _LEGACY_TABLES.items()
    }
    if any(present.values()) and not all(present.values()):
        missing = ", ".join(label for label, available in present.items() if not available)
        raise RuntimeError(
            f"Legacy saved-analysis queue has an incomplete schema; missing {missing}"
        )
    snapshot = {}
    for label, (table, columns, order) in _LEGACY_TABLES.items():
        rows = _projected_rows(db, table, columns, order)
        snapshot[label] = (rows, _rows_digest(rows))
    return snapshot


def _validate_legacy_job_histories(
    jobs: list[tuple], requests: list[tuple], attempts: list[tuple],
) -> None:
    requests_by_job: dict[str, list[tuple]] = {}
    attempts_by_job: dict[str, list[tuple]] = {}
    for row in requests:
        requests_by_job.setdefault(row[1], []).append(row)
    for row in attempts:
        attempts_by_job.setdefault(row[1], []).append(row)
    for job in jobs:
        job_id = job[0]
        job_requests = requests_by_job.get(job_id, [])
        job_attempts = sorted(attempts_by_job.get(job_id, []), key=lambda row: row[2])
        initial = [row for row in job_requests if row[2] == "initial"]
        retries = [row for row in job_requests if row[2] == "retry"]
        if not initial:
            raise RuntimeError(f"Legacy saved-analysis job {job_id} has no initial request")
        if not job_attempts:
            raise RuntimeError(f"Legacy saved-analysis job {job_id} has no execution attempt")
        numbers = [int(row[2]) for row in job_attempts]
        if numbers != list(range(1, len(job_attempts) + 1)):
            raise RuntimeError(
                f"Legacy saved-analysis job {job_id} has an incomplete attempt sequence"
            )
        first = job_attempts[0]
        if not any(row[3] == first[5] and row[4] == first[6] for row in initial):
            raise RuntimeError(
                f"Legacy saved-analysis job {job_id} initial request does not match its first attempt"
            )
        retry_events = sorted((row[3], row[4]) for row in retries)
        attempt_events = sorted((row[5], row[6]) for row in job_attempts[1:])
        if retry_events != attempt_events:
            raise RuntimeError(
                f"Legacy saved-analysis job {job_id} retry history does not match its attempts"
            )


_LEGACY_FREEZE_TRIGGER_PREFIX = "pipeline_freeze_legacy_queue"


def _legacy_freeze_triggers() -> list[tuple[str, str, str]]:
    return [
        (f"{_LEGACY_FREEZE_TRIGGER_PREFIX}_{label}_{action.lower()}", table, action)
        for label, (table, _columns, _order) in _LEGACY_TABLES.items()
        for action in ("INSERT", "UPDATE", "DELETE")
    ]


def _freeze_legacy_archive(db: sqlite3.Connection) -> None:
    if not all(_table_exists(db, item[0]) for item in _LEGACY_TABLES.values()):
        return
    for name, table, action in _legacy_freeze_triggers():
        db.execute(
            f"""CREATE TRIGGER {name}
                BEFORE {action} ON {table}
                BEGIN
                    SELECT RAISE(ABORT,
                        'legacy saved-analysis queue is frozen after pipeline migration');
                END"""
        )


def _validate_legacy_freeze(db: sqlite3.Connection) -> None:
    legacy_present = all(_table_exists(db, item[0]) for item in _LEGACY_TABLES.values())
    expected = {item[0] for item in _legacy_freeze_triggers()} if legacy_present else set()
    retained = {
        row[0] for row in db.execute(
            "SELECT name FROM sqlite_master WHERE type = 'trigger' AND name LIKE ?",
            (f"{_LEGACY_FREEZE_TRIGGER_PREFIX}%",),
        )
    }
    if retained != expected:
        raise RuntimeError("Legacy saved-analysis queue freeze triggers are incomplete")


def _validate_frozen_legacy_archive(db: sqlite3.Connection, marker: tuple) -> None:
    snapshot = _legacy_snapshot(db)
    expected_counts = marker[:3]
    expected_digests = marker[3:]
    labels = ("jobs", "requests", "attempts")
    actual_counts = tuple(len(snapshot[label][0]) for label in labels)
    actual_digests = tuple(snapshot[label][1] for label in labels)
    if actual_counts != expected_counts or actual_digests != expected_digests:
        raise RuntimeError(
            "The frozen legacy saved-analysis queue changed after pipeline migration"
        )
    _validate_legacy_freeze(db)


def _migrate_legacy_derived_jobs(db: sqlite3.Connection) -> None:
    marker = db.execute(
        """SELECT legacy_jobs_count, legacy_requests_count, legacy_attempts_count,
                  legacy_jobs_digest, legacy_requests_digest, legacy_attempts_digest
           FROM pipeline_job_migrations WHERE migration_id = ?""",
        (_LEGACY_MIGRATION_ID,),
    ).fetchone()
    if marker is not None:
        _validate_frozen_legacy_archive(db, marker)
        return

    for table in ("pipeline_job_requests", "pipeline_job_attempts", "pipeline_jobs"):
        if db.execute(f"SELECT 1 FROM {table} LIMIT 1").fetchone() is not None:
            raise RuntimeError(
                "Pipeline job storage contains data without a completed migration marker"
            )

    snapshot = _legacy_snapshot(db)
    jobs = snapshot["jobs"][0]
    requests = snapshot["requests"][0]
    attempts = snapshot["attempts"][0]
    job_ids = {row[0] for row in jobs}
    if any(row[1] not in job_ids for row in requests):
        raise RuntimeError("Legacy saved-analysis requests contain a missing job relationship")
    if any(row[1] not in job_ids for row in attempts):
        raise RuntimeError("Legacy saved-analysis attempts contain a missing job relationship")
    _validate_legacy_job_histories(jobs, requests, attempts)

    if jobs:
        db.executemany(
            """INSERT INTO pipeline_jobs (
                   job_id, job_key, job_type, source_run_id, source_observation_id,
                   source_status, source_sha256, source_size_bytes, target_family,
                   target_analysis_version, target_payload_schema_version,
                   target_parameters_json, target_computation_key, target_result_id,
                   source_kind, source_ref, definition_json, requested_by, requested_at
               ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                         'scan_run', ?, '{}', ?, ?)""",
            [row[:14] + (row[3],) + row[14:] for row in jobs],
        )
    if requests:
        db.executemany(
            """INSERT INTO pipeline_job_requests
                   (request_token, job_id, request_kind, requested_by, requested_at)
               VALUES (?, ?, ?, ?, ?)""",
            requests,
        )
    if attempts:
        db.executemany(
            """INSERT INTO pipeline_job_attempts (
                   attempt_id, job_id, attempt_number, state, claim_token,
                   requested_by, requested_at, started_at, finished_at,
                   outcome, result_id, error, output_kind, output_id
               ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            [row + (("derived_result" if row[10] else None), row[10]) for row in attempts],
        )

    projections = {
        "jobs": ("pipeline_jobs", _LEGACY_TABLES["jobs"][1], "job_id"),
        "requests": ("pipeline_job_requests", _LEGACY_TABLES["requests"][1], "request_token"),
        "attempts": ("pipeline_job_attempts", _LEGACY_TABLES["attempts"][1], "attempt_id"),
    }
    for label, (table, columns, order) in projections.items():
        copied = _projected_rows(db, table, columns, order)
        if copied != snapshot[label][0]:
            raise RuntimeError(f"Legacy saved-analysis {label} did not copy exactly")

    _freeze_legacy_archive(db)
    _validate_legacy_freeze(db)
    db.execute(
        """INSERT INTO pipeline_job_migrations VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            _LEGACY_MIGRATION_ID, len(jobs), len(requests), len(attempts),
            snapshot["jobs"][1], snapshot["requests"][1],
            snapshot["attempts"][1], utc_now(),
        ),
    )


def _source_snapshot(db: sqlite3.Connection, run_id: str) -> dict:
    row = db.execute("SELECT status FROM scan_runs WHERE run_id = ?", (run_id,)).fetchone()
    if row is None:
        raise KeyError("Scan run not found")
    status = str(row[0] or "")
    if status not in NMAP_ANALYSIS_TERMINAL_STATES:
        raise DerivedJobConflict("Only a finalized scan can prepare saved analysis")
    rows = _scan_xml_rows(db, run_id)
    if len(rows) != 1:
        raise DerivedJobConflict(
            "The scan must have one authoritative registered scan.xml before analysis can be prepared"
        )
    observation_id, digest, size_bytes = rows[0]
    parameters = dict(NMAP_BASE_PARAMETERS)
    identity = derived_result_identity(
        family=NMAP_BASE_ANALYSIS_FAMILY,
        analysis_version=NMAP_BASE_ANALYSIS_VERSION,
        payload_schema_version=NMAP_BASE_PAYLOAD_SCHEMA_VERSION,
        parameters=parameters,
        inputs=[{
            "role": "nmap_xml", "kind": "artifact_sha256", "identity": digest,
            "metadata": {"media_family": "nmap_xml"},
        }],
    )
    frozen = {
        "job_type": JOB_TYPE,
        "source_run_id": run_id,
        "source_observation_id": observation_id,
        "source_status": status,
        "source_sha256": digest,
        "source_size_bytes": int(size_bytes),
        "target_family": NMAP_BASE_ANALYSIS_FAMILY,
        "target_analysis_version": NMAP_BASE_ANALYSIS_VERSION,
        "target_payload_schema_version": NMAP_BASE_PAYLOAD_SCHEMA_VERSION,
        "target_parameters_json": _canonical_json(parameters),
        "target_computation_key": identity.computation_key,
        "target_result_id": identity.result_id,
    }
    frozen["job_key"] = _job_key(frozen)
    return frozen


def _attempt_dict(row) -> dict | None:
    if row is None:
        return None
    keys = (
        "attempt_id", "attempt_number", "state", "requested_by", "requested_at",
        "started_at", "finished_at", "outcome", "result_id", "output_kind",
        "output_id", "error",
    )
    return dict(zip(keys, row))


def _job_dict(db: sqlite3.Connection, row) -> dict:
    latest = db.execute(
        """SELECT attempt_id, attempt_number, state, requested_by, requested_at,
                  started_at, finished_at, outcome, result_id, output_kind,
                  output_id, error
           FROM pipeline_job_attempts WHERE job_id = ?
           ORDER BY attempt_number DESC LIMIT 1""",
        (row[0],),
    ).fetchone()
    attempts = db.execute(
        "SELECT COUNT(*) FROM pipeline_job_attempts WHERE job_id = ?", (row[0],)
    ).fetchone()[0]
    return {
        "job_id": row[0], "job_type": row[1], "source_run_id": row[2],
        "source_observation_id": row[3], "source_status": row[4],
        "source_sha256": row[5], "source_size_bytes": row[6],
        "target_family": row[7], "target_analysis_version": row[8],
        "target_payload_schema_version": row[9], "target_result_id": row[10],
        "requested_by": row[11], "requested_at": row[12],
        "source_kind": row[13], "source_ref": row[14],
        "definition": json.loads(row[15] or "{}"),
        "attempt_count": attempts, "latest_attempt": _attempt_dict(latest),
    }


_JOB_COLUMNS = """job_id, job_type, source_run_id, source_observation_id,
 source_status, source_sha256, source_size_bytes, target_family,
 target_analysis_version, target_payload_schema_version, target_result_id,
 requested_by, requested_at, source_kind, source_ref, definition_json"""


def enqueue_nmap_base_job(
    db_path: Path, run_id: str, *, request_token: str, requested_by: str,
) -> dict:
    init_derived_job_storage(db_path)
    if not isinstance(run_id, str) or not _RUN_ID.fullmatch(run_id):
        raise ValueError("Invalid scan run identifier")
    token = _request_token(request_token)
    now = utc_now()
    with connect_database(db_path) as db:
        db.execute("BEGIN IMMEDIATE")
        frozen = _source_snapshot(db, run_id)
        prior = db.execute(
            "SELECT job_id, request_kind FROM pipeline_job_requests WHERE request_token = ?",
            (token,),
        ).fetchone()
        if prior is not None:
            job = db.execute(
                f"SELECT {_JOB_COLUMNS} FROM pipeline_jobs WHERE job_id = ?", (prior[0],)
            ).fetchone()
            if job is None or prior[1] != "initial" or job[2] != run_id or job[3] != frozen["source_observation_id"]:
                raise DerivedJobConflict("That request token is already used for different work")
            return _job_dict(db, job)
        existing = db.execute(
            f"SELECT {_JOB_COLUMNS} FROM pipeline_jobs WHERE job_key = ?",
            (frozen["job_key"],),
        ).fetchone()
        if existing is None:
            job_id = f"analysis_job_{uuid.uuid4().hex}"
            db.execute(
                """INSERT INTO pipeline_jobs (
                       job_id, job_key, job_type, source_run_id, source_observation_id,
                       source_status, source_sha256, source_size_bytes, target_family,
                       target_analysis_version, target_payload_schema_version,
                       target_parameters_json, target_computation_key, target_result_id,
                       source_kind, source_ref, definition_json, requested_by, requested_at
                   ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'scan_run', ?, '{}', ?, ?)""",
                (job_id, frozen["job_key"], frozen["job_type"], run_id,
                 frozen["source_observation_id"], frozen["source_status"],
                 frozen["source_sha256"], frozen["source_size_bytes"],
                 frozen["target_family"], frozen["target_analysis_version"],
                 frozen["target_payload_schema_version"], frozen["target_parameters_json"],
                 frozen["target_computation_key"], frozen["target_result_id"],
                 run_id, requested_by, now),
            )
            db.execute(
                """INSERT INTO pipeline_job_attempts (
                       attempt_id, job_id, attempt_number, state, requested_by, requested_at
                   ) VALUES (?, ?, 1, 'queued', ?, ?)""",
                (f"analysis_attempt_{uuid.uuid4().hex}", job_id, requested_by, now),
            )
            existing = db.execute(
                f"SELECT {_JOB_COLUMNS} FROM pipeline_jobs WHERE job_id = ?", (job_id,)
            ).fetchone()
        db.execute(
            """INSERT INTO pipeline_job_requests (
                   request_token, job_id, request_kind, requested_by, requested_at
               ) VALUES (?, ?, 'initial', ?, ?)""",
            (token, existing[0], requested_by, now),
        )
        result = _job_dict(db, existing)
    start_derived_job_worker(db_path)
    return result


def _nmap_scope_snapshot(
    db: sqlite3.Connection,
    assignment_id: str,
    *,
    required_source_kind: str,
    automated_context: dict | None = None,
) -> dict:
    row = db.execute(
        """SELECT assignment.artifact_observation_id, assignment.scope_id,
                  assignment.revision, assignment.event_kind,
                  assignment.assignment_mode, observation.sha256,
                  observation.source_kind, observation.source_ref,
                  artifact.size_bytes, scope.active
           FROM artifact_scope_assignments assignment
           JOIN artifact_observations observation
             ON observation.observation_id = assignment.artifact_observation_id
           JOIN artifact_registry artifact ON artifact.sha256 = observation.sha256
           JOIN network_scopes scope ON scope.scope_id = assignment.scope_id
           WHERE assignment.assignment_id = ?""",
        (assignment_id,),
    ).fetchone()
    if row is None:
        raise KeyError("Eligible Nmap scope assignment does not exist")
    if row[6] != required_source_kind:
        raise DerivedJobConflict("The assignment is not for the expected Nmap evidence source")
    if db.execute(
        "SELECT 1 FROM artifact_scope_assignments WHERE supersedes_assignment_id = ?",
        (assignment_id,),
    ).fetchone():
        raise DerivedJobConflict("The selected scope assignment is no longer current")
    if not bool(row[9]):
        raise DerivedJobConflict("The selected Network Scope is archived")
    definition = {
        "assignment_id": assignment_id,
        "scope_id": row[1],
        "assignment_revision": int(row[2]),
        "assignment_event_kind": row[3],
        "assignment_mode": row[4],
        "parser_version": NMAP_ENDPOINT_PARSER,
    }
    if automated_context is not None:
        definition["automated_scope_context"] = automated_context
    source_run_id = row[7] if required_source_kind == "nmap_scan" else None
    frozen = {
        "job_type": NMAP_SCOPE_JOB_TYPE,
        "source_run_id": source_run_id,
        "source_observation_id": row[0],
        "source_status": "completed" if source_run_id else "assigned",
        "source_sha256": row[5],
        "source_size_bytes": int(row[8]),
        "target_family": NMAP_SCOPE_TARGET_FAMILY,
        "target_analysis_version": NMAP_ENDPOINT_PARSER,
        "target_payload_schema_version": NMAP_SCOPE_PAYLOAD_SCHEMA_VERSION,
        "target_parameters_json": "{}",
        "target_computation_key": None,
        "target_result_id": None,
        "source_kind": row[6],
        "source_ref": row[7],
        "definition_json": _canonical_json(definition),
    }
    frozen["job_key"] = _job_key(frozen)
    return frozen


def _enqueue_scope_snapshot(
    db: sqlite3.Connection,
    frozen: dict,
    *,
    request_token: str,
    requested_by: str,
    allow_retry: bool = True,
) -> dict:
    now = utc_now()
    prior = db.execute(
        "SELECT job_id, request_kind FROM pipeline_job_requests WHERE request_token = ?",
        (request_token,),
    ).fetchone()
    if prior is not None:
        job = db.execute(
            f"SELECT {_JOB_COLUMNS} FROM pipeline_jobs WHERE job_id = ?", (prior[0],)
        ).fetchone()
        if job is None or job[1] != NMAP_SCOPE_JOB_TYPE or job[3] != frozen["source_observation_id"]:
            raise DerivedJobConflict("That request token is already used for different work")
        if job[15] != frozen["definition_json"]:
            raise DerivedJobConflict("That request token is already used for different work")
        return _job_dict(db, job)

    job = db.execute(
        f"SELECT {_JOB_COLUMNS} FROM pipeline_jobs WHERE job_key = ?",
        (frozen["job_key"],),
    ).fetchone()
    request_kind = "initial"
    if job is None:
        job_id = f"pipeline_job_{uuid.uuid4().hex}"
        db.execute(
            """INSERT INTO pipeline_jobs (
                   job_id, job_key, job_type, source_run_id, source_observation_id,
                   source_status, source_sha256, source_size_bytes, target_family,
                   target_analysis_version, target_payload_schema_version,
                   target_parameters_json, target_computation_key, target_result_id,
                   source_kind, source_ref, definition_json, requested_by, requested_at
               ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (job_id, frozen["job_key"], frozen["job_type"], frozen["source_run_id"],
             frozen["source_observation_id"], frozen["source_status"],
             frozen["source_sha256"], frozen["source_size_bytes"],
             frozen["target_family"], frozen["target_analysis_version"],
             frozen["target_payload_schema_version"], frozen["target_parameters_json"],
             frozen["target_computation_key"], frozen["target_result_id"],
             frozen["source_kind"], frozen["source_ref"], frozen["definition_json"],
             requested_by, now),
        )
        db.execute(
            """INSERT INTO pipeline_job_attempts (
                   attempt_id, job_id, attempt_number, state, requested_by, requested_at
               ) VALUES (?, ?, 1, 'queued', ?, ?)""",
            (f"pipeline_attempt_{uuid.uuid4().hex}", job_id, requested_by, now),
        )
        job = db.execute(
            f"SELECT {_JOB_COLUMNS} FROM pipeline_jobs WHERE job_id = ?", (job_id,)
        ).fetchone()
    else:
        latest = db.execute(
            """SELECT attempt_number, state FROM pipeline_job_attempts
               WHERE job_id = ? ORDER BY attempt_number DESC LIMIT 1""",
            (job[0],),
        ).fetchone()
        if latest is None:
            raise DerivedJobConflict("The retained processing job has no attempt history")
        if not allow_retry:
            return _job_dict(db, job)
        if latest[1] in {"failed", "interrupted"}:
            request_kind = "retry"
            db.execute(
                """INSERT INTO pipeline_job_attempts (
                       attempt_id, job_id, attempt_number, state, requested_by, requested_at
                   ) VALUES (?, ?, ?, 'queued', ?, ?)""",
                (f"pipeline_attempt_{uuid.uuid4().hex}", job[0], int(latest[0]) + 1,
                 requested_by, now),
            )
    db.execute(
        """INSERT INTO pipeline_job_requests (
               request_token, job_id, request_kind, requested_by, requested_at
           ) VALUES (?, ?, ?, ?, ?)""",
        (request_token, job[0], request_kind, requested_by, now),
    )
    return _job_dict(db, job)


def enqueue_manual_nmap_scope_job(
    db_path: Path,
    assignment_id: str,
    *,
    request_token: str,
    requested_by: str,
) -> dict:
    init_derived_job_storage(db_path)
    token = _request_token(request_token)
    with connect_database(db_path) as db:
        db.execute("BEGIN IMMEDIATE")
        result = _enqueue_manual_nmap_scope_job(
            db, assignment_id, request_token=token, requested_by=requested_by,
        )
    start_derived_job_worker(db_path)
    return result


def enqueue_automated_nmap_scope_job(
    db_path: Path,
    run_id: str,
    *,
    request_token: str,
    requested_by: str,
) -> dict:
    from app.automated_nmap_foundation import init_automated_nmap_foundation_storage

    init_automated_nmap_foundation_storage(db_path)
    init_derived_job_storage(db_path)
    token = _request_token(request_token)
    with connect_database(db_path) as db:
        db.execute("BEGIN IMMEDIATE")
        result, _ = _enqueue_automated_nmap_scope_job(
            db, run_id, request_token=token, requested_by=requested_by,
        )
    start_derived_job_worker(db_path)
    return result


def _enqueue_manual_nmap_scope_job(
    db: sqlite3.Connection,
    assignment_id: str,
    *,
    request_token: str,
    requested_by: str,
) -> dict:
    frozen = _nmap_scope_snapshot(
        db, assignment_id, required_source_kind="nmap_import",
    )
    return _enqueue_scope_snapshot(
        db, frozen, request_token=request_token, requested_by=requested_by,
    )


def _enqueue_automated_nmap_scope_job(
    db: sqlite3.Connection,
    run_id: str,
    *,
    request_token: str,
    requested_by: str,
    allow_retry: bool = True,
) -> tuple[dict, str]:
    from app.automated_nmap_foundation import _ensure_inherited_assignment, _run_evidence

    evidence = _run_evidence(db, run_id)
    assignment_id = _ensure_inherited_assignment(db, evidence, requested_by)
    context = {
        "run_id": run_id,
        "scope_id": evidence["scope_id"],
        "scope_label": evidence["scope_label"],
        "scope_version": evidence["scope_version"],
        "scope_recorded_at": evidence["scope_recorded_at"],
    }
    frozen = _nmap_scope_snapshot(
        db,
        assignment_id,
        required_source_kind="nmap_scan",
        automated_context=context,
    )
    if frozen["source_run_id"] != run_id or frozen["source_observation_id"] != evidence["observation_id"]:
        raise DerivedJobConflict("The inherited scan assignment changed before it was queued")
    return (
        _enqueue_scope_snapshot(
            db, frozen, request_token=request_token, requested_by=requested_by,
            allow_retry=allow_retry,
        ),
        assignment_id,
    )


def _manual_contract_from_frozen(frozen: dict) -> dict:
    definition = json.loads(frozen["definition_json"] or "{}")
    return {
        "intent_kind": MANUAL_NMAP_INTENT,
        "source_kind": frozen["source_kind"],
        "source_ref": frozen["source_ref"],
        "observation_id": frozen["source_observation_id"],
        "source_sha256": frozen["source_sha256"],
        "source_size_bytes": int(frozen["source_size_bytes"]),
        "assignment_id": definition.get("assignment_id"),
        "scope_id": definition.get("scope_id"),
        "assignment_revision": definition.get("assignment_revision"),
        "assignment_event_kind": definition.get("assignment_event_kind"),
        "assignment_mode": definition.get("assignment_mode"),
        "target_family": frozen["target_family"],
        "target_analysis_version": frozen["target_analysis_version"],
        "target_payload_schema_version": frozen["target_payload_schema_version"],
        "target_parameters": json.loads(frozen["target_parameters_json"] or "{}"),
    }


def _automated_contract_from_evidence(evidence: dict) -> dict:
    return {
        "intent_kind": AUTOMATED_NMAP_INTENT,
        "source_kind": "nmap_scan",
        "run_id": evidence["run_id"],
        "source_status": evidence["run_status"],
        "observation_id": evidence["observation_id"],
        "source_sha256": evidence["sha256"],
        "source_size_bytes": evidence["size_bytes"],
        "scope_id": evidence["scope_id"],
        "scope_label": evidence["scope_label"],
        "scope_version": evidence["scope_version"],
        "scope_recorded_at": evidence["scope_recorded_at"],
        "target_family": NMAP_SCOPE_TARGET_FAMILY,
        "target_analysis_version": NMAP_ENDPOINT_PARSER,
        "target_payload_schema_version": NMAP_SCOPE_PAYLOAD_SCHEMA_VERSION,
        "target_parameters": {},
        "eligibility_reasons": [],
    }


def dispatch_next_pipeline_intake(db_path: Path) -> bool:
    """Admit one explicitly marked pending source without scanning historical rows."""
    from app.automated_nmap_foundation import (
        AutomatedNmapFoundationConflict,
        _run_evidence,
        init_automated_nmap_foundation_storage,
    )

    init_automated_nmap_foundation_storage(db_path)
    init_derived_job_storage(db_path)
    with connect_database(db_path) as db:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute(
            """SELECT intent_id, intent_kind, source_id, policy_version,
                      assignment_id, actor, request_token, contract_json
               FROM pipeline_admission_intents
               WHERE state = 'pending'
               ORDER BY created_at, intent_id LIMIT 1"""
        ).fetchone()
        if row is None:
            return False
        intent_id, intent_kind, source_id = row[0], row[1], row[2]
        db.execute(
            """UPDATE pipeline_admission_intents
               SET activity_state = 'waiting', updated_at = ?, last_error = NULL
               WHERE intent_id = ? AND state = 'pending'""",
            (utc_now(), intent_id),
        )
        db.execute("SAVEPOINT pipeline_admission")
        try:
            if int(row[3]) != NMAP_INGESTION_POLICY_VERSION:
                raise DerivedJobConflict("The intake policy version is no longer supported")
            retained_contract = json.loads(row[7] or "{}")
            if intent_kind == MANUAL_NMAP_INTENT:
                assignment_id = row[4]
                if not assignment_id:
                    raise DerivedJobConflict("The manual intake assignment is unavailable")
                frozen = _nmap_scope_snapshot(
                    db, assignment_id, required_source_kind="nmap_import",
                )
                if _manual_contract_from_frozen(frozen) != retained_contract:
                    raise DerivedJobConflict("The manual intake contract changed before admission")
                job = _enqueue_scope_snapshot(
                    db, frozen, request_token=row[6], requested_by=row[5],
                    allow_retry=False,
                )
                resolved_assignment_id = assignment_id
            elif intent_kind == AUTOMATED_NMAP_INTENT:
                evidence = _run_evidence(db, source_id)
                if not evidence["eligible"]:
                    raise AutomatedNmapFoundationConflict(
                        "; ".join(evidence["eligibility_reasons"])
                    )
                if _automated_contract_from_evidence(evidence) != retained_contract:
                    raise DerivedJobConflict("The automated intake contract changed before admission")
                job, resolved_assignment_id = _enqueue_automated_nmap_scope_job(
                    db,
                    source_id,
                    request_token=row[6],
                    requested_by=row[5],
                    allow_retry=False,
                )
            else:
                raise DerivedJobConflict("The intake intent type is unsupported")
            db.execute("RELEASE pipeline_admission")
            db.execute(
                """UPDATE pipeline_admission_intents
                   SET state = 'admitted', updated_at = ?, admitted_job_id = ?,
                       resolved_assignment_id = ?, activity_state = 'complete',
                       last_error = NULL
                   WHERE intent_id = ? AND state = 'pending'""",
                (utc_now(), job["job_id"], resolved_assignment_id, intent_id),
            )
        except (KeyError, ValueError, json.JSONDecodeError) as exc:
            db.execute("ROLLBACK TO pipeline_admission")
            db.execute("RELEASE pipeline_admission")
            db.execute(
                """UPDATE pipeline_admission_intents
                   SET state = 'blocked', updated_at = ?,
                       activity_state = 'blocked', last_error = ?
                   WHERE intent_id = ? AND state = 'pending'""",
                (utc_now(), (str(exc).strip() or exc.__class__.__name__)[:2000], intent_id),
            )
    return True


def retry_derived_job(
    db_path: Path, job_id: str, *, request_token: str, requested_by: str,
) -> dict:
    init_derived_job_storage(db_path)
    token = _request_token(request_token)
    now = utc_now()
    with connect_database(db_path) as db:
        db.execute("BEGIN IMMEDIATE")
        job = db.execute(
            f"SELECT {_JOB_COLUMNS} FROM pipeline_jobs WHERE job_id = ?", (job_id,)
        ).fetchone()
        if job is None:
            raise KeyError("Saved-analysis job not found")
        prior = db.execute(
            "SELECT job_id, request_kind FROM pipeline_job_requests WHERE request_token = ?",
            (token,),
        ).fetchone()
        if prior is not None:
            if prior != (job_id, "retry"):
                raise DerivedJobConflict("That request token is already used for different work")
            return _job_dict(db, job)
        latest = db.execute(
            """SELECT attempt_number, state FROM pipeline_job_attempts
               WHERE job_id = ? ORDER BY attempt_number DESC LIMIT 1""",
            (job_id,),
        ).fetchone()
        if latest is None or latest[1] not in {"failed", "interrupted"}:
            raise DerivedJobConflict("Only failed or interrupted work can be retried")
        attempt_id = f"analysis_attempt_{uuid.uuid4().hex}"
        db.execute(
            """INSERT INTO pipeline_job_attempts (
                   attempt_id, job_id, attempt_number, state, requested_by, requested_at
               ) VALUES (?, ?, ?, 'queued', ?, ?)""",
            (attempt_id, job_id, int(latest[0]) + 1, requested_by, now),
        )
        db.execute(
            """INSERT INTO pipeline_job_requests (
                   request_token, job_id, request_kind, requested_by, requested_at
               ) VALUES (?, ?, 'retry', ?, ?)""",
            (token, job_id, requested_by, now),
        )
        result = _job_dict(db, job)
    start_derived_job_worker(db_path)
    return result


def claim_next_derived_job(db_path: Path) -> dict | None:
    init_derived_job_storage(db_path)
    claim = uuid.uuid4().hex
    now = utc_now()
    with connect_database(db_path) as db:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute(
            """SELECT attempt_id, job_id FROM pipeline_job_attempts
               WHERE state = 'queued' ORDER BY requested_at, attempt_id LIMIT 1"""
        ).fetchone()
        if row is None:
            return None
        changed = db.execute(
            """UPDATE pipeline_job_attempts
               SET state = 'running', claim_token = ?, started_at = ?
               WHERE attempt_id = ? AND state = 'queued'""",
            (claim, now, row[0]),
        ).rowcount
        if changed != 1:
            return None
        return {"attempt_id": row[0], "job_id": row[1], "claim_token": claim}


def _current_contract_matches(job: sqlite3.Row | tuple) -> bool:
    return (
        job[6] == NMAP_BASE_ANALYSIS_FAMILY
        and job[7] == NMAP_BASE_ANALYSIS_VERSION
        and int(job[8]) == NMAP_BASE_PAYLOAD_SCHEMA_VERSION
        and job[9] == _canonical_json(dict(NMAP_BASE_PARAMETERS))
    )


def execute_claimed_derived_job(db_path: Path, claim: dict, run_local_path: Path) -> dict:
    with connect_database(db_path, read_only=True) as db:
        row = db.execute(
            """SELECT job.job_id, job.source_run_id, job.source_observation_id,
                      job.source_status, job.source_sha256, job.source_size_bytes,
                      job.target_family, job.target_analysis_version,
                      job.target_payload_schema_version, job.target_parameters_json,
                      job.target_computation_key, job.target_result_id
               FROM pipeline_jobs job
               JOIN pipeline_job_attempts attempt ON attempt.job_id = job.job_id
               WHERE job.job_id = ? AND attempt.attempt_id = ?
                 AND attempt.state = 'running' AND attempt.claim_token = ?""",
            (claim["job_id"], claim["attempt_id"], claim["claim_token"]),
        ).fetchone()
    if row is None:
        raise DerivedJobConflict("The saved-analysis worker no longer owns this attempt")
    run_local_path = _validate_supplied_run_path(run_local_path, row[1])
    if not _current_contract_matches(row):
        raise DerivedJobConflict("The application calculation rules changed before this job ran")
    if row[3] not in NMAP_ANALYSIS_TERMINAL_STATES:
        raise DerivedJobConflict("The requested source state is not finalized")
    expected = derived_result_identity(
        family=row[6], analysis_version=row[7],
        payload_schema_version=int(row[8]), parameters=json.loads(row[9]),
        inputs=[{
            "role": "nmap_xml", "kind": "artifact_sha256", "identity": row[4],
            "metadata": {"media_family": "nmap_xml"},
        }],
    )
    if expected.computation_key != row[10] or expected.result_id != row[11]:
        raise DerivedJobConflict("The saved-analysis job identity is inconsistent")
    _verify_run_local_artifact(run_local_path, row[4], int(row[5]))
    source_guard = _scan_authority_guard(row[1], row[2])

    def guard(db: sqlite3.Connection) -> None:
        source_guard(db)
        owned = db.execute(
            """SELECT 1 FROM pipeline_job_attempts
               WHERE attempt_id = ? AND job_id = ? AND state = 'running' AND claim_token = ?""",
            (claim["attempt_id"], claim["job_id"], claim["claim_token"]),
        ).fetchone()
        if owned is None:
            raise DerivedJobConflict("The saved-analysis worker lost its claim")

    def finalize(db: sqlite3.Connection, created: bool) -> None:
        changed = db.execute(
            """UPDATE pipeline_job_attempts
               SET state = 'completed', finished_at = ?, outcome = ?, result_id = ?,
                   output_kind = 'derived_result', output_id = ?, error = NULL
               WHERE attempt_id = ? AND job_id = ? AND state = 'running' AND claim_token = ?""",
            (utc_now(), "created" if created else "reused", row[11], row[11],
             claim["attempt_id"], claim["job_id"], claim["claim_token"]),
        ).rowcount
        if changed != 1:
            raise DerivedJobConflict("The saved-analysis worker lost its claim")

    result = analyze_registered_nmap_result(
        db_path, row[2], family=row[6], analysis_version=row[7],
        payload_schema_version=int(row[8]), parameters=json.loads(row[9]),
        parser=_parse_nmap_xml, authority_guard=guard,
        before_publish=lambda: _verify_run_local_artifact(
            run_local_path, row[4], int(row[5])
        ),
        transaction_finalize=finalize,
    )
    return result


def execute_claimed_nmap_scope_job(db_path: Path, claim: dict) -> dict:
    job_columns = (
        "job_id", "job_key", "job_type", "source_run_id", "source_observation_id",
        "source_status", "source_sha256", "source_size_bytes", "target_family",
        "target_analysis_version", "target_payload_schema_version",
        "target_parameters_json", "target_computation_key", "target_result_id",
        "source_kind", "source_ref", "definition_json",
    )
    select_columns = ", ".join(f"job.{name}" for name in job_columns)
    with connect_database(db_path, read_only=True) as db:
        db.row_factory = sqlite3.Row
        row = db.execute(
            f"""SELECT {select_columns}, attempt.requested_by AS attempt_requested_by
                FROM pipeline_jobs job
                JOIN pipeline_job_attempts attempt ON attempt.job_id = job.job_id
                WHERE job.job_id = ? AND attempt.attempt_id = ?
                  AND attempt.state = 'running' AND attempt.claim_token = ?""",
            (claim["job_id"], claim["attempt_id"], claim["claim_token"]),
        ).fetchone()
    if row is None:
        raise DerivedJobConflict("The Nmap scope worker no longer owns this attempt")
    frozen_job = tuple(row[name] for name in job_columns)
    try:
        definition = json.loads(row["definition_json"] or "{}")
    except json.JSONDecodeError as exc:
        raise DerivedJobConflict("The scoped Nmap job definition is unreadable") from exc
    assignment_id = definition.get("assignment_id") if isinstance(definition, dict) else None
    identity_payload = {
        "job_type": row["job_type"],
        "source_run_id": row["source_run_id"],
        "source_observation_id": row["source_observation_id"],
        "source_status": row["source_status"],
        "source_sha256": row["source_sha256"],
        "source_size_bytes": int(row["source_size_bytes"]),
        "target_family": row["target_family"],
        "target_analysis_version": row["target_analysis_version"],
        "target_payload_schema_version": row["target_payload_schema_version"],
        "target_parameters_json": row["target_parameters_json"],
        "target_computation_key": row["target_computation_key"],
        "target_result_id": row["target_result_id"],
        "source_kind": row["source_kind"],
        "source_ref": row["source_ref"],
        "definition_json": row["definition_json"],
    }
    if (
        row["job_type"] != NMAP_SCOPE_JOB_TYPE
        or row["target_family"] != NMAP_SCOPE_TARGET_FAMILY
        or row["target_analysis_version"] != NMAP_ENDPOINT_PARSER
        or int(row["target_payload_schema_version"]) != NMAP_SCOPE_PAYLOAD_SCHEMA_VERSION
        or row["target_parameters_json"] != "{}"
        or row["target_computation_key"] is not None
        or row["target_result_id"] is not None
        or definition.get("parser_version") != NMAP_ENDPOINT_PARSER
        or _canonical_json(definition) != row["definition_json"]
        or _job_key(identity_payload) != row["job_key"]
        or not assignment_id
    ):
        raise DerivedJobConflict("The scoped Nmap job identity or processing rules changed before this job ran")

    def validate_authority(db: sqlite3.Connection) -> None:
        assignment = db.execute(
            """SELECT assignment.artifact_observation_id, assignment.scope_id,
                      assignment.revision, assignment.event_kind,
                      assignment.assignment_mode, observation.sha256,
                      observation.source_kind, observation.source_ref,
                      artifact.size_bytes, scope.active
               FROM artifact_scope_assignments assignment
               JOIN artifact_observations observation
                 ON observation.observation_id = assignment.artifact_observation_id
               JOIN artifact_registry artifact ON artifact.sha256 = observation.sha256
               JOIN network_scopes scope ON scope.scope_id = assignment.scope_id
               WHERE assignment.assignment_id = ?""",
            (assignment_id,),
        ).fetchone()
        expected_assignment = (
            row["source_observation_id"], definition.get("scope_id"),
            definition.get("assignment_revision"), definition.get("assignment_event_kind"),
            definition.get("assignment_mode"), row["source_sha256"],
            row["source_kind"], row["source_ref"], int(row["source_size_bytes"]),
        )
        if assignment is None or tuple(assignment[:9]) != expected_assignment:
            raise DerivedJobConflict("The queued assignment no longer matches the frozen job")
        if not bool(assignment[9]):
            raise DerivedJobConflict("The queued assignment scope is archived")
        if db.execute(
            "SELECT 1 FROM artifact_scope_assignments WHERE supersedes_assignment_id = ?",
            (assignment_id,),
        ).fetchone():
            raise DerivedJobConflict("The queued assignment is no longer current")
        automated = definition.get("automated_scope_context")
        if automated is None:
            if row["source_kind"] != "nmap_import" or row["source_run_id"] is not None:
                raise DerivedJobConflict("The manual Nmap source contract changed")
            if row["source_status"] != "assigned":
                raise DerivedJobConflict("The manual Nmap source state changed")
        else:
            from app.automated_nmap_foundation import _run_evidence

            current = _run_evidence(db, automated.get("run_id"))
            if not current["eligible"]:
                raise DerivedJobConflict("The retained scan is no longer eligible for processing")
            expected_context = {
                "run_id": current["run_id"],
                "scope_id": current["scope_id"],
                "scope_label": current["scope_label"],
                "scope_version": current["scope_version"],
                "scope_recorded_at": current["scope_recorded_at"],
            }
            if (
                expected_context != automated
                or current["observation_id"] != row["source_observation_id"]
                or row["source_run_id"] != current["run_id"]
                or row["source_ref"] != current["run_id"]
                or row["source_kind"] != "nmap_scan"
                or row["source_status"] != "completed"
            ):
                raise DerivedJobConflict("The retained scan scope authority changed")

    def verify_source_bytes() -> None:
        observation = get_artifact_observation(db_path, row["source_observation_id"])
        if observation is None:
            raise DerivedJobConflict("The queued Nmap evidence observation is unavailable")
        if (
            observation["sha256"] != row["source_sha256"]
            or int(observation["size_bytes"]) != int(row["source_size_bytes"])
            or observation["source_kind"] != row["source_kind"]
            or observation["source_ref"] != row["source_ref"]
        ):
            raise DerivedJobConflict("The queued Nmap evidence identity changed")
        canonical = Path(observation["canonical_path"])
        if canonical.is_symlink() or sha256_file(canonical) != (
            row["source_sha256"], int(row["source_size_bytes"]),
        ):
            raise DerivedJobConflict("The queued Nmap evidence failed exact-content verification")

    with connect_database(db_path, read_only=True) as db:
        validate_authority(db)
    verify_source_bytes()

    def guard(db: sqlite3.Connection) -> None:
        db.row_factory = sqlite3.Row
        owned = db.execute(
            f"""SELECT {select_columns} FROM pipeline_jobs job
                JOIN pipeline_job_attempts attempt ON attempt.job_id = job.job_id
                WHERE job.job_id = ? AND attempt.attempt_id = ?
                  AND attempt.state = 'running' AND attempt.claim_token = ?""",
            (claim["job_id"], claim["attempt_id"], claim["claim_token"]),
        ).fetchone()
        if owned is None:
            raise DerivedJobConflict("The Nmap scope worker lost its claim")
        if tuple(owned[name] for name in job_columns) != frozen_job:
            raise DerivedJobConflict("The scoped Nmap job definition changed while processing")
        validate_authority(db)

    def finalize(db: sqlite3.Connection, created: bool, assessment_id: str) -> None:
        changed = db.execute(
            """UPDATE pipeline_job_attempts
               SET state = 'completed', finished_at = ?, outcome = ?, result_id = NULL,
                   output_kind = 'entity_assessment', output_id = ?, error = NULL
               WHERE attempt_id = ? AND job_id = ? AND state = 'running'
                 AND claim_token = ?""",
            (utc_now(), "created" if created else "reused", assessment_id,
             claim["attempt_id"], claim["job_id"], claim["claim_token"]),
        ).rowcount
        if changed != 1:
            raise DerivedJobConflict("The Nmap scope worker lost its claim")

    return ingest_assigned_nmap_observation(
        db_path,
        expected_assignment_id=assignment_id,
        linked_by=row["attempt_requested_by"],
        parser_version=row["target_analysis_version"],
        before_publish=verify_source_bytes,
        transaction_guard=guard,
        transaction_finalize=finalize,
    )


def fail_claimed_derived_job(db_path: Path, claim: dict, error: Exception) -> None:
    message = str(error).strip() or error.__class__.__name__
    with connect_database(db_path) as db:
        db.execute("BEGIN IMMEDIATE")
        db.execute(
            """UPDATE pipeline_job_attempts
               SET state = 'failed', finished_at = ?, error = ?
               WHERE attempt_id = ? AND job_id = ? AND state = 'running' AND claim_token = ?""",
            (utc_now(), message[:2000], claim["attempt_id"], claim["job_id"], claim["claim_token"]),
        )


def run_next_derived_job(db_path: Path, data_dir: Path) -> bool:
    claim = claim_next_derived_job(db_path)
    if claim is None:
        return False
    try:
        run_id = None
        with connect_database(db_path, read_only=True) as db:
            found = db.execute(
                "SELECT job_type, source_run_id FROM pipeline_jobs WHERE job_id = ?",
                (claim["job_id"],),
            ).fetchone()
            job_type = found[0] if found else None
            run_id = found[1] if found else None
        if job_type == JOB_TYPE:
            if not run_id:
                raise DerivedJobConflict("The saved-analysis job definition is unavailable")
            execute_claimed_derived_job(
                db_path, claim, _run_local_path(data_dir, run_id),
            )
        elif job_type == NMAP_SCOPE_JOB_TYPE:
            execute_claimed_nmap_scope_job(db_path, claim)
        else:
            raise DerivedJobConflict("The pipeline job type is not supported by this worker")
    except Exception as exc:
        fail_claimed_derived_job(db_path, claim, exc)
    return True


def _record_pipeline_intake_error(
    db_path: Path, error: Exception, *, paused: bool,
) -> None:
    prefix = (
        "Automatic admission paused after repeated queue storage errors"
        if paused else "Automatic admission delayed by a queue storage error"
    )
    message = f"{prefix}: {str(error).strip() or error.__class__.__name__}"[:2000]
    with connect_database(db_path) as db:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute(
            """SELECT intent_id FROM pipeline_admission_intents
               WHERE state = 'pending' ORDER BY created_at, intent_id LIMIT 1"""
        ).fetchone()
        if row is not None:
            db.execute(
                """UPDATE pipeline_admission_intents
                   SET updated_at = ?, activity_state = ?, last_error = ?
                   WHERE intent_id = ? AND state = 'pending'""",
                (utc_now(), "paused" if paused else "retrying", message, row[0]),
            )


def _worker_loop(db_path: Path, data_dir: Path, stop: threading.Event) -> None:
    paused_after_error = False
    intake_failures = 0
    admission_enabled = True
    try:
        while not stop.is_set():
            admitted = False
            retry_delay = None
            if admission_enabled:
                try:
                    admitted = dispatch_next_pipeline_intake(db_path)
                    intake_failures = 0
                except sqlite3.OperationalError as exc:
                    intake_failures += 1
                    if intake_failures > len(_INTAKE_RETRY_DELAYS):
                        paused_after_error = True
                        admission_enabled = False
                    else:
                        retry_delay = _INTAKE_RETRY_DELAYS[intake_failures - 1]
                    try:
                        _record_pipeline_intake_error(
                            db_path, exc, paused=not admission_enabled,
                        )
                    except sqlite3.Error:
                        pass
            ran = run_next_derived_job(db_path, data_dir)
            if retry_delay is not None:
                if stop.wait(retry_delay):
                    break
                continue
            if not admitted and not ran:
                break
    except Exception:
        paused_after_error = True
        raise
    finally:
        path = Path(db_path).resolve()
        with _WORKERS_LOCK:
            current = _WORKERS.get(path)
            if current and current[0] is stop:
                _WORKERS.pop(path, None)
            if not stop.is_set() and not paused_after_error:
                with connect_database(path, read_only=True) as db:
                    queued = db.execute(
                        "SELECT 1 FROM pipeline_job_attempts WHERE state = 'queued' LIMIT 1"
                    ).fetchone()
                    pending_intake = db.execute(
                        "SELECT 1 FROM pipeline_admission_intents WHERE state = 'pending' LIMIT 1"
                    ).fetchone()
                if queued or pending_intake:
                    start_derived_job_worker(path, data_dir)


def start_derived_job_worker(db_path: Path, data_dir: Path | None = None) -> None:
    path = Path(db_path).resolve()
    root = Path(data_dir) if data_dir is not None else path.parent
    with _WORKERS_LOCK:
        current = _WORKERS.get(path)
        if current and current[1].is_alive():
            return
        init_pipeline_intake_storage(path)
        with connect_database(path) as db:
            db.execute(
                """UPDATE pipeline_admission_intents
                   SET activity_state = 'waiting', updated_at = ?, last_error = NULL
                   WHERE state = 'pending'
                     AND activity_state IN ('retrying', 'paused')""",
                (utc_now(),),
            )
        stop = threading.Event()
        thread = threading.Thread(
            target=_worker_loop, args=(path, root, stop), daemon=True,
            name="saved-analysis-worker",
        )
        _WORKERS[path] = (stop, thread)
        thread.start()


def stop_derived_job_worker(db_path: Path, timeout: float = 2.0) -> None:
    path = Path(db_path).resolve()
    with _WORKERS_LOCK:
        current = _WORKERS.get(path)
    if current:
        current[0].set()
        current[1].join(timeout=timeout)


def recover_interrupted_derived_jobs(db_path: Path) -> int:
    init_derived_job_storage(db_path)
    with connect_database(db_path) as db:
        db.execute("BEGIN IMMEDIATE")
        return db.execute(
            """UPDATE pipeline_job_attempts
               SET state = 'interrupted', finished_at = ?,
                   error = 'Application stopped while this attempt was running'
               WHERE state = 'running'""",
            (utc_now(),),
        ).rowcount


def list_derived_jobs(db_path: Path, *, limit: int = 25, offset: int = 0) -> dict:
    limit = max(1, min(int(limit), 100))
    offset = max(0, int(offset))
    if not Path(db_path).is_file():
        return {"items": [], "total": 0, "limit": limit, "offset": offset,
                "has_more": False}
    with connect_database(db_path, read_only=True) as db:
        db.execute("BEGIN")
        available = db.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'pipeline_jobs'"
        ).fetchone()
        if available is None:
            return {"items": [], "total": 0, "limit": limit, "offset": offset,
                    "has_more": False}
        total = db.execute("SELECT COUNT(*) FROM pipeline_jobs").fetchone()[0]
        rows = db.execute(
            f"""SELECT {_JOB_COLUMNS} FROM pipeline_jobs
                ORDER BY requested_at DESC, job_id DESC LIMIT ? OFFSET ?""",
            (limit, offset),
        ).fetchall()
        items = [_job_dict(db, row) for row in rows]
    return {"items": items, "total": total, "limit": limit, "offset": offset,
            "has_more": offset + len(items) < total}


def nmap_scope_job_for_assignment(
    db_path: Path, assignment_id: str,
) -> dict | None:
    if not Path(db_path).is_file():
        return None
    with connect_database(db_path, read_only=True) as db:
        available = db.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'pipeline_jobs'"
        ).fetchone()
        if available is None:
            return None
        rows = db.execute(
            f"""SELECT {_JOB_COLUMNS}
                FROM pipeline_jobs job
                JOIN artifact_scope_assignments assignment
                  ON assignment.artifact_observation_id = job.source_observation_id
                WHERE job.job_type = ? AND assignment.assignment_id = ?
                ORDER BY job.requested_at DESC, job.job_id DESC""",
            (NMAP_SCOPE_JOB_TYPE, assignment_id),
        ).fetchall()
        for row in rows:
            if json.loads(row[15] or "{}").get("assignment_id") == assignment_id:
                return _job_dict(db, row)
    return None


def nmap_scope_job_for_run(db_path: Path, run_id: str) -> dict | None:
    if not Path(db_path).is_file():
        return None
    with connect_database(db_path, read_only=True) as db:
        available = db.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'pipeline_jobs'"
        ).fetchone()
        if available is None:
            return None
        row = db.execute(
            f"""SELECT {_JOB_COLUMNS} FROM pipeline_jobs
                WHERE job_type = ? AND source_run_id = ?
                ORDER BY requested_at DESC, job_id DESC LIMIT 1""",
            (NMAP_SCOPE_JOB_TYPE, run_id),
        ).fetchone()
        return _job_dict(db, row) if row is not None else None


def scan_run_job_statuses(db_path: Path, run_ids: list[str], data_dir: Path) -> dict[str, dict]:
    result: dict[str, dict] = {}
    if not run_ids or not Path(db_path).is_file():
        return result
    with connect_database(db_path, read_only=True) as db:
        db.execute("BEGIN")
        jobs_available = db.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'pipeline_jobs'"
        ).fetchone() is not None
        for run_id in run_ids:
            try:
                frozen = _source_snapshot(db, run_id)
                local = _run_local_path(data_dir, run_id)
                eligible = local.is_file() and not local.is_symlink()
                reason = "" if eligible else "The retained run-local scan.xml is unavailable."
            except (KeyError, DerivedJobConflict, ValueError) as exc:
                eligible, reason, frozen = False, str(exc), None
            row = None
            if jobs_available:
                row = db.execute(
                    f"""SELECT {_JOB_COLUMNS} FROM pipeline_jobs
                        WHERE job_type = ? AND source_run_id = ?
                        ORDER BY requested_at DESC, job_id DESC LIMIT 1""",
                    (JOB_TYPE, run_id),
                ).fetchone()
            result[run_id] = {
                "eligible": eligible, "eligibility_reason": reason,
                "current_job": _job_dict(db, row) if row else None,
                "current_contract": frozen is not None,
            }
    return result
