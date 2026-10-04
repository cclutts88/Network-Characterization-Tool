"""Durable, operator-requested jobs for verified saved calculations."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import sqlite3
import threading
import uuid

from app.artifacts import utc_now
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


JOB_TYPE = "nmap_base_analysis"
_ACTIVE_STATES = {"queued", "running"}
_RUN_ID = re.compile(r"^[0-9a-f]{32}$")
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
    init_derived_result_storage(db_path)
    with connect_database(db_path) as db:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS derived_analysis_jobs (
                job_id TEXT PRIMARY KEY,
                job_key TEXT NOT NULL UNIQUE,
                job_type TEXT NOT NULL CHECK(job_type = 'nmap_base_analysis'),
                source_run_id TEXT NOT NULL,
                source_observation_id TEXT NOT NULL,
                source_status TEXT NOT NULL,
                source_sha256 TEXT NOT NULL,
                source_size_bytes INTEGER NOT NULL CHECK(source_size_bytes >= 0),
                target_family TEXT NOT NULL,
                target_analysis_version TEXT NOT NULL,
                target_payload_schema_version INTEGER NOT NULL,
                target_parameters_json TEXT NOT NULL,
                target_computation_key TEXT NOT NULL,
                target_result_id TEXT NOT NULL,
                requested_by TEXT NOT NULL,
                requested_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS derived_analysis_job_requests (
                request_token TEXT PRIMARY KEY,
                job_id TEXT NOT NULL,
                request_kind TEXT NOT NULL CHECK(request_kind IN ('initial', 'retry')),
                requested_by TEXT NOT NULL,
                requested_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS derived_analysis_job_attempts (
                attempt_id TEXT PRIMARY KEY,
                job_id TEXT NOT NULL,
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
                error TEXT,
                UNIQUE(job_id, attempt_number)
            );
            CREATE UNIQUE INDEX IF NOT EXISTS derived_job_one_active_attempt
                ON derived_analysis_job_attempts(job_id)
                WHERE state IN ('queued', 'running');
            CREATE INDEX IF NOT EXISTS derived_job_attempt_queue
                ON derived_analysis_job_attempts(state, requested_at, attempt_id);
            CREATE INDEX IF NOT EXISTS derived_job_run_lookup
                ON derived_analysis_jobs(source_run_id, requested_at DESC);
            """
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
        "started_at", "finished_at", "outcome", "result_id", "error",
    )
    return dict(zip(keys, row))


def _job_dict(db: sqlite3.Connection, row) -> dict:
    latest = db.execute(
        """SELECT attempt_id, attempt_number, state, requested_by, requested_at,
                  started_at, finished_at, outcome, result_id, error
           FROM derived_analysis_job_attempts WHERE job_id = ?
           ORDER BY attempt_number DESC LIMIT 1""",
        (row[0],),
    ).fetchone()
    attempts = db.execute(
        "SELECT COUNT(*) FROM derived_analysis_job_attempts WHERE job_id = ?", (row[0],)
    ).fetchone()[0]
    return {
        "job_id": row[0], "job_type": row[1], "source_run_id": row[2],
        "source_observation_id": row[3], "source_status": row[4],
        "source_sha256": row[5], "source_size_bytes": row[6],
        "target_family": row[7], "target_analysis_version": row[8],
        "target_payload_schema_version": row[9], "target_result_id": row[10],
        "requested_by": row[11], "requested_at": row[12],
        "attempt_count": attempts, "latest_attempt": _attempt_dict(latest),
    }


_JOB_COLUMNS = """job_id, job_type, source_run_id, source_observation_id,
 source_status, source_sha256, source_size_bytes, target_family,
 target_analysis_version, target_payload_schema_version, target_result_id,
 requested_by, requested_at"""


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
            "SELECT job_id, request_kind FROM derived_analysis_job_requests WHERE request_token = ?",
            (token,),
        ).fetchone()
        if prior is not None:
            job = db.execute(
                f"SELECT {_JOB_COLUMNS} FROM derived_analysis_jobs WHERE job_id = ?", (prior[0],)
            ).fetchone()
            if job is None or prior[1] != "initial" or job[2] != run_id or job[3] != frozen["source_observation_id"]:
                raise DerivedJobConflict("That request token is already used for different work")
            return _job_dict(db, job)
        existing = db.execute(
            f"SELECT {_JOB_COLUMNS} FROM derived_analysis_jobs WHERE job_key = ?",
            (frozen["job_key"],),
        ).fetchone()
        if existing is None:
            job_id = f"analysis_job_{uuid.uuid4().hex}"
            db.execute(
                """INSERT INTO derived_analysis_jobs (
                       job_id, job_key, job_type, source_run_id, source_observation_id,
                       source_status, source_sha256, source_size_bytes, target_family,
                       target_analysis_version, target_payload_schema_version,
                       target_parameters_json, target_computation_key, target_result_id,
                       requested_by, requested_at
                   ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (job_id, frozen["job_key"], frozen["job_type"], run_id,
                 frozen["source_observation_id"], frozen["source_status"],
                 frozen["source_sha256"], frozen["source_size_bytes"],
                 frozen["target_family"], frozen["target_analysis_version"],
                 frozen["target_payload_schema_version"], frozen["target_parameters_json"],
                 frozen["target_computation_key"], frozen["target_result_id"],
                 requested_by, now),
            )
            db.execute(
                """INSERT INTO derived_analysis_job_attempts (
                       attempt_id, job_id, attempt_number, state, requested_by, requested_at
                   ) VALUES (?, ?, 1, 'queued', ?, ?)""",
                (f"analysis_attempt_{uuid.uuid4().hex}", job_id, requested_by, now),
            )
            existing = db.execute(
                f"SELECT {_JOB_COLUMNS} FROM derived_analysis_jobs WHERE job_id = ?", (job_id,)
            ).fetchone()
        db.execute(
            """INSERT INTO derived_analysis_job_requests (
                   request_token, job_id, request_kind, requested_by, requested_at
               ) VALUES (?, ?, 'initial', ?, ?)""",
            (token, existing[0], requested_by, now),
        )
        result = _job_dict(db, existing)
    start_derived_job_worker(db_path)
    return result


def retry_derived_job(
    db_path: Path, job_id: str, *, request_token: str, requested_by: str,
) -> dict:
    init_derived_job_storage(db_path)
    token = _request_token(request_token)
    now = utc_now()
    with connect_database(db_path) as db:
        db.execute("BEGIN IMMEDIATE")
        job = db.execute(
            f"SELECT {_JOB_COLUMNS} FROM derived_analysis_jobs WHERE job_id = ?", (job_id,)
        ).fetchone()
        if job is None:
            raise KeyError("Saved-analysis job not found")
        prior = db.execute(
            "SELECT job_id, request_kind FROM derived_analysis_job_requests WHERE request_token = ?",
            (token,),
        ).fetchone()
        if prior is not None:
            if prior != (job_id, "retry"):
                raise DerivedJobConflict("That request token is already used for different work")
            return _job_dict(db, job)
        latest = db.execute(
            """SELECT attempt_number, state FROM derived_analysis_job_attempts
               WHERE job_id = ? ORDER BY attempt_number DESC LIMIT 1""",
            (job_id,),
        ).fetchone()
        if latest is None or latest[1] not in {"failed", "interrupted"}:
            raise DerivedJobConflict("Only failed or interrupted work can be retried")
        attempt_id = f"analysis_attempt_{uuid.uuid4().hex}"
        db.execute(
            """INSERT INTO derived_analysis_job_attempts (
                   attempt_id, job_id, attempt_number, state, requested_by, requested_at
               ) VALUES (?, ?, ?, 'queued', ?, ?)""",
            (attempt_id, job_id, int(latest[0]) + 1, requested_by, now),
        )
        db.execute(
            """INSERT INTO derived_analysis_job_requests (
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
            """SELECT attempt_id, job_id FROM derived_analysis_job_attempts
               WHERE state = 'queued' ORDER BY requested_at, attempt_id LIMIT 1"""
        ).fetchone()
        if row is None:
            return None
        changed = db.execute(
            """UPDATE derived_analysis_job_attempts
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
               FROM derived_analysis_jobs job
               JOIN derived_analysis_job_attempts attempt ON attempt.job_id = job.job_id
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
            """SELECT 1 FROM derived_analysis_job_attempts
               WHERE attempt_id = ? AND job_id = ? AND state = 'running' AND claim_token = ?""",
            (claim["attempt_id"], claim["job_id"], claim["claim_token"]),
        ).fetchone()
        if owned is None:
            raise DerivedJobConflict("The saved-analysis worker lost its claim")

    def finalize(db: sqlite3.Connection, created: bool) -> None:
        changed = db.execute(
            """UPDATE derived_analysis_job_attempts
               SET state = 'completed', finished_at = ?, outcome = ?, result_id = ?, error = NULL
               WHERE attempt_id = ? AND job_id = ? AND state = 'running' AND claim_token = ?""",
            (utc_now(), "created" if created else "reused", row[11], claim["attempt_id"],
             claim["job_id"], claim["claim_token"]),
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


def fail_claimed_derived_job(db_path: Path, claim: dict, error: Exception) -> None:
    message = str(error).strip() or error.__class__.__name__
    with connect_database(db_path) as db:
        db.execute("BEGIN IMMEDIATE")
        db.execute(
            """UPDATE derived_analysis_job_attempts
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
                "SELECT source_run_id FROM derived_analysis_jobs WHERE job_id = ?", (claim["job_id"],)
            ).fetchone()
            run_id = found[0] if found else None
        if not run_id:
            raise DerivedJobConflict("The saved-analysis job definition is unavailable")
        execute_claimed_derived_job(
            db_path, claim, _run_local_path(data_dir, run_id),
        )
    except Exception as exc:
        fail_claimed_derived_job(db_path, claim, exc)
    return True


def _worker_loop(db_path: Path, data_dir: Path, stop: threading.Event) -> None:
    try:
        while not stop.is_set() and run_next_derived_job(db_path, data_dir):
            pass
    finally:
        path = Path(db_path).resolve()
        with _WORKERS_LOCK:
            current = _WORKERS.get(path)
            if current and current[0] is stop:
                _WORKERS.pop(path, None)
            if not stop.is_set():
                with connect_database(path, read_only=True) as db:
                    queued = db.execute(
                        "SELECT 1 FROM derived_analysis_job_attempts WHERE state = 'queued' LIMIT 1"
                    ).fetchone()
                if queued:
                    start_derived_job_worker(path, data_dir)


def start_derived_job_worker(db_path: Path, data_dir: Path | None = None) -> None:
    path = Path(db_path).resolve()
    root = Path(data_dir) if data_dir is not None else path.parent
    with _WORKERS_LOCK:
        current = _WORKERS.get(path)
        if current and current[1].is_alive():
            return
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
            """UPDATE derived_analysis_job_attempts
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
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'derived_analysis_jobs'"
        ).fetchone()
        if available is None:
            return {"items": [], "total": 0, "limit": limit, "offset": offset,
                    "has_more": False}
        total = db.execute("SELECT COUNT(*) FROM derived_analysis_jobs").fetchone()[0]
        rows = db.execute(
            f"""SELECT {_JOB_COLUMNS} FROM derived_analysis_jobs
                ORDER BY requested_at DESC, job_id DESC LIMIT ? OFFSET ?""",
            (limit, offset),
        ).fetchall()
        items = [_job_dict(db, row) for row in rows]
    return {"items": items, "total": total, "limit": limit, "offset": offset,
            "has_more": offset + len(items) < total}


def scan_run_job_statuses(db_path: Path, run_ids: list[str], data_dir: Path) -> dict[str, dict]:
    result: dict[str, dict] = {}
    if not run_ids or not Path(db_path).is_file():
        return result
    with connect_database(db_path, read_only=True) as db:
        db.execute("BEGIN")
        jobs_available = db.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'derived_analysis_jobs'"
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
                    f"""SELECT {_JOB_COLUMNS} FROM derived_analysis_jobs
                        WHERE source_run_id = ? ORDER BY requested_at DESC, job_id DESC LIMIT 1""",
                    (run_id,),
                ).fetchone()
            result[run_id] = {
                "eligible": eligible, "eligibility_reason": reason,
                "current_job": _job_dict(db, row) if row else None,
                "current_contract": frozen is not None,
            }
    return result
