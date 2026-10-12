from __future__ import annotations

import argparse
import json
from pathlib import Path
import sqlite3
import subprocess
import sys


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from app.database import connect_database  # noqa: E402
from app.derived_jobs import init_derived_job_storage, recover_interrupted_derived_jobs  # noqa: E402
import probe_nct_writer_lock as lock_probe  # noqa: E402


def probe_args(root: Path, expect: str, phase: str, output: Path) -> argparse.Namespace:
    args = argparse.Namespace(
        lock_path=root / ".analyzer.db.nct-writer.lock",
        expect=expect,
        scenario_id="forced-stop-20261012",
        scenario_kind="forced-termination",
        phase=phase,
        image="registry.example/nct@sha256:" + "a" * 64,
        application_version="0.14.0-dev",
        build_id="build-123",
        deployment_uid="11111111-2222-4333-8444-555555555555",
        deployment_generation=7,
        pod_uid="22222222-2222-4333-8444-555555555555",
        node_uid="33333333-2222-4333-8444-555555555555",
        storage_attachment_identity="csi-attachment-12345678",
        pvc_uid="44444444-2222-4333-8444-555555555555",
        bound_volume_uid="55555555-2222-4333-8444-555555555555",
        qualification_report_digest="e" * 64,
        receipt_path=output,
    )
    lock_probe._validate(args)
    return args


def insert_job(db: sqlite3.Connection, job_id: str, requested_at: str) -> None:
    db.execute(
        """INSERT INTO pipeline_jobs (
               job_id, job_key, job_type, source_run_id, source_observation_id,
               source_status, source_sha256, source_size_bytes, target_family,
               target_analysis_version, target_payload_schema_version,
               target_parameters_json, target_computation_key, target_result_id,
               source_kind, source_ref, definition_json, requested_by, requested_at
           ) VALUES (?, ?, 'nmap_base_analysis', NULL, ?, 'complete', ?, 1,
                     'test_family', '1', 1, '{}', ?, ?, 'scan_run', ?, '{}',
                     'analyst', ?)""",
        (
            job_id, f"key-{job_id}", f"observation-{job_id}", "a" * 64,
            f"computation-{job_id}", f"result-{job_id}", f"source-{job_id}", requested_at,
        ),
    )
    db.execute(
        """INSERT INTO pipeline_job_requests
           (request_token, job_id, request_kind, requested_by, requested_at)
           VALUES (?, ?, 'initial', 'analyst', ?)""",
        (f"request-{job_id}", job_id, requested_at),
    )
    db.execute(
        """INSERT INTO pipeline_job_attempts
           (attempt_id, job_id, attempt_number, state, requested_by, requested_at)
           VALUES (?, ?, 1, 'queued', 'analyst', ?)""",
        (f"attempt-{job_id}", job_id, requested_at),
    )


def test_sigkill_releases_writer_lock_and_restart_recovers_only_running_attempt(tmp_path: Path) -> None:
    root = tmp_path / "data"
    root.mkdir()
    db_path = root / "analyzer.db"
    init_derived_job_storage(db_path)
    with connect_database(db_path) as db:
        db.execute("BEGIN IMMEDIATE")
        insert_job(db, "pipeline_job_running", "2026-10-12T00:00:00Z")
        insert_job(db, "pipeline_job_queued", "2026-10-12T00:01:00Z")

    child_code = """
import json,sys,time
from pathlib import Path
from app.writer_guard import acquire_application_writer_guard
from app.derived_jobs import claim_next_derived_job
db=Path(sys.argv[1])
guard=acquire_application_writer_guard(db)
claim=claim_next_derived_job(db)
print(json.dumps(claim), flush=True)
time.sleep(60)
"""
    child = subprocess.Popen(
        [sys.executable, "-c", child_code, str(db_path)],
        cwd=Path(__file__).resolve().parents[1],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        assert child.stdout is not None
        claim = json.loads(child.stdout.readline())
        assert claim["job_id"] == "pipeline_job_running"
        active = lock_probe.probe(
            probe_args(root, "contended", "old-writer-active", tmp_path / "active.json")
        )
        assert active["writer_lock"]["observed"] == "contended"
        child.kill()
        child.wait(timeout=5)
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=5)

    released = lock_probe.probe(
        probe_args(root, "available", "replacement-writer-released", tmp_path / "released.json")
    )
    assert released["writer_lock"]["observed"] == "available"
    with connect_database(db_path) as db:
        db.execute(
            "UPDATE work_leases SET expires_at='2000-01-01T00:00:00.000Z' WHERE lease_key=?",
            (claim["lease_key"],),
        )
    assert recover_interrupted_derived_jobs(db_path) == 1
    with connect_database(db_path, read_only=True) as db:
        attempts = db.execute(
            """SELECT job_id, attempt_number, state, requested_by, output_id
                 FROM pipeline_job_attempts
                ORDER BY job_id, attempt_number"""
        ).fetchall()
    assert attempts == [
        ("pipeline_job_queued", 1, "queued", "analyst", None),
        ("pipeline_job_running", 1, "interrupted", "analyst", None),
        ("pipeline_job_running", 2, "queued", "system-recovery", None),
    ]
