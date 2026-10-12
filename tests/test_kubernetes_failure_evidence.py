from __future__ import annotations

import argparse
import fcntl
import json
import hashlib
from pathlib import Path
import sqlite3
import subprocess
import sys

import pytest


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import nct_kubernetes_failure_evidence as evidence  # noqa: E402
import nct_kubernetes_recovery as recovery  # noqa: E402
import probe_nct_writer_lock as lock_probe  # noqa: E402


RUNNING_JOB = "pipeline_job_running"
QUEUED_JOB = "pipeline_job_queued"
INTENT_ID = "intake_intent_12345678"


def create_data(root: Path) -> None:
    root.mkdir()
    (root / ".analyzer.db.nct-writer.lock").write_bytes(b"")
    db = sqlite3.connect(root / "analyzer.db")
    db.executescript(
        """
        PRAGMA foreign_keys=ON;
        CREATE TABLE pipeline_jobs (
          job_id TEXT PRIMARY KEY, job_type TEXT NOT NULL, source_kind TEXT NOT NULL,
          source_ref TEXT, requested_by TEXT NOT NULL
        );
        CREATE TABLE pipeline_job_attempts (
          attempt_id TEXT PRIMARY KEY, job_id TEXT NOT NULL REFERENCES pipeline_jobs(job_id),
          attempt_number INTEGER NOT NULL, state TEXT NOT NULL, claim_token TEXT,
          requested_by TEXT NOT NULL, requested_at TEXT NOT NULL, started_at TEXT,
          finished_at TEXT, outcome TEXT, result_id TEXT, output_kind TEXT,
          output_id TEXT, error TEXT
        );
        CREATE TABLE pipeline_job_requests (
          request_token TEXT PRIMARY KEY, job_id TEXT NOT NULL REFERENCES pipeline_jobs(job_id),
          request_kind TEXT NOT NULL, requested_by TEXT NOT NULL, requested_at TEXT NOT NULL
        );
        CREATE TABLE pipeline_admission_intents (
          intent_id TEXT PRIMARY KEY, intent_kind TEXT NOT NULL, source_kind TEXT NOT NULL,
          source_id TEXT NOT NULL, actor TEXT NOT NULL, request_token TEXT NOT NULL,
          state TEXT NOT NULL, activity_state TEXT NOT NULL, admitted_job_id TEXT,
          last_error TEXT
        );
        """
    )
    for job_id, state in ((RUNNING_JOB, "running"), (QUEUED_JOB, "queued")):
        db.execute(
            "INSERT INTO pipeline_jobs VALUES (?, 'nmap_scope_assessment', 'nmap_scan_run', ?, 'analyst')",
            (job_id, f"source-{job_id}"),
        )
        db.execute(
            "INSERT INTO pipeline_job_requests VALUES (?, ?, 'initial', 'analyst', '2026-10-12T00:00:00Z')",
            (f"request-{job_id}", job_id),
        )
        db.execute(
            """INSERT INTO pipeline_job_attempts
               VALUES (?, ?, 1, ?, ?, 'analyst', '2026-10-12T00:00:00Z',
                       ?, NULL, NULL, NULL, NULL, NULL, NULL)""",
            (
                f"attempt-{job_id}", job_id, state,
                "claim-running" if state == "running" else None,
                "2026-10-12T00:01:00Z" if state == "running" else None,
            ),
        )
    db.execute(
        """INSERT INTO pipeline_admission_intents VALUES
           (?, 'automated_nmap_scope', 'nmap_scan_run', 'source-1', 'analyst',
            'intent-request', 'pending', 'waiting', NULL, NULL)""",
        (INTENT_ID,),
    )
    db.commit()
    db.close()


def snapshot_args(root: Path, output: Path, mode: str, phase: str, restart_count: int = 0) -> argparse.Namespace:
    health = root.parent / f"health-{output.stem}.json"
    transitions = [] if mode == "cold" else ["2026-10-12T00:00:00Z|readiness|ready"]
    if mode == "runtime" and phase != "before-failure":
        transitions = [
            "2026-10-12T00:03:00Z|startup|started",
            "2026-10-12T00:04:00Z|readiness|ready",
        ]
    if transitions:
        health.write_text(json.dumps({"transitions": transitions}), encoding="utf-8")
    restore_receipt = root.parent / "gate4a-restore-receipt.json"
    if not restore_receipt.exists():
        body = {
            "schema_version": recovery.SCHEMA_VERSION,
            "status": "restore_verification_passed",
            "backup_id": "backup-20261012",
            "source_image": "registry.example/nct@sha256:" + "a" * 64,
            "source_application_version": "0.14.0-dev",
            "source_build_id": "build-123",
            "manifest_sha256": "1" * 64,
            "backup_receipt_sha256": "4" * 64,
            "archive_sha256": "2" * 64,
            "inventory_root_sha256": "3" * 64,
            "target_qualification_report_digest": "e" * 64,
            "source_qualification_report_digest": "5" * 64,
            "backup_qualification_report_digest": "6" * 64,
            "source_and_backup_preserved": True,
            "source_storage_identity": {"pvc_uid": "source-pvc-12345678", "bound_volume_uid": "source-pv-12345678"},
            "backup_storage_identity": {"pvc_uid": "backup-pvc-12345678", "bound_volume_uid": "backup-pv-12345678"},
            "target_storage_identity": {
                "pvc_uid": "44444444-2222-4333-8444-555555555555",
                "bound_volume_uid": "55555555-2222-4333-8444-555555555555",
            },
        }
        body["receipt_sha256"] = recovery._digest(body)
        restore_receipt.write_text(json.dumps(body), encoding="utf-8")
    args = argparse.Namespace(
        mode=mode,
        phase=phase,
        data_root=root,
        tracked_job_id=[RUNNING_JOB, QUEUED_JOB],
        tracked_intent_id=[INTENT_ID],
        health_transitions=health if transitions else None,
        health_transition=[],
        output=output,
        scenario_id="forced-stop-20261012",
        scenario_kind="forced-termination",
        image="registry.example/nct@sha256:" + "a" * 64,
        application_version="0.14.0-dev",
        build_id="build-123",
        deployment_uid="11111111-2222-4333-8444-555555555555",
        deployment_generation=7,
        pod_uid="22222222-2222-4333-8444-555555555555",
        container_restart_count=restart_count,
        node_uid="33333333-2222-4333-8444-555555555555",
        storage_attachment_identity="csi-attachment-12345678",
        pvc_uid="44444444-2222-4333-8444-555555555555",
        bound_volume_uid="55555555-2222-4333-8444-555555555555",
        qualification_report_digest="e" * 64,
        gate4a_restore_receipt=restore_receipt,
        validation_root=root.parent,
        max_files=10_000,
        max_bytes=1024**3,
        max_seconds=60,
    )
    evidence._validate_snapshot(args)
    return args


def lock_args(root: Path, output: Path, expect: str, phase: str) -> argparse.Namespace:
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


def test_snapshot_and_verifier_preserve_interrupted_queued_retry_and_receipts(tmp_path: Path) -> None:
    root = tmp_path / "data"
    create_data(root)
    source_before = {
        path.relative_to(root).as_posix(): (path.read_bytes(), path.stat().st_mtime_ns)
        for path in root.rglob("*") if path.is_file()
    }
    before_cold_path = tmp_path / "before-cold.json"
    before_runtime_path = tmp_path / "before-runtime.json"
    evidence.snapshot(snapshot_args(root, before_cold_path, "cold", "before-failure"))
    assert {
        path.relative_to(root).as_posix(): (path.read_bytes(), path.stat().st_mtime_ns)
        for path in root.rglob("*") if path.is_file()
    } == source_before
    evidence.snapshot(snapshot_args(root, before_runtime_path, "runtime", "before-failure"))

    active_lock_path = tmp_path / "active-lock.json"
    holder = subprocess.Popen(
        [
            sys.executable,
            "-c",
            (
                "import fcntl,sys; f=open(sys.argv[1],'r+b'); "
                "fcntl.lockf(f,fcntl.LOCK_EX,1,0); print('ready',flush=True); sys.stdin.read()"
            ),
            str(root / ".analyzer.db.nct-writer.lock"),
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        assert holder.stdout is not None
        assert holder.stdout.readline().strip() == "ready"
        lock_probe.probe(lock_args(root, active_lock_path, "contended", "old-writer-active"))
    finally:
        if holder.stdin:
            holder.stdin.close()
        holder.wait(timeout=5)

    db = sqlite3.connect(root / "analyzer.db")
    db.execute(
        """UPDATE pipeline_job_attempts
           SET state='interrupted', finished_at='2026-10-12T00:02:00Z', claim_token=NULL,
               error='Application stopped while this attempt was running'
           WHERE job_id=?""",
        (RUNNING_JOB,),
    )
    db.execute(
        """UPDATE pipeline_job_attempts
           SET state='completed', started_at='2026-10-12T00:02:00Z', finished_at='2026-10-12T00:03:00Z',
               outcome='created', result_id='result-queued', output_kind='derived_result',
               output_id='result-queued' WHERE job_id=?""",
        (QUEUED_JOB,),
    )
    db.execute(
        "UPDATE pipeline_admission_intents SET state='admitted', activity_state='complete', admitted_job_id=? WHERE intent_id=?",
        (QUEUED_JOB, INTENT_ID),
    )
    db.execute(
        "INSERT INTO pipeline_job_requests VALUES ('intent-request', ?, 'automatic', 'analyst', '2026-10-12T00:03:00Z')",
        (QUEUED_JOB,),
    )
    db.commit()
    db.close()
    after_runtime_path = tmp_path / "after-runtime.json"
    evidence.snapshot(snapshot_args(root, after_runtime_path, "runtime", "after-restart", 1))

    db = sqlite3.connect(root / "analyzer.db")
    db.execute(
        "INSERT INTO pipeline_job_requests VALUES ('retry-token', ?, 'retry', 'analyst', '2026-10-12T00:04:00Z')",
        (RUNNING_JOB,),
    )
    db.execute(
        """INSERT INTO pipeline_job_attempts
           VALUES ('retry-attempt', ?, 2, 'completed', 'retry-claim', 'analyst',
                   '2026-10-12T00:04:00Z', '2026-10-12T00:04:00Z', '2026-10-12T00:05:00Z',
                   'reused', 'result-running', 'derived_result', 'result-running', NULL)""",
        (RUNNING_JOB,),
    )
    db.commit()
    db.close()
    after_retry_path = tmp_path / "after-retry.json"
    evidence.snapshot(snapshot_args(root, after_retry_path, "runtime", "after-retry", 1))
    after_cold_path = tmp_path / "after-cold.json"
    evidence.snapshot(snapshot_args(root, after_cold_path, "cold", "after-retry", 1))

    released_lock_path = tmp_path / "released-lock.json"
    lock_probe.probe(lock_args(root, released_lock_path, "available", "replacement-writer-released"))
    selected_before = tmp_path / "evidence-before.xml"
    selected_after = tmp_path / "evidence-after.xml"
    selected_before.write_bytes(b"retained evidence\n")
    selected_after.write_bytes(b"retained evidence\n")
    result_path = tmp_path / "verified.json"
    orchestration_path = tmp_path / "orchestration.json"
    orchestration_path.write_text(json.dumps({
        "schema_version": 1,
        "scenario": {"id": "forced-stop-20261012", "kind": "forced-termination"},
        "deployment_uid": "11111111-2222-4333-8444-555555555555",
        "generation_before": 7, "generation_after": 7,
        "old": {"pod_uid": "22222222-2222-4333-8444-555555555555", "node_uid": "33333333-2222-4333-8444-555555555555", "container_restart_count": 0, "storage_attachment_identity": "csi-attachment-12345678"},
        "new": {"pod_uid": "22222222-2222-4333-8444-555555555555", "node_uid": "33333333-2222-4333-8444-555555555555", "container_restart_count": 1, "storage_attachment_identity": "csi-attachment-12345678"},
        "max_ready_pods": 1, "max_writer_owners": 1,
        "events": [
            {"event": "before_ready", "at": "2026-10-12T00:00:00Z"},
            {"event": "readiness_lost", "at": "2026-10-12T00:01:00Z"},
            {"event": "old_writer_stopped", "at": "2026-10-12T00:02:00Z"},
            {"event": "replacement_created", "at": "2026-10-12T00:03:00Z"},
            {"event": "after_ready", "at": "2026-10-12T00:04:00Z"},
        ],
        "fencing": {"required": False}, "detachment": {"required": False},
        "no_replacement_before_fencing_and_detachment": False,
    }), encoding="utf-8")
    pod = {
        "pod_uid": "22222222-2222-4333-8444-555555555555",
        "node_uid": "33333333-2222-4333-8444-555555555555",
        "phase": "Running", "ready": True,
        "storage_attachment_identity": "csi-attachment-12345678",
    }
    cluster_observations = tmp_path / "cluster-observations.json"
    cluster_observations.write_text(json.dumps({
        "schema_version": 1,
        "scenario": {"id": "forced-stop-20261012", "kind": "forced-termination"},
        "samples": [
            {"event": "before_ready", "observed_at": "2026-10-12T00:00:00Z", "deployment_uid": "11111111-2222-4333-8444-555555555555", "deployment_generation": 7, "pods": [pod], "writer_owners_observed": 1},
            {"event": "readiness_lost", "observed_at": "2026-10-12T00:01:00Z", "deployment_uid": "11111111-2222-4333-8444-555555555555", "deployment_generation": 7, "pods": [dict(pod, ready=False)], "writer_owners_observed": 0},
            {"event": "old_writer_stopped", "observed_at": "2026-10-12T00:02:00Z", "deployment_uid": "11111111-2222-4333-8444-555555555555", "deployment_generation": 7, "pods": [dict(pod, ready=False)], "writer_owners_observed": 0},
            {"event": "replacement_created", "observed_at": "2026-10-12T00:03:00Z", "deployment_uid": "11111111-2222-4333-8444-555555555555", "deployment_generation": 7, "pods": [dict(pod, ready=False)], "writer_owners_observed": 0},
            {"event": "after_ready", "observed_at": "2026-10-12T00:04:00Z", "deployment_uid": "11111111-2222-4333-8444-555555555555", "deployment_generation": 7, "pods": [pod], "writer_owners_observed": 1},
        ],
    }), encoding="utf-8")
    result = evidence.verify(
        argparse.Namespace(
            before_runtime=before_runtime_path,
            after_runtime=after_runtime_path,
            before_cold=before_cold_path,
            after_cold=after_cold_path,
            after_retry=after_retry_path,
            active_lock_receipt=active_lock_path,
            released_lock_receipt=released_lock_path,
            pre_replacement_lock_receipt=None,
            selected_evidence_before=selected_before,
            selected_evidence_after=selected_after,
            orchestration_record=orchestration_path,
            cluster_observations=cluster_observations,
            fencing_evidence=None,
            detachment_evidence=None,
            max_evidence_bytes=1024**2,
            max_provider_bytes=1024**2,
            max_seconds=60,
            output=result_path,
        )
    )

    assert result["status"] == "gate4b_scenario_verified"
    assert result["checks"]["running_attempts_interrupted"] == 1
    assert result["checks"]["queued_attempts_preserved_or_completed"] == 1
    assert result["checks"]["completed_retry_verified"] is True
    assert json.loads(result_path.read_text())["attestation"] == result["attestation"]


def test_verifier_rejects_disappearing_queued_work(tmp_path: Path) -> None:
    before = {
        "work": {
            "jobs": {
                RUNNING_JOB: {
                    "job_id": RUNNING_JOB, "job_type": "type", "source_kind": "source",
                    "source_ref": "ref", "requested_by": "analyst", "requests": [],
                    "attempts": [{"attempt_id": "a", "attempt_number": 1, "state": "running"}],
                }
            },
            "admission_intents": {},
        }
    }
    after = {"work": {"jobs": {}, "admission_intents": {}}}
    try:
        evidence._verify_work(before, after, None)
    except evidence.FailureEvidenceError as exc:
        assert "disappeared" in str(exc)
    else:
        raise AssertionError("disappearing work must fail verification")


def test_work_verifier_requires_pending_admission_intent() -> None:
    attempt = {
        "attempt_id": "running-1", "attempt_number": 1, "state": "running",
        "outcome": None, "result_id": None, "output_kind": None, "output_id": None,
    }
    queued = dict(attempt, attempt_id="queued-1", state="queued")
    before = {"work": {"jobs": {
        "running": {"job_id": "running", "job_type": "t", "source_kind": "s", "source_ref": "r", "requested_by": "a", "attempts": [attempt], "requests": []},
        "queued": {"job_id": "queued", "job_type": "t", "source_kind": "s", "source_ref": "q", "requested_by": "a", "attempts": [queued], "requests": []},
    }, "admission_intents": {}}}
    interrupted = dict(attempt, state="interrupted")
    after = {"work": {"jobs": {
        "running": dict(before["work"]["jobs"]["running"], attempts=[interrupted]),
        "queued": before["work"]["jobs"]["queued"],
    }, "admission_intents": {}}}
    with pytest.raises(evidence.FailureEvidenceError, match="pending admission intent"):
        evidence._verify_work(before, after, after)


def test_node_loss_orchestration_binds_fencing_detachment_and_distinct_attachment(tmp_path: Path) -> None:
    fencing = tmp_path / "fencing.txt"
    detachment = tmp_path / "detachment.txt"
    fencing.write_text("provider confirms old node fenced", encoding="utf-8")
    detachment.write_text("provider confirms old attachment detached", encoding="utf-8")
    old_runtime = {
        "deployment_uid": "deployment-12345678", "deployment_generation": 7,
        "pod_uid": "pod-old-12345678", "node_uid": "node-old-12345678",
        "container_restart_count": 0, "storage_attachment_identity": "attachment-old-12345678",
    }
    new_runtime = dict(
        old_runtime, pod_uid="pod-new-12345678", node_uid="node-new-12345678",
        storage_attachment_identity="attachment-new-12345678",
    )
    record = {
        "schema_version": 1,
        "scenario": {"id": "node-loss-20261012", "kind": "node-loss"},
        "deployment_uid": old_runtime["deployment_uid"],
        "generation_before": 7, "generation_after": 7,
        "old": old_runtime, "new": new_runtime,
        "max_ready_pods": 1, "max_writer_owners": 1,
        "events": [
            {"event": "before_ready", "at": "2026-10-12T00:00:00Z"},
            {"event": "readiness_lost", "at": "2026-10-12T00:01:00Z"},
            {"event": "node_fenced", "at": "2026-10-12T00:02:00Z"},
            {"event": "old_writer_stopped", "at": "2026-10-12T00:02:00Z"},
            {"event": "storage_detached", "at": "2026-10-12T00:03:00Z"},
            {"event": "storage_attached", "at": "2026-10-12T00:04:00Z"},
            {"event": "pre_replacement_lock_passed", "at": "2026-10-12T00:05:00Z"},
            {"event": "replacement_created", "at": "2026-10-12T00:06:00Z"},
            {"event": "after_ready", "at": "2026-10-12T00:07:00Z"},
        ],
        "fencing": {
            "required": True, "old_node_uid": old_runtime["node_uid"], "operator": "infra-op",
            "completed_at": "2026-10-12T00:02:00Z", "evidence_sha256": hashlib.sha256(fencing.read_bytes()).hexdigest(),
        },
        "detachment": {
            "required": True, "old_attachment_identity": old_runtime["storage_attachment_identity"], "operator": "storage-op",
            "completed_at": "2026-10-12T00:03:00Z", "evidence_sha256": hashlib.sha256(detachment.read_bytes()).hexdigest(),
        },
        "no_replacement_before_fencing_and_detachment": True,
    }
    record_path = tmp_path / "orchestration.json"
    record_path.write_text(json.dumps(record), encoding="utf-8")
    args = argparse.Namespace(
        orchestration_record=record_path, fencing_evidence=fencing, detachment_evidence=detachment,
        max_provider_bytes=1024**2,
    )
    before = {"scenario": record["scenario"], "runtime": old_runtime}
    after = {"scenario": record["scenario"], "runtime": new_runtime}
    observed, external = evidence._verify_orchestration(args, before, after)
    assert observed == record
    assert set(external) == {"fencing", "detachment"}
    old_pod = {"pod_uid": old_runtime["pod_uid"], "node_uid": old_runtime["node_uid"], "phase": "Running", "ready": True, "storage_attachment_identity": old_runtime["storage_attachment_identity"]}
    new_pod = {"pod_uid": new_runtime["pod_uid"], "node_uid": new_runtime["node_uid"], "phase": "Running", "ready": True, "storage_attachment_identity": new_runtime["storage_attachment_identity"]}
    samples = []
    for event in record["events"]:
        sample = {"event": event["event"], "observed_at": event["at"], "deployment_uid": old_runtime["deployment_uid"], "deployment_generation": 7, "pods": [], "writer_owners_observed": 0}
        if event["event"] == "before_ready":
            sample["pods"] = [old_pod]
            sample["writer_owners_observed"] = 1
        elif event["event"] in {"readiness_lost", "node_fenced", "old_writer_stopped"}:
            sample["pods"] = [dict(old_pod, ready=False)]
        elif event["event"] == "storage_detached":
            sample["attachments"] = [{"identity": old_runtime["storage_attachment_identity"], "state": "detached", "node_uid": old_runtime["node_uid"]}]
        elif event["event"] == "replacement_created":
            sample["pods"] = [dict(new_pod, ready=False)]
        elif event["event"] == "after_ready":
            sample["pods"] = [new_pod]
            sample["writer_owners_observed"] = 1
        if event["event"] in {"storage_attached", "pre_replacement_lock_passed", "replacement_created", "after_ready"}:
            sample["attachments"] = [{"identity": new_runtime["storage_attachment_identity"], "state": "attached", "node_uid": new_runtime["node_uid"]}]
        samples.append(sample)
    cluster_path = tmp_path / "node-loss-observations.json"
    cluster_path.write_text(json.dumps({"schema_version": 1, "scenario": record["scenario"], "samples": samples}), encoding="utf-8")
    args.cluster_observations = cluster_path
    cluster = evidence._verify_cluster_observations(
        args, before, after, record,
        ["2026-10-12T00:00:00Z|readiness|ready"],
        ["2026-10-12T00:06:00Z|startup|started", "2026-10-12T00:07:00Z|readiness|ready"],
    )
    assert cluster["max_ready_pods"] == 1
    assert cluster["max_writer_owners"] == 1
    assert cluster["pre_replacement_generation"] == 7

    duplicate_old_state = json.loads(json.dumps(samples))
    detached_sample = next(item for item in duplicate_old_state if item["event"] == "storage_detached")
    detached_sample["attachments"].append({"identity": old_runtime["storage_attachment_identity"], "state": "attached", "node_uid": old_runtime["node_uid"]})
    cluster_path.write_text(json.dumps({"schema_version": 1, "scenario": record["scenario"], "samples": duplicate_old_state}), encoding="utf-8")
    with pytest.raises(evidence.FailureEvidenceError, match="old attachment active"):
        evidence._verify_cluster_observations(
            args, before, after, record,
            ["2026-10-12T00:00:00Z|readiness|ready"],
            ["2026-10-12T00:06:00Z|startup|started", "2026-10-12T00:07:00Z|readiness|ready"],
        )

    old_active_after_attach = json.loads(json.dumps(samples))
    attached_sample = next(item for item in old_active_after_attach if item["event"] == "storage_attached")
    attached_sample["attachments"].append({"identity": old_runtime["storage_attachment_identity"], "state": "attached", "node_uid": old_runtime["node_uid"]})
    cluster_path.write_text(json.dumps({"schema_version": 1, "scenario": record["scenario"], "samples": old_active_after_attach}), encoding="utf-8")
    with pytest.raises(evidence.FailureEvidenceError, match="old attachment active"):
        evidence._verify_cluster_observations(
            args, before, after, record,
            ["2026-10-12T00:00:00Z|readiness|ready"],
            ["2026-10-12T00:06:00Z|startup|started", "2026-10-12T00:07:00Z|readiness|ready"],
        )

    stale_old_pod = json.loads(json.dumps(samples))
    replacement_sample = next(item for item in stale_old_pod if item["event"] == "replacement_created")
    replacement_sample["pods"].append(dict(old_pod, ready=False))
    cluster_path.write_text(json.dumps({"schema_version": 1, "scenario": record["scenario"], "samples": stale_old_pod}), encoding="utf-8")
    with pytest.raises(evidence.FailureEvidenceError, match="retain the old Pod"):
        evidence._verify_cluster_observations(
            args, before, after, record,
            ["2026-10-12T00:00:00Z|readiness|ready"],
            ["2026-10-12T00:06:00Z|startup|started", "2026-10-12T00:07:00Z|readiness|ready"],
        )

    cluster_path.write_text(json.dumps({"schema_version": 1, "scenario": record["scenario"], "samples": samples}), encoding="utf-8")
    record["no_replacement_before_fencing_and_detachment"] = False
    record_path.write_text(json.dumps(record), encoding="utf-8")
    with pytest.raises(evidence.FailureEvidenceError, match="replacement was held"):
        evidence._verify_orchestration(args, before, after)


def test_controlled_rescheduling_requires_one_generation_step_after_pre_probe(tmp_path: Path) -> None:
    scenario = {"id": "reschedule-20261012", "kind": "controlled-rescheduling"}
    old = {
        "deployment_uid": "deployment-12345678", "deployment_generation": 7,
        "pod_uid": "pod-old-12345678", "node_uid": "node-old-12345678",
        "storage_attachment_identity": "attachment-old-12345678", "container_restart_count": 0,
    }
    new = dict(
        old, deployment_generation=8, pod_uid="pod-new-12345678",
        node_uid="node-new-12345678", storage_attachment_identity="attachment-new-12345678",
    )
    event_names = [
        "before_ready", "readiness_lost", "old_writer_stopped", "storage_detached",
        "storage_attached", "pre_replacement_lock_passed", "replacement_created", "after_ready",
    ]
    times = {name: f"2026-10-12T00:{index:02d}:00Z" for index, name in enumerate(event_names)}
    record = {
        "events": [{"event": name, "at": times[name]} for name in event_names],
        "max_ready_pods": 1, "max_writer_owners": 1,
    }
    old_pod = {"pod_uid": old["pod_uid"], "node_uid": old["node_uid"], "phase": "Running", "ready": True, "storage_attachment_identity": old["storage_attachment_identity"]}
    new_pod = {"pod_uid": new["pod_uid"], "node_uid": new["node_uid"], "phase": "Running", "ready": True, "storage_attachment_identity": new["storage_attachment_identity"]}
    samples = []
    for name in event_names:
        sample = {
            "event": name, "observed_at": times[name], "deployment_uid": old["deployment_uid"],
            "deployment_generation": 8 if name in {"replacement_created", "after_ready"} else 7,
            "pods": [], "writer_owners_observed": 0,
        }
        if name == "before_ready":
            sample["pods"] = [old_pod]
            sample["writer_owners_observed"] = 1
        elif name in {"readiness_lost", "old_writer_stopped"}:
            sample["pods"] = [dict(old_pod, ready=False)]
        elif name == "replacement_created":
            sample["pods"] = [dict(new_pod, ready=False)]
        elif name == "after_ready":
            sample["pods"] = [new_pod]
            sample["writer_owners_observed"] = 1
        if name == "storage_detached":
            sample["attachments"] = [{"identity": old["storage_attachment_identity"], "node_uid": old["node_uid"], "state": "detached"}]
        elif name in {"storage_attached", "pre_replacement_lock_passed", "replacement_created", "after_ready"}:
            sample["attachments"] = [{"identity": new["storage_attachment_identity"], "node_uid": new["node_uid"], "state": "attached"}]
        samples.append(sample)
    path = tmp_path / "controlled-observations.json"
    path.write_text(json.dumps({"schema_version": 1, "scenario": scenario, "samples": samples}), encoding="utf-8")
    args = argparse.Namespace(cluster_observations=path)
    before = {"scenario": scenario, "runtime": old}
    after = {"scenario": scenario, "runtime": new}
    result = evidence._verify_cluster_observations(
        args, before, after, record,
        [f"{times['before_ready']}|readiness|ready"],
        [f"{times['replacement_created']}|startup|started", f"{times['after_ready']}|readiness|ready"],
    )
    assert result["pre_replacement_generation"] == 7

    after["runtime"] = dict(new, deployment_generation=9)
    invalid_generation_samples = json.loads(json.dumps(samples))
    for sample in invalid_generation_samples:
        if sample["event"] in {"replacement_created", "after_ready"}:
            sample["deployment_generation"] = 9
    path.write_text(json.dumps({"schema_version": 1, "scenario": scenario, "samples": invalid_generation_samples}), encoding="utf-8")
    with pytest.raises(evidence.FailureEvidenceError, match="generation transition"):
        evidence._verify_cluster_observations(
            args, before, after, record,
            [f"{times['before_ready']}|readiness|ready"],
            [f"{times['replacement_created']}|startup|started", f"{times['after_ready']}|readiness|ready"],
        )


def test_recreate_observations_reject_old_pod_after_replacement(tmp_path: Path) -> None:
    scenario = {"id": "recreate-20261012", "kind": "recreate-replacement"}
    old = {
        "deployment_uid": "deployment-12345678", "deployment_generation": 7,
        "pod_uid": "pod-old-12345678", "node_uid": "node-a-12345678",
        "storage_attachment_identity": "attachment-12345678", "container_restart_count": 0,
    }
    new = dict(old, deployment_generation=8, pod_uid="pod-new-12345678")
    events = [
        {"event": "before_ready", "at": "2026-10-12T00:00:00Z"},
        {"event": "readiness_lost", "at": "2026-10-12T00:01:00Z"},
        {"event": "old_writer_stopped", "at": "2026-10-12T00:02:00Z"},
        {"event": "replacement_created", "at": "2026-10-12T00:03:00Z"},
        {"event": "after_ready", "at": "2026-10-12T00:04:00Z"},
    ]
    old_pod = {"pod_uid": old["pod_uid"], "node_uid": old["node_uid"], "phase": "Running", "ready": True, "storage_attachment_identity": old["storage_attachment_identity"]}
    new_pod = {"pod_uid": new["pod_uid"], "node_uid": new["node_uid"], "phase": "Running", "ready": True, "storage_attachment_identity": new["storage_attachment_identity"]}
    samples = [
        {"event": "before_ready", "observed_at": events[0]["at"], "deployment_uid": old["deployment_uid"], "deployment_generation": 7, "pods": [old_pod], "writer_owners_observed": 1},
        {"event": "readiness_lost", "observed_at": events[1]["at"], "deployment_uid": old["deployment_uid"], "deployment_generation": 7, "pods": [dict(old_pod, ready=False)], "writer_owners_observed": 0},
        {"event": "old_writer_stopped", "observed_at": events[2]["at"], "deployment_uid": old["deployment_uid"], "deployment_generation": 7, "pods": [], "writer_owners_observed": 0},
        {"event": "replacement_created", "observed_at": events[3]["at"], "deployment_uid": old["deployment_uid"], "deployment_generation": 8, "pods": [dict(new_pod, ready=False), dict(old_pod, ready=False)], "writer_owners_observed": 0},
        {"event": "after_ready", "observed_at": events[4]["at"], "deployment_uid": old["deployment_uid"], "deployment_generation": 8, "pods": [new_pod], "writer_owners_observed": 1},
    ]
    path = tmp_path / "recreate-observations.json"
    path.write_text(json.dumps({"schema_version": 1, "scenario": scenario, "samples": samples}), encoding="utf-8")
    with pytest.raises(evidence.FailureEvidenceError, match="retain the old Pod"):
        evidence._verify_cluster_observations(
            argparse.Namespace(cluster_observations=path),
            {"scenario": scenario, "runtime": old}, {"scenario": scenario, "runtime": new},
            {"events": events, "max_ready_pods": 1, "max_writer_owners": 1},
            ["2026-10-12T00:00:00Z|readiness|ready"],
            ["2026-10-12T00:03:00Z|startup|started", "2026-10-12T00:04:00Z|readiness|ready"],
        )


def test_external_file_size_is_rejected_before_streaming(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    class ExplodingReader:
        def read(self, _size: int) -> bytes:
            raise AssertionError("oversized evidence must not be read")

    class ReaderContext:
        def __enter__(self):
            return ExplodingReader(), type("Opened", (), {"st_size": 4096})()

        def __exit__(self, *_args):
            return False

    monkeypatch.setattr(evidence.recovery, "_regular_reader", lambda *_args, **_kwargs: ReaderContext())
    with pytest.raises(evidence.FailureEvidenceError, match="declared byte limit"):
        evidence._file_sha256(tmp_path / "oversized.bin", max_bytes=1024)
