#!/usr/bin/env python3
"""Record and verify bounded Gate 4B failure-recovery evidence."""
from __future__ import annotations

import argparse
from contextlib import nullcontext
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import sys
import tempfile
import time

import nct_kubernetes_recovery as recovery


SCHEMA_VERSION = 2
TOOL_VERSION = "1"
MAX_REPORT_BYTES = 16 * 1024**2
MAX_INPUT_BYTES = 16 * 1024**2
MAX_TRACKED_ITEMS = 100
MAX_EVIDENCE_REFERENCES = 100_000
MAX_VALUE_CHARS = 512
SCENARIO_RE = re.compile(r"^[a-z0-9][a-z0-9-]{7,79}$")
DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
IMAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]*@sha256:[0-9a-f]{64}$")
HEALTH_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\|(startup|readiness|liveness)\|[a-z0-9_-]{2,32}$"
)


class FailureEvidenceError(ValueError):
    pass


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _file_sha256(path: Path, *, max_bytes: int | None = None) -> tuple[str, int]:
    try:
        digest = hashlib.sha256()
        size = 0
        with recovery._regular_reader(path, "evidence file") as (handle, opened):
            if max_bytes is not None and opened.st_size > max_bytes:
                raise FailureEvidenceError(f"evidence file exceeds its declared byte limit: {path}")
            while chunk := handle.read(1024 * 1024):
                recovery._check_deadline()
                if max_bytes is not None and size + len(chunk) > max_bytes:
                    raise FailureEvidenceError(f"evidence file exceeds its declared byte limit: {path}")
                digest.update(chunk)
                size += len(chunk)
            if size != opened.st_size:
                raise FailureEvidenceError(f"evidence file changed while it was read: {path}")
    except recovery.RecoveryError as exc:
        raise FailureEvidenceError(f"evidence file is missing or unsafe: {path}") from exc
    return digest.hexdigest(), size


def _write(path: Path, value: dict) -> None:
    payload = json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True).encode("utf-8") + b"\n"
    if len(payload) > MAX_REPORT_BYTES:
        raise FailureEvidenceError("failure-acceptance report exceeds its safe size limit")
    if path.is_symlink():
        raise FailureEvidenceError("output must not be a symbolic link")
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        temporary.unlink(missing_ok=True)


def _load(path: Path, label: str) -> dict:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size <= 0 or info.st_size > MAX_INPUT_BYTES:
            raise FailureEvidenceError(f"{label} has an invalid type or size")
        with os.fdopen(fd, "rb") as handle:
            payload = handle.read(MAX_INPUT_BYTES + 1)
        if len(payload) > MAX_INPUT_BYTES:
            raise FailureEvidenceError(f"{label} exceeds its safe size limit")
        value = json.loads(payload.decode("utf-8"))
    except FailureEvidenceError:
        if "fd" in locals():
            try:
                os.close(fd)
            except OSError:
                pass
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise FailureEvidenceError(f"{label} is unreadable") from exc
    if not isinstance(value, dict):
        raise FailureEvidenceError(f"{label} must be a JSON object")
    return value


def _verify_gate4a_receipt(receipt: dict, args: argparse.Namespace) -> str:
    if receipt.get("schema_version") != recovery.SCHEMA_VERSION or receipt.get("status") != "restore_verification_passed":
        raise FailureEvidenceError("Gate 4A restore receipt is not a passing supported receipt")
    supplied = receipt.get("receipt_sha256")
    body = {key: value for key, value in receipt.items() if key != "receipt_sha256"}
    if not DIGEST_RE.fullmatch(str(supplied)) or supplied != recovery._digest(body):
        raise FailureEvidenceError("Gate 4A restore receipt self-digest is invalid")
    target = receipt.get("target_storage_identity")
    if not isinstance(target, dict):
        raise FailureEvidenceError("Gate 4A restore receipt is missing target storage identity")
    if target.get("pvc_uid") != args.pvc_uid or target.get("bound_volume_uid") != args.bound_volume_uid:
        raise FailureEvidenceError("Gate 4A restore receipt belongs to different restored storage")
    if receipt.get("target_qualification_report_digest") != args.qualification_report_digest:
        raise FailureEvidenceError("Gate 4A restore receipt uses different qualification evidence")
    if receipt.get("source_image") != args.image:
        raise FailureEvidenceError("Gate 4A restore receipt uses a different exact image")
    if receipt.get("source_application_version") != args.application_version or receipt.get("source_build_id") != args.build_id:
        raise FailureEvidenceError("Gate 4A restore receipt uses a different application build")
    for key in ("manifest_sha256", "backup_receipt_sha256", "archive_sha256", "inventory_root_sha256"):
        if not DIGEST_RE.fullmatch(str(receipt.get(key))):
            raise FailureEvidenceError(f"Gate 4A restore receipt has invalid {key}")
    if not recovery.BACKUP_ID_RE.fullmatch(str(receipt.get("backup_id", ""))):
        raise FailureEvidenceError("Gate 4A restore receipt has an invalid backup relationship")
    source = receipt.get("source_storage_identity")
    backup = receipt.get("backup_storage_identity")
    if not isinstance(source, dict) or not isinstance(backup, dict):
        raise FailureEvidenceError("Gate 4A restore receipt is missing source or backup identity")
    identities = {
        (source.get("pvc_uid"), source.get("bound_volume_uid")),
        (backup.get("pvc_uid"), backup.get("bound_volume_uid")),
        (target.get("pvc_uid"), target.get("bound_volume_uid")),
    }
    if len(identities) != 3 or any(not pvc or not volume for pvc, volume in identities):
        raise FailureEvidenceError("Gate 4A restore receipt does not preserve three distinct storage identities")
    for key in ("source_qualification_report_digest", "backup_qualification_report_digest"):
        if not DIGEST_RE.fullmatch(str(receipt.get(key))):
            raise FailureEvidenceError(f"Gate 4A restore receipt has invalid {key}")
    if receipt.get("source_and_backup_preserved") is not True:
        raise FailureEvidenceError("Gate 4A restore receipt does not preserve source and backup")
    return supplied


def _verify_attestation(value: dict, label: str) -> None:
    attestation = value.get("attestation")
    if not isinstance(attestation, dict) or attestation.get("algorithm") != "sha256":
        raise FailureEvidenceError(f"{label} is missing its SHA-256 attestation")
    body = {key: item for key, item in value.items() if key != "attestation"}
    if attestation.get("digest") != _digest(body):
        raise FailureEvidenceError(f"{label} attestation does not match its content")


def _tracked_work(db: sqlite3.Connection, job_ids: list[str], intent_ids: list[str]) -> dict:
    if len(job_ids) > MAX_TRACKED_ITEMS or len(intent_ids) > MAX_TRACKED_ITEMS:
        raise FailureEvidenceError("too many jobs or admission intents were requested")
    jobs: dict[str, dict] = {}
    for job_id in job_ids:
        job = db.execute(
            "SELECT job_id, job_type, source_kind, source_ref, requested_by FROM pipeline_jobs WHERE job_id=?",
            (job_id,),
        ).fetchone()
        if job is None:
            raise FailureEvidenceError(f"tracked processing job is missing: {job_id}")
        attempts = [
            dict(row)
            for row in db.execute(
                """SELECT attempt_id, attempt_number, state, claim_token, lease_owner,
                          lease_epoch, lease_expires_at, requested_by,
                          requested_at, started_at, finished_at, outcome, result_id,
                          output_kind, output_id, error
                     FROM pipeline_job_attempts WHERE job_id=? ORDER BY attempt_number""",
                (job_id,),
            )
        ]
        for attempt in attempts:
            lease_key = f"derived-attempt:{attempt['attempt_id']}"
            lease = db.execute(
                """SELECT lease_key, work_kind, work_id, fencing_epoch, lease_id,
                          owner_id, state, acquired_at, renewed_at, expires_at,
                          released_at, recovery_reason
                     FROM work_leases WHERE lease_key=?""",
                (lease_key,),
            ).fetchone()
            attempt["lease"] = dict(lease) if lease is not None else None
            attempt["lease_events"] = [
                dict(event)
                for event in db.execute(
                    """SELECT event_id, lease_key, fencing_epoch, lease_id, owner_id,
                              event_kind, recorded_at, detail
                         FROM work_lease_events WHERE lease_key=?
                         ORDER BY recorded_at, event_id""",
                    (lease_key,),
                )
            ]
        requests = [
            dict(row)
            for row in db.execute(
                """SELECT request_token, request_kind, requested_by, requested_at
                     FROM pipeline_job_requests WHERE job_id=? ORDER BY requested_at, request_token""",
                (job_id,),
            )
        ]
        jobs[job_id] = {
            "job_id": job[0], "job_type": job[1], "source_kind": job[2],
            "source_ref": job[3], "requested_by": job[4],
            "attempts": attempts, "requests": requests,
        }
    intents: dict[str, dict] = {}
    for intent_id in intent_ids:
        row = db.execute(
            """SELECT intent_id, intent_kind, source_kind, source_id, actor, request_token,
                      state, activity_state, admitted_job_id, last_error
                 FROM pipeline_admission_intents WHERE intent_id=?""",
            (intent_id,),
        ).fetchone()
        if row is None:
            raise FailureEvidenceError(f"tracked admission intent is missing: {intent_id}")
        intent = dict(row)
        intent["matching_requests"] = [
            dict(item)
            for item in db.execute(
                """SELECT request_token, job_id, request_kind, requested_by, requested_at
                     FROM pipeline_job_requests WHERE request_token=?
                     ORDER BY requested_at, job_id""",
                (intent["request_token"],),
            )
        ]
        intents[intent_id] = intent
    return {"jobs": jobs, "admission_intents": intents}


def _evidence_entries(db_path: Path, root: Path) -> list[dict]:
    from app.storage_health import evidence_references

    references, issues, active = evidence_references(db_path, data_root=root)
    if issues or active:
        raise FailureEvidenceError("retained evidence contains unresolved or active records")
    if len(references) > MAX_EVIDENCE_REFERENCES:
        raise FailureEvidenceError("retained evidence exceeds the Gate 4B reference limit")
    entries: list[dict] = []
    for reference in references:
        path = Path(reference.get("path", ""))
        try:
            relative = path.absolute().relative_to(root.absolute())
        except (OSError, ValueError) as exc:
            raise FailureEvidenceError("retained evidence reference is outside the data root") from exc
        digest, size = _file_sha256(root / relative)
        expected = reference.get("expected_hash")
        if expected and expected != digest:
            raise FailureEvidenceError("retained evidence does not match its recorded identity")
        entries.append({"path": relative.as_posix(), "sha256": digest, "size": size})
    return sorted(entries, key=lambda item: (item["path"], item["sha256"]))


def snapshot(args: argparse.Namespace) -> dict:
    root = args.data_root.absolute()
    db_path = root / "analyzer.db"
    if root.is_symlink() or not root.is_dir():
        raise FailureEvidenceError("data root must be a real directory")
    recovery._start_deadline(args.max_seconds)
    lock_context = recovery._writer_lock(root) if args.mode == "cold" else nullcontext()
    with lock_context:
        inspection_root = root
        source_inventory = None
        temporary_context = (
            tempfile.TemporaryDirectory(prefix="nct-gate4b-validation-", dir=args.validation_root)
            if args.mode == "cold" else nullcontext(None)
        )
        with temporary_context as temporary_name:
            if args.mode == "cold":
                inspection_root = Path(temporary_name)
                try:
                    captured = recovery._fd_tree(
                        root, copy_to=inspection_root,
                        max_files=args.max_files, max_bytes=args.max_bytes,
                    )
                except recovery.RecoveryError as exc:
                    raise FailureEvidenceError("cold source tree could not be captured safely") from exc
                public = recovery._public_inventory(captured)
                source_inventory = {
                    "root_sha256": recovery._digest(public),
                    "entries": len(public),
                    "files": sum(item["kind"] == "file" for item in public),
                    "bytes": sum(item["size"] for item in public if item["kind"] == "file"),
                }
            inspection_db = inspection_root / "analyzer.db"
            if not inspection_db.is_file():
                raise FailureEvidenceError("captured data does not contain analyzer.db")
            try:
                db = sqlite3.connect(f"file:{inspection_db.as_posix()}?mode=ro", uri=True)
                db.row_factory = sqlite3.Row
                db.execute("PRAGMA query_only=ON")
                db.execute("BEGIN")
                work = _tracked_work(db, args.tracked_job_id, args.tracked_intent_id)
            except sqlite3.Error as exc:
                raise FailureEvidenceError("tracked processing state could not be read") from exc
            finally:
                if "db" in locals():
                    db.close()
            validation = None
            entries = None
            if args.mode == "cold":
                validation = {
                    "database": recovery._database_baseline(inspection_db),
                    "artifacts": recovery._artifact_baseline(inspection_db, inspection_root),
                    "evidence": recovery._evidence_baseline(inspection_db, inspection_root),
                }
                entries = _evidence_entries(inspection_db, inspection_root)
    restore_receipt = _load(args.gate4a_restore_receipt, "Gate 4A restore receipt")
    restore_receipt_digest = _verify_gate4a_receipt(restore_receipt, args)
    body = {
        "schema_version": SCHEMA_VERSION,
        "status": "snapshot_recorded",
        "recorded_at": _utc_now(),
        "mode": args.mode,
        "phase": args.phase,
        "scenario": {"id": args.scenario_id, "kind": args.scenario_kind},
        "runtime": {
            "image": args.image,
            "application_version": args.application_version,
            "build_id": args.build_id,
            "deployment_uid": args.deployment_uid,
            "deployment_generation": args.deployment_generation,
            "pod_uid": args.pod_uid,
            "container_restart_count": args.container_restart_count,
            "node_uid": args.node_uid,
            "storage_attachment_identity": args.storage_attachment_identity,
        },
        "storage": {
            "pvc_uid": args.pvc_uid,
            "bound_volume_uid": args.bound_volume_uid,
            "qualification_report_digest": args.qualification_report_digest,
            "gate4a_restore_receipt_digest": restore_receipt_digest,
        },
        "health_transitions": (
            _load(args.health_transitions, "health-transition record")
            if args.health_transitions
            else {"transitions": args.health_transition}
        ),
        "work": work,
        "cold_validation": validation,
        "cold_source_inventory": source_inventory,
        "evidence_entries": entries,
        "tool": {
            "version": TOOL_VERSION,
            "source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        },
        "limitations": {
            "digest_authenticated": False,
            "node_names_are_durable_identity": False,
            "proves_node_power_state": False,
            "proves_storage_detachment": False,
        },
    }
    body["attestation"] = {"algorithm": "sha256", "digest": _digest(body)}
    _write(args.output, body)
    return body


def _assert_same_binding(values: list[dict]) -> None:
    first = values[0]
    expected = {
        "scenario": first["scenario"],
        "image": first["runtime"]["image"],
        "application_version": first["runtime"]["application_version"],
        "build_id": first["runtime"]["build_id"],
        "deployment_uid": first["runtime"]["deployment_uid"],
        "pvc_uid": first["storage"]["pvc_uid"],
        "bound_volume_uid": first["storage"]["bound_volume_uid"],
        "qualification_report_digest": first["storage"]["qualification_report_digest"],
        "gate4a_restore_receipt_digest": first["storage"]["gate4a_restore_receipt_digest"],
    }
    for value in values[1:]:
        observed = {
            "scenario": value["scenario"],
            "image": value["runtime"]["image"],
            "application_version": value["runtime"]["application_version"],
            "build_id": value["runtime"]["build_id"],
            "deployment_uid": value["runtime"]["deployment_uid"],
            "pvc_uid": value["storage"]["pvc_uid"],
            "bound_volume_uid": value["storage"]["bound_volume_uid"],
            "qualification_report_digest": value["storage"]["qualification_report_digest"],
            "gate4a_restore_receipt_digest": value["storage"]["gate4a_restore_receipt_digest"],
        }
        if observed != expected:
            raise FailureEvidenceError("Gate 4B evidence bindings changed during the scenario")


def _verify_work(before: dict, after: dict, after_recovery: dict) -> dict:
    def identity(attempt: dict) -> tuple[object, object, object]:
        return attempt.get("claim_token"), attempt.get("lease_owner"), attempt.get("lease_epoch")

    def matching_events(attempt: dict, event_kind: str) -> list[dict]:
        claim, owner, epoch = identity(attempt)
        events = attempt.get("lease_events")
        if not isinstance(events, list):
            raise FailureEvidenceError("protected work is missing lease event history")
        return [
            event for event in events
            if isinstance(event, dict)
            and event.get("event_kind") == event_kind
            and event.get("lease_id") == claim
            and event.get("owner_id") == owner
            and event.get("fencing_epoch") == epoch
        ]

    def require_attempt_identity(attempt: dict, *, state: str) -> dict:
        claim, owner, epoch = identity(attempt)
        if not isinstance(claim, str) or not claim or not isinstance(owner, str) or not owner:
            raise FailureEvidenceError(f"{state} work is missing its protected owner identity")
        if not isinstance(epoch, int) or epoch < 1:
            raise FailureEvidenceError(f"{state} work has an invalid fencing epoch")
        lease = attempt.get("lease")
        if not isinstance(lease, dict) or lease.get("lease_key") != f"derived-attempt:{attempt['attempt_id']}":
            raise FailureEvidenceError(f"{state} work is missing its exact lease record")
        if lease.get("work_id") != attempt["attempt_id"] or lease.get("fencing_epoch") != epoch:
            raise FailureEvidenceError(f"{state} work lease is bound to a different attempt or epoch")
        return lease

    before_jobs = before["work"]["jobs"]
    after_jobs = after["work"]["jobs"]
    recovered_jobs = after_recovery["work"]["jobs"]
    if set(before_jobs) != set(after_jobs) or set(before_jobs) != set(recovered_jobs):
        raise FailureEvidenceError("tracked processing work disappeared or changed identity")
    running_verified = queued_verified = recovery_verified = 0
    for job_id, prior in before_jobs.items():
        current = after_jobs[job_id]
        recovered = recovered_jobs[job_id]
        for key in ("job_id", "job_type", "source_kind", "source_ref", "requested_by"):
            if prior[key] != current[key] or prior[key] != recovered[key]:
                raise FailureEvidenceError("tracked processing job provenance changed")
        prior_attempts = prior["attempts"]
        current_attempts = current["attempts"]
        recovered_attempts = recovered["attempts"]
        if not prior_attempts or len(current_attempts) < len(prior_attempts):
            raise FailureEvidenceError("tracked processing attempt history was lost")
        prior_latest = prior_attempts[-1]
        matching = next((item for item in current_attempts if item["attempt_id"] == prior_latest["attempt_id"]), None)
        if matching is None:
            raise FailureEvidenceError("tracked processing attempt disappeared")
        if prior_latest["state"] == "running":
            prior_lease = require_attempt_identity(prior_latest, state="running")
            if prior_lease.get("state") != "active" or (
                prior_lease.get("lease_id"), prior_lease.get("owner_id")
            ) != identity(prior_latest)[:2]:
                raise FailureEvidenceError("running work was not protected by its exact active lease")
            prior_acquired = matching_events(prior_latest, "acquired")
            if len(prior_acquired) != 1:
                raise FailureEvidenceError("running work does not have exactly one matching acquisition event")
            if matching["state"] != "interrupted" or any(
                matching[key] is not None for key in ("outcome", "result_id", "output_kind", "output_id")
            ):
                raise FailureEvidenceError("running work was not retained as an unpublished interrupted attempt")
            interrupted_lease = require_attempt_identity(matching, state="interrupted")
            interrupted_acquired = matching_events(matching, "acquired")
            interrupted_expired = matching_events(matching, "expired")
            if interrupted_lease.get("state") != "released" or len(
                interrupted_expired
            ) != 1 or len(interrupted_acquired) != 1:
                raise FailureEvidenceError("interrupted work does not prove exact protected-owner expiry")
            original_acquired_at = _event_time(
                interrupted_acquired[0].get("recorded_at"), "original acquisition",
            )
            if original_acquired_at != _event_time(
                prior_acquired[0].get("recorded_at"), "original acquisition before restart",
            ):
                raise FailureEvidenceError("original acquisition event changed across restart evidence")
            original_started_at = _event_time(prior_latest.get("started_at"), "original attempt start")
            original_finished_at = _event_time(matching.get("finished_at"), "interrupted attempt finish")
            original_expired_at = _event_time(
                interrupted_expired[0].get("recorded_at"), "original owner expiry",
            )
            if not (
                original_acquired_at <= original_started_at
                <= original_finished_at <= original_expired_at
            ):
                raise FailureEvidenceError(
                    "original acquisition, interrupted attempt, and expiry are outside their required chronology"
                )
            if len(current_attempts) != len(prior_attempts) + 1:
                raise FailureEvidenceError("expired running work did not create exactly one recovery attempt")
            recovery = current_attempts[-1]
            if recovery["requested_by"] != "system-recovery" or recovery["attempt_number"] != prior_latest["attempt_number"] + 1:
                raise FailureEvidenceError("the automatic recovery attempt has invalid attribution or sequence")
            recovery_requests = [
                item for item in current["requests"]
                if item["request_kind"] == "retry" and item["requested_by"] == "system-recovery"
            ]
            if len(recovery_requests) != 1:
                raise FailureEvidenceError("automatic recovery did not retain exactly one attributed request")
            final = recovered_attempts[-1]
            if len(recovered_attempts) != len(current_attempts) or final["attempt_id"] != recovery["attempt_id"]:
                raise FailureEvidenceError("restart recovery created duplicate attempts")
            if final["state"] != "completed" or final["outcome"] not in {"created", "reused"} or not final["output_id"]:
                raise FailureEvidenceError("the protected recovery attempt did not complete with one guarded output")
            final_lease = require_attempt_identity(final, state="completed recovery")
            acquired = matching_events(final, "acquired")
            released = matching_events(final, "released")
            if final_lease.get("state") != "released" or len(acquired) != 1 or len(released) != 1:
                raise FailureEvidenceError("completed recovery does not prove one acquired and released lease")
            recovery_started_at = _event_time(final.get("started_at"), "recovery attempt start")
            recovery_finished_at = _event_time(final.get("finished_at"), "recovery attempt finish")
            recovery_acquired_at = _event_time(acquired[0].get("recorded_at"), "recovery acquisition")
            recovery_released_at = _event_time(released[0].get("recorded_at"), "recovery release")
            if not (
                recovery_started_at <= recovery_acquired_at
                <= recovery_released_at <= recovery_finished_at
            ):
                raise FailureEvidenceError(
                    "recovery lease events fall outside the recovery attempt window"
                )
            running_verified += 1
            recovery_verified += 1
        elif prior_latest["state"] == "queued":
            if matching["state"] not in {"queued", "completed"}:
                raise FailureEvidenceError("queued work did not remain queued or complete")
            if len(current_attempts) != len(prior_attempts) or recovered_attempts != current_attempts:
                raise FailureEvidenceError("queued work produced a duplicate attempt")
            if matching["state"] == "completed" and not matching["output_id"]:
                raise FailureEvidenceError("completed queued work has no guarded output")
            queued_verified += 1
    if running_verified < 1 or queued_verified < 1 or recovery_verified != running_verified:
        raise FailureEvidenceError("the scenario must prove one running recovery and one queued attempt")
    before_intents = before["work"]["admission_intents"]
    after_intents = after["work"]["admission_intents"]
    recovered_intents = after_recovery["work"]["admission_intents"]
    if not before_intents:
        raise FailureEvidenceError("the scenario must track at least one pending admission intent")
    if before_intents.keys() != after_intents.keys() or before_intents.keys() != recovered_intents.keys():
        raise FailureEvidenceError("a tracked admission intent disappeared")
    admission_verified = 0
    for intent_id, prior in before_intents.items():
        for observed in (after_intents[intent_id], recovered_intents[intent_id]):
            for key in ("intent_id", "intent_kind", "source_kind", "source_id", "actor", "request_token"):
                if prior[key] != observed[key]:
                    raise FailureEvidenceError("admission intent attribution changed")
            matches = observed["matching_requests"]
            if observed["state"] == "pending":
                if observed["admitted_job_id"] is not None or matches:
                    raise FailureEvidenceError("pending admission intent has duplicate or unexplained admission")
            elif observed["state"] == "admitted":
                if observed["activity_state"] != "complete" or not observed["admitted_job_id"]:
                    raise FailureEvidenceError("admitted intent is missing its completed job attribution")
                if len(matches) != 1 or matches[0]["job_id"] != observed["admitted_job_id"]:
                    raise FailureEvidenceError("admission intent did not create exactly one attributed job request")
            else:
                raise FailureEvidenceError("admission intent entered an unsupported state after recovery")
        admission_verified += 1
    return {
        "running_attempts_interrupted": running_verified,
        "queued_attempts_preserved_or_completed": queued_verified,
        "pending_admission_intents_attributed": admission_verified,
        "automatic_recovery_verified": True,
    }


def _health_values(snapshot_value: dict, label: str) -> list[str]:
    record = snapshot_value.get("health_transitions")
    values = record.get("transitions") if isinstance(record, dict) else None
    if not isinstance(values, list) or not values or any(
        not isinstance(item, str) or not HEALTH_RE.fullmatch(item) for item in values
    ):
        raise FailureEvidenceError(f"{label} health transitions are missing or malformed")
    return values


def _event_time(value: str, label: str) -> datetime:
    if not isinstance(value, str):
        raise FailureEvidenceError(f"{label} must use an exact UTC time")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
    except ValueError as exc:
        raise FailureEvidenceError(f"{label} has an invalid UTC time") from exc
    if parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise FailureEvidenceError(f"{label} must use an exact UTC time")
    return parsed


def _verify_orchestration(args: argparse.Namespace, before: dict, after: dict) -> tuple[dict, dict]:
    record = _load(args.orchestration_record, "orchestration record")
    if record.get("schema_version") != SCHEMA_VERSION:
        raise FailureEvidenceError("orchestration record schema is unsupported")
    if record.get("scenario") != before["scenario"]:
        raise FailureEvidenceError("orchestration record belongs to a different scenario")
    if record.get("deployment_uid") != before["runtime"]["deployment_uid"]:
        raise FailureEvidenceError("orchestration record belongs to a different Deployment")
    old, new = record.get("old"), record.get("new")
    if not isinstance(old, dict) or not isinstance(new, dict):
        raise FailureEvidenceError("orchestration record is missing old or replacement identity")
    expected_old = before["runtime"]
    expected_new = after["runtime"]
    for key in ("pod_uid", "node_uid", "container_restart_count", "storage_attachment_identity"):
        if old.get(key) != expected_old.get(key) or new.get(key) != expected_new.get(key):
            raise FailureEvidenceError("orchestration record runtime identity does not match snapshots")
    if record.get("generation_before") != expected_old["deployment_generation"] or record.get("generation_after") != expected_new["deployment_generation"]:
        raise FailureEvidenceError("orchestration Deployment generation does not match snapshots")
    if record.get("max_ready_pods") != 1 or record.get("max_writer_owners") != 1:
        raise FailureEvidenceError("orchestration did not prove a single Ready Pod and writer")
    events = record.get("events")
    if not isinstance(events, list) or not events:
        raise FailureEvidenceError("orchestration record has no bounded event sequence")
    if len(events) > 100:
        raise FailureEvidenceError("orchestration event sequence exceeds its limit")
    times: dict[str, datetime] = {}
    previous: datetime | None = None
    for event in events:
        if not isinstance(event, dict) or set(event) != {"event", "at"}:
            raise FailureEvidenceError("orchestration event is malformed")
        name = event["event"]
        if not isinstance(name, str) or name in times:
            raise FailureEvidenceError("orchestration event names must be unique")
        observed = _event_time(event["at"], f"orchestration event {name}")
        if previous is not None and observed < previous:
            raise FailureEvidenceError("orchestration events are not chronological")
        times[name], previous = observed, observed
    for required in ("before_ready", "readiness_lost", "old_writer_stopped", "replacement_created", "after_ready"):
        if required not in times:
            raise FailureEvidenceError(f"orchestration event is missing: {required}")
    kind = before["scenario"]["kind"]
    fencing = record.get("fencing")
    detachment = record.get("detachment")
    external: dict[str, dict] = {}
    require_detachment = kind in {"controlled-rescheduling", "node-loss"}
    require_fencing = kind == "node-loss"
    if kind == "node-loss":
        if "node_fenced" not in times or not (
            times["before_ready"] <= times["readiness_lost"] <= times["node_fenced"]
            <= times["old_writer_stopped"] <= times["replacement_created"] <= times["after_ready"]
        ):
            raise FailureEvidenceError("node-loss chronology does not prove fence-before-writer-stop")
    elif not (
        times["before_ready"] <= times["readiness_lost"] <= times["old_writer_stopped"]
        <= times["replacement_created"] <= times["after_ready"]
    ):
        raise FailureEvidenceError("orchestration ordering does not prove stop-before-replacement")
    remaining_provider_bytes = args.max_provider_bytes
    for label, value, required, evidence_path in (
        ("fencing", fencing, require_fencing, args.fencing_evidence),
        ("detachment", detachment, require_detachment, args.detachment_evidence),
    ):
        if not isinstance(value, dict) or value.get("required") is not required:
            raise FailureEvidenceError(f"orchestration {label} requirement is incorrect")
        if required:
            if evidence_path is None:
                raise FailureEvidenceError(f"{label} evidence is required for this scenario")
            digest, size = _file_sha256(evidence_path, max_bytes=remaining_provider_bytes)
            remaining_provider_bytes -= size
            if value.get("evidence_sha256") != digest or not value.get("operator"):
                raise FailureEvidenceError(f"{label} evidence does not match its retained provider record")
            completed = _event_time(value.get("completed_at"), f"{label} completion")
            expected_event = "node_fenced" if label == "fencing" else "storage_detached"
            if times.get(expected_event) != completed:
                raise FailureEvidenceError(f"{label} completion does not match the event sequence")
            external[label] = {"sha256": digest, "size": size, "operator": value["operator"], "completed_at": value["completed_at"]}
    if require_detachment:
        if any(name not in times for name in ("storage_detached", "storage_attached", "pre_replacement_lock_passed")):
            raise FailureEvidenceError("rescheduling is missing detach, destination attach, or pre-replacement probe events")
        if detachment.get("old_attachment_identity") != old["storage_attachment_identity"]:
            raise FailureEvidenceError("detachment evidence belongs to a different old attachment")
        if new["storage_attachment_identity"] == old["storage_attachment_identity"]:
            raise FailureEvidenceError("rescheduling must record the distinct replacement attachment identity")
        if not (
            times["old_writer_stopped"] <= times["storage_detached"] <= times["storage_attached"]
            <= times["pre_replacement_lock_passed"] <= times["replacement_created"] <= times["after_ready"]
        ):
            raise FailureEvidenceError("destination attachment and lock proof did not precede replacement")
    if require_fencing:
        if fencing.get("old_node_uid") != old["node_uid"]:
            raise FailureEvidenceError("fencing evidence belongs to a different old node")
        if record.get("no_replacement_before_fencing_and_detachment") is not True:
            raise FailureEvidenceError("node loss did not prove replacement was held for fencing and detachment")
        if not (times["node_fenced"] <= times["old_writer_stopped"] <= times["storage_detached"] <= times["replacement_created"]):
            raise FailureEvidenceError("node-loss replacement preceded fencing or storage detachment")
    return record, external


def _verify_cluster_observations(
    args: argparse.Namespace, before: dict, after: dict, orchestration: dict,
    before_health: list[str], after_health: list[str],
) -> dict:
    observations = _load(args.cluster_observations, "cluster observation log")
    if observations.get("schema_version") != SCHEMA_VERSION or observations.get("scenario") != before["scenario"]:
        raise FailureEvidenceError("cluster observation log has the wrong schema or scenario")
    samples = observations.get("samples")
    if not isinstance(samples, list) or not samples or len(samples) > 1000:
        raise FailureEvidenceError("cluster observation log is missing or exceeds its sample limit")
    prior_time: datetime | None = None
    by_event: dict[str, dict] = {}
    max_ready = max_writers = 0
    for sample in samples:
        if not isinstance(sample, dict):
            raise FailureEvidenceError("cluster observation sample is malformed")
        observed = _event_time(sample.get("observed_at"), "cluster observation time")
        if prior_time is not None and observed < prior_time:
            raise FailureEvidenceError("cluster observations are not chronological")
        prior_time = observed
        event = sample.get("event")
        if not isinstance(event, str) or event in by_event:
            raise FailureEvidenceError("cluster observation event names must be unique")
        if sample.get("deployment_uid") != before["runtime"]["deployment_uid"]:
            raise FailureEvidenceError("cluster observation belongs to a different Deployment")
        generation = sample.get("deployment_generation")
        if not isinstance(generation, int) or generation < before["runtime"]["deployment_generation"]:
            raise FailureEvidenceError("cluster observation has an invalid Deployment generation")
        pods = sample.get("pods")
        if not isinstance(pods, list) or len(pods) > 10:
            raise FailureEvidenceError("cluster observation Pod list is malformed")
        ready = 0
        for pod in pods:
            if not isinstance(pod, dict) or not all(
                isinstance(pod.get(key), str) and pod[key]
                for key in ("pod_uid", "node_uid", "phase", "storage_attachment_identity")
            ) or not isinstance(pod.get("ready"), bool):
                raise FailureEvidenceError("cluster observation Pod identity is malformed")
            ready += int(pod["ready"])
        writers = sample.get("writer_owners_observed")
        if not isinstance(writers, int) or writers < 0 or writers > 10:
            raise FailureEvidenceError("cluster observation writer count is malformed")
        max_ready, max_writers = max(max_ready, ready), max(max_writers, writers)
        by_event[event] = sample
    events = orchestration["events"]
    for item in events:
        sample = by_event.get(item["event"])
        if sample is None or sample["observed_at"] != item["at"]:
            raise FailureEvidenceError("orchestration events are not backed by cluster observations")
    if max_ready != orchestration["max_ready_pods"] or max_writers != orchestration["max_writer_owners"]:
        raise FailureEvidenceError("orchestration maxima do not match cluster observations")
    if max_ready > 1 or max_writers > 1:
        raise FailureEvidenceError("cluster observations show overlapping Ready Pods or writers")
    old, new = before["runtime"], after["runtime"]
    for event, runtime in (("before_ready", old), ("after_ready", new)):
        sample = by_event[event]
        if sample["deployment_generation"] != runtime["deployment_generation"]:
            raise FailureEvidenceError("cluster observation generation does not match runtime evidence")
        matches = [pod for pod in sample["pods"] if pod["pod_uid"] == runtime["pod_uid"] and pod["ready"]]
        if len(matches) != 1 or any(
            matches[0][key] != runtime[key]
            for key in ("node_uid", "storage_attachment_identity")
        ):
            raise FailureEvidenceError("cluster observation does not prove the expected Ready Pod identity")
    event_times = {item["event"]: _event_time(item["at"], item["event"]) for item in events}
    before_ready_health = [_event_time(item.split("|", 1)[0], "before readiness") for item in before_health if "|readiness|ready" in item]
    after_startup_health = [_event_time(item.split("|", 1)[0], "after startup") for item in after_health if "|startup|started" in item]
    after_ready_health = [_event_time(item.split("|", 1)[0], "after readiness") for item in after_health if "|readiness|ready" in item]
    if event_times["before_ready"] not in before_ready_health:
        raise FailureEvidenceError("before health evidence is not tied to the observed Ready event")
    if not after_startup_health or any(
        value < event_times["replacement_created"] or value > event_times["after_ready"]
        for value in after_startup_health + after_ready_health
    ) or event_times["after_ready"] not in after_ready_health:
        raise FailureEvidenceError("after health evidence is not tied to replacement observations")
    replacement_uid = new["pod_uid"]
    if replacement_uid != old["pod_uid"]:
        for event, sample in by_event.items():
            observed = _event_time(sample["observed_at"], event)
            if observed < event_times["replacement_created"] and any(
                pod["pod_uid"] == replacement_uid for pod in sample["pods"]
            ):
                raise FailureEvidenceError("cluster observations show the replacement before its permitted event")
            if observed >= event_times["replacement_created"] and any(
                pod["pod_uid"] == old["pod_uid"] for pod in sample["pods"]
            ):
                raise FailureEvidenceError("cluster observations retain the old Pod when replacement exists")
    if before["scenario"]["kind"] in {"controlled-rescheduling", "node-loss"}:
        old_attachment = old["storage_attachment_identity"]
        new_attachment = new["storage_attachment_identity"]
        detached = by_event["storage_detached"].get("attachments")
        attached = by_event["storage_attached"].get("attachments")
        if not isinstance(detached, list) or not any(
            item.get("identity") == old_attachment and item.get("state") == "detached" for item in detached if isinstance(item, dict)
        ):
            raise FailureEvidenceError("cluster observations do not prove the old attachment detached")
        if not isinstance(attached, list) or not any(
            item.get("identity") == new_attachment and item.get("node_uid") == new["node_uid"] and item.get("state") == "attached"
            for item in attached if isinstance(item, dict)
        ):
            raise FailureEvidenceError("cluster observations do not prove the destination attachment")
        detach_time = event_times["storage_detached"]
        attach_time = event_times["storage_attached"]
        replacement_time = event_times["replacement_created"]
        for event, sample in by_event.items():
            observed = _event_time(sample["observed_at"], event)
            if observed >= detach_time:
                attachments = sample.get("attachments", [])
                if not isinstance(attachments, list) or any(
                    item.get("identity") == old_attachment and item.get("state") != "detached"
                    for item in attachments if isinstance(item, dict)
                ):
                    raise FailureEvidenceError("cluster observations show the old attachment active after detachment")
            if observed >= attach_time:
                attachments = sample.get("attachments")
                active = [
                    item for item in attachments if isinstance(item, dict) and item.get("state") != "detached"
                ] if isinstance(attachments, list) else []
                if len(active) != 1 or active[0].get("identity") != new_attachment or active[0].get("node_uid") != new["node_uid"] or active[0].get("state") != "attached":
                    raise FailureEvidenceError("cluster observations do not show only the destination attachment before replacement")
        pre_generation = by_event["pre_replacement_lock_passed"]["deployment_generation"]
        if before["scenario"]["kind"] == "controlled-rescheduling":
            if pre_generation + 1 != new["deployment_generation"]:
                raise FailureEvidenceError("controlled rescheduling has an invalid pre-scale generation transition")
        elif pre_generation != new["deployment_generation"]:
            raise FailureEvidenceError("node-loss pre-replacement generation differs from the recovered runtime")
    else:
        pre_generation = None
    return {
        "sha256": _digest(observations), "samples": len(samples),
        "max_ready_pods": max_ready, "max_writer_owners": max_writers,
        "pre_replacement_generation": pre_generation,
    }


def verify(args: argparse.Namespace) -> dict:
    if args.max_seconds < 1 or args.max_seconds > 1800:
        raise FailureEvidenceError("verifier time limit is outside the enforced range")
    if args.max_evidence_bytes < 1 or args.max_evidence_bytes > recovery.DEFAULT_MAX_BYTES:
        raise FailureEvidenceError("verifier evidence byte limit is outside the enforced range")
    if args.max_provider_bytes < 1 or args.max_provider_bytes > MAX_INPUT_BYTES:
        raise FailureEvidenceError("verifier provider byte limit is outside the enforced range")
    recovery._start_deadline(args.max_seconds)
    before_runtime = _load(args.before_runtime, "before-runtime snapshot")
    after_runtime = _load(args.after_runtime, "after-runtime snapshot")
    before_cold = _load(args.before_cold, "before-cold snapshot")
    after_cold = _load(args.after_cold, "after-cold snapshot")
    after_recovery = _load(args.after_recovery, "after-recovery snapshot")
    values = [before_runtime, after_runtime, before_cold, after_cold, after_recovery]
    for index, value in enumerate(values):
        _verify_attestation(value, f"snapshot {index + 1}")
    _assert_same_binding(values)
    if before_runtime["mode"] != "runtime" or after_runtime["mode"] != "runtime":
        raise FailureEvidenceError("runtime snapshots are required before and after restart")
    if before_runtime["phase"] != "before-failure" or after_runtime["phase"] != "after-restart":
        raise FailureEvidenceError("runtime snapshots do not describe before-failure and after-restart")
    if before_cold["mode"] != "cold" or after_cold["mode"] != "cold":
        raise FailureEvidenceError("cold snapshots are required before and after the scenario")
    if after_recovery["mode"] != "runtime" or after_recovery["phase"] != "after-recovery":
        raise FailureEvidenceError("the recovery snapshot must be a runtime after-recovery record")
    if after_recovery["runtime"] != after_runtime["runtime"]:
        raise FailureEvidenceError("after-recovery runtime identity changed from the recovered Pod")
    before_health = _health_values(before_runtime, "before-runtime")
    after_health = _health_values(after_runtime, "after-runtime")
    if not any("|readiness|ready" in item for item in before_health):
        raise FailureEvidenceError("before-runtime health does not prove readiness")
    if not any("|startup|started" in item for item in after_health) or not any(
        "|readiness|ready" in item for item in after_health
    ):
        raise FailureEvidenceError("after-runtime health does not prove startup and readiness")
    scenario_kind = before_runtime["scenario"]["kind"]
    before_runtime_identity = before_runtime["runtime"]
    after_runtime_identity = after_runtime["runtime"]
    if scenario_kind == "forced-termination":
        if before_runtime_identity["pod_uid"] != after_runtime_identity["pod_uid"]:
            raise FailureEvidenceError("forced process termination did not restart the same Pod")
        if after_runtime_identity["container_restart_count"] <= before_runtime_identity["container_restart_count"]:
            raise FailureEvidenceError("forced process termination did not increase the container restart count")
        if after_runtime_identity["deployment_generation"] != before_runtime_identity["deployment_generation"]:
            raise FailureEvidenceError("forced process termination unexpectedly changed Deployment generation")
    elif scenario_kind == "recreate-replacement":
        if before_runtime_identity["pod_uid"] == after_runtime_identity["pod_uid"]:
            raise FailureEvidenceError("Recreate replacement did not produce a new Pod UID")
        if after_runtime_identity["deployment_generation"] <= before_runtime_identity["deployment_generation"]:
            raise FailureEvidenceError("Recreate replacement did not advance Deployment generation")
    elif scenario_kind in {"controlled-rescheduling", "node-loss"}:
        if before_runtime_identity["pod_uid"] == after_runtime_identity["pod_uid"]:
            raise FailureEvidenceError("rescheduling did not produce a new Pod UID")
        if before_runtime_identity["node_uid"] == after_runtime_identity["node_uid"]:
            raise FailureEvidenceError("rescheduling did not move to a different node UID")
        if scenario_kind == "controlled-rescheduling" and after_runtime_identity["deployment_generation"] <= before_runtime_identity["deployment_generation"]:
            raise FailureEvidenceError("rescheduling did not advance Deployment generation")
        if scenario_kind == "node-loss" and after_runtime_identity["deployment_generation"] < before_runtime_identity["deployment_generation"]:
            raise FailureEvidenceError("node-loss evidence reports a regressed Deployment generation")
    orchestration, external_evidence = _verify_orchestration(args, before_runtime, after_runtime)
    cluster_observations = _verify_cluster_observations(
        args, before_runtime, after_runtime, orchestration, before_health, after_health,
    )
    prior_entries = {(item["path"], item["sha256"], item["size"]) for item in before_cold["evidence_entries"]}
    current_entries = {(item["path"], item["sha256"], item["size"]) for item in after_cold["evidence_entries"]}
    if not prior_entries.issubset(current_entries):
        raise FailureEvidenceError("retained evidence changed or disappeared after failure recovery")
    before_validation = before_cold["cold_validation"]
    after_validation = after_cold["cold_validation"]
    if before_validation["database"]["schema_fingerprint"] != after_validation["database"]["schema_fingerprint"]:
        raise FailureEvidenceError("database schema changed during Gate 4B failure testing")
    if after_validation["artifacts"]["verified"] != after_validation["artifacts"]["count"]:
        raise FailureEvidenceError("Artifact Registry verification is incomplete after recovery")
    if after_validation["evidence"]["artifact_observations"] < before_validation["evidence"]["artifact_observations"]:
        raise FailureEvidenceError("artifact observations disappeared after recovery")
    before_download = _file_sha256(args.selected_evidence_before, max_bytes=args.max_evidence_bytes)
    after_download = _file_sha256(
        args.selected_evidence_after,
        max_bytes=args.max_evidence_bytes - before_download[1],
    )
    if before_download != after_download:
        raise FailureEvidenceError("the selected retained-evidence download changed")
    active_lock = _load(args.active_lock_receipt, "active-writer lock receipt")
    released_lock = _load(args.released_lock_receipt, "released-writer lock receipt")
    lock_receipts = [
        ("active-writer lock receipt", active_lock, "contended", "old-writer-active", before_runtime["runtime"], True, before_runtime["runtime"]["deployment_generation"]),
        ("released-writer lock receipt", released_lock, "available", "replacement-writer-released", after_runtime["runtime"], True, after_runtime["runtime"]["deployment_generation"]),
    ]
    pre_replacement_lock = None
    if scenario_kind in {"controlled-rescheduling", "node-loss"}:
        if args.pre_replacement_lock_receipt is None:
            raise FailureEvidenceError("a pre-replacement available-lock receipt is required for rescheduling")
        pre_replacement_lock = _load(
            args.pre_replacement_lock_receipt, "pre-replacement lock receipt"
        )
        lock_receipts.append(
            ("pre-replacement lock receipt", pre_replacement_lock, "available", "destination-pre-replacement", after_runtime["runtime"], False, cluster_observations["pre_replacement_generation"])
        )
    for label, receipt, expected, expected_phase, runtime, require_pod, expected_generation in lock_receipts:
        _verify_attestation(receipt, label)
        if receipt.get("status") != "pass" or receipt.get("writer_lock", {}).get("observed") != expected:
            raise FailureEvidenceError(f"{label} did not prove {expected}")
        receipt_scenario = receipt.get("scenario", {})
        if {
            "id": receipt_scenario.get("id"), "kind": receipt_scenario.get("kind")
        } != before_runtime["scenario"]:
            raise FailureEvidenceError(f"{label} belongs to a different scenario")
        if receipt.get("storage", {}).get("pvc_uid") != before_runtime["storage"]["pvc_uid"]:
            raise FailureEvidenceError(f"{label} belongs to a different PVC")
        if receipt.get("storage", {}).get("bound_volume_uid") != before_runtime["storage"]["bound_volume_uid"]:
            raise FailureEvidenceError(f"{label} belongs to a different bound volume")
        if receipt.get("storage", {}).get("qualification_report_digest") != before_runtime["storage"]["qualification_report_digest"]:
            raise FailureEvidenceError(f"{label} belongs to different storage qualification evidence")
        if receipt.get("runtime", {}).get("image") != before_runtime["runtime"]["image"]:
            raise FailureEvidenceError(f"{label} belongs to a different image")
        if receipt.get("deployment", {}).get("uid") != before_runtime["runtime"]["deployment_uid"]:
            raise FailureEvidenceError(f"{label} belongs to a different Deployment")
        if receipt_scenario.get("phase") != expected_phase:
            raise FailureEvidenceError(f"{label} uses the wrong scenario phase")
        receipt_runtime = receipt.get("runtime", {})
        receipt_deployment = receipt.get("deployment", {})
        for key in ("image", "application_version", "build_id"):
            if receipt_runtime.get(key) != runtime.get(key):
                raise FailureEvidenceError(f"{label} has a different {key.replace('_', ' ')}")
        for key in ("node_uid", "storage_attachment_identity"):
            if receipt_deployment.get(key) != runtime.get(key):
                raise FailureEvidenceError(f"{label} has a different {key.replace('_', ' ')}")
        if require_pod and receipt_deployment.get("pod_uid") != runtime.get("pod_uid"):
            raise FailureEvidenceError(f"{label} has a different pod UID")
        if not require_pod and "pod_uid" in receipt_deployment:
            raise FailureEvidenceError("pre-replacement lock receipt claims a replacement Pod that did not yet exist")
        if receipt_deployment.get("generation") != expected_generation:
            raise FailureEvidenceError(f"{label} has a different Deployment generation")
    if pre_replacement_lock is not None:
        checked = str(pre_replacement_lock.get("checked_at", "")).replace("+00:00", "Z")
        event = next(item for item in orchestration["events"] if item["event"] == "pre_replacement_lock_passed")
        if checked != event["at"]:
            raise FailureEvidenceError("pre-replacement lock receipt time does not match cluster observations")
    work = _verify_work(before_runtime, after_runtime, after_recovery)
    body = {
        "schema_version": SCHEMA_VERSION,
        "status": "gate4b_scenario_verified",
        "verified_at": _utc_now(),
        "scenario": before_runtime["scenario"],
        "bindings": {
            "runtime": before_runtime["runtime"],
            "storage": before_runtime["storage"],
        },
        "checks": {
            "writer_lock_contended_while_active": True,
            "writer_lock_available_after_fencing": True,
            "database_integrity": "ok",
            "artifact_registry_verified": after_validation["artifacts"],
            "prior_retained_evidence_preserved": len(prior_entries),
            "artifact_observations_before": before_validation["evidence"]["artifact_observations"],
            "artifact_observations_after": after_validation["evidence"]["artifact_observations"],
            "selected_evidence_sha256": before_download[0],
            "orchestration_single_writer": True,
            "cluster_observations": cluster_observations,
            "external_fencing_and_detachment_bound": bool(external_evidence),
            **work,
        },
        "source_receipts": {
            "before_runtime": before_runtime["attestation"]["digest"],
            "after_runtime": after_runtime["attestation"]["digest"],
            "before_cold": before_cold["attestation"]["digest"],
            "after_cold": after_cold["attestation"]["digest"],
            "active_lock": active_lock["attestation"]["digest"],
            "released_lock": released_lock["attestation"]["digest"],
            "pre_replacement_lock": (
                pre_replacement_lock["attestation"]["digest"] if pre_replacement_lock else None
            ),
            "orchestration": _digest(orchestration),
            "external_evidence": external_evidence,
            "cluster_observations": cluster_observations["sha256"],
        },
        "limitations": {
            "digest_authenticated": False,
            "provider_evidence_content_interpreted_by_tool": False,
            "provider_evidence_digest_bound_and_order_checked": bool(external_evidence),
        },
    }
    body["attestation"] = {"algorithm": "sha256", "digest": _digest(body)}
    _write(args.output, body)
    return body


def _add_binding(target: argparse.ArgumentParser) -> None:
    target.add_argument("--scenario-id", required=True)
    target.add_argument(
        "--scenario-kind",
        choices=("forced-termination", "recreate-replacement", "controlled-rescheduling", "node-loss"),
        required=True,
    )
    target.add_argument("--image", required=True)
    target.add_argument("--application-version", required=True)
    target.add_argument("--build-id", required=True)
    target.add_argument("--deployment-uid", required=True)
    target.add_argument("--deployment-generation", type=int, required=True)
    target.add_argument("--pod-uid", required=True)
    target.add_argument("--container-restart-count", type=int, required=True)
    target.add_argument("--node-uid", required=True)
    target.add_argument("--storage-attachment-identity", required=True)
    target.add_argument("--pvc-uid", required=True)
    target.add_argument("--bound-volume-uid", required=True)
    target.add_argument("--qualification-report-digest", required=True)
    target.add_argument("--gate4a-restore-receipt", type=Path, required=True)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    record = commands.add_parser("snapshot")
    record.add_argument("--mode", choices=("runtime", "cold"), required=True)
    record.add_argument("--phase", choices=("before-failure", "after-restart", "after-recovery"), required=True)
    record.add_argument("--data-root", type=Path, required=True)
    record.add_argument("--tracked-job-id", action="append", default=[])
    record.add_argument("--tracked-intent-id", action="append", default=[])
    record.add_argument("--health-transitions", type=Path)
    record.add_argument("--health-transition", action="append", default=[])
    record.add_argument("--validation-root", type=Path, default=Path("/tmp"))
    record.add_argument("--max-files", type=int, default=recovery.DEFAULT_MAX_FILES)
    record.add_argument("--max-bytes", type=int, default=recovery.DEFAULT_MAX_BYTES)
    record.add_argument("--max-seconds", type=int, default=300)
    record.add_argument("--output", type=Path, required=True)
    _add_binding(record)
    check = commands.add_parser("verify")
    check.add_argument("--before-runtime", type=Path, required=True)
    check.add_argument("--after-runtime", type=Path, required=True)
    check.add_argument("--before-cold", type=Path, required=True)
    check.add_argument("--after-cold", type=Path, required=True)
    check.add_argument("--after-recovery", type=Path, required=True)
    check.add_argument("--active-lock-receipt", type=Path, required=True)
    check.add_argument("--released-lock-receipt", type=Path, required=True)
    check.add_argument("--pre-replacement-lock-receipt", type=Path)
    check.add_argument("--selected-evidence-before", type=Path, required=True)
    check.add_argument("--selected-evidence-after", type=Path, required=True)
    check.add_argument("--orchestration-record", type=Path, required=True)
    check.add_argument("--cluster-observations", type=Path, required=True)
    check.add_argument("--fencing-evidence", type=Path)
    check.add_argument("--detachment-evidence", type=Path)
    check.add_argument("--max-evidence-bytes", type=int, default=recovery.DEFAULT_MAX_BYTES)
    check.add_argument("--max-provider-bytes", type=int, default=MAX_INPUT_BYTES)
    check.add_argument("--max-seconds", type=int, default=300)
    check.add_argument("--output", type=Path, required=True)
    return parser


def _validate_snapshot(args: argparse.Namespace) -> None:
    if not SCENARIO_RE.fullmatch(args.scenario_id):
        raise FailureEvidenceError("scenario ID must be 8-80 lowercase letters, digits, or hyphens")
    if not IMAGE_RE.fullmatch(args.image) or len(args.image) > MAX_VALUE_CHARS:
        raise FailureEvidenceError("image must use an exact sha256 digest")
    if args.deployment_generation < 1 or args.container_restart_count < 0:
        raise FailureEvidenceError("deployment generation and restart count are invalid")
    for attribute in (
        "application_version", "build_id", "deployment_uid", "pod_uid", "node_uid",
        "storage_attachment_identity", "pvc_uid", "bound_volume_uid",
    ):
        value = getattr(args, attribute)
        if not value or len(value) > MAX_VALUE_CHARS or any(ord(char) < 32 for char in value):
            raise FailureEvidenceError(f"{attribute.replace('_', ' ')} is invalid or too large")
    for attribute in ("qualification_report_digest",):
        if not DIGEST_RE.fullmatch(getattr(args, attribute)):
            raise FailureEvidenceError(f"{attribute.replace('_', ' ')} is invalid")
    if args.max_files < 1 or args.max_files > recovery.DEFAULT_MAX_FILES:
        raise FailureEvidenceError("max files is outside the enforced limit")
    if args.max_bytes < 1 or args.max_bytes > recovery.DEFAULT_MAX_BYTES:
        raise FailureEvidenceError("max bytes is outside the enforced limit")
    if args.max_seconds < 1 or args.max_seconds > 1800:
        raise FailureEvidenceError("max seconds is outside the enforced limit")
    if args.validation_root.is_symlink() or not args.validation_root.is_dir():
        raise FailureEvidenceError("validation root must be a real directory")
    if len(set(args.tracked_job_id)) != len(args.tracked_job_id):
        raise FailureEvidenceError("tracked job IDs must be unique")
    if len(set(args.tracked_intent_id)) != len(args.tracked_intent_id):
        raise FailureEvidenceError("tracked admission intent IDs must be unique")
    if args.mode == "runtime" and bool(args.health_transitions) == bool(args.health_transition):
        raise FailureEvidenceError(
            "runtime snapshots require either one health-transition record or bounded health-transition values"
        )
    if args.mode == "cold" and (args.health_transitions or args.health_transition):
        raise FailureEvidenceError("cold snapshots must not claim live health transitions")
    if len(args.health_transition) > 100 or any(
        not value or len(value) > MAX_VALUE_CHARS or any(ord(char) < 32 for char in value)
        for value in args.health_transition
    ):
        raise FailureEvidenceError("health-transition values are invalid or too large")


def main() -> int:
    try:
        args = _parser().parse_args()
        if args.command == "snapshot":
            _validate_snapshot(args)
            result = snapshot(args)
        else:
            result = verify(args)
        print(json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=True))
    except (FailureEvidenceError, recovery.RecoveryError) as exc:
        print(json.dumps({"status": "failed", "error": str(exc)}, sort_keys=True), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
