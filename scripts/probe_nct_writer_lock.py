#!/usr/bin/env python3
"""Prove whether the existing NCT writer lock is owned without opening SQLite."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
import time


SCHEMA_VERSION = 1
TOOL_VERSION = "1"
MAX_RECEIPT_BYTES = 4096
MAX_VALUE_CHARS = 512
SCENARIO_RE = re.compile(r"^[a-z0-9][a-z0-9-]{7,79}$")
DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
IMAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]*@sha256:[0-9a-f]{64}$")


class ProbeError(ValueError):
    pass


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _source_sha256() -> str:
    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def _bounded(value: str, label: str) -> str:
    if not value or len(value) > MAX_VALUE_CHARS or any(ord(char) < 32 for char in value):
        raise ProbeError(f"{label} is invalid or too large")
    return value


def _write_receipt(path: Path, value: dict) -> None:
    payload = _canonical(value)
    if not payload or len(payload) > MAX_RECEIPT_BYTES:
        raise ProbeError("writer-lock receipt exceeds the Kubernetes termination-message limit")
    if path.is_symlink():
        raise ProbeError("writer-lock receipt path must not be a symbolic link")
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


def probe(args: argparse.Namespace) -> dict:
    path = args.lock_path
    if path.name != ".analyzer.db.nct-writer.lock":
        raise ProbeError("writer-lock probe must target the fixed NCT lock filename")
    flags = os.O_RDWR | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except FileNotFoundError as exc:
        raise ProbeError("the existing NCT writer lock is missing; the probe will not create it") from exc
    except OSError as exc:
        raise ProbeError("the existing NCT writer lock could not be opened safely") from exc
    observed = "unknown"
    acquired = False
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ProbeError("the existing NCT writer lock is not one safe regular file")
        try:
            fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB, 1, 0, os.SEEK_SET)
            acquired = True
            observed = "available"
        except OSError as exc:
            if exc.errno not in {errno.EACCES, errno.EAGAIN}:
                raise ProbeError("the NCT writer lock state could not be measured") from exc
            observed = "contended"
        if observed != args.expect:
            raise ProbeError(
                f"writer-lock expectation failed: expected {args.expect}, observed {observed}"
            )
    finally:
        if acquired:
            fcntl.lockf(fd, fcntl.LOCK_UN, 1, 0, os.SEEK_SET)
        os.close(fd)

    body = {
        "schema_version": SCHEMA_VERSION,
        "status": "pass",
        "checked_at": _utc_now(),
        "scenario": {
            "id": args.scenario_id,
            "kind": args.scenario_kind,
            "phase": args.phase,
        },
        "deployment": {
            "uid": args.deployment_uid,
            "generation": args.deployment_generation,
            "node_uid": args.node_uid,
            "storage_attachment_identity": args.storage_attachment_identity,
        },
        "runtime": {
            "image": args.image,
            "application_version": args.application_version,
            "build_id": args.build_id,
        },
        "storage": {
            "pvc_uid": args.pvc_uid,
            "bound_volume_uid": args.bound_volume_uid,
            "qualification_report_digest": args.qualification_report_digest,
        },
        "writer_lock": {
            "path": str(path),
            "expected": args.expect,
            "observed": observed,
            "opened_existing_only": True,
            "sqlite_opened": False,
            "released_if_acquired": acquired,
            "destination_attachment_hold_seconds": args.hold_seconds,
        },
        "tool": {"version": TOOL_VERSION, "source_sha256": _source_sha256()},
        "limitations": {
            "digest_authenticated": False,
            "proves_process_or_node_fencing": False,
            "proves_storage_detachment": False,
        },
    }
    if args.pod_uid:
        body["deployment"]["pod_uid"] = args.pod_uid
    body["attestation"] = {"algorithm": "sha256", "digest": hashlib.sha256(_canonical(body)).hexdigest()}
    _write_receipt(args.receipt_path, body)
    return body


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lock-path", type=Path, default=Path("/data/.analyzer.db.nct-writer.lock"))
    parser.add_argument("--expect", choices=("contended", "available"), required=True)
    parser.add_argument("--scenario-id", required=True)
    parser.add_argument(
        "--scenario-kind",
        choices=("forced-termination", "recreate-replacement", "controlled-rescheduling", "node-loss"),
        required=True,
    )
    parser.add_argument(
        "--phase",
        choices=("old-writer-active", "destination-pre-replacement", "replacement-writer-released"),
        required=True,
    )
    parser.add_argument("--image", required=True)
    parser.add_argument("--application-version", required=True)
    parser.add_argument("--build-id", required=True)
    parser.add_argument("--deployment-uid", required=True)
    parser.add_argument("--deployment-generation", type=int, required=True)
    parser.add_argument("--pod-uid")
    parser.add_argument("--node-uid", required=True)
    parser.add_argument("--storage-attachment-identity", required=True)
    parser.add_argument("--pvc-uid", required=True)
    parser.add_argument("--bound-volume-uid", required=True)
    parser.add_argument("--qualification-report-digest", required=True)
    parser.add_argument("--hold-seconds", type=int, default=0)
    parser.add_argument("--receipt-path", type=Path, default=Path("/tmp/nct-writer-lock-receipt.json"))
    return parser


def _validate(args: argparse.Namespace) -> None:
    if not SCENARIO_RE.fullmatch(args.scenario_id):
        raise ProbeError("scenario ID must be 8-80 lowercase letters, digits, or hyphens")
    if not IMAGE_RE.fullmatch(args.image) or len(args.image) > MAX_VALUE_CHARS:
        raise ProbeError("image must use an exact sha256 digest")
    if args.deployment_generation < 1:
        raise ProbeError("deployment generation must be positive")
    args.hold_seconds = getattr(args, "hold_seconds", 0)
    if args.hold_seconds < 0 or args.hold_seconds > 1800:
        raise ProbeError("attachment hold seconds must be between 0 and 1800")
    for name in (
        "application_version", "build_id", "deployment_uid", "node_uid",
        "storage_attachment_identity", "pvc_uid", "bound_volume_uid",
    ):
        setattr(args, name, _bounded(getattr(args, name), name.replace("_", " ")))
    if args.pod_uid is not None:
        args.pod_uid = _bounded(args.pod_uid, "pod UID")
    if not DIGEST_RE.fullmatch(args.qualification_report_digest):
        raise ProbeError("qualification report digest is invalid")
    if args.expect == "contended" and args.phase != "old-writer-active":
        raise ProbeError("a contended probe must describe the old-writer-active phase")
    if args.expect == "available" and args.phase not in {
        "destination-pre-replacement", "replacement-writer-released",
    }:
        raise ProbeError("an available probe must describe a destination or released-replacement phase")
    if args.phase == "destination-pre-replacement":
        if args.scenario_kind not in {"controlled-rescheduling", "node-loss"}:
            raise ProbeError("a destination pre-replacement probe is only valid for rescheduling or node loss")
        if args.pod_uid is not None:
            raise ProbeError("a destination pre-replacement probe must not claim a replacement Pod UID")
        if args.hold_seconds < 60:
            raise ProbeError("a destination pre-replacement probe must hold the attachment for at least 60 seconds")
    elif args.pod_uid is None:
        raise ProbeError("a Pod UID is required for active and released-replacement probes")
    elif args.hold_seconds:
        raise ProbeError("only a destination pre-replacement probe may hold the attachment")


def main() -> int:
    try:
        args = _parser().parse_args()
        _validate(args)
        result = probe(args)
        print(json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=True))
        sys.stdout.flush()
        if args.hold_seconds:
            time.sleep(args.hold_seconds)
    except ProbeError as exc:
        print(json.dumps({"status": "failed", "error": str(exc)}, sort_keys=True), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
