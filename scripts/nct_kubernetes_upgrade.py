#!/usr/bin/env python3
"""Create bounded, fail-closed evidence for NCT Kubernetes upgrades and rollbacks."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import sqlite3
import stat
import sys
import tempfile
import time
from typing import Iterator

from app.schema_compatibility import image_schema_contract, schema_state
import nct_kubernetes_recovery as recovery


TOOL_VERSION = "1"
RECEIPT_SCHEMA_VERSION = 1
WRITER_LOCK_NAME = ".analyzer.db.nct-writer.lock"
IMAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]*@sha256:[0-9a-f]{64}$")
DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
SCENARIO_RE = re.compile(r"^[a-z0-9][a-z0-9-]{7,79}$")
DEFAULT_MAX_FILES = 1_000_000
DEFAULT_MAX_BYTES = 4 * 1024**4
DEFAULT_MAX_SECONDS = 1_800
MAX_JSON_BYTES = 2 * 1024**2
MAX_OUTPUT_BYTES = 2 * 1024**2
_DEADLINE: float | None = None


class UpgradeEvidenceError(ValueError):
    pass


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _image_digest(value: object) -> str:
    text = str(value or "")
    marker = "sha256:"
    if marker not in text:
        raise UpgradeEvidenceError("runtime image identity has no immutable sha256 digest")
    digest = text.rsplit(marker, 1)[1]
    if not DIGEST_RE.fullmatch(digest):
        raise UpgradeEvidenceError("runtime image identity has an invalid sha256 digest")
    return digest


def _receipt(value: dict) -> dict:
    return {**value, "receipt_sha256": _digest(value)}


def _verify_receipt(value: dict, label: str) -> None:
    supplied = value.get("receipt_sha256")
    body = {key: item for key, item in value.items() if key != "receipt_sha256"}
    if not isinstance(supplied, str) or supplied != _digest(body):
        raise UpgradeEvidenceError(f"{label} receipt digest is invalid")


def _read_json(path: Path, label: str, *, limit: int = MAX_JSON_BYTES) -> dict:
    try:
        info = os.lstat(path)
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise UpgradeEvidenceError(f"{label} must be a regular file, not a link")
        if info.st_size < 2 or info.st_size > limit:
            raise UpgradeEvidenceError(f"{label} size is outside the safe limit")
        value = json.loads(path.read_text(encoding="utf-8"))
    except UpgradeEvidenceError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise UpgradeEvidenceError(f"{label} is unreadable JSON") from exc
    if not isinstance(value, dict):
        raise UpgradeEvidenceError(f"{label} must contain a JSON object")
    return value


def _write_json(path: Path, value: dict, *, overwrite: bool) -> None:
    path = path.absolute()
    payload = json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + "\n"
    if len(payload.encode("utf-8")) > MAX_OUTPUT_BYTES:
        raise UpgradeEvidenceError("upgrade receipt exceeds the safe output limit")
    if path.is_symlink():
        raise UpgradeEvidenceError("output must not be a symbolic link")
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not overwrite:
        raise UpgradeEvidenceError("output already exists; use --overwrite to replace it")
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        if path.exists() and not overwrite:
            raise UpgradeEvidenceError("output appeared while writing; refusing to replace it")
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        temporary.unlink(missing_ok=True)


def _start_deadline(seconds: int) -> None:
    global _DEADLINE
    if seconds < 1 or seconds > DEFAULT_MAX_SECONDS:
        raise UpgradeEvidenceError("time limit is outside the enforced range")
    _DEADLINE = time.monotonic() + seconds
    recovery._start_deadline(seconds)


def _check_deadline() -> None:
    if _DEADLINE is not None and time.monotonic() > _DEADLINE:
        raise UpgradeEvidenceError("upgrade evidence operation exceeded its time limit")


def _safe_relative(path: Path, root: Path) -> str:
    try:
        relative = path.relative_to(root)
    except ValueError as exc:
        raise UpgradeEvidenceError("data path escaped the declared root") from exc
    value = PurePosixPath(*relative.parts)
    if value.is_absolute() or ".." in value.parts or any(part in {"", "."} for part in value.parts):
        raise UpgradeEvidenceError("data path is unsafe")
    return value.as_posix()


@contextmanager
def _available_writer_lock(root: Path) -> Iterator[None]:
    lock_path = root / WRITER_LOCK_NAME
    try:
        info = os.lstat(lock_path)
    except OSError as exc:
        raise UpgradeEvidenceError(
            "Upgrade blocked: the existing NCT writer lock is missing or unreadable. Nothing was opened or changed."
        ) from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise UpgradeEvidenceError("Upgrade blocked: the NCT writer lock is unsafe. Nothing was opened or changed.")
    flags = os.O_RDWR | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(lock_path, flags)
    try:
        try:
            fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB, 1, 0, os.SEEK_SET)
        except OSError as exc:
            raise UpgradeEvidenceError(
                "Upgrade blocked: an active writer was detected. Nothing was opened or changed."
            ) from exc
        yield
    finally:
        try:
            fcntl.lockf(fd, fcntl.LOCK_UN, 1, 0, os.SEEK_SET)
        finally:
            os.close(fd)


def _hash_file(path: Path) -> tuple[str, int]:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags)
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode):
            raise UpgradeEvidenceError("data tree contains a link or special file")
        digest, size = hashlib.sha256(), 0
        while chunk := os.read(fd, 1024 * 1024):
            _check_deadline()
            digest.update(chunk)
            size += len(chunk)
        final = os.fstat(fd)
        if (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) != (
            final.st_dev, final.st_ino, final.st_size, final.st_mtime_ns
        ):
            raise UpgradeEvidenceError("data file changed during cold inspection")
        return digest.hexdigest(), size
    finally:
        os.close(fd)


def _tree_inventory(root: Path, *, max_files: int, max_bytes: int) -> dict:
    try:
        records = recovery._fd_tree(
            root, copy_to=None, max_files=max_files, max_bytes=max_bytes
        )
    except recovery.RecoveryError as exc:
        raise UpgradeEvidenceError(str(exc)) from exc
    public = recovery._public_inventory(records)
    total_bytes = sum(int(item["size"]) for item in public if item["kind"] == "file")
    names = {item["path"] for item in public if item["kind"] == "file"}
    return {
        "files": len(public),
        "bytes": total_bytes,
        "inventory_sha256": _digest(public),
        "database_present": "analyzer.db" in names,
        "wal_present": "analyzer.db-wal" in names,
        "shm_present": "analyzer.db-shm" in names,
    }


def _copy_database_bundle(root: Path, validation_root: Path, max_bytes: int) -> Path:
    validation_root = validation_root.resolve()
    validation_root.mkdir(parents=True, exist_ok=True)
    if validation_root.is_symlink() or any(validation_root.iterdir()):
        raise UpgradeEvidenceError("private database validation directory must be empty")
    destination = Path(tempfile.mkdtemp(prefix="nct-gate4c-db-", dir=validation_root))
    root_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        root_flags |= os.O_NOFOLLOW
    root_fd = os.open(root, root_flags)
    total = 0
    try:
        for name in ("analyzer.db", "analyzer.db-wal", "analyzer.db-shm"):
            _check_deadline()
            file_flags = os.O_RDONLY | os.O_CLOEXEC
            if hasattr(os, "O_NOFOLLOW"):
                file_flags |= os.O_NOFOLLOW
            try:
                source_fd = os.open(name, file_flags, dir_fd=root_fd)
            except FileNotFoundError:
                if name == "analyzer.db":
                    raise UpgradeEvidenceError("the cold data root has no analyzer.db")
                continue
            try:
                opened = os.fstat(source_fd)
                if not stat.S_ISREG(opened.st_mode):
                    raise UpgradeEvidenceError("database bundle contains a link or special file")
                target = destination / name
                out_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
                target_fd = os.open(target, out_flags, 0o600)
                try:
                    with os.fdopen(os.dup(source_fd), "rb") as source_handle, os.fdopen(
                        os.dup(target_fd), "wb"
                    ) as target_handle:
                        while chunk := source_handle.read(1024 * 1024):
                            _check_deadline()
                            total += len(chunk)
                            if total > max_bytes:
                                raise UpgradeEvidenceError("database validation copy exceeds its byte limit")
                            target_handle.write(chunk)
                        target_handle.flush()
                        os.fsync(target_handle.fileno())
                finally:
                    os.close(target_fd)
                final = os.fstat(source_fd)
                if (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) != (
                    final.st_dev, final.st_ino, final.st_size, final.st_mtime_ns
                ):
                    raise UpgradeEvidenceError("database bundle changed during private copy")
            finally:
                os.close(source_fd)
        directory_fd = os.open(destination, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except BaseException:
        import shutil
        shutil.rmtree(destination, ignore_errors=True)
        raise
    finally:
        os.close(root_fd)
    return destination / "analyzer.db"


def _database_observation(db_path: Path, root: Path, *, max_bytes: int) -> dict:
    uri = db_path.resolve().as_uri() + "?mode=ro"
    connection = sqlite3.connect(uri, uri=True, timeout=30)
    try:
        integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
        user_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        tables = {
            row[0] for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        counts = {}
        for name in (
            "artifact_registry", "artifact_observations", "imports", "endpoint_receipts",
            "service_receipts", "pipeline_jobs", "analyst_users", "analyst_sessions",
        ):
            counts[name] = int(connection.execute(f'SELECT COUNT(*) FROM "{name}"').fetchone()[0]) if name in tables else 0
        active_work = 0
        if "pipeline_jobs" in tables:
            active_work = int(connection.execute(
                "SELECT COUNT(*) FROM pipeline_jobs WHERE state IN ('queued','running','awaiting_fallback_approval','updating','migrating')"
            ).fetchone()[0])
        artifacts = []
        artifact_bytes = 0
        if "artifact_registry" in tables:
            for sha256, stored_path, size_bytes in connection.execute(
                "SELECT sha256, stored_path, size_bytes FROM artifact_registry ORDER BY sha256"
            ):
                _check_deadline()
                path = Path(stored_path)
                if not path.is_absolute():
                    path = root / path
                path = path.resolve()
                try:
                    path.relative_to(root.resolve())
                except ValueError as exc:
                    raise UpgradeEvidenceError("Artifact Registry path escapes the data root") from exc
                digest, size = _hash_file(path)
                artifact_bytes += size
                if artifact_bytes > max_bytes:
                    raise UpgradeEvidenceError("Artifact Registry verification exceeds the byte limit")
                if digest != sha256 or size != int(size_bytes):
                    raise UpgradeEvidenceError("Artifact Registry content verification failed")
                artifacts.append({"sha256": sha256, "size": size})
        state = schema_state(db_path)
    finally:
        connection.close()
    ledger = state["migration_ledger"]
    ledger_head = ledger[-1] if ledger else None
    return {
        "integrity": integrity,
        "user_version": user_version,
        "schema_state": state,
        "migration_ledger_head": ledger_head,
        "table_counts": counts,
        "active_work": active_work,
        "artifact_registry_verified": len(artifacts),
        "artifact_registry_sha256": _digest(artifacts),
    }


def inspect_data(args: argparse.Namespace) -> dict:
    _start_deadline(args.max_seconds)
    root = args.data_root.resolve()
    contract = image_schema_contract()
    if contract["contract_digest"] != args.contract_digest:
        raise UpgradeEvidenceError("the supplied schema-contract digest does not belong to this image")
    if not IMAGE_RE.fullmatch(args.image):
        raise UpgradeEvidenceError("image must use an exact sha256 digest")
    if len(args.runtime_image_id) > 1_024 or _image_digest(args.runtime_image_id) != _image_digest(args.image):
        raise UpgradeEvidenceError("runtime image ID does not match the requested immutable image")
    with _available_writer_lock(root):
        inventory = _tree_inventory(root, max_files=args.max_files, max_bytes=args.max_bytes)
        if not inventory["database_present"]:
            raise UpgradeEvidenceError("the cold data root has no analyzer.db")
        private_db = _copy_database_bundle(
            root, args.validation_root, args.max_validation_bytes
        )
        try:
            database = _database_observation(
                private_db, root, max_bytes=args.max_bytes
            )
        finally:
            import shutil
            shutil.rmtree(private_db.parent, ignore_errors=True)
    if database["integrity"] != "ok":
        raise UpgradeEvidenceError("cold database integrity check failed")
    if database["active_work"]:
        raise UpgradeEvidenceError(
            "Upgrade blocked: active work was detected. Nothing was opened or changed."
        )
    state = database["schema_state"]
    if args.phase != "failed-candidate":
        if not state["schema_fingerprint_matches"]:
            raise UpgradeEvidenceError("recorded and live schema fingerprints differ")
        if any(item["status"] != "completed" for item in state["migration_ledger"]):
            raise UpgradeEvidenceError("schema migration ledger contains incomplete work")
    body = {
        "schema_version": RECEIPT_SCHEMA_VERSION,
        "tool_version": TOOL_VERSION,
        "status": "failed_candidate_inspection_recorded" if args.phase == "failed-candidate" else "upgrade_inspection_passed",
        "scenario_id": args.scenario_id,
        "phase": args.phase,
        "recorded_at": datetime.now().astimezone().isoformat(),
        "image": args.image,
        "runtime_image_id": args.runtime_image_id,
        "application_version": contract["application_version"],
        "build_id": contract["build_id"],
        "build_commit": contract["build_commit"],
        "schema_contract_digest": contract["contract_digest"],
        "deployment_uid": args.deployment_uid,
        "deployment_generation": args.deployment_generation,
        "pod_uid": args.pod_uid,
        "node_uid": args.node_uid,
        "storage_attachment_identity": args.storage_attachment_identity,
        "pvc_uid": args.pvc_uid,
        "bound_volume_uid": args.bound_volume_uid,
        "qualification_report_digest": args.qualification_report_digest,
        "inventory": inventory,
        "database": database,
        "writer_lock": "available",
    }
    return _receipt(body)


def _validated_contract(path: Path, label: str) -> dict:
    value = _read_json(path, label)
    digest = value.get("contract_digest")
    body = {key: item for key, item in value.items() if key != "contract_digest"}
    if not isinstance(digest, str) or digest != _digest(body):
        raise UpgradeEvidenceError(f"{label} contract digest is invalid")
    required = {
        "schema_contract_version", "application_version", "build_id", "build_commit",
        "readable_schema_versions", "writable_schema_version", "data_layout_contract",
        "migration_ids", "migration_plan_digest", "direct_rollback_rule",
    }
    if not required <= value.keys():
        raise UpgradeEvidenceError(f"{label} contract is incomplete")
    if value["migration_plan_digest"] != _digest({"migration_ids": value["migration_ids"]}):
        raise UpgradeEvidenceError(f"{label} migration-plan digest is invalid")
    return value


def bind_contract(args: argparse.Namespace) -> dict:
    contract = _validated_contract(args.contract, "image")
    if not IMAGE_RE.fullmatch(args.requested_image):
        raise UpgradeEvidenceError("requested image must use an exact sha256 digest")
    if len(args.runtime_image_id) > 1_024 or _image_digest(args.runtime_image_id) != _image_digest(args.requested_image):
        raise UpgradeEvidenceError("runtime image ID does not match the requested immutable image")
    body = {
        "schema_version": RECEIPT_SCHEMA_VERSION,
        "tool_version": TOOL_VERSION,
        "status": "image_contract_bound",
        "requested_image": args.requested_image,
        "runtime_image_id": args.runtime_image_id,
        "application_version": contract["application_version"],
        "build_id": contract["build_id"],
        "build_commit": contract["build_commit"],
        "contract_digest": contract["contract_digest"],
        "contract": contract,
    }
    return _receipt(body)


def _validated_envelope(path: Path, label: str, expected_image: str) -> dict:
    value = _read_json(path, label)
    _verify_receipt(value, label)
    if value.get("status") != "image_contract_bound":
        raise UpgradeEvidenceError(f"{label} is not a bound image contract")
    contract = value.get("contract")
    if not isinstance(contract, dict):
        raise UpgradeEvidenceError(f"{label} has no schema contract")
    contract_body = {key: item for key, item in contract.items() if key != "contract_digest"}
    if contract.get("contract_digest") != _digest(contract_body):
        raise UpgradeEvidenceError(f"{label} schema contract digest is invalid")
    if (
        value.get("requested_image") != expected_image
        or _image_digest(value.get("runtime_image_id")) != _image_digest(expected_image)
        or value.get("contract_digest") != contract.get("contract_digest")
        or value.get("application_version") != contract.get("application_version")
        or value.get("build_id") != contract.get("build_id")
        or value.get("build_commit") != contract.get("build_commit")
    ):
        raise UpgradeEvidenceError(f"{label} does not bind the expected image and build")
    return value


def _validated_backup(
    receipt_path: Path, manifest_path: Path, expected_digest: str,
    before: dict, old_image: str, old_contract: dict,
) -> tuple[dict, dict]:
    if not DIGEST_RE.fullmatch(expected_digest):
        raise UpgradeEvidenceError("separately retained backup receipt digest is invalid")
    receipt = _read_json(receipt_path, "Gate 4A backup receipt")
    manifest = _read_json(manifest_path, "Gate 4A backup manifest", limit=128 * 1024**2)
    _verify_receipt(receipt, "Gate 4A backup")
    if receipt.get("receipt_sha256") != expected_digest:
        raise UpgradeEvidenceError("Gate 4A backup receipt differs from its separately retained digest")
    manifest_body = {key: item for key, item in manifest.items() if key != "manifest_sha256"}
    if manifest.get("manifest_sha256") != _digest(manifest_body):
        raise UpgradeEvidenceError("Gate 4A backup manifest digest is invalid")
    required_manifest = {
        "source", "backup", "inventory", "inventory_root_sha256", "archive",
        "database", "artifact_registry", "retained_evidence", "manifest_sha256",
    }
    if not required_manifest <= manifest.keys() or not isinstance(manifest.get("inventory"), list):
        raise UpgradeEvidenceError("Gate 4A backup manifest is incomplete")
    if manifest.get("inventory_root_sha256") != _digest(manifest["inventory"]):
        raise UpgradeEvidenceError("Gate 4A backup inventory digest is invalid")
    backup_identity = (manifest.get("backup") or {}).get("storage_identity") or {}
    archive = manifest.get("archive") or {}
    if (
        receipt.get("status") != "backup_verified"
        or receipt.get("manifest_sha256") != manifest.get("manifest_sha256")
        or receipt.get("inventory_root_sha256") != manifest.get("inventory_root_sha256")
        or receipt.get("archive_sha256") != archive.get("sha256")
        or receipt.get("source_storage_identity_sha256") != _digest((manifest.get("source") or {}).get("storage_identity") or {})
        or receipt.get("backup_storage_identity_sha256") != _digest(backup_identity)
        or receipt.get("source_qualification_report_digest") != (manifest.get("source") or {}).get("qualification_report_digest")
        or receipt.get("backup_qualification_report_digest") != (manifest.get("backup") or {}).get("qualification_report_digest")
        or receipt.get("retained_evidence_verified") != (manifest.get("retained_evidence") or {}).get("verified")
        or not receipt.get("source_and_backup_preserved")
    ):
        raise UpgradeEvidenceError("Gate 4A backup receipt does not authorize the manifest")
    if not isinstance(receipt.get("retained_evidence_verified"), int):
        raise UpgradeEvidenceError("Gate 4A backup retained-evidence result is invalid")
    source = manifest.get("source") or {}
    identity = source.get("storage_identity") or {}
    if (
        source.get("image") != old_image
        or source.get("application_version") != old_contract.get("application_version")
        or source.get("build_id") != old_contract.get("build_id")
        or identity.get("pvc_uid") != before.get("pvc_uid")
        or identity.get("bound_volume_uid") != before.get("bound_volume_uid")
        or source.get("qualification_report_digest") != before.get("qualification_report_digest")
        or manifest.get("inventory_root_sha256") != before.get("inventory", {}).get("inventory_sha256")
    ):
        raise UpgradeEvidenceError("Gate 4A backup does not match the inspected source data and storage")
    return receipt, manifest


def create_plan(args: argparse.Namespace) -> dict:
    old_envelope = _validated_envelope(args.old_contract, "old image contract", args.old_image)
    new_envelope = _validated_envelope(args.new_contract, "new image contract", args.new_image)
    old_contract = old_envelope["contract"]
    new_contract = new_envelope["contract"]
    before = _read_json(args.before_inspection, "before inspection")
    _verify_receipt(before, "before inspection")
    if before.get("status") != "upgrade_inspection_passed" or before.get("phase") != "before-upgrade":
        raise UpgradeEvidenceError("before inspection is not a passing pre-upgrade inspection")
    if before.get("scenario_id") != args.scenario_id:
        raise UpgradeEvidenceError("scenario identity changed before planning")
    if (
        before.get("image") != args.old_image
        or _image_digest(before.get("runtime_image_id")) != _image_digest(old_envelope["runtime_image_id"])
        or old_contract["contract_digest"] != before.get("schema_contract_digest")
    ):
        raise UpgradeEvidenceError("old image or schema contract does not match the cold source")
    backup, manifest = _validated_backup(
        args.backup_receipt, args.backup_manifest, args.backup_receipt_digest,
        before, args.old_image, old_contract,
    )
    if args.old_image == args.new_image:
        raise UpgradeEvidenceError("old and new image digests must be different")
    if (
        args.expected_candidate_generation <= int(before["deployment_generation"])
        or args.expected_rollback_generation <= args.expected_candidate_generation
    ):
        raise UpgradeEvidenceError("planned Deployment generations must advance in strict order")
    current = before["database"]["schema_state"]
    if current["schema_version"] not in old_contract["readable_schema_versions"]:
        raise UpgradeEvidenceError("old image contract does not authorize the current schema")
    new_target = int(new_contract["writable_schema_version"])
    direct = (
        new_target in old_contract["readable_schema_versions"]
        and new_target == int(old_contract["writable_schema_version"])
        and old_contract["data_layout_contract"] == new_contract["data_layout_contract"]
        and old_contract["migration_plan_digest"] == new_contract["migration_plan_digest"]
    )
    decision = "direct" if direct else "restore"
    body = {
        "schema_version": RECEIPT_SCHEMA_VERSION,
        "tool_version": TOOL_VERSION,
        "status": "upgrade_preflight_passed",
        "scenario_id": args.scenario_id,
        "created_at": datetime.now().astimezone().isoformat(),
        "old_image": args.old_image,
        "new_image": args.new_image,
        "old_contract": old_contract,
        "new_contract": new_contract,
        "old_contract_envelope_sha256": old_envelope["receipt_sha256"],
        "new_contract_envelope_sha256": new_envelope["receipt_sha256"],
        "old_runtime_image_id": old_envelope["runtime_image_id"],
        "new_runtime_image_id": new_envelope["runtime_image_id"],
        "before_inspection_sha256": before["receipt_sha256"],
        "backup_receipt_sha256": backup["receipt_sha256"],
        "backup_manifest_sha256": manifest["manifest_sha256"],
        "backup_inventory_root_sha256": manifest["inventory_root_sha256"],
        "backup_storage": (manifest.get("backup") or {}).get("storage_identity") or {},
        "backup_storage_qualification_report_digest": (manifest.get("backup") or {}).get("qualification_report_digest"),
        "source_storage": {
            key: before[key] for key in (
                "pvc_uid", "bound_volume_uid", "qualification_report_digest",
                "storage_attachment_identity",
            )
        },
        "source_cluster": {
            key: before[key] for key in (
                "deployment_uid", "deployment_generation", "pod_uid", "node_uid",
            )
        },
        "expected_candidate_generation": args.expected_candidate_generation,
        "expected_rollback_generation": args.expected_rollback_generation,
        "current_schema_version": current["schema_version"],
        "target_schema_version": new_target,
        "rollback_decision": decision,
        "direct_rollback_authorized": direct,
        "compatibility_rule": old_contract["direct_rollback_rule"],
        "operator_message": (
            "Direct rollback is machine-authorized for this exact unchanged schema and migration plan."
            if direct else
            "Restore required: use the verified pre-upgrade backup and a separate empty qualified target."
        ),
    }
    return _receipt(body)


def _sha256_file(path: Path, max_bytes: int) -> str:
    digest, size = _hash_file(path)
    if size > max_bytes:
        raise UpgradeEvidenceError("selected evidence exceeds the declared byte limit")
    return digest


def _validate_web_check(value: dict, phase: str) -> None:
    if value.get("phase") != phase:
        raise UpgradeEvidenceError(f"{phase} web check is mislabeled")
    if value.get("startup_status") != 200 or value.get("readiness_status") != 200:
        raise UpgradeEvidenceError(f"{phase} startup or readiness did not pass")
    if value.get("existing_account_signin") is not True:
        raise UpgradeEvidenceError(f"{phase} existing-account sign-in did not pass")


def _validate_events(path: Path, scenario_id: str, required: list[str]) -> list[dict]:
    value = _read_json(path, "upgrade event record")
    events = value.get("events")
    if value.get("scenario_id") != scenario_id or not isinstance(events, list) or len(events) > 100:
        raise UpgradeEvidenceError("upgrade event record is invalid or unbounded")
    seen, last = [], None
    for item in events:
        if not isinstance(item, dict) or not isinstance(item.get("event"), str):
            raise UpgradeEvidenceError("upgrade event is malformed")
        try:
            timestamp = datetime.fromisoformat(item["at"])
        except (KeyError, TypeError, ValueError) as exc:
            raise UpgradeEvidenceError("upgrade event timestamp is invalid") from exc
        if timestamp.tzinfo is None or (last is not None and timestamp <= last):
            raise UpgradeEvidenceError("upgrade events must have strictly increasing UTC-aware timestamps")
        if timestamp.utcoffset().total_seconds() != 0:
            raise UpgradeEvidenceError("upgrade event timestamps must be UTC")
        last = timestamp
        seen.append(item["event"])
    cursor = 0
    for event in seen:
        if cursor < len(required) and event == required[cursor]:
            cursor += 1
    if cursor != len(required):
        raise UpgradeEvidenceError("upgrade event record is missing or reorders a required event")
    return events


def record_candidate_failure(args: argparse.Namespace) -> dict:
    envelope = _validated_envelope(args.contract, "candidate contract", args.image)
    contract = envelope["contract"]
    inspection = _read_json(args.failed_inspection, "failed candidate inspection")
    _verify_receipt(inspection, "failed candidate inspection")
    if (
        inspection.get("status") != "failed_candidate_inspection_recorded"
        or inspection.get("phase") != "failed-candidate"
        or inspection.get("scenario_id") != args.scenario_id
        or inspection.get("image") != args.image
        or _image_digest(inspection.get("runtime_image_id")) != _image_digest(args.image)
        or inspection.get("schema_contract_digest") != contract.get("contract_digest")
    ):
        raise UpgradeEvidenceError("failed candidate inspection does not match the failed image")
    evidence = _read_json(args.failure_evidence, "candidate failure evidence")
    runtime = evidence.get("runtime") or {}
    container = evidence.get("container") or {}
    if (
        evidence.get("scenario_id") != args.scenario_id
        or evidence.get("phase") != "candidate-failure"
        or runtime.get("pod_uid") != inspection.get("pod_uid")
        or _image_digest(runtime.get("image_id")) != _image_digest(args.image)
        or not isinstance(evidence.get("observed_at"), str)
        or not isinstance(container.get("exit_code"), int)
    ):
        raise UpgradeEvidenceError("candidate failure evidence does not match the inspected Pod and image")
    _utc_timestamp(evidence["observed_at"], "candidate failure evidence")
    startup_status = evidence.get("startup_status")
    readiness_status = evidence.get("readiness_status")
    terminated_failure = container.get("terminated") is True and container.get("exit_code") != 0
    health_failure = startup_status != 200 or readiness_status != 200
    if not terminated_failure and not health_failure:
        raise UpgradeEvidenceError("a successful candidate cannot be recorded as failed")
    if args.failure_stage == "during-migration":
        state = inspection.get("database", {}).get("schema_state", {})
        ledger = state.get("migration_ledger") or []
        incomplete = (
            state.get("schema_fingerprint_matches") is not True
            or state.get("schema_version") != contract["writable_schema_version"]
            or any(item.get("status") != "completed" for item in ledger)
        )
        if not incomplete:
            raise UpgradeEvidenceError("a completed healthy migration cannot be relabeled as a migration failure")
    body = {
        "schema_version": RECEIPT_SCHEMA_VERSION,
        "tool_version": TOOL_VERSION,
        "status": "candidate_startup_failed",
        "scenario_id": args.scenario_id,
        "recorded_at": datetime.now().astimezone().isoformat(),
        "image": args.image,
        "runtime_image_id": inspection["runtime_image_id"],
        "failure_stage": args.failure_stage,
        "startup_status": startup_status,
        "readiness_status": readiness_status,
        "container_terminated": container.get("terminated") is True,
        "container_exit_code": container.get("exit_code"),
        "failure_reason": str(container.get("reason", ""))[:200],
        "failure_observed_at": evidence["observed_at"],
        "failure_evidence_sha256": _digest(evidence),
        "failed_inspection_sha256": inspection["receipt_sha256"],
        "contract_envelope_sha256": envelope["receipt_sha256"],
    }
    return _receipt(body)


def record_cluster_observation(args: argparse.Namespace) -> dict:
    expected_ready = {
        "old-stopped": 0, "candidate-ready": 1, "candidate-failed": 0,
        "candidate-stopped": 0, "rollback-ready": 1, "rollback-stopped": 0,
    }
    expected_writers = {
        "old-stopped": {0}, "candidate-ready": {1}, "candidate-failed": {0, 1},
        "candidate-stopped": {0}, "rollback-ready": {1}, "rollback-stopped": {0},
    }
    writer_receipt = _read_json(args.writer_receipt, "cluster-observation writer-lock receipt")
    writer_digest = _verify_lock_attestation(writer_receipt, "cluster-observation writer-lock receipt")
    probe_phase = {
        "old-stopped": "old-writer-released",
        "candidate-ready": "candidate-writer-active",
        "candidate-failed": "candidate-writer-active",
        "candidate-stopped": "candidate-writer-released",
        "rollback-ready": "rollback-writer-active",
        "rollback-stopped": "rollback-writer-released",
    }[args.phase]
    lock = writer_receipt.get("writer_lock") or {}
    scenario = writer_receipt.get("scenario") or {}
    observed = lock.get("observed")
    measured_writers = 1 if observed == "contended" else 0 if observed == "available" else -1
    if (
        writer_receipt.get("status") != "pass"
        or scenario != {"id": args.scenario_id, "kind": "guarded-upgrade", "phase": probe_phase}
        or lock.get("opened_existing_only") is not True
        or lock.get("sqlite_opened") is not False
        or measured_writers < 0
    ):
        raise UpgradeEvidenceError("cluster observation writer-lock receipt is invalid or belongs to another phase")
    if (
        args.ready_pods != expected_ready[args.phase]
        or measured_writers not in expected_writers[args.phase]
        or args.writer_owners != measured_writers
    ):
        raise UpgradeEvidenceError("cluster observation counts do not match the declared phase")
    samples: list[dict] = []
    if args.previous:
        prior = _read_json(args.previous, "prior cluster observations")
        if prior.get("scenario_id") != args.scenario_id or not isinstance(prior.get("samples"), list):
            raise UpgradeEvidenceError("prior cluster observations belong to another scenario")
        samples = list(prior["samples"])
        if len(samples) >= 5:
            raise UpgradeEvidenceError("cluster observation record is already complete")
    sample = {
        "at": datetime.now(timezone.utc).isoformat(), "phase": args.phase,
        "ready_pods": args.ready_pods, "writer_owners": measured_writers,
        "writer_lock_attestation_sha256": writer_digest,
        "deployment_uid": args.deployment_uid,
        "deployment_generation": args.deployment_generation,
        "pod_uid": args.pod_uid, "node_uid": args.node_uid,
        "storage_attachment_identity": args.storage_attachment_identity,
        "pvc_uid": args.pvc_uid, "bound_volume_uid": args.bound_volume_uid,
    }
    return {"scenario_id": args.scenario_id, "samples": [*samples, sample]}


def _validate_inspection(
    value: dict, *, plan: dict, phase: str, image: str, contract: dict,
    status: str = "upgrade_inspection_passed",
) -> None:
    if (
        value.get("status") != status
        or value.get("scenario_id") != plan.get("scenario_id")
        or value.get("phase") != phase
        or value.get("image") != image
        or _image_digest(value.get("runtime_image_id")) != _image_digest(image)
        or value.get("schema_contract_digest") != contract.get("contract_digest")
        or value.get("application_version") != contract.get("application_version")
        or value.get("build_id") != contract.get("build_id")
        or value.get("build_commit") != contract.get("build_commit")
        or value.get("writer_lock") != "available"
    ):
        raise UpgradeEvidenceError(f"{phase} inspection does not match its planned image, build, or released writer")


def _same_storage(value: dict, expected: dict) -> bool:
    return all(value.get(key) == expected.get(key) for key in (
        "pvc_uid", "bound_volume_uid", "qualification_report_digest",
        "storage_attachment_identity",
    ))


def _verify_lock_attestation(value: dict, label: str) -> str:
    attestation = value.get("attestation") or {}
    body = {key: item for key, item in value.items() if key != "attestation"}
    digest = _digest(body)
    if attestation.get("algorithm") != "sha256" or attestation.get("digest") != digest:
        raise UpgradeEvidenceError(f"{label} digest is invalid")
    return digest


def _validate_lock_receipt(path: Path, *, scenario: str, phase: str, inspection: dict) -> dict:
    value = _read_json(path, f"{phase} writer-lock receipt")
    _verify_lock_attestation(value, f"{phase} writer-lock receipt")
    scenario_info = value.get("scenario") or {}
    deployment = value.get("deployment") or {}
    runtime = value.get("runtime") or {}
    storage = value.get("storage") or {}
    lock = value.get("writer_lock") or {}
    if (
        value.get("status") != "pass"
        or scenario_info != {"id": scenario, "kind": "guarded-upgrade", "phase": phase}
        or runtime.get("image") != inspection.get("image")
        or runtime.get("application_version") != inspection.get("application_version")
        or runtime.get("build_id") != inspection.get("build_id")
        or deployment.get("uid") != inspection.get("deployment_uid")
        or deployment.get("generation") != inspection.get("deployment_generation")
        or deployment.get("pod_uid") != inspection.get("pod_uid")
        or deployment.get("node_uid") != inspection.get("node_uid")
        or deployment.get("storage_attachment_identity") != inspection.get("storage_attachment_identity")
        or storage.get("pvc_uid") != inspection.get("pvc_uid")
        or storage.get("bound_volume_uid") != inspection.get("bound_volume_uid")
        or storage.get("qualification_report_digest") != inspection.get("qualification_report_digest")
        or lock.get("expected") != "available"
        or lock.get("observed") != "available"
        or lock.get("opened_existing_only") is not True
        or lock.get("sqlite_opened") is not False
    ):
        raise UpgradeEvidenceError(f"{phase} writer-lock receipt does not match the exact stopped phase")
    return value


def _validate_active_lock_receipt(
    path: Path, *, scenario: str, phase: str, inspection: dict,
    allow_observe: bool = False,
) -> dict:
    value = _read_json(path, f"{phase} writer-lock receipt")
    _verify_lock_attestation(value, f"{phase} writer-lock receipt")
    scenario_info = value.get("scenario") or {}
    deployment = value.get("deployment") or {}
    runtime = value.get("runtime") or {}
    storage = value.get("storage") or {}
    lock = value.get("writer_lock") or {}
    expected_values = {"observe"} if allow_observe else {"contended"}
    observed_values = {"available", "contended"} if allow_observe else {"contended"}
    if (
        value.get("status") != "pass"
        or scenario_info != {"id": scenario, "kind": "guarded-upgrade", "phase": phase}
        or runtime.get("image") != inspection.get("image")
        or runtime.get("application_version") != inspection.get("application_version")
        or runtime.get("build_id") != inspection.get("build_id")
        or deployment.get("uid") != inspection.get("deployment_uid")
        or deployment.get("generation") != inspection.get("deployment_generation")
        or deployment.get("pod_uid") != inspection.get("pod_uid")
        or deployment.get("node_uid") != inspection.get("node_uid")
        or deployment.get("storage_attachment_identity") != inspection.get("storage_attachment_identity")
        or storage.get("pvc_uid") != inspection.get("pvc_uid")
        or storage.get("bound_volume_uid") != inspection.get("bound_volume_uid")
        or storage.get("qualification_report_digest") != inspection.get("qualification_report_digest")
        or lock.get("expected") not in expected_values
        or lock.get("observed") not in observed_values
        or lock.get("opened_existing_only") is not True
        or lock.get("sqlite_opened") is not False
        or lock.get("released_if_acquired") is not (lock.get("observed") == "available")
    ):
        raise UpgradeEvidenceError(f"{phase} writer-lock receipt does not match the exact active phase")
    return value


def _validate_cluster_observations(
    path: Path, scenario: str, expected: list[tuple[str, int, dict, dict]],
) -> dict:
    value = _read_json(path, "cluster observations")
    samples = value.get("samples")
    if value.get("scenario_id") != scenario or not isinstance(samples, list) or len(samples) != len(expected):
        raise UpgradeEvidenceError("cluster observations are incomplete or belong to another scenario")
    last = None
    for sample, (phase, ready, inspection, writer_receipt) in zip(samples, expected):
        observed_lock = (writer_receipt.get("writer_lock") or {}).get("observed")
        measured_writers = (
            1 if observed_lock == "contended" else
            0 if observed_lock == "available" else -1
        )
        try:
            when = datetime.fromisoformat(sample["at"])
        except (KeyError, TypeError, ValueError) as exc:
            raise UpgradeEvidenceError("cluster observation timestamp is invalid") from exc
        if when.tzinfo is None or when.utcoffset().total_seconds() != 0 or (last is not None and when <= last):
            raise UpgradeEvidenceError("cluster observations must be strictly ordered UTC timestamps")
        last = when
        if (
            sample.get("phase") != phase
            or sample.get("ready_pods") != ready
            or measured_writers < 0
            or sample.get("writer_owners") != measured_writers
            or sample.get("writer_lock_attestation_sha256")
            != writer_receipt.get("attestation", {}).get("digest")
            or int(sample.get("ready_pods", 2)) > 1
            or int(sample.get("writer_owners", 2)) > 1
            or sample.get("deployment_uid") != inspection.get("deployment_uid")
            or sample.get("deployment_generation") != inspection.get("deployment_generation")
            or sample.get("pod_uid") != inspection.get("pod_uid")
            or sample.get("node_uid") != inspection.get("node_uid")
            or sample.get("storage_attachment_identity") != inspection.get("storage_attachment_identity")
            or sample.get("pvc_uid") != inspection.get("pvc_uid")
            or sample.get("bound_volume_uid") != inspection.get("bound_volume_uid")
        ):
            raise UpgradeEvidenceError(f"cluster observation {phase} does not prove the exact single-writer transition")
    return value


def _validate_restore_receipt(path: Path, expected_digest: str, *, plan: dict, rollback: dict) -> dict:
    if not DIGEST_RE.fullmatch(expected_digest):
        raise UpgradeEvidenceError("separately retained restore receipt digest is invalid")
    value = _read_json(path, "Gate 4A restore receipt")
    _verify_receipt(value, "Gate 4A restore")
    source = value.get("source_storage_identity") or {}
    target = value.get("target_storage_identity") or {}
    if (
        value.get("receipt_sha256") != expected_digest
        or value.get("status") != "restore_verification_passed"
        or value.get("source_image") != plan.get("old_image")
        or value.get("source_application_version") != plan["old_contract"].get("application_version")
        or value.get("source_build_id") != plan["old_contract"].get("build_id")
        or value.get("manifest_sha256") != plan.get("backup_manifest_sha256")
        or value.get("backup_receipt_sha256") != plan.get("backup_receipt_sha256")
        or value.get("inventory_root_sha256") != plan.get("backup_inventory_root_sha256")
        or source.get("pvc_uid") != plan["source_storage"].get("pvc_uid")
        or source.get("bound_volume_uid") != plan["source_storage"].get("bound_volume_uid")
        or value.get("source_qualification_report_digest") != plan["source_storage"].get("qualification_report_digest")
        or target.get("pvc_uid") != rollback.get("pvc_uid")
        or target.get("bound_volume_uid") != rollback.get("bound_volume_uid")
        or value.get("target_qualification_report_digest") != rollback.get("qualification_report_digest")
        or (value.get("backup_storage_identity") or {}).get("pvc_uid") != plan["backup_storage"].get("pvc_uid")
        or (value.get("backup_storage_identity") or {}).get("bound_volume_uid") != plan["backup_storage"].get("bound_volume_uid")
        or value.get("backup_qualification_report_digest") != plan.get("backup_storage_qualification_report_digest")
        or value.get("source_and_backup_preserved") is not True
        or not isinstance(value.get("retained_evidence_verified"), int)
        or value.get("retained_evidence_verified", -1) < 0
    ):
        raise UpgradeEvidenceError("Gate 4A restore receipt does not prove the planned source and fresh target")
    return value


def _utc_timestamp(value: object, label: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value))
    except ValueError as exc:
        raise UpgradeEvidenceError(f"{label} timestamp is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset().total_seconds() != 0:
        raise UpgradeEvidenceError(f"{label} timestamp must be UTC-aware")
    return parsed


def _validate_cross_record_chronology(
    *, before: dict, candidate: dict, rollback: dict, old_lock: dict,
    candidate_active_lock: dict, candidate_lock: dict,
    rollback_active_lock: dict, rollback_lock: dict, observations: dict,
    events: list[dict], successful: bool, restore_receipt: dict | None,
    failure_receipt: dict | None,
) -> None:
    samples = {item["phase"]: item for item in observations["samples"]}
    event_times = {item["event"]: _utc_timestamp(item["at"], f"{item['event']} event") for item in events}
    candidate_phase = "candidate-ready" if successful else "candidate-failed"
    rollback_start = "old-started-on-current-data" if "old-started-on-current-data" in event_times else "old-started-on-restored-data"
    prefix = [
        _utc_timestamp(old_lock["checked_at"], "old writer release"),
        _utc_timestamp(samples["old-stopped"]["at"], "old stopped observation"),
        _utc_timestamp(before["recorded_at"], "before inspection"),
        event_times["candidate-started"],
    ]
    if failure_receipt is not None:
        prefix.append(_utc_timestamp(failure_receipt["failure_observed_at"], "candidate failure"))
    prefix.extend([
        _utc_timestamp(candidate_active_lock["checked_at"], "candidate active writer measurement"),
        _utc_timestamp(samples[candidate_phase]["at"], f"{candidate_phase} observation"),
        _utc_timestamp(candidate_lock["checked_at"], "candidate writer release"),
        _utc_timestamp(samples["candidate-stopped"]["at"], "candidate stopped observation"),
        _utc_timestamp(candidate["recorded_at"], "candidate inspection"),
    ])
    if restore_receipt is not None:
        prefix.append(_utc_timestamp(restore_receipt["verified_at"], "restore verification"))
    ordered = [
        *prefix,
        event_times[rollback_start],
        _utc_timestamp(rollback_active_lock["checked_at"], "rollback active writer measurement"),
        _utc_timestamp(samples["rollback-ready"]["at"], "rollback ready observation"),
        _utc_timestamp(rollback_lock["checked_at"], "rollback writer release"),
        _utc_timestamp(samples["rollback-stopped"]["at"], "rollback stopped observation"),
        _utc_timestamp(rollback["recorded_at"], "rollback inspection"),
    ]
    if any(later <= earlier for earlier, later in zip(ordered, ordered[1:])):
        raise UpgradeEvidenceError("writer release, inspection, and cluster chronology is stale or reordered")


def verify_scenario(args: argparse.Namespace) -> dict:
    _start_deadline(args.max_seconds)
    plan = _read_json(args.plan, "upgrade plan")
    _verify_receipt(plan, "upgrade plan")
    before = _read_json(args.before_inspection, "before inspection")
    _verify_receipt(before, "before inspection")
    if plan.get("status") != "upgrade_preflight_passed":
        raise UpgradeEvidenceError("upgrade plan did not pass preflight")
    scenario = plan["scenario_id"]
    _validate_inspection(
        before, plan=plan, phase="before-upgrade", image=plan["old_image"],
        contract=plan["old_contract"],
    )
    if before["receipt_sha256"] != plan["before_inspection_sha256"]:
        raise UpgradeEvidenceError("before inspection changed after preflight")
    if not _same_storage(before, plan["source_storage"]) or any(
        before.get(key) != plan["source_cluster"].get(key)
        for key in ("deployment_uid", "deployment_generation", "pod_uid", "node_uid")
    ):
        raise UpgradeEvidenceError("before inspection no longer matches the planned source identities")
    before_web = _read_json(args.before_web_check, "before web check")
    _validate_web_check(before_web, "before-upgrade")
    before_hash = _sha256_file(args.evidence_before, args.max_evidence_bytes)
    old_lock = _validate_lock_receipt(
        args.old_lock_receipt, scenario=scenario, phase="old-writer-released", inspection=before,
    )

    successful = bool(args.after_inspection)
    failed = bool(args.failed_inspection)
    if successful == failed:
        raise UpgradeEvidenceError("provide exactly one successful or failed candidate inspection")
    after = None
    after_web = None
    after_hash = None
    failure = None
    candidate = None
    required = ["old-writer-released", "backup-verified", "preflight-passed", "candidate-started"]
    if successful:
        after = _read_json(args.after_inspection, "after inspection")
        _verify_receipt(after, "after inspection")
        _validate_inspection(
            after, plan=plan, phase="after-upgrade", image=plan["new_image"],
            contract=plan["new_contract"],
        )
        if (
            not _same_storage(after, plan["source_storage"])
            or after.get("deployment_uid") != plan["source_cluster"]["deployment_uid"]
            or after.get("deployment_generation") != plan["expected_candidate_generation"]
            or _image_digest(after.get("runtime_image_id")) != _image_digest(plan["new_runtime_image_id"])
        ):
            raise UpgradeEvidenceError("after-upgrade inspection does not match the planned cluster and storage identities")
        if after["database"]["schema_state"]["schema_version"] != plan["target_schema_version"]:
            raise UpgradeEvidenceError("candidate did not reach its declared target schema")
        for name, count in before["database"]["table_counts"].items():
            if after["database"]["table_counts"].get(name, 0) < count:
                raise UpgradeEvidenceError(f"retained record count decreased for {name}")
        after_web = _read_json(args.after_web_check, "after web check")
        _validate_web_check(after_web, "after-upgrade")
        after_hash = _sha256_file(args.evidence_after, args.max_evidence_bytes)
        if before_hash != after_hash:
            raise UpgradeEvidenceError("retained evidence download changed during upgrade")
        candidate = after
        required.append("candidate-ready")
    else:
        candidate = _read_json(args.failed_inspection, "failed candidate inspection")
        _verify_receipt(candidate, "failed candidate inspection")
        _validate_inspection(
            candidate, plan=plan, phase="failed-candidate", image=plan["new_image"],
            contract=plan["new_contract"], status="failed_candidate_inspection_recorded",
        )
        if (
            not _same_storage(candidate, plan["source_storage"])
            or candidate.get("deployment_uid") != plan["source_cluster"]["deployment_uid"]
            or candidate.get("deployment_generation") != plan["expected_candidate_generation"]
            or _image_digest(candidate.get("runtime_image_id")) != _image_digest(plan["new_runtime_image_id"])
        ):
            raise UpgradeEvidenceError("failed candidate inspection does not match the planned cluster and storage identities")
        failure = _read_json(args.candidate_failure, "candidate failure receipt")
        _verify_receipt(failure, "candidate failure")
        if (
            failure.get("status") != "candidate_startup_failed"
            or failure.get("scenario_id") != scenario
            or failure.get("image") != plan["new_image"]
            or failure.get("contract_envelope_sha256")
            != plan.get("new_contract_envelope_sha256")
            or failure.get("failed_inspection_sha256") != candidate["receipt_sha256"]
            or (failure.get("startup_status") == 200 and failure.get("readiness_status") == 200)
            or not DIGEST_RE.fullmatch(str(failure.get("failure_evidence_sha256", "")))
        ):
            raise UpgradeEvidenceError("candidate failure receipt does not prove the planned failure")
        required.append("candidate-failed")

    candidate_active_lock = _validate_active_lock_receipt(
        args.candidate_active_lock_receipt, scenario=scenario,
        phase="candidate-writer-active", inspection=candidate,
        allow_observe=failed,
    )
    candidate_lock = _validate_lock_receipt(
        args.candidate_lock_receipt, scenario=scenario,
        phase="candidate-writer-released", inspection=candidate,
    )
    required.append("candidate-writer-released")
    if not args.rollback_inspection or not args.rollback_web_check or not args.evidence_rollback:
        raise UpgradeEvidenceError("the guarded exercise requires rollback inspection, web, and evidence checks")
    rollback = _read_json(args.rollback_inspection, "rollback inspection")
    _verify_receipt(rollback, "rollback inspection")
    _validate_inspection(
        rollback, plan=plan, phase="after-rollback", image=plan["old_image"],
        contract=plan["old_contract"],
    )
    if (
        rollback.get("deployment_uid") != plan["source_cluster"]["deployment_uid"]
        or rollback.get("deployment_generation") != plan["expected_rollback_generation"]
        or _image_digest(rollback.get("runtime_image_id")) != _image_digest(plan["old_runtime_image_id"])
    ):
        raise UpgradeEvidenceError("rollback inspection does not match the planned Deployment and old image")

    effective_decision = "restore" if failed else plan["rollback_decision"]
    restore_receipt = None
    if effective_decision == "direct":
        if not plan["direct_rollback_authorized"] or not _same_storage(rollback, plan["source_storage"]):
            raise UpgradeEvidenceError("direct rollback was not authorized for the exact source storage")
        required.extend(("old-started-on-current-data", "rollback-ready"))
    else:
        backup_storage = plan.get("backup_storage") or {}
        if (
            rollback.get("pvc_uid") in {before.get("pvc_uid"), candidate.get("pvc_uid"), backup_storage.get("pvc_uid")}
            or rollback.get("bound_volume_uid") in {before.get("bound_volume_uid"), candidate.get("bound_volume_uid"), backup_storage.get("bound_volume_uid")}
            or rollback.get("storage_attachment_identity") in {before.get("storage_attachment_identity"), candidate.get("storage_attachment_identity")}
        ):
            raise UpgradeEvidenceError("Restore blocked: source, backup, candidate, and target identities must remain separate")
        if not args.restore_receipt or not args.restore_receipt_digest:
            raise UpgradeEvidenceError("restore rollback requires the Gate 4A restore receipt and retained digest")
        restore_receipt = _validate_restore_receipt(
            args.restore_receipt, args.restore_receipt_digest, plan=plan, rollback=rollback,
        )
        required.extend(("failed-claim-preserved", "restore-target-verified", "old-started-on-restored-data", "rollback-ready"))

    rollback_web = _read_json(args.rollback_web_check, "rollback web check")
    _validate_web_check(rollback_web, "after-rollback")
    rollback_hash = _sha256_file(args.evidence_rollback, args.max_evidence_bytes)
    if rollback_hash != before_hash:
        raise UpgradeEvidenceError("retained evidence changed after rollback")
    for name, count in before["database"]["table_counts"].items():
        if rollback["database"]["table_counts"].get(name, 0) < count:
            raise UpgradeEvidenceError(f"retained rollback record count decreased for {name}")
    rollback_active_lock = _validate_active_lock_receipt(
        args.rollback_active_lock_receipt, scenario=scenario,
        phase="rollback-writer-active", inspection=rollback,
    )
    rollback_lock = _validate_lock_receipt(
        args.rollback_lock_receipt, scenario=scenario,
        phase="rollback-writer-released", inspection=rollback,
    )
    observations_expected = [
        ("old-stopped", 0, before, old_lock),
        (("candidate-ready" if successful else "candidate-failed"),
         (1 if successful else 0), candidate, candidate_active_lock),
        ("candidate-stopped", 0, candidate, candidate_lock),
        ("rollback-ready", 1, rollback, rollback_active_lock),
        ("rollback-stopped", 0, rollback, rollback_lock),
    ]
    observations = _validate_cluster_observations(
        args.cluster_observations, scenario, observations_expected,
    )
    events = _validate_events(args.events, scenario, required)
    _validate_cross_record_chronology(
        before=before, candidate=candidate, rollback=rollback,
        old_lock=old_lock, candidate_active_lock=candidate_active_lock,
        candidate_lock=candidate_lock, rollback_active_lock=rollback_active_lock,
        rollback_lock=rollback_lock,
        observations=observations, events=events, successful=successful,
        restore_receipt=restore_receipt,
        failure_receipt=failure,
    )
    body = {
        "schema_version": RECEIPT_SCHEMA_VERSION,
        "tool_version": TOOL_VERSION,
        "status": "failed_upgrade_restore_verification_passed" if failed else "upgrade_rollback_verification_passed",
        "scenario_id": scenario,
        "verified_at": datetime.now().astimezone().isoformat(),
        "plan_sha256": plan["receipt_sha256"],
        "before_inspection_sha256": before["receipt_sha256"],
        "after_inspection_sha256": after["receipt_sha256"] if after else None,
        "failed_inspection_sha256": candidate["receipt_sha256"] if failed else None,
        "candidate_failure_sha256": failure["receipt_sha256"] if failure else None,
        "rollback_inspection_sha256": rollback["receipt_sha256"],
        "old_image": plan["old_image"],
        "new_image": plan["new_image"],
        "rollback_decision": effective_decision,
        "compatibility_rule": plan["compatibility_rule"],
        "event_record_sha256": _digest({"scenario_id": scenario, "events": events}),
        "cluster_observations_sha256": _digest(observations),
        "old_lock_attestation_sha256": old_lock["attestation"]["digest"],
        "candidate_active_lock_attestation_sha256": candidate_active_lock["attestation"]["digest"],
        "candidate_lock_attestation_sha256": candidate_lock["attestation"]["digest"],
        "rollback_active_lock_attestation_sha256": rollback_active_lock["attestation"]["digest"],
        "rollback_lock_attestation_sha256": rollback_lock["attestation"]["digest"],
        "restore_receipt_sha256": restore_receipt["receipt_sha256"] if restore_receipt else None,
        "evidence_sha256": before_hash,
        "after_upgrade_evidence_sha256": after_hash,
        "after_rollback_evidence_sha256": rollback_hash,
        "before_web_check_sha256": _digest(before_web),
        "after_web_check_sha256": _digest(after_web) if after_web else None,
        "rollback_web_check_sha256": _digest(rollback_web),
        "operator_message": (
            "Upgrade and rollback checks passed. The restored copy represents the recorded backup time; later changes are not included."
            if effective_decision == "restore" else
            "Upgrade checks passed with retained evidence and account access verified."
        ),
    }
    return _receipt(body)


def _common_output(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--overwrite", action="store_true")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    contract = sub.add_parser("contract")
    _common_output(contract)
    bind = sub.add_parser("bind-contract")
    bind.add_argument("--contract", type=Path, required=True)
    bind.add_argument("--requested-image", required=True)
    bind.add_argument("--runtime-image-id", required=True)
    _common_output(bind)
    inspect = sub.add_parser("inspect")
    inspect.add_argument("--data-root", type=Path, required=True)
    inspect.add_argument("--scenario-id", required=True)
    inspect.add_argument("--phase", choices=("before-upgrade", "after-upgrade", "failed-candidate", "after-rollback"), required=True)
    inspect.add_argument("--image", required=True)
    inspect.add_argument("--runtime-image-id", required=True)
    inspect.add_argument("--contract-digest", required=True)
    inspect.add_argument("--deployment-uid", required=True)
    inspect.add_argument("--deployment-generation", type=int, required=True)
    inspect.add_argument("--pod-uid", required=True)
    inspect.add_argument("--node-uid", required=True)
    inspect.add_argument("--storage-attachment-identity", required=True)
    inspect.add_argument("--pvc-uid", required=True)
    inspect.add_argument("--bound-volume-uid", required=True)
    inspect.add_argument("--qualification-report-digest", required=True)
    inspect.add_argument("--validation-root", type=Path, required=True)
    inspect.add_argument("--max-validation-bytes", type=int, default=20 * 1024**3)
    inspect.add_argument("--max-files", type=int, default=DEFAULT_MAX_FILES)
    inspect.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES)
    inspect.add_argument("--max-seconds", type=int, default=300)
    _common_output(inspect)
    plan = sub.add_parser("plan")
    plan.add_argument("--scenario-id", required=True)
    plan.add_argument("--old-image", required=True)
    plan.add_argument("--new-image", required=True)
    plan.add_argument("--old-contract", type=Path, required=True)
    plan.add_argument("--new-contract", type=Path, required=True)
    plan.add_argument("--before-inspection", type=Path, required=True)
    plan.add_argument("--backup-receipt", type=Path, required=True)
    plan.add_argument("--backup-manifest", type=Path, required=True)
    plan.add_argument("--backup-receipt-digest", required=True)
    plan.add_argument("--expected-candidate-generation", type=int, required=True)
    plan.add_argument("--expected-rollback-generation", type=int, required=True)
    _common_output(plan)
    failure = sub.add_parser("record-failure")
    failure.add_argument("--scenario-id", required=True)
    failure.add_argument("--image", required=True)
    failure.add_argument("--contract", type=Path, required=True)
    failure.add_argument("--failed-inspection", type=Path, required=True)
    failure.add_argument("--failure-stage", choices=("before-migration", "during-migration", "after-migration"), required=True)
    failure.add_argument("--failure-evidence", type=Path, required=True)
    _common_output(failure)
    observe = sub.add_parser("observe-cluster")
    observe.add_argument("--scenario-id", required=True)
    observe.add_argument("--phase", choices=(
        "old-stopped", "candidate-ready", "candidate-failed", "candidate-stopped",
        "rollback-ready", "rollback-stopped",
    ), required=True)
    observe.add_argument("--ready-pods", type=int, required=True)
    observe.add_argument("--writer-owners", type=int, required=True)
    observe.add_argument("--writer-receipt", type=Path, required=True)
    observe.add_argument("--deployment-uid", required=True)
    observe.add_argument("--deployment-generation", type=int, required=True)
    observe.add_argument("--pod-uid", required=True)
    observe.add_argument("--node-uid", required=True)
    observe.add_argument("--storage-attachment-identity", required=True)
    observe.add_argument("--pvc-uid", required=True)
    observe.add_argument("--bound-volume-uid", required=True)
    observe.add_argument("--previous", type=Path)
    _common_output(observe)
    verify = sub.add_parser("verify")
    verify.add_argument("--plan", type=Path, required=True)
    verify.add_argument("--before-inspection", type=Path, required=True)
    verify.add_argument("--after-inspection", type=Path)
    verify.add_argument("--failed-inspection", type=Path)
    verify.add_argument("--candidate-failure", type=Path)
    verify.add_argument("--rollback-inspection", type=Path, required=True)
    verify.add_argument("--old-lock-receipt", type=Path, required=True)
    verify.add_argument("--candidate-active-lock-receipt", type=Path, required=True)
    verify.add_argument("--candidate-lock-receipt", type=Path, required=True)
    verify.add_argument("--rollback-active-lock-receipt", type=Path, required=True)
    verify.add_argument("--rollback-lock-receipt", type=Path, required=True)
    verify.add_argument("--cluster-observations", type=Path, required=True)
    verify.add_argument("--restore-receipt", type=Path)
    verify.add_argument("--restore-receipt-digest")
    verify.add_argument("--events", type=Path, required=True)
    verify.add_argument("--before-web-check", type=Path, required=True)
    verify.add_argument("--after-web-check", type=Path)
    verify.add_argument("--rollback-web-check", type=Path, required=True)
    verify.add_argument("--evidence-before", type=Path, required=True)
    verify.add_argument("--evidence-after", type=Path)
    verify.add_argument("--evidence-rollback", type=Path, required=True)
    verify.add_argument("--max-evidence-bytes", type=int, default=1024**3)
    verify.add_argument("--max-seconds", type=int, default=300)
    _common_output(verify)
    return parser


def _validate_common(args: argparse.Namespace) -> None:
    scenario = getattr(args, "scenario_id", None)
    if scenario is not None and not SCENARIO_RE.fullmatch(scenario):
        raise UpgradeEvidenceError("scenario ID must be 8-80 lowercase letters, digits, or hyphens")
    for name in ("old_image", "new_image", "requested_image", "image"):
        value = getattr(args, name, None)
        if value is not None and not IMAGE_RE.fullmatch(value):
            raise UpgradeEvidenceError(f"{name.replace('_', ' ')} must use an exact sha256 digest")
    for name in ("contract_digest", "qualification_report_digest", "backup_receipt_digest", "restore_receipt_digest"):
        value = getattr(args, name, None)
        if value is not None and not DIGEST_RE.fullmatch(value):
            raise UpgradeEvidenceError(f"{name.replace('_', ' ')} is invalid")
    if getattr(args, "deployment_generation", 1) < 1:
        raise UpgradeEvidenceError("Deployment generation must be positive")
    if getattr(args, "max_files", 1) < 1 or getattr(args, "max_files", 1) > DEFAULT_MAX_FILES:
        raise UpgradeEvidenceError("file limit is outside the enforced range")
    if getattr(args, "max_bytes", 1) < 1 or getattr(args, "max_bytes", 1) > DEFAULT_MAX_BYTES:
        raise UpgradeEvidenceError("byte limit is outside the enforced range")
    if getattr(args, "max_validation_bytes", 1) < 1 or getattr(args, "max_validation_bytes", 1) > DEFAULT_MAX_BYTES:
        raise UpgradeEvidenceError("validation-copy byte limit is outside the enforced range")
    if getattr(args, "max_evidence_bytes", 1) < 1 or getattr(args, "max_evidence_bytes", 1) > DEFAULT_MAX_BYTES:
        raise UpgradeEvidenceError("evidence byte limit is outside the enforced range")


def main() -> int:
    try:
        args = _parser().parse_args()
        _validate_common(args)
        if args.command == "contract":
            result = image_schema_contract()
        elif args.command == "bind-contract":
            result = bind_contract(args)
        elif args.command == "inspect":
            result = inspect_data(args)
        elif args.command == "plan":
            result = create_plan(args)
        elif args.command == "record-failure":
            result = record_candidate_failure(args)
        elif args.command == "observe-cluster":
            result = record_cluster_observation(args)
        else:
            result = verify_scenario(args)
        _write_json(args.output, result, overwrite=args.overwrite)
        print(json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=True))
    except (UpgradeEvidenceError, recovery.RecoveryError, sqlite3.Error, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
