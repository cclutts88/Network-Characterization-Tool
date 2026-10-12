#!/usr/bin/env python3
"""Create and verify bounded cold NCT backups without contacting Kubernetes."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import sqlite3
import stat
import tarfile
import tempfile
import time
from typing import Iterator


SCHEMA_VERSION = 1
TOOL_VERSION = "1"
WRITER_LOCK_NAME = ".analyzer.db.nct-writer.lock"
DEFAULT_MAX_FILES = 1_000_000
DEFAULT_MAX_BYTES = 4 * 1024**4
DEFAULT_MAX_SECONDS = 14_400
BACKUP_FIXED_OVERHEAD = 64 * 1024**2
BACKUP_PER_ENTRY_OVERHEAD = 2048
MAX_IDENTITY_BYTES = 16_384
MAX_MANIFEST_BYTES = 128 * 1024**2
MAX_RECEIPT_BYTES = 65_536
BACKUP_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{7,79}$")
IMAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]*@sha256:[0-9a-f]{64}$")
DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
ACTIVE_STATES = {"queued", "running", "awaiting_fallback_approval", "updating", "migrating"}
_DEADLINE_AT: float | None = None


class RecoveryError(ValueError):
    pass


def _start_deadline(seconds: int) -> None:
    global _DEADLINE_AT
    if seconds < 1:
        raise RecoveryError("recovery time limit must be positive")
    _DEADLINE_AT = time.monotonic() + seconds


def _check_deadline() -> None:
    if _DEADLINE_AT is not None and time.monotonic() > _DEADLINE_AT:
        raise RecoveryError("recovery operation exceeded its declared time limit")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


@contextmanager
def _regular_reader(path: Path, label: str) -> Iterator[tuple[io.BufferedReader, os.stat_result]]:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            os.close(fd)
            raise RecoveryError(f"{label} is not a safe regular file")
    except RecoveryError:
        raise
    except OSError as exc:
        raise RecoveryError(f"{label} could not be opened safely") from exc
    try:
        with os.fdopen(fd, "rb") as handle:
            yield handle, info
    finally:
        pass


def _file_digest(path: Path) -> tuple[str, int]:
    digest, size = hashlib.sha256(), 0
    with _regular_reader(path, "recovery file") as (handle, opened):
        while chunk := handle.read(1024 * 1024):
            _check_deadline()
            digest.update(chunk)
            size += len(chunk)
        if size != opened.st_size:
            raise RecoveryError("recovery file changed while it was read")
    return digest.hexdigest(), size


def _tool_source_sha256() -> str:
    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def _identity(raw: str, label: str) -> dict:
    if len(raw.encode("utf-8")) > MAX_IDENTITY_BYTES:
        raise RecoveryError(f"{label} identity is too large")
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RecoveryError(f"{label} identity must be JSON") from exc
    if not isinstance(value, dict) or not value:
        raise RecoveryError(f"{label} identity must be a nonempty JSON object")
    for key in ("namespace", "pvc", "pvc_uid", "bound_volume_uid"):
        if not isinstance(value.get(key), str) or not value[key].strip():
            raise RecoveryError(f"{label} identity is missing {key}")
    return value


def _identity_key(value: dict) -> tuple[str, str]:
    return value["pvc_uid"], value["bound_volume_uid"]


def _safe_relative(name: str) -> PurePosixPath:
    value = PurePosixPath(name)
    if not name or name.startswith("/") or value.is_absolute() or ".." in value.parts:
        raise RecoveryError("backup contains an unsafe path")
    if any(part in {"", "."} for part in value.parts):
        raise RecoveryError("backup contains a malformed path")
    return value


def _reject_symlink_components(path: Path, label: str) -> None:
    current = path.absolute()
    chain = list(reversed(current.parents)) + [current]
    for item in chain:
        try:
            if item.is_symlink():
                raise RecoveryError(f"{label} path contains a symbolic link")
        except OSError as exc:
            raise RecoveryError(f"{label} path could not be inspected safely") from exc


def _directory_identity(path: Path, label: str) -> tuple[int, int]:
    _reject_symlink_components(path, label)
    try:
        value = os.stat(path, follow_symlinks=False)
    except OSError as exc:
        raise RecoveryError(f"{label} storage could not be identified") from exc
    if not stat.S_ISDIR(value.st_mode):
        raise RecoveryError(f"{label} storage must be a real directory")
    return value.st_dev, value.st_ino


def _fd_tree(
    root: Path, *, copy_to: Path | None, max_files: int, max_bytes: int,
) -> list[dict]:
    """Read one tree without following directory-entry substitutions or links."""
    _reject_symlink_components(root, "source")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        root_fd = os.open(root, flags)
    except OSError as exc:
        raise RecoveryError("source storage could not be opened safely") from exc
    items: list[dict] = []
    names: set[str] = set()
    folded: dict[str, str] = {}
    totals = {"files": 0, "bytes": 0}

    def walk(directory_fd: int, relative: PurePosixPath) -> None:
        _check_deadline()
        try:
            children = sorted(os.listdir(directory_fd))
        except OSError as exc:
            raise RecoveryError("source directory could not be listed safely") from exc
        for name in children:
            _check_deadline()
            child_relative = relative / name
            safe = _safe_relative(child_relative.as_posix()).as_posix()
            if safe == WRITER_LOCK_NAME:
                continue
            folded_name = safe.casefold()
            if safe in names or (folded_name in folded and folded[folded_name] != safe):
                raise RecoveryError("source contains duplicate or case-colliding paths")
            names.add(safe)
            folded[folded_name] = safe
            try:
                observed = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            except OSError as exc:
                raise RecoveryError(f"source path could not be inspected: {safe}") from exc
            if stat.S_ISLNK(observed.st_mode) or not (
                stat.S_ISREG(observed.st_mode) or stat.S_ISDIR(observed.st_mode)
            ):
                raise RecoveryError(f"source contains a link or special file: {safe}")
            mode = stat.S_IMODE(observed.st_mode)
            destination = copy_to.joinpath(*child_relative.parts) if copy_to else None
            if stat.S_ISDIR(observed.st_mode):
                try:
                    child_fd = os.open(name, flags, dir_fd=directory_fd)
                except OSError as exc:
                    raise RecoveryError(f"source directory changed while opening: {safe}") from exc
                try:
                    opened = os.fstat(child_fd)
                    if not stat.S_ISDIR(opened.st_mode) or (
                        opened.st_dev, opened.st_ino
                    ) != (observed.st_dev, observed.st_ino):
                        raise RecoveryError(f"source directory changed while opening: {safe}")
                    if destination:
                        destination.mkdir(mode=0o700, exist_ok=False)
                    walk(child_fd, child_relative)
                    if destination:
                        os.chmod(destination, mode)
                    final = os.fstat(child_fd)
                    if (final.st_dev, final.st_ino, final.st_mtime_ns, final.st_ctime_ns) != (
                        opened.st_dev, opened.st_ino, opened.st_mtime_ns, opened.st_ctime_ns
                    ):
                        raise RecoveryError(f"source directory changed during capture: {safe}")
                finally:
                    os.close(child_fd)
                item = {"path": safe, "kind": "directory", "mode": mode, "size": 0,
                        "sha256": hashlib.sha256(b"").hexdigest()}
            else:
                file_flags = os.O_RDONLY | os.O_CLOEXEC
                if hasattr(os, "O_NOFOLLOW"):
                    file_flags |= os.O_NOFOLLOW
                if hasattr(os, "O_NONBLOCK"):
                    file_flags |= os.O_NONBLOCK
                try:
                    source_fd = os.open(name, file_flags, dir_fd=directory_fd)
                except OSError as exc:
                    raise RecoveryError(f"source file changed while opening: {safe}") from exc
                try:
                    opened = os.fstat(source_fd)
                    if not stat.S_ISREG(opened.st_mode) or (
                        opened.st_dev, opened.st_ino
                    ) != (observed.st_dev, observed.st_ino):
                        raise RecoveryError(f"source file changed while opening: {safe}")
                    digest, size = hashlib.sha256(), 0
                    target_handle = None
                    if destination:
                        out_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
                        if hasattr(os, "O_NOFOLLOW"):
                            out_flags |= os.O_NOFOLLOW
                        target_fd = os.open(destination, out_flags, 0o600)
                        target_handle = os.fdopen(target_fd, "wb")
                    try:
                        with os.fdopen(os.dup(source_fd), "rb") as source_handle:
                            while chunk := source_handle.read(1024 * 1024):
                                _check_deadline()
                                digest.update(chunk)
                                size += len(chunk)
                                if target_handle:
                                    target_handle.write(chunk)
                        if target_handle:
                            target_handle.flush()
                            os.fchmod(target_handle.fileno(), mode)
                            os.fsync(target_handle.fileno())
                    finally:
                        if target_handle:
                            target_handle.close()
                    final = os.fstat(source_fd)
                    if size != opened.st_size or (
                        final.st_dev, final.st_ino, final.st_size,
                        final.st_mtime_ns, final.st_ctime_ns,
                    ) != (
                        opened.st_dev, opened.st_ino, opened.st_size,
                        opened.st_mtime_ns, opened.st_ctime_ns,
                    ):
                        raise RecoveryError(f"source file changed during capture: {safe}")
                finally:
                    os.close(source_fd)
                item = {"path": safe, "kind": "file", "mode": mode, "size": size,
                        "sha256": digest.hexdigest()}
                totals["bytes"] += size
            totals["files"] += 1
            if totals["files"] > max_files or totals["bytes"] > max_bytes:
                raise RecoveryError("source exceeds the declared recovery limits")
            items.append(item)

    try:
        walk(root_fd, PurePosixPath())
    finally:
        os.close(root_fd)
    items.sort(key=lambda item: item["path"])
    return items


def _scan(root: Path, *, max_files: int, max_bytes: int, hash_files: bool = True) -> list[dict]:
    if root.is_symlink() or not root.is_dir():
        raise RecoveryError("data root must be a real directory")
    items: list[dict] = []
    names: set[str] = set()
    folded: dict[str, str] = {}
    total_bytes = 0
    stack = [root]
    while stack:
        _check_deadline()
        directory = stack.pop()
        try:
            children = sorted(os.scandir(directory), key=lambda item: item.name)
        except OSError as exc:
            raise RecoveryError("data inventory could not be read") from exc
        for child in children:
            _check_deadline()
            path = Path(child.path)
            relative = path.relative_to(root).as_posix()
            if relative == WRITER_LOCK_NAME:
                continue
            safe = _safe_relative(relative).as_posix()
            folded_name = safe.casefold()
            if safe in names or (folded_name in folded and folded[folded_name] != safe):
                raise RecoveryError("data contains duplicate or case-colliding paths")
            names.add(safe)
            folded[folded_name] = safe
            try:
                info = child.stat(follow_symlinks=False)
            except OSError as exc:
                raise RecoveryError(f"data path could not be inspected: {safe}") from exc
            mode = stat.S_IMODE(info.st_mode)
            if stat.S_ISDIR(info.st_mode):
                item = {"path": safe, "kind": "directory", "mode": mode, "size": 0,
                        "sha256": hashlib.sha256(b"").hexdigest()}
                stack.append(path)
            elif stat.S_ISREG(info.st_mode):
                digest, size = _file_digest(path) if hash_files else ("", info.st_size)
                if size != info.st_size:
                    raise RecoveryError(f"data path changed while it was read: {safe}")
                item = {"path": safe, "kind": "file", "mode": mode, "size": size,
                        "sha256": digest, "device": info.st_dev, "inode": info.st_ino,
                        "mtime_ns": info.st_mtime_ns, "ctime_ns": info.st_ctime_ns}
                total_bytes += size
            else:
                raise RecoveryError(f"data contains a link or special file: {safe}")
            items.append(item)
            if len(items) > max_files or total_bytes > max_bytes:
                raise RecoveryError("data exceeds the declared recovery limits")
    items.sort(key=lambda item: item["path"])
    return items


def _public_inventory(items: list[dict]) -> list[dict]:
    keys = ("path", "kind", "mode", "size", "sha256")
    return [{key: item[key] for key in keys} for item in items]


def _fingerprints(items: list[dict]) -> list[tuple]:
    return [
        (item["path"], item["kind"], item["mode"], item["size"], item.get("device"),
         item.get("inode"), item.get("mtime_ns"), item.get("ctime_ns"))
        for item in items
    ]


@contextmanager
def _writer_lock(root: Path) -> Iterator[None]:
    path = root / WRITER_LOCK_NAME
    flags = os.O_RDWR | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags, 0o600)
    except OSError as exc:
        raise RecoveryError("the existing NCT writer lock could not be opened safely") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise RecoveryError("writer lock is not a safe regular file")
        try:
            fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB, 1, 0, os.SEEK_SET)
        except OSError as exc:
            raise RecoveryError("NCT is still running or another writer owns the data") from exc
        yield
    finally:
        try:
            fcntl.lockf(fd, fcntl.LOCK_UN, 1, 0, os.SEEK_SET)
        finally:
            os.close(fd)


def _active_work(root: Path) -> list[str]:
    active: list[str] = []
    for path in root.rglob("manifest.json"):
        if path.is_symlink() or not path.is_file():
            continue
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise RecoveryError(f"work manifest is unreadable: {path.relative_to(root).as_posix()}") from exc
        if isinstance(value, dict) and value.get("status") in ACTIVE_STATES:
            active.append(path.relative_to(root).as_posix())
    return sorted(active)


def _database_active_work(db_path: Path) -> list[str]:
    db = sqlite3.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True)
    try:
        tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        findings: list[str] = []
        checks = (
            ("scan_runs", "status", ("queued", "running", "awaiting_fallback_approval")),
            ("pipeline_job_attempts", "state", ("queued", "running")),
            ("artifact_compaction_journal", "state",
             ("preparing", "prepared", "replaced", "verified", "recovery-required")),
        )
        for table, column, states in checks:
            if table not in tables:
                continue
            marks = ",".join("?" for _ in states)
            count = db.execute(
                f'SELECT COUNT(*) FROM "{table}" WHERE "{column}" IN ({marks})', states
            ).fetchone()[0]
            if count:
                findings.append(f"{table}:{count}")
        if "pipeline_admission_intents" in tables:
            count = db.execute(
                """SELECT COUNT(*) FROM pipeline_admission_intents
                   WHERE state='pending' AND activity_state IN ('waiting','retrying')"""
            ).fetchone()[0]
            if count:
                findings.append(f"pipeline_admission_intents:{count}")
        if "scan_schedules" in tables:
            for schedule_id, raw in db.execute("SELECT schedule_id, definition_json FROM scan_schedules"):
                try:
                    value = json.loads(raw)
                except (TypeError, json.JSONDecodeError) as exc:
                    raise RecoveryError(f"scan schedule is unreadable: {schedule_id}") from exc
                if isinstance(value, dict) and value.get("batch_status") in {
                    "queued", "running", "recovery_pending"
                }:
                    findings.append(f"scan_schedule:{schedule_id}")
        return findings
    except sqlite3.Error as exc:
        raise RecoveryError("database work state could not be inspected") from exc
    finally:
        db.close()


def _database_baseline(path: Path) -> dict:
    if not path.is_file() or path.is_symlink():
        raise RecoveryError("analyzer.db is missing or unsafe")
    try:
        db = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)
        db.execute("PRAGMA query_only=ON")
        integrity = [row[0] for row in db.execute("PRAGMA integrity_check")]
        foreign = [list(row) for row in db.execute("PRAGMA foreign_key_check")]
        tables = [row[0] for row in db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
        )]
        counts = {
            name: db.execute(f'SELECT COUNT(*) FROM "{name.replace(chr(34), chr(34) * 2)}"').fetchone()[0]
            for name in tables
        }
        schema = list(db.execute(
            "SELECT type, name, tbl_name, COALESCE(sql, '') FROM sqlite_master ORDER BY type, name"
        ))
        user_version = db.execute("PRAGMA user_version").fetchone()[0]
    except sqlite3.Error as exc:
        raise RecoveryError("analyzer.db failed cold integrity inspection") from exc
    finally:
        if "db" in locals():
            db.close()
    if integrity != ["ok"] or foreign:
        raise RecoveryError("analyzer.db integrity or foreign-key verification failed")
    return {
        "integrity_check": "ok", "foreign_key_violations": 0,
        "user_version": user_version, "table_counts": counts,
        "schema_fingerprint": _digest(schema),
    }


def _artifact_baseline(db_path: Path, root: Path) -> dict:
    db = sqlite3.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True)
    db.row_factory = sqlite3.Row
    try:
        tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if "artifact_registry" not in tables:
            return {"count": 0, "bytes": 0, "verified": 0}
        rows = db.execute("SELECT sha256, size_bytes, canonical_path FROM artifact_registry ORDER BY sha256").fetchall()
    finally:
        db.close()
    verified, total = 0, 0
    for row in rows:
        recorded = Path(row["canonical_path"])
        try:
            relative = recorded.relative_to("/data") if recorded.is_absolute() else recorded
        except ValueError as exc:
            raise RecoveryError("artifact registry path is outside /data") from exc
        safe = _safe_relative(relative.as_posix())
        path = root.joinpath(*safe.parts)
        if path.is_symlink() or not path.is_file():
            raise RecoveryError("artifact registry path is missing or unsafe")
        digest, size = _file_digest(path)
        if digest != row["sha256"] or size != int(row["size_bytes"]):
            raise RecoveryError("artifact registry content does not match its retained identity")
        verified += 1
        total += size
    return {"count": len(rows), "bytes": total, "verified": verified}


def _evidence_baseline(db_path: Path, root: Path) -> dict:
    """Verify supported retained evidence and observation links on a private copy."""
    try:
        from app.storage_health import evidence_references
        references, issues, active = evidence_references(db_path, data_root=root)
    except (OSError, sqlite3.Error, ValueError) as exc:
        raise RecoveryError("retained evidence references could not be inspected") from exc
    if issues:
        raise RecoveryError("retained evidence references contain missing, unsafe, or unreadable records")
    if active:
        raise RecoveryError("retained evidence still records active collection work")
    verified: list[dict] = []
    for reference in references:
        path = Path(reference.get("path", ""))
        try:
            relative = path.absolute().relative_to(root.absolute())
        except (OSError, ValueError) as exc:
            raise RecoveryError("retained evidence reference is outside the data root") from exc
        safe = _safe_relative(relative.as_posix())
        candidate = root.joinpath(*safe.parts)
        if candidate.is_symlink() or not candidate.is_file():
            raise RecoveryError("retained evidence reference is missing or unsafe")
        digest, size = _file_digest(candidate)
        expected = reference.get("expected_hash")
        if expected and expected != digest:
            raise RecoveryError("retained evidence reference does not match its recorded hash")
        verified.append({"path": safe.as_posix(), "sha256": digest, "size": size})
    verified.sort(key=lambda item: (item["path"], item["sha256"]))
    db = sqlite3.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True)
    try:
        tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        observations = 0
        orphan_observations = 0
        if "artifact_observations" in tables:
            observations = db.execute("SELECT COUNT(*) FROM artifact_observations").fetchone()[0]
            if "artifact_registry" not in tables:
                orphan_observations = observations
            else:
                orphan_observations = db.execute(
                    """SELECT COUNT(*) FROM artifact_observations observation
                       LEFT JOIN artifact_registry artifact ON artifact.sha256=observation.sha256
                       WHERE artifact.sha256 IS NULL"""
                ).fetchone()[0]
    except sqlite3.Error as exc:
        raise RecoveryError("artifact observations could not be verified") from exc
    finally:
        db.close()
    if orphan_observations:
        raise RecoveryError("artifact observations contain unresolved retained content")
    return {
        "references": len(verified), "verified": len(verified),
        "reference_root_sha256": _digest(verified),
        "artifact_observations": observations, "orphan_observations": 0,
        "active_collections": 0, "issues": 0,
    }


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError as exc:
        raise RecoveryError(f"recovery directory could not be durably synchronized: {path.name}") from exc


def _write_json(path: Path, value: dict, *, limit: int = MAX_MANIFEST_BYTES) -> None:
    payload = json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True).encode("utf-8") + b"\n"
    if len(payload) > limit:
        raise RecoveryError("recovery report exceeds the safe size limit")
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def _write_termination_receipt(path: Path, value: dict) -> None:
    """Write the bounded restore receipt to Kubernetes' mounted termination file."""
    payload = _canonical(value)
    if not payload or len(payload) > 4096:
        raise RecoveryError("restore receipt exceeds the Kubernetes termination-message limit")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags, 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise RecoveryError("restore receipt target is not a safe regular file")
            with os.fdopen(fd, "wb", closefd=False) as handle:
                handle.write(payload)
                handle.flush()
            os.fsync(fd)
        finally:
            os.close(fd)
    except RecoveryError:
        raise
    except OSError as exc:
        raise RecoveryError("restore receipt could not be written durably") from exc


def _read_json(path: Path, *, limit: int) -> dict:
    try:
        with _regular_reader(path, "recovery report") as (handle, info):
            if not 1 <= info.st_size <= limit:
                raise RecoveryError("recovery report is missing, unsafe, or over its size limit")
            payload = handle.read(limit + 1)
        if len(payload) != info.st_size or len(payload) > limit:
            raise RecoveryError("recovery report is missing, unsafe, or over its size limit")
        value = json.loads(payload.decode("utf-8"))
    except RecoveryError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RecoveryError("recovery report is unreadable") from exc
    if not isinstance(value, dict):
        raise RecoveryError("recovery report must be a JSON object")
    return value


def _tar_info(item: dict) -> tarfile.TarInfo:
    info = tarfile.TarInfo(item["path"])
    info.mode = item["mode"]
    info.uid = info.gid = 10001
    info.uname = info.gname = "nct"
    info.mtime = 0
    if item["kind"] == "directory":
        info.type = tarfile.DIRTYPE
        info.size = 0
    else:
        info.type = tarfile.REGTYPE
        info.size = item["size"]
    return info


def _verify_archive(archive: Path, expected: list[dict], *, max_files: int, max_bytes: int) -> None:
    wanted = {item["path"]: item for item in expected}
    seen, folded, total = set(), {}, 0
    try:
        with _regular_reader(archive, "backup archive") as (handle, _info):
            with tarfile.open(fileobj=handle, mode="r:") as bundle:
                for member in bundle:
                    _check_deadline()
                    name = _safe_relative(member.name).as_posix()
                    if name in seen or (name.casefold() in folded and folded[name.casefold()] != name):
                        raise RecoveryError("backup archive contains duplicate or case-colliding paths")
                    seen.add(name)
                    folded[name.casefold()] = name
                    if len(seen) > max_files:
                        raise RecoveryError("backup archive exceeds the declared recovery limits")
                    item = wanted.get(name)
                    if item is None or member.mode != item["mode"]:
                        raise RecoveryError("backup archive does not match its manifest")
                    if item["kind"] == "directory":
                        if not member.isdir():
                            raise RecoveryError("backup archive changed a directory type")
                        continue
                    if not member.isfile() or member.islnk() or member.issym() or member.size != item["size"]:
                        raise RecoveryError("backup archive contains an unsafe or changed file")
                    extracted = bundle.extractfile(member)
                    if extracted is None:
                        raise RecoveryError("backup archive file could not be read")
                    digest, size = hashlib.sha256(), 0
                    while chunk := extracted.read(1024 * 1024):
                        _check_deadline()
                        digest.update(chunk)
                        size += len(chunk)
                    total += size
                    if digest.hexdigest() != item["sha256"]:
                        raise RecoveryError("backup archive content digest does not match")
                    if total > max_bytes:
                        raise RecoveryError("backup archive exceeds the declared recovery limits")
    except (tarfile.TarError, OSError) as exc:
        raise RecoveryError("backup archive is unreadable or truncated") from exc
    if seen != set(wanted):
        raise RecoveryError("backup archive is missing manifest entries")


def _validated_inventory(value: object, *, max_files: int, max_bytes: int) -> list[dict]:
    if not isinstance(value, list) or len(value) > max_files:
        raise RecoveryError("backup inventory is invalid or exceeds its file limit")
    result: list[dict] = []
    seen: set[str] = set()
    folded: dict[str, str] = {}
    total = 0
    empty = hashlib.sha256(b"").hexdigest()
    for raw in value:
        if not isinstance(raw, dict):
            raise RecoveryError("backup inventory entry is invalid")
        path = _safe_relative(raw.get("path") if isinstance(raw.get("path"), str) else "").as_posix()
        kind, mode, size, digest = raw.get("kind"), raw.get("mode"), raw.get("size"), raw.get("sha256")
        if kind not in {"file", "directory"} or not isinstance(mode, int) or not 0 <= mode <= 0o7777:
            raise RecoveryError("backup inventory entry type or mode is invalid")
        if not isinstance(size, int) or size < 0 or not isinstance(digest, str) or not DIGEST_RE.fullmatch(digest):
            raise RecoveryError("backup inventory entry size or digest is invalid")
        if kind == "directory" and (size != 0 or digest != empty):
            raise RecoveryError("backup inventory directory entry is invalid")
        if path in seen or (path.casefold() in folded and folded[path.casefold()] != path):
            raise RecoveryError("backup inventory contains duplicate or case-colliding paths")
        seen.add(path)
        folded[path.casefold()] = path
        total += size if kind == "file" else 0
        if total > max_bytes:
            raise RecoveryError("backup inventory exceeds its byte limit")
        result.append({"path": path, "kind": kind, "mode": mode, "size": size, "sha256": digest})
    if result != sorted(result, key=lambda item: item["path"]):
        raise RecoveryError("backup inventory is not in canonical order")
    return result


def create_backup(args: argparse.Namespace) -> dict:
    _start_deadline(args.max_seconds)
    source, backup_root = args.source.absolute(), args.backup_root.absolute()
    if source == backup_root or source in backup_root.parents or backup_root in source.parents:
        raise RecoveryError("source and backup storage must be separate")
    if source.is_symlink() or not source.is_dir():
        raise RecoveryError("source storage must be a real directory")
    source_identity = _identity(args.source_identity, "source")
    backup_identity = _identity(args.backup_identity, "backup")
    if _identity_key(source_identity) == _identity_key(backup_identity):
        raise RecoveryError("source and backup storage identities must differ")
    if not BACKUP_ID_RE.fullmatch(args.backup_id):
        raise RecoveryError("backup ID must be 8-80 lowercase letters, digits, or hyphens")
    if not IMAGE_RE.fullmatch(args.image):
        raise RecoveryError("image must use an exact sha256 digest")
    if not DIGEST_RE.fullmatch(args.source_qualification_report_digest):
        raise RecoveryError("source qualification report digest is invalid")
    if not DIGEST_RE.fullmatch(args.backup_qualification_report_digest):
        raise RecoveryError("backup qualification report digest is invalid")
    if backup_root.is_symlink() or not backup_root.is_dir():
        raise RecoveryError("backup storage must be a real directory")
    source_directory_identity = _directory_identity(source, "source")
    backup_directory_identity = _directory_identity(backup_root, "backup")
    source_real, backup_real = source.resolve(), backup_root.resolve()
    if source_real == backup_real or source_real in backup_real.parents or backup_real in source_real.parents:
        raise RecoveryError("source and backup storage must be separate")
    destination = backup_root / args.backup_id
    receipt_dir = backup_root / "receipts"
    if destination.exists() or destination.is_symlink():
        raise RecoveryError("backup destination already exists")
    destination.mkdir(mode=0o700)
    receipt_dir.mkdir(mode=0o700, exist_ok=True)
    if receipt_dir.is_symlink() or not receipt_dir.is_dir():
        raise RecoveryError("backup receipt directory is unsafe")
    archive = destination / "payload.tar"
    capture = destination / ".capture"
    capture.mkdir(mode=0o700)
    _fsync_directory(backup_root)
    try:
        with _writer_lock(source):
            preflight = _fd_tree(
                source, copy_to=None, max_files=args.max_files, max_bytes=args.max_bytes,
            )
            source_bytes = sum(item["size"] for item in preflight if item["kind"] == "file")
            minimum_free = (
                source_bytes * 2 + len(preflight) * BACKUP_PER_ENTRY_OVERHEAD
                + BACKUP_FIXED_OVERHEAD
            )
            available_free = shutil.disk_usage(backup_root).free
            if available_free < minimum_free:
                raise RecoveryError(
                    "backup storage lacks space for the private snapshot, archive, and recovery records"
                )
            before = _fd_tree(
                source, copy_to=capture, max_files=args.max_files, max_bytes=args.max_bytes,
            )
            after = _fd_tree(
                source, copy_to=None, max_files=args.max_files, max_bytes=args.max_bytes,
            )
            if (_public_inventory(preflight) != _public_inventory(before)
                    or _public_inventory(before) != _public_inventory(after)):
                raise RecoveryError("source data changed during backup")
            if (_directory_identity(source, "source") != source_directory_identity
                    or _directory_identity(backup_root, "backup") != backup_directory_identity):
                raise RecoveryError("source or backup storage identity changed during backup")
        public = _public_inventory(before)
        with tarfile.open(archive, "x:", dereference=True) as bundle:
            for item in public:
                _check_deadline()
                info = _tar_info(item)
                if item["kind"] == "directory":
                    bundle.addfile(info)
                else:
                    with (capture / item["path"]).open("rb") as handle:
                        bundle.addfile(info, handle)
        os.chmod(archive, 0o600)
        with archive.open("rb") as handle:
            os.fsync(handle.fileno())
        _fsync_directory(destination)
        _verify_archive(archive, public, max_files=args.max_files, max_bytes=args.max_bytes)
        active = _active_work(capture)
        database_active = _database_active_work(capture / "analyzer.db")
        if active or database_active:
            raise RecoveryError("NCT data records active work; finish or interrupt it before backup")
        baseline = _database_baseline(capture / "analyzer.db")
        artifacts = _artifact_baseline(capture / "analyzer.db", capture)
        evidence = _evidence_baseline(capture / "analyzer.db", capture)
        archive_sha256, archive_bytes = _file_digest(archive)
        manifest = {
            "schema_version": SCHEMA_VERSION,
            "backup_id": args.backup_id,
            "created_at": _utc_now(),
            "tool": {"version": TOOL_VERSION, "source_sha256": _tool_source_sha256()},
            "source": {
                "storage_identity": source_identity,
                "qualification_report_digest": args.source_qualification_report_digest,
                "image": args.image,
                "application_version": args.application_version,
                "build_id": args.build_id,
                "mount_path": "/data",
            },
            "backup": {
                "storage_identity": backup_identity,
                "qualification_report_digest": args.backup_qualification_report_digest,
                "mount_path": "/backup",
            },
            "limits": {"max_files": args.max_files, "max_bytes": args.max_bytes},
            "capacity_preflight": {
                "source_bytes": source_bytes,
                "minimum_free_bytes": minimum_free,
                "available_before_bytes": available_free,
            },
            "inventory": public,
            "inventory_root_sha256": _digest(public),
            "archive": {"name": archive.name, "sha256": archive_sha256, "size": archive_bytes},
            "database": baseline,
            "artifact_registry": artifacts,
            "retained_evidence": evidence,
            "limitations": [
                "Digests are integrity evidence, not authenticated signatures.",
                "This cold package does not prove Kubernetes, Range, node-loss, upgrade, or rollback readiness.",
            ],
        }
        manifest["manifest_sha256"] = _digest(manifest)
        shutil.rmtree(capture)
        _fsync_directory(destination)
        _write_json(destination / "manifest.json", manifest)
        receipt = {
            "schema_version": SCHEMA_VERSION, "status": "backup_verified",
            "backup_id": args.backup_id, "verified_at": _utc_now(),
            "manifest_sha256": manifest["manifest_sha256"],
            "archive_sha256": archive_sha256,
            "inventory_root_sha256": manifest["inventory_root_sha256"],
            "source_storage_identity_sha256": _digest(source_identity),
            "backup_storage_identity_sha256": _digest(backup_identity),
            "source_qualification_report_digest": args.source_qualification_report_digest,
            "backup_qualification_report_digest": args.backup_qualification_report_digest,
            "retained_evidence_verified": evidence["verified"],
            "source_and_backup_preserved": True,
        }
        receipt["receipt_sha256"] = _digest(receipt)
        _write_json(receipt_dir / f"{args.backup_id}.json", receipt)
        _fsync_directory(backup_root)
        return receipt
    except BaseException:
        # Preserve the incomplete destination for inspection; never replace or remove source data.
        raise


def _load_backup(backup_root: Path, backup_id: str) -> tuple[dict, dict, Path]:
    destination = backup_root / backup_id
    manifest_path, receipt_path = destination / "manifest.json", backup_root / "receipts" / f"{backup_id}.json"
    manifest = _read_json(manifest_path, limit=MAX_MANIFEST_BYTES)
    receipt = _read_json(receipt_path, limit=MAX_RECEIPT_BYTES)
    try:
        if manifest.get("schema_version") != SCHEMA_VERSION or receipt.get("schema_version") != SCHEMA_VERSION:
            raise RecoveryError("backup schema version is unsupported")
        tool = manifest.get("tool")
        if not isinstance(tool, dict) or tool.get("version") != TOOL_VERSION:
            raise RecoveryError("backup tool version is unsupported")
        if tool.get("source_sha256") != _tool_source_sha256():
            raise RecoveryError("backup tool source does not match this recovery image")
        manifest_without_digest = {key: value for key, value in manifest.items() if key != "manifest_sha256"}
        receipt_without_digest = {key: value for key, value in receipt.items() if key != "receipt_sha256"}
        if manifest.get("manifest_sha256") != _digest(manifest_without_digest):
            raise RecoveryError("backup manifest digest is invalid")
        if receipt.get("receipt_sha256") != _digest(receipt_without_digest):
            raise RecoveryError("backup receipt digest is invalid")
        if receipt.get("manifest_sha256") != manifest["manifest_sha256"] or receipt.get("status") != "backup_verified":
            raise RecoveryError("backup receipt does not authorize this manifest")
        archive_value = manifest.get("archive")
        if not isinstance(archive_value, dict) or archive_value.get("name") != "payload.tar":
            raise RecoveryError("backup archive name is invalid")
        if not DIGEST_RE.fullmatch(archive_value.get("sha256", "")):
            raise RecoveryError("backup archive digest is invalid")
        if not isinstance(archive_value.get("size"), int) or archive_value["size"] < 0:
            raise RecoveryError("backup archive size is invalid")
        archive = destination / "payload.tar"
        digest, size = _file_digest(archive)
        if digest != archive_value["sha256"] or size != archive_value["size"]:
            raise RecoveryError("backup archive digest or size changed")
    except RecoveryError:
        raise
    except (KeyError, TypeError, ValueError, OverflowError) as exc:
        raise RecoveryError("backup manifest or receipt structure is invalid") from exc
    return manifest, receipt, archive


def restore_backup(args: argparse.Namespace) -> dict:
    _start_deadline(args.max_seconds)
    backup_root, target = args.backup_root.absolute(), args.target.absolute()
    if target == backup_root or target in backup_root.parents or backup_root in target.parents:
        raise RecoveryError("backup and restore target storage must be separate")
    if not BACKUP_ID_RE.fullmatch(args.backup_id):
        raise RecoveryError("backup ID is invalid")
    manifest, receipt, archive = _load_backup(backup_root, args.backup_id)
    if not DIGEST_RE.fullmatch(args.expected_receipt_digest):
        raise RecoveryError("expected backup receipt digest is invalid")
    if receipt.get("receipt_sha256") != args.expected_receipt_digest:
        raise RecoveryError("backup receipt does not match the separately recorded digest")
    source_identity = manifest["source"]["storage_identity"]
    expected_source_identity = _identity(args.expected_source_identity, "expected source")
    if source_identity != expected_source_identity:
        raise RecoveryError("backup source storage identity does not match the expected source")
    backup_identity = _identity(args.backup_identity, "backup")
    target_identity = _identity(args.target_identity, "target")
    if not DIGEST_RE.fullmatch(args.backup_qualification_report_digest):
        raise RecoveryError("backup qualification report digest is invalid")
    if not DIGEST_RE.fullmatch(args.target_qualification_report_digest):
        raise RecoveryError("target qualification report digest is invalid")
    identities = {_identity_key(source_identity), _identity_key(backup_identity), _identity_key(target_identity)}
    if len(identities) != 3:
        raise RecoveryError("source, backup, and restore target identities must all differ")
    if backup_identity != manifest["backup"]["storage_identity"]:
        raise RecoveryError("backup storage identity changed")
    if args.backup_qualification_report_digest != manifest["backup"].get("qualification_report_digest"):
        raise RecoveryError("backup qualification report digest changed")
    if backup_root.is_symlink() or not backup_root.is_dir():
        raise RecoveryError("backup storage must be a real directory")
    if target.is_symlink() or not target.is_dir() or any(target.iterdir()):
        raise RecoveryError("restore target must be a real, empty directory")
    backup_directory_identity = _directory_identity(backup_root, "backup")
    target_directory_identity = _directory_identity(target, "restore target")
    backup_real, target_real = backup_root.resolve(), target.resolve()
    if target_real == backup_real or target_real in backup_real.parents or backup_real in target_real.parents:
        raise RecoveryError("backup and restore target storage must be separate")
    limits = manifest.get("limits") or {}
    try:
        max_files = min(args.max_files, int(limits.get("max_files", 0)))
        max_bytes = min(args.max_bytes, int(limits.get("max_bytes", 0)))
    except (AttributeError, TypeError, ValueError, OverflowError) as exc:
        raise RecoveryError("backup recovery limits are invalid") from exc
    if max_files < 1 or max_bytes < 1:
        raise RecoveryError("backup recovery limits are invalid")
    expected = _validated_inventory(manifest.get("inventory"), max_files=max_files, max_bytes=max_bytes)
    if manifest.get("inventory_root_sha256") != _digest(expected):
        raise RecoveryError("backup inventory digest is invalid")
    _verify_archive(archive, expected, max_files=max_files, max_bytes=max_bytes)
    try:
        directory_modes: list[tuple[Path, int]] = []
        with _regular_reader(archive, "backup archive") as (archive_handle, _info):
            with tarfile.open(fileobj=archive_handle, mode="r:") as bundle:
                for member in bundle:
                    _check_deadline()
                    relative = _safe_relative(member.name)
                    destination = target.joinpath(*relative.parts)
                    if member.isdir():
                        destination.mkdir(mode=0o700, parents=True, exist_ok=False)
                        directory_modes.append((destination, member.mode))
        with _regular_reader(archive, "backup archive") as (archive_handle, _info):
            with tarfile.open(fileobj=archive_handle, mode="r:") as bundle:
                for member in bundle:
                    _check_deadline()
                    if member.isdir():
                        continue
                    relative = _safe_relative(member.name)
                    destination = target.joinpath(*relative.parts)
                    source = bundle.extractfile(member)
                    if source is None:
                        raise RecoveryError("backup file could not be extracted")
                    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
                    if hasattr(os, "O_NOFOLLOW"):
                        flags |= os.O_NOFOLLOW
                    fd = os.open(destination, flags, 0o600)
                    try:
                        with os.fdopen(fd, "wb") as handle:
                            while chunk := source.read(1024 * 1024):
                                _check_deadline()
                                handle.write(chunk)
                            handle.flush()
                            os.fchmod(handle.fileno(), member.mode)
                            os.fsync(handle.fileno())
                    except BaseException:
                        try:
                            os.close(fd)
                        except OSError:
                            pass
                        raise
        for directory, mode in sorted(directory_modes, key=lambda item: len(item[0].parts), reverse=True):
            os.chmod(directory, mode)
        for directory, _dirs, _files in os.walk(target, topdown=False):
            fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
    except (tarfile.TarError, OSError) as exc:
        raise RecoveryError("restore was interrupted; preserve this target and use a fresh empty target") from exc
    restored = _scan(target, max_files=max_files, max_bytes=max_bytes)
    public = _public_inventory(restored)
    if public != expected or _digest(public) != manifest["inventory_root_sha256"]:
        raise RecoveryError("restored bytes do not exactly match the backup inventory")
    if (_directory_identity(backup_root, "backup") != backup_directory_identity
            or _directory_identity(target, "restore target") != target_directory_identity):
        raise RecoveryError("backup or restore target storage identity changed during restore")
    database = _database_baseline(target / "analyzer.db")
    artifacts = _artifact_baseline(target / "analyzer.db", target)
    evidence = _evidence_baseline(target / "analyzer.db", target)
    if (database != manifest.get("database") or artifacts != manifest.get("artifact_registry")
            or evidence != manifest.get("retained_evidence")):
        raise RecoveryError("restored database or retained evidence does not match the backup baseline")
    result = {
        "schema_version": SCHEMA_VERSION, "status": "restore_verification_passed",
        "backup_id": args.backup_id, "verified_at": _utc_now(),
        "source_image": manifest["source"]["image"],
        "source_application_version": manifest["source"]["application_version"],
        "source_build_id": manifest["source"]["build_id"],
        "manifest_sha256": manifest["manifest_sha256"],
        "backup_receipt_sha256": receipt["receipt_sha256"],
        "archive_sha256": manifest["archive"]["sha256"],
        "inventory_root_sha256": manifest["inventory_root_sha256"],
        "target_storage_identity_sha256": _digest(target_identity),
        "source_storage_identity": source_identity,
        "backup_storage_identity": backup_identity,
        "target_storage_identity": target_identity,
        "source_qualification_report_digest": manifest["source"]["qualification_report_digest"],
        "backup_qualification_report_digest": args.backup_qualification_report_digest,
        "target_qualification_report_digest": args.target_qualification_report_digest,
        "restored_files": sum(item["kind"] == "file" for item in expected),
        "restored_bytes": sum(item["size"] for item in expected if item["kind"] == "file"),
        "database_integrity": "ok", "artifact_registry_verified": artifacts["verified"],
        "retained_evidence_verified": evidence["verified"],
        "source_and_backup_preserved": True,
        "next_step": "Start the same exact image against this restore target and complete login, readiness, and retained-evidence download verification.",
    }
    result["receipt_sha256"] = _digest(result)
    _write_termination_receipt(args.receipt_path, result)
    return result


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--backup-root", type=Path, required=True)
    common.add_argument("--backup-id", required=True)
    common.add_argument("--backup-identity", required=True)
    common.add_argument("--max-files", type=int, default=DEFAULT_MAX_FILES)
    common.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES)
    common.add_argument("--max-seconds", type=int, default=DEFAULT_MAX_SECONDS)
    backup = subparsers.add_parser("backup", parents=[common])
    backup.add_argument("--source", type=Path, required=True)
    backup.add_argument("--source-identity", required=True)
    backup.add_argument("--source-qualification-report-digest", required=True)
    backup.add_argument("--backup-qualification-report-digest", required=True)
    backup.add_argument("--image", required=True)
    backup.add_argument("--application-version", required=True)
    backup.add_argument("--build-id", required=True)
    restore = subparsers.add_parser("restore", parents=[common])
    restore.add_argument("--target", type=Path, required=True)
    restore.add_argument("--target-identity", required=True)
    restore.add_argument("--expected-source-identity", required=True)
    restore.add_argument("--expected-receipt-digest", required=True)
    restore.add_argument("--backup-qualification-report-digest", required=True)
    restore.add_argument("--target-qualification-report-digest", required=True)
    restore.add_argument("--receipt-path", type=Path, required=True)
    return parser


def main() -> int:
    try:
        args = _parser().parse_args()
        if args.max_files < 1 or args.max_bytes < 1 or args.max_seconds < 1:
            raise RecoveryError("recovery limits must be positive")
        result = create_backup(args) if args.command == "backup" else restore_backup(args)
        print(json.dumps(result, sort_keys=True, ensure_ascii=True))
    except RecoveryError as exc:
        print(json.dumps({"status": "failed", "error": str(exc), "source_and_backup_preserved": True},
                         sort_keys=True), file=os.sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
