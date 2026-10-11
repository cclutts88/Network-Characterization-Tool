#!/usr/bin/env python3
"""Qualify one mounted directory for a future single-replica NCT deployment."""
from __future__ import annotations

import argparse
import ctypes
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import select
import signal
import sqlite3
import stat
import subprocess
import sys
import time
import uuid


TOOL_VERSION = "nct-storage-qualification:1"
REPORT_SCHEMA_VERSION = 1
WORKSPACE_PREFIX = ".nct-storage-qualification-"
CHILD_TIMEOUT_SECONDS = 8.0
OVERALL_TIMEOUT_SECONDS = 30.0
MAX_CHILD_OUTPUT_BYTES = 16_384
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_WORKSPACE_BYTES = 32 * 1024 * 1024
MAX_REPORT_BYTES = 65_536
MAX_STORAGE_IDENTITY_BYTES = 512
REPLACE_ITERATIONS = 64
TOKEN_FILE = ".nct-qualification-token"
_SAFE_NAME = re.compile(r"^\.nct-storage-qualification-[0-9a-f]{32}$")


FILE_LOCK_CHILD = r"""
import fcntl, os, sys
fd = os.open(sys.argv[1], os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW)
try:
    try:
        fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB, 1, 0, os.SEEK_SET)
    except OSError as exc:
        if exc.errno in (11, 13):
            raise SystemExit(23)
        raise
finally:
    os.close(fd)
"""


SQLITE_LOCK_CHILD = r"""
import sqlite3, sys
db = sqlite3.connect(sys.argv[1], timeout=0, isolation_level=None)
try:
    try:
        db.execute("BEGIN IMMEDIATE")
    except sqlite3.OperationalError as exc:
        if "locked" in str(exc).lower():
            raise SystemExit(24)
        raise
    else:
        db.execute("ROLLBACK")
        raise SystemExit(25)
finally:
    db.close()
"""


SQLITE_COMMIT_CHILD = r"""
import json, sqlite3, sys
db = sqlite3.connect(sys.argv[1], timeout=2, isolation_level=None)
try:
    mode = db.execute("PRAGMA journal_mode=WAL").fetchone()[0]
    db.execute("PRAGMA synchronous=FULL")
    db.execute("BEGIN IMMEDIATE")
    db.execute("INSERT INTO qualification_events(value) VALUES ('child-committed')")
    db.execute("COMMIT")
    checkpoint = list(db.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone())
    integrity = db.execute("PRAGMA integrity_check").fetchone()[0]
    print(json.dumps({"journal_mode": mode, "checkpoint": checkpoint, "integrity": integrity}))
finally:
    db.close()
"""


REPLACE_OBSERVER_CHILD = r"""
import hashlib, json, os, sys
workspace_fd = int(sys.argv[1])
target_name = sys.argv[2]
allowed = {sys.argv[3], sys.argv[4]}
observations = 0
seen = set()
for raw_command in sys.stdin.buffer:
    expected = raw_command.decode("ascii", "strict").strip()
    if expected == "STOP":
        break
    if expected not in allowed:
        print(json.dumps({"error": "invalid_command", "observations": observations}), flush=True)
        raise SystemExit(30)
    try:
        fd = os.open(target_name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=workspace_fd)
    except FileNotFoundError:
        print(json.dumps({"error": "target_missing", "observations": observations}))
        raise SystemExit(31)
    try:
        data = b""
        while True:
            chunk = os.read(fd, 4096)
            if not chunk:
                break
            data += chunk
            if len(data) > 4096:
                print(json.dumps({"error": "target_oversized", "observations": observations}))
                raise SystemExit(32)
    finally:
        os.close(fd)
    digest = hashlib.sha256(data).hexdigest()
    if digest not in allowed or digest != expected:
        print(json.dumps({"error": "unexpected_content", "observations": observations, "digest": digest}))
        raise SystemExit(33)
    observations += 1
    seen.add(digest)
    print("OK " + digest, flush=True)
print(json.dumps({"observations": observations, "seen_digests": sorted(seen)}), flush=True)
raise SystemExit(0 if observations else 34)
"""


CONTINUOUS_REPLACE_OBSERVER_CHILD = r"""
import hashlib, json, os, select, sys
workspace_fd = int(sys.argv[1])
target_name = sys.argv[2]
allowed = {sys.argv[3], sys.argv[4]}
observations = 0
seen = set()
print("READY", flush=True)
while True:
    try:
        fd = os.open(target_name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=workspace_fd)
    except FileNotFoundError:
        print(json.dumps({"error": "target_missing", "observations": observations, "seen_digests": sorted(seen)}), flush=True)
        raise SystemExit(41)
    try:
        data = b""
        while True:
            chunk = os.read(fd, 4096)
            if not chunk:
                break
            data += chunk
            if len(data) > 4096:
                print(json.dumps({"error": "target_oversized", "observations": observations, "seen_digests": sorted(seen)}), flush=True)
                raise SystemExit(42)
    finally:
        os.close(fd)
    digest = hashlib.sha256(data).hexdigest()
    if digest not in allowed:
        print(json.dumps({"error": "unexpected_content", "observations": observations, "seen_digests": sorted(seen), "digest": digest}), flush=True)
        raise SystemExit(43)
    observations += 1
    seen.add(digest)
    ready, _, _ = select.select([sys.stdin.buffer], [], [], 0)
    if ready and sys.stdin.buffer.readline().decode("ascii", "strict").strip() == "STOP":
        break
print(json.dumps({"observations": observations, "seen_digests": sorted(seen)}), flush=True)
"""


def _detail(value: object) -> str:
    return str(value).replace("\r", " ").replace("\n", " ")[:240]


def _canonical_bytes(value: dict) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("utf-8")


def report_digest(report: dict) -> str:
    unsigned = dict(report)
    unsigned.pop("attestation", None)
    return hashlib.sha256(_canonical_bytes(unsigned)).hexdigest()


def verify_report_digest(report: dict) -> bool:
    attestation = report.get("attestation") or {}
    return (
        attestation.get("algorithm") == "sha256"
        and attestation.get("authenticated") is False
        and attestation.get("digest") == report_digest(report)
    )


def _result(check_id: str, status: str, detail: str, started: float, **facts) -> dict:
    value = {
        "id": check_id,
        "status": status,
        "detail": _detail(detail),
        "duration_seconds": round(time.monotonic() - started, 6),
    }
    if facts:
        value["facts"] = facts
    return value


def _run_process(
    command: list[str], *, timeout: float, start_new_session: bool,
    pass_fds: tuple[int, ...] = (), output_limit: int = MAX_CHILD_OUTPUT_BYTES,
) -> dict:
    started = time.monotonic()
    process = subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=False,
        start_new_session=start_new_session,
        pass_fds=pass_fds,
    )
    timed_out = False
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            if start_new_session and os.name == "posix":
                os.killpg(process.pid, signal.SIGKILL)
            else:
                process.kill()
        except ProcessLookupError:
            pass
        try:
            stdout, stderr = process.communicate(timeout=2)
        except subprocess.TimeoutExpired:
            try:
                process.kill()
            except ProcessLookupError:
                pass
            if process.stdout is not None:
                process.stdout.close()
            if process.stderr is not None:
                process.stderr.close()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                pass
            stdout, stderr = b"", b"Child did not terminate after forced shutdown"
    output_limited = len(stdout) <= output_limit and len(stderr) <= output_limit
    return {
        "returncode": process.returncode,
        "timed_out": timed_out,
        "reaped": process.poll() is not None,
        "output_limited": output_limited,
        "stdout": stdout[:output_limit].decode("utf-8", "replace"),
        "stderr": stderr[:output_limit].decode("utf-8", "replace"),
        "duration_seconds": round(time.monotonic() - started, 6),
    }


def _child(
    command: list[str], timeout: float = CHILD_TIMEOUT_SECONDS, *, pass_fds: tuple[int, ...] = (),
) -> dict:
    return _run_process(
        command, timeout=timeout, start_new_session=False, pass_fds=pass_fds,
    )


def _workspace_path(workspace_fd: int, name: str) -> str:
    return f"/proc/self/fd/{workspace_fd}/{name}"


def _check_file_lock(workspace_fd: int) -> dict:
    started = time.monotonic()
    name = "advisory-lock.bin"
    path = _workspace_path(workspace_fd, name)
    fd = os.open(
        name,
        os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600,
        dir_fd=workspace_fd,
    )
    try:
        os.write(fd, b"nct-lock-check")
        os.fsync(fd)
        fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB, 1, 0, os.SEEK_SET)
        blocked = _child(
            [sys.executable, "-c", FILE_LOCK_CHILD, path], pass_fds=(workspace_fd,),
        )
        if blocked["timed_out"] or not blocked["reaped"] or not blocked["output_limited"]:
            return _result("advisory_file_lock", "fail", "Contending child did not terminate cleanly", started)
        if blocked["returncode"] != 23:
            return _result("advisory_file_lock", "fail", "A second process was not rejected by the held lock", started)
        fcntl.lockf(fd, fcntl.LOCK_UN, 1, 0, os.SEEK_SET)
        released = _child(
            [sys.executable, "-c", FILE_LOCK_CHILD, path], pass_fds=(workspace_fd,),
        )
        if (
            released["timed_out"] or not released["reaped"]
            or not released["output_limited"] or released["returncode"] != 0
        ):
            return _result("advisory_file_lock", "fail", "The lock did not become available after release", started)
    finally:
        os.close(fd)
    return _result(
        "advisory_file_lock", "pass", "Separate-process lock contention and release succeeded", started,
        contender_exit=23, successor_exit=0,
    )


def _write_file_at(workspace_fd: int, name: str, payload: bytes) -> None:
    fd = os.open(
        name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600,
        dir_fd=workspace_fd,
    )
    try:
        os.write(fd, payload)
        os.fsync(fd)
    finally:
        os.close(fd)


def _replacement_observer_facts_are_valid(
    value: object, old_digest: str, new_digest: str,
) -> bool:
    return (
        isinstance(value, dict)
        and value.get("observations") == REPLACE_ITERATIONS + 1
        and value.get("seen_digests") == sorted([old_digest, new_digest])
    )


def _observer_exchange(observer: subprocess.Popen, expected_digest: str) -> int:
    if observer.stdin is None or observer.stdout is None:
        raise RuntimeError("Replacement observer pipes were unavailable")
    command = (expected_digest + "\n").encode("ascii")
    observer.stdin.write(command)
    observer.stdin.flush()
    ready, _, _ = select.select([observer.stdout], [], [], 2.0)
    if not ready:
        raise TimeoutError("Replacement observer did not acknowledge an exact state")
    line = observer.stdout.readline()
    expected = ("OK " + expected_digest + "\n").encode("ascii")
    if line != expected:
        raise ValueError("Replacement observer rejected an exact state")
    return len(line)


def _read_observer_line(observer: subprocess.Popen, timeout: float = 2.0) -> bytes:
    if observer.stdout is None:
        raise RuntimeError("Replacement observer output pipe was unavailable")
    ready, _, _ = select.select([observer.stdout], [], [], timeout)
    if not ready:
        raise TimeoutError("Replacement observer did not respond")
    return observer.stdout.readline()


def _start_continuous_observer(
    workspace_fd: int, target_name: str, old_digest: str, new_digest: str,
) -> subprocess.Popen:
    observer = subprocess.Popen(
        [
            sys.executable, "-c", CONTINUOUS_REPLACE_OBSERVER_CHILD,
            str(workspace_fd), target_name, old_digest, new_digest,
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=False,
        pass_fds=(workspace_fd,),
    )
    if _read_observer_line(observer) != b"READY\n":
        if observer.poll() is None:
            observer.kill()
        observer.communicate(timeout=2)
        raise RuntimeError("Continuous replacement observer did not become ready")
    return observer


def _stop_continuous_observer(observer: subprocess.Popen) -> tuple[dict, int, int]:
    if observer.stdin is None:
        raise RuntimeError("Continuous replacement observer input pipe was unavailable")
    observer.stdin.write(b"STOP\n")
    observer.stdin.flush()
    stdout, stderr = observer.communicate(timeout=2)
    try:
        facts = json.loads(stdout.decode("utf-8", "replace"))
    except (TypeError, ValueError):
        facts = {"error": "invalid_output"}
    return facts, len(stdout), len(stderr)


def _check_atomic_rename(workspace_fd: int) -> dict:
    started = time.monotonic()
    source_name = "rename-source.bin"
    target_name = "rename-target.bin"
    old_payload = b"nct-atomic-replace-old:" + os.urandom(32)
    new_payload = b"nct-atomic-replace-new:" + os.urandom(32)
    old_digest = hashlib.sha256(old_payload).hexdigest()
    new_digest = hashlib.sha256(new_payload).hexdigest()
    _write_file_at(workspace_fd, target_name, old_payload)
    os.fsync(workspace_fd)
    continuous = _start_continuous_observer(
        workspace_fd, target_name, old_digest, new_digest,
    )
    try:
        observer = subprocess.Popen(
            [
                sys.executable, "-c", REPLACE_OBSERVER_CHILD, str(workspace_fd),
                target_name, old_digest, new_digest,
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=False,
            pass_fds=(workspace_fd,),
        )
    except BaseException:
        if continuous.poll() is None:
            continuous.kill()
        continuous.communicate(timeout=2)
        raise
    acknowledged_bytes = 0
    try:
        acknowledged_bytes += _observer_exchange(observer, old_digest)
        for index in range(REPLACE_ITERATIONS):
            payload = new_payload if index % 2 == 0 else old_payload
            expected_digest = new_digest if index % 2 == 0 else old_digest
            _write_file_at(workspace_fd, source_name, payload)
            os.replace(
                source_name, target_name,
                src_dir_fd=workspace_fd, dst_dir_fd=workspace_fd,
            )
            os.fsync(workspace_fd)
            acknowledged_bytes += _observer_exchange(observer, expected_digest)
        if observer.stdin is None:
            raise RuntimeError("Replacement observer input pipe was unavailable")
        observer.stdin.write(b"STOP\n")
        observer.stdin.flush()
        stdout, stderr = observer.communicate(timeout=2)
        continuous_facts, continuous_stdout_bytes, continuous_stderr_bytes = (
            _stop_continuous_observer(continuous)
        )
    except BaseException:
        if observer.poll() is None:
            observer.kill()
        observer.communicate(timeout=2)
        if continuous.poll() is None:
            continuous.kill()
        continuous.communicate(timeout=2)
        raise
    if (
        acknowledged_bytes + len(stdout) + continuous_stdout_bytes > MAX_CHILD_OUTPUT_BYTES
        or len(stderr) + continuous_stderr_bytes > MAX_CHILD_OUTPUT_BYTES
    ):
        return _result("atomic_rename_and_fsync", "fail", "Replacement observer exceeded its output limit", started)
    try:
        observer_facts = json.loads(stdout.decode("utf-8", "replace"))
    except (TypeError, ValueError):
        return _result("atomic_rename_and_fsync", "fail", "Replacement observer returned invalid output", started)
    target_fd = os.open(target_name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=workspace_fd)
    try:
        final_payload = os.read(target_fd, 4096)
    finally:
        os.close(target_fd)
    if (
        observer.returncode != 0
        or continuous.returncode != 0
        or not _replacement_observer_facts_are_valid(observer_facts, old_digest, new_digest)
        or continuous_facts.get("seen_digests") != sorted([old_digest, new_digest])
        or int(continuous_facts.get("observations", 0)) < REPLACE_ITERATIONS + 1
        or final_payload not in (old_payload, new_payload)
    ):
        return _result("atomic_rename_and_fsync", "fail", "Observed replacement was missing, partial, or unexpected", started)
    return _result(
        "atomic_rename_and_fsync", "pass",
        "Repeated replacement stayed exact under synchronized and continuous separate-process observation",
        started,
        replacements=REPLACE_ITERATIONS,
        observer_reads=int(observer_facts["observations"]),
        continuous_observer_reads=int(continuous_facts["observations"]),
        payload_bytes=max(len(old_payload), len(new_payload)),
    )


def _sqlite_child_facts_are_valid(value: object) -> bool:
    if not isinstance(value, dict):
        return False
    checkpoint = value.get("checkpoint")
    return (
        str(value.get("journal_mode", "")).lower() == "wal"
        and value.get("integrity") == "ok"
        and isinstance(checkpoint, list)
        and len(checkpoint) == 3
        and all(isinstance(item, int) for item in checkpoint)
        and checkpoint == [0, 0, 0]
    )


def _check_sqlite_wal(workspace_fd: int) -> dict:
    started = time.monotonic()
    name = "qualification.sqlite3"
    path = _workspace_path(workspace_fd, name)
    db = sqlite3.connect(path, timeout=2, isolation_level=None)
    try:
        mode = str(db.execute("PRAGMA journal_mode=WAL").fetchone()[0]).lower()
        db.execute("PRAGMA synchronous=FULL")
        db.execute("CREATE TABLE qualification_events(id INTEGER PRIMARY KEY, value TEXT NOT NULL)")
        db.execute("INSERT INTO qualification_events(value) VALUES ('parent-committed')")
        wal_created = os.stat(name + "-wal", dir_fd=workspace_fd, follow_symlinks=False).st_size >= 0
        shm_created = os.stat(name + "-shm", dir_fd=workspace_fd, follow_symlinks=False).st_size >= 0
        db.execute("BEGIN IMMEDIATE")
        contender = _child(
            [sys.executable, "-c", SQLITE_LOCK_CHILD, path], pass_fds=(workspace_fd,),
        )
        db.execute("ROLLBACK")
    finally:
        db.close()
    if mode != "wal" or not wal_created or not shm_created:
        return _result("sqlite_wal", "fail", "SQLite did not create WAL and SHM state", started)
    if (
        contender["timed_out"] or not contender["reaped"]
        or not contender["output_limited"] or contender["returncode"] != 24
    ):
        return _result("sqlite_wal", "fail", "A second SQLite writer was not rejected cleanly", started)
    committer = _child(
        [sys.executable, "-c", SQLITE_COMMIT_CHILD, path], pass_fds=(workspace_fd,),
    )
    if (
        committer["timed_out"] or not committer["reaped"]
        or not committer["output_limited"] or committer["returncode"] != 0
    ):
        return _result("sqlite_wal", "fail", "The separate SQLite commit/checkpoint child failed", started)
    try:
        child_facts = json.loads(committer["stdout"])
    except (TypeError, ValueError):
        return _result("sqlite_wal", "fail", "The SQLite child returned invalid bounded output", started)
    if not _sqlite_child_facts_are_valid(child_facts):
        return _result("sqlite_wal", "fail", "The SQLite child did not confirm WAL mode, integrity, and a non-busy truncated checkpoint", started)
    try:
        wal_size_after_checkpoint = os.stat(
            name + "-wal", dir_fd=workspace_fd, follow_symlinks=False,
        ).st_size
    except FileNotFoundError:
        wal_size_after_checkpoint = 0
    if wal_size_after_checkpoint != 0:
        return _result("sqlite_wal", "fail", "The WAL was not truncated after the child checkpoint", started)
    reopened = sqlite3.connect(path, timeout=2)
    try:
        rows = [row[0] for row in reopened.execute("SELECT value FROM qualification_events ORDER BY id")]
        integrity = reopened.execute("PRAGMA integrity_check").fetchone()[0]
    finally:
        reopened.close()
    if rows != ["parent-committed", "child-committed"] or integrity != "ok":
        return _result("sqlite_wal", "fail", "Reopened SQLite content or integrity was incorrect", started)
    return _result(
        "sqlite_wal", "pass",
        "WAL/SHM creation, writer contention, checkpoint, child exit, reopen, and integrity succeeded",
        started,
        journal_mode=mode,
        checkpoint=child_facts.get("checkpoint"),
        child_journal_mode=child_facts.get("journal_mode"),
        child_integrity=child_facts.get("integrity"),
        wal_bytes_after_checkpoint=wal_size_after_checkpoint,
        row_count=len(rows),
        integrity=integrity,
    )


def _read_token(workspace_fd: int) -> str:
    fd = os.open(TOKEN_FILE, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=workspace_fd)
    try:
        value = os.read(fd, 256)
        if os.read(fd, 1):
            raise ValueError("Qualification marker exceeded its size limit")
    finally:
        os.close(fd)
    return value.decode("ascii", "strict")


def _validate_worker_descriptors(
    root_fd: int,
    workspace_fd: int,
    *,
    expected_root: tuple[int, int],
    expected_workspace: tuple[int, int],
    expected_token: str,
) -> None:
    parent = os.fstat(root_fd)
    current = os.fstat(workspace_fd)
    if (parent.st_dev, parent.st_ino) != expected_root or not stat.S_ISDIR(parent.st_mode):
        raise ValueError("Worker root identity does not match the orchestrator")
    if (
        (current.st_dev, current.st_ino) != expected_workspace
        or not stat.S_ISDIR(current.st_mode)
        or stat.S_IMODE(current.st_mode) != 0o700
    ):
        raise ValueError("Worker workspace identity or permissions changed")
    if not expected_token or _read_token(workspace_fd) != expected_token:
        raise ValueError("Worker qualification marker did not match the orchestrator")


def _arm_parent_death_group_kill(expected_parent_pid: int) -> None:
    if sys.platform != "linux" or expected_parent_pid <= 1:
        raise ValueError("Worker parent-death containment requires Linux")

    def terminate_group(_signum, _frame) -> None:
        signal.signal(signal.SIGTERM, signal.SIG_DFL)
        os.killpg(os.getpgrp(), signal.SIGKILL)

    signal.signal(signal.SIGTERM, terminate_group)
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(1, signal.SIGTERM, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "Could not arm worker parent-death containment")
    if os.getppid() != expected_parent_pid:
        raise ValueError("The qualification orchestrator exited before worker containment was armed")


def _worker(
    check_id: str,
    root_fd: int,
    workspace_fd: int,
    *,
    expected_root: tuple[int, int],
    expected_workspace: tuple[int, int],
    expected_token: str,
    expected_parent_pid: int,
) -> int:
    try:
        _arm_parent_death_group_kill(expected_parent_pid)
        _validate_worker_descriptors(
            root_fd,
            workspace_fd,
            expected_root=expected_root,
            expected_workspace=expected_workspace,
            expected_token=expected_token,
        )
    except BaseException as exc:
        result = _result(check_id, "fail", exc, time.monotonic())
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 1
    if check_id == "advisory_file_lock":
        result = _check_file_lock(workspace_fd)
    elif check_id == "atomic_rename_and_fsync":
        result = _check_atomic_rename(workspace_fd)
    elif check_id == "sqlite_wal":
        result = _check_sqlite_wal(workspace_fd)
    else:
        result = _result(check_id, "fail", "Unknown qualification worker", time.monotonic())
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["status"] == "pass" else 1


def _run_worker(
    check_id: str,
    timeout: float,
    *,
    root_fd: int,
    workspace_fd: int,
    root_identity: tuple[int, int],
    workspace_identity: tuple[int, int],
    workspace_token: str,
) -> dict:
    orchestrator_pid = os.getpid()
    process = _run_process(
        [
            sys.executable,
            str(Path(__file__).resolve()),
            "--worker-check",
            check_id,
            "--root-fd",
            str(root_fd),
            "--workspace-fd",
            str(workspace_fd),
            "--workspace-token",
            workspace_token,
            "--orchestrator-pid",
            str(orchestrator_pid),
            "--root-device-id",
            str(root_identity[0]),
            "--root-inode",
            str(root_identity[1]),
            "--workspace-device-id",
            str(workspace_identity[0]),
            "--workspace-inode",
            str(workspace_identity[1]),
        ],
        timeout=timeout,
        start_new_session=True,
        pass_fds=(root_fd, workspace_fd),
    )
    if process["timed_out"]:
        return _result(check_id, "timed_out", "Qualification child exceeded its time limit", time.monotonic())
    if not process["reaped"] or not process["output_limited"]:
        return _result(check_id, "fail", "Qualification child was not reaped or exceeded its output limit", time.monotonic())
    try:
        result = json.loads(process["stdout"])
    except (TypeError, ValueError):
        return _result(check_id, "fail", "Qualification child returned invalid bounded JSON", time.monotonic())
    if process["returncode"] != 0 or result.get("id") != check_id or result.get("status") != "pass":
        return _result(check_id, "fail", result.get("detail", "Qualification child failed"), time.monotonic())
    return result


def _validate_root(root: Path) -> tuple[Path, int, dict]:
    if not root.is_absolute():
        raise ValueError("The supplied root must be an absolute path")
    requested = Path(os.path.abspath(os.fspath(root)))
    resolved = requested.resolve(strict=True)
    if requested != resolved:
        raise ValueError("The supplied root or one of its parents is a symbolic link")
    if resolved == Path(resolved.anchor):
        raise ValueError("The operating-system filesystem root cannot be qualified")
    value = os.lstat(resolved)
    if not stat.S_ISDIR(value.st_mode) or stat.S_ISLNK(value.st_mode):
        raise ValueError("The supplied root must be a real directory")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    root_fd = os.open(resolved, flags)
    current = os.fstat(root_fd)
    if (current.st_dev, current.st_ino) != (value.st_dev, value.st_ino):
        os.close(root_fd)
        raise ValueError("The supplied root changed while it was being opened")
    filesystem = os.statvfs(root_fd)
    facts = {
        "resolved_root": str(resolved),
        "device_id": current.st_dev,
        "inode": current.st_ino,
        "owner_uid": current.st_uid,
        "owner_gid": current.st_gid,
        "mode": format(stat.S_IMODE(current.st_mode), "04o"),
        "filesystem_block_size": filesystem.f_frsize,
        "filesystem_name_max": filesystem.f_namemax,
    }
    return resolved, root_fd, facts


def _create_workspace(root_fd: int, root: Path, name: str) -> tuple[Path, tuple[int, int]]:
    if not _SAFE_NAME.fullmatch(name):
        raise ValueError("The qualification workspace name is not contained and safe")
    created = False
    try:
        os.mkdir(name, 0o700, dir_fd=root_fd)
        created = True
        os.chmod(name, 0o700, dir_fd=root_fd)
        value = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
        if not stat.S_ISDIR(value.st_mode) or stat.S_IMODE(value.st_mode) != 0o700:
            raise ValueError("The qualification workspace is not a private directory")
    except BaseException:
        if created:
            os.rmdir(name, dir_fd=root_fd)
        raise
    workspace = root / name
    if workspace.parent != root:
        raise ValueError("The qualification workspace escaped its supplied root")
    return workspace, (value.st_dev, value.st_ino)


def _open_workspace(root_fd: int, name: str, identity: tuple[int, int]) -> int:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    workspace_fd = os.open(name, flags, dir_fd=root_fd)
    current = os.fstat(workspace_fd)
    if (
        (current.st_dev, current.st_ino) != identity
        or not stat.S_ISDIR(current.st_mode)
        or stat.S_IMODE(current.st_mode) != 0o700
    ):
        os.close(workspace_fd)
        raise ValueError("The qualification workspace changed while it was being opened")
    return workspace_fd


def _create_workspace_token(workspace_fd: int, token: str) -> None:
    if not re.fullmatch(r"[0-9a-f]{64}", token):
        raise ValueError("The qualification workspace token is invalid")
    _write_file_at(workspace_fd, TOKEN_FILE, token.encode("ascii"))
    os.fsync(workspace_fd)


def _workspace_usage(workspace_fd: int) -> tuple[int, int]:
    total = 0
    count = 0
    for name in os.listdir(workspace_fd):
        value = os.stat(name, dir_fd=workspace_fd, follow_symlinks=False)
        if not stat.S_ISREG(value.st_mode):
            raise ValueError("Qualification created an unexpected non-file object")
        if value.st_size > MAX_FILE_BYTES:
            raise ValueError("A qualification file exceeded its size limit")
        total += value.st_size
        count += 1
    if total > MAX_WORKSPACE_BYTES:
        raise ValueError("Qualification workspace exceeded its size limit")
    return total, count


def _cleanup_workspace(
    root_fd: int,
    workspace_fd: int,
    root_identity: tuple[int, int],
    name: str,
    workspace_identity: tuple[int, int],
) -> dict:
    started = time.monotonic()
    try:
        current_root = os.fstat(root_fd)
        if (current_root.st_dev, current_root.st_ino) != root_identity:
            raise ValueError("The supplied root identity changed before cleanup")
        current = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
        if (current.st_dev, current.st_ino) != workspace_identity or not stat.S_ISDIR(current.st_mode):
            raise ValueError("The qualification workspace identity changed before cleanup")
        opened = os.fstat(workspace_fd)
        if (opened.st_dev, opened.st_ino) != workspace_identity:
            raise ValueError("The open qualification workspace identity changed before cleanup")
        entries = os.listdir(workspace_fd)
        for entry in entries:
            value = os.stat(entry, dir_fd=workspace_fd, follow_symlinks=False)
            if not stat.S_ISREG(value.st_mode):
                raise ValueError("Cleanup refused an unexpected non-file object")
            os.unlink(entry, dir_fd=workspace_fd)
        os.fsync(workspace_fd)
        current = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
        if (current.st_dev, current.st_ino) != workspace_identity:
            raise ValueError("The qualification workspace changed during cleanup")
        os.rmdir(name, dir_fd=root_fd)
        os.fsync(root_fd)
        return _result("cleanup", "pass", "The private qualification workspace was removed", started)
    except BaseException as exc:
        return _result("cleanup", "fail", exc, started)


def _unavailable(check_id: str, detail: str) -> dict:
    return _result(check_id, "unavailable", detail, time.monotonic())


def _finalize(report: dict) -> dict:
    report["overall"] = "pass" if (
        all(item.get("status") == "pass" for item in report["checks"])
        and report["cleanup"].get("status") == "pass"
    ) else "fail"
    report["attestation"] = {
        "algorithm": "sha256",
        "authenticated": False,
        "meaning": "Integrity digest only; this report is not signed or independently authenticated.",
        "digest": report_digest(report),
    }
    if len(_canonical_bytes(report)) > MAX_REPORT_BYTES:
        compact = {
            "schema_version": REPORT_SCHEMA_VERSION,
            "tool": report["tool"],
            "declared": report["declared"],
            "overall": "fail",
            "checks": [_unavailable("report_size", "The qualification report exceeded its size limit")],
            "cleanup": report["cleanup"],
            "limitations": report["limitations"],
        }
        compact["attestation"] = {
            "algorithm": "sha256", "authenticated": False,
            "meaning": "Integrity digest only; this report is not signed or independently authenticated.",
            "digest": report_digest(compact),
        }
        return compact
    return report


def _qualify_storage_in_process(
    root: Path,
    storage_identity: str,
    *,
    workspace_name: str,
    workspace_token: str,
) -> dict:
    started = time.monotonic()
    source_path = Path(__file__).resolve()
    declared_identity = storage_identity.strip()
    identity_bytes = declared_identity.encode("utf-8")
    identity_accepted = bool(declared_identity) and len(identity_bytes) <= MAX_STORAGE_IDENTITY_BYTES
    report = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "tool": {
            "version": TOOL_VERSION,
            "source_sha256": hashlib.sha256(source_path.read_bytes()).hexdigest(),
        },
        "declared": {
            "storage_identity": declared_identity if identity_accepted else None,
            "storage_identity_sha256": hashlib.sha256(identity_bytes).hexdigest(),
            "accepted": identity_accepted,
        },
        "measured": {},
        "checks": [],
        "cleanup": _unavailable("cleanup", "No private workspace was created"),
        "limits": {
            "overall_seconds": OVERALL_TIMEOUT_SECONDS,
            "child_seconds": CHILD_TIMEOUT_SECONDS,
            "child_output_bytes": MAX_CHILD_OUTPUT_BYTES,
            "file_bytes": MAX_FILE_BYTES,
            "workspace_bytes": MAX_WORKSPACE_BYTES,
            "report_bytes": MAX_REPORT_BYTES,
            "storage_identity_bytes": MAX_STORAGE_IDENTITY_BYTES,
        },
        "limitations": [
            "A pass applies only to the exact mounted environment tested.",
            "This report does not approve a storage class or establish Kubernetes, Range, or mission readiness.",
            "Replacement stability, backup/restore, node loss, forced termination, upgrades, and rollback require later gates.",
            "The digest is unauthenticated and detects alteration only when checked against a separately trusted copy.",
        ],
    }
    if not identity_accepted:
        detail = (
            "A declared storage identity is required"
            if not declared_identity
            else "The declared storage identity exceeded its size limit"
        )
        report["checks"].append(_result("root", "fail", detail, started))
        for check_id in ("advisory_file_lock", "atomic_rename_and_fsync", "sqlite_wal"):
            report["checks"].append(_unavailable(check_id, "Root validation did not complete"))
        report["checks"].append(
            _unavailable("bounded_resources", "Qualification resource use was not measured")
        )
        return _finalize(report)
    root_fd = None
    workspace = None
    workspace_identity = None
    root_identity = None
    workspace_fd = None
    usage_total = None
    usage_count = None
    resource_error = None
    try:
        resolved, root_fd, facts = _validate_root(root)
        root_value = os.fstat(root_fd)
        root_identity = (root_value.st_dev, root_value.st_ino)
        report["measured"] = facts
        report["measured"]["executor_uid"] = os.geteuid()
        report["measured"]["executor_gid"] = os.getegid()
        report["checks"].append(_result("root", "pass", "Root identity and permissions were measured without following links", started))
        workspace, workspace_identity = _create_workspace(root_fd, resolved, workspace_name)
        workspace_fd = _open_workspace(root_fd, workspace_name, workspace_identity)
        _create_workspace_token(workspace_fd, workspace_token)
        report["measured"]["workspace_mode"] = "0700"
        report["measured"]["workspace_device_id"] = workspace_identity[0]
        for check_id in ("advisory_file_lock", "atomic_rename_and_fsync", "sqlite_wal"):
            remaining = OVERALL_TIMEOUT_SECONDS - (time.monotonic() - started)
            if remaining <= 0:
                report["checks"].append(_unavailable(check_id, "Overall qualification time limit was exhausted"))
                continue
            report["checks"].append(
                _run_worker(
                    check_id,
                    min(CHILD_TIMEOUT_SECONDS, remaining),
                    root_fd=root_fd,
                    workspace_fd=workspace_fd,
                    root_identity=root_identity,
                    workspace_identity=workspace_identity,
                    workspace_token=workspace_token,
                )
            )
        usage_total, usage_count = _workspace_usage(workspace_fd)
        report["measured"]["qualification_file_count"] = usage_count
        report["measured"]["qualification_bytes"] = usage_total
    except BaseException as exc:
        resource_error = _detail(exc)
        if not any(item["id"] == "root" for item in report["checks"]):
            report["checks"].append(_result("root", "fail", exc, started))
        present = {item["id"] for item in report["checks"]}
        for check_id in ("advisory_file_lock", "atomic_rename_and_fsync", "sqlite_wal"):
            if check_id not in present:
                report["checks"].append(_unavailable(check_id, "Qualification setup did not complete"))
    finally:
        if (
            root_fd is not None and workspace_fd is not None
            and workspace_identity is not None and root_identity is not None
        ):
            report["cleanup"] = _cleanup_workspace(
                root_fd, workspace_fd, root_identity, workspace_name, workspace_identity,
            )
        elif workspace is None:
            report["cleanup"] = _result("cleanup", "pass", "No qualification workspace required cleanup", time.monotonic())
        if workspace_fd is not None:
            os.close(workspace_fd)
        if root_fd is not None:
            os.close(root_fd)
    elapsed = time.monotonic() - started
    report["measured"]["elapsed_seconds"] = round(elapsed, 6)
    if resource_error is not None:
        report["checks"].append(
            _result("bounded_resources", "fail", resource_error, started)
        )
    elif usage_total is None or usage_count is None:
        report["checks"].append(
            _unavailable("bounded_resources", "Qualification resource use was not measured")
        )
    elif elapsed > OVERALL_TIMEOUT_SECONDS:
        report["checks"].append(
            _result("bounded_resources", "fail", "Overall qualification time limit was exceeded", started)
        )
    else:
        report["checks"].append(
            _result(
                "bounded_resources", "pass",
                "Time, child output, file, workspace, and report bounds were enforced",
                started,
                workspace_bytes=usage_total,
                workspace_files=usage_count,
            )
        )
    return _finalize(report)


def _controller_failure_report(storage_identity: str, detail: str, workspace_name: str) -> dict:
    declared_identity = storage_identity.strip()
    identity_bytes = declared_identity.encode("utf-8")
    accepted = bool(declared_identity) and len(identity_bytes) <= MAX_STORAGE_IDENTITY_BYTES
    report = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "tool": {
            "version": TOOL_VERSION,
            "source_sha256": hashlib.sha256(Path(__file__).resolve().read_bytes()).hexdigest(),
        },
        "declared": {
            "storage_identity": declared_identity if accepted else None,
            "storage_identity_sha256": hashlib.sha256(identity_bytes).hexdigest(),
            "accepted": accepted,
        },
        "measured": {"workspace_name": workspace_name},
        "checks": [
            _result("controller", "fail", detail, time.monotonic()),
            _unavailable("advisory_file_lock", "The bounded qualification controller did not complete"),
            _unavailable("atomic_rename_and_fsync", "The bounded qualification controller did not complete"),
            _unavailable("sqlite_wal", "The bounded qualification controller did not complete"),
            _unavailable("bounded_resources", "The bounded qualification controller did not complete"),
        ],
        "cleanup": _unavailable(
            "cleanup",
            "Cleanup could not be confirmed after the qualification controller failed or timed out",
        ),
        "limits": {
            "overall_seconds": OVERALL_TIMEOUT_SECONDS,
            "child_seconds": CHILD_TIMEOUT_SECONDS,
            "child_output_bytes": MAX_CHILD_OUTPUT_BYTES,
            "file_bytes": MAX_FILE_BYTES,
            "workspace_bytes": MAX_WORKSPACE_BYTES,
            "report_bytes": MAX_REPORT_BYTES,
            "storage_identity_bytes": MAX_STORAGE_IDENTITY_BYTES,
        },
        "limitations": [
            "A pass applies only to the exact mounted environment tested.",
            "This report does not approve a storage class or establish Kubernetes, Range, or mission readiness.",
            "A controller failure may leave the named private workspace for manual inspection and removal.",
            "The digest is unauthenticated and detects alteration only when checked against a separately trusted copy.",
        ],
    }
    return _finalize(report)


def _controller_report_matches_request(
    report: object,
    *,
    storage_identity: str,
    source_sha256: str,
    returncode: int,
) -> bool:
    if not isinstance(report, dict) or not verify_report_digest(report):
        return False
    declared = report.get("declared") or {}
    tool = report.get("tool") or {}
    expected_identity = storage_identity.strip()
    expected_identity_bytes = expected_identity.encode("utf-8")
    overall = report.get("overall")
    return (
        report.get("schema_version") == REPORT_SCHEMA_VERSION
        and tool.get("version") == TOOL_VERSION
        and tool.get("source_sha256") == source_sha256
        and declared.get("accepted") is True
        and declared.get("storage_identity") == expected_identity
        and declared.get("storage_identity_sha256") == hashlib.sha256(expected_identity_bytes).hexdigest()
        and overall in ("pass", "fail")
        and ((overall == "pass" and returncode == 0) or (overall == "fail" and returncode == 1))
    )


def qualify_storage(root: Path, storage_identity: str) -> dict:
    workspace_name = WORKSPACE_PREFIX + uuid.uuid4().hex
    workspace_token = uuid.uuid4().hex + uuid.uuid4().hex
    identity_bytes = storage_identity.strip().encode("utf-8")
    if not storage_identity.strip() or len(identity_bytes) > MAX_STORAGE_IDENTITY_BYTES:
        return _qualify_storage_in_process(
            root,
            storage_identity,
            workspace_name=workspace_name,
            workspace_token=workspace_token,
        )
    source_sha256 = hashlib.sha256(Path(__file__).resolve().read_bytes()).hexdigest()
    process = _run_process(
        [
            sys.executable,
            str(Path(__file__).resolve()),
            "--orchestrate",
            "--root",
            str(root),
            "--storage-identity",
            storage_identity,
            "--workspace-name",
            workspace_name,
            "--workspace-token",
            workspace_token,
        ],
        timeout=OVERALL_TIMEOUT_SECONDS,
        start_new_session=True,
        output_limit=MAX_REPORT_BYTES,
    )
    if process["timed_out"]:
        return _controller_failure_report(
            storage_identity, "The complete qualification exceeded its overall time limit", workspace_name,
        )
    if not process["reaped"] or not process["output_limited"]:
        return _controller_failure_report(
            storage_identity, "The qualification controller was not reaped or exceeded its output limit", workspace_name,
        )
    try:
        report = json.loads(process["stdout"])
    except (TypeError, ValueError):
        return _controller_failure_report(
            storage_identity, "The qualification controller returned invalid bounded JSON", workspace_name,
        )
    if not _controller_report_matches_request(
        report,
        storage_identity=storage_identity,
        source_sha256=source_sha256,
        returncode=process["returncode"],
    ):
        return _controller_failure_report(
            storage_identity, "The qualification controller report failed integrity validation", workspace_name,
        )
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path)
    parser.add_argument("--storage-identity")
    parser.add_argument("--orchestrate", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--workspace-name", help=argparse.SUPPRESS)
    parser.add_argument("--workspace-token", help=argparse.SUPPRESS)
    parser.add_argument("--worker-check", choices=("advisory_file_lock", "atomic_rename_and_fsync", "sqlite_wal"), help=argparse.SUPPRESS)
    parser.add_argument("--root-fd", type=int, help=argparse.SUPPRESS)
    parser.add_argument("--workspace-fd", type=int, help=argparse.SUPPRESS)
    parser.add_argument("--orchestrator-pid", type=int, help=argparse.SUPPRESS)
    parser.add_argument("--root-device-id", type=int, help=argparse.SUPPRESS)
    parser.add_argument("--root-inode", type=int, help=argparse.SUPPRESS)
    parser.add_argument("--workspace-device-id", type=int, help=argparse.SUPPRESS)
    parser.add_argument("--workspace-inode", type=int, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.worker_check:
        identities = (
            args.root_fd,
            args.workspace_fd,
            args.orchestrator_pid,
            args.root_device_id,
            args.root_inode,
            args.workspace_device_id,
            args.workspace_inode,
        )
        if any(value is None for value in identities) or not args.workspace_token:
            parser.error("worker descriptors, identities, and orchestrator token are required")
        return _worker(
            args.worker_check,
            args.root_fd,
            args.workspace_fd,
            expected_root=(args.root_device_id, args.root_inode),
            expected_workspace=(args.workspace_device_id, args.workspace_inode),
            expected_token=args.workspace_token,
            expected_parent_pid=args.orchestrator_pid,
        )
    if args.root is None or args.storage_identity is None:
        parser.error("--root and --storage-identity are required")
    if args.orchestrate:
        if not args.workspace_name or not args.workspace_token:
            parser.error("the bounded orchestrator requires its workspace name and token")
        report = _qualify_storage_in_process(
            args.root,
            args.storage_identity,
            workspace_name=args.workspace_name,
            workspace_token=args.workspace_token,
        )
    else:
        if args.workspace_name or args.workspace_token:
            parser.error("workspace controls are internal to the bounded orchestrator")
        report = qualify_storage(args.root, args.storage_identity)
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if len(rendered.encode("utf-8")) > MAX_REPORT_BYTES:
        raise RuntimeError("The bounded qualification report exceeded its output limit")
    print(rendered, end="")
    return 0 if report["overall"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
