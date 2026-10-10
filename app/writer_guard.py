"""Fail-closed process guard for the SQLite-backed NCT data area."""
from __future__ import annotations

from dataclasses import dataclass
import errno
import fcntl
import os
from pathlib import Path
import stat
import threading


_REGISTRY_LOCK = threading.Lock()
_PROCESS_GUARDS: dict[Path, "ApplicationWriterGuard"] = {}


class WriterGuardContended(RuntimeError):
    """Raised when another application process owns the NCT data area."""


@dataclass
class ApplicationWriterGuard:
    path: Path
    _fd: int
    _released: bool = False

    def release(self) -> None:
        if self._released:
            return
        with _REGISTRY_LOCK:
            if self._released:
                return
            try:
                fcntl.lockf(self._fd, fcntl.LOCK_UN, 1, 0, os.SEEK_SET)
            finally:
                os.close(self._fd)
                self._released = True
                if _PROCESS_GUARDS.get(self.path) is self:
                    _PROCESS_GUARDS.pop(self.path, None)


def writer_guard_path(db_path: Path) -> Path:
    path = Path(db_path)
    return path.parent / f".{path.name}.nct-writer.lock"


def acquire_application_writer_guard(db_path: Path) -> ApplicationWriterGuard:
    """Acquire the one-process writer guard before SQLite or migrations are opened."""
    requested_path = writer_guard_path(db_path)
    guard_path = requested_path.parent.resolve(strict=False) / requested_path.name
    with _REGISTRY_LOCK:
        if guard_path in _PROCESS_GUARDS:
            raise WriterGuardContended(
                "Another NCT application process is already using this data directory."
            )
        flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(guard_path, flags, 0o600)
        except OSError as exc:
            if exc.errno in {errno.ELOOP, errno.EMLINK}:
                raise WriterGuardContended(
                    "The NCT application writer guard is not a safe regular file."
                ) from exc
            raise
        try:
            os.set_inheritable(fd, False)
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise WriterGuardContended(
                    "The NCT application writer guard is not a safe regular file."
                )
            try:
                fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB, 1, 0, os.SEEK_SET)
            except OSError as exc:
                if exc.errno in {errno.EACCES, errno.EAGAIN}:
                    raise WriterGuardContended(
                        "Another NCT application process is already using this data directory."
                    ) from exc
                raise
            guard = ApplicationWriterGuard(path=guard_path, _fd=fd)
            _PROCESS_GUARDS[guard_path] = guard
            return guard
        except BaseException:
            os.close(fd)
            raise
