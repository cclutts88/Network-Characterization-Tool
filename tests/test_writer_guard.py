from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys

import pytest

from app.writer_guard import (
    WriterGuardContended,
    acquire_application_writer_guard,
    writer_guard_path,
)


def _attempt_in_separate_process(db_path: Path, *, crash: bool = False) -> subprocess.CompletedProcess[str]:
    action = "os._exit(0)" if crash else "guard.release()"
    code = f"""
import os
from pathlib import Path
from app.writer_guard import WriterGuardContended, acquire_application_writer_guard
try:
    guard = acquire_application_writer_guard(Path({str(db_path)!r}))
except WriterGuardContended:
    raise SystemExit(23)
{action}
"""
    return subprocess.run(
        [sys.executable, "-c", code],
        cwd=Path(__file__).resolve().parents[1],
        capture_output=True,
        text=True,
        timeout=15,
    )


def test_separate_process_contention_fails_closed_without_changing_database(tmp_path: Path) -> None:
    db_path = tmp_path / "analyzer.db"
    db_path.write_bytes(b"unchanged-database-bytes")
    guard = acquire_application_writer_guard(db_path)
    try:
        contender = _attempt_in_separate_process(db_path)
        assert contender.returncode == 23, contender.stderr
        assert db_path.read_bytes() == b"unchanged-database-bytes"
    finally:
        guard.release()


def test_release_and_process_exit_allow_the_next_owner_without_replacing_guard(tmp_path: Path) -> None:
    db_path = tmp_path / "analyzer.db"
    guard = acquire_application_writer_guard(db_path)
    path = writer_guard_path(db_path)
    inode = path.stat().st_ino
    assert os.get_inheritable(guard._fd) is False
    guard.release()
    assert path.is_file()
    assert path.stat().st_ino == inode
    assert _attempt_in_separate_process(db_path).returncode == 0
    assert path.stat().st_ino == inode

    assert _attempt_in_separate_process(db_path, crash=True).returncode == 0
    replacement = acquire_application_writer_guard(db_path)
    replacement.release()


def test_same_process_reentry_and_unsafe_symlink_fail_closed(tmp_path: Path) -> None:
    db_path = tmp_path / "analyzer.db"
    guard = acquire_application_writer_guard(db_path)
    try:
        with pytest.raises(WriterGuardContended, match="already using"):
            acquire_application_writer_guard(db_path)
    finally:
        guard.release()

    path = writer_guard_path(db_path)
    path.unlink()
    target = tmp_path / "not-the-guard"
    target.write_text("leave me alone")
    path.symlink_to(target)
    with pytest.raises(WriterGuardContended, match="safe regular file"):
        acquire_application_writer_guard(db_path)
    assert target.read_text() == "leave me alone"
