#!/usr/bin/env python3
"""Read-only Range upgrade work and retained-data checks."""

from __future__ import annotations

import argparse
import glob
import hashlib
import json
from pathlib import Path
import sqlite3
import sys


ACTIVE_MANIFEST_STATES = {
    "queued", "dispatching", "running", "waiting_for_password", "awaiting_fallback_approval",
    "updating", "migrating",
}
ACTIVE_DATABASE_STATES = (
    ("scan_runs", "status", ("queued", "dispatching", "running", "awaiting_fallback_approval")),
    ("pipeline_job_attempts", "state", ("queued", "running")),
    ("scan_foundation_processing_attempts", "status", ("running",)),
    ("device_contact_runs", "state", ("waiting", "preparing", "contact_starting", "contact_active", "needs_attention")),
    ("device_contact_attempts", "state", ("preparing", "contact_starting", "contact_active", "needs_attention")),
    ("scan_schedule_occurrences", "state", ("waiting", "preparing", "active", "needs_attention")),
    ("scan_schedule_chunks", "state", ("waiting", "preparing", "active", "needs_attention")),
    ("work_leases", "state", ("active", "recovery_required")),
    ("artifact_compaction_journal", "state", ("preparing", "prepared", "replaced", "verified", "recovery-required")),
)
DATABASE_FILES = {
    "analyzer.db", "analyzer.db-wal", "analyzer.db-shm", "analyzer.db-journal",
}


def _tables(connection: sqlite3.Connection) -> set[str]:
    return {
        str(row[0])
        for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
    }


def active_work(root: Path) -> list[dict]:
    active: list[dict] = []
    for raw_path in glob.glob(str(root / "**" / "manifest.json"), recursive=True):
        path = Path(raw_path)
        try:
            item = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        state = item.get("status")
        if state in ACTIVE_MANIFEST_STATES:
            active.append({"source": "manifest", "path": str(path), "state": state})
    db_path = root / "analyzer.db"
    if not db_path.exists():
        return active
    connection = sqlite3.connect(f"file:{db_path}?mode=ro&immutable=1", uri=True)
    try:
        tables = _tables(connection)
        for table, column, states in ACTIVE_DATABASE_STATES:
            if table not in tables:
                continue
            placeholders = ",".join("?" for _ in states)
            count = int(connection.execute(
                f'SELECT COUNT(*) FROM "{table}" WHERE "{column}" IN ({placeholders})',
                states,
            ).fetchone()[0])
            if count:
                active.append({"source": "database", "table": table, "count": count})
        if "pipeline_admission_intents" in tables:
            count = int(connection.execute(
                "SELECT COUNT(*) FROM pipeline_admission_intents "
                "WHERE state = 'pending' OR activity_state IN ('waiting','retrying','paused')"
            ).fetchone()[0])
            if count:
                active.append({
                    "source": "database", "table": "pipeline_admission_intents", "count": count,
                })
    finally:
        connection.close()
    return active


def _hash_file(path: Path) -> dict:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
            size += len(block)
    return {"size": size, "sha256": digest.hexdigest()}


def snapshot(root: Path) -> dict:
    root = root.resolve()
    files: dict[str, dict] = {}
    restore_files: dict[str, dict] = {}
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        if path.is_symlink():
            raise ValueError(f"Saved data contains a symbolic link: {path.relative_to(root)}")
        if not path.is_file() or path.name == ".nct-writer.lock":
            continue
        relative = path.relative_to(root).as_posix()
        identity = _hash_file(path)
        restore_files[relative] = identity
        if path.name not in DATABASE_FILES:
            files[relative] = identity
    result = {
        "files": files,
        "restore_files": restore_files,
        "database": {"present": False, "integrity": None, "foreign_key_errors": [], "tables": {}},
        "artifact_registry": [],
    }
    db_path = root / "analyzer.db"
    if not db_path.exists():
        return result
    connection = sqlite3.connect(f"file:{db_path}?mode=ro&immutable=1", uri=True)
    try:
        result["database"]["present"] = True
        result["database"]["integrity"] = connection.execute("PRAGMA integrity_check").fetchone()[0]
        result["database"]["foreign_key_errors"] = [
            list(row) for row in connection.execute("PRAGMA foreign_key_check")
        ]
        existing = sorted(name for name in _tables(connection) if not name.startswith("sqlite_"))
        for table in existing:
            escaped = table.replace('"', '""')
            result["database"]["tables"][table] = int(
                connection.execute(f'SELECT COUNT(*) FROM "{escaped}"').fetchone()[0]
            )
        if "artifact_registry" in existing:
            for digest, size_bytes, canonical_path in connection.execute(
                "SELECT sha256, size_bytes, canonical_path FROM artifact_registry ORDER BY sha256"
            ):
                path = Path(canonical_path).resolve()
                try:
                    path.relative_to(root)
                except ValueError as exc:
                    raise ValueError(f"Artifact path escapes {root}: {canonical_path}") from exc
                observed = _hash_file(path)
                if observed != {"size": int(size_bytes), "sha256": digest}:
                    raise ValueError(f"Registered artifact does not match retained bytes: {digest}")
                result["artifact_registry"].append(observed)
    finally:
        connection.close()
    if result["database"]["integrity"] != "ok" or result["database"]["foreign_key_errors"]:
        raise ValueError("Saved database integrity or foreign-key validation failed")
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("active", "snapshot"))
    parser.add_argument("--root", type=Path, default=Path("/data"))
    args = parser.parse_args()
    if args.mode == "active":
        active = active_work(args.root)
        print(json.dumps(active, sort_keys=True))
        return 42 if active else 0
    print(json.dumps(snapshot(args.root), sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, sqlite3.Error, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1) from exc
