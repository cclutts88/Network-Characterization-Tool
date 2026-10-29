#!/usr/bin/env python3
"""Exact-source full-package gate; the stopped database is never modified."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import sqlite3
import tempfile

from app.schema_compatibility import begin_schema_migration, complete_schema_migration
from app.scan_history_index import init_scan_history_index_storage

PHASE5 = ("0.16.0-range-test-20261025-phase5-r1", "be92fb78e938adc3fced581629d4609ac0a43f6a")
SOURCES = {
    PHASE5: 7,
    ("0.16.0-range-test-20261027-recovery-r1", "0bd11969ffd81aad7cbc8335af755b80c9af0639"): 8,
}


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024**2), b""):
            result.update(block)
    return result.hexdigest()


def audit(db_path, build_id, commit, required=7):
    if SOURCES.get((build_id, commit)) != required:
        raise ValueError("This full package accepts only exact tested Phase 5 R1 or Recovery R1 sources with their recorded schema versions. Preserve the installation.")
    wal = db_path.with_name(db_path.name + "-wal")
    if not db_path.is_file() or wal.exists() and wal.stat().st_size:
        raise ValueError("The stopped database is missing or still has uncheckpointed WAL")
    original_hash = digest(db_path)
    with sqlite3.connect(f"file:{db_path}?mode=ro&immutable=1", uri=True) as db:
        if db.execute("PRAGMA integrity_check").fetchone()[0] != "ok" or db.execute("PRAGMA foreign_key_check").fetchall():
            raise ValueError("Saved data failed integrity or foreign-key checks")
        version, origin, origin_commit = db.execute("SELECT schema_version,originating_build_id,originating_build_commit FROM nct_schema_state WHERE singleton=1").fetchone()
        if version != required or (origin, origin_commit) != (build_id, commit):
            raise ValueError("Saved data does not match the exact supported source origin/version; no reset or guessed migration is performed")
    with tempfile.TemporaryDirectory(prefix="nct-schema-gate-") as temporary:
        copied = Path(temporary) / "analyzer.db"
        shutil.copyfile(db_path, copied)
        # Exact current ledger/fingerprint validation, on a disposable copy only.
        attempt = begin_schema_migration(copied)
        if required == 7:
            if attempt is None or attempt.target_schema_version != 8:
                raise ValueError("Expected the reviewed version-7 to version-8 history migration")
            init_scan_history_index_storage(copied)
            complete_schema_migration(copied, attempt)
        elif attempt is not None:
            raise ValueError("Schema-8 source unexpectedly requires a migration")
        if begin_schema_migration(copied) is not None:
            raise ValueError("Replacement schema did not remain verified after migration")
    if digest(db_path) != original_hash:
        raise ValueError("Stopped source changed during compatibility checking")
    return {"status": "pass", "compatibility": "exact-source-v%d-to-v8-disposable-image-gate" % required,
        "schema_version": required, "database_sha256": original_hash,
        "retained_running_build_id": build_id, "retained_running_build_commit": commit}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", type=Path, default=Path("/data/analyzer.db"))
    parser.add_argument("--expected-build-id", required=True)
    parser.add_argument("--expected-build-commit", required=True)
    parser.add_argument("--required-source-version", type=int, default=7)
    args = parser.parse_args()
    print(json.dumps(audit(args.db, args.expected_build_id, args.expected_build_commit, args.required_source_version), sort_keys=True))
