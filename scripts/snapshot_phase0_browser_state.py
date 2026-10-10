"""Print a read-only identity snapshot of NCT benchmark data."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sqlite3


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def snapshot(data_root: Path) -> dict:
    db_path = data_root / "analyzer.db"
    if not db_path.is_file():
        raise ValueError("analyzer.db is missing")
    logical = hashlib.sha256()
    counts: dict[str, int] = {}
    with sqlite3.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True) as db:
        db.execute("PRAGMA query_only=ON")
        tables = [
            row[0]
            for row in db.execute(
                "SELECT name FROM sqlite_master WHERE type='table' "
                "AND name NOT LIKE 'sqlite_%' ORDER BY name"
            )
        ]
        for table in tables:
            quoted = '"' + table.replace('"', '""') + '"'
            columns = [row[1] for row in db.execute(f"PRAGMA table_info({quoted})")]
            rows = db.execute(f"SELECT * FROM {quoted} ORDER BY rowid").fetchall()
            counts[table] = len(rows)
            logical.update(json.dumps([table, columns], sort_keys=True).encode())
            for row in rows:
                normalized = [value.hex() if isinstance(value, bytes) else value for value in row]
                logical.update(json.dumps(normalized, sort_keys=True, default=str).encode())
    evidence = hashlib.sha256()
    evidence_files = 0
    for path in sorted(data_root.rglob("*")):
        if not path.is_file() or path.name in {"analyzer.db", "analyzer.db-wal", "analyzer.db-shm"}:
            continue
        evidence_files += 1
        relative = path.relative_to(data_root).as_posix().encode()
        evidence.update(relative + b"\0" + _sha256(path).encode() + b"\0")
    return {
        "database_logical_sha256": logical.hexdigest(),
        "database_main_file_sha256": _sha256(db_path),
        "database_table_counts": counts,
        "evidence_sha256": evidence.hexdigest(),
        "evidence_file_count": evidence_files,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-root", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(snapshot(args.data_root.resolve()), sort_keys=True))


if __name__ == "__main__":
    main()
