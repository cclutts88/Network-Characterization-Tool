#!/usr/bin/env python3
"""Snapshot and verify retained state for the concurrent-client benchmark."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sqlite3

from scripts.benchmark_phase0_concurrent_clients import CYCLES, WORKER_COUNT


EXPECTED_CHANGED_TABLES = {
    "analyst_sessions",
    "analyst_investigation_notes",
    "analyst_investigation_note_audit",
    "analyst_workspace_layouts",
    "analyst_workspace_layout_audit",
    "analyst_view_preferences",
    "analyst_filter_presets",
}


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
    table_digests: dict[str, str] = {}
    with sqlite3.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True) as db:
        db.execute("PRAGMA query_only=ON")
        integrity = [str(row[0]) for row in db.execute("PRAGMA integrity_check")]
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
            table_digest = hashlib.sha256()
            header = json.dumps([table, columns], sort_keys=True).encode()
            logical.update(header)
            table_digest.update(header)
            for row in rows:
                normalized = [value.hex() if isinstance(value, bytes) else value for value in row]
                content = json.dumps(normalized, sort_keys=True, default=str).encode()
                logical.update(content)
                table_digest.update(content)
            table_digests[table] = table_digest.hexdigest()
    evidence = hashlib.sha256()
    evidence_files = 0
    for path in sorted(data_root.rglob("*")):
        if not path.is_file() or path.name in {"analyzer.db", "analyzer.db-wal", "analyzer.db-shm"}:
            continue
        evidence_files += 1
        relative = path.relative_to(data_root).as_posix().encode()
        evidence.update(relative + b"\0" + _sha256(path).encode() + b"\0")
    return {
        "database_integrity": integrity,
        "database_logical_sha256": logical.hexdigest(),
        "database_table_counts": counts,
        "database_table_digests": table_digests,
        "evidence_sha256": evidence.hexdigest(),
        "evidence_file_count": evidence_files,
    }


def _decode_json(value: str) -> dict:
    decoded = json.loads(value)
    if not isinstance(decoded, dict):
        raise AssertionError("stored snapshot is not an object")
    return decoded


def verify(data_root: Path, before: dict, setup: dict, run: dict) -> dict:
    failures: list[str] = []
    after = snapshot(data_root)
    if before.get("database_integrity") != ["ok"] or after.get("database_integrity") != ["ok"]:
        failures.append("SQLite integrity check did not return ok before and after")
    if before.get("evidence_sha256") != after.get("evidence_sha256"):
        failures.append("retained evidence bytes changed")
    if before.get("evidence_file_count") != after.get("evidence_file_count"):
        failures.append("retained evidence file count changed")
    before_digests = before.get("database_table_digests") or {}
    after_digests = after.get("database_table_digests") or {}
    if set(before_digests) != set(after_digests):
        failures.append("database table set changed")
    changed = {
        table for table in before_digests
        if before_digests.get(table) != after_digests.get(table)
    }
    if changed != EXPECTED_CHANGED_TABLES:
        failures.append(
            f"expected changed tables {sorted(EXPECTED_CHANGED_TABLES)}, found {sorted(changed)}"
        )
    if not (run.get("summary") or {}).get("passed"):
        failures.append("client benchmark result did not pass")

    db_path = data_root / "analyzer.db"
    with sqlite3.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True) as db:
        db.row_factory = sqlite3.Row
        users = setup["users"]
        expected_owners = set(users) | {"collision-analyst"}
        actual_owners = {
            str(row[0])
            for row in db.execute(
                "SELECT username FROM analyst_users WHERE username != 'phase0admin'"
            )
        }
        if actual_owners != expected_owners:
            failures.append("analyst user roster changed")
        if int(db.execute("SELECT COUNT(*) FROM analyst_sessions").fetchone()[0]) != 20:
            failures.append("expected exactly 20 separate authenticated sessions")
        session_counts = {
            str(row["username"]): int(row["total"])
            for row in db.execute(
                "SELECT username, COUNT(*) AS total FROM analyst_sessions GROUP BY username"
            )
        }
        expected_session_counts = {
            "phase0admin": 1,
            "collision-analyst": 3,
            **{username: 2 for username in users},
        }
        if session_counts != expected_session_counts:
            failures.append(
                f"authenticated session ownership mismatch: expected {expected_session_counts}, found {session_counts}"
            )

        for index, username in enumerate(users):
            record = setup["records"][username]
            expected_version = 1 + CYCLES
            marker = f"{username}:{CYCLES}"
            note = db.execute(
                "SELECT owner, version, content FROM analyst_investigation_notes WHERE note_id = ?",
                (record["note_id"],),
            ).fetchone()
            layout = db.execute(
                "SELECT owner, version, snapshot_json FROM analyst_workspace_layouts WHERE layout_id = ?",
                (record["layout_id"],),
            ).fetchone()
            view = db.execute(
                "SELECT owner, version, snapshot_json FROM analyst_view_preferences WHERE owner = ? AND page = 'hunt'",
                (username,),
            ).fetchone()
            preset = db.execute(
                "SELECT owner, version, snapshot_json FROM analyst_filter_presets WHERE preset_id = ?",
                (record["preset_id"],),
            ).fetchone()
            for family, row in {"note": note, "layout": layout, "view": view, "preset": preset}.items():
                if row is None or str(row["owner"]) != username or int(row["version"]) != expected_version:
                    failures.append(f"{username} {family} owner/version mismatch")
                    continue
                actual_marker = str(row["content"]) if family == "note" else str(_decode_json(row["snapshot_json"]).get("marker"))
                if actual_marker != marker:
                    failures.append(f"{username} {family} final marker mismatch")
            for table, identity_column, identity in (
                ("analyst_investigation_note_audit", "note_id", record["note_id"]),
                ("analyst_workspace_layout_audit", "layout_id", record["layout_id"]),
            ):
                audit = db.execute(
                    f"SELECT owner, action, version, actor FROM {table} WHERE {identity_column} = ? ORDER BY audit_id",
                    (identity,),
                ).fetchall()
                expected_actions = ["create"] + ["update"] * CYCLES
                if (
                    [int(row["version"]) for row in audit] != list(range(1, expected_version + 1))
                    or [str(row["action"]) for row in audit] != expected_actions
                    or any(str(row["owner"]) != username or str(row["actor"]) != username for row in audit)
                ):
                    failures.append(f"{username} {table} audit sequence mismatch")
            for table in (
                "analyst_investigation_notes", "analyst_workspace_layouts",
                "analyst_view_preferences", "analyst_filter_presets",
            ):
                count = int(db.execute(f"SELECT COUNT(*) FROM {table} WHERE owner = ?", (username,)).fetchone()[0])
                if count != 1:
                    failures.append(f"{username} has {count} rows in {table}, expected 1")

        collision = db.execute(
            "SELECT owner, version, content FROM analyst_investigation_notes WHERE note_id = ?",
            (setup["collision"]["note_id"],),
        ).fetchone()
        if (
            collision is None
            or str(collision["owner"]) != "collision-analyst"
            or int(collision["version"]) != 2
            or str(collision["content"]) not in {"collision-0", "collision-1"}
        ):
            failures.append("same-record collision final state is incorrect")
        collision_audit = db.execute(
            "SELECT owner, action, version, actor FROM analyst_investigation_note_audit "
            "WHERE note_id = ? ORDER BY audit_id",
            (setup["collision"]["note_id"],),
        ).fetchall()
        if (
            [(row["action"], row["version"]) for row in collision_audit] != [("create", 1), ("update", 2)]
            or any(row["owner"] != "collision-analyst" or row["actor"] != "collision-analyst" for row in collision_audit)
        ):
            failures.append("same-record collision audit is not exactly create then one update")

        expected_counts = {
            "analyst_users": 10,
            "analyst_sessions": 20,
            "analyst_auth_audit": 10,
            "analyst_investigation_notes": WORKER_COUNT + 1,
            "analyst_investigation_note_audit": (WORKER_COUNT * (CYCLES + 1)) + 2,
            "analyst_workspace_layouts": WORKER_COUNT,
            "analyst_workspace_layout_audit": WORKER_COUNT * (CYCLES + 1),
            "analyst_view_preferences": WORKER_COUNT,
            "analyst_filter_presets": WORKER_COUNT,
        }
        for table, expected in expected_counts.items():
            actual = int(db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
            if actual != expected:
                failures.append(f"{table}: expected {expected} rows, found {actual}")

    return {
        "passed": not failures,
        "failures": failures,
        "expected_changed_tables": sorted(EXPECTED_CHANGED_TABLES),
        "actual_changed_tables": sorted(changed),
        "expected_session_counts": {
            "phase0admin": 1,
            "collision-analyst": 3,
            **{username: 2 for username in setup["users"]},
        },
        "before": before,
        "after": after,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("snapshot", "verify"), required=True)
    parser.add_argument("--data-root", type=Path, required=True)
    parser.add_argument("--before", type=Path)
    parser.add_argument("--setup", type=Path)
    parser.add_argument("--run", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.mode == "snapshot":
        result = snapshot(args.data_root.resolve())
    else:
        if args.before is None or args.setup is None or args.run is None:
            parser.error("--before, --setup and --run are required for verification")
        result = verify(
            args.data_root.resolve(),
            json.loads(args.before.read_text(encoding="utf-8")),
            json.loads(args.setup.read_text(encoding="utf-8")),
            json.loads(args.run.read_text(encoding="utf-8")),
        )
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")


if __name__ == "__main__":
    main()
