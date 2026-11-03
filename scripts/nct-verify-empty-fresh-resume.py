#!/usr/bin/env python3
"""Refuse fresh-install resume when any analyst or retained evidence exists."""
from __future__ import annotations

import sqlite3
import sys
from pathlib import Path


EVIDENCE_TABLES = (
    "scan_runs",
    "scan_schedules",
    "imports",
    "artifact_registry",
    "artifact_observations",
    "device_collections",
    "device_collection_authority",
    "device_collection_authority_inputs",
    "arkime_imports",
    "arkime_session_receipts",
    "arkime_summary_imports",
    "arkime_summary_receipts",
    "arkime_pull_profiles",
    "arkime_pull_runs",
    "analyst_investigation_notes",
    "analyst_workspace_layouts",
    "analyst_view_preferences",
    "pipeline_jobs",
    "pipeline_job_requests",
    "device_contact_runs",
    "device_scope_assignments",
    "endpoint_entities",
    "service_entities",
    "entity_assessments",
    "saved_networks",
    "network_scopes",
    "device_collection_profile_roots",
    "device_collection_profile_versions",
)

EVIDENCE_FOLDERS = ("imports", "artifacts", "scan-runs", "device-configs", "arkime")


def verify(db_path: Path, data_root: Path, admin_user: str) -> int:
    if not db_path.is_file() or not data_root.is_dir():
        raise ValueError("the fresh-install database or data directory is missing")
    with sqlite3.connect(f"file:{db_path}?mode=ro", uri=True) as db:
        db.row_factory = sqlite3.Row
        users = db.execute(
            "SELECT username, role, disabled FROM analyst_users ORDER BY username"
        ).fetchall()
        if len(users) != 1 or users[0]["username"] != admin_user:
            raise ValueError("the fresh installation does not contain exactly the expected Administrator")
        if users[0]["role"] != "admin" or int(users[0]["disabled"]):
            raise ValueError("the expected Administrator is not active")

        present = {
            row[0]
            for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        for table in EVIDENCE_TABLES:
            if table in present and int(db.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0]):
                raise ValueError(f"retained operator data exists in {table}")

        audit = db.execute(
            "SELECT action, actor FROM analyst_auth_audit WHERE username = ? ORDER BY audit_id",
            (admin_user,),
        ).fetchall()
        expected = [("create", "bootstrap")]
        if [(row["action"], row["actor"]) for row in audit] == expected:
            resets = 0
        elif [(row["action"], row["actor"]) for row in audit] == [
            *expected,
            ("password_reset", "host-administrator-setup"),
        ]:
            resets = 1
        else:
            raise ValueError("the Administrator audit history is not an empty fresh-install history")

    for folder in EVIDENCE_FOLDERS:
        root = data_root / folder
        if root.exists() and any(path.is_file() for path in root.rglob("*")):
            raise ValueError(f"retained evidence files exist under {folder}")
    return resets


def main() -> int:
    if len(sys.argv) != 4:
        raise ValueError("usage: nct-verify-empty-fresh-resume.py DATABASE DATA_ROOT ADMIN")
    resets = verify(Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3])
    print(f"PASSWORD_RESET_COUNT={resets}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, sqlite3.Error, ValueError) as exc:
        raise SystemExit(f"Fresh-install empty-state verification failed: {exc}")
