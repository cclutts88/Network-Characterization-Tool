"""Exact empty-install proof shared by the trusted fresh installer and host helper."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import sqlite3
from pathlib import Path


EVIDENCE_TABLES = (
    "scan_runs", "scan_schedules", "imports", "artifact_registry",
    "artifact_observations", "device_collections", "device_collection_authority",
    "device_collection_authority_inputs", "arkime_imports",
    "arkime_session_receipts", "arkime_summary_imports",
    "arkime_summary_receipts", "arkime_pull_profiles", "arkime_pull_runs",
    "analyst_investigation_notes", "analyst_workspace_layouts",
    "analyst_view_preferences", "pipeline_jobs", "pipeline_job_requests",
    "device_contact_runs", "device_scope_assignments", "endpoint_entities",
    "service_entities", "entity_assessments", "saved_networks", "network_scopes",
    "device_collection_profile_roots", "device_collection_profile_versions",
)
EVIDENCE_FOLDERS = ("imports", "artifacts", "scan-runs", "device-configs", "arkime")


def _parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("the authenticated session expiry has no timezone")
    return parsed.astimezone(timezone.utc)


def verify_empty(
    db_path: Path,
    data_root: Path,
    admin_user: str,
    *,
    expected_session_token: str | None = None,
) -> int:
    """Prove the expected one-admin empty state, optionally after its first sign-in."""
    if not db_path.is_file() or db_path.is_symlink() or not data_root.is_dir() or data_root.is_symlink():
        raise ValueError("the fresh-install database or data directory is missing or linked")
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
            *expected, ("password_reset", "host-administrator-setup")
        ]:
            resets = 1
        else:
            raise ValueError("the Administrator audit history is not an empty fresh-install history")

        sessions = db.execute(
            "SELECT token_hash, username, expires_at FROM analyst_sessions ORDER BY token_hash"
        ).fetchall()
        if expected_session_token is None:
            if sessions:
                raise ValueError("the fresh installation already contains an authenticated session")
        else:
            expected_hash = hashlib.sha256(expected_session_token.encode()).hexdigest()
            if len(sessions) != 1 or sessions[0]["username"] != admin_user or sessions[0]["token_hash"] != expected_hash:
                raise ValueError("the fresh installation session does not match this exact first sign-in")
            if _parse_time(sessions[0]["expires_at"]) <= datetime.now(timezone.utc):
                raise ValueError("the fresh installation session has expired")

    for folder in EVIDENCE_FOLDERS:
        root = data_root / folder
        if root.exists() and (root.is_symlink() or any(path.is_file() for path in root.rglob("*"))):
            raise ValueError(f"retained evidence files exist under {folder}")
    return resets
