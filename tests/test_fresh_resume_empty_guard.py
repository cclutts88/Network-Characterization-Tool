import sqlite3
from pathlib import Path
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "scripts" / "nct-verify-empty-fresh-resume.py"
EVIDENCE_TABLES = (
    "scan_runs",
    "scan_schedules",
    "imports",
    "artifact_registry",
    "artifact_observations",
    "device_collections",
    "device_collection_authority",
    "device_collection_authority_inputs",
)


def fresh_data(root: Path) -> tuple[Path, Path]:
    data = root / "data"
    data.mkdir()
    db_path = data / "analyzer.db"
    with sqlite3.connect(db_path) as db:
        db.executescript(
            """
            CREATE TABLE analyst_users (
                username TEXT PRIMARY KEY, role TEXT NOT NULL, disabled INTEGER NOT NULL
            );
            CREATE TABLE analyst_auth_audit (
                audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL, action TEXT NOT NULL, actor TEXT NOT NULL
            );
            INSERT INTO analyst_users VALUES ('admin', 'admin', 0);
            INSERT INTO analyst_auth_audit (username, action, actor)
                VALUES ('admin', 'create', 'bootstrap');
            """
        )
        for table in EVIDENCE_TABLES:
            db.execute(f'CREATE TABLE "{table}" (record_id TEXT)')
    return data, db_path


def run_guard(data: Path, db_path: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(HELPER), str(db_path), str(data), "admin"],
        capture_output=True,
        text=True,
    )


def test_empty_fresh_resume_state_is_accepted(tmp_path):
    data, db_path = fresh_data(tmp_path)
    result = run_guard(data, db_path)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "PASSWORD_RESET_COUNT=0"


@pytest.mark.parametrize(
    "table",
    ("imports", "artifact_registry", "device_collection_authority", "device_collection_authority_inputs"),
)
def test_fresh_resume_rejects_each_retained_database_evidence_type(tmp_path, table):
    data, db_path = fresh_data(tmp_path)
    with sqlite3.connect(db_path) as db:
        db.execute(f'INSERT INTO "{table}" VALUES (?)', ("retained",))
    result = run_guard(data, db_path)
    assert result.returncode != 0
    assert table in result.stderr


def test_fresh_resume_rejects_orphaned_scan_file(tmp_path):
    data, db_path = fresh_data(tmp_path)
    retained = data / "scan-runs" / "orphaned-run"
    retained.mkdir(parents=True)
    (retained / "scan.xml").write_text("<nmaprun/>", encoding="utf-8")
    result = run_guard(data, db_path)
    assert result.returncode != 0
    assert "scan-runs" in result.stderr


def test_fresh_resume_accepts_only_the_single_expected_password_reset(tmp_path):
    data, db_path = fresh_data(tmp_path)
    with sqlite3.connect(db_path) as db:
        db.execute(
            "INSERT INTO analyst_auth_audit (username, action, actor) VALUES (?, ?, ?)",
            ("admin", "password_reset", "host-administrator-setup"),
        )
    result = run_guard(data, db_path)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "PASSWORD_RESET_COUNT=1"
