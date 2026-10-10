from pathlib import Path
import shutil
import sqlite3
import subprocess
import uuid

import pytest

from scripts.snapshot_phase0_browser_state import snapshot
from scripts.prepare_phase0_browser_data import (
    FIXED_EVIDENCE_MTIME_NS,
    FIXED_RUNTIME_TIME,
    _deterministic_application_runtime,
    _freeze_evidence_file_mtimes,
    _freeze_preparation_metadata,
    _initialize_data_root,
    _rebase_artifact_paths,
)


def test_rendered_browser_runner_self_test():
    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js is required for the rendered-browser benchmark self-test")
    root = Path(__file__).resolve().parents[1]
    completed = subprocess.run(
        [node, str(root / "scripts" / "benchmark_phase0_browser.mjs"), "--self-test"],
        cwd=root, capture_output=True, text=True, check=False,
    )
    assert completed.returncode == 0, completed.stderr or completed.stdout
    assert "rendered-browser benchmark self-test passed" in completed.stdout


def test_read_only_state_snapshot_is_stable(tmp_path):
    import sqlite3

    db_path = tmp_path / "analyzer.db"
    with sqlite3.connect(db_path) as db:
        db.execute("CREATE TABLE evidence (name TEXT NOT NULL)")
        db.execute("INSERT INTO evidence VALUES ('retained')")
    evidence = tmp_path / "source.xml"
    evidence.write_bytes(b"<nmaprun />")
    before_bytes = db_path.read_bytes()
    first = snapshot(tmp_path)
    second = snapshot(tmp_path)
    assert first == second
    assert db_path.read_bytes() == before_bytes
    assert first["database_table_counts"] == {"evidence": 1}
    assert first["evidence_file_count"] == 1


def test_browser_preparation_freezes_ids_and_clocks_then_restores_globals():
    import app.artifacts as artifacts
    import app.network_scopes as network_scopes

    original_uuid4 = uuid.uuid4
    original_artifact_clock = artifacts.utc_now
    original_scope_clock = network_scopes.utc_now
    with _deterministic_application_runtime():
        assert uuid.uuid4().hex == "00000000000000000000000000000001"
        assert uuid.uuid4().hex == "00000000000000000000000000000002"
        assert artifacts.utc_now() == FIXED_RUNTIME_TIME
        assert network_scopes.utc_now() == FIXED_RUNTIME_TIME
    assert uuid.uuid4 is original_uuid4
    assert artifacts.utc_now is original_artifact_clock
    assert network_scopes.utc_now is original_scope_clock


def test_browser_preparation_rebases_only_paths_inside_fresh_data_root(tmp_path):
    data_root = tmp_path / "fresh-run"
    data_root.mkdir()
    db_path = data_root / "analyzer.db"
    with sqlite3.connect(db_path) as db:
        db.execute("CREATE TABLE artifact_registry (sha256 TEXT, canonical_path TEXT)")
        db.execute(
            "INSERT INTO artifact_registry VALUES (?, ?)",
            ("abc", str(data_root / "artifacts" / "sha256" / "ab" / "abc")),
        )
    _rebase_artifact_paths(db_path, data_root)
    with sqlite3.connect(db_path) as db:
        assert db.execute("SELECT canonical_path FROM artifact_registry").fetchone()[0] == (
            "/data/artifacts/sha256/ab/abc"
        )

    with sqlite3.connect(db_path) as db:
        db.execute("UPDATE artifact_registry SET canonical_path = '/outside/evidence'")
    with pytest.raises(ValueError, match="outside the fresh data root"):
        _rebase_artifact_paths(db_path, data_root)


def test_browser_preparation_freezes_disposable_catalog_timestamp(tmp_path):
    db_path = tmp_path / "analyzer.db"
    with sqlite3.connect(db_path) as db:
        db.execute(
            "CREATE TABLE device_evidence_catalog_meta "
            "(singleton INTEGER, schema_version INTEGER, reconciled_at TEXT)"
        )
        db.execute(
            "INSERT INTO device_evidence_catalog_meta VALUES (1, 1, CURRENT_TIMESTAMP)"
        )
        db.execute(
            "CREATE TABLE device_analysis_cache "
            "(run_id TEXT, updated_at TEXT)"
        )
        db.execute(
            "INSERT INTO device_analysis_cache VALUES ('run-1', CURRENT_TIMESTAMP)"
        )
    _freeze_preparation_metadata(db_path)
    with sqlite3.connect(db_path) as db:
        assert db.execute(
            "SELECT reconciled_at FROM device_evidence_catalog_meta"
        ).fetchone()[0] == FIXED_RUNTIME_TIME
        assert db.execute(
            "SELECT updated_at FROM device_analysis_cache"
        ).fetchone()[0] == FIXED_RUNTIME_TIME


def test_browser_preparation_freezes_staged_evidence_times(tmp_path):
    newest = tmp_path / "device-configs" / "a-run" / "manifest.json"
    older = tmp_path / "device-configs" / "b-run" / "manifest.json"
    newest.parent.mkdir(parents=True)
    older.parent.mkdir(parents=True)
    newest.write_text("newest", encoding="utf-8")
    older.write_text("older", encoding="utf-8")
    _freeze_evidence_file_mtimes(tmp_path)
    newest_value = newest.stat()
    older_value = older.stat()
    assert newest_value.st_mtime_ns == FIXED_EVIDENCE_MTIME_NS + 2_000_000_000
    assert older_value.st_mtime_ns == FIXED_EVIDENCE_MTIME_NS + 1_000_000_000
    assert newest_value.st_mtime_ns > older_value.st_mtime_ns


def test_browser_preparation_accepts_only_an_existing_empty_mount(tmp_path):
    mounted = tmp_path / "mounted"
    mounted.mkdir()
    _initialize_data_root(mounted, allow_existing_empty=True)
    (mounted / "unexpected.txt").write_text("occupied", encoding="utf-8")
    with pytest.raises(ValueError, match="must not exist"):
        _initialize_data_root(mounted, allow_existing_empty=True)
    existing = tmp_path / "existing"
    existing.mkdir()
    with pytest.raises(ValueError, match="must not exist"):
        _initialize_data_root(existing, allow_existing_empty=False)
    created = tmp_path / "new-root"
    _initialize_data_root(created, allow_existing_empty=True)
    assert created.is_dir()
