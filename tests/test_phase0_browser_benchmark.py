from pathlib import Path
import shutil
import subprocess

import pytest

from scripts.snapshot_phase0_browser_state import snapshot


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
