from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest


def test_scan_history_runtime_refreshes_do_not_lose_or_stale_rows():
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is not installed in this test environment")
    project_root = Path(__file__).resolve().parents[1]
    completed = subprocess.run(
        [node, str(project_root / "tests" / "scan_history_ui_runtime.mjs")],
        cwd=project_root,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
