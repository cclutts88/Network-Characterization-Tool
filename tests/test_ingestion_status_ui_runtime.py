from __future__ import annotations

from pathlib import Path
import shutil
import subprocess

import pytest


def test_delayed_ingestion_page_cannot_replace_newer_page():
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is not installed in this test environment")
    project_root = Path(__file__).resolve().parents[1]
    completed = subprocess.run(
        [node, str(project_root / "tests" / "ingestion_status_ui_runtime.mjs")],
        cwd=project_root, capture_output=True, text=True, timeout=30, check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
