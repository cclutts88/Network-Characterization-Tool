from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest


def test_exposure_report_runtime_rejects_stale_responses_and_clears_old_details():
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is not installed in this test environment")
    project_root = Path(__file__).resolve().parents[1]
    completed = subprocess.run(
        [node, str(project_root / "tests" / "exposure_report_ui_runtime.mjs")],
        cwd=project_root,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
