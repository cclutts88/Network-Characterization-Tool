from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest


def test_scan_artifact_labels_and_combined_run_notes() -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is unavailable in this test environment")
    project_root = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        [node, str(project_root / "tests" / "scan_artifact_ui_runtime.mjs")],
        cwd=project_root,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "Scan artifact UI runtime regressions passed" in result.stdout
