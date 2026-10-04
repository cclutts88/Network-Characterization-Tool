from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest


def test_compaction_confirmation_submits_the_plan_shown_to_the_operator():
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is not installed in this test environment")
    project_root = Path(__file__).resolve().parents[1]
    completed = subprocess.run(
        [node, str(project_root / "tests" / "storage_compaction_ui_runtime.mjs")],
        cwd=project_root,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
