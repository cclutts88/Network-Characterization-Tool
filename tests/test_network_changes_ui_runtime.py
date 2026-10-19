from pathlib import Path
import shutil
import subprocess

import pytest


def test_network_changes_unassessed_path_rendering_runtime():
    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js is required for the Network Changes UI regression")
    project_root = Path(__file__).resolve().parents[1]
    completed = subprocess.run(
        [node, str(project_root / "tests" / "network_changes_ui_runtime.mjs")],
        cwd=project_root,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr or completed.stdout
    assert "Network changes path-assessment UI runtime regression passed" in completed.stdout
