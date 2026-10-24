from pathlib import Path
import shutil
import subprocess

import pytest


def test_map_to_scan_handoff_runtime():
    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js is required for the Map-to-scan runtime regression")
    project_root = Path(__file__).resolve().parents[1]
    completed = subprocess.run(
        [node, str(project_root / "tests" / "map_scan_handoff_ui_runtime.mjs")],
        cwd=project_root,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr or completed.stdout
    assert "Map-to-scan handoff runtime regression passed" in completed.stdout
