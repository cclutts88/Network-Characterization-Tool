from pathlib import Path
import shutil
import subprocess

import pytest


def test_network_map_expanded_summary_spacing_runtime():
    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js is required for the Map layout runtime regression")
    project_root = Path(__file__).resolve().parents[1]
    completed = subprocess.run(
        [node, str(project_root / "tests" / "network_map_ui_runtime.mjs")],
        cwd=project_root,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr or completed.stdout
    assert "Network Map expanded spacing runtime regression passed" in completed.stdout
