from pathlib import Path
import shutil
import subprocess

import pytest


def test_current_network_server_paging_runtime():
    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js is required for the Current Network paging regression")
    project_root = Path(__file__).resolve().parents[1]
    completed = subprocess.run(
        [node, str(project_root / "tests" / "network_inventory_paging_runtime.mjs")],
        cwd=project_root,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr or completed.stdout
    assert "Current Network server paging runtime regression passed" in completed.stdout
