from pathlib import Path
import shutil
import subprocess

import pytest


def test_mac_association_ui_rejects_stale_responses():
    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js is required for the MAC association browser regression")
    project_root = Path(__file__).resolve().parents[1]
    completed = subprocess.run(
        [node, str(project_root / "tests" / "mac_association_ui_runtime.mjs")],
        cwd=project_root,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr or completed.stdout
    assert "MAC association UI stale-response regression passed" in completed.stdout
