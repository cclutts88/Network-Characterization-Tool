from pathlib import Path
import shutil
import subprocess

import pytest


def test_reachability_policy_request_ownership_runtime():
    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js is required for the browser-handler runtime regression")
    project_root = Path(__file__).resolve().parents[1]
    completed = subprocess.run(
        [node, str(project_root / "tests" / "reachability_policy_ui_runtime.mjs")],
        cwd=project_root,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr or completed.stdout
    assert "Reach proposed-policy UI runtime regressions passed" in completed.stdout
