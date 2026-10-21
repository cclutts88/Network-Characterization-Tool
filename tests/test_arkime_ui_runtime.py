from pathlib import Path
import shutil
import subprocess

import pytest


def test_arkime_ui_runtime_regressions():
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is required for the Arkime UI runtime regression")
    project_root = Path(__file__).resolve().parents[1]
    completed = subprocess.run(
        [node, str(project_root / "tests" / "arkime_ui_runtime.mjs")],
        cwd=project_root,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr or completed.stdout
    assert "Arkime UI paging and request-ownership regressions passed" in completed.stdout
