from pathlib import Path
import shutil
import subprocess

import pytest


def test_scan_profile_mutation_runtime_regression():
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is required for the browser-runtime regression")
    script = Path(__file__).with_name("scan_profile_mutation_runtime.mjs")
    completed = subprocess.run(
        [node, str(script)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "Scan profile mutation UI runtime regression passed" in completed.stdout
