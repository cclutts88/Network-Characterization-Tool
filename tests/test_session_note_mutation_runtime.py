from pathlib import Path
import shutil
import subprocess

import pytest


def test_investigation_note_mutation_runtime_regression():
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is required for the browser-runtime regression")
    script = Path(__file__).with_name("session_note_mutation_runtime.mjs")
    completed = subprocess.run(
        [node, str(script)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "Investigation note mutation UI runtime regression passed" in completed.stdout
