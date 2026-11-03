import shutil
import subprocess
from pathlib import Path

import pytest


def test_guided_tutorial_runtime_regressions():
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is not installed in this test environment")
    script = Path(__file__).parent / "js" / "tutorial_runtime.test.mjs"
    result = subprocess.run(
        [node, str(script)],
        capture_output=True,
        check=False,
        text=True,
        timeout=20,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "tutorial runtime regressions passed" in result.stdout
