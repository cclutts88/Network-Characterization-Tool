from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest


def test_hunting_auto_enrichment_runtime_regressions() -> None:
    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js is unavailable in this test environment")
    script = Path(__file__).with_name("hunting_auto_enrichment_runtime.mjs")
    completed = subprocess.run(
        [node, str(script)],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
