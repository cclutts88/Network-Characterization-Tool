from __future__ import annotations

import os
import tempfile
import uuid
from pathlib import Path


TEST_DATA_DIR = Path(tempfile.gettempdir()) / f"nmap-analyzer-tests-{uuid.uuid4().hex}"
os.environ["ANALYZER_DATA_DIR"] = str(TEST_DATA_DIR)
