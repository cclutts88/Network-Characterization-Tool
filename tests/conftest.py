from __future__ import annotations

import os
import tempfile
import uuid
from pathlib import Path

import pytest


TEST_DATA_DIR = Path(tempfile.gettempdir()) / f"nmap-analyzer-tests-{uuid.uuid4().hex}"
os.environ["ANALYZER_DATA_DIR"] = str(TEST_DATA_DIR)


@pytest.fixture(autouse=True)
def reset_process_worker_admission_fences():
    """Keep one test's simulated application shutdown from fencing later tests."""
    from app.derived_jobs import resume_derived_job_worker
    from app.poc import resume_scan_workers
    from app.storage_health import resume_storage_jobs

    resume_storage_jobs()
    resume_scan_workers()
    resume_derived_job_worker()
    yield
