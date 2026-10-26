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


@pytest.fixture
def bypass_collection_safety_gate(monkeypatch):
    """Keep older focused tests isolated from the new shared setup prerequisite."""
    def ready(*_args, expected_scope_id=None, **_kwargs):
        scope_id = expected_scope_id or "test-scope"
        return {
            "ready": True,
            "scope": {"scope_id": scope_id, "version": 1, "label": "Test scope"},
            "no_strike": {"entries": [], "revision": 0},
            "review": {"revision": 1, "scope_id": scope_id},
        }

    def bind(*_args, context=None, **_kwargs):
        scope_id = (context or {}).get("scope_id") or "test-scope"
        return ready(expected_scope_id=scope_id), context

    monkeypatch.setattr("app.poc.require_collection_safety_ready", ready)
    monkeypatch.setattr("app.poc.require_collection_safety_ready_on_connection", ready)
    monkeypatch.setattr("app.poc.bind_collection_scope_context_on_connection", bind)
    monkeypatch.setattr("app.poc.active_collection_enabled", lambda: False)
    monkeypatch.setattr("app.device_configs.require_collection_safety_ready", ready)
    monkeypatch.setattr("app.device_configs.require_device_contact_manifest_ready", ready)
    yield


@pytest.fixture(autouse=True)
def keep_legacy_tests_focused_on_their_original_contract(request):
    """Only the dedicated setup suite exercises the new global prerequisite."""
    if request.node.path.name not in {
        "test_collection_safety_setup.py", "test_scan_run_batch.py",
    }:
        request.getfixturevalue("bypass_collection_safety_gate")
    yield
