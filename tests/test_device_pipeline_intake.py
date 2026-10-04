from __future__ import annotations

import json
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient

from app import derived_jobs as jobs
from app import device_configs, pipeline_intake
from app.database import connect_database
from app.device_collection_authority import (
    DeviceCollectionIntegrityError,
    get_device_collection_authority,
    tombstone_device_collection,
)
from app.main import app
from app.pipeline_intake import (
    MANUAL_DEVICE_INTENT,
    get_admission_intent,
)


CONFIG = """===== show running-config =====
hostname pipeline-router
interface GigabitEthernet0/1
 ip address 10.90.0.1 255.255.255.0
ip route 0.0.0.0 0.0.0.0 192.0.2.1
"""


def _prepared_collected(tmp_path, monkeypatch, *, run_id="d" * 32):
    db_path = tmp_path / "analyzer.db"
    run_dir = tmp_path / "device-configs" / run_id
    run_dir.mkdir(parents=True)
    monkeypatch.setattr(device_configs, "DB_PATH", db_path)
    monkeypatch.setattr(device_configs, "CONFIG_DIR", tmp_path / "device-configs")
    (run_dir / "router-config.txt").write_text(CONFIG)
    (run_dir / "stdout.txt").write_text("bounded preview\n")
    (run_dir / "command-history.txt").write_text("10 show version\n")
    manifest = {
        "run_id": run_id,
        "created_at": "2030-01-01T00:00:00+00:00",
        "completed_at": "2030-01-01T00:01:00+00:00",
        "operator": "pipeline-analyst",
        "originating_host": "nct-test",
        "vendor": "cisco",
        "device_type": "router",
        "device_address": "192.0.2.90",
        "operation": "configuration_pull",
        "status": "completed",
        "output_complete": True,
        "output_truncated": False,
        "command_history_truncated": False,
        "command_history_status": "captured",
        "command_history_artifact": "command-history.txt",
        "history_command": "show history",
        "commands": ["show running-config", "show history"],
        "local_output_name": "router-config.txt",
    }
    (run_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return db_path, run_dir, manifest


def _upload(client: TestClient):
    return client.post(
        "/api/device-configs/upload",
        data={
            "operator": "pipeline-analyst",
            "originating_host": "nct-test",
            "vendor": "cisco",
            "device_type": "router",
            "device_address": "192.0.2.90",
            "device_name": "Pipeline Router",
        },
        files={"result_file": ("router.txt", CONFIG, "text/plain")},
    )


def test_new_manual_upload_uses_worker_and_never_calculates_on_summary_request(
    tmp_path, monkeypatch,
):
    db_path = tmp_path / "analyzer.db"
    config_dir = tmp_path / "device-configs"
    monkeypatch.setattr(device_configs, "DB_PATH", db_path)
    monkeypatch.setattr(device_configs, "CONFIG_DIR", config_dir)
    monkeypatch.setattr(jobs, "start_derived_job_worker", lambda *args, **kwargs: None)

    with TestClient(app) as client:
        response = _upload(client)
        assert response.status_code == 200
        run_id = response.json()["run_id"]
        pending = client.get(f"/api/device-configs/{run_id}/summary")

    assert pending.status_code == 409
    assert "waiting" in pending.json()["detail"]
    intent = get_admission_intent(
        db_path, intent_kind=MANUAL_DEVICE_INTENT, source_id=run_id,
    )
    assert intent["state"] == "pending"
    with connect_database(db_path, read_only=True) as db:
        assert db.execute(
            """SELECT 1 FROM sqlite_master
               WHERE type = 'table' AND name = 'derived_results'"""
        ).fetchone() is None

    assert jobs.dispatch_next_pipeline_intake(db_path) is True
    assert jobs.run_next_derived_job(db_path, tmp_path) is True
    job = jobs.device_summary_job_for_run(db_path, run_id)
    assert job["latest_attempt"]["state"] == "completed"
    assert job["latest_attempt"]["output_kind"] == "derived_result"

    with TestClient(app) as client:
        ready = client.get(f"/api/device-configs/{run_id}/summary")
        history = client.get("/api/device-configs").json()
    assert ready.status_code == 200
    assert ready.json()["counts"]["routes"] == 1
    assert history[0]["summary_processing_state"] == "completed"


def _create_old_intake_schema(db_path, *, row_id="legacy-intent"):
    with connect_database(db_path) as db:
        db.executescript(
            """
            CREATE TABLE pipeline_intake_sources (
                source_kind TEXT NOT NULL, source_id TEXT NOT NULL,
                policy_version INTEGER NOT NULL, marked_by TEXT NOT NULL,
                marked_at TEXT NOT NULL, PRIMARY KEY(source_kind, source_id)
            );
            CREATE TABLE pipeline_admission_intents (
                intent_id TEXT PRIMARY KEY,
                intent_kind TEXT NOT NULL CHECK (
                    intent_kind IN ('manual_nmap_scope', 'automated_nmap_scope')
                ),
                source_kind TEXT NOT NULL, source_id TEXT NOT NULL,
                policy_version INTEGER NOT NULL, observation_id TEXT,
                assignment_id TEXT, scope_id TEXT, actor TEXT NOT NULL,
                request_token TEXT NOT NULL UNIQUE, contract_json TEXT NOT NULL,
                state TEXT NOT NULL CHECK (
                    state IN ('pending', 'admitted', 'needs_scope', 'blocked')
                ),
                created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
                admitted_job_id TEXT, resolved_assignment_id TEXT,
                activity_state TEXT NOT NULL,
                last_error TEXT,
                UNIQUE(intent_kind, source_id)
            );
            CREATE TRIGGER pipeline_admission_intents_no_delete
                BEFORE DELETE ON pipeline_admission_intents
                BEGIN SELECT RAISE(ABORT, 'pipeline admission intents are retained'); END;
            """
        )
        values = (
            row_id, "manual_nmap_scope", "nmap_import_observation", "source-1",
            1, "observation-1", "assignment-1", "scope-1", "analyst",
            "token-1", json.dumps({"frozen": True}), "pending",
            "2030-01-01T00:00:00+00:00", "2030-01-01T00:00:01+00:00",
            None, None, "retrying", "temporary queue delay",
        )
        db.execute(
            """INSERT INTO pipeline_admission_intents VALUES
               (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            values,
        )
    return values


def test_intent_table_replacement_preserves_every_value(tmp_path):
    db_path = tmp_path / "old.db"
    values = _create_old_intake_schema(db_path)
    pipeline_intake.init_pipeline_intake_storage(db_path)
    with connect_database(db_path, read_only=True) as db:
        retained = db.execute(
            "SELECT * FROM pipeline_admission_intents"
        ).fetchone()
        sql = db.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' "
            "AND name='pipeline_admission_intents'"
        ).fetchone()[0]
    assert retained == values
    assert "manual_device_summary" in sql
    assert "collected_device_summary" in sql


def test_intent_table_replacement_failure_rolls_back_old_table(
    tmp_path, monkeypatch,
):
    db_path = tmp_path / "rollback.db"
    values = _create_old_intake_schema(db_path, row_id="rollback-intent")
    monkeypatch.setattr(
        pipeline_intake,
        "_after_intent_migration_copy",
        lambda db: (_ for _ in ()).throw(RuntimeError("injected replacement failure")),
    )
    with pytest.raises(RuntimeError, match="injected replacement failure"):
        pipeline_intake.init_pipeline_intake_storage(db_path)
    with connect_database(db_path) as db:
        assert db.execute("SELECT * FROM pipeline_admission_intents").fetchone() == values
        with pytest.raises(sqlite3.IntegrityError, match="retained"):
            db.execute("DELETE FROM pipeline_admission_intents")
        sql = db.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' "
            "AND name='pipeline_admission_intents'"
        ).fetchone()[0]
    assert "manual_device_summary" not in sql


def test_uncertain_activation_does_not_overwrite_committed_manifest(
    tmp_path, monkeypatch,
):
    from tests.test_collected_device_summary_authority import finalized_collection

    original = device_configs.activate_collected_device_authority

    def commit_then_raise(*args, **kwargs):
        original(*args, **kwargs)
        raise device_configs.DeviceCollectionIntegrityError("uncertain return")

    monkeypatch.setattr(jobs, "start_derived_job_worker", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        device_configs, "activate_collected_device_authority", commit_then_raise,
    )
    db_path, _, run_dir, manifest = finalized_collection(tmp_path, monkeypatch)
    retained = json.loads((run_dir / "manifest.json").read_text())
    assert retained["summary_verification_status"] == "verified"
    assert get_device_collection_authority(db_path, manifest["run_id"])["state"] == "active"


def test_collected_manifest_is_verified_before_authority_and_intent_are_visible(
    tmp_path, monkeypatch,
):
    db_path, run_dir, manifest = _prepared_collected(tmp_path, monkeypatch)
    original = device_configs.activate_collected_device_authority
    observed = []

    def inspect_then_activate(*args, **kwargs):
        retained = json.loads((run_dir / "manifest.json").read_text())
        observed.append(retained["summary_verification_status"])
        assert get_admission_intent(
            db_path,
            intent_kind=pipeline_intake.COLLECTED_DEVICE_INTENT,
            source_id=manifest["run_id"],
        ) is None
        return original(*args, **kwargs)

    monkeypatch.setattr(jobs, "start_derived_job_worker", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        device_configs, "activate_collected_device_authority", inspect_then_activate,
    )
    assert device_configs._finalize_device_collection(run_dir, manifest) is True
    assert observed == ["verified"]
    assert get_admission_intent(
        db_path,
        intent_kind=pipeline_intake.COLLECTED_DEVICE_INTENT,
        source_id=manifest["run_id"],
    )["state"] == "pending"


def test_final_manifest_write_failure_leaves_preparing_without_intent(
    tmp_path, monkeypatch,
):
    db_path, run_dir, manifest = _prepared_collected(
        tmp_path, monkeypatch, run_id="e" * 32,
    )
    original_write = device_configs._write_json_atomic

    def fail_verified(path, value):
        if value.get("summary_verification_status") == "verified":
            raise OSError("injected final manifest failure")
        return original_write(path, value)

    monkeypatch.setattr(device_configs, "_write_json_atomic", fail_verified)
    assert device_configs._finalize_device_collection(run_dir, manifest) is False
    assert get_device_collection_authority(db_path, manifest["run_id"])["state"] == "preparing"
    assert get_admission_intent(
        db_path,
        intent_kind=pipeline_intake.COLLECTED_DEVICE_INTENT,
        source_id=manifest["run_id"],
    ) is None


def test_restart_window_after_verified_manifest_still_reports_incomplete(
    tmp_path, monkeypatch,
):
    db_path, run_dir, manifest = _prepared_collected(
        tmp_path, monkeypatch, run_id="f" * 32,
    )
    monkeypatch.setattr(
        device_configs,
        "activate_collected_device_authority",
        lambda *args, **kwargs: (_ for _ in ()).throw(KeyboardInterrupt()),
    )
    with pytest.raises(KeyboardInterrupt):
        device_configs._finalize_device_collection(run_dir, manifest)
    assert json.loads((run_dir / "manifest.json").read_text())[
        "summary_verification_status"
    ] == "verified"
    assert get_device_collection_authority(db_path, manifest["run_id"])["state"] == "preparing"
    records = device_configs.history(limit=25)
    assert records[0]["status"] == "incomplete"
    assert records[0]["summary_verification_status"] == "preparing"
    assert records[0]["summary_processing_state"] == "incomplete"


def test_failed_device_job_retries_same_frozen_contract_without_network_contact(
    tmp_path, monkeypatch,
):
    db_path = tmp_path / "analyzer.db"
    monkeypatch.setattr(device_configs, "DB_PATH", db_path)
    monkeypatch.setattr(device_configs, "CONFIG_DIR", tmp_path / "device-configs")
    monkeypatch.setattr(jobs, "start_derived_job_worker", lambda *args, **kwargs: None)
    with TestClient(app) as client:
        run_id = _upload(client).json()["run_id"]
    assert jobs.dispatch_next_pipeline_intake(db_path) is True
    claim = jobs.claim_next_derived_job(db_path)
    jobs.fail_claimed_derived_job(db_path, claim, RuntimeError("injected parse failure"))
    before = jobs.device_summary_job_for_run(db_path, run_id)
    retried = jobs.retry_derived_job(
        db_path, before["job_id"], request_token="device-local-retry",
        requested_by="pipeline-analyst",
    )
    after = jobs.device_summary_job_for_run(db_path, run_id)
    assert retried["job_id"] == before["job_id"] == after["job_id"]
    assert after["definition"] == before["definition"]
    assert after["attempt_count"] == 2
    assert jobs.run_next_derived_job(db_path, tmp_path) is True
    completed = jobs.device_summary_job_for_run(db_path, run_id)
    assert completed["latest_attempt"]["state"] == "completed"
    assert completed["definition"] == before["definition"]


@pytest.mark.parametrize("failure_mode", ["deleted", "lost_claim"])
def test_device_publication_rejects_deleted_authority_or_lost_claim(
    tmp_path, monkeypatch, failure_mode,
):
    from app import device_summary_result

    db_path = tmp_path / "analyzer.db"
    monkeypatch.setattr(device_configs, "DB_PATH", db_path)
    monkeypatch.setattr(device_configs, "CONFIG_DIR", tmp_path / "device-configs")
    monkeypatch.setattr(jobs, "start_derived_job_worker", lambda *args, **kwargs: None)
    with TestClient(app) as client:
        run_id = _upload(client).json()["run_id"]
    assert jobs.dispatch_next_pipeline_intake(db_path) is True
    original = device_summary_result.calculate_device_collection_summary
    changed = threading.Event()

    def invalidate(**kwargs):
        if failure_mode == "deleted":
            tombstone_device_collection(db_path, run_id)
        else:
            assert jobs.recover_interrupted_derived_jobs(db_path) == 1
        changed.set()
        return original(**kwargs)

    monkeypatch.setattr(
        device_summary_result, "calculate_device_collection_summary", invalidate,
    )
    assert jobs.run_next_derived_job(db_path, tmp_path) is True
    assert changed.is_set()
    job = jobs.device_summary_job_for_run(db_path, run_id)
    expected = "failed" if failure_mode == "deleted" else "interrupted"
    assert job["latest_attempt"]["state"] == expected
    with connect_database(db_path, read_only=True) as db:
        assert db.execute("SELECT COUNT(*) FROM derived_results").fetchone()[0] == 0


def test_duplicate_device_encounters_finish_created_then_reused(tmp_path, monkeypatch):
    db_path = tmp_path / "analyzer.db"
    monkeypatch.setattr(device_configs, "DB_PATH", db_path)
    monkeypatch.setattr(device_configs, "CONFIG_DIR", tmp_path / "device-configs")
    monkeypatch.setattr(jobs, "start_derived_job_worker", lambda *args, **kwargs: None)
    with TestClient(app) as client:
        run_ids = [_upload(client).json()["run_id"] for _ in range(2)]
    for _ in run_ids:
        assert jobs.dispatch_next_pipeline_intake(db_path) is True
        assert jobs.run_next_derived_job(db_path, tmp_path) is True
    outcomes = [
        jobs.device_summary_job_for_run(db_path, run_id)["latest_attempt"]["outcome"]
        for run_id in run_ids
    ]
    assert sorted(outcomes) == ["created", "reused"]
    with connect_database(db_path, read_only=True) as db:
        assert db.execute("SELECT COUNT(*) FROM derived_results").fetchone()[0] == 1
        assert db.execute(
            "SELECT COUNT(*) FROM derived_result_observation_links"
        ).fetchone()[0] == 4


def test_identical_pending_encounter_cannot_publish_links_from_page_request(
    tmp_path, monkeypatch,
):
    db_path = tmp_path / "analyzer.db"
    monkeypatch.setattr(device_configs, "DB_PATH", db_path)
    monkeypatch.setattr(device_configs, "CONFIG_DIR", tmp_path / "device-configs")
    monkeypatch.setattr(jobs, "start_derived_job_worker", lambda *args, **kwargs: None)
    with TestClient(app) as client:
        first_id = _upload(client).json()["run_id"]
    assert jobs.dispatch_next_pipeline_intake(db_path) is True
    assert jobs.run_next_derived_job(db_path, tmp_path) is True
    with connect_database(db_path, read_only=True) as db:
        before = db.execute(
            "SELECT COUNT(*) FROM derived_result_observation_links"
        ).fetchone()[0]

    with TestClient(app) as client:
        second_id = _upload(client).json()["run_id"]
        pending = client.get(f"/api/device-configs/{second_id}/summary")
    assert pending.status_code == 409
    assert "waiting" in pending.json()["detail"]
    assert jobs.device_summary_job_for_run(db_path, second_id) is None
    with connect_database(db_path, read_only=True) as db:
        after = db.execute(
            "SELECT COUNT(*) FROM derived_result_observation_links"
        ).fetchone()[0]
    assert before == after == 2
    assert jobs.device_summary_job_for_run(db_path, first_id)["latest_attempt"][
        "state"
    ] == "completed"


def test_concurrent_device_publication_completes_both_attempts(tmp_path, monkeypatch):
    db_path = tmp_path / "analyzer.db"
    monkeypatch.setattr(device_configs, "DB_PATH", db_path)
    monkeypatch.setattr(device_configs, "CONFIG_DIR", tmp_path / "device-configs")
    monkeypatch.setattr(jobs, "start_derived_job_worker", lambda *args, **kwargs: None)
    with TestClient(app) as client:
        run_ids = [_upload(client).json()["run_id"] for _ in range(2)]
    assert jobs.dispatch_next_pipeline_intake(db_path) is True
    assert jobs.dispatch_next_pipeline_intake(db_path) is True
    with ThreadPoolExecutor(max_workers=2) as pool:
        completed = list(pool.map(
            lambda _: jobs.run_next_derived_job(db_path, tmp_path), range(2),
        ))
    assert completed == [True, True]
    attempts = [
        jobs.device_summary_job_for_run(db_path, run_id)["latest_attempt"]
        for run_id in run_ids
    ]
    assert all(item["state"] == "completed" for item in attempts)
    assert sorted(item["outcome"] for item in attempts) == ["created", "reused"]
    with connect_database(db_path, read_only=True) as db:
        assert db.execute("SELECT COUNT(*) FROM derived_results").fetchone()[0] == 1
