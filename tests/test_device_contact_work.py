from __future__ import annotations

from pathlib import Path
import sqlite3

import pytest

from app.device_contact_work import (
    DEVICE_CONTACT_CAPACITY_LEASE_KEY,
    DeviceContactConflict,
    claim_device_contact_run,
    close_device_contact_after_review,
    create_device_contact_run,
    get_device_contact_run,
    init_device_contact_work_storage,
    list_unsynced_device_contact_presentations,
    mark_device_contact_presentation_synced,
    mark_device_contact_active,
    mark_device_contact_starting,
    publish_device_contact_terminal,
    recover_abandoned_device_contact,
    request_device_contact_cancellation,
)
from app.schema_compatibility import (
    DEVICE_CONTACT_MIGRATION_ID,
    LEGACY_MIGRATION_ID,
    MIGRATION_ID,
    SCHEDULED_WORK_MIGRATION_ID,
    WORK_COORDINATION_MIGRATION_ID,
    SchemaCompatibilityError,
    begin_schema_migration,
    complete_schema_migration,
    fail_schema_migration,
    schema_fingerprint,
    schema_state,
)
from app.scheduled_work import init_scheduled_work_storage
from app.work_coordination import work_lease_status
from app.work_coordination import WorkLeaseConflict


def _run(db_path: Path, suffix: str = "1") -> str:
    return create_device_contact_run(
        db_path,
        operation_kind="configuration-pull",
        subject_key=f"router-{suffix}",
        request={"host": f"192.0.2.{suffix}", "protocol": "ssh"},
        created_by="analyst.one",
    )


def test_run_and_shared_capacity_leases_are_acquired_atomically(tmp_path: Path) -> None:
    db_path = tmp_path / "analyzer.db"
    first_id = _run(db_path, "1")
    second_id = _run(db_path, "2")
    claim = claim_device_contact_run(db_path, first_id, owner_id="worker.one")

    with pytest.raises(WorkLeaseConflict, match="responsible"):
        claim_device_contact_run(db_path, second_id, owner_id="worker.two")

    second = get_device_contact_run(db_path, second_id)
    assert second is not None and second["state"] == "waiting"
    assert second["attempts"] == []
    assert work_lease_status(db_path, f"device-contact-run:{second_id}") is None
    assert claim.run_lease.fencing_epoch == 1
    assert claim.capacity_lease.lease_key == DEVICE_CONTACT_CAPACITY_LEASE_KEY


def test_cancellation_wins_atomically_before_contact(tmp_path: Path) -> None:
    db_path = tmp_path / "analyzer.db"
    run_id = _run(db_path)
    claim = claim_device_contact_run(db_path, run_id, owner_id="worker.one")
    request_device_contact_cancellation(
        db_path, run_id, requested_by="analyst.two", reason="Wrong device"
    )

    assert mark_device_contact_starting(db_path, claim) is False
    run = get_device_contact_run(db_path, run_id)
    assert run is not None and run["state"] == "cancelled"
    assert run["contact_phase"] == "not_started"
    assert run["controls"][0]["requested_by"] == "analyst.two"
    assert work_lease_status(db_path, claim.run_lease.lease_key)["state"] == "released"
    assert work_lease_status(db_path, claim.capacity_lease.lease_key)["state"] == "released"


def test_pre_contact_abandonment_closes_without_recontact(tmp_path: Path) -> None:
    db_path = tmp_path / "analyzer.db"
    run_id = _run(db_path)
    first = claim_device_contact_run(db_path, run_id, owner_id="worker.one")

    assert recover_abandoned_device_contact(
        db_path, run_id, former_process_ended=True
    ) == "failed"
    run = get_device_contact_run(db_path, run_id)
    assert run is not None and run["retry_count"] == 0
    assert run["state"] == "failed"
    assert run["contact_phase"] == "contact_stopped"
    assert run["attempts"][0]["state"] == "failed"
    assert "start a new collection" in run["status_reason"]
    assert work_lease_status(db_path, first.run_lease.lease_key)["state"] == "released"
    assert work_lease_status(db_path, first.capacity_lease.lease_key)["state"] == "released"


def test_post_contact_abandonment_requires_attributed_admin_closure(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "analyzer.db"
    run_id = _run(db_path)
    claim = claim_device_contact_run(db_path, run_id, owner_id="worker.one")
    assert mark_device_contact_starting(db_path, claim) is True
    mark_device_contact_active(db_path, claim)

    assert recover_abandoned_device_contact(
        db_path, run_id, former_process_ended=True
    ) == "needs_attention"
    with pytest.raises(ValueError, match="processes"):
        close_device_contact_after_review(
            db_path,
            run_id,
            reviewed_by="admin.one",
            reason="Reviewed interrupted pull",
            former_processes_stopped=False,
            files_stable=True,
            file_review={"files": ["running.txt"], "stable": True},
        )
    with pytest.raises(ValueError, match="stable"):
        close_device_contact_after_review(
            db_path,
            run_id,
            reviewed_by="admin.one",
            reason="Reviewed interrupted pull",
            former_processes_stopped=True,
            files_stable=False,
            file_review={"files": ["running.txt"], "stable": False},
        )

    review_id = close_device_contact_after_review(
        db_path,
        run_id,
        reviewed_by="admin.one",
        reason="Former process stopped; retained file size and digest are stable",
        former_processes_stopped=True,
        files_stable=True,
        file_review={"files": ["running.txt"], "stable": True, "samples": 2},
    )
    run = get_device_contact_run(db_path, run_id)
    assert run is not None and run["state"] == "failed"
    assert run["reviews"][0]["review_id"] == review_id
    assert run["reviews"][0]["reviewed_by"] == "admin.one"
    assert run["controls"][-1]["control_kind"] == "admin_closed"
    assert work_lease_status(db_path, claim.run_lease.lease_key)["state"] == "released"
    assert work_lease_status(db_path, claim.capacity_lease.lease_key)["state"] == "released"


def test_terminal_publication_rolls_back_callback_and_keeps_both_fences(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "analyzer.db"
    run_id = _run(db_path)
    claim = claim_device_contact_run(db_path, run_id, owner_id="worker.one")
    assert mark_device_contact_starting(db_path, claim) is True
    mark_device_contact_active(db_path, claim)

    def fail_after_write(connection: sqlite3.Connection) -> None:
        connection.execute(
            "INSERT INTO device_contact_controls VALUES (?, ?, 'cancel_requested', "
            "CURRENT_TIMESTAMP, 'test', 'must roll back')",
            ("f" * 32, run_id),
        )
        raise RuntimeError("injected terminal failure")

    with pytest.raises(RuntimeError, match="terminal failure"):
        publish_device_contact_terminal(
            db_path,
            claim,
            outcome="complete",
            reason="Complete",
            transaction_callback=fail_after_write,
        )

    run = get_device_contact_run(db_path, run_id)
    assert run is not None and run["state"] == "contact_active"
    assert run["controls"] == []
    assert work_lease_status(db_path, claim.run_lease.lease_key)["state"] == "active"
    assert work_lease_status(db_path, claim.capacity_lease.lease_key)["state"] == "active"


def _create_verified_v3_fixture(db_path: Path) -> None:
    attempt = begin_schema_migration(db_path)
    assert attempt is not None
    init_scheduled_work_storage(db_path)
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            "DELETE FROM nct_schema_migrations WHERE migration_id IN (?, ?)",
            (DEVICE_CONTACT_MIGRATION_ID, MIGRATION_ID),
        )
        fingerprint = schema_fingerprint(connection)
        connection.execute(
            """UPDATE nct_schema_migrations
                  SET status = 'completed', after_schema_fingerprint = ?,
                      error_summary = NULL
                WHERE migration_id IN (?, ?, ?)""",
            (
                fingerprint, LEGACY_MIGRATION_ID,
                WORK_COORDINATION_MIGRATION_ID, SCHEDULED_WORK_MIGRATION_ID,
            ),
        )
        connection.execute(
            """UPDATE nct_schema_state
                  SET schema_contract_version = 3, schema_version = 3,
                      migration_plan_digest = 'nct-v3-fixture',
                      schema_fingerprint = ?""",
            (fingerprint,),
        )


def test_v3_to_v5_interrupted_ddl_resumes_with_exact_lineage(tmp_path: Path) -> None:
    from app.mission_environment import init_mission_environment_storage

    db_path = tmp_path / "analyzer.db"
    _create_verified_v3_fixture(db_path)
    first = begin_schema_migration(db_path)
    assert first is not None and first.attempt == 1

    with sqlite3.connect(db_path) as connection:
        connection.execute(
            """CREATE TABLE IF NOT EXISTS device_contact_runs (
                   run_id TEXT PRIMARY KEY CHECK(length(run_id) = 32),
                   operation_kind TEXT NOT NULL,
                   subject_key TEXT NOT NULL,
                   request_json TEXT NOT NULL,
                   request_digest TEXT NOT NULL CHECK(length(request_digest) = 64),
                   state TEXT NOT NULL CHECK(state IN (
                       'waiting', 'preparing', 'contact_starting', 'contact_active',
                       'complete', 'cancelled', 'failed', 'needs_attention'
                   )),
                   contact_phase TEXT NOT NULL CHECK(contact_phase IN (
                       'not_started', 'preparing', 'contact_starting',
                       'contact_active', 'contact_stopped', 'uncertain', 'complete'
                   )),
                   cancellation_requested INTEGER NOT NULL DEFAULT 0
                       CHECK(cancellation_requested IN (0, 1)),
                   retry_count INTEGER NOT NULL DEFAULT 0 CHECK(retry_count IN (0, 1)),
                   active_attempt_number INTEGER,
                   created_at TEXT NOT NULL,
                   created_by TEXT NOT NULL,
                   updated_at TEXT NOT NULL,
                   completed_at TEXT,
                   status_reason TEXT
               )"""
        )
    fail_schema_migration(db_path, first, RuntimeError("injected v4 initializer failure"))

    retry = begin_schema_migration(db_path)
    assert retry is not None and retry.attempt == 2
    init_device_contact_work_storage(db_path)
    init_mission_environment_storage(db_path)
    complete_schema_migration(db_path, retry)

    with sqlite3.connect(db_path) as connection:
        columns = {
            row[1] for row in connection.execute(
                "PRAGMA table_info(device_contact_runs)"
            )
        }
    assert {"terminal_manifest_json", "presentation_synced"} <= columns

    run_id = _run(db_path, "10")
    claim = claim_device_contact_run(db_path, run_id, owner_id="worker.recovered")
    assert mark_device_contact_starting(db_path, claim) is True
    mark_device_contact_active(db_path, claim)
    terminal_manifest = {"run_id": run_id, "status": "completed"}
    publish_device_contact_terminal(
        db_path,
        claim,
        outcome="complete",
        reason="Recovered schema terminal publication",
        terminal_manifest=terminal_manifest,
    )
    pending = list_unsynced_device_contact_presentations(db_path)
    assert pending == [{
        "run_id": run_id,
        "attempt_number": 1,
        "manifest": terminal_manifest,
    }]
    mark_device_contact_presentation_synced(db_path, run_id)
    assert list_unsynced_device_contact_presentations(db_path) == []

    state = schema_state(db_path)
    assert state["schema_version"] == 5
    assert state["schema_fingerprint_matches"] is True
    assert [item["migration_id"] for item in state["migration_ledger"]] == [
        LEGACY_MIGRATION_ID,
        WORK_COORDINATION_MIGRATION_ID,
        SCHEDULED_WORK_MIGRATION_ID,
        DEVICE_CONTACT_MIGRATION_ID,
        MIGRATION_ID,
    ]
    assert state["migration_ledger"][-1]["attempts"] == 2


def test_version_three_image_rejects_completed_version_four(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app import schema_compatibility
    from app.mission_environment import init_mission_environment_storage

    db_path = tmp_path / "analyzer.db"
    attempt = begin_schema_migration(db_path)
    init_device_contact_work_storage(db_path)
    init_mission_environment_storage(db_path)
    complete_schema_migration(db_path, attempt)

    monkeypatch.setattr(schema_compatibility, "SCHEMA_CONTRACT_VERSION", 3)
    monkeypatch.setattr(schema_compatibility, "WRITABLE_SCHEMA_VERSION", 3)
    monkeypatch.setattr(schema_compatibility, "READABLE_SCHEMA_VERSIONS", (1, 2, 3))
    monkeypatch.setattr(
        schema_compatibility,
        "MIGRATION_PLAN",
        (
            LEGACY_MIGRATION_ID,
            WORK_COORDINATION_MIGRATION_ID,
            SCHEDULED_WORK_MIGRATION_ID,
        ),
    )
    monkeypatch.setattr(
        schema_compatibility, "MIGRATION_ID", SCHEDULED_WORK_MIGRATION_ID
    )
    with pytest.raises(SchemaCompatibilityError, match="newer"):
        schema_compatibility.begin_schema_migration(db_path)
