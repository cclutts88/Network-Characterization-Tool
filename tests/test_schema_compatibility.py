from __future__ import annotations

from pathlib import Path
import asyncio
import sqlite3

import pytest

from app.schema_compatibility import (
    DATA_LAYOUT_CONTRACT,
    MIGRATION_ID,
    SchemaCompatibilityError,
    begin_schema_migration,
    complete_schema_migration,
    fail_schema_migration,
    image_schema_contract,
    migration_plan_digest,
    schema_state,
    schema_fingerprint,
)
from app.work_coordination import init_work_coordination_storage


def test_schema_contract_migration_records_completed_fingerprint(tmp_path: Path) -> None:
    db_path = tmp_path / "analyzer.db"
    attempt = begin_schema_migration(db_path)
    assert attempt is not None
    with sqlite3.connect(db_path) as db:
        db.execute("CREATE TABLE retained_evidence(id TEXT PRIMARY KEY, value TEXT NOT NULL)")
        db.execute("INSERT INTO retained_evidence VALUES ('evidence-1', 'kept')")
    complete_schema_migration(db_path, attempt)

    state = schema_state(db_path)
    assert state["schema_version"] == 2
    assert state["data_layout_contract"] == DATA_LAYOUT_CONTRACT
    assert state["migration_plan_digest"] == migration_plan_digest()
    assert state["schema_fingerprint_matches"] is True
    assert state["migration_ledger"][-1]["migration_id"] == MIGRATION_ID
    assert state["migration_ledger"][-1]["status"] == "completed"
    assert begin_schema_migration(db_path) is None


def test_interrupted_schema_migration_retries_idempotently(tmp_path: Path) -> None:
    db_path = tmp_path / "analyzer.db"
    first = begin_schema_migration(db_path)
    assert first is not None
    fail_schema_migration(db_path, first, RuntimeError("injected migration failure"))

    retry = begin_schema_migration(db_path)
    assert retry is not None
    assert retry.attempt == 2
    with sqlite3.connect(db_path) as db:
        db.execute("CREATE TABLE IF NOT EXISTS retained_evidence(id TEXT PRIMARY KEY)")
    complete_schema_migration(db_path, retry)
    state = schema_state(db_path)
    assert state["migration_ledger"][-1]["attempts"] == 2
    assert state["migration_ledger"][-1]["status"] == "completed"


def test_verified_version_one_database_upgrades_with_complete_lineage(tmp_path: Path) -> None:
    db_path = tmp_path / "analyzer.db"
    begin_schema_migration(db_path)
    with sqlite3.connect(db_path) as db:
        fingerprint = schema_fingerprint(db)
        db.execute("DELETE FROM nct_schema_migrations WHERE migration_id = 'nct-work-coordination-v2'")
        db.execute(
            """UPDATE nct_schema_state
                  SET schema_contract_version = 1, schema_version = 1,
                      migration_plan_digest = 'legacy-plan', schema_fingerprint = ?""",
            (fingerprint,),
        )
    upgrade = begin_schema_migration(db_path)
    assert upgrade is not None
    init_work_coordination_storage(db_path)
    complete_schema_migration(db_path, upgrade)
    state = schema_state(db_path)
    assert state["schema_version"] == 2
    assert [item["migration_id"] for item in state["migration_ledger"]] == [
        "nct-foundation-data-contract-v1", "nct-work-coordination-v2",
    ]


@pytest.mark.parametrize("mutation", [
    "DELETE FROM nct_schema_migrations WHERE migration_id='nct-foundation-data-contract-v1'",
    "UPDATE nct_schema_migrations SET status='failed' WHERE migration_id='nct-foundation-data-contract-v1'",
    "UPDATE nct_schema_migrations SET after_schema_fingerprint=NULL WHERE migration_id='nct-foundation-data-contract-v1'",
])
def test_version_two_requires_completed_version_one_lineage(
    tmp_path: Path, mutation: str,
) -> None:
    db_path = tmp_path / "analyzer.db"
    attempt = begin_schema_migration(db_path)
    init_work_coordination_storage(db_path)
    complete_schema_migration(db_path, attempt)
    with sqlite3.connect(db_path) as db:
        db.execute(mutation)
    with pytest.raises(SchemaCompatibilityError, match="ledger"):
        begin_schema_migration(db_path)


def test_newer_or_changed_schema_contract_fails_closed(tmp_path: Path) -> None:
    db_path = tmp_path / "analyzer.db"
    attempt = begin_schema_migration(db_path)
    complete_schema_migration(db_path, attempt)
    with sqlite3.connect(db_path) as db:
        db.execute("UPDATE nct_schema_state SET schema_version = 99")
    with pytest.raises(SchemaCompatibilityError, match="not readable"):
        begin_schema_migration(db_path)


@pytest.mark.parametrize("mutation, message", [
    ("CREATE TABLE unexpected_schema(id INTEGER)", "fingerprint"),
    ("DROP TABLE nct_schema_migrations", "ledger"),
])
def test_ready_schema_drift_fails_closed(tmp_path: Path, mutation: str, message: str) -> None:
    db_path = tmp_path / "analyzer.db"
    attempt = begin_schema_migration(db_path)
    complete_schema_migration(db_path, attempt)
    with sqlite3.connect(db_path) as db:
        db.execute(mutation)
    with pytest.raises(SchemaCompatibilityError, match=message):
        begin_schema_migration(db_path)


@pytest.mark.parametrize("mutation", [
    "DELETE FROM nct_schema_migrations",
    "UPDATE nct_schema_migrations SET status='failed'",
    "UPDATE nct_schema_migrations SET after_schema_fingerprint='bad'",
])
def test_incomplete_or_mismatched_completed_ledger_fails_closed(
    tmp_path: Path, mutation: str
) -> None:
    db_path = tmp_path / "analyzer.db"
    attempt = begin_schema_migration(db_path)
    complete_schema_migration(db_path, attempt)
    with sqlite3.connect(db_path) as db:
        db.execute(mutation)
    with pytest.raises(SchemaCompatibilityError, match="ledger"):
        begin_schema_migration(db_path)


def test_image_contract_is_self_verifying_and_build_bound() -> None:
    contract = image_schema_contract()
    assert contract["schema_contract_version"] == 2
    assert contract["writable_schema_version"] == 2
    assert contract["readable_schema_versions"] == [1, 2]
    assert len(contract["contract_digest"]) == 64
    assert contract["build_id"]
    assert contract["build_commit"]


def test_lifespan_schema_rejection_never_marks_ready_or_starts_workers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app import main

    calls: list[str] = []

    class Guard:
        def release(self) -> None:
            calls.append("guard-released")

    monkeypatch.setattr(main, "DATA_DIR", tmp_path)
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "analyzer.db")
    monkeypatch.setattr(main, "begin_startup", lambda: calls.append("starting"))
    monkeypatch.setattr(main, "mark_failed", lambda: calls.append("failed"))
    monkeypatch.setattr(main, "mark_ready", lambda: calls.append("ready"))
    monkeypatch.setattr(main, "acquire_application_writer_guard", lambda _path: Guard())
    monkeypatch.setattr(main, "configure_database", lambda _path: None)
    monkeypatch.setattr(
        main, "begin_schema_migration",
        lambda _path: (_ for _ in ()).throw(SchemaCompatibilityError("schema drift")),
    )
    monkeypatch.setattr(main, "resume_scan_workers", lambda: calls.append("scan-worker"))
    monkeypatch.setattr(main, "resume_derived_job_worker", lambda: calls.append("derived-worker"))
    monkeypatch.setattr(main, "start_derived_job_worker", lambda *_args: calls.append("derived-start"))
    monkeypatch.setattr(main, "stop_storage_jobs", lambda: True)
    monkeypatch.setattr(main, "stop_schedule_batch_workers", lambda: True)
    monkeypatch.setattr(main, "stop_scan_workers", lambda: True)

    async def rejected_startup() -> None:
        async with main.lifespan(main.app):
            raise AssertionError("startup should never yield")

    with pytest.raises(SchemaCompatibilityError, match="schema drift"):
        asyncio.run(rejected_startup())
    assert "failed" in calls
    assert "ready" not in calls
    assert "scan-worker" not in calls
    assert "derived-worker" not in calls
    assert "derived-start" not in calls
