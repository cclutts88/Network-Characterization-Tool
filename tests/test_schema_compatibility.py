from __future__ import annotations

from pathlib import Path
import asyncio
import sqlite3

import pytest

from app.database import connect_database
from app.schema_compatibility import (
    DATA_LAYOUT_CONTRACT,
    DEVICE_CONTACT_MIGRATION_ID,
    EXPECTED_V7_UPGRADE_SCHEMA_FINGERPRINT,
    LEGACY_MIGRATION_ID,
    MISSION_ENVIRONMENT_MIGRATION_ID,
    MIGRATION_ID,
    MIGRATION_PLAN,
    SCHEDULED_WORK_MIGRATION_ID,
    SUPPORTED_V4_RANGE_BUILDS,
    SUPPORTED_V5_RANGE_BUILDS,
    SUPPORTED_V6_RANGE_BUILDS,
    SUPPORTED_V6_SCHEMA_FINGERPRINTS,
    VLAN_EVIDENCE_MIGRATION_ID,
    SchemaCompatibilityError,
    WORK_COORDINATION_MIGRATION_ID,
    begin_schema_migration,
    complete_schema_migration as _complete_schema_migration,
    fail_schema_migration,
    image_schema_contract,
    migration_plan_digest,
    schema_state,
    schema_fingerprint,
    schema_upgrade_preflight,
)
from app.work_coordination import init_work_coordination_storage
from app.arkime_connector import init_arkime_connector_storage
from app.arkime_evidence import init_arkime_evidence_storage
from app.arkime_history import init_arkime_history_storage
from app.arkime_summary import init_arkime_summary_storage
from app.device_vlan_observations import create_device_vlan_schema
from app.device_observations import init_device_observation_storage
from app.pipeline_intake import init_pipeline_intake_storage
from app.searchsploit import init_searchsploit_storage
from app.storage_health import (
    _init_compaction_journal,
    init_storage_health_storage,
)


def complete_schema_migration(db_path: Path, attempt) -> None:
    with connect_database(db_path) as db:
        create_device_vlan_schema(db)
    if attempt is not None and attempt.target_schema_version == 7:
        init_arkime_evidence_storage(db_path)
        init_arkime_summary_storage(db_path)
        init_arkime_connector_storage(db_path)
        init_arkime_history_storage(db_path)
    _complete_schema_migration(db_path, attempt)


def _create_verified_version_two_fixture(db_path: Path) -> None:
    """Create the schema and completed ledger emitted by the v2 image."""
    attempt = begin_schema_migration(db_path)
    assert attempt is not None
    init_work_coordination_storage(db_path)
    with sqlite3.connect(db_path) as db:
        db.execute(
            "DELETE FROM nct_schema_migrations WHERE migration_id IN (?, ?, ?, ?)",
            (
                SCHEDULED_WORK_MIGRATION_ID,
                DEVICE_CONTACT_MIGRATION_ID,
                MISSION_ENVIRONMENT_MIGRATION_ID,
                MIGRATION_ID,
            ),
        )
        fingerprint = schema_fingerprint(db)
        db.execute(
            """UPDATE nct_schema_migrations
                  SET status = 'completed', after_schema_fingerprint = ?,
                      error_summary = NULL
                WHERE migration_id IN (?, ?)""",
            (fingerprint, LEGACY_MIGRATION_ID, WORK_COORDINATION_MIGRATION_ID),
        )
        db.execute(
            """UPDATE nct_schema_state
                  SET schema_contract_version = 2, schema_version = 2,
                      migration_plan_digest = 'nct-v2-fixture',
                      schema_fingerprint = ?""",
            (fingerprint,),
        )


def _create_first_scheduled_work_table(db_path: Path) -> None:
    """Commit the first real v3 table as an initializer would before failing."""
    with sqlite3.connect(db_path) as db:
        db.execute(
            """CREATE TABLE IF NOT EXISTS scan_schedule_definitions (
                   schedule_id TEXT NOT NULL,
                   definition_version INTEGER NOT NULL CHECK(definition_version >= 1),
                   definition_digest TEXT NOT NULL CHECK(length(definition_digest) = 64),
                   contract_json TEXT NOT NULL,
                   created_at TEXT NOT NULL,
                   created_by TEXT NOT NULL,
                   PRIMARY KEY(schedule_id, definition_version),
                   UNIQUE(schedule_id, definition_digest),
                   FOREIGN KEY(schedule_id) REFERENCES scan_schedules(schedule_id)
                       ON DELETE CASCADE
               )"""
        )


def test_schema_contract_migration_records_completed_fingerprint(tmp_path: Path) -> None:
    db_path = tmp_path / "analyzer.db"
    attempt = begin_schema_migration(db_path)
    assert attempt is not None
    with sqlite3.connect(db_path) as db:
        db.execute("CREATE TABLE retained_evidence(id TEXT PRIMARY KEY, value TEXT NOT NULL)")
        db.execute("INSERT INTO retained_evidence VALUES ('evidence-1', 'kept')")
    complete_schema_migration(db_path, attempt)

    state = schema_state(db_path)
    assert state["schema_version"] == 7
    assert state["data_layout_contract"] == DATA_LAYOUT_CONTRACT
    assert state["migration_plan_digest"] == migration_plan_digest()
    assert state["schema_fingerprint_matches"] is True
    current = next(
        item for item in state["migration_ledger"]
        if item["migration_id"] == MIGRATION_ID
    )
    assert current["status"] == "completed"
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
    current = next(
        item for item in state["migration_ledger"]
        if item["migration_id"] == MIGRATION_ID
    )
    assert current["attempts"] == 2
    assert current["status"] == "completed"


def test_version_two_requires_staged_upgrade_through_version_five(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "analyzer.db"
    _create_verified_version_two_fixture(db_path)

    with pytest.raises(SchemaCompatibilityError, match="version 5 first"):
        begin_schema_migration(db_path)


def test_version_two_stage_boundary_precedes_later_schema_work(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "analyzer.db"
    _create_verified_version_two_fixture(db_path)

    with pytest.raises(SchemaCompatibilityError, match="version 5 first"):
        begin_schema_migration(db_path)


def test_verified_version_one_requires_staged_upgrade(tmp_path: Path) -> None:
    db_path = tmp_path / "analyzer.db"
    begin_schema_migration(db_path)
    with sqlite3.connect(db_path) as db:
        fingerprint = schema_fingerprint(db)
        db.execute(
            """DELETE FROM nct_schema_migrations
                 WHERE migration_id IN (
                    'nct-work-coordination-v2',
                    'nct-scheduled-occurrences-v3',
                    'nct-device-contact-fencing-v4',
                    'nct-mission-environment-v5',
                    'nct-scoped-vlan-evidence-v6'
                 )"""
        )
        db.execute(
            """UPDATE nct_schema_state
                  SET schema_contract_version = 1, schema_version = 1,
                      migration_plan_digest = 'legacy-plan', schema_fingerprint = ?""",
            (fingerprint,),
        )
    with pytest.raises(SchemaCompatibilityError, match="version 5 first"):
        begin_schema_migration(db_path)


def _create_verified_version_four_fixture(db_path: Path) -> None:
    attempt = begin_schema_migration(db_path)
    assert attempt is not None
    complete_schema_migration(db_path, attempt)
    with sqlite3.connect(db_path) as db:
        schema_build_id, schema_build_commit = SUPPORTED_V4_RANGE_BUILDS[0]
        db.execute(
            "DELETE FROM nct_schema_migrations WHERE migration_id IN (?, ?, ?)",
            (
                MISSION_ENVIRONMENT_MIGRATION_ID,
                VLAN_EVIDENCE_MIGRATION_ID,
                MIGRATION_ID,
            ),
        )
        fingerprint = schema_fingerprint(db)
        db.execute(
            """UPDATE nct_schema_migrations
                  SET after_schema_fingerprint = ?,
                      originating_build_id = ?, originating_build_commit = ?
                WHERE migration_id = ?""",
            (
                fingerprint,
                schema_build_id,
                schema_build_commit,
                DEVICE_CONTACT_MIGRATION_ID,
            ),
        )
        db.execute(
            """UPDATE nct_schema_state
                  SET schema_contract_version = 4, schema_version = 4,
                      migration_plan_digest = ?, schema_fingerprint = ?,
                      originating_build_id = ?, originating_build_commit = ?""",
            (
                migration_plan_digest(MIGRATION_PLAN[:4]),
                fingerprint,
                schema_build_id,
                schema_build_commit,
            ),
        )
    _checkpoint_database(db_path)


def _create_verified_version_five_fixture(db_path: Path) -> None:
    """Create the sealed schema and completed lineage emitted by the v5 image."""
    attempt = begin_schema_migration(db_path)
    assert attempt is not None
    complete_schema_migration(db_path, attempt)
    _seal_current_schema_as_version_five(db_path)


def _seal_current_schema_as_version_five(db_path: Path) -> None:
    with sqlite3.connect(db_path) as db:
        schema_build_id, schema_build_commit = SUPPORTED_V5_RANGE_BUILDS[0]
        db.execute("DROP TABLE device_vlan_receipts")
        db.execute("DROP TABLE device_vlan_assessments")
        db.execute("DROP TABLE device_vlan_admission_intents")
        db.execute(
            "DELETE FROM nct_schema_migrations WHERE migration_id IN (?, ?)",
            (VLAN_EVIDENCE_MIGRATION_ID, MIGRATION_ID),
        )
        fingerprint = schema_fingerprint(db)
        db.execute(
            """UPDATE nct_schema_migrations
                  SET after_schema_fingerprint = ?,
                      originating_build_id = ?, originating_build_commit = ?
                WHERE migration_id = ?""",
            (
                fingerprint,
                schema_build_id,
                schema_build_commit,
                MISSION_ENVIRONMENT_MIGRATION_ID,
            ),
        )
        db.execute(
            """UPDATE nct_schema_state
                  SET schema_contract_version = 5, schema_version = 5,
                      migration_plan_digest = ?, schema_fingerprint = ?,
                      originating_build_id = ?, originating_build_commit = ?""",
            (
                migration_plan_digest(MIGRATION_PLAN[:5]),
                fingerprint,
                schema_build_id,
                schema_build_commit,
            ),
        )
    _checkpoint_database(db_path)


def _create_initialized_version_five_fixture(db_path: Path) -> None:
    """Create the actual pre-v6 device and intake schema, then seal it as v5."""
    attempt = begin_schema_migration(db_path)
    assert attempt is not None
    init_device_observation_storage(db_path)
    init_pipeline_intake_storage(db_path)
    complete_schema_migration(db_path, attempt)
    _seal_current_schema_as_version_five(db_path)


def _schema_preflight(db_path: Path) -> dict[str, object]:
    running_build_id, running_build_commit = SUPPORTED_V4_RANGE_BUILDS[1]
    return schema_upgrade_preflight(
        db_path,
        expected_build_id=running_build_id,
        expected_build_commit=running_build_commit,
    )


def _version_five_schema_preflight(db_path: Path) -> dict[str, object]:
    running_build_id, running_build_commit = SUPPORTED_V5_RANGE_BUILDS[0]
    return schema_upgrade_preflight(
        db_path,
        expected_build_id=running_build_id,
        expected_build_commit=running_build_commit,
    )


def _create_verified_version_six_fixture(db_path: Path) -> None:
    with sqlite3.connect(db_path) as db:
        fixture = (
            Path(__file__).parent / "fixtures" / "phase4_r5_schema.sql"
        ).read_text(encoding="utf-8")
        db.executescript(fixture)
    _checkpoint_database(db_path)


def _version_six_schema_preflight(db_path: Path) -> dict[str, object]:
    running_build_id, running_build_commit = SUPPORTED_V6_RANGE_BUILDS[0]
    return schema_upgrade_preflight(
        db_path,
        expected_build_id=running_build_id,
        expected_build_commit=running_build_commit,
    )


def _checkpoint_database(db_path: Path) -> None:
    with connect_database(db_path) as db:
        assert db.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()[0] == 0


def _add_phase2_late_schema_group(db_path: Path, group: str) -> None:
    if group == "searchsploit":
        init_searchsploit_storage(db_path)
        with sqlite3.connect(db_path) as db:
            db.execute(
                """INSERT INTO searchsploit_query_cache(
                       provider_key, query, candidates_json, updated_at
                   ) VALUES ('provider', 'query', '[]', '2026-10-13T00:00:00+00:00')"""
            )
        return
    if group == "backfill":
        with sqlite3.connect(db_path) as db:
            db.execute(
                "CREATE TABLE artifact_backfill (source_key TEXT PRIMARY KEY, "
                "fingerprint TEXT NOT NULL, sha256 TEXT NOT NULL)"
            )
            db.execute(
                "INSERT INTO artifact_backfill VALUES ('source', '[1, 2, 3]', 'abc')"
            )
        return
    if group == "compaction":
        _init_compaction_journal(db_path)
        with sqlite3.connect(db_path) as db:
            db.execute(
                """INSERT INTO artifact_compaction_journal(
                       compaction_id, item_id, source_path, canonical_path,
                       recovery_path, sha256, size_bytes, source_fingerprint_json,
                       canonical_fingerprint_json, state, detail, updated_at
                   ) VALUES (
                       'compaction', 'item', '/data/source', '/data/canonical',
                       '/data/recovery', 'abc', 3, '{}', '{}', 'verified', NULL,
                       '2026-10-13T00:00:00+00:00'
                   )"""
            )
        return
    raise AssertionError(f"unknown late schema group: {group}")


@pytest.mark.parametrize("groups", [
    ("searchsploit",),
    ("backfill",),
    ("compaction",),
    ("searchsploit", "backfill"),
    ("searchsploit", "compaction"),
    ("backfill", "compaction"),
    ("searchsploit", "backfill", "compaction"),
])
def test_verified_version_four_accepts_only_exact_phase2_late_schema_groups(
    tmp_path: Path,
    groups: tuple[str, ...],
) -> None:
    from app.mission_environment import init_mission_environment_storage

    db_path = tmp_path / "analyzer.db"
    _create_verified_version_four_fixture(db_path)
    for group in groups:
        _add_phase2_late_schema_group(db_path, group)
    with connect_database(db_path) as db:
        assert db.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()[0] == 0

    result = _schema_preflight(db_path)
    assert result["status"] == "pass"
    with pytest.raises(SchemaCompatibilityError, match="version 5 first"):
        begin_schema_migration(db_path)
    with sqlite3.connect(db_path) as db:
        if "searchsploit" in groups:
            assert db.execute(
                "SELECT COUNT(*) FROM searchsploit_query_cache"
            ).fetchone()[0] == 1
        if "backfill" in groups:
            assert db.execute(
                "SELECT COUNT(*) FROM artifact_backfill"
            ).fetchone()[0] == 1
        if "compaction" in groups:
            assert db.execute(
                "SELECT COUNT(*) FROM artifact_compaction_journal"
            ).fetchone()[0] == 1


@pytest.mark.parametrize("mutation", [
    "CREATE TABLE artifact_backfill (source_key TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, sha256 TEXT NOT NULL, altered TEXT)",
    "CREATE TABLE searchsploit_query_cache (provider_key TEXT NOT NULL, query TEXT NOT NULL, candidates_json TEXT NOT NULL, updated_at TEXT NOT NULL, PRIMARY KEY (provider_key, query))",
])
def test_version_four_rejects_altered_or_incomplete_phase2_late_schema(
    tmp_path: Path,
    mutation: str,
) -> None:
    db_path = tmp_path / "analyzer.db"
    _create_verified_version_four_fixture(db_path)
    with sqlite3.connect(db_path) as db:
        db.execute(mutation)
    with connect_database(db_path) as db:
        assert db.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()[0] == 0
    with pytest.raises(SchemaCompatibilityError, match="unrecognized"):
        _schema_preflight(db_path)


def test_version_four_rejects_known_late_schema_plus_unexpected_drift(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "analyzer.db"
    _create_verified_version_four_fixture(db_path)
    _add_phase2_late_schema_group(db_path, "searchsploit")
    with sqlite3.connect(db_path) as db:
        db.execute("CREATE TABLE unexpected_schema(id INTEGER PRIMARY KEY)")
    _checkpoint_database(db_path)
    _checkpoint_database(db_path)
    with connect_database(db_path) as db:
        assert db.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()[0] == 0
    with pytest.raises(SchemaCompatibilityError, match="unrecognized"):
        _schema_preflight(db_path)


def test_version_five_startup_owns_maintenance_schema_before_fingerprinting(
    tmp_path: Path,
) -> None:
    from app.mission_environment import init_mission_environment_storage

    db_path = tmp_path / "analyzer.db"
    attempt = begin_schema_migration(db_path)
    init_mission_environment_storage(db_path)
    init_searchsploit_storage(db_path)
    init_storage_health_storage(db_path)
    complete_schema_migration(db_path, attempt)
    before = schema_state(db_path)["live_schema_fingerprint"]

    init_searchsploit_storage(db_path)
    init_storage_health_storage(db_path)

    after = schema_state(db_path)
    assert after["live_schema_fingerprint"] == before
    assert after["schema_fingerprint_matches"] is True
    assert begin_schema_migration(db_path) is None


def test_version_four_read_only_preflight_accepts_exact_late_schema_and_preserves_bytes(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "analyzer.db"
    _create_verified_version_four_fixture(db_path)
    for group in ("searchsploit", "backfill", "compaction"):
        _add_phase2_late_schema_group(db_path, group)
    with connect_database(db_path) as db:
        assert db.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()[0] == 0
    before = db_path.read_bytes()

    result = _schema_preflight(db_path)

    assert result["status"] == "pass"
    assert result["compatibility"] == "exact-known-phase2-late-schema"
    assert result["schema_version"] == 4
    assert result["integrity"] == "ok"
    assert result["foreign_key_errors"] == []
    assert result["originating_build_id"] == SUPPORTED_V4_RANGE_BUILDS[0][0]
    assert result["retained_running_build_id"] == SUPPORTED_V4_RANGE_BUILDS[1][0]
    assert result["known_late_schema_objects"] == [
        "artifact_backfill",
        "artifact_compaction_journal",
        "searchsploit_query_cache",
        "searchsploit_query_cache_updated",
    ]
    assert db_path.read_bytes() == before


def test_version_four_read_only_preflight_rejects_unknown_drift(tmp_path: Path) -> None:
    db_path = tmp_path / "analyzer.db"
    _create_verified_version_four_fixture(db_path)
    with sqlite3.connect(db_path) as db:
        db.execute("CREATE TABLE unexpected_schema(id INTEGER PRIMARY KEY)")
    _checkpoint_database(db_path)

    with pytest.raises(SchemaCompatibilityError, match="unrecognized"):
        _schema_preflight(db_path)


def test_version_four_read_only_preflight_rejects_incomplete_ledger(tmp_path: Path) -> None:
    db_path = tmp_path / "analyzer.db"
    _create_verified_version_four_fixture(db_path)
    with sqlite3.connect(db_path) as db:
        db.execute(
            "DELETE FROM nct_schema_migrations WHERE migration_id = ?",
            (WORK_COORDINATION_MIGRATION_ID,),
        )
    _checkpoint_database(db_path)

    with pytest.raises(SchemaCompatibilityError, match="ledger"):
        _schema_preflight(db_path)


def test_version_four_read_only_preflight_rejects_changed_state_origin(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "analyzer.db"
    _create_verified_version_four_fixture(db_path)
    with sqlite3.connect(db_path) as db:
        db.execute(
            "UPDATE nct_schema_state SET originating_build_id = 'different-build'"
        )
    _checkpoint_database(db_path)

    with pytest.raises(SchemaCompatibilityError, match="origin"):
        _schema_preflight(db_path)


def test_version_four_read_only_preflight_rejects_changed_v4_ledger_origin(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "analyzer.db"
    _create_verified_version_four_fixture(db_path)
    with sqlite3.connect(db_path) as db:
        db.execute(
            "UPDATE nct_schema_migrations SET originating_build_commit = 'different' "
            "WHERE migration_id = ?",
            (DEVICE_CONTACT_MIGRATION_ID,),
        )
    _checkpoint_database(db_path)

    with pytest.raises(SchemaCompatibilityError, match="ledger"):
        _schema_preflight(db_path)


def test_version_four_read_only_preflight_rejects_changed_plan_digest(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "analyzer.db"
    _create_verified_version_four_fixture(db_path)
    with sqlite3.connect(db_path) as db:
        db.execute(
            "UPDATE nct_schema_state SET migration_plan_digest = 'different-plan'"
        )
    _checkpoint_database(db_path)

    with pytest.raises(SchemaCompatibilityError, match="migration plan"):
        _schema_preflight(db_path)


def test_version_four_read_only_preflight_rejects_consistent_unknown_origin(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "analyzer.db"
    _create_verified_version_four_fixture(db_path)
    with sqlite3.connect(db_path) as db:
        db.execute(
            "UPDATE nct_schema_state SET originating_build_id = 'unknown-build', "
            "originating_build_commit = 'unknown-commit'"
        )
        db.execute(
            "UPDATE nct_schema_migrations SET originating_build_id = 'unknown-build', "
            "originating_build_commit = 'unknown-commit' WHERE migration_id = ?",
            (DEVICE_CONTACT_MIGRATION_ID,),
        )
    _checkpoint_database(db_path)

    with pytest.raises(SchemaCompatibilityError, match="schema origin"):
        _schema_preflight(db_path)


def test_version_four_read_only_preflight_rejects_unknown_running_build(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "analyzer.db"
    _create_verified_version_four_fixture(db_path)

    with pytest.raises(SchemaCompatibilityError, match="retained running build"):
        schema_upgrade_preflight(
            db_path,
            expected_build_id="unknown-build",
            expected_build_commit="unknown-commit",
        )


def test_version_five_read_only_preflight_accepts_exact_phase3_range_source(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "analyzer.db"
    _create_initialized_version_five_fixture(db_path)
    with connect_database(db_path) as db:
        assert db.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()[0] == 0
    before = db_path.read_bytes()

    result = _version_five_schema_preflight(db_path)

    assert result["status"] == "pass"
    assert result["compatibility"] == "recorded-fingerprint-match-v5"
    assert result["schema_contract_version"] == 5
    assert result["schema_version"] == 5
    assert result["migration_plan_digest"] == migration_plan_digest(MIGRATION_PLAN[:5])
    assert result["originating_build_id"] == SUPPORTED_V5_RANGE_BUILDS[0][0]
    assert result["retained_running_build_id"] == SUPPORTED_V5_RANGE_BUILDS[0][0]
    assert result["migration_ids"] == list(MIGRATION_PLAN[:5])
    assert result["integrity"] == "ok"
    assert result["foreign_key_errors"] == []
    assert db_path.read_bytes() == before


def test_version_five_read_only_preflight_rejects_schema_drift(tmp_path: Path) -> None:
    db_path = tmp_path / "analyzer.db"
    _create_initialized_version_five_fixture(db_path)
    with sqlite3.connect(db_path) as db:
        db.execute("CREATE TABLE unexpected_schema(id INTEGER PRIMARY KEY)")
    _checkpoint_database(db_path)

    with pytest.raises(SchemaCompatibilityError, match="version 5.*unrecognized"):
        _version_five_schema_preflight(db_path)


def test_version_five_read_only_preflight_rejects_incomplete_ledger(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "analyzer.db"
    _create_initialized_version_five_fixture(db_path)
    with sqlite3.connect(db_path) as db:
        db.execute(
            "DELETE FROM nct_schema_migrations WHERE migration_id = ?",
            (MISSION_ENVIRONMENT_MIGRATION_ID,),
        )
    _checkpoint_database(db_path)

    with pytest.raises(SchemaCompatibilityError, match="version 5 migration ledger"):
        _version_five_schema_preflight(db_path)


def test_version_five_read_only_preflight_rejects_changed_origin(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "analyzer.db"
    _create_initialized_version_five_fixture(db_path)
    with sqlite3.connect(db_path) as db:
        db.execute(
            "UPDATE nct_schema_state SET originating_build_commit = 'different'"
        )
    _checkpoint_database(db_path)

    with pytest.raises(SchemaCompatibilityError, match="schema origin"):
        _version_five_schema_preflight(db_path)


def test_version_five_read_only_preflight_rejects_changed_final_ledger_origin(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "analyzer.db"
    _create_initialized_version_five_fixture(db_path)
    with sqlite3.connect(db_path) as db:
        db.execute(
            "UPDATE nct_schema_migrations SET originating_build_id = 'different' "
            "WHERE migration_id = ?",
            (MISSION_ENVIRONMENT_MIGRATION_ID,),
        )
    _checkpoint_database(db_path)

    with pytest.raises(SchemaCompatibilityError, match="version 5 migration ledger"):
        _version_five_schema_preflight(db_path)


def test_version_five_read_only_preflight_rejects_unknown_running_build(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "analyzer.db"
    _create_initialized_version_five_fixture(db_path)
    _checkpoint_database(db_path)

    with pytest.raises(SchemaCompatibilityError, match="retained running build"):
        schema_upgrade_preflight(
            db_path,
            expected_build_id="unknown-build",
            expected_build_commit="unknown-commit",
        )


def test_version_six_read_only_preflight_accepts_exact_phase4_range_source(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "analyzer.db"
    _create_verified_version_six_fixture(db_path)
    before = db_path.read_bytes()

    result = _version_six_schema_preflight(db_path)

    assert result["status"] == "pass"
    assert result["compatibility"] == "recorded-fingerprint-match-v6"
    assert result["schema_contract_version"] == 6
    assert result["schema_version"] == 6
    assert result["migration_plan_digest"] == migration_plan_digest(MIGRATION_PLAN[:6])
    assert result["originating_build_id"] == SUPPORTED_V6_RANGE_BUILDS[0][0]
    assert result["retained_running_build_id"] == SUPPORTED_V6_RANGE_BUILDS[0][0]
    assert result["live_schema_fingerprint"] == SUPPORTED_V6_SCHEMA_FINGERPRINTS[
        SUPPORTED_V6_RANGE_BUILDS[0]
    ]
    assert result["migration_ids"] == list(MIGRATION_PLAN[:6])
    assert result["integrity"] == "ok"
    assert result["foreign_key_errors"] == []
    assert db_path.read_bytes() == before


def test_version_six_read_only_preflight_rejects_schema_drift(tmp_path: Path) -> None:
    db_path = tmp_path / "analyzer.db"
    _create_verified_version_six_fixture(db_path)
    with sqlite3.connect(db_path) as db:
        db.execute("CREATE TABLE unexpected_schema(id INTEGER PRIMARY KEY)")
        changed_fingerprint = schema_fingerprint(db)
        db.execute(
            "UPDATE nct_schema_state SET schema_fingerprint = ?",
            (changed_fingerprint,),
        )
        db.execute(
            """UPDATE nct_schema_migrations
                  SET after_schema_fingerprint = ? WHERE migration_id = ?""",
            (changed_fingerprint, MIGRATION_ID),
        )
    _checkpoint_database(db_path)

    with pytest.raises(SchemaCompatibilityError, match="version 6.*unrecognized"):
        _version_six_schema_preflight(db_path)


def test_version_six_read_only_preflight_rejects_incomplete_ledger(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "analyzer.db"
    _create_verified_version_six_fixture(db_path)
    with sqlite3.connect(db_path) as db:
        db.execute(
            "DELETE FROM nct_schema_migrations WHERE migration_id = ?",
            (VLAN_EVIDENCE_MIGRATION_ID,),
        )
    _checkpoint_database(db_path)

    with pytest.raises(SchemaCompatibilityError, match="version 6 migration ledger"):
        _version_six_schema_preflight(db_path)


def test_version_six_read_only_preflight_rejects_unknown_schema_origin(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "analyzer.db"
    _create_verified_version_six_fixture(db_path)
    with sqlite3.connect(db_path) as db:
        db.execute(
            """UPDATE nct_schema_state
                  SET originating_build_id = 'unknown-build',
                      originating_build_commit = 'unknown-commit'"""
        )
    _checkpoint_database(db_path)

    with pytest.raises(SchemaCompatibilityError, match="schema origin"):
        _version_six_schema_preflight(db_path)


def test_version_six_read_only_preflight_rejects_unknown_running_build(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "analyzer.db"
    _create_verified_version_six_fixture(db_path)

    with pytest.raises(SchemaCompatibilityError, match="retained running build"):
        schema_upgrade_preflight(
            db_path,
            expected_build_id="unknown-build",
            expected_build_commit="unknown-commit",
        )


def test_exact_phase4_version_six_upgrades_to_version_seven_runtime_schema(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "analyzer.db"
    _create_verified_version_six_fixture(db_path)

    upgrade = begin_schema_migration(db_path)

    assert upgrade is not None
    assert upgrade.migration_id == MIGRATION_ID
    assert upgrade.target_schema_version == 7
    complete_schema_migration(db_path, upgrade)
    state = schema_state(db_path)
    assert state["schema_version"] == 7
    assert state["schema_contract_version"] == 7
    assert state["live_schema_fingerprint"] == EXPECTED_V7_UPGRADE_SCHEMA_FINGERPRINT
    assert state["schema_fingerprint_matches"] is True
    assert [item["migration_id"] for item in state["migration_ledger"]] == list(
        MIGRATION_PLAN
    )
    assert begin_schema_migration(db_path) is None


def test_exact_phase4_version_six_hard_interruption_after_v7_ddl_resumes(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "analyzer.db"
    _create_verified_version_six_fixture(db_path)
    first = begin_schema_migration(db_path)
    assert first is not None
    init_arkime_evidence_storage(db_path)
    init_arkime_summary_storage(db_path)
    init_arkime_connector_storage(db_path)
    init_arkime_history_storage(db_path)

    retry = begin_schema_migration(db_path)

    assert retry is not None
    assert retry.attempt == 2
    complete_schema_migration(db_path, retry)
    assert schema_state(db_path)["schema_version"] == 7


def test_version_six_to_seven_rejects_unreviewed_schema_change(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "analyzer.db"
    _create_verified_version_six_fixture(db_path)
    first = begin_schema_migration(db_path)
    assert first is not None
    init_arkime_evidence_storage(db_path)
    init_arkime_summary_storage(db_path)
    init_arkime_connector_storage(db_path)
    init_arkime_history_storage(db_path)
    with sqlite3.connect(db_path) as db:
        db.execute("CREATE TABLE unexpected_v7_schema(id INTEGER PRIMARY KEY)")
    fail_schema_migration(db_path, first, RuntimeError("unexpected v7 DDL"))

    with pytest.raises(SchemaCompatibilityError, match="exact resumable"):
        begin_schema_migration(db_path)


def test_version_seven_image_requires_phase4_bridge_for_version_five(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "analyzer.db"
    _create_verified_version_five_fixture(db_path)
    before = schema_state(db_path)

    with pytest.raises(SchemaCompatibilityError, match="phase4 bridge image"):
        begin_schema_migration(db_path)

    after = schema_state(db_path)
    assert after["schema_version"] == 5
    assert after["schema_fingerprint_matches"] is True
    assert after["migration_ledger"] == before["migration_ledger"]


def test_phase5_package_preflight_refuses_version_five_source(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "analyzer.db"
    _create_verified_version_five_fixture(db_path)
    running_build_id, running_build_commit = SUPPORTED_V5_RANGE_BUILDS[0]

    with pytest.raises(
        SchemaCompatibilityError,
        match="requires exact schema version 6.*exact Phase 4 bridge package first",
    ):
        schema_upgrade_preflight(
            db_path,
            expected_build_id=running_build_id,
            expected_build_commit=running_build_commit,
            required_source_version=6,
        )


def test_verified_version_four_requires_staged_upgrade(tmp_path: Path) -> None:
    db_path = tmp_path / "analyzer.db"
    _create_verified_version_four_fixture(db_path)
    with pytest.raises(SchemaCompatibilityError, match="version 5 first"):
        begin_schema_migration(db_path)


def test_version_four_staged_boundary_does_not_start_v6(tmp_path: Path) -> None:
    db_path = tmp_path / "analyzer.db"
    _create_verified_version_four_fixture(db_path)
    with pytest.raises(SchemaCompatibilityError, match="version 5 first"):
        begin_schema_migration(db_path)


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
    assert contract["schema_contract_version"] == 7
    assert contract["writable_schema_version"] == 7
    assert contract["readable_schema_versions"] == [1, 2, 3, 4, 5, 6, 7]
    assert len(contract["contract_digest"]) == 64
    assert contract["build_id"]
    assert contract["build_commit"]


def test_version_five_image_rejects_completed_version_six(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app import schema_compatibility

    db_path = tmp_path / "analyzer.db"
    attempt = begin_schema_migration(db_path)
    complete_schema_migration(db_path, attempt)

    monkeypatch.setattr(schema_compatibility, "SCHEMA_CONTRACT_VERSION", 5)
    monkeypatch.setattr(schema_compatibility, "WRITABLE_SCHEMA_VERSION", 5)
    monkeypatch.setattr(schema_compatibility, "READABLE_SCHEMA_VERSIONS", (1, 2, 3, 4, 5))
    monkeypatch.setattr(schema_compatibility, "MIGRATION_PLAN", MIGRATION_PLAN[:5])
    monkeypatch.setattr(
        schema_compatibility, "MIGRATION_ID", MISSION_ENVIRONMENT_MIGRATION_ID
    )

    with pytest.raises(SchemaCompatibilityError, match="newer"):
        schema_compatibility.begin_schema_migration(db_path)


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
