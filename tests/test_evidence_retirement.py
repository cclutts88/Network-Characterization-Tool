from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import shutil
import sqlite3

import pytest

from app.database import connect_database
import app.evidence_retirement as retirement
from app.evidence_retirement import (
    EvidenceAlreadyRetired,
    EvidenceDependency,
    EvidenceRetirementAdapter,
    EvidenceRetirementBlocked,
    EvidenceRetirementError,
    RetiredEvidenceDependency,
    init_evidence_retirement_storage,
    is_evidence_retired,
    publish_with_active_dependencies,
    require_active_dependencies,
    retire_evidence,
    retirement_cache_token,
)
from app.poc import init_poc_storage
import app.schema_compatibility as schema


def _adapter(*, blocked: str | None = None) -> EvidenceRetirementAdapter:
    def identities(db, encounter_id):
        row = db.execute(
            "SELECT observation_id FROM source_encounters WHERE encounter_id=?",
            (encounter_id,),
        ).fetchone()
        if row is None:
            raise EvidenceRetirementError("source encounter does not exist")
        return {"encounter_id": encounter_id, "observation_id": row[0]}

    return EvidenceRetirementAdapter(
        resolve_identities=identities,
        active_work_detail=lambda _db, _encounter_id: blocked,
    )


def _foundation_db(tmp_path: Path) -> Path:
    path = tmp_path / "retirement.db"
    with connect_database(path) as db:
        db.execute(
            "CREATE TABLE source_encounters("
            "encounter_id TEXT PRIMARY KEY,observation_id TEXT UNIQUE,sha256 TEXT)"
        )
        db.executemany(
            "INSERT INTO source_encounters VALUES (?,?,?)",
            [
                ("encounter-a", "observation-a", "same-content"),
                ("encounter-b", "observation-b", "same-content"),
            ],
        )
    init_evidence_retirement_storage(path)
    return path


def _source_v8(tmp_path: Path) -> Path:
    path = tmp_path / "source-v8.db"
    with sqlite3.connect(path) as db:
        db.executescript(
            (Path(__file__).parent / "fixtures/phase5_r1_schema.sql").read_text()
        )
        v7_fingerprint = schema.schema_fingerprint(db)
        for version, identity in enumerate(schema.MIGRATION_PLAN[:7], 1):
            db.execute(
                "INSERT INTO nct_schema_migrations VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    identity, version, "v8-fixture", "fixture", "completed", 1,
                    "fixture", "fixture", "fixture", v7_fingerprint,
                    v7_fingerprint, None,
                ),
            )
        db.execute(schema.HISTORY_INTENT_DDL)
        db.execute(
            "INSERT INTO nct_schema_state VALUES (1,7,7,?,?,?,?,?,?)",
            (
                schema.DATA_LAYOUT_CONTRACT,
                schema.migration_plan_digest(schema.MIGRATION_PLAN[:7]),
                v7_fingerprint, "v8-fixture", "fixture", "fixture",
            ),
        )
    from app.scan_history_index import init_scan_history_index_storage
    init_scan_history_index_storage.__wrapped__(path)
    with sqlite3.connect(path) as db:
        v8_fingerprint = schema.schema_fingerprint(db)
        db.execute(
            "INSERT INTO nct_schema_migrations VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                schema.HISTORY_RULES_MIGRATION_ID, 8, "v8-fixture", "fixture",
                "completed", 1, "fixture", "fixture", "fixture",
                v7_fingerprint, v8_fingerprint, None,
            ),
        )
        db.execute(
            """UPDATE nct_schema_state
                  SET schema_contract_version=8,schema_version=8,
                      migration_plan_digest=?,schema_fingerprint=?""",
            (
                schema.migration_plan_digest(schema.MIGRATION_PLAN[:8]),
                v8_fingerprint,
            ),
        )
    return path


def test_retirement_is_encounter_specific_and_immutable(tmp_path):
    path = _foundation_db(tmp_path)
    event = retire_evidence(
        path, source_family="nmap_import", encounter_id="encounter-a",
        actor="analyst", reason="wrong network", adapter=_adapter(),
    )
    assert event["revision"] == 1
    with connect_database(path) as db:
        assert is_evidence_retired(
            db, source_family="nmap_import", encounter_id="encounter-a",
        )
        assert not is_evidence_retired(
            db, source_family="nmap_import", encounter_id="encounter-b",
        )
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            db.execute("UPDATE evidence_retirement_events SET reason='changed'")
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            db.execute("DELETE FROM evidence_retirement_identities")
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            db.execute("UPDATE evidence_retirement_lineage SET lineage_id='changed'")


def test_sealed_receipt_refuses_replace_extra_alias_and_alias_takeover(tmp_path):
    path = _foundation_db(tmp_path)
    event = retire_evidence(
        path, source_family="nmap_import", encounter_id="encounter-a",
        actor="analyst", reason="wrong network", adapter=_adapter(),
    )
    with connect_database(path) as db:
        lineage_id = db.execute(
            "SELECT lineage_id FROM evidence_retirement_lineage WHERE singleton=1"
        ).fetchone()[0]
        assert db.execute(
            "SELECT sealed,identity_count FROM evidence_retirement_events "
            "WHERE revision=?",
            (event["revision"],),
        ).fetchone() == (1, 2)
        with pytest.raises(sqlite3.IntegrityError, match="lineage conflicts"):
            db.execute(
                """INSERT OR REPLACE INTO evidence_retirement_lineage
                   SELECT singleton,lineage_id,'replacement'
                     FROM evidence_retirement_lineage WHERE singleton=1"""
            )
        with pytest.raises(sqlite3.IntegrityError, match="event conflicts"):
            db.execute(
                """INSERT OR REPLACE INTO evidence_retirement_events
                   SELECT revision,event_id,lineage_id,source_family,encounter_id,
                          identity_snapshot_json,identity_snapshot_sha256,
                          previous_event_digest,event_digest,identity_count,sealed,
                          'replacement',reason,retired_at
                     FROM evidence_retirement_events WHERE revision=?""",
                (event["revision"],),
            )
        with pytest.raises(sqlite3.IntegrityError, match="retirement identity"):
            db.execute(
                """INSERT OR REPLACE INTO evidence_retirement_identities(
                       revision,source_family,encounter_id,
                       identity_namespace,identity_value
                   )
                   SELECT revision,source_family,encounter_id,
                          identity_namespace,identity_value
                     FROM evidence_retirement_identities
                    WHERE revision=? LIMIT 1""",
                (event["revision"],),
            )
        with pytest.raises(sqlite3.IntegrityError, match="unsealed event snapshot"):
            db.execute(
                "INSERT INTO evidence_retirement_identities VALUES (?,?,?,?,?)",
                (
                    event["revision"], "nmap_import", "encounter-a",
                    "fabricated_alias", "fabricated-value",
                ),
            )
        fake_identities, fake_snapshot, fake_snapshot_sha = retirement._identity_snapshot(
            "nmap_import",
            "encounter-c",
            {
                "encounter_id": "encounter-c",
                "observation_id": "observation-a",
            },
        )
        with pytest.raises(sqlite3.IntegrityError, match="pre-sealed"):
            db.execute(
                """INSERT INTO evidence_retirement_events(
                       event_id,lineage_id,source_family,encounter_id,
                       identity_snapshot_json,identity_snapshot_sha256,
                       previous_event_digest,event_digest,identity_count,sealed,
                       actor,reason,retired_at
                   ) VALUES (?,?,?,?,?,?,?,?,?,1,?,?,?)""",
                (
                    "direct-sealed", lineage_id, "nmap_import", "encounter-c",
                    fake_snapshot, fake_snapshot_sha, event["event_digest"],
                    "direct-sealed-digest", len(fake_identities), "analyst",
                    "forged", event["retired_at"],
                ),
            )
        cursor = db.execute(
            """INSERT INTO evidence_retirement_events(
                   event_id,lineage_id,source_family,encounter_id,
                   identity_snapshot_json,identity_snapshot_sha256,
                   previous_event_digest,event_digest,identity_count,sealed,
                   actor,reason,retired_at
               ) VALUES (?,?,?,?,?,?,?,?,?,0,?,?,?)""",
            (
                "alias-takeover", lineage_id, "nmap_import", "encounter-c",
                fake_snapshot, fake_snapshot_sha, event["event_digest"],
                "alias-takeover-digest", len(fake_identities), "analyst",
                "forged", event["retired_at"],
            ),
        )
        fake_revision = int(cursor.lastrowid)
        db.execute(
            "INSERT INTO evidence_retirement_identities VALUES (?,?,?,?,?)",
            (
                fake_revision, "nmap_import", "encounter-c",
                "encounter_id", "encounter-c",
            ),
        )
        with pytest.raises(sqlite3.IntegrityError, match="identity conflicts"):
            db.execute(
                "INSERT OR REPLACE INTO evidence_retirement_identities "
                "VALUES (?,?,?,?,?)",
                (
                    fake_revision, "nmap_import", "encounter-c",
                    "observation_id", "observation-a",
                ),
            )
        db.rollback()


def test_mid_ddl_interruption_rolls_back_and_v8_migration_retries(
    tmp_path, monkeypatch,
):
    path = _source_v8(tmp_path)
    attempt = schema.begin_schema_migration(path)
    original_connect = retirement.connect_database

    def interrupted_connect(*args, **kwargs):
        db = original_connect(*args, **kwargs)
        creates = 0

        def authorizer(action, *_):
            nonlocal creates
            if action == sqlite3.SQLITE_CREATE_TABLE:
                creates += 1
                if creates == 2:
                    return sqlite3.SQLITE_DENY
            return sqlite3.SQLITE_OK

        db.set_authorizer(authorizer)
        return db

    with monkeypatch.context() as patch:
        patch.setattr(retirement, "connect_database", interrupted_connect)
        with pytest.raises(sqlite3.DatabaseError):
            init_evidence_retirement_storage.__wrapped__(path)
    with sqlite3.connect(path) as db:
        present = {
            row[0] for row in db.execute(
                "SELECT name FROM sqlite_master WHERE name LIKE "
                "'evidence_retirement_%'"
            )
        }
    assert present == set()
    schema.fail_schema_migration(path, attempt, RuntimeError("interrupted DDL"))
    retry = schema.begin_schema_migration(path)
    assert retry.attempt == 2
    init_evidence_retirement_storage(path)
    schema.complete_schema_migration(path, retry)
    assert schema.begin_schema_migration(path) is None


def test_content_hash_can_never_be_a_retirement_identity(tmp_path):
    path = _foundation_db(tmp_path)
    adapter = EvidenceRetirementAdapter(
        resolve_identities=lambda _db, encounter_id: {
            "encounter_id": encounter_id, "sha256": "same-content",
        },
        active_work_detail=lambda _db, _encounter_id: None,
    )
    with pytest.raises(EvidenceRetirementError, match="content hashes"):
        retire_evidence(
            path, source_family="nmap_import", encounter_id="encounter-a",
            actor="analyst", reason="wrong", adapter=adapter,
        )


def test_active_work_refusal_and_dependency_guard(tmp_path):
    path = _foundation_db(tmp_path)
    with pytest.raises(EvidenceRetirementBlocked, match="worker owns encounter"):
        retire_evidence(
            path, source_family="nmap_import", encounter_id="encounter-a",
            actor="analyst", reason="wrong", adapter=_adapter(
                blocked="worker owns encounter",
            ),
        )
    with connect_database(path, read_only=True) as db:
        assert db.execute(
            "SELECT count(*) FROM evidence_retirement_events"
        ).fetchone()[0] == 0
    retire_evidence(
        path, source_family="nmap_import", encounter_id="encounter-a",
        actor="analyst", reason="wrong", adapter=_adapter(),
    )
    with connect_database(path) as db:
        with pytest.raises(RetiredEvidenceDependency, match="revision 1"):
            require_active_dependencies(db, [EvidenceDependency(
                "nmap_import", "observation_id", "observation-a",
            )])
        require_active_dependencies(db, [EvidenceDependency(
            "nmap_import", "observation_id", "observation-b",
        )])


def test_publish_refuses_a_dependency_retired_while_work_was_running(tmp_path):
    path = _foundation_db(tmp_path)
    with connect_database(path) as db:
        db.execute("CREATE TABLE published_results(result_id TEXT PRIMARY KEY)")
    # The calculation began earlier; retirement wins before its publish transaction.
    retire_evidence(
        path, source_family="nmap_import", encounter_id="encounter-a",
        actor="analyst", reason="wrong", adapter=_adapter(),
    )
    dependency = EvidenceDependency(
        "nmap_import", "observation_id", "observation-a",
    )
    with pytest.raises(RetiredEvidenceDependency):
        publish_with_active_dependencies(
            path, [dependency],
            lambda db: db.execute(
                "INSERT INTO published_results VALUES ('stale')"
            ),
        )
    publish_with_active_dependencies(
        path,
        [EvidenceDependency("nmap_import", "observation_id", "observation-b")],
        lambda db: db.execute("INSERT INTO published_results VALUES ('active')"),
    )
    with connect_database(path, read_only=True) as db:
        assert db.execute("SELECT result_id FROM published_results").fetchall() == [
            ("active",),
        ]


def test_concurrent_duplicate_retirement_creates_one_event(tmp_path):
    path = _foundation_db(tmp_path)

    def run():
        try:
            return retire_evidence(
                path, source_family="nmap_import", encounter_id="encounter-a",
                actor="analyst", reason="wrong", adapter=_adapter(),
            )["revision"]
        except EvidenceAlreadyRetired:
            return "already"

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(lambda _: run(), range(2)))
    assert sorted(outcomes, key=str) == [1, "already"]
    with connect_database(path, read_only=True) as db:
        assert db.execute(
            "SELECT count(*) FROM evidence_retirement_events"
        ).fetchone()[0] == 1


def test_restore_branch_cannot_reuse_same_cache_token(tmp_path):
    path = _foundation_db(tmp_path)
    backup = tmp_path / "backup.db"
    with connect_database(path) as source, sqlite3.connect(backup) as target:
        source.backup(target)
    retire_evidence(
        path, source_family="nmap_import", encounter_id="encounter-a",
        actor="analyst", reason="branch a", adapter=_adapter(),
    )
    token_a = retirement_cache_token(path)
    restored = tmp_path / "restored.db"
    shutil.copy2(backup, restored)
    retire_evidence(
        restored, source_family="nmap_import", encounter_id="encounter-b",
        actor="analyst", reason="branch b", adapter=_adapter(),
    )
    token_b = retirement_cache_token(restored)
    assert token_a.split(":", 2)[:2] == token_b.split(":", 2)[:2]
    assert token_a != token_b


def test_v8_to_v9_migration_retries_and_cold_restore_is_exact(tmp_path):
    path = _source_v8(tmp_path)
    attempt = schema.begin_schema_migration(path)
    assert attempt.target_schema_version == 9
    init_evidence_retirement_storage(path)
    schema.fail_schema_migration(path, attempt, RuntimeError("simulated stop"))
    retry = schema.begin_schema_migration(path)
    assert retry.attempt == 2
    schema.complete_schema_migration(path, retry)
    assert schema.begin_schema_migration(path) is None
    assert schema.schema_state(path)["schema_version"] == 9
    restored = tmp_path / "restored-v9.db"
    shutil.copy2(path, restored)
    assert schema.begin_schema_migration(restored) is None


def test_v8_schema_drift_is_refused_before_migration(tmp_path):
    path = _source_v8(tmp_path)
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE unrelated(id)")
    with pytest.raises(schema.SchemaCompatibilityError, match="fingerprint"):
        schema.begin_schema_migration(path)


def test_fresh_v9_bootstrap_seals_retirement_and_history(tmp_path):
    path = tmp_path / "fresh-v9.db"
    attempt = schema.begin_schema_migration(path)
    init_poc_storage(path)
    schema.complete_schema_migration(path, attempt)
    assert schema.begin_schema_migration(path) is None
    state = schema.schema_state(path)
    assert state["schema_version"] == 9
    assert state["schema_fingerprint_matches"]
