import json
from pathlib import Path
import sqlite3
import importlib.util

import pytest
import app.schema_compatibility as schema
from app.database import connect_database
from app.scan_history_index import init_scan_history_index_storage


def source_v7(tmp_path):
    path = tmp_path / "analyzer.db"
    with sqlite3.connect(path) as db:
        db.executescript((Path(__file__).parent / "fixtures/phase5_r1_schema.sql").read_text())
        fingerprint = schema.schema_fingerprint(db)
        for version, identity in enumerate(schema.MIGRATION_PLAN[:7], 1):
            db.execute("INSERT INTO nct_schema_migrations VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", (identity, version, "0.16.0-range-test-20261025-phase5-r1", "be92fb78e938adc3fced581629d4609ac0a43f6a", "completed", 1, "fixture", "fixture", "fixture", fingerprint, fingerprint, None))
        db.execute("INSERT INTO nct_schema_state VALUES (1,7,7,?,?,?,?,?,?)", (schema.DATA_LAYOUT_CONTRACT, schema.migration_plan_digest(schema.MIGRATION_PLAN[:7]), fingerprint, "0.16.0-range-test-20261025-phase5-r1", "be92fb78e938adc3fced581629d4609ac0a43f6a", "fixture"))
        db.execute("INSERT INTO scan_runs VALUES (?,?,?,?,?,?,?,?,?)", ("a" * 32, "fixture", "completed", "analyst", "retained", "host", "eth0", "profile", json.dumps({"run_id": "a" * 32, "status": "completed", "created_at": "fixture", "targets": ["192.0.2.0/24"]})))
    return path


def test_seven_to_eight_preserves_previous_receipts_and_survives_repeated_start(tmp_path):
    path = source_v7(tmp_path)
    with connect_database(path, read_only=True) as db:
        before = schema._history_prior_ledger(db)
    attempt = schema.begin_schema_migration(path)
    assert attempt.target_schema_version == 8
    init_scan_history_index_storage(path)
    schema.complete_schema_migration(path, attempt)
    assert schema.begin_schema_migration(path) is None
    assert schema.schema_state(path)["schema_version"] == 8
    assert schema.schema_state(path)["schema_fingerprint_matches"]
    with connect_database(path, read_only=True) as db:
        assert schema._history_prior_ledger(db) == before
        assert db.execute("SELECT count(*) FROM scan_runs").fetchone()[0] == 1
    # A real second startup initializer must not alter the sealed schema again.
    init_scan_history_index_storage.__wrapped__(path)
    assert schema.begin_schema_migration(path) is None


@pytest.mark.parametrize("after_rules", [False, True])
def test_owned_history_migration_can_resume_before_or_after_atomic_rules(tmp_path, after_rules):
    path = source_v7(tmp_path)
    first = schema.begin_schema_migration(path)
    if after_rules:
        init_scan_history_index_storage(path)
    schema.fail_schema_migration(path, first, RuntimeError("simulated stop"))
    retry = schema.begin_schema_migration(path)
    assert retry.attempt == 2
    init_scan_history_index_storage(path)
    schema.complete_schema_migration(path, retry)
    assert schema.begin_schema_migration(path) is None


def test_unowned_old_seal_drift_never_creates_migration_intent(tmp_path):
    path = source_v7(tmp_path)
    init_scan_history_index_storage(path)
    with pytest.raises(schema.SchemaCompatibilityError, match="fingerprint"):
        schema.begin_schema_migration(path)
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT count(*) FROM sqlite_master WHERE name='nct_schema_migration_intents'").fetchone()[0] == 0


@pytest.mark.parametrize("damage", ["unrelated", "rules", "prior_receipt", "intent_pair"])
def test_retry_refuses_anything_outside_exact_owned_source_or_target(tmp_path, damage):
    path = source_v7(tmp_path)
    schema.begin_schema_migration(path)
    with sqlite3.connect(path) as db:
        if damage == "unrelated":
            db.execute("CREATE TABLE unrelated(id)")
        elif damage == "rules":
            db.executescript("DROP TRIGGER scan_history_membership_group_insert; CREATE TRIGGER scan_history_membership_group_insert AFTER INSERT ON scan_history_memberships BEGIN SELECT 1; END;")
        elif damage == "intent_pair":
            intent = json.loads(db.execute("SELECT source_history_json FROM nct_schema_migration_intents").fetchone()[0])
            intent["scan_history_membership_group_insert"] = "CREATE TRIGGER scan_history_membership_group_insert AFTER INSERT ON scan_history_memberships BEGIN SELECT 1; END"
            db.executescript("DROP TRIGGER scan_history_membership_group_insert; " + intent["scan_history_membership_group_insert"])
            db.execute("UPDATE nct_schema_migration_intents SET source_history_json=?", (json.dumps(intent),))
        else:
            db.execute("UPDATE nct_schema_migrations SET attempts=2 WHERE target_schema_version=3")
    with pytest.raises(schema.SchemaCompatibilityError):
        schema.begin_schema_migration(path)


def test_fresh_eight_bootstrap_retries_without_rewriting_completed_history_receipt(tmp_path):
    path = tmp_path / "fresh.db"
    first = schema.begin_schema_migration(path)
    schema.fail_schema_migration(path, first, RuntimeError("simulated bootstrap stop"))
    second = schema.begin_schema_migration(path)
    assert second.target_schema_version == 8 and second.attempt == 2
    from app.poc import init_poc_storage
    init_poc_storage(path)
    schema.complete_schema_migration(path, second)
    assert schema.begin_schema_migration(path) is None


def test_fresh_eight_cannot_seal_missing_target_history_rules(tmp_path):
    path = tmp_path / "fresh.db"
    attempt = schema.begin_schema_migration(path)
    with pytest.raises(schema.SchemaCompatibilityError, match="history rules"):
        schema.complete_schema_migration(path, attempt)
    assert schema.schema_state(path)["schema_version"] == 0


def test_atomic_rule_replacement_rolls_back_all_drops_on_failure(tmp_path, monkeypatch):
    import app.scan_history_index as history
    path = source_v7(tmp_path)
    schema.begin_schema_migration(path)
    with connect_database(path, read_only=True) as db:
        before = schema.schema_fingerprint(db)
    original = history.connect_database
    def refusing(*args, **kwargs):
        db = original(*args, **kwargs)
        db.set_authorizer(lambda action, *_: sqlite3.SQLITE_DENY if action == sqlite3.SQLITE_CREATE_TRIGGER else sqlite3.SQLITE_OK)
        return db
    with monkeypatch.context() as patch:
        patch.setattr(history, "connect_database", refusing)
        with pytest.raises(sqlite3.DatabaseError):
            history.init_scan_history_index_storage(path)
    with connect_database(path, read_only=True) as db:
        assert schema.schema_fingerprint(db) == before
    retry = schema.begin_schema_migration(path)
    history.init_scan_history_index_storage(path)
    schema.complete_schema_migration(path, retry)
    assert schema.begin_schema_migration(path) is None


def test_full_package_preflight_completes_eight_on_copy_only(tmp_path):
    path = source_v7(tmp_path)
    spec = importlib.util.spec_from_file_location("package_history_gate", Path(__file__).parents[1] / "scripts/nct-package-schema-preflight.py")
    gate = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gate)
    before = gate.digest(path)
    result = gate.audit(path, *gate.PHASE5)
    assert result["status"] == "pass"
    assert gate.digest(path) == before
    assert schema.schema_state(path)["schema_version"] == 7


def test_six_requires_the_separately_qualified_phase_five_bridge(tmp_path):
    path = source_v7(tmp_path)
    with sqlite3.connect(path) as db:
        db.execute("UPDATE nct_schema_state SET schema_version=6,schema_contract_version=6")
    with pytest.raises(schema.SchemaCompatibilityError, match="Phase 5 R1 bridge"):
        schema.begin_schema_migration(path)
