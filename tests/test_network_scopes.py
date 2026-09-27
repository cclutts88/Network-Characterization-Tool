from concurrent.futures import ThreadPoolExecutor
import sqlite3
import threading

import pytest

from app.database import connect_database
from app.network_scopes import (
    NetworkScopeConflict,
    archive_network_scope,
    create_network_scope,
    get_network_scope,
    init_network_scope_storage,
    list_network_scope_history,
    list_network_scopes,
    update_network_scope,
)


def create(db, label="Mission network"):
    return create_network_scope(db, label=label, description="Initial context",
                                created_by="alice")


def test_scope_identity_lifecycle_audit_and_archived_label_reuse(tmp_path):
    db = tmp_path / "nct.db"
    original = create(db)
    assert original["scope_id"].startswith("scope_")
    assert "Mission" not in original["scope_id"]
    assert original["version"] == 1 and original["active"] is True
    assert list_network_scopes(db) == [original]

    updated = update_network_scope(
        db, original["scope_id"], expected_version=1, updated_by="bob",
        reason="Use the approved mission label", label="Range enclave",
        description="Updated context",
    )
    assert updated["scope_id"] == original["scope_id"]
    assert updated["version"] == 2 and updated["label"] == "Range enclave"
    archived = archive_network_scope(
        db, original["scope_id"], expected_version=2, archived_by="bob",
        reason="Mission ended",
    )
    assert archived["scope_id"] == original["scope_id"]
    assert archived["version"] == 3 and archived["active"] is False
    assert list_network_scopes(db) == []
    assert list_network_scopes(db, include_archived=True) == [archived]
    replacement = create_network_scope(db, label="Range enclave", created_by="carol")
    assert replacement["scope_id"] != original["scope_id"]

    history = list_network_scope_history(db, original["scope_id"])
    assert [item["event"] for item in history] == ["created", "updated", "archived"]
    assert [(item["previous_version"], item["new_version"]) for item in history] == [
        (None, 1), (1, 2), (2, 3)]
    assert history[1]["before"]["label"] == "Mission network"
    assert history[1]["after"]["label"] == "Range enclave"
    assert history[2]["reason"] == "Mission ended"


@pytest.mark.parametrize("first,duplicate", [
    ("Straße", "STRASSE"),
    ("Kelvin K", "Kelvin K"),
])
def test_active_labels_use_unicode_normalized_casefold_keys(tmp_path, first, duplicate):
    db = tmp_path / "nct.db"
    create(db, first)
    with pytest.raises(ValueError, match="already uses this label"):
        create(db, duplicate)


def test_competing_updates_produce_one_version_and_one_audit_event(tmp_path):
    db = tmp_path / "nct.db"
    item = create(db)
    start = threading.Barrier(2)
    def attempt(label):
        start.wait(timeout=5)
        try:
            return update_network_scope(
                db, item["scope_id"], expected_version=1, updated_by="analyst",
                reason="Concurrent rename test", label=label,
            )["version"]
        except NetworkScopeConflict:
            return "conflict"
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(attempt, ["First name", "Second name"]))
    assert sorted(results, key=str) == [2, "conflict"]
    assert get_network_scope(db, item["scope_id"])["version"] == 2
    assert [event["event"] for event in list_network_scope_history(db, item["scope_id"])] == [
        "created", "updated"]


@pytest.mark.parametrize("action", ["update", "archive"])
def test_audit_failure_rolls_back_scope_mutation(tmp_path, action):
    db = tmp_path / "nct.db"
    item = create(db)
    with connect_database(db) as connection:
        connection.execute(
            """CREATE TRIGGER reject_scope_audit BEFORE INSERT ON network_scope_audit
               BEGIN SELECT RAISE(ABORT, 'simulated audit failure'); END""")
    with pytest.raises(sqlite3.IntegrityError, match="simulated audit failure"):
        if action == "update":
            update_network_scope(
                db, item["scope_id"], expected_version=1, updated_by="bob",
                reason="Test rollback", label="Changed",
            )
        else:
            archive_network_scope(
                db, item["scope_id"], expected_version=1, archived_by="bob",
                reason="Test rollback",
            )
    retained = get_network_scope(db, item["scope_id"])
    assert retained["version"] == 1 and retained["active"] is True
    assert retained["label"] == "Mission network"
    assert len(list_network_scope_history(db, item["scope_id"])) == 1


def test_scope_and_audit_records_cannot_be_deleted_or_rewritten(tmp_path):
    db = tmp_path / "nct.db"
    item = create(db)
    audit_id = list_network_scope_history(db, item["scope_id"])[0]["audit_id"]
    with connect_database(db) as connection:
        with pytest.raises(sqlite3.IntegrityError, match="cannot be deleted"):
            connection.execute("DELETE FROM network_scopes WHERE scope_id = ?", (item["scope_id"],))
        with pytest.raises(sqlite3.IntegrityError, match="audit is immutable"):
            connection.execute("UPDATE network_scope_audit SET reason = 'changed' WHERE audit_id = ?", (audit_id,))
        with pytest.raises(sqlite3.IntegrityError, match="audit is immutable"):
            connection.execute("DELETE FROM network_scope_audit WHERE audit_id = ?", (audit_id,))
        with pytest.raises(sqlite3.IntegrityError, match="identity is immutable"):
            connection.execute("UPDATE network_scopes SET scope_id = 'changed' WHERE scope_id = ?", (item["scope_id"],))


def test_legacy_scope_backfill_is_inactive_exact_idempotent_and_non_destructive(tmp_path):
    db = tmp_path / "nct.db"
    with connect_database(db) as connection:
        connection.executescript("""
            CREATE TABLE endpoint_entities (
                entity_id TEXT PRIMARY KEY, scope_id TEXT NOT NULL, address TEXT NOT NULL
            );
            CREATE TABLE entity_assessments (
                assessment_id TEXT PRIMARY KEY, scope_id TEXT NOT NULL
            );
            CREATE TABLE service_entities (
                entity_id TEXT PRIMARY KEY, host_id TEXT NOT NULL,
                protocol TEXT NOT NULL, port INTEGER NOT NULL
            );
            CREATE TABLE endpoint_receipts (
                assessment_id TEXT NOT NULL, host_id TEXT NOT NULL, facts_json TEXT NOT NULL
            );
            CREATE TABLE service_receipts (
                assessment_id TEXT NOT NULL, service_id TEXT NOT NULL, facts_json TEXT NOT NULL
            );
            INSERT INTO endpoint_entities VALUES ('host-1', 'legacy/context:A', '192.0.2.1');
            INSERT INTO entity_assessments VALUES ('assessment-1', 'legacy/context:B');
            INSERT INTO service_entities VALUES ('service-1', 'host-1', 'tcp', 443);
            INSERT INTO endpoint_receipts VALUES ('assessment-1', 'host-1', '{}');
            INSERT INTO service_receipts VALUES ('assessment-1', 'service-1', '{}');
        """)
    init_network_scope_storage(db)
    init_network_scope_storage.__wrapped__(db)
    scopes = list_network_scopes(db, include_archived=True)
    assert [item["scope_id"] for item in scopes] == ["legacy/context:A", "legacy/context:B"]
    assert all(item["active"] is False and item["legacy"] is True for item in scopes)
    assert [len(list_network_scope_history(db, item["scope_id"])) for item in scopes] == [1, 1]
    with connect_database(db) as connection:
        assert connection.execute("SELECT * FROM endpoint_entities").fetchall() == [
            ("host-1", "legacy/context:A", "192.0.2.1")]
        assert connection.execute("SELECT * FROM entity_assessments").fetchall() == [
            ("assessment-1", "legacy/context:B")]
        assert connection.execute("SELECT * FROM service_entities").fetchall() == [
            ("service-1", "host-1", "tcp", 443)]
        assert connection.execute("SELECT * FROM endpoint_receipts").fetchall() == [
            ("assessment-1", "host-1", "{}")]
        assert connection.execute("SELECT * FROM service_receipts").fetchall() == [
            ("assessment-1", "service-1", "{}")]


def test_scope_storage_initializes_after_database_replacement(tmp_path):
    db = tmp_path / "nct.db"
    init_network_scope_storage(db)
    replacement = tmp_path / "replacement.db"
    with connect_database(replacement) as connection:
        connection.execute("CREATE TABLE replacement_marker (value TEXT)")
    replacement.replace(db)
    item = create(db, "Replacement database")
    assert get_network_scope(db, item["scope_id"])["label"] == "Replacement database"
