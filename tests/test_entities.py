from concurrent.futures import ThreadPoolExecutor
import sqlite3
import threading

import pytest

from app.artifacts import register_artifact_bytes
from app.database import connect_database
from app.entities import init_entity_storage, record_assessment
from app.network_scopes import archive_network_scope, create_network_scope


def artifact(db):
    return register_artifact_bytes(db_path=db, content=b"retained source", source_kind="test",
                                   source_ref="run-1")["observation_id"]


def host(address="192.0.2.1", state="open"):
    return {"address": address, "facts": {"presence": "assumed"}, "services": [
        {"protocol": "TCP", "port": 53, "facts": {"state": state}},
        {"protocol": "udp", "port": 53, "facts": {"state": "open|filtered"}},
    ]}


def scope(db, label="Test network"):
    return create_network_scope(db, label=label, created_by="tester")["scope_id"]


def record(db, observation, scope_id, **kwargs):
    return record_assessment(db, **dict(scope_id=scope_id, artifact_observation_id=observation,
                                        parser_version="fixture:1", assessed_at=None,
                                        hosts=[host()], **kwargs))


def counts(db):
    with connect_database(db) as connection:
        return tuple(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                     for table in ("endpoint_entities", "service_entities", "entity_assessments",
                                   "endpoint_receipts", "service_receipts"))


def test_scope_protocol_and_replay_identity(tmp_path):
    db = tmp_path / "nct.db"
    observation = artifact(db)
    first_scope, second_scope = scope(db, "First"), scope(db, "Second")
    first = record(db, observation, first_scope)
    assert record(db, observation, first_scope) == first
    record_assessment(db, scope_id=second_scope, artifact_observation_id=observation,
                      parser_version="fixture:1", assessed_at=None, hosts=[host()])
    assert counts(db) == (2, 4, 2, 2, 4)
    with connect_database(db) as connection:
        states = connection.execute("SELECT facts_json FROM service_receipts").fetchall()
        assert ('{"state":"open|filtered"}',) in states
        assert connection.execute("SELECT DISTINCT facts_json FROM endpoint_receipts").fetchall() == [
            ('{"presence":"assumed"}',)]


def test_receipts_survive_older_empty_and_reprocessed_evidence(tmp_path):
    db = tmp_path / "nct.db"
    observation = artifact(db)
    scope_id = scope(db)
    record_assessment(db, scope_id=scope_id, artifact_observation_id=observation,
                      parser_version="fixture:1", assessed_at="2026-09-20T10:00:00-05:00",
                      time_basis="fixture source timestamp", hosts=[host()])
    second = artifact(db)
    record_assessment(db, scope_id=scope_id, artifact_observation_id=second,
                      parser_version="fixture:1", assessed_at="2020-01-01T00:00:00Z",
                      time_basis="fixture source timestamp", hosts=[])
    record_assessment(db, scope_id=scope_id, artifact_observation_id=observation,
                      parser_version="fixture:2", assessed_at=None, hosts=[host(state="closed")])
    assert counts(db) == (1, 2, 3, 2, 4)
    with connect_database(db) as connection:
        assert connection.execute("SELECT assessed_at FROM entity_assessments ORDER BY rowid").fetchall() == [
            ("2026-09-20T15:00:00+00:00",), ("2020-01-01T00:00:00+00:00",), (None,)]
        assert connection.execute("SELECT COUNT(*) FROM entity_assessments a JOIN artifact_observations o "
                                  "ON o.observation_id=a.artifact_observation_id").fetchone()[0] == 3
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("DELETE FROM artifact_observations WHERE observation_id=?", (observation,))


def test_conflicting_replay_and_missing_source_leave_no_partial_data(tmp_path):
    db = tmp_path / "nct.db"
    observation = artifact(db)
    scope_id = scope(db)
    record(db, observation, scope_id)
    for source, expected in ((observation, ValueError), ("missing", sqlite3.IntegrityError)):
        with pytest.raises(expected):
            record_assessment(db, scope_id=scope_id, artifact_observation_id=source,
                              parser_version="fixture:1", assessed_at=None, hosts=[host("192.0.2.2")])
    assert counts(db) == (1, 2, 1, 1, 2)


def test_concurrent_replay_is_one_assessment(tmp_path):
    db = tmp_path / "nct.db"
    observation = artifact(db)
    scope_id = scope(db)
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: record(db, observation, scope_id), range(16)))
    assert len(set(results)) == 1
    assert counts(db) == (1, 2, 1, 1, 2)


def test_write_failure_rolls_back_entire_assessment(tmp_path):
    db = tmp_path / "nct.db"
    observation = artifact(db)
    first_scope, second_scope = scope(db, "First"), scope(db, "Second")
    record(db, observation, first_scope)
    second = artifact(db)
    with connect_database(db) as connection:
        connection.execute("CREATE TRIGGER reject_service BEFORE INSERT ON service_receipts "
                           "BEGIN SELECT RAISE(ABORT, 'test failure'); END")
    with pytest.raises(sqlite3.IntegrityError, match="test failure"):
        record_assessment(db, scope_id=second_scope, artifact_observation_id=second,
                          parser_version="fixture:1", assessed_at=None, hosts=[host("192.0.2.2")])
    assert counts(db) == (1, 2, 1, 1, 2)


def test_replaced_database_initializes_registry_dependency(tmp_path):
    db = tmp_path / "nct.db"
    init_entity_storage(db)
    replacement = tmp_path / "replacement.db"
    with connect_database(replacement) as connection:
        connection.execute("CREATE TABLE replacement_marker (value TEXT)")
    replacement.replace(db)
    init_entity_storage(db)
    observation = artifact(db)
    scope_id = scope(db)
    record(db, observation, scope_id)
    assert counts(db) == (1, 2, 1, 1, 2)


def test_caller_mutation_after_snapshot_cannot_change_receipts(tmp_path, monkeypatch):
    import app.entities as entities
    db = tmp_path / "nct.db"
    observation = artifact(db)
    scope_id = scope(db)
    input_host = host()
    original = entities.init_entity_storage
    def mutate_after_snapshot(path):
        input_host["facts"]["presence"] = "changed"
        input_host["services"][0]["facts"]["state"] = "changed"
        original(path)
    monkeypatch.setattr(entities, "init_entity_storage", mutate_after_snapshot)
    record_assessment(db, scope_id=scope_id, artifact_observation_id=observation,
                      parser_version="fixture:1", assessed_at=None, hosts=[input_host])
    with connect_database(db) as connection:
        assert connection.execute("SELECT facts_json FROM endpoint_receipts").fetchone()[0] == '{"presence":"assumed"}'
        assert connection.execute("SELECT facts_json FROM service_receipts ORDER BY rowid").fetchone()[0] == '{"state":"open"}'


@pytest.mark.parametrize("change", [
    {"scope_id": " "}, {"assessed_at": "2026-01-01"},
    {"assessed_at": "2026-01-01T00:00:00Z"}, {"time_basis": "invented"},
    {"hosts": [host(), host()]}, {"hosts": [host("bad IP")]},
    {"hosts": [{"address": "192.0.2.1", "services": [{"protocol": "tcp", "port": True}]}]},
])
def test_invalid_input_does_not_publish(tmp_path, change):
    db = tmp_path / "nct.db"
    observation = artifact(db)
    scope_id = scope(db)
    arguments = dict(scope_id=scope_id, artifact_observation_id=observation,
                     parser_version="fixture:1", assessed_at=None, hosts=[host()])
    arguments.update(change)
    with pytest.raises(ValueError):
        record_assessment(db, **arguments)
    with connect_database(db) as connection:
        assert not connection.execute("SELECT name FROM sqlite_master WHERE name='entity_assessments'").fetchall()


def test_archived_scope_allows_identical_replay_but_no_new_assessment(tmp_path):
    db = tmp_path / "nct.db"
    observation = artifact(db)
    scope_id = scope(db)
    assessment_id = record(db, observation, scope_id)
    archive_network_scope(db, scope_id, expected_version=1, archived_by="tester",
                          reason="Retired test context")
    assert record(db, observation, scope_id) == assessment_id
    with pytest.raises(ValueError, match="archived"):
        record_assessment(db, scope_id=scope_id, artifact_observation_id=observation,
                          parser_version="fixture:2", assessed_at=None, hosts=[host()])
    second_observation = artifact(db)
    with pytest.raises(ValueError, match="archived"):
        record_assessment(db, scope_id=scope_id, artifact_observation_id=second_observation,
                          parser_version="fixture:1", assessed_at=None, hosts=[host()])
    assert counts(db) == (1, 2, 1, 1, 2)


def test_missing_scope_rejects_assessment_without_partial_entities(tmp_path):
    db = tmp_path / "nct.db"
    observation = artifact(db)
    with pytest.raises(ValueError, match="does not exist"):
        record_assessment(db, scope_id="scope_missing", artifact_observation_id=observation,
                          parser_version="fixture:1", assessed_at=None, hosts=[host()])
    assert counts(db) == (0, 0, 0, 0, 0)
    with connect_database(db) as connection:
        with pytest.raises(sqlite3.IntegrityError, match="missing or archived"):
            connection.execute(
                "INSERT INTO endpoint_entities VALUES ('direct-host', 'scope_missing', '192.0.2.2')"
            )


def test_concurrent_archive_and_assessment_serialize_without_partial_rows(tmp_path):
    db = tmp_path / "nct.db"
    observation = artifact(db)
    scope_id = scope(db)
    start = threading.Barrier(2)
    def assess():
        start.wait(timeout=5)
        try:
            record(db, observation, scope_id)
            return "recorded"
        except ValueError as exc:
            assert "archived" in str(exc)
            return "archived"
    def archive():
        start.wait(timeout=5)
        archive_network_scope(db, scope_id, expected_version=1, archived_by="tester",
                              reason="Concurrent archive test")
        return "archived"
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = [future.result() for future in (pool.submit(assess), pool.submit(archive))]
    assert "archived" in results
    retained = counts(db)
    assert retained in {(0, 0, 0, 0, 0), (1, 2, 1, 1, 2)}
    with connect_database(db) as connection:
        assert connection.execute(
            "SELECT active FROM network_scopes WHERE scope_id = ?", (scope_id,)
        ).fetchone() == (0,)
