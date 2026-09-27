from concurrent.futures import ThreadPoolExecutor
import sqlite3
import threading

import pytest

from app.artifacts import register_artifact_bytes
from app.database import connect_database
from app.entities import record_assessment
from app.evidence_scope_assignments import (
    EvidenceScopeConflict,
    assign_artifact_scope,
    correct_artifact_scope,
    init_evidence_scope_assignment_storage,
    list_artifact_scope_assignments,
)
from app.network_scopes import archive_network_scope, create_network_scope


def observation(db, *, content=b"evidence", source_ref="upload:one"):
    return register_artifact_bytes(
        db_path=db, content=content, source_kind="nmap_import",
        source_ref=source_ref, actor="tester",
        observed_at="2030-01-01T00:00:00+00:00",
    )


def scope(db, label):
    return create_network_scope(db, label=label, created_by="tester")


def assign(db, item, destination, *, actor="alice", reason="Confirmed lab context"):
    return assign_artifact_scope(
        db, artifact_observation_id=item["observation_id"],
        scope_id=destination["scope_id"], actor=actor, reason=reason,
        whole_artifact_confirmed=True,
    )


def test_assignment_is_observation_specific_and_does_not_ingest(tmp_path):
    db = tmp_path / "nct.db"
    first = observation(db, source_ref="upload:one")
    second = observation(db, source_ref="upload:two")
    assert first["sha256"] == second["sha256"]
    destination = scope(db, "Lab")

    first_assignment = assign(db, first, destination)
    second_assignment = assign(db, second, destination)
    assert first_assignment["artifact_observation_id"] != second_assignment["artifact_observation_id"]
    assert first_assignment["assignment_mode"] == "whole_artifact"
    with connect_database(db) as connection:
        assert connection.execute("SELECT COUNT(*) FROM entity_assessments").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM endpoint_entities").fetchone()[0] == 0


def test_assignment_requires_existing_observation_active_scope_and_confirmation(tmp_path):
    db = tmp_path / "nct.db"
    item = observation(db)
    destination = scope(db, "Lab")
    archived = scope(db, "Former lab")
    archive_network_scope(
        db, archived["scope_id"], expected_version=1, archived_by="tester", reason="Closed",
    )
    with pytest.raises(ValueError, match="confirmation"):
        assign_artifact_scope(
            db, artifact_observation_id=item["observation_id"],
            scope_id=destination["scope_id"], actor="alice", reason="Checked",
            whole_artifact_confirmed=False,
        )
    with pytest.raises(ValueError, match="observation does not exist"):
        assign_artifact_scope(
            db, artifact_observation_id="missing", scope_id=destination["scope_id"],
            actor="alice", reason="Checked", whole_artifact_confirmed=True,
        )
    with pytest.raises(ValueError, match="archived"):
        assign(db, item, archived)
    assert list_artifact_scope_assignments(db, item["observation_id"]) == []


def test_assignment_rejects_duplicate_root_and_unlinked_legacy_assessment(tmp_path):
    db = tmp_path / "nct.db"
    item = observation(db)
    first_scope = scope(db, "Lab")
    second_scope = scope(db, "Production")
    assign(db, item, first_scope)
    with pytest.raises(EvidenceScopeConflict, match="already assigned"):
        assign(db, item, second_scope)

    legacy = observation(db, content=b"legacy", source_ref="upload:legacy")
    record_assessment(
        db, scope_id=first_scope["scope_id"],
        artifact_observation_id=legacy["observation_id"], parser_version="legacy:1",
        assessed_at=None, hosts=[], assessment_facts={"legacy": True},
    )
    with pytest.raises(EvidenceScopeConflict, match="migration reconciliation"):
        assign(db, legacy, first_scope)
    with connect_database(db) as connection:
        with pytest.raises(sqlite3.IntegrityError, match="requires reconciliation"):
            connection.execute(
                """INSERT INTO artifact_scope_assignments VALUES
                   ('bypass', ?, ?, 1, 'assigned', NULL, 'whole_artifact',
                    'mallory', 'Bypass application check', '2030-01-01T00:00:00+00:00')""",
                (legacy["observation_id"], first_scope["scope_id"]),
            )


def test_correction_appends_one_successor_and_preserves_history(tmp_path):
    db = tmp_path / "nct.db"
    item = observation(db)
    first_scope = scope(db, "Lab")
    second_scope = scope(db, "Production")
    root = assign(db, item, first_scope)
    corrected = correct_artifact_scope(
        db, expected_assignment_id=root["assignment_id"],
        destination_scope_id=second_scope["scope_id"], actor="bob",
        reason="Operator confirmed production context", whole_artifact_confirmed=True,
    )
    history = list_artifact_scope_assignments(db, item["observation_id"])
    assert history == [root, corrected]
    assert corrected["revision"] == 2
    assert corrected["event_kind"] == "corrected"
    assert corrected["supersedes_assignment_id"] == root["assignment_id"]
    with pytest.raises(EvidenceScopeConflict, match="another session"):
        correct_artifact_scope(
            db, expected_assignment_id=root["assignment_id"],
            destination_scope_id=first_scope["scope_id"], actor="carol",
            reason="Stale correction", whole_artifact_confirmed=True,
        )
    with pytest.raises(ValueError, match="different"):
        correct_artifact_scope(
            db, expected_assignment_id=corrected["assignment_id"],
            destination_scope_id=second_scope["scope_id"], actor="carol",
            reason="No actual change", whole_artifact_confirmed=True,
        )


def test_archived_source_can_be_corrected_only_to_active_destination(tmp_path):
    db = tmp_path / "nct.db"
    item = observation(db)
    source = scope(db, "Lab")
    destination = scope(db, "Production")
    blocked = scope(db, "Former site")
    root = assign(db, item, source)
    archive_network_scope(
        db, source["scope_id"], expected_version=1, archived_by="tester", reason="Closed",
    )
    archive_network_scope(
        db, blocked["scope_id"], expected_version=1, archived_by="tester", reason="Closed",
    )
    with pytest.raises(ValueError, match="archived"):
        correct_artifact_scope(
            db, expected_assignment_id=root["assignment_id"],
            destination_scope_id=blocked["scope_id"], actor="bob",
            reason="Wrong destination", whole_artifact_confirmed=True,
        )
    corrected = correct_artifact_scope(
        db, expected_assignment_id=root["assignment_id"],
        destination_scope_id=destination["scope_id"], actor="bob",
        reason="Move future interpretation to production", whole_artifact_confirmed=True,
    )
    assert corrected["scope_id"] == destination["scope_id"]


def test_competing_roots_and_corrections_create_one_chain(tmp_path):
    db = tmp_path / "nct.db"
    item = observation(db)
    scopes = [scope(db, name) for name in ("Lab", "Production", "Backup")]
    barrier = threading.Barrier(2)

    def initial(destination):
        barrier.wait(timeout=5)
        try:
            return assign(db, item, destination)["assignment_id"]
        except EvidenceScopeConflict:
            return "conflict"

    with ThreadPoolExecutor(max_workers=2) as pool:
        roots = list(pool.map(initial, scopes[:2]))
    assert roots.count("conflict") == 1
    root = list_artifact_scope_assignments(db, item["observation_id"])[0]

    barrier = threading.Barrier(2)
    destinations = [item for item in scopes if item["scope_id"] != root["scope_id"]]

    def correction(destination):
        barrier.wait(timeout=5)
        try:
            return correct_artifact_scope(
                db, expected_assignment_id=root["assignment_id"],
                destination_scope_id=destination["scope_id"], actor="bob",
                reason="Concurrent correction", whole_artifact_confirmed=True,
            )["assignment_id"]
        except EvidenceScopeConflict:
            return "conflict"

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(correction, destinations))
    assert results.count("conflict") == 1
    assert len(list_artifact_scope_assignments(db, item["observation_id"])) == 2


def test_database_blocks_assignment_branch_cross_observation_mutation_and_delete(tmp_path):
    db = tmp_path / "nct.db"
    first = observation(db, source_ref="upload:first")
    second = observation(db, source_ref="upload:second")
    scopes = [scope(db, name) for name in ("Lab", "Production")]
    root = assign(db, first, scopes[0])
    init_evidence_scope_assignment_storage(db)
    with connect_database(db) as connection:
        with pytest.raises(sqlite3.IntegrityError, match="invalid assignment successor"):
            connection.execute(
                """INSERT INTO artifact_scope_assignments VALUES
                   ('bad', ?, ?, 2, 'corrected', ?, 'whole_artifact',
                    'mallory', 'Cross observation', '2030-01-01T00:00:00+00:00')""",
                (second["observation_id"], scopes[1]["scope_id"], root["assignment_id"]),
            )
        with pytest.raises(sqlite3.IntegrityError, match="CHECK constraint failed"):
            connection.execute(
                """INSERT INTO artifact_scope_assignments VALUES
                   ('blank-time', ?, ?, 2, 'corrected', ?, 'whole_artifact',
                    'mallory', 'Missing time', '')""",
                (first["observation_id"], scopes[1]["scope_id"], root["assignment_id"]),
            )
        with pytest.raises(sqlite3.IntegrityError, match="CHECK constraint failed"):
            connection.execute(
                """INSERT INTO artifact_scope_assignments VALUES
                   ('non-utc-time', ?, ?, 2, 'corrected', ?, 'whole_artifact',
                    'mallory', 'Wrong time zone', '2030-01-01T01:00:00+01:00')""",
                (first["observation_id"], scopes[1]["scope_id"], root["assignment_id"]),
            )
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            connection.execute(
                "UPDATE artifact_scope_assignments SET reason = 'changed' WHERE assignment_id = ?",
                (root["assignment_id"],),
            )
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            connection.execute(
                "DELETE FROM artifact_scope_assignments WHERE assignment_id = ?",
                (root["assignment_id"],),
            )


def test_assessment_links_must_match_and_all_entity_evidence_is_immutable(tmp_path):
    db = tmp_path / "nct.db"
    item = observation(db)
    first_scope = scope(db, "Lab")
    second_scope = scope(db, "Production")
    assignment = assign(db, item, first_scope)
    assessment_id = record_assessment(
        db, scope_id=first_scope["scope_id"],
        artifact_observation_id=item["observation_id"], parser_version="test:1",
        assessed_at=None,
        hosts=[{"address": "192.0.2.1", "facts": {"state": "up"},
                "services": [{"protocol": "tcp", "port": 443,
                              "facts": {"state": "open"}}]}],
    )
    other_assignment = assign(db, observation(db, content=b"other"), second_scope)
    with connect_database(db) as connection:
        for linked_at, linked_by in (
            ("", "tester"),
            ("2030-01-01T01:00:00+01:00", "tester"),
            ("2030-01-01T00:00:00+00:00", ""),
            ("2030-01-01T00:00:00+00:00", " padded "),
        ):
            with pytest.raises(sqlite3.IntegrityError, match="CHECK constraint failed"):
                connection.execute(
                    "INSERT INTO assessment_scope_assignment_links VALUES (?, ?, ?, ?)",
                    (assignment["assignment_id"], assessment_id, linked_at, linked_by),
                )
        connection.execute(
            "INSERT INTO assessment_scope_assignment_links VALUES (?, ?, ?, ?)",
            (assignment["assignment_id"], assessment_id,
             "2030-01-01T00:00:00+00:00", "tester"),
        )
        with pytest.raises(sqlite3.IntegrityError, match="do not match"):
            connection.execute(
                "INSERT INTO assessment_scope_assignment_links VALUES (?, ?, ?, ?)",
                (other_assignment["assignment_id"], assessment_id,
                 "2030-01-01T00:00:00+00:00", "tester"),
            )
        for statement in (
            "UPDATE entity_assessments SET parser_version = 'changed'",
            "DELETE FROM entity_assessments",
            "UPDATE endpoint_entities SET address = '192.0.2.2'",
            "DELETE FROM endpoint_entities",
            "UPDATE service_entities SET port = 80",
            "DELETE FROM service_entities",
            "UPDATE endpoint_receipts SET facts_json = '{}'",
            "DELETE FROM endpoint_receipts",
            "UPDATE service_receipts SET facts_json = '{}'",
            "DELETE FROM service_receipts",
            "UPDATE assessment_scope_assignment_links SET linked_by = 'changed'",
            "DELETE FROM assessment_scope_assignment_links",
        ):
            with pytest.raises(sqlite3.IntegrityError, match="immutable"):
                connection.execute(statement)
