from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import sqlite3
import threading
import time

import pytest

import app.assigned_nmap_ingestion as coordinator
from app.artifacts import register_artifact_bytes
from app.database import connect_database
from app.entities import prepare_assessment, record_assessment
from app.evidence_scope_assignments import assign_artifact_scope, correct_artifact_scope
from app.network_scopes import archive_network_scope, create_network_scope


NMAP = b"""<nmaprun args="nmap -sS 192.0.2.1" start="100">
<scaninfo type="syn" protocol="tcp" numservices="1" services="443"/>
<host starttime="101" endtime="109"><status state="up" reason="syn-ack"/>
<address addr="192.0.2.1" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port>
</ports></host><runstats><finished time="110"/></runstats></nmaprun>"""


def artifact(db, *, content=NMAP, source_ref="upload:one"):
    return register_artifact_bytes(
        db_path=db, content=content, source_kind="nmap_import",
        source_ref=source_ref, actor="tester",
        observed_at="2030-01-01T00:00:00+00:00",
    )


def scope(db, label):
    return create_network_scope(db, label=label, created_by="tester")


def assign(db, item, destination):
    return assign_artifact_scope(
        db, artifact_observation_id=item["observation_id"],
        scope_id=destination["scope_id"], actor="analyst",
        reason="Reviewed whole-artifact network context",
        whole_artifact_confirmed=True,
    )


def ingest(db, assignment, **kwargs):
    return coordinator.ingest_assigned_nmap_observation(
        db, expected_assignment_id=assignment["assignment_id"],
        linked_by="processor", **kwargs,
    )


def counts(db):
    names = (
        "entity_assessments", "endpoint_entities", "service_entities",
        "endpoint_receipts", "service_receipts",
        "assessment_scope_assignment_links",
    )
    with connect_database(db) as connection:
        return {
            name: connection.execute(f"SELECT COUNT(*) FROM {name}").fetchone()[0]
            for name in names
        }


def test_happy_path_commits_complete_graph_and_exact_replay_is_noop(tmp_path):
    db = tmp_path / "nct.db"
    item = artifact(db)
    assignment = assign(db, item, scope(db, "Lab"))

    first = ingest(db, assignment)
    assert first == {
        "assessment_id": first["assessment_id"],
        "scope_id": assignment["scope_id"],
        "artifact_observation_id": item["observation_id"],
        "parser_version": "nmap-endpoints:1",
        "address_count": 1,
        "service_receipt_count": 1,
        "assessed_at": "1970-01-01T00:01:50+00:00",
        "assignment_id": assignment["assignment_id"],
        "assessment_created": True,
        "link_created": True,
        "completed_replay": False,
    }
    before = counts(db)
    assert before == {
        "entity_assessments": 1, "endpoint_entities": 1, "service_entities": 1,
        "endpoint_receipts": 1, "service_receipts": 1,
        "assessment_scope_assignment_links": 1,
    }
    replay = ingest(db, assignment)
    assert replay["assessment_id"] == first["assessment_id"]
    assert replay["completed_replay"] is True
    assert replay["assessment_created"] is False
    assert replay["link_created"] is False
    assert counts(db) == before


def test_completed_replay_survives_later_correction_and_scope_archive(tmp_path):
    db = tmp_path / "nct.db"
    item = artifact(db)
    source = scope(db, "Lab")
    destination = scope(db, "Production")
    root = assign(db, item, source)
    completed = ingest(db, root)
    correct_artifact_scope(
        db, expected_assignment_id=root["assignment_id"],
        destination_scope_id=destination["scope_id"], actor="analyst",
        reason="Corrected context", whole_artifact_confirmed=True,
    )
    archive_network_scope(
        db, source["scope_id"], expected_version=1,
        archived_by="admin", reason="Retired lab",
    )
    replay = ingest(db, root)
    assert replay["assessment_id"] == completed["assessment_id"]
    assert replay["completed_replay"] is True
    assert counts(db)["assessment_scope_assignment_links"] == 1


def test_stale_or_archived_unlinked_assignment_is_rejected_without_rows(tmp_path):
    for mutation in ("correct", "archive"):
        db = tmp_path / f"{mutation}.db"
        item = artifact(db)
        source = scope(db, "Lab")
        root = assign(db, item, source)
        if mutation == "correct":
            destination = scope(db, "Production")
            correct_artifact_scope(
                db, expected_assignment_id=root["assignment_id"],
                destination_scope_id=destination["scope_id"], actor="analyst",
                reason="Corrected context", whole_artifact_confirmed=True,
            )
        else:
            archive_network_scope(
                db, source["scope_id"], expected_version=1,
                archived_by="admin", reason="Retired lab",
            )
        with pytest.raises(coordinator.AssignedNmapConflict, match="current|archived"):
            ingest(db, root)
        assert all(value == 0 for value in counts(db).values())


def test_unlinked_assessment_does_not_make_stale_assignment_a_completed_replay(tmp_path):
    db = tmp_path / "nct.db"
    item = artifact(db)
    first_scope = scope(db, "Lab")
    root = assign(db, item, first_scope)
    prepared, _ = coordinator.prepare_nmap_observation(
        db, observation_id=item["observation_id"], scope_id=first_scope["scope_id"],
    )
    record_assessment(
        db, scope_id=prepared.scope_id,
        artifact_observation_id=prepared.artifact_observation_id,
        parser_version=prepared.parser_version,
        assessed_at=prepared.assessed_at,
        time_basis="nmap runstats finished epoch",
        hosts=[{"address": "192.0.2.1", "facts": {
            "addresses": [{"addr": "192.0.2.1", "addrtype": "ipv4"}],
        }, "services": []}],
        assessment_facts={"unlinked": True},
    )
    correct_artifact_scope(
        db, expected_assignment_id=root["assignment_id"],
        destination_scope_id=scope(db, "Production")["scope_id"],
        actor="analyst", reason="Corrected context", whole_artifact_confirmed=True,
    )
    before = counts(db)
    with pytest.raises(coordinator.AssignedNmapConflict, match="no longer current"):
        ingest(db, root)
    assert counts(db) == before
    assert counts(db)["assessment_scope_assignment_links"] == 0


def test_correction_back_to_prior_scope_reuses_assessment_and_adds_link(tmp_path):
    db = tmp_path / "nct.db"
    item = artifact(db)
    first_scope = scope(db, "Lab")
    second_scope = scope(db, "Production")
    first = assign(db, item, first_scope)
    first_result = ingest(db, first)
    second = correct_artifact_scope(
        db, expected_assignment_id=first["assignment_id"],
        destination_scope_id=second_scope["scope_id"], actor="analyst",
        reason="Production context", whole_artifact_confirmed=True,
    )
    ingest(db, second)
    third = correct_artifact_scope(
        db, expected_assignment_id=second["assignment_id"],
        destination_scope_id=first_scope["scope_id"], actor="analyst",
        reason="Confirmed lab context", whole_artifact_confirmed=True,
    )
    result = ingest(db, third)
    assert result["assessment_id"] == first_result["assessment_id"]
    assert result["assessment_created"] is False
    assert result["link_created"] is True
    assert counts(db)["entity_assessments"] == 2
    assert counts(db)["assessment_scope_assignment_links"] == 3


def test_parser_versions_create_separate_assessments_and_links(tmp_path):
    db = tmp_path / "nct.db"
    assignment = assign(db, artifact(db), scope(db, "Lab"))
    first = ingest(db, assignment)
    second = ingest(db, assignment, parser_version="nmap-endpoints:2")
    assert first["assessment_id"] != second["assessment_id"]
    assert second["assessment_created"] is True
    assert second["link_created"] is True
    assert counts(db)["entity_assessments"] == 2
    assert counts(db)["assessment_scope_assignment_links"] == 2


def test_link_failure_rolls_back_assessment_entities_and_receipts(tmp_path):
    db = tmp_path / "nct.db"
    assignment = assign(db, artifact(db), scope(db, "Lab"))
    with connect_database(db) as connection:
        connection.execute("""CREATE TRIGGER reject_test_link BEFORE INSERT ON
            assessment_scope_assignment_links BEGIN SELECT RAISE(ABORT, 'injected'); END""")
    with pytest.raises(sqlite3.IntegrityError, match="injected"):
        ingest(db, assignment)
    assert all(value == 0 for value in counts(db).values())


@pytest.mark.parametrize("damage", ["missing", "changed", "corrupt"])
def test_unavailable_or_corrupt_canonical_artifact_publishes_nothing(tmp_path, damage):
    db = tmp_path / f"{damage}.db"
    item = artifact(db, content=b"not xml" if damage == "corrupt" else NMAP)
    assignment = assign(db, item, scope(db, "Lab"))
    canonical = Path(item["canonical_path"])
    if damage == "missing":
        canonical.unlink()
    elif damage == "changed":
        canonical.write_bytes(NMAP + b"changed")
    with pytest.raises(ValueError):
        ingest(db, assignment)
    assert all(value == 0 for value in counts(db).values())


def test_changed_facts_under_completed_parser_identity_conflict(tmp_path, monkeypatch):
    db = tmp_path / "nct.db"
    item = artifact(db)
    assignment = assign(db, item, scope(db, "Lab"))
    ingest(db, assignment)
    original = coordinator.prepare_nmap_observation

    def changed(*args, **kwargs):
        prepared, result = original(*args, **kwargs)
        replacement = prepare_assessment(
            scope_id=prepared.scope_id,
            artifact_observation_id=prepared.artifact_observation_id,
            parser_version=prepared.parser_version,
            assessed_at=prepared.assessed_at,
            hosts=[],
            time_basis="nmap runstats finished epoch",
            assessment_facts={"changed": True},
        )
        return replacement, result

    monkeypatch.setattr(coordinator, "prepare_nmap_observation", changed)
    before = counts(db)
    with pytest.raises(ValueError, match="different facts"):
        ingest(db, assignment)
    assert counts(db) == before


@pytest.mark.parametrize("mutation", ["correct", "archive"])
def test_mutation_winning_during_parse_rejects_unlinked_ingestion(
    tmp_path, monkeypatch, mutation,
):
    db = tmp_path / f"{mutation}.db"
    item = artifact(db)
    source = scope(db, "Lab")
    root = assign(db, item, source)
    destination = scope(db, "Production")
    parsed = threading.Event()
    release = threading.Event()
    original = coordinator.prepare_nmap_observation

    def paused(*args, **kwargs):
        result = original(*args, **kwargs)
        parsed.set()
        assert release.wait(timeout=5)
        return result

    monkeypatch.setattr(coordinator, "prepare_nmap_observation", paused)
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(ingest, db, root)
        assert parsed.wait(timeout=5)
        if mutation == "correct":
            correct_artifact_scope(
                db, expected_assignment_id=root["assignment_id"],
                destination_scope_id=destination["scope_id"], actor="analyst",
                reason="Correction won", whole_artifact_confirmed=True,
            )
        else:
            archive_network_scope(
                db, source["scope_id"], expected_version=1,
                archived_by="admin", reason="Archive won",
            )
        release.set()
        with pytest.raises(coordinator.AssignedNmapConflict):
            future.result(timeout=5)
    assert all(value == 0 for value in counts(db).values())


@pytest.mark.parametrize("mutation", ["correct", "archive"])
def test_ingestion_winning_writer_lock_commits_before_mutation(
    tmp_path, monkeypatch, mutation,
):
    db = tmp_path / f"{mutation}.db"
    item = artifact(db)
    source = scope(db, "Lab")
    root = assign(db, item, source)
    destination = scope(db, "Production")
    writing = threading.Event()
    release = threading.Event()
    mutation_started = threading.Event()
    original = coordinator.record_prepared_assessment_on_connection

    def paused(db_connection, prepared):
        result = original(db_connection, prepared)
        writing.set()
        assert release.wait(timeout=5)
        return result

    def mutate():
        mutation_started.set()
        if mutation == "correct":
            return correct_artifact_scope(
                db, expected_assignment_id=root["assignment_id"],
                destination_scope_id=destination["scope_id"], actor="analyst",
                reason="Correction follows ingestion", whole_artifact_confirmed=True,
            )
        return archive_network_scope(
            db, source["scope_id"], expected_version=1,
            archived_by="admin", reason="Archive follows ingestion",
        )

    monkeypatch.setattr(coordinator, "record_prepared_assessment_on_connection", paused)
    with ThreadPoolExecutor(max_workers=2) as pool:
        ingestion = pool.submit(ingest, db, root)
        assert writing.wait(timeout=5)
        later_mutation = pool.submit(mutate)
        assert mutation_started.wait(timeout=5)
        time.sleep(0.05)
        assert not later_mutation.done()
        release.set()
        assert ingestion.result(timeout=5)["link_created"] is True
        later_mutation.result(timeout=5)
    assert counts(db)["assessment_scope_assignment_links"] == 1
    assert ingest(db, root)["completed_replay"] is True


def test_database_trigger_blocks_stale_and_inactive_direct_links(tmp_path):
    for mutation in ("correct", "archive"):
        db = tmp_path / f"direct-{mutation}.db"
        item = artifact(db)
        source = scope(db, "Lab")
        root = assign(db, item, source)
        assessment_id = record_assessment(
            db, scope_id=source["scope_id"],
            artifact_observation_id=item["observation_id"],
            parser_version="direct-test:1", assessed_at=None, hosts=[],
        )
        if mutation == "correct":
            correct_artifact_scope(
                db, expected_assignment_id=root["assignment_id"],
                destination_scope_id=scope(db, "Production")["scope_id"],
                actor="analyst", reason="Corrected", whole_artifact_confirmed=True,
            )
        else:
            archive_network_scope(
                db, source["scope_id"], expected_version=1,
                archived_by="admin", reason="Archived",
            )
        with connect_database(db) as connection:
            with pytest.raises(sqlite3.IntegrityError, match="stale or scope is archived"):
                connection.execute(
                    "INSERT INTO assessment_scope_assignment_links VALUES (?, ?, ?, ?)",
                    (root["assignment_id"], assessment_id,
                     "2030-01-01T00:00:00+00:00", "tester"),
                )


def test_identical_bytes_in_separate_observations_remain_separate(tmp_path):
    db = tmp_path / "nct.db"
    destination = scope(db, "Lab")
    first = artifact(db, source_ref="upload:first")
    second = artifact(db, source_ref="upload:second")
    assert first["sha256"] == second["sha256"]
    first_result = ingest(db, assign(db, first, destination))
    second_result = ingest(db, assign(db, second, destination))
    assert first_result["assessment_id"] != second_result["assessment_id"]
    assert counts(db)["entity_assessments"] == 2
    assert counts(db)["assessment_scope_assignment_links"] == 2


def test_schema_initialization_recovers_after_database_replacement(tmp_path):
    db = tmp_path / "nct.db"
    first = artifact(db)
    ingest(db, assign(db, first, scope(db, "First")))
    replacement_db = tmp_path / "replacement.db"
    with connect_database(replacement_db) as connection:
        connection.execute("CREATE TABLE replacement_marker (value TEXT)")
    replacement_db.replace(db)
    replacement = artifact(db, source_ref="upload:replacement")
    result = ingest(db, assign(db, replacement, scope(db, "Replacement")))
    assert result["address_count"] == 1
    assert counts(db)["assessment_scope_assignment_links"] == 1


def test_coordinator_is_only_imported_by_reviewed_processing_boundaries():
    coordinator_path = Path(coordinator.__file__).resolve()
    importers = []
    for source in Path("app").glob("*.py"):
        if source.resolve() == coordinator_path:
            continue
        if "assigned_nmap_ingestion" in source.read_text(encoding="utf-8"):
            importers.append(source.name)
    assert importers == ["automated_nmap_foundation.py", "main.py"]
