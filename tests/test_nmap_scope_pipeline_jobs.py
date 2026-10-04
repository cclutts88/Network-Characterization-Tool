from __future__ import annotations

from pathlib import Path
import json

import pytest

import app.assigned_nmap_ingestion as assigned_ingestion
import app.derived_jobs as jobs
from app.artifacts import register_artifact_bytes
from app.database import connect_database
from app.evidence_scope_assignments import assign_artifact_scope, correct_artifact_scope
from app.network_scopes import archive_network_scope, create_network_scope


XML = b'''<nmaprun scanner="nmap" version="7.95" args="nmap -n -sS 192.0.2.10" start="100">
<scaninfo type="syn" protocol="tcp" numservices="1" services="443"/>
<host starttime="101" endtime="109"><status state="up" reason="syn-ack"/>
<address addr="192.0.2.10" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port>
</ports></host><runstats><finished time="110" timestr="done"/><hosts up="1" down="0" total="1"/></runstats></nmaprun>'''


def manual_assignment(tmp_path: Path):
    db_path = tmp_path / "nct.db"
    observation = register_artifact_bytes(
        db_path=db_path,
        content=XML,
        source_kind="nmap_import",
        source_ref="upload:test",
        original_filename="evidence.xml",
        actor="analyst",
    )
    scope = create_network_scope(db_path, label="Lab", created_by="admin")
    assignment = assign_artifact_scope(
        db_path,
        artifact_observation_id=observation["observation_id"],
        scope_id=scope["scope_id"],
        actor="analyst",
        reason="Reviewed whole-file context",
        whole_artifact_confirmed=True,
    )
    return db_path, observation, scope, assignment


def test_duplicate_request_is_one_job_and_one_attempt(tmp_path, monkeypatch):
    db_path, _, _, assignment = manual_assignment(tmp_path)
    monkeypatch.setattr(jobs, "start_derived_job_worker", lambda *args, **kwargs: None)

    first = jobs.enqueue_manual_nmap_scope_job(
        db_path,
        assignment["assignment_id"],
        request_token="same-request",
        requested_by="analyst",
    )
    replay = jobs.enqueue_manual_nmap_scope_job(
        db_path,
        assignment["assignment_id"],
        request_token="same-request",
        requested_by="analyst",
    )

    assert first["job_id"] == replay["job_id"]
    assert first["latest_attempt"]["attempt_id"] == replay["latest_attempt"]["attempt_id"]
    with connect_database(db_path, read_only=True) as db:
        assert db.execute("SELECT COUNT(*) FROM pipeline_jobs").fetchone()[0] == 1
        assert db.execute("SELECT COUNT(*) FROM pipeline_job_attempts").fetchone()[0] == 1
        assert db.execute("SELECT COUNT(*) FROM pipeline_job_requests").fetchone()[0] == 1


def test_stale_assignment_fails_without_publishing_receipts(tmp_path, monkeypatch):
    db_path, _, first_scope, assignment = manual_assignment(tmp_path)
    second_scope = create_network_scope(db_path, label="Production", created_by="admin")
    monkeypatch.setattr(jobs, "start_derived_job_worker", lambda *args, **kwargs: None)
    queued = jobs.enqueue_manual_nmap_scope_job(
        db_path,
        assignment["assignment_id"],
        request_token="stale-assignment",
        requested_by="analyst",
    )
    correct_artifact_scope(
        db_path,
        expected_assignment_id=assignment["assignment_id"],
        destination_scope_id=second_scope["scope_id"],
        actor="analyst",
        reason="Corrected after review",
        whole_artifact_confirmed=True,
    )

    assert jobs.run_next_derived_job(db_path, tmp_path) is True
    with connect_database(db_path, read_only=True) as db:
        attempt = db.execute(
            "SELECT state, error FROM pipeline_job_attempts WHERE job_id = ?",
            (queued["job_id"],),
        ).fetchone()
        assert attempt[0] == "failed"
        assert "no longer current" in attempt[1]
        assert db.execute("SELECT COUNT(*) FROM entity_assessments").fetchone()[0] == 0
        assert db.execute(
            "SELECT COUNT(*) FROM assessment_scope_assignment_links"
        ).fetchone()[0] == 0


def test_archived_scope_and_parser_change_fail_before_publication(tmp_path, monkeypatch):
    archived_dir = tmp_path / "archived"
    parser_dir = tmp_path / "parser"
    archived_dir.mkdir()
    parser_dir.mkdir()
    monkeypatch.setattr(jobs, "start_derived_job_worker", lambda *args, **kwargs: None)

    archived_db, _, scope, assignment = manual_assignment(archived_dir)
    archived_job = jobs.enqueue_manual_nmap_scope_job(
        archived_db,
        assignment["assignment_id"],
        request_token="archive-after-queue",
        requested_by="analyst",
    )
    archive_network_scope(
        archived_db,
        scope["scope_id"],
        expected_version=1,
        archived_by="admin",
        reason="Retired before processing",
    )
    jobs.run_next_derived_job(archived_db, archived_dir)

    parser_db, _, _, parser_assignment = manual_assignment(parser_dir)
    parser_job = jobs.enqueue_manual_nmap_scope_job(
        parser_db,
        parser_assignment["assignment_id"],
        request_token="parser-change",
        requested_by="analyst",
    )
    monkeypatch.setattr(jobs, "NMAP_ENDPOINT_PARSER", "nmap-endpoints:future")
    jobs.run_next_derived_job(parser_db, parser_dir)

    for db_path, job, expected in (
        (archived_db, archived_job, "archived"),
        (parser_db, parser_job, "rules changed"),
    ):
        with connect_database(db_path, read_only=True) as db:
            state, error = db.execute(
                "SELECT state, error FROM pipeline_job_attempts WHERE job_id = ?",
                (job["job_id"],),
            ).fetchone()
            assert state == "failed"
            assert expected in error
            assert db.execute("SELECT COUNT(*) FROM entity_assessments").fetchone()[0] == 0


def test_publication_failure_rolls_back_evidence_and_records_failed_attempt(
    tmp_path, monkeypatch,
):
    db_path, _, _, assignment = manual_assignment(tmp_path)
    monkeypatch.setattr(jobs, "start_derived_job_worker", lambda *args, **kwargs: None)
    queued = jobs.enqueue_manual_nmap_scope_job(
        db_path,
        assignment["assignment_id"],
        request_token="publication-rollback",
        requested_by="analyst",
    )
    original = assigned_ingestion.record_prepared_assessment_on_connection

    def fail_after_records(db, prepared):
        original(db, prepared)
        raise RuntimeError("injected publication failure")

    monkeypatch.setattr(
        assigned_ingestion,
        "record_prepared_assessment_on_connection",
        fail_after_records,
    )
    jobs.run_next_derived_job(db_path, tmp_path)

    with connect_database(db_path, read_only=True) as db:
        attempt = db.execute(
            "SELECT state, error FROM pipeline_job_attempts WHERE job_id = ?",
            (queued["job_id"],),
        ).fetchone()
        assert attempt == ("failed", "injected publication failure")
        assert db.execute("SELECT COUNT(*) FROM entity_assessments").fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM endpoint_entities").fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM service_entities").fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM endpoint_receipts").fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM service_receipts").fetchone()[0] == 0
        assert db.execute(
            "SELECT COUNT(*) FROM assessment_scope_assignment_links"
        ).fetchone()[0] == 0


def test_restart_marks_running_interrupted_and_explicit_retry_completes(
    tmp_path, monkeypatch,
):
    db_path, _, _, assignment = manual_assignment(tmp_path)
    monkeypatch.setattr(jobs, "start_derived_job_worker", lambda *args, **kwargs: None)
    queued = jobs.enqueue_manual_nmap_scope_job(
        db_path,
        assignment["assignment_id"],
        request_token="before-restart",
        requested_by="analyst",
    )
    claim = jobs.claim_next_derived_job(db_path)
    assert claim is not None
    assert jobs.recover_interrupted_derived_jobs(db_path) == 1
    retried = jobs.retry_derived_job(
        db_path,
        queued["job_id"],
        request_token="after-restart",
        requested_by="analyst",
    )
    assert retried["latest_attempt"]["state"] == "queued"
    jobs.run_next_derived_job(db_path, tmp_path)

    with connect_database(db_path, read_only=True) as db:
        attempts = db.execute(
            """SELECT attempt_number, state FROM pipeline_job_attempts
               WHERE job_id = ? ORDER BY attempt_number""",
            (queued["job_id"],),
        ).fetchall()
        assert attempts == [(1, "interrupted"), (2, "completed")]
        assert db.execute("SELECT COUNT(*) FROM entity_assessments").fetchone()[0] == 1
        assert db.execute(
            "SELECT COUNT(*) FROM assessment_scope_assignment_links"
        ).fetchone()[0] == 1


def test_corrupted_assignment_definition_cannot_cross_to_another_observation(
    tmp_path, monkeypatch,
):
    db_path, _, _, assignment_a = manual_assignment(tmp_path)
    observation_b = register_artifact_bytes(
        db_path=db_path,
        content=XML.replace(b"192.0.2.10", b"192.0.2.11"),
        source_kind="nmap_import",
        source_ref="upload:other",
        original_filename="other.xml",
        actor="analyst",
    )
    scope_b = create_network_scope(db_path, label="Other", created_by="admin")
    assignment_b = assign_artifact_scope(
        db_path,
        artifact_observation_id=observation_b["observation_id"],
        scope_id=scope_b["scope_id"],
        actor="analyst",
        reason="Separate reviewed context",
        whole_artifact_confirmed=True,
    )
    monkeypatch.setattr(jobs, "start_derived_job_worker", lambda *args, **kwargs: None)
    queued = jobs.enqueue_manual_nmap_scope_job(
        db_path,
        assignment_a["assignment_id"],
        request_token="definition-corruption",
        requested_by="analyst",
    )
    with connect_database(db_path) as db:
        definition = json.loads(db.execute(
            "SELECT definition_json FROM pipeline_jobs WHERE job_id = ?",
            (queued["job_id"],),
        ).fetchone()[0])
        definition["assignment_id"] = assignment_b["assignment_id"]
        db.execute(
            "UPDATE pipeline_jobs SET definition_json = ? WHERE job_id = ?",
            (json.dumps(definition, sort_keys=True, separators=(",", ":")), queued["job_id"]),
        )

    jobs.run_next_derived_job(db_path, tmp_path)
    with connect_database(db_path, read_only=True) as db:
        state, error = db.execute(
            "SELECT state, error FROM pipeline_job_attempts WHERE job_id = ?",
            (queued["job_id"],),
        ).fetchone()
        assert state == "failed"
        assert "identity" in error
        assert db.execute("SELECT COUNT(*) FROM entity_assessments").fetchone()[0] == 0
        assert db.execute(
            "SELECT COUNT(*) FROM assessment_scope_assignment_links"
        ).fetchone()[0] == 0


def test_assignment_corrected_after_parse_fails_at_publication_guard(
    tmp_path, monkeypatch,
):
    db_path, _, _, assignment = manual_assignment(tmp_path)
    destination = create_network_scope(db_path, label="Corrected", created_by="admin")
    monkeypatch.setattr(jobs, "start_derived_job_worker", lambda *args, **kwargs: None)
    queued = jobs.enqueue_manual_nmap_scope_job(
        db_path,
        assignment["assignment_id"],
        request_token="mid-parse-correction",
        requested_by="analyst",
    )
    original = jobs.ingest_assigned_nmap_observation

    def correct_between_parse_and_publish(*args, **kwargs):
        verify = kwargs["before_publish"]

        def mutate_authority():
            verify()
            correct_artifact_scope(
                db_path,
                expected_assignment_id=assignment["assignment_id"],
                destination_scope_id=destination["scope_id"],
                actor="analyst",
                reason="Correction won after parsing",
                whole_artifact_confirmed=True,
            )

        kwargs["before_publish"] = mutate_authority
        return original(*args, **kwargs)

    monkeypatch.setattr(jobs, "ingest_assigned_nmap_observation", correct_between_parse_and_publish)
    jobs.run_next_derived_job(db_path, tmp_path)

    with connect_database(db_path, read_only=True) as db:
        state, error = db.execute(
            "SELECT state, error FROM pipeline_job_attempts WHERE job_id = ?",
            (queued["job_id"],),
        ).fetchone()
        assert state == "failed"
        assert "no longer current" in error
        assert db.execute("SELECT COUNT(*) FROM entity_assessments").fetchone()[0] == 0
        assert db.execute(
            "SELECT COUNT(*) FROM assessment_scope_assignment_links"
        ).fetchone()[0] == 0
