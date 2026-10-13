from __future__ import annotations

import json
from pathlib import Path
import sqlite3
import time

import pytest
from fastapi.testclient import TestClient

import app.derived_jobs as jobs
from app.artifacts import (
    register_artifact_bytes,
    register_artifact_file,
    register_finalized_files,
)
from app.automated_nmap_foundation import (
    get_automated_scan_foundation_status,
    init_automated_nmap_foundation_storage,
)
from app.automated_nmap_scope_corrections import (
    AutomatedNmapScopeCorrectionConflict,
    correct_automated_nmap_scope_handoff,
    init_automated_nmap_scope_correction_storage,
)
from app.database import connect_database
from app.evidence_scope_assignments import assign_artifact_scope, correct_artifact_scope
from app.network_scopes import create_network_scope
from app.pipeline_intake import (
    AUTOMATED_NMAP_INTENT,
    MANUAL_NMAP_INTENT,
    NMAP_INGESTION_POLICY_VERSION,
    get_admission_intent,
    recover_missing_automated_nmap_intents,
)
from app.poc import (
    ScanRunRequest,
    insert_scan_run_manifest,
    prepare_scan_run,
    update_scan_run_manifest,
)
from app.saved_network_scope_associations import (
    change_saved_network_scope_association,
    get_run_scope_context,
)
from app.saved_networks import SavedNetworkCreate, create_saved_network


XML = b'''<nmaprun scanner="nmap" version="7.95" args="nmap -n -sS 192.0.2.10" start="100">
<scaninfo type="syn" protocol="tcp" numservices="1" services="443"/>
<host starttime="101" endtime="109"><status state="up" reason="syn-ack"/>
<address addr="192.0.2.10" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port>
</ports></host><runstats><finished time="110" timestr="done"/><hosts up="1" down="0" total="1"/></runstats></nmaprun>'''


def manual_assignment(tmp_path: Path, *, marked: bool = True):
    db_path = tmp_path / "analyzer.db"
    observation = register_artifact_bytes(
        db_path=db_path,
        content=XML,
        source_kind="nmap_import",
        source_ref="upload:test",
        original_filename="evidence.xml",
        actor="analyst",
        observed_at="2030-01-01T00:00:00+00:00",
        pipeline_policy_version=(NMAP_INGESTION_POLICY_VERSION if marked else None),
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


def completed_automated_run(
    tmp_path: Path, *, finalize: bool = True, register_observation: bool = True,
):
    db_path = tmp_path / "analyzer.db"
    network = create_saved_network(
        SavedNetworkCreate(
            name="Lab subnet", cidr="192.0.2.0/24", created_by="analyst",
        ),
        db_path,
    )
    scope = create_network_scope(db_path, label="Lab", created_by="admin")
    association = change_saved_network_scope_association(
        db_path,
        network["saved_network_id"],
        scope_id=scope["scope_id"],
        expected_association_id=None,
        expected_revision=None,
        actor="analyst",
        reason="Reviewed authority",
    )
    request = ScanRunRequest(
        operator="analyst",
        created_by="analyst",
        name="Automatic pipeline scan",
        originating_host="nct-test",
        interface="eth0",
        profile="Standard",
        profile_id="builtin-standard",
        profile_version=2,
        targets=[network["cidr"]],
        manual_targets=[],
        saved_network_ids=[network["saved_network_id"]],
        reviewed_scope_associations=[{
            "association_id": association["association_id"],
            "revision": association["revision"],
        }],
        capture=True,
        timeout_seconds=30,
    )
    run = prepare_scan_run(request, db_path, interfaces={"eth0"})
    run["status"] = "completed"
    run["completed_at"] = "2030-01-01T00:01:00+00:00"
    xml_path = tmp_path / "scan.xml"
    xml_path.write_bytes(XML)
    observation = None
    if register_observation:
        observation = register_artifact_file(
            db_path=db_path,
            source_path=xml_path,
            source_kind="nmap_scan",
            source_ref=run["run_id"],
            original_filename="scan.xml",
            actor="analyst",
            observed_at=run["completed_at"],
            observation_key=f"nmap_scan:{run['run_id']}:scan.xml",
            run_id=run["run_id"],
            scope_context=get_run_scope_context(db_path, run["run_id"]),
        )
    if finalize:
        update_scan_run_manifest(run, db_path)
    return db_path, run, scope, observation


def test_finalized_scan_registration_retains_its_reviewed_scope(tmp_path):
    db_path, run, scope, _ = completed_automated_run(
        tmp_path,
        finalize=False,
        register_observation=False,
    )

    register_finalized_files(
        db_path,
        tmp_path,
        run,
        "nmap_scan",
        ["scan.xml"],
    )
    update_scan_run_manifest(run, db_path)
    init_automated_nmap_foundation_storage(db_path)

    status = get_automated_scan_foundation_status(db_path, run["run_id"])
    intent = get_admission_intent(
        db_path,
        intent_kind=AUTOMATED_NMAP_INTENT,
        source_id=run["run_id"],
    )
    assert run["artifact_registry"]["status"] == "complete"
    assert status["eligible"] is True
    assert status["scope_id"] == scope["scope_id"]
    assert intent["state"] == "pending"
    assert intent["scope_id"] == scope["scope_id"]


def bad_scope_handoff(tmp_path: Path):
    db_path, run, scope, _ = completed_automated_run(
        tmp_path,
        finalize=False,
        register_observation=False,
    )
    run_dir = tmp_path / "scan-runs" / run["run_id"]
    run_dir.mkdir(parents=True)
    xml_path = run_dir / "scan.xml"
    xml_path.write_bytes(XML)
    observation = register_artifact_file(
        db_path=db_path,
        source_path=xml_path,
        source_kind="nmap_scan",
        source_ref=run["run_id"],
        original_filename="scan.xml",
        actor="analyst",
        observed_at=run["completed_at"],
        observation_key=f"nmap_scan:{run['run_id']}:scan.xml",
        metadata={"relative_path": str(xml_path.relative_to(db_path.parent))},
        run_id=run["run_id"],
        scope_context=None,
    )
    update_scan_run_manifest(run, db_path)
    init_automated_nmap_foundation_storage(db_path)
    init_automated_nmap_scope_correction_storage(db_path)
    return db_path, run, scope, observation


def test_explicit_scope_handoff_correction_preserves_failed_intent_and_is_idempotent(
    tmp_path, monkeypatch,
):
    import app.automated_nmap_scope_corrections as corrections

    monkeypatch.setattr(corrections, "start_derived_job_worker", lambda *_args: None)
    db_path, run, scope, observation = bad_scope_handoff(tmp_path)
    before = get_admission_intent(
        db_path,
        intent_kind=AUTOMATED_NMAP_INTENT,
        source_id=run["run_id"],
    )
    assert before["state"] == "needs_scope"

    first = correct_automated_nmap_scope_handoff(
        db_path,
        tmp_path,
        run["run_id"],
        actor="admin",
        reason="Reviewed the retained A51 scope handoff",
        request_token="scope-correction-1",
    )
    replay = correct_automated_nmap_scope_handoff(
        db_path,
        tmp_path,
        run["run_id"],
        actor="admin",
        reason="Reviewed the retained A51 scope handoff",
        request_token="scope-correction-1",
    )

    after = get_admission_intent(
        db_path,
        intent_kind=AUTOMATED_NMAP_INTENT,
        source_id=run["run_id"],
    )
    status = get_automated_scan_foundation_status(db_path, run["run_id"])
    assert after == before
    assert replay == first
    assert first["observation_id"] == observation["observation_id"]
    assert first["corrected_contract"]["scope_id"] == scope["scope_id"]
    assert status["eligible"] is True
    assert status["scope_handoff_correction"]["state"] == "corrected"
    assert status["processing_job"]["latest_attempt"]["state"] == "queued"
    assert status["network_contact"] is False
    with connect_database(db_path, read_only=True) as db:
        assert db.execute(
            "SELECT COUNT(*) FROM automated_nmap_scope_corrections"
        ).fetchone()[0] == 1
        assert db.execute(
            "SELECT COUNT(*) FROM artifact_observation_scope_contexts "
            "WHERE observation_id = ?",
            (observation["observation_id"],),
        ).fetchone()[0] == 1
        assert db.execute(
            "SELECT COUNT(*) FROM pipeline_jobs WHERE source_run_id = ?",
            (run["run_id"],),
        ).fetchone()[0] == 1
        assert db.execute(
            "SELECT COUNT(*) FROM pipeline_job_attempts WHERE state = 'queued'"
        ).fetchone()[0] == 1
    with connect_database(db_path) as db:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            db.execute(
                "UPDATE automated_nmap_scope_corrections SET reason = 'changed'"
            )
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            db.execute("DELETE FROM automated_nmap_scope_corrections")

    with pytest.raises(
        AutomatedNmapScopeCorrectionConflict, match="already has",
    ):
        correct_automated_nmap_scope_handoff(
            db_path,
            tmp_path,
            run["run_id"],
            actor="admin",
            reason="A different request must not replace the first",
            request_token="scope-correction-2",
        )


def test_scope_handoff_correction_replay_wakes_committed_job_after_start_failure(
    tmp_path, monkeypatch,
):
    import app.automated_nmap_scope_corrections as corrections

    db_path, run, _, _ = bad_scope_handoff(tmp_path)
    monkeypatch.setattr(
        jobs,
        "searchsploit_provider_snapshot",
        lambda: {
            "available": False,
            "provider": "SearchSploit / Exploit-DB",
            "provider_key": None,
            "message": "Offline data is not staged in this test",
        },
    )
    starts = []

    def recover_on_replay(path, data_dir):
        starts.append(True)
        if len(starts) == 1:
            raise RuntimeError("injected post-commit worker start failure")
        assert jobs.run_next_derived_job(path, data_dir) is True

    monkeypatch.setattr(corrections, "start_derived_job_worker", recover_on_replay)
    request = {
        "actor": "admin",
        "reason": "Verified retained scope after worker startup interruption",
        "request_token": "scope-correction-worker-recovery",
    }
    with pytest.raises(RuntimeError, match="post-commit worker start failure"):
        correct_automated_nmap_scope_handoff(
            db_path, tmp_path, run["run_id"], **request,
        )
    with connect_database(db_path, read_only=True) as db:
        committed = db.execute(
            "SELECT correction_id, job_id FROM automated_nmap_scope_corrections"
        ).fetchone()
        assert committed is not None
        assert db.execute(
            "SELECT COUNT(*) FROM pipeline_jobs WHERE source_run_id = ?",
            (run["run_id"],),
        ).fetchone()[0] == 1

    replay = correct_automated_nmap_scope_handoff(
        db_path, tmp_path, run["run_id"], **request,
    )

    assert len(starts) == 2
    assert replay["correction_id"] == committed[0]
    assert replay["job_id"] == committed[1]
    with connect_database(db_path, read_only=True) as db:
        assert db.execute(
            "SELECT state FROM pipeline_job_attempts WHERE job_id = ?",
            (committed[1],),
        ).fetchone()[0] == "completed"
        assert db.execute(
            "SELECT COUNT(*) FROM automated_nmap_scope_corrections"
        ).fetchone()[0] == 1


@pytest.mark.parametrize("unsafe_run_id", ["not-a-run-id", "../outside"])
def test_scope_handoff_correction_rejects_malformed_or_traversal_run_id(
    tmp_path, monkeypatch, unsafe_run_id,
):
    import app.automated_nmap_scope_corrections as corrections

    db_path, _, _, _ = bad_scope_handoff(tmp_path)
    monkeypatch.setattr(corrections, "start_derived_job_worker", lambda *_args: None)
    with pytest.raises(
        AutomatedNmapScopeCorrectionConflict, match="Invalid scan run identifier",
    ):
        correct_automated_nmap_scope_handoff(
            db_path,
            tmp_path,
            unsafe_run_id,
            actor="admin",
            reason="Unsafe retained identity must fail closed",
            request_token=f"unsafe-{unsafe_run_id}",
        )
    with connect_database(db_path, read_only=True) as db:
        assert db.execute(
            "SELECT COUNT(*) FROM automated_nmap_scope_corrections"
        ).fetchone()[0] == 0
        assert db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='pipeline_jobs'"
        ).fetchone() is None


def test_scope_handoff_correction_rejects_symlinked_run_directory(
    tmp_path, monkeypatch,
):
    import app.automated_nmap_scope_corrections as corrections

    db_path, run, _, _ = bad_scope_handoff(tmp_path)
    run_dir = tmp_path / "scan-runs" / run["run_id"]
    retained_elsewhere = tmp_path / "retained-elsewhere"
    run_dir.rename(retained_elsewhere)
    try:
        run_dir.symlink_to(retained_elsewhere, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"Symbolic links are unavailable: {exc}")
    monkeypatch.setattr(corrections, "start_derived_job_worker", lambda *_args: None)

    with pytest.raises(
        AutomatedNmapScopeCorrectionConflict, match="symbolic links",
    ):
        correct_automated_nmap_scope_handoff(
            db_path,
            tmp_path,
            run["run_id"],
            actor="admin",
            reason="Symlinked retained evidence must fail closed",
            request_token="scope-correction-symlink",
        )
    with connect_database(db_path, read_only=True) as db:
        assert db.execute(
            "SELECT COUNT(*) FROM automated_nmap_scope_corrections"
        ).fetchone()[0] == 0
        assert db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='pipeline_jobs'"
        ).fetchone() is None


def test_scope_handoff_correction_completes_local_foundation_and_queues_candidates(
    tmp_path, monkeypatch,
):
    import app.automated_nmap_scope_corrections as corrections
    import app.poc as poc

    db_path, run, scope, observation = bad_scope_handoff(tmp_path)
    before = get_admission_intent(
        db_path,
        intent_kind=AUTOMATED_NMAP_INTENT,
        source_id=run["run_id"],
    )
    monkeypatch.setattr(corrections, "start_derived_job_worker", lambda *_args: None)
    monkeypatch.setattr(
        jobs,
        "searchsploit_provider_snapshot",
        lambda: {
            "available": False,
            "provider": "SearchSploit / Exploit-DB",
            "provider_key": None,
            "message": "Offline data is not staged in this test",
        },
    )

    def unexpected_network_process(*_args, **_kwargs):
        raise AssertionError("The correction must not start a scan or network process")

    monkeypatch.setattr(poc.subprocess, "Popen", unexpected_network_process)
    correction = correct_automated_nmap_scope_handoff(
        db_path,
        tmp_path,
        run["run_id"],
        actor="admin",
        reason="End-to-end retained evidence verification",
        request_token="scope-correction-end-to-end",
    )
    ready = get_automated_scan_foundation_status(db_path, run["run_id"])
    assert ready["eligible"] is True
    assert ready["scope_id"] == scope["scope_id"]
    assert ready["network_contact"] is False

    assert jobs.run_next_derived_job(db_path, tmp_path) is True

    complete = get_automated_scan_foundation_status(db_path, run["run_id"])
    after = get_admission_intent(
        db_path,
        intent_kind=AUTOMATED_NMAP_INTENT,
        source_id=run["run_id"],
    )
    assert after == before
    assert complete["state"] == "foundation_complete"
    assert complete["scope_handoff_correction"]["state"] == "corrected"
    assert complete["network_contact"] is False
    with connect_database(db_path, read_only=True) as db:
        assessment = db.execute(
            """SELECT assessment.artifact_observation_id, link.assignment_id
               FROM entity_assessments assessment
               JOIN assessment_scope_assignment_links link
                 ON link.assessment_id = assessment.assessment_id"""
        ).fetchone()
        assert tuple(assessment) == (
            observation["observation_id"], correction["assignment_id"],
        )
        candidate = db.execute(
            """SELECT source_run_id, source_observation_id, source_kind, source_ref
               FROM pipeline_jobs WHERE job_type = ?""",
            ("nmap_searchsploit_candidates",),
        ).fetchone()
        assert tuple(candidate) == (
            run["run_id"], observation["observation_id"],
            "nmap_scan", run["run_id"],
        )


def test_scope_handoff_correction_rolls_back_if_canonical_evidence_changed(
    tmp_path, monkeypatch,
):
    import app.automated_nmap_scope_corrections as corrections

    monkeypatch.setattr(corrections, "start_derived_job_worker", lambda *_args: None)
    db_path, run, _, observation = bad_scope_handoff(tmp_path)
    Path(observation["canonical_path"]).write_bytes(b"changed")

    with pytest.raises(
        AutomatedNmapScopeCorrectionConflict, match="canonical aggregate",
    ):
        correct_automated_nmap_scope_handoff(
            db_path,
            tmp_path,
            run["run_id"],
            actor="admin",
            reason="Should fail closed",
            request_token="scope-correction-drift",
        )

    with connect_database(db_path, read_only=True) as db:
        assert db.execute(
            "SELECT COUNT(*) FROM automated_nmap_scope_corrections"
        ).fetchone()[0] == 0
        assert db.execute(
            "SELECT COUNT(*) FROM artifact_observation_scope_contexts "
            "WHERE observation_id = ?",
            (observation["observation_id"],),
        ).fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM pipeline_jobs").fetchone()[0] == 0
        assert db.execute(
            "SELECT COUNT(*) FROM artifact_scope_assignments"
        ).fetchone()[0] == 0


def test_scope_handoff_correction_rolls_back_if_queueing_fails(
    tmp_path, monkeypatch,
):
    import app.automated_nmap_scope_corrections as corrections

    monkeypatch.setattr(corrections, "start_derived_job_worker", lambda *_args: None)
    db_path, run, _, observation = bad_scope_handoff(tmp_path)

    def fail_queue(*_args, **_kwargs):
        raise RuntimeError("injected correction queue failure")

    monkeypatch.setattr(corrections, "_enqueue_automated_nmap_scope_job", fail_queue)
    with pytest.raises(RuntimeError, match="injected correction queue failure"):
        correct_automated_nmap_scope_handoff(
            db_path,
            tmp_path,
            run["run_id"],
            actor="admin",
            reason="The transaction must roll back",
            request_token="scope-correction-rollback",
        )

    with connect_database(db_path, read_only=True) as db:
        assert db.execute(
            "SELECT COUNT(*) FROM automated_nmap_scope_corrections"
        ).fetchone()[0] == 0
        assert db.execute(
            "SELECT COUNT(*) FROM artifact_observation_scope_contexts "
            "WHERE observation_id = ?",
            (observation["observation_id"],),
        ).fetchone()[0] == 0
        assert db.execute(
            "SELECT COUNT(*) FROM artifact_scope_assignments"
        ).fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM pipeline_jobs").fetchone()[0] == 0


def test_scope_handoff_correction_rejects_manifest_scope_drift(tmp_path, monkeypatch):
    import app.automated_nmap_scope_corrections as corrections

    monkeypatch.setattr(corrections, "start_derived_job_worker", lambda *_args: None)
    db_path, run, _, observation = bad_scope_handoff(tmp_path)
    with connect_database(db_path) as db:
        row = db.execute(
            "SELECT manifest_json FROM scan_runs WHERE run_id = ?", (run["run_id"],)
        ).fetchone()
        manifest = json.loads(row[0])
        manifest["network_scope_context"]["scope_label"] = "Changed after scan"
        db.execute(
            "UPDATE scan_runs SET manifest_json = ? WHERE run_id = ?",
            (json.dumps(manifest, sort_keys=True), run["run_id"]),
        )

    with pytest.raises(
        AutomatedNmapScopeCorrectionConflict, match="manifest and retained",
    ):
        correct_automated_nmap_scope_handoff(
            db_path,
            tmp_path,
            run["run_id"],
            actor="admin",
            reason="Must not use changed authority",
            request_token="scope-correction-context-drift",
        )
    with connect_database(db_path, read_only=True) as db:
        assert db.execute(
            "SELECT COUNT(*) FROM artifact_observation_scope_contexts "
            "WHERE observation_id = ?",
            (observation["observation_id"],),
        ).fetchone()[0] == 0


def test_scope_handoff_correction_route_requires_admin_and_confirmation(
    tmp_path, monkeypatch,
):
    import app.automated_nmap_scope_corrections as corrections
    import app.main as main
    import app.poc as poc

    db_path, run, _, _ = bad_scope_handoff(tmp_path)
    monkeypatch.setattr(corrections, "start_derived_job_worker", lambda *_args: None)
    monkeypatch.setattr(main, "DB_PATH", db_path)
    monkeypatch.setattr(main, "DATA_DIR", tmp_path)
    monkeypatch.setattr(poc, "DB_PATH", db_path)
    monkeypatch.setattr(main, "auth_enabled", lambda: True)
    monkeypatch.setattr(
        main,
        "session_identity",
        lambda *_args: {
            "username": "alice", "display_name": "Alice", "role": "analyst",
        },
    )
    with TestClient(main.app) as client:
        denied = client.post(
            f"/api/scan-runs/{run['run_id']}/scope-handoff-corrections",
            json={
                "request_token": "route-correction-analyst",
                "reason": "Analyst must not repair this handoff",
                "confirmed": True,
            },
        )
    assert denied.status_code == 403

    monkeypatch.setattr(
        main,
        "session_identity",
        lambda *_args: {
            "username": "admin", "display_name": "Administrator", "role": "admin",
        },
    )
    with TestClient(main.app) as client:
        unconfirmed = client.post(
            f"/api/scan-runs/{run['run_id']}/scope-handoff-corrections",
            json={
                "request_token": "route-correction-unconfirmed",
                "reason": "Review requires explicit confirmation",
                "confirmed": False,
            },
        )
        corrected = client.post(
            f"/api/scan-runs/{run['run_id']}/scope-handoff-corrections",
            json={
                "request_token": "route-correction-admin",
                "reason": "Verified the exact retained scope handoff",
                "confirmed": True,
            },
        )
    assert unconfirmed.status_code == 422
    assert corrected.status_code == 202
    assert corrected.json()["correction"]["actor"] == "admin"
    assert corrected.json()["status"]["scope_handoff_correction"]["state"] == "corrected"


def test_new_manual_assignment_commits_pending_intent_but_history_stays_manual(tmp_path):
    marked_dir = tmp_path / "marked"
    historical_dir = tmp_path / "historical"
    marked_dir.mkdir()
    historical_dir.mkdir()
    marked_db, _, _, marked_assignment = manual_assignment(marked_dir, marked=True)
    historical_db, _, _, historical_assignment = manual_assignment(
        historical_dir, marked=False,
    )

    intent = get_admission_intent(
        marked_db,
        intent_kind=MANUAL_NMAP_INTENT,
        source_id=marked_assignment["assignment_id"],
    )
    historical = get_admission_intent(
        historical_db,
        intent_kind=MANUAL_NMAP_INTENT,
        source_id=historical_assignment["assignment_id"],
    )

    assert intent["state"] == "pending"
    assert intent["activity_state"] == "waiting"
    assert intent["assignment_id"] == marked_assignment["assignment_id"]
    assert historical is None


def test_dispatch_is_durable_idempotent_and_restart_safe(tmp_path):
    db_path, _, _, assignment = manual_assignment(tmp_path)

    assert jobs.dispatch_next_pipeline_intake(db_path) is True
    assert jobs.dispatch_next_pipeline_intake(db_path) is False

    intent = get_admission_intent(
        db_path,
        intent_kind=MANUAL_NMAP_INTENT,
        source_id=assignment["assignment_id"],
    )
    assert intent["state"] == "admitted"
    assert intent["activity_state"] == "complete"
    with connect_database(db_path, read_only=True) as db:
        assert db.execute("SELECT COUNT(*) FROM pipeline_jobs").fetchone()[0] == 1
        assert db.execute("SELECT COUNT(*) FROM pipeline_job_attempts").fetchone()[0] == 1
        assert db.execute("SELECT COUNT(*) FROM pipeline_job_requests").fetchone()[0] == 1


def test_queue_failure_rolls_back_and_leaves_intent_recoverable(tmp_path, monkeypatch):
    db_path, _, _, assignment = manual_assignment(tmp_path)

    def fail_queue(*args, **kwargs):
        raise sqlite3.OperationalError("injected queue failure")

    monkeypatch.setattr(jobs, "_enqueue_scope_snapshot", fail_queue)
    with pytest.raises(sqlite3.OperationalError, match="injected queue failure"):
        jobs.dispatch_next_pipeline_intake(db_path)

    intent = get_admission_intent(
        db_path,
        intent_kind=MANUAL_NMAP_INTENT,
        source_id=assignment["assignment_id"],
    )
    assert intent["state"] == "pending"
    assert intent["activity_state"] == "waiting"
    with connect_database(db_path, read_only=True) as db:
        assert db.execute("SELECT COUNT(*) FROM pipeline_jobs").fetchone()[0] == 0


@pytest.mark.parametrize("terminal_state", ["failed", "interrupted"])
def test_automatic_admission_never_retries_an_existing_terminal_attempt(
    tmp_path, monkeypatch, terminal_state,
):
    db_path, _, _, assignment = manual_assignment(tmp_path)
    monkeypatch.setattr(jobs, "start_derived_job_worker", lambda *args, **kwargs: None)
    queued = jobs.enqueue_manual_nmap_scope_job(
        db_path,
        assignment["assignment_id"],
        request_token=f"explicit-{terminal_state}",
        requested_by="analyst",
    )
    claim = jobs.claim_next_derived_job(db_path)
    assert claim is not None
    if terminal_state == "failed":
        jobs.fail_claimed_derived_job(db_path, claim, RuntimeError("expected failure"))
    else:
        with connect_database(db_path) as db:
            db.execute(
                "UPDATE work_leases SET expires_at = '2000-01-01T00:00:00.000Z' "
                "WHERE lease_key = ?",
                (claim["lease_key"],),
            )
        assert jobs.recover_interrupted_derived_jobs(db_path) == 1

    assert jobs.dispatch_next_pipeline_intake(db_path) is True

    intent = get_admission_intent(
        db_path,
        intent_kind=MANUAL_NMAP_INTENT,
        source_id=assignment["assignment_id"],
    )
    assert intent["state"] == "admitted"
    assert intent["admitted_job_id"] == queued["job_id"]
    with connect_database(db_path, read_only=True) as db:
        attempts = db.execute(
            """SELECT attempt_number, state FROM pipeline_job_attempts
               WHERE job_id = ? ORDER BY attempt_number""",
            (queued["job_id"],),
        ).fetchall()
        requests = db.execute(
            "SELECT request_token FROM pipeline_job_requests WHERE job_id = ?",
            (queued["job_id"],),
        ).fetchall()
    if terminal_state == "failed":
        assert attempts == [(1, "failed")]
        assert requests == [("explicit-failed",)]
    else:
        assert attempts == [(1, "interrupted"), (2, "queued")]
        assert requests == [
            ("explicit-interrupted",),
            (f"recovery-{claim['attempt_id']}-{claim['lease_epoch']}",),
        ]


def test_persistent_queue_failure_pauses_without_hot_respawn_then_recovers(
    tmp_path, monkeypatch,
):
    db_path, _, _, assignment = manual_assignment(tmp_path)
    original_dispatch = jobs.dispatch_next_pipeline_intake
    calls = 0

    def unavailable(*args, **kwargs):
        nonlocal calls
        calls += 1
        raise sqlite3.OperationalError("queue storage unavailable")

    monkeypatch.setattr(jobs, "_INTAKE_RETRY_DELAYS", (0.0, 0.0, 0.0))
    monkeypatch.setattr(jobs, "dispatch_next_pipeline_intake", unavailable)
    jobs.start_derived_job_worker(db_path, tmp_path)
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        current = jobs._WORKERS.get(db_path.resolve())
        if current is None:
            break
        current[1].join(timeout=0.01)
    assert jobs._WORKERS.get(db_path.resolve()) is None
    assert calls == 4
    time.sleep(0.03)
    assert calls == 4

    delayed = get_admission_intent(
        db_path,
        intent_kind=MANUAL_NMAP_INTENT,
        source_id=assignment["assignment_id"],
    )
    assert delayed["state"] == "pending"
    assert delayed["activity_state"] == "paused"
    assert "paused after repeated queue storage errors" in delayed["last_error"]

    monkeypatch.setattr(jobs, "dispatch_next_pipeline_intake", original_dispatch)
    jobs.start_derived_job_worker(db_path, tmp_path)
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        recovered = get_admission_intent(
            db_path,
            intent_kind=MANUAL_NMAP_INTENT,
            source_id=assignment["assignment_id"],
        )
        if recovered["state"] == "admitted":
            break
        time.sleep(0.01)
    assert recovered["state"] == "admitted"
    assert recovered["activity_state"] == "complete"


def test_transient_queue_error_is_visible_as_retrying_then_recovers(
    tmp_path, monkeypatch,
):
    db_path, _, _, assignment = manual_assignment(tmp_path)
    original_dispatch = jobs.dispatch_next_pipeline_intake
    calls = 0

    def unavailable_once(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise sqlite3.OperationalError("temporary queue storage failure")
        return original_dispatch(*args, **kwargs)

    monkeypatch.setattr(jobs, "_INTAKE_RETRY_DELAYS", (0.1,))
    monkeypatch.setattr(jobs, "dispatch_next_pipeline_intake", unavailable_once)
    jobs.start_derived_job_worker(db_path, tmp_path)

    deadline = time.monotonic() + 2
    retrying = None
    while time.monotonic() < deadline:
        retrying = get_admission_intent(
            db_path,
            intent_kind=MANUAL_NMAP_INTENT,
            source_id=assignment["assignment_id"],
        )
        if retrying["activity_state"] == "retrying":
            break
        time.sleep(0.005)
    assert retrying["state"] == "pending"
    assert retrying["activity_state"] == "retrying"
    assert "delayed by a queue storage error" in retrying["last_error"]

    deadline = time.monotonic() + 3
    recovered = retrying
    while time.monotonic() < deadline:
        recovered = get_admission_intent(
            db_path,
            intent_kind=MANUAL_NMAP_INTENT,
            source_id=assignment["assignment_id"],
        )
        if recovered["state"] == "admitted":
            break
        time.sleep(0.01)
    assert recovered["state"] == "admitted"
    assert recovered["activity_state"] == "complete"


def test_worker_shutdown_interrupts_admission_backoff(tmp_path, monkeypatch):
    db_path, _, _, _ = manual_assignment(tmp_path)
    entered = False

    def unavailable(*args, **kwargs):
        nonlocal entered
        entered = True
        raise sqlite3.OperationalError("queue storage unavailable")

    monkeypatch.setattr(jobs, "_INTAKE_RETRY_DELAYS", (5.0,))
    monkeypatch.setattr(jobs, "dispatch_next_pipeline_intake", unavailable)
    jobs.start_derived_job_worker(db_path, tmp_path)
    deadline = time.monotonic() + 1
    while not entered and time.monotonic() < deadline:
        time.sleep(0.005)
    started = time.monotonic()
    jobs.stop_derived_job_worker(db_path, timeout=1)
    elapsed = time.monotonic() - started
    current = jobs._WORKERS.get(db_path.resolve())
    assert entered is True
    assert elapsed < 1
    assert current is None or not current[1].is_alive()


def test_correction_before_dispatch_blocks_old_contract_and_admits_new(tmp_path):
    db_path, _, _, first = manual_assignment(tmp_path)
    destination = create_network_scope(db_path, label="Production", created_by="admin")
    corrected = correct_artifact_scope(
        db_path,
        expected_assignment_id=first["assignment_id"],
        destination_scope_id=destination["scope_id"],
        actor="analyst",
        reason="Corrected after source review",
        whole_artifact_confirmed=True,
    )

    assert jobs.dispatch_next_pipeline_intake(db_path) is True
    assert jobs.dispatch_next_pipeline_intake(db_path) is True

    old_intent = get_admission_intent(
        db_path, intent_kind=MANUAL_NMAP_INTENT, source_id=first["assignment_id"],
    )
    new_intent = get_admission_intent(
        db_path, intent_kind=MANUAL_NMAP_INTENT, source_id=corrected["assignment_id"],
    )
    assert old_intent["state"] == "blocked"
    assert "no longer current" in old_intent["last_error"]
    assert new_intent["state"] == "admitted"
    assert new_intent["resolved_assignment_id"] == corrected["assignment_id"]
    with connect_database(db_path, read_only=True) as db:
        assert db.execute("SELECT COUNT(*) FROM pipeline_jobs").fetchone()[0] == 1


def test_parser_change_before_dispatch_blocks_frozen_contract(tmp_path, monkeypatch):
    db_path, _, _, assignment = manual_assignment(tmp_path)
    monkeypatch.setattr(jobs, "NMAP_ENDPOINT_PARSER", "nmap-endpoints:future")

    assert jobs.dispatch_next_pipeline_intake(db_path) is True

    intent = get_admission_intent(
        db_path,
        intent_kind=MANUAL_NMAP_INTENT,
        source_id=assignment["assignment_id"],
    )
    assert intent["state"] == "blocked"
    assert "contract changed" in intent["last_error"]
    with connect_database(db_path, read_only=True) as db:
        assert db.execute("SELECT COUNT(*) FROM pipeline_jobs").fetchone()[0] == 0


def test_completed_marked_scan_creates_intent_and_dispatches_once(tmp_path):
    db_path, run, scope, observation = completed_automated_run(tmp_path)
    intent = get_admission_intent(
        db_path, intent_kind=AUTOMATED_NMAP_INTENT, source_id=run["run_id"],
    )

    assert intent["state"] == "pending"
    assert intent["observation_id"] == observation["observation_id"]
    assert intent["scope_id"] == scope["scope_id"]
    assert jobs.dispatch_next_pipeline_intake(db_path) is True
    assert jobs.dispatch_next_pipeline_intake(db_path) is False

    admitted = get_admission_intent(
        db_path, intent_kind=AUTOMATED_NMAP_INTENT, source_id=run["run_id"],
    )
    status = get_automated_scan_foundation_status(db_path, run["run_id"])
    assert admitted["state"] == "admitted"
    assert status["admission_intent"]["admitted_job_id"] == admitted["admitted_job_id"]
    with connect_database(db_path, read_only=True) as db:
        assert db.execute(
            "SELECT COUNT(*) FROM pipeline_jobs WHERE source_run_id = ?",
            (run["run_id"],),
        ).fetchone()[0] == 1


def test_completed_progress_before_xml_registration_waits_for_finalized_source(tmp_path):
    db_path, run, _, observation = completed_automated_run(tmp_path, finalize=False)
    with connect_database(db_path) as db:
        db.execute(
            "DELETE FROM artifact_observations WHERE observation_id = ?",
            (observation["observation_id"],),
        )

    # A scan can set its terminal status while writing merge/analysis progress.
    # That progress save must not freeze a missing-source admission contract.
    update_scan_run_manifest(run, db_path)
    assert get_admission_intent(
        db_path, intent_kind=AUTOMATED_NMAP_INTENT, source_id=run["run_id"],
    ) is None

    xml_path = tmp_path / "finalized-scan.xml"
    xml_path.write_bytes(XML)
    finalized = register_artifact_file(
        db_path=db_path,
        source_path=xml_path,
        source_kind="nmap_scan",
        source_ref=run["run_id"],
        original_filename="scan.xml",
        actor="analyst",
        observed_at=run["completed_at"],
        observation_key=f"nmap_scan:{run['run_id']}:scan.xml",
        run_id=run["run_id"],
        scope_context=get_run_scope_context(db_path, run["run_id"]),
    )
    update_scan_run_manifest(run, db_path)

    intent = get_admission_intent(
        db_path, intent_kind=AUTOMATED_NMAP_INTENT, source_id=run["run_id"],
    )
    assert intent["state"] == "pending"
    assert intent["observation_id"] == finalized["observation_id"]


def test_restart_recovers_intent_after_final_xml_registration_crash_window(tmp_path):
    db_path, run, _, observation = completed_automated_run(tmp_path, finalize=False)
    with connect_database(db_path) as db:
        db.execute(
            "DELETE FROM artifact_observations WHERE observation_id = ?",
            (observation["observation_id"],),
        )

    update_scan_run_manifest(run, db_path)
    xml_path = tmp_path / "restart-finalized-scan.xml"
    xml_path.write_bytes(XML)
    finalized = register_artifact_file(
        db_path=db_path,
        source_path=xml_path,
        source_kind="nmap_scan",
        source_ref=run["run_id"],
        original_filename="scan.xml",
        actor="analyst",
        observed_at=run["completed_at"],
        observation_key=f"nmap_scan:{run['run_id']}:scan.xml",
        run_id=run["run_id"],
        scope_context=get_run_scope_context(db_path, run["run_id"]),
    )
    assert get_admission_intent(
        db_path, intent_kind=AUTOMATED_NMAP_INTENT, source_id=run["run_id"],
    ) is None

    assert recover_missing_automated_nmap_intents(db_path) == [run["run_id"]]
    intent = get_admission_intent(
        db_path, intent_kind=AUTOMATED_NMAP_INTENT, source_id=run["run_id"],
    )
    assert intent["state"] == "pending"
    assert intent["observation_id"] == finalized["observation_id"]
    assert jobs.dispatch_next_pipeline_intake(db_path) is True
    assert recover_missing_automated_nmap_intents(db_path) == []


def test_completed_run_metadata_updates_do_not_rewrite_admission_identity(tmp_path):
    db_path, run, _, _ = completed_automated_run(tmp_path)
    before = get_admission_intent(
        db_path, intent_kind=AUTOMATED_NMAP_INTENT, source_id=run["run_id"],
    )
    run["owner"] = "second-analyst"
    run["owner_changed_at"] = "2030-01-01T00:02:00+00:00"
    update_scan_run_manifest(run, db_path)
    after = get_admission_intent(
        db_path, intent_kind=AUTOMATED_NMAP_INTENT, source_id=run["run_id"],
    )

    assert after == before


def test_marked_scan_does_not_create_intent_until_successful_finalization(tmp_path):
    db_path, run, _, _ = completed_automated_run(tmp_path, finalize=False)
    assert get_admission_intent(
        db_path, intent_kind=AUTOMATED_NMAP_INTENT, source_id=run["run_id"],
    ) is None

    with connect_database(db_path) as db:
        marker = db.execute(
            "SELECT policy_version FROM pipeline_intake_sources WHERE source_id = ?",
            (run["run_id"],),
        ).fetchone()
    assert marker == (NMAP_INGESTION_POLICY_VERSION,)

    update_scan_run_manifest(run, db_path)
    assert get_admission_intent(
        db_path, intent_kind=AUTOMATED_NMAP_INTENT, source_id=run["run_id"],
    )["state"] == "pending"


def test_marked_completed_scan_without_registered_xml_is_visible_and_blocked(tmp_path):
    db_path, run, _, _ = completed_automated_run(tmp_path, finalize=False)
    with connect_database(db_path) as db:
        db.execute(
            "DELETE FROM artifact_observations WHERE source_ref = ?",
            (run["run_id"],),
        )
    run["artifact_registry"] = {
        "files": [],
        "errors": [{"filename": "scan.xml", "error": "missing"}],
        "status": "partial",
    }
    update_scan_run_manifest(run, db_path)

    intent = get_admission_intent(
        db_path, intent_kind=AUTOMATED_NMAP_INTENT, source_id=run["run_id"],
    )
    assert intent["state"] == "blocked"
    assert "aggregate scan.xml" in intent["last_error"]
    assert jobs.dispatch_next_pipeline_intake(db_path) is False


def test_marked_manual_target_scan_remains_needs_scope(tmp_path):
    db_path = tmp_path / "analyzer.db"
    request = ScanRunRequest(
        operator="analyst",
        created_by="analyst",
        name="Manual target scan",
        originating_host="nct-test",
        interface="eth0",
        profile="Standard",
        profile_id="builtin-standard",
        profile_version=2,
        targets=["192.0.2.10"],
        manual_targets=["192.0.2.10"],
        saved_network_ids=[],
        reviewed_scope_associations=[],
        capture=True,
        timeout_seconds=30,
    )
    run = prepare_scan_run(request, db_path, interfaces={"eth0"})
    run["status"] = "completed"
    run["completed_at"] = "2030-01-01T00:01:00+00:00"
    xml_path = tmp_path / "manual-target.xml"
    xml_path.write_bytes(XML)
    register_artifact_file(
        db_path=db_path,
        source_path=xml_path,
        source_kind="nmap_scan",
        source_ref=run["run_id"],
        original_filename="scan.xml",
        actor="analyst",
        observed_at=run["completed_at"],
        observation_key=f"nmap_scan:{run['run_id']}:scan.xml",
        run_id=run["run_id"],
        scope_context=None,
    )
    update_scan_run_manifest(run, db_path)

    intent = get_admission_intent(
        db_path, intent_kind=AUTOMATED_NMAP_INTENT, source_id=run["run_id"],
    )
    assert intent["state"] == "needs_scope"
    assert "manual targets" in intent["last_error"]
    assert jobs.dispatch_next_pipeline_intake(db_path) is False


def test_unmarked_historical_completed_run_is_not_automatically_adopted(tmp_path):
    db_path = tmp_path / "analyzer.db"
    run = {
        "run_id": "a" * 32,
        "created_at": "2029-01-01T00:00:00+00:00",
        "completed_at": "2029-01-01T00:01:00+00:00",
        "status": "completed",
        "operator": "historical",
        "reason": "retained before automatic admission",
        "originating_host": "nct-old",
        "interface": "eth0",
        "profile": "Standard",
        "manual_targets": [],
    }
    insert_scan_run_manifest(run, db_path)
    xml_path = tmp_path / "historical-scan.xml"
    xml_path.write_bytes(XML)
    register_artifact_file(
        db_path=db_path,
        source_path=xml_path,
        source_kind="nmap_scan",
        source_ref=run["run_id"],
        original_filename="scan.xml",
        actor="historical",
        observed_at=run["completed_at"],
        observation_key=f"nmap_scan:{run['run_id']}:scan.xml",
        run_id=run["run_id"],
        scope_context=None,
    )
    update_scan_run_manifest(run, db_path)

    assert recover_missing_automated_nmap_intents(db_path) == []

    assert get_admission_intent(
        db_path, intent_kind=AUTOMATED_NMAP_INTENT, source_id=run["run_id"],
    ) is None
    with connect_database(db_path, read_only=True) as db:
        assert db.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'pipeline_jobs'",
        ).fetchone() is None


def test_intake_identity_is_immutable(tmp_path):
    db_path, _, _, assignment = manual_assignment(tmp_path)
    intent = get_admission_intent(
        db_path,
        intent_kind=MANUAL_NMAP_INTENT,
        source_id=assignment["assignment_id"],
    )
    with connect_database(db_path) as db:
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            db.execute(
                "UPDATE pipeline_admission_intents SET scope_id = 'changed' WHERE intent_id = ?",
                (intent["intent_id"],),
            )
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            db.execute(
                "UPDATE pipeline_intake_sources SET policy_version = 99",
            )
