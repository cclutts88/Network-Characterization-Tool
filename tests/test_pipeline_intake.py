from __future__ import annotations

import json
from pathlib import Path
import sqlite3
import time

import pytest

import app.derived_jobs as jobs
from app.artifacts import register_artifact_bytes, register_artifact_file
from app.automated_nmap_foundation import get_automated_scan_foundation_status
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


def completed_automated_run(tmp_path: Path, *, finalize: bool = True):
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
    assert attempts == [(1, terminal_state)]
    assert requests == [(f"explicit-{terminal_state}",)]


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
