from __future__ import annotations

from fastapi.testclient import TestClient
import pytest

from app import derived_jobs as jobs
from app import device_configs
from app import main as main_module
from app.database import connect_database
from app.device_limits import MAX_SUMMARY_ITEMS
from app.device_observations import (
    DeviceObservationConflict,
    assign_device_scope,
    capture_device_interface_source,
    correct_device_scope,
    extract_device_interface_addresses,
    get_device_interface_receipts,
    get_device_observation_status,
    publish_device_interface_assessment,
)
from app.main import app
from app.network_scopes import create_network_scope
from app.pipeline_intake import DEVICE_OBSERVATION_INTENT, get_admission_intent


def _upload(client: TestClient, configuration: str, address: str = "192.0.2.90"):
    return client.post(
        "/api/device-configs/upload",
        data={
            "operator": "observation-analyst",
            "originating_host": "nct-test",
            "vendor": "cisco",
            "device_type": "router",
            "device_address": address,
            "device_name": "Observation Router",
        },
        files={"result_file": ("router.txt", configuration, "text/plain")},
    )


def _complete_summary(tmp_path, monkeypatch, configuration: str, address="192.0.2.90"):
    db_path = tmp_path / "analyzer.db"
    monkeypatch.setattr(device_configs, "DB_PATH", db_path)
    monkeypatch.setattr(device_configs, "CONFIG_DIR", tmp_path / "device-configs")
    monkeypatch.setattr(jobs, "start_derived_job_worker", lambda *args, **kwargs: None)
    with TestClient(app) as client:
        response = _upload(client, configuration, address)
    assert response.status_code == 200, response.text
    run_id = response.json()["run_id"]
    assert jobs.dispatch_next_pipeline_intake(db_path) is True
    assert jobs.run_next_derived_job(db_path, tmp_path) is True
    assert jobs.device_summary_job_for_run(db_path, run_id)["latest_attempt"]["state"] == "completed"
    return db_path, run_id


def _scope(db_path, label):
    return create_network_scope(db_path, label=label, created_by="scope-admin")


def _assign_and_process(db_path, tmp_path, run_id, scope):
    assignment = assign_device_scope(
        db_path, run_id=run_id, scope_id=scope["scope_id"],
        actor="observation-analyst", reason="Confirmed whole collection context",
        whole_collection_confirmed=True,
    )
    intent = get_admission_intent(
        db_path, intent_kind=DEVICE_OBSERVATION_INTENT,
        source_id=assignment["assignment_id"],
    )
    assert intent["state"] == "pending"
    assert jobs.dispatch_next_pipeline_intake(db_path) is True
    assert jobs.run_next_derived_job(db_path, tmp_path) is True
    return assignment


def test_extractor_preserves_multiple_families_secondary_and_routing_context():
    result = extract_device_interface_addresses("""
interface GigabitEthernet0/1
 vrf forwarding BLUE
 ip address 192.0.2.1 255.255.255.0
 ip address 192.0.2.2 255.255.255.0 secondary
 ipv6 address 2001:db8:1::1/64
interface Ethernet9
 vrf member UNKNOWN-FORM
 ip address 203.0.113.99 255.255.255.0
set interfaces ge-0/0/0 unit 7 family inet address 198.51.100.7/24
set routing-instances RED interface ge-0/0/0.7
set interfaces ethernet eth9 address '203.0.113.9/27'
set vrf name GREEN interface eth9
address-looking but unsupported 10.10.10.10/24
""".strip())
    receipts = result["receipts"]
    assert [(item["interface_name"], item["address"], item["prefix_length"])
            for item in receipts] == [
        ("GigabitEthernet0/1", "192.0.2.1", 24),
        ("GigabitEthernet0/1", "192.0.2.2", 24),
        ("GigabitEthernet0/1", "2001:db8:1::1", 64),
        ("Ethernet9", "203.0.113.99", 24),
        ("ge-0/0/0.7", "198.51.100.7", 24),
        ("eth9", "203.0.113.9", 27),
    ]
    assert [item["routing_context"] for item in receipts] == [
        "BLUE", "BLUE", "BLUE", None, "RED", "GREEN",
    ]
    assert receipts[3]["routing_context_status"] == "unresolved"
    assert receipts[1]["facts"] == {"secondary": True}
    assert result["coverage"]["unsupported_address_line_count"] == 1
    assert result["coverage"]["unsupported_context_line_count"] == 1
    assert result["coverage"]["source_time_known"] is False
    assert result["coverage"]["absence_supported"] is False


def test_extractor_does_not_invent_generated_ipv6_or_hide_context_conflicts():
    result = extract_device_interface_addresses("""
interface Ethernet0
 ipv6 address 2001:db8:1::/64 eui-64
 ipv6 address fe80::1 link-local
set interfaces ethernet eth1 vrf 'BLUE'
set interfaces ethernet eth1 address '203.0.113.9/27'
set interfaces ge-0/0/0 unit 7 family inet address 198.51.100.7/24
set routing-instances RED interface ge-0/0/0.7
set routing-instances BLUE interface ge-0/0/0.7
set interfaces ge-0/0/1 unit 0 family inet address 10.1.0.1/24
set routing-instances GREEN interface "ge-0/0/1.0"
set interfaces ethernet 'eth2' vrf 'PURPLE'
set interfaces ethernet 'eth2' address '10.2.0.1/24'
""".strip())
    assert [(item["interface_name"], item["address"], item["routing_context"],
             item["routing_context_status"]) for item in result["receipts"]] == [
        ("eth1", "203.0.113.9", "BLUE", "known"),
        ("ge-0/0/0.7", "198.51.100.7", None, "unresolved"),
        ("ge-0/0/1.0", "10.1.0.1", "GREEN", "known"),
        ("eth2", "10.2.0.1", "PURPLE", "known"),
    ]
    assert result["coverage"]["unsupported_address_line_count"] == 2
    assert result["coverage"]["unsupported_context_line_count"] == 2


def test_scope_required_after_summary_and_durable_stage_publishes_traceable_receipts(
    tmp_path, monkeypatch,
):
    configuration = """interface GigabitEthernet0/1
 ip address 10.90.0.1 255.255.255.0
 ipv6 address 2001:db8:90::1/64
"""
    db_path, run_id = _complete_summary(tmp_path, monkeypatch, configuration)
    status = get_device_observation_status(db_path, run_id)
    assert status["state"] == "needs_scope"
    destination = _scope(db_path, "Device Lab")
    assignment = _assign_and_process(db_path, tmp_path, run_id, destination)

    status = get_device_observation_status(db_path, run_id)
    assert status["state"] == "completed", status
    assert status["assignment"]["assignment_id"] == assignment["assignment_id"]
    assert status["assignment"]["scope_label"] == "Device Lab"
    page = get_device_interface_receipts(db_path, run_id)
    assert page["meaning"].startswith("This retained configuration reported")
    assert page["claims"] == {
        "live_status": False, "physical_device_identity": False,
        "address_active_time": False, "absence_or_disappearance": False,
    }
    assert [(item["address"], item["prefix_length"])
            for item in page["receipts"]] == [
        ("10.90.0.1", 24), ("2001:db8:90::1", 64),
    ]
    assert page["source"]["source_url"].endswith("/files/uploaded-router.txt")
    with connect_database(db_path, read_only=True) as db:
        attempt = db.execute(
            """SELECT state, output_kind, output_id FROM pipeline_job_attempts
               WHERE job_id = ?""",
            (status["job_id"],),
        ).fetchone()
    assert attempt == (
        "completed", "device_interface_assessment",
        status["assessment"]["assessment_id"],
    )


def test_normalization_uses_exact_source_beyond_summary_display_limit(tmp_path, monkeypatch):
    lines = []
    for index in range(MAX_SUMMARY_ITEMS + 7):
        third, fourth = divmod(index, 250)
        lines.extend([
            f"interface Ethernet{index}",
            f" ip address 10.{third}.{fourth}.1 255.255.255.0",
        ])
    db_path, run_id = _complete_summary(tmp_path, monkeypatch, "\n".join(lines) + "\n")
    destination = _scope(db_path, "Scale Lab")
    _assign_and_process(db_path, tmp_path, run_id, destination)
    first = get_device_interface_receipts(db_path, run_id, limit=250)
    second = get_device_interface_receipts(db_path, run_id, limit=250, offset=250)
    third = get_device_interface_receipts(db_path, run_id, limit=250, offset=500)
    assert first["pagination"]["total"] == MAX_SUMMARY_ITEMS + 7
    assert len(first["receipts"]) == 250
    assert len(second["receipts"]) == 250
    assert len(third["receipts"]) == 7


def test_overlapping_addresses_in_different_scopes_and_duplicate_encounters_stay_separate(
    tmp_path, monkeypatch,
):
    configuration = "interface Ethernet0\n ip address 10.50.0.1 255.255.255.0\n"
    first_db, first_run = _complete_summary(tmp_path, monkeypatch, configuration, "10.50.0.1")
    # A second upload in the same isolated data root reuses the calculation but keeps
    # separate collection authority and provenance.
    with TestClient(app) as client:
        response = _upload(client, configuration, "10.50.0.1")
    second_run = response.json()["run_id"]
    assert jobs.dispatch_next_pipeline_intake(first_db) is True
    assert jobs.run_next_derived_job(first_db, tmp_path) is True
    red, blue = _scope(first_db, "Red enclave"), _scope(first_db, "Blue enclave")
    _assign_and_process(first_db, tmp_path, first_run, red)
    _assign_and_process(first_db, tmp_path, second_run, blue)
    first = get_device_interface_receipts(first_db, first_run)
    second = get_device_interface_receipts(first_db, second_run)
    assert first["receipts"][0]["address"] == second["receipts"][0]["address"]
    assert first["assignment"]["scope_id"] != second["assignment"]["scope_id"]
    assert first["assessment"]["assessment_id"] != second["assessment"]["assessment_id"]


def test_correction_is_append_only_and_stale_assignment_cannot_publish(tmp_path, monkeypatch):
    db_path, run_id = _complete_summary(
        tmp_path, monkeypatch,
        "interface Ethernet0\n ip address 192.0.2.1 255.255.255.0\n",
    )
    first, second = _scope(db_path, "First context"), _scope(db_path, "Second context")
    original = assign_device_scope(
        db_path, run_id=run_id, scope_id=first["scope_id"], actor="analyst",
        reason="Initial reviewed context", whole_collection_confirmed=True,
    )
    corrected = correct_device_scope(
        db_path, expected_assignment_id=original["assignment_id"],
        destination_scope_id=second["scope_id"], actor="analyst",
        reason="Corrected after review", whole_collection_confirmed=True,
    )
    assert corrected["revision"] == 2
    assert corrected["supersedes_assignment_id"] == original["assignment_id"]
    # The older intent is retained, but admission fails closed because its assignment
    # is no longer current. The correction remains independently recoverable.
    assert jobs.dispatch_next_pipeline_intake(db_path) is True
    assert jobs.dispatch_next_pipeline_intake(db_path) is True
    old = get_admission_intent(
        db_path, intent_kind=DEVICE_OBSERVATION_INTENT,
        source_id=original["assignment_id"],
    )
    assert old["state"] == "blocked"
    assert "no longer current" in old["last_error"]
    assert jobs.run_next_derived_job(db_path, tmp_path) is True
    assert get_device_observation_status(db_path, run_id)["assignment"]["scope_id"] == second["scope_id"]


def test_assignment_requires_completed_new_pipeline_summary(tmp_path, monkeypatch):
    db_path = tmp_path / "analyzer.db"
    monkeypatch.setattr(device_configs, "DB_PATH", db_path)
    monkeypatch.setattr(device_configs, "CONFIG_DIR", tmp_path / "device-configs")
    monkeypatch.setattr(jobs, "start_derived_job_worker", lambda *args, **kwargs: None)
    with TestClient(app) as client:
        run_id = _upload(
            client, "interface Ethernet0\n ip address 192.0.2.1 255.255.255.0\n",
        ).json()["run_id"]
    destination = _scope(db_path, "Pending Lab")
    with pytest.raises(DeviceObservationConflict, match="must complete"):
        assign_device_scope(
            db_path, run_id=run_id, scope_id=destination["scope_id"], actor="analyst",
            reason="Too early", whole_collection_confirmed=True,
        )


def test_device_scope_routes_assign_report_and_open_receipts(tmp_path, monkeypatch):
    db_path, run_id = _complete_summary(
        tmp_path, monkeypatch,
        "interface Ethernet0\n ip address 198.51.100.10 255.255.255.0\n",
    )
    destination = _scope(db_path, "Route Lab")
    monkeypatch.setattr(main_module, "DB_PATH", db_path)
    monkeypatch.setattr(main_module, "DATA_DIR", tmp_path)
    monkeypatch.setattr(main_module, "start_derived_job_worker", lambda *args, **kwargs: None)
    with TestClient(app) as client:
        assigned = client.post(
            f"/api/device-configs/{run_id}/scope-observations",
            json={
                "scope_id": destination["scope_id"],
                "reason": "Confirmed route test context",
                "whole_collection_confirmed": True,
            },
        )
    assert assigned.status_code == 201, assigned.text
    assert assigned.json()["state"] == "waiting"
    assert assigned.json()["assignment"]["scope_label"] == "Route Lab"
    assert jobs.dispatch_next_pipeline_intake(db_path) is True
    assert jobs.run_next_derived_job(db_path, tmp_path) is True
    with TestClient(app) as client:
        status = client.get(f"/api/device-configs/{run_id}/scope-observations")
        receipts = client.get(
            f"/api/device-configs/{run_id}/scope-observations/receipts?limit=25"
        )
    assert status.status_code == 200
    assert status.json()["state"] == "completed"
    assert receipts.status_code == 200
    assert receipts.json()["receipts"][0]["address"] == "198.51.100.10"


def test_scoped_collection_cannot_be_deleted_out_from_under_receipts(tmp_path, monkeypatch):
    db_path, run_id = _complete_summary(
        tmp_path, monkeypatch,
        "interface Ethernet0\n ip address 203.0.113.10 255.255.255.0\n",
    )
    destination = _scope(db_path, "Retention Lab")
    _assign_and_process(db_path, tmp_path, run_id, destination)
    with pytest.raises(RuntimeError, match="scoped address receipts"):
        device_configs.delete_device_collection(
            run_id, "unused", config_dir=tmp_path / "device-configs", db_path=db_path,
        )
    assert get_device_interface_receipts(db_path, run_id)["pagination"]["total"] == 1


def test_publication_failure_rolls_back_receipts_without_losing_completed_summary(
    tmp_path, monkeypatch,
):
    db_path, run_id = _complete_summary(
        tmp_path, monkeypatch,
        "interface Ethernet0\n ip address 203.0.113.20 255.255.255.0\n",
    )
    destination = _scope(db_path, "Rollback Lab")
    assignment = assign_device_scope(
        db_path, run_id=run_id, scope_id=destination["scope_id"], actor="analyst",
        reason="Exercise atomic publication", whole_collection_confirmed=True,
    )
    assert jobs.dispatch_next_pipeline_intake(db_path) is True

    from app import device_observations

    original_publish = device_observations.publish_device_interface_assessment

    def fail_during_finalize(*args, **kwargs):
        kwargs["transaction_finalize"] = (
            lambda *_args: (_ for _ in ()).throw(RuntimeError("injected finalize failure"))
        )
        return original_publish(*args, **kwargs)

    monkeypatch.setattr(
        device_observations, "publish_device_interface_assessment", fail_during_finalize,
    )
    assert jobs.run_next_derived_job(db_path, tmp_path) is True
    status = get_device_observation_status(db_path, run_id)
    assert status["state"] == "failed"
    assert status["assessment"] is None
    with connect_database(db_path, read_only=True) as db:
        assert db.execute("SELECT COUNT(*) FROM device_interface_assessments").fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM device_interface_receipts").fetchone()[0] == 0
        summary = db.execute(
            """SELECT COUNT(*) FROM pipeline_jobs summary_job
               JOIN pipeline_job_attempts summary_attempt
                 ON summary_attempt.job_id = summary_job.job_id
               WHERE summary_job.source_run_id = ?
                 AND summary_job.job_type = 'device_summary'
                 AND summary_attempt.state = 'completed'""",
            (run_id,),
        ).fetchone()[0]
    assert summary == 1
    assert status["assignment"]["assignment_id"] == assignment["assignment_id"]


def test_changed_run_local_source_fails_closed_without_receipts(tmp_path, monkeypatch):
    db_path, run_id = _complete_summary(
        tmp_path, monkeypatch,
        "interface Ethernet0\n ip address 203.0.113.30 255.255.255.0\n",
    )
    destination = _scope(db_path, "Changed Source Lab")
    assign_device_scope(
        db_path, run_id=run_id, scope_id=destination["scope_id"], actor="analyst",
        reason="Exercise exact source verification", whole_collection_confirmed=True,
    )
    assert jobs.dispatch_next_pipeline_intake(db_path) is True
    source = tmp_path / "device-configs" / run_id / "uploaded-router.txt"
    source.write_text(
        "interface Ethernet0\n ip address 203.0.113.31 255.255.255.0\n",
        encoding="utf-8",
    )
    assert jobs.run_next_derived_job(db_path, tmp_path) is True
    status = get_device_observation_status(db_path, run_id)
    assert status["state"] == "failed"
    assert "exact-content verification" in status["error"]
    with connect_database(db_path, read_only=True) as db:
        assert db.execute("SELECT COUNT(*) FROM device_interface_receipts").fetchone()[0] == 0


def test_interrupted_observation_attempt_can_be_retried_to_completion(tmp_path, monkeypatch):
    db_path, run_id = _complete_summary(
        tmp_path, monkeypatch,
        "interface Ethernet0\n ip address 203.0.113.40 255.255.255.0\n",
    )
    destination = _scope(db_path, "Restart Lab")
    assign_device_scope(
        db_path, run_id=run_id, scope_id=destination["scope_id"], actor="analyst",
        reason="Exercise restart recovery", whole_collection_confirmed=True,
    )
    assert jobs.dispatch_next_pipeline_intake(db_path) is True
    claim = jobs.claim_next_derived_job(db_path)
    assert claim is not None
    assert jobs.recover_interrupted_derived_jobs(db_path) == 1
    monkeypatch.setattr(jobs, "start_derived_job_worker", lambda *args, **kwargs: None)
    retried = jobs.retry_derived_job(
        db_path, claim["job_id"], request_token="restart-retry",
        requested_by="observation-analyst",
    )
    assert retried["latest_attempt"]["state"] == "queued"
    assert jobs.run_next_derived_job(db_path, tmp_path) is True
    status = get_device_observation_status(db_path, run_id)
    assert status["state"] == "completed"
    assert get_device_interface_receipts(db_path, run_id)["pagination"]["total"] == 1


def test_mixed_routing_contexts_cannot_publish_under_one_scope(tmp_path, monkeypatch):
    configuration = """interface Ethernet0
 vrf forwarding RED
 ip address 10.0.0.1 255.255.255.0
interface Ethernet1
 vrf forwarding BLUE
 ip address 10.0.0.1 255.255.255.0
"""
    db_path, run_id = _complete_summary(tmp_path, monkeypatch, configuration)
    destination = _scope(db_path, "Mixed Context Lab")
    assign_device_scope(
        db_path, run_id=run_id, scope_id=destination["scope_id"], actor="analyst",
        reason="Exercise mixed context rejection", whole_collection_confirmed=True,
    )
    assert jobs.dispatch_next_pipeline_intake(db_path) is True
    assert jobs.run_next_derived_job(db_path, tmp_path) is True
    status = get_device_observation_status(db_path, run_id)
    assert status["state"] == "failed"
    assert "more than one routing context" in status["error"]
    with connect_database(db_path, read_only=True) as db:
        assert db.execute("SELECT COUNT(*) FROM device_interface_assessments").fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM device_interface_receipts").fetchone()[0] == 0


def test_replay_rejects_changed_receipt_facts(tmp_path, monkeypatch):
    configuration = "interface Ethernet0\n ip address 10.0.0.1 255.255.255.0\n"
    db_path, run_id = _complete_summary(tmp_path, monkeypatch, configuration)
    destination = _scope(db_path, "Replay Lab")
    assignment = _assign_and_process(db_path, tmp_path, run_id, destination)
    status = get_device_observation_status(db_path, run_id)
    snapshot = capture_device_interface_source(db_path, run_id, tmp_path)
    changed = extract_device_interface_addresses(
        snapshot["content"].decode("utf-8", errors="replace")
    )
    changed["receipts"][0] = {
        **changed["receipts"][0], "address": "10.0.0.2",
    }
    with connect_database(db_path, read_only=True) as db:
        summary_result_id = db.execute(
            "SELECT summary_result_id FROM device_interface_assessments WHERE assessment_id = ?",
            (status["assessment"]["assessment_id"],),
        ).fetchone()[0]
    with pytest.raises(DeviceObservationConflict, match="receipt replay changed"):
        publish_device_interface_assessment(
            db_path,
            assignment_id=assignment["assignment_id"],
            summary_result_id=summary_result_id,
            snapshot=snapshot,
            extracted=changed,
        )
    assert get_device_interface_receipts(db_path, run_id)["receipts"][0]["address"] == "10.0.0.1"
