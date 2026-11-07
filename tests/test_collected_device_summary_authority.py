import json
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.database import connect_database
from app.device_collection_authority import (
    COLLECTED_DEVICE_SELECTION_CONTRACT,
    DeviceCollectionIncomplete,
    DeviceCollectionIntegrityError,
    get_device_collection_authority,
)
from app import device_configs
from app import derived_jobs as jobs
from app.device_evidence_catalog import (
    DeviceEvidenceCatalogError,
    select_latest_device_evidence,
)
from app.device_summary_result import analyze_collected_device_summary
from app.derived_contracts import (
    DEVICE_SUMMARY_PARAMETERS,
    DEVICE_SUMMARY_SCHEMA_VERSION,
    DEVICE_SUMMARY_VERSION,
    LEGACY_DEVICE_SUMMARY_PARAMETERS,
    LEGACY_DEVICE_SUMMARY_SCHEMA_VERSION,
    LEGACY_DEVICE_SUMMARY_VERSION,
    PREVIOUS_DEVICE_SUMMARY_PARAMETERS,
    PREVIOUS_DEVICE_SUMMARY_SCHEMA_VERSION,
    PREVIOUS_DEVICE_SUMMARY_VERSION,
)
from app.evidence_retirement import init_evidence_retirement_storage, retire_evidence
from app.evidence_retirement_sources import DEVICE_COLLECTION, device_collection_adapter


CONFIG = """===== show running-config =====
hostname verified-router
interface GigabitEthernet0/1
 ip address 10.88.0.1 255.255.255.0
ip route 0.0.0.0 0.0.0.0 192.0.2.1
===== show startup-config =====
hostname verified-router
interface GigabitEthernet0/1
 ip address 10.88.0.1 255.255.255.0
ip route 0.0.0.0 0.0.0.0 192.0.2.1
"""


def finalized_collection(tmp_path, monkeypatch, *, run_id="1" * 32, history=True):
    db_path = tmp_path / "analyzer.db"
    config_dir = tmp_path / "device-configs"
    run_dir = config_dir / run_id
    run_dir.mkdir(parents=True)
    init_evidence_retirement_storage(db_path)
    monkeypatch.setattr(device_configs, "DB_PATH", db_path)
    monkeypatch.setattr(device_configs, "CONFIG_DIR", config_dir)
    (run_dir / "router-config.txt").write_text(CONFIG)
    (run_dir / "stdout.txt").write_text("bounded response preview\n")
    (run_dir / "stderr.txt").write_text("")
    if history is not None:
        (run_dir / "command-history.txt").write_text(
            "10 show version\n11 configure terminal\n" if history else ""
        )
    manifest = {
        "run_id": run_id,
        "created_at": "2026-10-03T20:00:00+00:00",
        "completed_at": "2026-10-03T20:01:00+00:00",
        "operator": "analyst",
        "originating_host": "nct-test",
        "vendor": "cisco",
        "device_type": "router",
        "device_address": "10.88.0.1",
        "device_name": "Verified Router",
        "operation": "configuration_pull",
        "status": "completed",
        "output_complete": True,
        "output_truncated": False,
        "command_history_truncated": False,
        "command_history_status": "captured" if history else "unavailable",
        "command_history_artifact": "command-history.txt" if history is not None else None,
        "history_command": "show history",
        "commands": ["show running-config", "show startup-config", "show history"],
        "local_output_name": "router-config.txt",
    }
    (run_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    assert device_configs._finalize_device_collection(run_dir, manifest) is True
    return db_path, config_dir, run_dir, manifest


def test_completed_ssh_collection_uses_verified_reusable_summary(tmp_path, monkeypatch):
    db_path, _, run_dir, manifest = finalized_collection(tmp_path, monkeypatch)
    run_id = manifest["run_id"]
    authority = get_device_collection_authority(db_path, run_id)
    assert authority["state"] == "active"
    assert authority["selection_contract"] == COLLECTED_DEVICE_SELECTION_CONTRACT

    first = analyze_collected_device_summary(db_path, run_id, run_dir)
    warm = analyze_collected_device_summary(db_path, run_id, run_dir)
    assert first["payload"]["counts"]["routes"] == 1
    assert first["source_content"]["raw_output"] == "bounded response preview\n"
    assert first["payload"]["command_history"]["entries"][1]["line_number"] == 2
    assert warm["result_id"] == first["result_id"]
    assert warm["reused"] is True
    with connect_database(db_path, read_only=True) as db:
        assert db.execute(
            "SELECT COUNT(*) FROM device_collection_authority_inputs WHERE run_id = ?",
            (run_id,),
        ).fetchone()[0] == 3
        assert db.execute(
            "SELECT COUNT(*) FROM derived_results WHERE family = 'device_collection_summary'"
        ).fetchone()[0] == 1
        assert db.execute(
            "SELECT COUNT(*) FROM derived_result_observation_links WHERE result_id = ?",
            (first["result_id"],),
        ).fetchone()[0] == 3


def test_changed_history_parser_uses_new_contract_without_rewriting_legacy_result(
    tmp_path, monkeypatch,
):
    db_path, _, run_dir, manifest = finalized_collection(tmp_path, monkeypatch)
    run_id = manifest["run_id"]
    legacy = analyze_collected_device_summary(
        db_path,
        run_id,
        run_dir,
        analysis_version=LEGACY_DEVICE_SUMMARY_VERSION,
        payload_schema_version=LEGACY_DEVICE_SUMMARY_SCHEMA_VERSION,
        parameters=dict(LEGACY_DEVICE_SUMMARY_PARAMETERS),
    )
    current = analyze_collected_device_summary(db_path, run_id, run_dir)
    assert legacy["result_id"] != current["result_id"]
    assert legacy["analysis_version"] == LEGACY_DEVICE_SUMMARY_VERSION
    assert current["analysis_version"] == DEVICE_SUMMARY_VERSION
    with connect_database(db_path, read_only=True) as db:
        rows = db.execute(
            """SELECT analysis_version, payload_schema_version
               FROM derived_results WHERE family = 'device_collection_summary'
               ORDER BY analysis_version"""
        ).fetchall()
    assert [tuple(row) for row in rows] == [
        (LEGACY_DEVICE_SUMMARY_VERSION, LEGACY_DEVICE_SUMMARY_SCHEMA_VERSION),
        (DEVICE_SUMMARY_VERSION, 2),
    ]


def test_read_only_analysis_can_open_completed_legacy_summary(
    tmp_path, monkeypatch,
):
    from app import derived_jobs, device_analysis, pipeline_intake

    db_path, config_dir, run_dir, manifest = finalized_collection(tmp_path, monkeypatch)
    run_id = manifest["run_id"]
    legacy = analyze_collected_device_summary(
        db_path,
        run_id,
        run_dir,
        analysis_version=LEGACY_DEVICE_SUMMARY_VERSION,
        payload_schema_version=LEGACY_DEVICE_SUMMARY_SCHEMA_VERSION,
        parameters=dict(LEGACY_DEVICE_SUMMARY_PARAMETERS),
    )
    monkeypatch.setattr(
        pipeline_intake, "get_admission_intent", lambda *_args, **_kwargs: {"marked": True}
    )
    monkeypatch.setattr(
        derived_jobs,
        "device_summary_job_for_run",
        lambda *_args, **_kwargs: {
            "latest_attempt": {
                "state": "completed",
                "output_kind": "derived_result",
                "output_id": legacy["result_id"],
            }
        },
    )
    summary, loaded_manifest = device_analysis._device_summary_snapshot(
        run_id, config_dir, db_path, read_only_verified=True
    )
    assert summary["counts"]["routes"] == 1
    assert loaded_manifest["run_id"] == run_id


def test_corrected_parser_does_not_reuse_previous_summary_and_previous_stays_readable(
    tmp_path, monkeypatch,
):
    from app import derived_jobs, device_analysis, device_summary_result, pipeline_intake

    monkeypatch.setattr(derived_jobs, "start_derived_job_worker", lambda *_args: None)
    db_path, config_dir, run_dir, manifest = finalized_collection(tmp_path, monkeypatch)
    run_id = manifest["run_id"]
    current_builder = device_summary_result._summary_payload

    def prior_builder(snapshot):
        payload = current_builder(snapshot)
        payload["interfaces"] = [
            *payload["interfaces"],
            {"name": "IP-Address", "addresses": [], "source": "table heading"},
        ]
        payload["counts"]["interfaces"] = len(payload["interfaces"])
        return payload

    monkeypatch.setattr(device_summary_result, "_summary_payload", prior_builder)
    previous = analyze_collected_device_summary(
        db_path,
        run_id,
        run_dir,
        analysis_version=PREVIOUS_DEVICE_SUMMARY_VERSION,
        payload_schema_version=PREVIOUS_DEVICE_SUMMARY_SCHEMA_VERSION,
        parameters=dict(PREVIOUS_DEVICE_SUMMARY_PARAMETERS),
    )
    assert any(item["name"] == "IP-Address" for item in previous["payload"]["interfaces"])

    monkeypatch.setattr(device_summary_result, "_summary_payload", current_builder)
    current = analyze_collected_device_summary(db_path, run_id, run_dir)
    assert current["result_id"] != previous["result_id"]
    assert current["analysis_version"] == DEVICE_SUMMARY_VERSION
    assert all(item["name"] != "IP-Address" for item in current["payload"]["interfaces"])

    monkeypatch.setattr(
        pipeline_intake, "get_admission_intent", lambda *_args, **_kwargs: {"marked": True}
    )
    monkeypatch.setattr(
        derived_jobs,
        "device_summary_job_for_run",
        lambda *_args, **_kwargs: {
            "latest_attempt": {
                "state": "completed",
                "output_kind": "derived_result",
                "output_id": previous["result_id"],
            }
        },
    )
    legacy_summary, _loaded_manifest = device_analysis._device_summary_snapshot(
        run_id, config_dir, db_path, read_only_verified=True,
    )
    assert any(item["name"] == "IP-Address" for item in legacy_summary["interfaces"])


def test_startup_recovery_queues_current_summary_for_completed_previous_contract(
    tmp_path, monkeypatch,
):
    from app import derived_jobs, device_summary_result, pipeline_intake

    current_contract = {
        "version": DEVICE_SUMMARY_VERSION,
        "schema": DEVICE_SUMMARY_SCHEMA_VERSION,
        "parameters": DEVICE_SUMMARY_PARAMETERS,
    }
    monkeypatch.setattr(derived_jobs, "start_derived_job_worker", lambda *_args: None)
    for module in (pipeline_intake, derived_jobs, device_summary_result):
        monkeypatch.setattr(module, "DEVICE_SUMMARY_VERSION", PREVIOUS_DEVICE_SUMMARY_VERSION)
        monkeypatch.setattr(
            module, "DEVICE_SUMMARY_SCHEMA_VERSION", PREVIOUS_DEVICE_SUMMARY_SCHEMA_VERSION,
        )
        monkeypatch.setattr(
            module, "DEVICE_SUMMARY_PARAMETERS", PREVIOUS_DEVICE_SUMMARY_PARAMETERS,
        )

    db_path, _, _, manifest = finalized_collection(tmp_path, monkeypatch)
    run_id = manifest["run_id"]
    retired_run_id = "2" * 32
    finalized_collection(tmp_path, monkeypatch, run_id=retired_run_id)
    assert derived_jobs.dispatch_next_pipeline_intake(db_path) is True
    assert derived_jobs.run_next_derived_job(db_path, tmp_path) is True
    assert derived_jobs.dispatch_next_pipeline_intake(db_path) is True
    assert derived_jobs.run_next_derived_job(db_path, tmp_path) is True
    previous_job = derived_jobs.device_summary_job_for_run(db_path, run_id)
    assert previous_job["target_analysis_version"] == PREVIOUS_DEVICE_SUMMARY_VERSION
    assert previous_job["latest_attempt"]["state"] == "completed"
    retired_previous_job = derived_jobs.device_summary_job_for_run(db_path, retired_run_id)
    assert retired_previous_job["target_analysis_version"] == PREVIOUS_DEVICE_SUMMARY_VERSION
    assert retired_previous_job["latest_attempt"]["state"] == "completed"
    retire_evidence(
        db_path,
        source_family=DEVICE_COLLECTION,
        encounter_id=retired_run_id,
        actor="contract-recovery-test",
        reason="prove retired historical evidence is not recalculated",
        adapter=device_collection_adapter(),
    )

    for module in (pipeline_intake, derived_jobs, device_summary_result):
        monkeypatch.setattr(module, "DEVICE_SUMMARY_VERSION", current_contract["version"])
        monkeypatch.setattr(module, "DEVICE_SUMMARY_SCHEMA_VERSION", current_contract["schema"])
        monkeypatch.setattr(module, "DEVICE_SUMMARY_PARAMETERS", current_contract["parameters"])

    assert derived_jobs.recover_outdated_device_summary_jobs(db_path) == [run_id]
    queued = derived_jobs.device_summary_job_for_run(db_path, run_id)
    assert queued["target_analysis_version"] == DEVICE_SUMMARY_VERSION
    assert queued["latest_attempt"]["state"] == "queued"
    assert derived_jobs.run_next_derived_job(db_path, tmp_path) is True
    completed = derived_jobs.device_summary_job_for_run(db_path, run_id)
    assert completed["target_analysis_version"] == DEVICE_SUMMARY_VERSION
    assert completed["latest_attempt"]["state"] == "completed"
    assert derived_jobs.recover_outdated_device_summary_jobs(db_path) == []
    with connect_database(db_path, read_only=True) as db:
        assert db.execute(
            """SELECT COUNT(*) FROM pipeline_jobs
                 WHERE source_run_id=? AND target_analysis_version=?""",
            (retired_run_id, DEVICE_SUMMARY_VERSION),
        ).fetchone()[0] == 0


def test_startup_recovery_isolates_one_invalid_collection(
    tmp_path, monkeypatch, caplog,
):
    from app import derived_jobs, device_summary_result, pipeline_intake

    current_contract = {
        "version": DEVICE_SUMMARY_VERSION,
        "schema": DEVICE_SUMMARY_SCHEMA_VERSION,
        "parameters": DEVICE_SUMMARY_PARAMETERS,
    }
    monkeypatch.setattr(derived_jobs, "start_derived_job_worker", lambda *_args: None)
    for module in (pipeline_intake, derived_jobs, device_summary_result):
        monkeypatch.setattr(module, "DEVICE_SUMMARY_VERSION", PREVIOUS_DEVICE_SUMMARY_VERSION)
        monkeypatch.setattr(
            module, "DEVICE_SUMMARY_SCHEMA_VERSION", PREVIOUS_DEVICE_SUMMARY_SCHEMA_VERSION,
        )
        monkeypatch.setattr(
            module, "DEVICE_SUMMARY_PARAMETERS", PREVIOUS_DEVICE_SUMMARY_PARAMETERS,
        )

    invalid_run_id = "0" * 32
    valid_run_id = "1" * 32
    db_path, _, _, _manifest = finalized_collection(
        tmp_path, monkeypatch, run_id=invalid_run_id,
    )
    finalized_collection(tmp_path, monkeypatch, run_id=valid_run_id)
    for _run_id in (invalid_run_id, valid_run_id):
        assert derived_jobs.dispatch_next_pipeline_intake(db_path) is True
        assert derived_jobs.run_next_derived_job(db_path, tmp_path) is True

    for module in (pipeline_intake, derived_jobs, device_summary_result):
        monkeypatch.setattr(module, "DEVICE_SUMMARY_VERSION", current_contract["version"])
        monkeypatch.setattr(module, "DEVICE_SUMMARY_SCHEMA_VERSION", current_contract["schema"])
        monkeypatch.setattr(module, "DEVICE_SUMMARY_PARAMETERS", current_contract["parameters"])

    real_snapshot = derived_jobs._device_summary_snapshot

    def one_invalid_snapshot(db, candidate_run_id, *, intent_kind):
        if candidate_run_id == invalid_run_id:
            raise ValueError("invalid retained authority for test")
        return real_snapshot(db, candidate_run_id, intent_kind=intent_kind)

    monkeypatch.setattr(derived_jobs, "_device_summary_snapshot", one_invalid_snapshot)
    with caplog.at_level("WARNING"):
        assert derived_jobs.recover_outdated_device_summary_jobs(db_path) == [valid_run_id]
    assert invalid_run_id in caplog.text
    queued = derived_jobs.device_summary_job_for_run(db_path, valid_run_id)
    assert queued["target_analysis_version"] == DEVICE_SUMMARY_VERSION
    assert queued["latest_attempt"]["state"] == "queued"


def test_interactive_finalization_uses_same_verified_authority(tmp_path, monkeypatch):
    db_path = tmp_path / "analyzer.db"
    init_evidence_retirement_storage(db_path)
    config_dir = tmp_path / "device-configs"
    monkeypatch.setattr(device_configs, "DB_PATH", db_path)
    monkeypatch.setattr(device_configs, "CONFIG_DIR", config_dir)
    monkeypatch.setattr(device_configs, "_close_interactive_resources", lambda session: None)
    monkeypatch.setattr(device_configs, "capture_is_valid", lambda run_dir: True)
    monkeypatch.setattr(jobs, "start_derived_job_worker", lambda *args, **kwargs: None)
    plan = device_configs.DeviceConfigPlan(
        vendor="cisco", device_type="router", device_address="10.88.0.1",
        username="analyst", authentication_mode="password_prompt",
        operator="analyst", originating_host="nct-test",
        accountability_interface="eth0",
    )
    preview = device_configs.build_plan(plan)
    run_dir = config_dir / preview["run_id"]
    run_dir.mkdir(parents=True)
    fence = device_configs.acquire_device_contact_fence(
        preview["run_id"],
        operation_kind="interactive_configuration_pull",
        subject_key="10.88.0.1:22",
        request={"device_address": "10.88.0.1"},
        created_by="analyst",
        db_path=db_path,
    )
    work_dir = device_configs._device_contact_staging_dir(run_dir, fence)
    (work_dir / preview["local_output_name"]).write_text(CONFIG)
    (work_dir / "stdout.txt").write_text("preview\n")
    (work_dir / "command-history.txt").write_text("10 show version\n")
    manifest = device_configs.manifest_for(
        plan, preview, "running", operation="interactive_configuration_pull"
    )
    session = SimpleNamespace(
        session_id="interactive-test", plan=plan, preview=preview,
        retained_run_dir=run_dir, run_dir=work_dir, manifest=manifest,
        fence=fence, closed=False,
    )
    device_configs.publish_device_contact_starting(run_dir, manifest, fence)
    device_configs.publish_device_contact_active(run_dir, manifest, fence)
    result = device_configs._finish_interactive_session(
        session,
        status="completed",
        stderr="",
        failure_class=None,
        exit_code=0,
        extra={
            "local_output_name": preview["local_output_name"],
            "output_truncated": False,
            "command_history_status": "captured",
            "command_history_truncated": False,
            "command_history_artifact": "command-history.txt",
        },
    )
    assert result["summary_verification_status"] == "verified"
    authority = get_device_collection_authority(db_path, preview["run_id"])
    assert authority["state"] == "active"
    assert authority["selection_contract"] == COLLECTED_DEVICE_SELECTION_CONTRACT

    retained_manifest = json.loads((run_dir / "manifest.json").read_text())
    with connect_database(db_path, read_only=True) as db:
        catalog_manifest, terminal_manifest = db.execute(
            """SELECT catalog.manifest_json, contact.terminal_manifest_json
                 FROM device_evidence_catalog catalog
                 JOIN device_contact_runs contact ON contact.run_id = catalog.run_id
                WHERE catalog.run_id = ?""",
            (preview["run_id"],),
        ).fetchone()
    assert json.loads(catalog_manifest) == retained_manifest
    assert json.loads(terminal_manifest) == retained_manifest
    assert retained_manifest["contact_phase"] == "complete"

    assert jobs.dispatch_next_pipeline_intake(db_path) is True
    assert jobs.run_next_derived_job(db_path, tmp_path) is True
    selected, descriptor = select_latest_device_evidence(db_path, config_dir)
    assert [item["run_id"] for item in selected] == [preview["run_id"]]
    assert descriptor["selected_run_ids"] == [preview["run_id"]]

    retained_manifest["operator_note"] = "out-of-band edit"
    (run_dir / "manifest.json").write_text(json.dumps(retained_manifest))
    with pytest.raises(DeviceEvidenceCatalogError, match="changed after selector indexing"):
        select_latest_device_evidence(db_path, config_dir)


def test_empty_history_file_wins_over_embedded_history(tmp_path, monkeypatch):
    db_path, _, run_dir, manifest = finalized_collection(
        tmp_path, monkeypatch, history=False
    )
    result = analyze_collected_device_summary(
        db_path, manifest["run_id"], run_dir
    )
    assert result["payload"]["command_history"]["status"] == "unavailable"
    with connect_database(db_path, read_only=True) as db:
        row = db.execute(
            """SELECT source_kind, filename, size_bytes
               FROM device_collection_authority_inputs
               WHERE run_id = ? AND input_role = 'command_history'""",
            (manifest["run_id"],),
        ).fetchone()
    assert row == ("artifact_file", "command-history.txt", 0)


def test_missing_history_uses_frozen_absence_descriptor(tmp_path, monkeypatch):
    db_path, _, run_dir, manifest = finalized_collection(
        tmp_path, monkeypatch, history=None
    )
    result = analyze_collected_device_summary(
        db_path, manifest["run_id"], run_dir
    )
    assert result["payload"]["command_history"]["status"] == "unavailable"
    with connect_database(db_path, read_only=True) as db:
        row = db.execute(
            """SELECT source_kind, filename
               FROM device_collection_authority_inputs
               WHERE run_id = ? AND input_role = 'command_history'""",
            (manifest["run_id"],),
        ).fetchone()
    assert row == ("absent", None)


def test_changed_or_newly_preferred_file_is_an_integrity_conflict(tmp_path, monkeypatch):
    db_path, _, run_dir, manifest = finalized_collection(tmp_path, monkeypatch)
    (run_dir / "router-config.txt").unlink()
    (run_dir / "router-config.txt").write_text(CONFIG.replace("10.88.0.1", "10.89.0.1"))
    with pytest.raises(ValueError, match="exact-content verification"):
        analyze_collected_device_summary(db_path, manifest["run_id"], run_dir)

    db_path, _, run_dir, manifest = finalized_collection(
        tmp_path, monkeypatch, run_id="2" * 32
    )
    (run_dir / "aaa-config.txt").write_text(CONFIG)
    with pytest.raises(ValueError, match="registration is incomplete"):
        analyze_collected_device_summary(db_path, manifest["run_id"], run_dir)


def test_verification_failure_retries_locally_without_duplicate_observations(
    tmp_path, monkeypatch,
):
    monkeypatch.setattr(jobs, "start_derived_job_worker", lambda *_args, **_kwargs: None)
    original_activate = device_configs.activate_collected_device_authority
    monkeypatch.setattr(
        device_configs,
        "activate_collected_device_authority",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            DeviceCollectionIntegrityError("simulated activation interruption")
        ),
    )
    db_path = tmp_path / "analyzer.db"
    init_evidence_retirement_storage(db_path)
    config_dir = tmp_path / "device-configs"
    run_id = "3" * 32
    run_dir = config_dir / run_id
    run_dir.mkdir(parents=True)
    monkeypatch.setattr(device_configs, "DB_PATH", db_path)
    monkeypatch.setattr(device_configs, "CONFIG_DIR", config_dir)
    (run_dir / "router-config.txt").write_text(CONFIG)
    (run_dir / "stdout.txt").write_text("preview\n")
    manifest = {
        "run_id": run_id, "created_at": "2026-10-03T20:00:00+00:00",
        "completed_at": "2026-10-03T20:01:00+00:00", "operator": "analyst",
        "vendor": "cisco", "device_type": "router", "device_address": "10.88.0.1",
        "operation": "configuration_pull", "status": "completed",
        "output_complete": True, "output_truncated": False,
        "command_history_truncated": False, "commands": ["show running-config"],
        "history_command": "show history", "local_output_name": "router-config.txt",
    }
    (run_dir / "manifest.json").write_text(json.dumps(manifest))
    assert device_configs._finalize_device_collection(run_dir, manifest) is False
    assert manifest["status"] == "completed"
    assert manifest["summary_verification_status"] == "conflict"
    assert get_device_collection_authority(db_path, run_id)["state"] == "preparing"
    with connect_database(db_path, read_only=True) as db:
        before = db.execute(
            "SELECT COUNT(*) FROM artifact_observations WHERE source_ref = ?", (run_id,)
        ).fetchone()[0]

    monkeypatch.setattr(
        device_configs, "activate_collected_device_authority", original_activate
    )
    changed_config = run_dir / "router-config.txt"
    changed_config.unlink()
    changed_config.write_text(CONFIG.replace("10.88.0.1", "10.89.0.1"))
    with pytest.raises(HTTPException) as rejected:
        device_configs.retry_summary_verification(run_id)
    assert rejected.value.status_code == 409
    assert "could not verify" in rejected.value.detail
    assert get_device_collection_authority(db_path, run_id)["state"] == "preparing"
    with connect_database(db_path, read_only=True) as db:
        unchanged = db.execute(
            "SELECT COUNT(*) FROM artifact_observations WHERE source_ref = ?", (run_id,)
        ).fetchone()[0]
    assert unchanged == before

    changed_config.unlink()
    changed_config.write_text(CONFIG)
    retried = device_configs.retry_summary_verification(run_id)
    assert retried["status"] == "verified"
    assert retried["network_contacted"] is False
    assert get_device_collection_authority(db_path, run_id)["state"] == "active"
    with connect_database(db_path, read_only=True) as db:
        after = db.execute(
            "SELECT COUNT(*) FROM artifact_observations WHERE source_ref = ?", (run_id,)
        ).fetchone()[0]
    assert after == before


def test_file_replacement_between_freeze_and_registration_cannot_activate(
    tmp_path, monkeypatch,
):
    original_register = device_configs.register_finalized_files
    replaced = False

    def replace_before_registration(*args, **kwargs):
        nonlocal replaced
        run_dir = args[1]
        if kwargs.get("expected_files") is not None and not replaced:
            path = run_dir / "router-config.txt"
            path.unlink()
            path.write_text(CONFIG.replace("10.88.0.1", "10.89.0.1"))
            replaced = True
        return original_register(*args, **kwargs)

    monkeypatch.setattr(
        device_configs, "register_finalized_files", replace_before_registration
    )
    db_path = tmp_path / "analyzer.db"
    init_evidence_retirement_storage(db_path)
    config_dir = tmp_path / "device-configs"
    run_id = "5" * 32
    run_dir = config_dir / run_id
    run_dir.mkdir(parents=True)
    monkeypatch.setattr(device_configs, "DB_PATH", db_path)
    monkeypatch.setattr(device_configs, "CONFIG_DIR", config_dir)
    (run_dir / "router-config.txt").write_text(CONFIG)
    (run_dir / "stdout.txt").write_text("preview\n")
    manifest = {
        "run_id": run_id, "created_at": "2026-10-03T20:00:00+00:00",
        "completed_at": "2026-10-03T20:01:00+00:00", "operator": "analyst",
        "vendor": "cisco", "device_type": "router", "device_address": "10.88.0.1",
        "operation": "configuration_pull", "status": "completed",
        "output_complete": True, "output_truncated": False,
        "command_history_truncated": False, "commands": ["show running-config"],
        "history_command": "show history", "local_output_name": "router-config.txt",
    }
    (run_dir / "manifest.json").write_text(json.dumps(manifest))

    assert device_configs._finalize_device_collection(run_dir, manifest) is False
    assert manifest["summary_verification_status"] == "conflict"
    assert get_device_collection_authority(db_path, run_id)["state"] == "preparing"
    frozen = manifest["summary_verification_contract"]["files"]
    expected = next(item for item in frozen if item["filename"] == "router-config.txt")
    with connect_database(db_path, read_only=True) as db:
        rows = db.execute(
            "SELECT sha256 FROM artifact_observations WHERE source_ref = ?",
            (run_id,),
        ).fetchall()
    assert expected["sha256"] not in {row[0] for row in rows}


@pytest.mark.parametrize(
    "status,output_complete,output_truncated",
    [("failed", False, False), ("completed", False, True)],
)
def test_incomplete_collections_never_fall_back_to_old_analysis(
    tmp_path, monkeypatch, status, output_complete, output_truncated,
):
    db_path = tmp_path / "analyzer.db"
    init_evidence_retirement_storage(db_path)
    config_dir = tmp_path / "device-configs"
    run_id = "4" * 32
    run_dir = config_dir / run_id
    run_dir.mkdir(parents=True)
    monkeypatch.setattr(device_configs, "DB_PATH", db_path)
    monkeypatch.setattr(device_configs, "CONFIG_DIR", config_dir)
    (run_dir / "router-config.txt").write_text(CONFIG)
    manifest = {
        "run_id": run_id, "created_at": "2026-10-03T20:00:00+00:00",
        "completed_at": "2026-10-03T20:01:00+00:00", "operator": "analyst",
        "vendor": "cisco", "operation": "configuration_pull", "status": status,
        "output_complete": output_complete, "output_truncated": output_truncated,
        "command_history_truncated": False,
    }
    (run_dir / "manifest.json").write_text(json.dumps(manifest))
    assert device_configs._finalize_device_collection(run_dir, manifest) is False
    assert get_device_collection_authority(db_path, run_id) is None
    with pytest.raises(DeviceCollectionIncomplete, match="not eligible"):
        from app.device_analysis import _device_summary_snapshot

        _device_summary_snapshot(run_id, config_dir, db_path)
