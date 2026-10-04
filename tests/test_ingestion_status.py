from __future__ import annotations

import json

from fastapi.testclient import TestClient

from app import derived_jobs as jobs
from app.artifacts import register_artifact_bytes
from app.database import connect_database
from app.device_observations import assign_device_scope
from app.evidence_scope_assignments import correct_artifact_scope
from app.evidence_scope_assignments import assign_artifact_scope
from app.ingestion_status import list_ingestion_status
from app.main import app
from app.network_scopes import create_network_scope
from app.pipeline_intake import (
    COLLECTED_DEVICE_INTENT,
    NMAP_INGESTION_POLICY_VERSION,
    init_pipeline_intake_storage,
    record_device_summary_intent,
)
from tests.test_device_observations import _assign_and_process, _complete_summary, _upload
from tests.test_collected_device_summary_authority import finalized_collection
from tests.test_pipeline_intake import XML, completed_automated_run, manual_assignment


def _item(page, source_kind):
    return next(item for item in page["items"] if item["source_kind"] == source_kind)


def test_missing_database_is_a_bounded_empty_snapshot(tmp_path):
    page = list_ingestion_status(tmp_path / "missing.db", limit=999, offset=-5)
    assert page == {
        "items": [], "total": 0, "limit": 100, "offset": 0,
        "has_more": False,
        "counts": {"ready": 0, "processing": 0, "needs_scope": 0, "needs_attention": 0},
        "historical_unadopted": {
            "manual_nmap": 0, "automated_nmap": 0, "device": 0, "total": 0,
        },
        "snapshot": "read-only metadata transaction",
    }


def test_duplicate_manual_encounters_stay_separate_and_history_is_not_adopted(tmp_path):
    db_path = tmp_path / "analyzer.db"
    for position in range(2):
        register_artifact_bytes(
            db_path=db_path, content=XML, source_kind="nmap_import",
            source_ref=f"upload:{position}", original_filename=f"same-{position}.xml",
            actor="analyst", observed_at=f"2030-01-01T00:00:0{position}+00:00",
            pipeline_policy_version=NMAP_INGESTION_POLICY_VERSION,
        )
    register_artifact_bytes(
        db_path=db_path, content=XML, source_kind="nmap_import",
        source_ref="historical", original_filename="historical.xml",
        actor="analyst", observed_at="2029-01-01T00:00:00+00:00",
        pipeline_policy_version=None,
    )

    first = list_ingestion_status(db_path, limit=1)
    second = list_ingestion_status(db_path, limit=1, offset=1)
    assert first["total"] == 2 and first["has_more"] is True
    assert second["has_more"] is False
    assert first["items"][0]["encounter_id"] != second["items"][0]["encounter_id"]
    assert first["items"][0]["status"] == second["items"][0]["status"] == "needs_scope"
    assert first["historical_unadopted"] == {
        "manual_nmap": 1, "automated_nmap": 0, "device": 0, "total": 1,
    }


def test_manual_and_automated_nmap_reach_verified_ready_outputs(tmp_path):
    manual_dir, automated_dir = tmp_path / "manual", tmp_path / "automated"
    manual_dir.mkdir(); automated_dir.mkdir()
    manual_db, _, _, _ = manual_assignment(manual_dir)
    assert list_ingestion_status(manual_db)["items"][0]["status"] == "processing"
    assert jobs.dispatch_next_pipeline_intake(manual_db) is True
    assert jobs.run_next_derived_job(manual_db, manual_dir) is True
    manual = list_ingestion_status(manual_db)["items"][0]
    assert manual["status"] == "ready"
    assert manual["stages"][-1]["output"]["kind"] == "entity_assessment"

    automated_db, run, _, _ = completed_automated_run(automated_dir)
    assert jobs.dispatch_next_pipeline_intake(automated_db) is True
    assert jobs.run_next_derived_job(automated_db, automated_dir) is True
    automated = _item(list_ingestion_status(automated_db), "nmap_scan_run")
    assert automated["source_id"] == run["run_id"]
    assert automated["status"] == "ready"
    assert automated["stages"][-1]["output"]["kind"] == "entity_assessment"


def test_device_upload_requires_scope_then_reaches_ready(tmp_path, monkeypatch):
    db_path, run_id = _complete_summary(
        tmp_path, monkeypatch,
        "interface Ethernet0\n ip address 10.20.30.1 255.255.255.0\n",
    )
    before = _item(list_ingestion_status(db_path), "device_manual_upload_authority")
    assert before["status"] == "needs_scope"
    assert next(stage for stage in before["stages"] if stage["key"] == "summary")["state"] == "completed"
    scope = create_network_scope(db_path, label="Device scope", created_by="admin")
    _assign_and_process(db_path, tmp_path, run_id, scope)
    after = _item(list_ingestion_status(db_path), "device_manual_upload_authority")
    assert after["status"] == "ready"
    assert after["stages"][-1]["output"]["kind"] == "device_interface_assessment"


def test_completed_device_collection_uses_same_status_contract(tmp_path, monkeypatch):
    db_path, _, _, manifest = finalized_collection(tmp_path, monkeypatch)
    init_pipeline_intake_storage(db_path)
    with connect_database(db_path) as db:
        record_device_summary_intent(
            db, manifest["run_id"], intent_kind=COLLECTED_DEVICE_INTENT,
        )
    jobs.stop_derived_job_worker(db_path)
    jobs.dispatch_next_pipeline_intake(db_path)
    jobs.run_next_derived_job(db_path, tmp_path)
    before = _item(list_ingestion_status(db_path), "device_collected_authority")
    assert before["status"] == "needs_scope"
    scope = create_network_scope(db_path, label="Collected device scope", created_by="admin")
    _assign_and_process(db_path, tmp_path, manifest["run_id"], scope)
    after = _item(list_ingestion_status(db_path), "device_collected_authority")
    assert after["status"] == "ready"
    assert [stage["state"] for stage in after["stages"]] == [
        "completed", "completed", "completed", "completed",
    ]


def test_interrupted_work_and_missing_completed_output_need_attention(tmp_path):
    interrupted_dir, missing_dir = tmp_path / "interrupted", tmp_path / "missing"
    interrupted_dir.mkdir(); missing_dir.mkdir()
    interrupted_db, _, _, _ = manual_assignment(interrupted_dir)
    assert jobs.dispatch_next_pipeline_intake(interrupted_db) is True
    claim = jobs.claim_next_derived_job(interrupted_db)
    assert claim is not None
    assert jobs.recover_interrupted_derived_jobs(interrupted_db) == 1
    interrupted = list_ingestion_status(interrupted_db)["items"][0]
    assert interrupted["status"] == "needs_attention"
    assert interrupted["stages"][-1]["state"] == "interrupted"

    missing_db, _, _, _ = manual_assignment(missing_dir)
    assert jobs.dispatch_next_pipeline_intake(missing_db) is True
    assert jobs.run_next_derived_job(missing_db, missing_dir) is True
    with connect_database(missing_db) as db:
        db.execute(
            "UPDATE pipeline_job_attempts SET output_id = 'missing-output' WHERE state = 'completed'"
        )
    missing = list_ingestion_status(missing_db)["items"][0]
    assert missing["status"] == "needs_attention"
    assert missing["stages"][-1]["state"] == "blocked"
    assert "exact saved output" in missing["stages"][-1]["detail"]


def test_scope_correction_during_request_cannot_mix_snapshot(tmp_path, monkeypatch):
    db_path, observation, original_scope, assignment = manual_assignment(tmp_path)
    replacement = create_network_scope(db_path, label="Replacement", created_by="admin")
    import app.ingestion_status as status_module
    original_builder = status_module._manual_nmap
    changed = False

    def correct_after_snapshot(db, marker):
        nonlocal changed
        if not changed:
            changed = True
            correct_artifact_scope(
                db_path, expected_assignment_id=assignment["assignment_id"],
                destination_scope_id=replacement["scope_id"], actor="reviewer",
                reason="Deterministic snapshot race", whole_artifact_confirmed=True,
            )
        return original_builder(db, marker)

    monkeypatch.setattr(status_module, "_manual_nmap", correct_after_snapshot)
    page = list_ingestion_status(db_path)
    scope_stage = next(stage for stage in page["items"][0]["stages"] if stage["key"] == "scope")
    assert original_scope["label"] in scope_stage["detail"]
    with connect_database(db_path, read_only=True) as db:
        current = db.execute(
            """SELECT scope_id FROM artifact_scope_assignments old
               WHERE artifact_observation_id = ? AND NOT EXISTS (
                 SELECT 1 FROM artifact_scope_assignments newer
                 WHERE newer.supersedes_assignment_id = old.assignment_id)""",
            (observation["observation_id"],),
        ).fetchone()
    assert current[0] == replacement["scope_id"]


def test_status_read_does_not_change_pipeline_records(tmp_path):
    db_path, _, _, _ = manual_assignment(tmp_path)
    tables = (
        "pipeline_intake_sources", "pipeline_admission_intents", "pipeline_jobs",
        "pipeline_job_attempts", "entity_assessments",
    )
    with connect_database(db_path, read_only=True) as db:
        before = {table: db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                  if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone()
                  else None for table in tables}
    list_ingestion_status(db_path)
    with connect_database(db_path, read_only=True) as db:
        after = {table: db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                 if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone()
                 else None for table in tables}
    assert after == before


def test_admission_cannot_borrow_another_encounters_completed_job(tmp_path):
    db_path = tmp_path / "analyzer.db"
    first = register_artifact_bytes(
        db_path=db_path, content=XML, source_kind="nmap_import",
        source_ref="first", original_filename="first.xml", actor="analyst",
        pipeline_policy_version=NMAP_INGESTION_POLICY_VERSION,
    )
    second = register_artifact_bytes(
        db_path=db_path, content=XML.replace(b"192.0.2.10", b"192.0.2.11"),
        source_kind="nmap_import", source_ref="second",
        original_filename="second.xml", actor="analyst",
        pipeline_policy_version=NMAP_INGESTION_POLICY_VERSION,
    )
    scope = create_network_scope(db_path, label="Borrow test", created_by="admin")
    first_assignment = assign_artifact_scope(
        db_path, artifact_observation_id=first["observation_id"],
        scope_id=scope["scope_id"], actor="analyst", reason="First source",
        whole_artifact_confirmed=True,
    )
    second_assignment = assign_artifact_scope(
        db_path, artifact_observation_id=second["observation_id"],
        scope_id=scope["scope_id"], actor="analyst", reason="Second source",
        whole_artifact_confirmed=True,
    )
    assert jobs.dispatch_next_pipeline_intake(db_path) is True
    assert jobs.run_next_derived_job(db_path, tmp_path) is True
    with connect_database(db_path) as db:
        completed_intent = db.execute(
            """SELECT source_id, admitted_job_id FROM pipeline_admission_intents
               WHERE intent_kind = 'manual_nmap_scope'
                 AND admitted_job_id IS NOT NULL LIMIT 1"""
        ).fetchone()
        borrowed_assignment = (
            second_assignment if completed_intent[0] == first_assignment["assignment_id"]
            else first_assignment
        )
        borrowed_observation = (
            second if borrowed_assignment["assignment_id"] == second_assignment["assignment_id"]
            else first
        )
        db.execute(
            """UPDATE pipeline_admission_intents
               SET state='admitted', activity_state='complete', admitted_job_id=?
               WHERE source_id=?""",
            (completed_intent[1], borrowed_assignment["assignment_id"]),
        )
    page = list_ingestion_status(db_path, limit=10)
    borrowed = next(
        item for item in page["items"]
        if item["source_id"] == borrowed_observation["observation_id"]
    )
    assert borrowed["status"] == "needs_attention"
    assert "does not match this exact evidence encounter" in borrowed["stages"][-1]["detail"]


def test_device_summary_requires_every_frozen_provenance_role(tmp_path, monkeypatch):
    db_path, run_id = _complete_summary(
        tmp_path, monkeypatch,
        "interface Ethernet0\n ip address 10.22.0.1 255.255.255.0\n",
    )
    job = jobs.device_summary_job_for_run(db_path, run_id)
    result_id = job["latest_attempt"]["output_id"]
    with connect_database(db_path) as db:
        db.execute(
            """DELETE FROM derived_result_observation_links
               WHERE result_id = ? AND input_role = 'configuration'""",
            (result_id,),
        )
    item = _item(list_ingestion_status(db_path), "device_manual_upload_authority")
    summary = next(stage for stage in item["stages"] if stage["key"] == "summary")
    assert summary["state"] == "blocked"
    assert item["status"] == "needs_attention"


def test_failed_scan_is_terminal_attention_not_scope_work(tmp_path):
    db_path, run, _, _ = completed_automated_run(tmp_path, finalize=False)
    manifest = dict(run)
    manifest["status"] = "failed"
    with connect_database(db_path) as db:
        db.execute(
            "UPDATE scan_runs SET status='failed', manifest_json=? WHERE run_id=?",
            (json.dumps(manifest), run["run_id"]),
        )
    item = _item(list_ingestion_status(db_path), "nmap_scan_run")
    assert item["status"] == "needs_attention"
    assert [stage["state"] for stage in item["stages"]] == [
        "failed", "not_applicable", "not_applicable",
    ]
    assert "Scope assignment cannot make" in item["stages"][1]["detail"]


def test_one_malformed_record_does_not_abort_status_page(tmp_path):
    db_path, run, _, _ = completed_automated_run(tmp_path, finalize=False)
    register_artifact_bytes(
        db_path=db_path, content=XML, source_kind="nmap_import",
        source_ref="healthy", original_filename="healthy.xml", actor="analyst",
        pipeline_policy_version=NMAP_INGESTION_POLICY_VERSION,
    )
    with connect_database(db_path) as db:
        db.execute(
            "UPDATE scan_runs SET manifest_json='not-json' WHERE run_id=?",
            (run["run_id"],),
        )
    page = list_ingestion_status(db_path, limit=10)
    assert len(page["items"]) == 2
    broken = next(item for item in page["items"] if item["source_id"] == run["run_id"])
    healthy = next(item for item in page["items"] if item["source_kind"] == "nmap_import_observation")
    assert broken["status"] == "needs_attention"
    assert broken["stages"][0]["key"] == "integrity"
    assert healthy["status"] == "needs_scope"


def test_duplicate_device_encounters_can_share_one_verified_summary(tmp_path, monkeypatch):
    configuration = "interface Ethernet0\n ip address 10.23.0.1 255.255.255.0\n"
    db_path, first_run = _complete_summary(tmp_path, monkeypatch, configuration)
    with TestClient(app) as client:
        response = _upload(client, configuration)
    assert response.status_code == 200, response.text
    second_run = response.json()["run_id"]
    assert jobs.dispatch_next_pipeline_intake(db_path) is True
    assert jobs.run_next_derived_job(db_path, tmp_path) is True
    first_job = jobs.device_summary_job_for_run(db_path, first_run)
    second_job = jobs.device_summary_job_for_run(db_path, second_run)
    assert first_job["latest_attempt"]["output_id"] == second_job["latest_attempt"]["output_id"]

    items = [
        item for item in list_ingestion_status(db_path, limit=10)["items"]
        if item["source_kind"] == "device_manual_upload_authority"
    ]
    assert len(items) == 2
    assert all(
        next(stage for stage in item["stages"] if stage["key"] == "summary")["state"]
        == "completed"
        for item in items
    )


def test_changed_descriptor_identity_blocks_device_summary_completion(tmp_path, monkeypatch):
    db_path, run_id = _complete_summary(
        tmp_path, monkeypatch,
        "interface Ethernet0\n ip address 10.24.0.1 255.255.255.0\n",
    )
    result_id = jobs.device_summary_job_for_run(db_path, run_id)["latest_attempt"]["output_id"]
    with connect_database(db_path) as db:
        row = db.execute(
            """SELECT input_kind, input_metadata_json FROM derived_result_inputs
               WHERE result_id=? AND input_role='selection_shape'""",
            (result_id,),
        ).fetchone()
        db.execute(
            "DELETE FROM derived_result_inputs WHERE result_id=? AND input_role='selection_shape'",
            (result_id,),
        )
        db.execute(
            """INSERT INTO derived_result_inputs(
                   result_id, input_role, input_kind, input_identity, input_metadata_json
               ) VALUES (?, 'selection_shape', ?, 'changed-descriptor-identity', ?)""",
            (result_id, row[0], row[1]),
        )

    item = _item(list_ingestion_status(db_path), "device_manual_upload_authority")
    summary = next(stage for stage in item["stages"] if stage["key"] == "summary")
    assert summary["state"] == "blocked"
    assert item["status"] == "needs_attention"


def test_non_object_job_definition_isolated_as_integrity_issue(tmp_path):
    db_path, _, _, _ = manual_assignment(tmp_path)
    assert jobs.dispatch_next_pipeline_intake(db_path) is True
    assert jobs.run_next_derived_job(db_path, tmp_path) is True
    with connect_database(db_path) as db:
        db.execute("UPDATE pipeline_jobs SET definition_json='[]'")

    page = list_ingestion_status(db_path)
    assert page["total"] == 1
    item = page["items"][0]
    assert item["status"] == "needs_attention"
    assert item["stages"][0]["key"] == "integrity"
    assert "must be a JSON object" in item["stages"][0]["detail"]
