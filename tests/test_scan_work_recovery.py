from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from app import poc
from app.database import connect_database
from app.device_vlan_observations import init_device_vlan_observation_storage
from app.scan_work_recovery import (
    ScanWorkRecoveryError,
    apply_scan_work_recovery,
    diagnose_scan_work,
    pause_for_diagnosis,
    recovery_pause,
)
from app.schema_compatibility import begin_schema_migration, complete_schema_migration
from app.storage_health import _init_compaction_journal
from app.work_coordination import init_work_coordination_storage


def ready_database(
    tmp_path: Path, *, include_compaction: bool = False
) -> tuple[Path, Path]:
    data_dir = tmp_path / "data"
    data_dir.mkdir(parents=True)
    db_path = data_dir / "analyzer.db"
    attempt = begin_schema_migration(db_path)
    poc._POC_STORAGE_READY.clear()
    poc.init_poc_storage(db_path)
    init_work_coordination_storage(db_path)
    init_device_vlan_observation_storage(db_path)
    if include_compaction:
        _init_compaction_journal(db_path)
    complete_schema_migration(db_path, attempt)
    return data_dir, db_path


def add_run(
    db_path: Path,
    run_id: str,
    status: str,
    *,
    started: bool = False,
    execution_claim: bool = False,
    scheduled: bool = False,
) -> None:
    manifest = {
        "run_id": run_id,
        "created_at": f"2026-10-23T00:00:0{run_id[-1]}Z",
        "status": status,
        "operator": "analyst.one",
        "targets": ["192.0.2.0/29"],
        "profile": "Common ports",
        "scheduled": scheduled,
    }
    if started:
        manifest["started_at"] = "2026-10-23T00:01:00Z"
        manifest["progress"] = {"phase": "tcp"}
    if execution_claim:
        manifest["execution_claim"] = {"owner": "old-worker"}
    with connect_database(db_path) as db:
        db.execute(
            """INSERT INTO scan_runs(
                   run_id,created_at,status,operator_name,reason,originating_host,
                   interface_name,profile,manifest_json
               ) VALUES(?,?,?,?,?,?,?,?,?)""",
            (
                run_id,
                manifest["created_at"],
                status,
                "analyst.one",
                "authorized test",
                "nct-test",
                "eth0",
                "Common ports",
                json.dumps(manifest, sort_keys=True),
            ),
        )


def test_clean_saved_state_is_safe_and_requires_no_reset(tmp_path: Path) -> None:
    _, db_path = ready_database(tmp_path)
    plan = diagnose_scan_work(db_path)
    assert plan["safe_to_apply"] is True
    assert plan["blockers"] == []
    assert plan["affected_count"] == 0
    assert plan["automatic_contact_after_recovery"] is False


def test_recovery_preserves_queue_interrupts_uncertain_contact_and_keeps_evidence(
    tmp_path: Path,
) -> None:
    data_dir, db_path = ready_database(tmp_path)
    add_run(db_path, "a" * 31 + "1", "queued")
    add_run(db_path, "a" * 31 + "2", "dispatching", execution_claim=True)
    add_run(db_path, "a" * 31 + "3", "running", started=True)
    add_run(db_path, "a" * 31 + "4", "completed", started=True)
    evidence = data_dir / "scan-runs" / ("a" * 31 + "4") / "scan.xml"
    evidence.parent.mkdir(parents=True)
    evidence.write_bytes(b"<nmaprun><host/></nmaprun>")
    evidence_hash = hashlib.sha256(evidence.read_bytes()).hexdigest()

    plan = diagnose_scan_work(db_path)
    assert plan["safe_to_apply"] is True
    assert [item["action"] for item in plan["scans"]] == [
        "preserve_queue",
        "requeue_precontact",
        "interrupt_for_review",
    ]

    receipt = apply_scan_work_recovery(
        db_path,
        data_dir,
        expected_plan_digest=plan["plan_digest"],
        actor="admin",
        backup_path="/backups/nct-data.tar.gz",
        backup_sha256="b" * 64,
    )
    with connect_database(db_path, read_only=True) as db:
        rows = db.execute(
            "SELECT run_id,status,manifest_json FROM scan_runs ORDER BY rowid"
        ).fetchall()
        audits = db.execute(
            "SELECT run_id,event FROM scan_run_audit ORDER BY event_id"
        ).fetchall()
    assert [row[1] for row in rows] == [
        "queued", "queued", "interrupted", "completed"
    ]
    assert json.loads(rows[2][2])["recovery_required"] is True
    assert audits == [
        ("a" * 31 + "2", "recovery_requeued_precontact"),
        ("a" * 31 + "3", "recovery_interrupted"),
        (f"recovery:{receipt['recovery_id']}", "scan_work_recovery_receipt"),
    ]
    assert evidence.is_file()
    assert hashlib.sha256(evidence.read_bytes()).hexdigest() == evidence_hash
    assert receipt["completed_evidence_action"] == "preserved"
    assert receipt["preserved_queue_run_ids"] == [
        "a" * 31 + "1", "a" * 31 + "2"
    ]
    assert recovery_pause(data_dir)["state"] == "review_required"


def test_changed_plan_and_repeated_apply_fail_closed(tmp_path: Path) -> None:
    data_dir, db_path = ready_database(tmp_path)
    run_id = "c" * 32
    add_run(db_path, run_id, "dispatching", execution_claim=True)
    first = diagnose_scan_work(db_path)
    with connect_database(db_path) as db:
        manifest = json.loads(db.execute(
            "SELECT manifest_json FROM scan_runs WHERE run_id=?", (run_id,)
        ).fetchone()[0])
        manifest["started_at"] = "2026-10-23T00:02:00Z"
        db.execute(
            "UPDATE scan_runs SET manifest_json=? WHERE run_id=?",
            (json.dumps(manifest, sort_keys=True), run_id),
        )
    with pytest.raises(ScanWorkRecoveryError, match="plan changed"):
        apply_scan_work_recovery(
            db_path,
            data_dir,
            expected_plan_digest=first["plan_digest"],
            actor="admin",
            backup_path="/backups/first.tar.gz",
            backup_sha256="d" * 64,
        )

    current = diagnose_scan_work(db_path)
    apply_scan_work_recovery(
        db_path,
        data_dir,
        expected_plan_digest=current["plan_digest"],
        actor="admin",
        backup_path="/backups/current.tar.gz",
        backup_sha256="e" * 64,
    )
    with pytest.raises(ScanWorkRecoveryError, match="plan changed"):
        apply_scan_work_recovery(
            db_path,
            data_dir,
            expected_plan_digest=current["plan_digest"],
            actor="admin",
            backup_path="/backups/current.tar.gz",
            backup_sha256="e" * 64,
        )


def test_schema_drift_and_unresolved_compaction_refuse_recovery(tmp_path: Path) -> None:
    _, db_path = ready_database(tmp_path)
    with connect_database(db_path) as db:
        db.execute("CREATE TABLE unfamiliar_state(value TEXT)")
    drifted = diagnose_scan_work(db_path)
    assert drifted["safe_to_apply"] is False
    assert "fingerprint" in " ".join(drifted["blockers"]).lower()

    _, compaction_db = ready_database(tmp_path / "compaction", include_compaction=True)
    with connect_database(compaction_db) as db:
        db.execute(
            """INSERT INTO artifact_compaction_journal(
                   compaction_id,item_id,source_path,canonical_path,recovery_path,
                   sha256,size_bytes,source_fingerprint_json,
                   canonical_fingerprint_json,state,detail,updated_at
               ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                "active-compaction", "item-1", "/data/source", "/data/canonical",
                "/data/recovery", "a" * 64, 1, "{}", "{}", "preparing", None,
                "2026-10-23T00:00:00Z",
            ),
        )
    blocked = diagnose_scan_work(compaction_db)
    assert blocked["safe_to_apply"] is False
    assert "compaction" in " ".join(blocked["blockers"]).lower()


def test_schedule_contact_is_held_without_reopening_completed_chunk(tmp_path: Path) -> None:
    data_dir, db_path = ready_database(tmp_path)
    schedule_id = "schedule-recovery-test"
    occurrence_id = "1" * 32
    digest = "2" * 64
    now = "2026-10-23T00:00:00Z"
    with connect_database(db_path) as db:
        profile_id, profile_version = db.execute(
            "SELECT profile_id,version FROM scan_profiles ORDER BY built_in DESC LIMIT 1"
        ).fetchone()
        db.execute(
            "INSERT INTO scan_schedules VALUES(?,?,?,?,?,?,?)",
            (
                schedule_id, "Recovery schedule", now, "admin", profile_id,
                profile_version, json.dumps({"enabled": True}),
            ),
        )
        db.execute(
            "INSERT INTO scan_schedule_definitions VALUES(?,?,?,?,?,?)",
            (schedule_id, 1, digest, "{}", now, "admin"),
        )
        db.execute(
            """INSERT INTO scan_schedule_occurrences(
                   occurrence_id,schedule_id,definition_version,definition_digest,
                   due_at,trigger_kind,trigger_key,actor,state,frozen_json,
                   frozen_digest,created_at,started_at
               ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                occurrence_id, schedule_id, 1, digest, now, "scheduled", "daily",
                "scheduler", "active", "{}", digest, now, now,
            ),
        )
        db.execute(
            """INSERT INTO scan_schedule_chunks(
                   occurrence_id,chunk_number,targets_json,targets_digest,target_count,
                   state,contact_phase,attempt_count,created_at,completed_at
               ) VALUES(?,?,?,?,?,?,?,?,?,?)""",
            (occurrence_id, 1, '["192.0.2.1"]', digest, 1, "complete", "complete", 1, now, now),
        )
        db.execute(
            """INSERT INTO scan_schedule_chunks(
                   occurrence_id,chunk_number,targets_json,targets_digest,target_count,
                   state,contact_phase,attempt_count,created_at,started_at
               ) VALUES(?,?,?,?,?,?,?,?,?,?)""",
            (occurrence_id, 2, '["192.0.2.2"]', digest, 1, "active", "contact_active", 1, now, now),
        )
        db.execute(
            """INSERT INTO scan_schedule_chunks(
                   occurrence_id,chunk_number,targets_json,targets_digest,target_count,
                   state,contact_phase,attempt_count,created_at
               ) VALUES(?,?,?,?,?,?,?,?,?)""",
            (occurrence_id, 3, '["192.0.2.3"]', digest, 1, "waiting", "not_started", 0, now),
        )
    plan = diagnose_scan_work(db_path)
    assert plan["safe_to_apply"] is True
    assert [item["action"] for item in plan["schedule_chunks"]] == [
        "hold_for_review", "hold_for_review"
    ]
    apply_scan_work_recovery(
        db_path,
        data_dir,
        expected_plan_digest=plan["plan_digest"],
        actor="admin",
        backup_path="/backups/schedules.tar.gz",
        backup_sha256="9" * 64,
    )
    with connect_database(db_path, read_only=True) as db:
        chunks = db.execute(
            "SELECT chunk_number,state,contact_phase FROM scan_schedule_chunks ORDER BY chunk_number"
        ).fetchall()
        occurrence = db.execute(
            "SELECT state FROM scan_schedule_occurrences WHERE occurrence_id=?",
            (occurrence_id,),
        ).fetchone()[0]
        enabled = json.loads(db.execute(
            "SELECT definition_json FROM scan_schedules WHERE schedule_id=?",
            (schedule_id,),
        ).fetchone()[0])["enabled"]
    assert chunks == [
        (1, "complete", "complete"),
        (2, "needs_attention", "uncertain"),
        (3, "needs_attention", "not_started"),
    ]
    assert occurrence == "needs_attention"
    assert enabled == 0


def test_durable_pause_prevents_queued_scan_dispatch(tmp_path: Path) -> None:
    data_dir, db_path = ready_database(tmp_path)
    add_run(db_path, "f" * 32, "queued")
    plan = diagnose_scan_work(db_path)
    pause_for_diagnosis(data_dir, plan, "test pause")
    assert poc.dispatch_next_queued_run(db_path=db_path, data_dir=data_dir) is None
    with connect_database(db_path, read_only=True) as db:
        assert db.execute(
            "SELECT status FROM scan_runs WHERE run_id=?", ("f" * 32,)
        ).fetchone()[0] == "queued"


def test_read_only_status_is_available_to_queue_viewers(monkeypatch, tmp_path: Path) -> None:
    from app import main

    data_dir, db_path = ready_database(tmp_path)
    monkeypatch.setattr(main, "DATA_DIR", data_dir)
    monkeypatch.setattr(main, "DB_PATH", db_path)
    request = Request({"type": "http", "method": "GET", "path": "/", "headers": []})
    request.state.analyst = {"username": "viewer.one", "role": "viewer"}

    result = main.scan_work_recovery_status(request)

    assert result["pause"] is None
    assert result["plan"]["safe_to_apply"] is True
    assert result["plan"]["affected_count"] == 0


def test_resume_requires_exact_confirmation_then_restarts_preserved_work(
    monkeypatch, tmp_path: Path,
) -> None:
    from app import main
    from app.scan_work_recovery import write_recovery_pause

    calls: list[object] = []
    data_dir, db_path = ready_database(tmp_path)
    plan = diagnose_scan_work(db_path)
    write_recovery_pause(data_dir, {
        "contract": "nct-scan-work-recovery-pause-v1",
        "state": "review_required",
        "recorded_at": "2026-10-23T00:00:00Z",
        "reason": "test",
        "plan_digest": plan["plan_digest"],
        "affected_count": 0,
        "blockers": [],
    })
    monkeypatch.setattr(main, "DATA_DIR", data_dir)
    monkeypatch.setattr(main, "DB_PATH", db_path)
    monkeypatch.setattr(main, "auth_enabled", lambda: False)
    monkeypatch.setattr(main, "recover_interrupted_pulls", lambda path: calls.append(("recover", path)))
    monkeypatch.setattr(main, "start_arkime_pull_worker", lambda path: calls.append(("arkime", path)))
    monkeypatch.setattr(
        main,
        "dispatch_next_queued_run",
        lambda **kwargs: calls.append(("dispatch", kwargs)) or None,
    )
    request = Request({"type": "http", "method": "POST", "path": "/", "headers": []})
    request.state.analyst = None

    with pytest.raises(HTTPException, match="RESUME PRESERVED SCANS") as wrong:
        main.resume_recovered_scan_work(
            request,
            main.ScanRecoveryResumeRequest(
                plan_digest=plan["plan_digest"], confirmation="resume"
            ),
        )
    assert wrong.value.status_code == 422
    assert recovery_pause(data_dir)["state"] == "review_required"

    result = main.resume_recovered_scan_work(
        request,
        main.ScanRecoveryResumeRequest(
            plan_digest=plan["plan_digest"],
            confirmation="RESUME PRESERVED SCANS",
        ),
    )

    assert result["resumed"] is True
    assert result["resumed_by"] == "local-operator"
    paused = recovery_pause(data_dir)
    assert paused["scan_contact_paused"] is False
    assert paused["passive_contact_paused"] is True
    assert calls == [("dispatch", {"db_path": db_path, "data_dir": data_dir})]

    with pytest.raises(HTTPException, match="RESUME PASSIVE PULLS") as passive_wrong:
        main.resume_recovered_passive_work(
            request,
            main.PassiveRecoveryResumeRequest(
                plan_digest=plan["plan_digest"], confirmation="resume"
            ),
        )
    assert passive_wrong.value.status_code == 422

    passive = main.resume_recovered_passive_work(
        request,
        main.PassiveRecoveryResumeRequest(
            plan_digest=plan["plan_digest"], confirmation="RESUME PASSIVE PULLS"
        ),
    )
    assert passive["resumed"] is True
    assert passive["scan_contact_paused"] is False
    assert recovery_pause(data_dir) is None
    assert calls[-2:] == [("recover", db_path), ("arkime", db_path)]


def test_apply_requires_recorded_cold_backup_path(tmp_path: Path) -> None:
    data_dir, db_path = ready_database(tmp_path)
    plan = diagnose_scan_work(db_path)
    with pytest.raises(ScanWorkRecoveryError, match="backup path"):
        apply_scan_work_recovery(
            db_path,
            data_dir,
            expected_plan_digest=plan["plan_digest"],
            actor="admin",
            backup_path=" ",
            backup_sha256="a" * 64,
        )


def test_plan_digest_covers_full_scan_manifest(tmp_path: Path) -> None:
    _, db_path = ready_database(tmp_path)
    run_id = "m" * 32
    add_run(db_path, run_id, "dispatching", execution_claim=True)
    first = diagnose_scan_work(db_path)
    with connect_database(db_path) as db:
        manifest = json.loads(db.execute(
            "SELECT manifest_json FROM scan_runs WHERE run_id=?", (run_id,)
        ).fetchone()[0])
        manifest["interface"] = "eth9"
        manifest["tcp_ports"] = [22, 443]
        db.execute(
            "UPDATE scan_runs SET manifest_json=? WHERE run_id=?",
            (json.dumps(manifest, sort_keys=True), run_id),
        )
    second = diagnose_scan_work(db_path)
    assert second["plan_digest"] != first["plan_digest"]
    assert second["scans"][0]["manifest_digest"] != first["scans"][0]["manifest_digest"]


def test_plan_digest_covers_frozen_schedule_targets(tmp_path: Path) -> None:
    _, db_path = ready_database(tmp_path)
    schedule_id = "schedule-digest-test"
    occurrence_id = "7" * 32
    digest = "8" * 64
    now = "2026-10-23T00:00:00Z"
    with connect_database(db_path) as db:
        profile_id, profile_version = db.execute(
            "SELECT profile_id,version FROM scan_profiles ORDER BY built_in DESC LIMIT 1"
        ).fetchone()
        db.execute(
            "INSERT INTO scan_schedules VALUES(?,?,?,?,?,?,?)",
            (schedule_id, "Digest schedule", now, "admin", profile_id, profile_version, '{}'),
        )
        db.execute(
            "INSERT INTO scan_schedule_definitions VALUES(?,?,?,?,?,?)",
            (schedule_id, 1, digest, '{}', now, "admin"),
        )
        db.execute(
            """INSERT INTO scan_schedule_occurrences(
                   occurrence_id,schedule_id,definition_version,definition_digest,due_at,
                   trigger_kind,trigger_key,actor,state,frozen_json,frozen_digest,created_at
               ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
            (occurrence_id, schedule_id, 1, digest, now, "scheduled", "daily", "scheduler",
             "preparing", '{"targets":["192.0.2.1"]}', digest, now),
        )
        db.execute(
            """INSERT INTO scan_schedule_chunks(
                   occurrence_id,chunk_number,targets_json,targets_digest,target_count,
                   state,contact_phase,attempt_count,created_at
               ) VALUES(?,?,?,?,?,?,?,?,?)""",
            (occurrence_id, 1, '["192.0.2.1"]', digest, 1, "preparing", "preparing", 0, now),
        )
    first = diagnose_scan_work(db_path)
    with connect_database(db_path) as db:
        # Simulate a stopped-copy change below the application contract, then
        # restore the same immutability trigger before diagnosis.
        db.execute("DROP TRIGGER scan_schedule_chunk_frozen_fields")
        db.execute(
            "UPDATE scan_schedule_chunks SET targets_json=? WHERE occurrence_id=?",
            ('["192.0.2.99"]', occurrence_id),
        )
        db.executescript(
            """CREATE TRIGGER scan_schedule_chunk_frozen_fields
               BEFORE UPDATE OF occurrence_id, chunk_number, targets_json,
                   targets_digest, target_count, created_at
               ON scan_schedule_chunks
               BEGIN
                   SELECT RAISE(ABORT, 'Schedule chunk plan is immutable');
               END;"""
        )
    second = diagnose_scan_work(db_path)
    assert second["plan_digest"] != first["plan_digest"]
    assert second["schedule_chunks"][0]["targets_record_digest"] != first["schedule_chunks"][0]["targets_record_digest"]

    with connect_database(db_path) as db:
        db.execute(
            "UPDATE scan_schedules SET definition_json=? WHERE schedule_id=?",
            ('{"enabled":false,"note":"changed after preview"}', schedule_id),
        )
    third = diagnose_scan_work(db_path)
    assert third["plan_digest"] != second["plan_digest"]
    assert third["schedules"][0]["schedule_record"]["definition_json"] != second["schedules"][0]["schedule_record"]["definition_json"]


def test_changed_affected_schedule_definition_rejects_apply(tmp_path: Path) -> None:
    data_dir, db_path = ready_database(tmp_path)
    schedule_id = "schedule-apply-change-test"
    occurrence_id = "6" * 32
    digest = "7" * 64
    now = "2026-10-23T00:00:00Z"
    with connect_database(db_path) as db:
        profile_id, profile_version = db.execute(
            "SELECT profile_id,version FROM scan_profiles ORDER BY built_in DESC LIMIT 1"
        ).fetchone()
        db.execute(
            "INSERT INTO scan_schedules VALUES(?,?,?,?,?,?,?)",
            (schedule_id, "Apply change", now, "admin", profile_id, profile_version, '{"enabled":true}'),
        )
        db.execute(
            "INSERT INTO scan_schedule_definitions VALUES(?,?,?,?,?,?)",
            (schedule_id, 1, digest, '{}', now, "admin"),
        )
        db.execute(
            """INSERT INTO scan_schedule_occurrences(
                   occurrence_id,schedule_id,definition_version,definition_digest,due_at,
                   trigger_kind,trigger_key,actor,state,frozen_json,frozen_digest,created_at
               ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
            (occurrence_id, schedule_id, 1, digest, now, "scheduled", "daily", "scheduler",
             "preparing", '{}', digest, now),
        )
        db.execute(
            """INSERT INTO scan_schedule_chunks(
                   occurrence_id,chunk_number,targets_json,targets_digest,target_count,
                   state,contact_phase,attempt_count,created_at
               ) VALUES(?,?,?,?,?,?,?,?,?)""",
            (occurrence_id, 1, '["192.0.2.1"]', digest, 1, "preparing", "preparing", 0, now),
        )
    preview = diagnose_scan_work(db_path)
    with connect_database(db_path) as db:
        db.execute(
            "UPDATE scan_schedules SET definition_json=? WHERE schedule_id=?",
            ('{"enabled":false,"note":"changed after preview"}', schedule_id),
        )
    with pytest.raises(ScanWorkRecoveryError, match="plan changed"):
        apply_scan_work_recovery(
            db_path,
            data_dir,
            expected_plan_digest=preview["plan_digest"],
            actor="admin",
            backup_path="/backups/schedule-change.tar.gz",
            backup_sha256="f" * 64,
        )


def test_plan_digest_covers_complete_active_lease_ownership(tmp_path: Path) -> None:
    _, db_path = ready_database(tmp_path)
    with connect_database(db_path) as db:
        db.execute(
            """INSERT INTO work_leases VALUES(
                   ?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                "scan-capacity:primary", "scan", "run-1", 1, "lease-1", "worker-1",
                "active", "2026-10-23T00:00:00Z", "2026-10-23T00:00:00Z",
                "2026-10-23T00:10:00Z", None, None,
            ),
        )
    first = diagnose_scan_work(db_path)
    with connect_database(db_path) as db:
        db.execute(
            "UPDATE work_leases SET owner_id=? WHERE lease_key=?",
            ("worker-2", "scan-capacity:primary"),
        )
    second = diagnose_scan_work(db_path)
    assert second["plan_digest"] != first["plan_digest"]
    assert second["leases"][0]["owner_id"] == "worker-2"


def test_non_scan_active_lease_blocks_recovery(tmp_path: Path) -> None:
    _, db_path = ready_database(tmp_path)
    with connect_database(db_path) as db:
        db.execute(
            """INSERT INTO work_leases VALUES(
                   'device-contact:1','device_contact','pull-1',1,'lease-1','worker-1',
                   'active','2026-10-23T00:00:00Z','2026-10-23T00:00:00Z',
                   '2026-10-23T00:10:00Z',NULL,NULL)"""
        )
    plan = diagnose_scan_work(db_path)
    assert plan["safe_to_apply"] is False
    assert "device-contact:1" in " ".join(plan["blockers"])


def test_database_receipt_is_atomic_and_complete(tmp_path: Path) -> None:
    data_dir, db_path = ready_database(tmp_path)
    add_run(db_path, "r" * 32, "dispatching", execution_claim=True)
    plan = diagnose_scan_work(db_path)
    receipt = apply_scan_work_recovery(
        db_path, data_dir, expected_plan_digest=plan["plan_digest"], actor="admin",
        backup_path="/backups/atomic.tar.gz", backup_sha256="a" * 64,
    )
    with connect_database(db_path) as db:
        row = db.execute(
            """SELECT details FROM scan_run_audit
                 WHERE run_id=? AND event='scan_work_recovery_receipt'""",
            (f"recovery:{receipt['recovery_id']}",),
        ).fetchone()
        durable = json.loads(row[0])
        assert durable["plan"]["plan_digest"] == plan["plan_digest"]
        changes = durable["changes"]
        assert changes[0]["before"][0]["status"] == "dispatching"
        assert changes[0]["after"][0]["status"] == "queued"
        assert durable["receipt"]["database_receipt"] is True


def test_external_receipt_failure_keeps_database_receipt_and_pause(
    monkeypatch, tmp_path: Path,
) -> None:
    import app.scan_work_recovery as recovery

    data_dir, db_path = ready_database(tmp_path)
    add_run(db_path, "w" * 32, "dispatching", execution_claim=True)
    plan = diagnose_scan_work(db_path)
    monkeypatch.setattr(
        recovery, "_write_external_receipt",
        lambda path, receipt: (_ for _ in ()).throw(OSError("disk unavailable")),
    )
    with pytest.raises(OSError, match="disk unavailable"):
        apply_scan_work_recovery(
            db_path, data_dir, expected_plan_digest=plan["plan_digest"], actor="admin",
            backup_path="/backups/durable.tar.gz", backup_sha256="d" * 64,
        )
    pause = recovery_pause(data_dir)
    assert pause["state"] == "diagnosis_required"
    assert pause["recovery_id"]
    with connect_database(db_path, read_only=True) as db:
        assert db.execute(
            "SELECT COUNT(*) FROM scan_run_audit WHERE event='scan_work_recovery_receipt'"
        ).fetchone()[0] == 1


def test_passive_resume_failure_restores_contact_pause(monkeypatch, tmp_path: Path) -> None:
    from app import main
    from app.scan_work_recovery import write_recovery_pause

    data_dir, db_path = ready_database(tmp_path)
    plan = diagnose_scan_work(db_path)
    write_recovery_pause(data_dir, {
        "contract": "nct-scan-work-recovery-pause-v1", "state": "review_required",
        "recorded_at": "2026-10-23T00:00:00Z", "reason": "test",
        "plan_digest": plan["plan_digest"], "scan_contact_paused": False,
        "passive_contact_paused": True, "affected_count": 0, "blockers": [],
    })
    monkeypatch.setattr(main, "DATA_DIR", data_dir)
    monkeypatch.setattr(main, "DB_PATH", db_path)
    monkeypatch.setattr(main, "auth_enabled", lambda: False)
    monkeypatch.setattr(main, "recover_interrupted_pulls", lambda path: (_ for _ in ()).throw(RuntimeError("failed")))
    request = Request({"type": "http", "method": "POST", "path": "/", "headers": []})
    request.state.analyst = None
    with pytest.raises(HTTPException, match="remain paused") as failed:
        main.resume_recovered_passive_work(
            request,
            main.PassiveRecoveryResumeRequest(
                plan_digest=plan["plan_digest"], confirmation="RESUME PASSIVE PULLS"
            ),
        )
    assert failed.value.status_code == 503
    pause = recovery_pause(data_dir)
    assert pause["passive_contact_paused"] is True
    assert pause["scan_contact_paused"] is False


def test_scan_resume_failure_restores_contact_pause(monkeypatch, tmp_path: Path) -> None:
    from app import main
    from app.scan_work_recovery import write_recovery_pause

    data_dir, db_path = ready_database(tmp_path)
    plan = diagnose_scan_work(db_path)
    write_recovery_pause(data_dir, {
        "contract": "nct-scan-work-recovery-pause-v1", "state": "review_required",
        "recorded_at": "2026-10-23T00:00:00Z", "reason": "test",
        "plan_digest": plan["plan_digest"], "scan_contact_paused": True,
        "passive_contact_paused": False, "affected_count": 0, "blockers": [],
    })
    monkeypatch.setattr(main, "DATA_DIR", data_dir)
    monkeypatch.setattr(main, "DB_PATH", db_path)
    monkeypatch.setattr(main, "auth_enabled", lambda: False)
    monkeypatch.setattr(
        main, "dispatch_next_queued_run",
        lambda **kwargs: (_ for _ in ()).throw(RuntimeError("failed")),
    )
    request = Request({"type": "http", "method": "POST", "path": "/", "headers": []})
    request.state.analyst = None
    with pytest.raises(HTTPException, match="remain paused") as failed:
        main.resume_recovered_scan_work(
            request,
            main.ScanRecoveryResumeRequest(
                plan_digest=plan["plan_digest"], confirmation="RESUME PRESERVED SCANS"
            ),
        )
    assert failed.value.status_code == 503
    pause = recovery_pause(data_dir)
    assert pause["scan_contact_paused"] is True
    assert pause["passive_contact_paused"] is False
