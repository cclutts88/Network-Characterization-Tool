from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
import subprocess
import sys

import pytest

from app.artifacts import init_artifact_storage, register_artifact_bytes
from app.schema_compatibility import begin_schema_migration, complete_schema_migration, image_schema_contract


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import nct_kubernetes_recovery as recovery  # noqa: E402
import nct_kubernetes_upgrade as upgrade  # noqa: E402


OLD_IMAGE = "registry.example/nct@sha256:" + "a" * 64
NEW_IMAGE = "registry.example/nct@sha256:" + "b" * 64
SCENARIO = "upgrade-test-20261012"


def write_json(path: Path, value: dict) -> Path:
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def make_data(root: Path) -> None:
    root.mkdir()
    (root / upgrade.WRITER_LOCK_NAME).write_bytes(b"")
    db_path = root / "analyzer.db"
    attempt = begin_schema_migration(db_path)
    with sqlite3.connect(db_path) as db:
        db.execute("CREATE TABLE imports(id TEXT PRIMARY KEY)")
        db.execute("INSERT INTO imports VALUES ('saved-evidence')")
    complete_schema_migration(db_path, attempt)
    (root / "selected-evidence.xml").write_text("<nmaprun />", encoding="utf-8")


def inspect_args(root: Path, phase: str, image: str = OLD_IMAGE) -> argparse.Namespace:
    contract = image_schema_contract()
    return argparse.Namespace(
        data_root=root, scenario_id=SCENARIO, phase=phase, image=image,
        runtime_image_id="docker-pullable://" + image,
        contract_digest=contract["contract_digest"],
        deployment_uid="deployment-uid-12345678", deployment_generation=7,
        pod_uid="pod-uid-12345678", node_uid="node-uid-12345678",
        storage_attachment_identity="attachment-12345678",
        pvc_uid="pvc-uid-12345678", bound_volume_uid="pv-uid-12345678",
        qualification_report_digest="c" * 64,
        validation_root=root.parent / f"validation-{phase}",
        max_validation_bytes=100 * 1024**2, max_files=1_000,
        max_bytes=100 * 1024**2, max_seconds=30,
    )


def signed_contract(value: dict) -> dict:
    body = {key: item for key, item in value.items() if key != "contract_digest"}
    return {**body, "contract_digest": upgrade._digest(body)}


def changed_contract() -> dict:
    contract = dict(image_schema_contract())
    contract["writable_schema_version"] = 2
    contract["readable_schema_versions"] = [1, 2]
    contract["migration_ids"] = [*contract["migration_ids"], "schema-v2"]
    contract["migration_plan_digest"] = upgrade._digest({"migration_ids": contract["migration_ids"]})
    return signed_contract(contract)


def contract_envelope(contract: dict, image: str, runtime_image: str | None = None) -> dict:
    return upgrade._receipt({
        "schema_version": 1, "tool_version": "1", "status": "image_contract_bound",
        "requested_image": image, "runtime_image_id": "docker-pullable://" + (runtime_image or image),
        "application_version": contract["application_version"],
        "build_id": contract["build_id"], "build_commit": contract["build_commit"],
        "contract_digest": contract["contract_digest"], "contract": contract,
    })


def backup_records(contract: dict, before: dict, inventory: list[dict]) -> tuple[dict, dict]:
    source_identity = {
        "namespace": "nct", "pvc": "nct-data", "pvc_uid": before["pvc_uid"],
        "bound_volume_uid": before["bound_volume_uid"],
    }
    backup_identity = {
        "namespace": "nct", "pvc": "nct-backup", "pvc_uid": "backup-pvc-12345678",
        "bound_volume_uid": "backup-pv-12345678",
    }
    manifest_body = {
        "schema_version": 1, "backup_id": "backup-20261012", "created_at": "2026-10-12T00:00:00+00:00",
        "tool": {"version": "1", "source_sha256": "1" * 64},
        "source": {"storage_identity": source_identity,
                   "qualification_report_digest": before["qualification_report_digest"],
                   "image": OLD_IMAGE, "application_version": contract["application_version"],
                   "build_id": contract["build_id"], "mount_path": "/data"},
        "backup": {"storage_identity": backup_identity,
                   "qualification_report_digest": "d" * 64, "mount_path": "/backup"},
        "limits": {"max_files": 1000, "max_bytes": 10_000_000},
        "capacity_preflight": {"source_bytes": 1, "minimum_free_bytes": 2, "available_before_bytes": 3},
        "inventory": inventory, "inventory_root_sha256": upgrade._digest(inventory),
        "archive": {"name": "payload.tar", "sha256": "e" * 64, "size": 1},
        "database": {"sha256": "f" * 64},
        "artifact_registry": {"verified": 0}, "retained_evidence": {"verified": 1},
        "limitations": [],
    }
    manifest = {**manifest_body, "manifest_sha256": upgrade._digest(manifest_body)}
    receipt = upgrade._receipt({
        "schema_version": 1, "status": "backup_verified", "backup_id": "backup-20261012",
        "verified_at": "2026-10-12T00:01:00+00:00",
        "manifest_sha256": manifest["manifest_sha256"], "archive_sha256": "e" * 64,
        "inventory_root_sha256": manifest["inventory_root_sha256"],
        "source_storage_identity_sha256": upgrade._digest(source_identity),
        "backup_storage_identity_sha256": upgrade._digest(backup_identity),
        "source_qualification_report_digest": before["qualification_report_digest"],
        "backup_qualification_report_digest": "d" * 64,
        "retained_evidence_verified": 1, "source_and_backup_preserved": True,
    })
    return receipt, manifest


def test_cold_inspection_binds_schema_inventory_and_writer_release(tmp_path: Path) -> None:
    root = tmp_path / "data"
    make_data(root)
    before = {item.relative_to(root).as_posix(): hashlib.sha256(item.read_bytes()).hexdigest()
              for item in root.rglob("*") if item.is_file()}
    args = inspect_args(root, "before-upgrade")
    result = upgrade.inspect_data(args)
    assert result["status"] == "upgrade_inspection_passed"
    assert result["writer_lock"] == "available"
    assert result["database"]["integrity"] == "ok"
    assert result["database"]["schema_state"]["schema_fingerprint_matches"] is True
    assert result["database"]["table_counts"]["imports"] == 1
    upgrade._verify_receipt(result, "inspection")
    after = {item.relative_to(root).as_posix(): hashlib.sha256(item.read_bytes()).hexdigest()
             for item in root.rglob("*") if item.is_file()}
    assert after == before
    assert list(args.validation_root.iterdir()) == []


def test_cold_inspection_verifies_populated_artifact_registry(tmp_path: Path) -> None:
    root = tmp_path / "data"
    root.mkdir()
    (root / upgrade.WRITER_LOCK_NAME).write_bytes(b"")
    db_path = root / "analyzer.db"
    attempt = begin_schema_migration(db_path)
    init_artifact_storage(db_path)
    complete_schema_migration(db_path, attempt)
    artifact = register_artifact_bytes(
        db_path=db_path,
        content=b"<nmaprun><host /></nmaprun>",
        source_kind="nmap_import",
        source_ref="gate7-populated-registry",
        original_filename="evidence.xml",
        actor="analyst.one",
    )

    result = upgrade.inspect_data(inspect_args(root, "before-upgrade"))

    assert result["database"]["artifact_registry_verified"] == 1
    assert result["database"]["table_counts"]["artifact_registry"] == 1
    assert result["database"]["table_counts"]["artifact_observations"] == 1
    assert result["database"]["artifact_registry_sha256"] == upgrade._digest([
        {"sha256": artifact["sha256"], "size": artifact["size_bytes"]}
    ])


def test_inspection_blocks_active_writer_without_changing_data(tmp_path: Path) -> None:
    root = tmp_path / "data"
    make_data(root)
    before = (root / "analyzer.db").read_bytes()
    child = subprocess.Popen([
        sys.executable, "-c",
        "import fcntl,sys,time; f=open(sys.argv[1],'r+b'); fcntl.lockf(f.fileno(),fcntl.LOCK_EX,1,0); print('locked',flush=True); time.sleep(10)",
        str(root / upgrade.WRITER_LOCK_NAME),
    ], stdout=subprocess.PIPE, text=True)
    try:
        assert child.stdout is not None and child.stdout.readline().strip() == "locked"
        with pytest.raises(upgrade.UpgradeEvidenceError, match="active writer"):
            upgrade.inspect_data(inspect_args(root, "before-upgrade"))
    finally:
        child.terminate(); child.wait(timeout=5)
    assert (root / "analyzer.db").read_bytes() == before


def plan_fixture(tmp_path: Path, *, new_contract: dict | None = None) -> tuple[argparse.Namespace, dict, dict, dict]:
    root = tmp_path / "data"
    make_data(root)
    before = upgrade.inspect_data(inspect_args(root, "before-upgrade"))
    old = image_schema_contract()
    new = new_contract or old
    records = recovery._public_inventory(recovery._fd_tree(root, copy_to=None, max_files=1000, max_bytes=100 * 1024**2))
    receipt, manifest = backup_records(old, before, records)
    values = {
        "old": contract_envelope(old, OLD_IMAGE), "new": contract_envelope(new, NEW_IMAGE),
        "before": before, "backup": receipt, "manifest": manifest,
    }
    paths = {name: write_json(tmp_path / f"{name}.json", value) for name, value in values.items()}
    args = argparse.Namespace(
        scenario_id=SCENARIO, old_image=OLD_IMAGE, new_image=NEW_IMAGE,
        old_contract=paths["old"], new_contract=paths["new"],
        before_inspection=paths["before"], backup_receipt=paths["backup"],
        backup_manifest=paths["manifest"], backup_receipt_digest=receipt["receipt_sha256"],
        expected_candidate_generation=8, expected_rollback_generation=9,
    )
    return args, before, receipt, manifest


def test_preflight_binds_contract_backup_and_exact_source(tmp_path: Path) -> None:
    args, _before, receipt, manifest = plan_fixture(tmp_path)
    plan = upgrade.create_plan(args)
    assert plan["rollback_decision"] == "direct"
    assert plan["backup_manifest_sha256"] == manifest["manifest_sha256"]
    assert plan["backup_receipt_sha256"] == receipt["receipt_sha256"]

    bad = contract_envelope(image_schema_contract(), NEW_IMAGE, runtime_image=OLD_IMAGE)
    write_json(args.new_contract, bad)
    with pytest.raises(upgrade.UpgradeEvidenceError, match="expected image"):
        upgrade.create_plan(args)


@pytest.mark.parametrize("change", ["claim", "qualification", "inventory", "archive", "receipt-digest"])
def test_preflight_rejects_mismatched_backup_without_mutation(tmp_path: Path, change: str) -> None:
    args, _before, receipt, manifest = plan_fixture(tmp_path)
    if change == "receipt-digest":
        args.backup_receipt_digest = "0" * 64
    else:
        if change == "claim":
            manifest["source"]["storage_identity"]["pvc_uid"] = "wrong-pvc"
        elif change == "qualification":
            manifest["source"]["qualification_report_digest"] = "0" * 64
        elif change == "inventory":
            manifest["inventory"].append({"path": "wrong", "kind": "file", "mode": 384, "size": 0, "sha256": hashlib.sha256(b"").hexdigest()})
            manifest["inventory_root_sha256"] = upgrade._digest(manifest["inventory"])
        else:
            manifest["archive"]["sha256"] = "0" * 64
        manifest["manifest_sha256"] = upgrade._digest({k: v for k, v in manifest.items() if k != "manifest_sha256"})
        receipt["manifest_sha256"] = manifest["manifest_sha256"]
        receipt["inventory_root_sha256"] = manifest["inventory_root_sha256"]
        if change != "archive":
            receipt["archive_sha256"] = manifest["archive"]["sha256"]
        receipt["source_storage_identity_sha256"] = upgrade._digest(manifest["source"]["storage_identity"])
        receipt["source_qualification_report_digest"] = manifest["source"]["qualification_report_digest"]
        receipt = upgrade._receipt({k: v for k, v in receipt.items() if k != "receipt_sha256"})
        args.backup_receipt_digest = receipt["receipt_sha256"]
        write_json(args.backup_manifest, manifest); write_json(args.backup_receipt, receipt)
    with pytest.raises(upgrade.UpgradeEvidenceError):
        upgrade.create_plan(args)


def inspection_receipt(*, phase: str, status: str, image: str, contract: dict, generation: int,
                       pod: str, attachment: str, pvc: str, pv: str, qualification: str,
                       inventory: str, schema_version: int, counts: dict[str, int]) -> dict:
    recorded_at = {
        "before-upgrade": "2026-10-12T00:03:00+00:00",
        "after-upgrade": "2026-10-12T00:13:00+00:00",
        "failed-candidate": "2026-10-12T00:13:00+00:00",
        "after-rollback": "2026-10-12T00:23:00+00:00",
    }[phase]
    return upgrade._receipt({
        "schema_version": 1, "tool_version": "1", "status": status,
        "scenario_id": SCENARIO, "phase": phase, "recorded_at": recorded_at,
        "image": image, "runtime_image_id": "docker-pullable://" + image,
        "application_version": contract["application_version"], "build_id": contract["build_id"],
        "build_commit": contract["build_commit"], "schema_contract_digest": contract["contract_digest"],
        "deployment_uid": "deployment-uid-12345678", "deployment_generation": generation,
        "pod_uid": pod, "node_uid": "node-uid-12345678", "storage_attachment_identity": attachment,
        "pvc_uid": pvc, "bound_volume_uid": pv, "qualification_report_digest": qualification,
        "inventory": {"inventory_sha256": inventory, "files": 2, "bytes": 10,
                      "database_present": True, "wal_present": False, "shm_present": False},
        "database": {"integrity": "ok", "user_version": 0,
                     "schema_state": {"schema_version": schema_version, "migration_ledger": [],
                                      "schema_fingerprint_matches": phase != "failed-candidate"},
                     "migration_ledger_head": None, "table_counts": counts, "active_work": 0,
                     "artifact_registry_verified": 0, "artifact_registry_sha256": upgrade._digest([])},
        "writer_lock": "available",
    })


def lock_receipt(
    phase: str, inspection: dict, *, observed: str = "available",
    expected: str | None = None,
) -> dict:
    checked_at = {
        "old-writer-released": "2026-10-12T00:01:00+00:00",
        "candidate-writer-active": "2026-10-12T00:09:00+00:00",
        "candidate-writer-released": "2026-10-12T00:11:00+00:00",
        "rollback-writer-active": "2026-10-12T00:19:00+00:00",
        "rollback-writer-released": "2026-10-12T00:21:00+00:00",
    }[phase]
    expected = expected or ("contended" if phase.endswith("-active") else "available")
    body = {
        "schema_version": 1, "status": "pass", "checked_at": checked_at,
        "scenario": {"id": SCENARIO, "kind": "guarded-upgrade", "phase": phase},
        "deployment": {"uid": inspection["deployment_uid"], "generation": inspection["deployment_generation"],
                       "node_uid": inspection["node_uid"], "storage_attachment_identity": inspection["storage_attachment_identity"],
                       "pod_uid": inspection["pod_uid"]},
        "runtime": {"image": inspection["image"], "application_version": inspection["application_version"],
                    "build_id": inspection["build_id"]},
        "storage": {"pvc_uid": inspection["pvc_uid"], "bound_volume_uid": inspection["bound_volume_uid"],
                    "qualification_report_digest": inspection["qualification_report_digest"]},
        "writer_lock": {"path": "/data/.analyzer.db.nct-writer.lock", "expected": expected,
                        "observed": observed, "opened_existing_only": True, "sqlite_opened": False,
                        "released_if_acquired": observed == "available", "destination_attachment_hold_seconds": 0},
        "tool": {"version": "1", "source_sha256": "1" * 64},
        "limitations": {"digest_authenticated": False, "proves_process_or_node_fencing": False,
                        "proves_storage_detachment": False},
    }
    return {**body, "attestation": {"algorithm": "sha256", "digest": upgrade._digest(body)}}


def observations(
    candidate: dict, rollback: dict, before: dict, *, failed: bool,
    writer_receipts: list[dict],
) -> dict:
    phases = [("old-stopped", 0, before), (("candidate-failed" if failed else "candidate-ready"),
              (0 if failed else 1), candidate), ("candidate-stopped", 0, candidate),
              ("rollback-ready", 1, rollback), ("rollback-stopped", 0, rollback)]
    times = (2, 10, 12, 20, 22)
    return {"scenario_id": SCENARIO, "samples": [
        {"at": datetime(2026, 10, 12, 0, times[index], tzinfo=timezone.utc).isoformat(), "phase": phase,
         "ready_pods": ready,
         "writer_owners": 1 if writer_receipts[index]["writer_lock"]["observed"] == "contended" else 0,
         "writer_lock_attestation_sha256": writer_receipts[index]["attestation"]["digest"],
         "deployment_uid": item["deployment_uid"], "deployment_generation": item["deployment_generation"],
         "pod_uid": item["pod_uid"], "node_uid": item["node_uid"],
         "storage_attachment_identity": item["storage_attachment_identity"],
         "pvc_uid": item["pvc_uid"], "bound_volume_uid": item["bound_volume_uid"]}
        for index, (phase, ready, item) in enumerate(phases)
    ]}


def restore_receipt(plan: dict, rollback: dict) -> dict:
    return upgrade._receipt({
        "schema_version": 1, "status": "restore_verification_passed", "backup_id": "backup-20261012",
        "verified_at": "2026-10-12T00:17:00+00:00", "source_image": plan["old_image"],
        "source_application_version": plan["old_contract"]["application_version"],
        "source_build_id": plan["old_contract"]["build_id"],
        "manifest_sha256": plan["backup_manifest_sha256"],
        "backup_receipt_sha256": plan["backup_receipt_sha256"], "archive_sha256": "e" * 64,
        "inventory_root_sha256": plan["backup_inventory_root_sha256"], "target_storage_identity_sha256": "f" * 64,
        "source_storage_identity": {"pvc_uid": plan["source_storage"]["pvc_uid"],
                                    "bound_volume_uid": plan["source_storage"]["bound_volume_uid"]},
        "backup_storage_identity": plan["backup_storage"],
        "target_storage_identity": {"pvc_uid": rollback["pvc_uid"], "bound_volume_uid": rollback["bound_volume_uid"]},
        "source_qualification_report_digest": plan["source_storage"]["qualification_report_digest"],
        "backup_qualification_report_digest": "d" * 64,
        "target_qualification_report_digest": rollback["qualification_report_digest"],
        "restored_files": 2, "restored_bytes": 10, "database_integrity": "ok",
        "artifact_registry_verified": 0, "retained_evidence_verified": 1,
        "source_and_backup_preserved": True, "next_step": "verify",
    })


def scenario_files(tmp_path: Path, *, restore: bool, failed: bool = False) -> tuple[argparse.Namespace, dict[str, Path]]:
    old, new = image_schema_contract(), (changed_contract() if restore else image_schema_contract())
    counts = {"imports": 1, "artifact_registry": 0, "artifact_observations": 0,
              "endpoint_receipts": 0, "service_receipts": 0, "pipeline_jobs": 0,
              "analyst_users": 1, "analyst_sessions": 0}
    source = {"pvc_uid": "pvc-old-12345678", "bound_volume_uid": "pv-old-12345678",
              "qualification_report_digest": "c" * 64, "storage_attachment_identity": "attachment-old"}
    before = inspection_receipt(phase="before-upgrade", status="upgrade_inspection_passed",
        image=OLD_IMAGE, contract=old, generation=7, pod="pod-old", attachment=source["storage_attachment_identity"],
        pvc=source["pvc_uid"], pv=source["bound_volume_uid"], qualification=source["qualification_report_digest"],
        inventory="e" * 64, schema_version=1, counts=counts)
    candidate = inspection_receipt(phase=("failed-candidate" if failed else "after-upgrade"),
        status=("failed_candidate_inspection_recorded" if failed else "upgrade_inspection_passed"),
        image=NEW_IMAGE, contract=new, generation=8, pod="pod-new", attachment=source["storage_attachment_identity"],
        pvc=source["pvc_uid"], pv=source["bound_volume_uid"], qualification=source["qualification_report_digest"],
        inventory="f" * 64, schema_version=(1 if failed else new["writable_schema_version"]), counts=counts)
    if restore or failed:
        rollback_storage = {"pvc_uid": "pvc-restore-12345678", "bound_volume_uid": "pv-restore-12345678",
                            "qualification_report_digest": "9" * 64, "storage_attachment_identity": "attachment-restore"}
        rollback_inventory = "7" * 64
    else:
        rollback_storage, rollback_inventory = source, "f" * 64
    rollback_counts = dict(counts)
    rollback_counts["analyst_sessions"] = 1
    rollback = inspection_receipt(phase="after-rollback", status="upgrade_inspection_passed",
        image=OLD_IMAGE, contract=old, generation=9, pod="pod-rollback", attachment=rollback_storage["storage_attachment_identity"],
        pvc=rollback_storage["pvc_uid"], pv=rollback_storage["bound_volume_uid"],
        qualification=rollback_storage["qualification_report_digest"], inventory=rollback_inventory,
        schema_version=1, counts=rollback_counts)
    plan = upgrade._receipt({
        "schema_version": 1, "tool_version": "1", "status": "upgrade_preflight_passed",
        "scenario_id": SCENARIO, "old_image": OLD_IMAGE, "new_image": NEW_IMAGE,
        "old_contract": old, "new_contract": new,
        "new_contract_envelope_sha256": contract_envelope(
            new, NEW_IMAGE
        )["receipt_sha256"],
        "old_runtime_image_id": "docker-pullable://" + OLD_IMAGE,
        "new_runtime_image_id": "docker-pullable://" + NEW_IMAGE,
        "before_inspection_sha256": before["receipt_sha256"],
        "backup_receipt_sha256": "1" * 64, "backup_manifest_sha256": "2" * 64,
        "backup_inventory_root_sha256": "e" * 64,
        "backup_storage": {"pvc_uid": "backup-pvc", "bound_volume_uid": "backup-pv"},
        "backup_storage_qualification_report_digest": "d" * 64,
        "source_storage": source,
        "source_cluster": {"deployment_uid": before["deployment_uid"], "deployment_generation": 7,
                           "pod_uid": before["pod_uid"], "node_uid": before["node_uid"]},
        "expected_candidate_generation": 8, "expected_rollback_generation": 9,
        "current_schema_version": 1, "target_schema_version": new["writable_schema_version"],
        "rollback_decision": ("restore" if restore else "direct"),
        "direct_rollback_authorized": not restore,
        "compatibility_rule": old["direct_rollback_rule"], "operator_message": "test",
    })
    old_lock = lock_receipt("old-writer-released", before)
    candidate_active = lock_receipt(
        "candidate-writer-active", candidate,
        observed=("available" if failed else "contended"),
        expected=("observe" if failed else "contended"),
    )
    candidate_lock = lock_receipt("candidate-writer-released", candidate)
    rollback_active = lock_receipt(
        "rollback-writer-active", rollback, observed="contended",
    )
    rollback_lock = lock_receipt("rollback-writer-released", rollback)
    writer_receipts = [old_lock, candidate_active, candidate_lock, rollback_active, rollback_lock]
    values = {"plan": plan, "before": before, "candidate": candidate, "rollback": rollback,
              "old-lock": old_lock, "candidate-active-lock": candidate_active,
              "candidate-lock": candidate_lock, "rollback-active-lock": rollback_active,
              "rollback-lock": rollback_lock,
              "observations": observations(
                  candidate, rollback, before, failed=failed,
                  writer_receipts=writer_receipts,
              )}
    required = ["old-writer-released", "backup-verified", "preflight-passed", "candidate-started",
                ("candidate-failed" if failed else "candidate-ready"), "candidate-writer-released"]
    if restore or failed:
        required += ["failed-claim-preserved", "restore-target-verified", "old-started-on-restored-data", "rollback-ready"]
    else:
        required += ["old-started-on-current-data", "rollback-ready"]
    event_minutes = {
        "old-writer-released": 1, "backup-verified": 2, "preflight-passed": 4,
        "candidate-started": 5, "candidate-ready": 9, "candidate-failed": 9,
        "candidate-writer-released": 14, "failed-claim-preserved": 15,
        "restore-target-verified": 16, "old-started-on-restored-data": 18,
        "old-started-on-current-data": 18, "rollback-ready": 19,
    }
    values["events"] = {"scenario_id": SCENARIO, "events": [
        {"event": name, "at": datetime(2026, 10, 12, 0, event_minutes[name], tzinfo=timezone.utc).isoformat()}
        for name in required]}
    if restore or failed:
        values["restore"] = restore_receipt(plan, rollback)
    if failed:
        values["failure"] = upgrade._receipt({
            "schema_version": 1, "tool_version": "1", "status": "candidate_startup_failed",
            "scenario_id": SCENARIO, "recorded_at": "2026-10-12T00:10:00+00:00",
            "image": NEW_IMAGE, "runtime_image_id": "docker-pullable://" + NEW_IMAGE,
            "failure_stage": "during-migration", "startup_status": 503, "readiness_status": 503,
            "container_terminated": True, "container_exit_code": 1,
            "failure_reason": "injected failure", "failure_observed_at": "2026-10-12T00:08:00+00:00",
            "failure_evidence_sha256": "3" * 64,
            "contract_envelope_sha256": contract_envelope(
                new, NEW_IMAGE
            )["receipt_sha256"],
            "failed_inspection_sha256": candidate["receipt_sha256"],
        })
    paths = {name: write_json(tmp_path / f"{name}.json", value) for name, value in values.items()}
    for phase in ("before-upgrade", "after-upgrade", "after-rollback"):
        paths[f"web-{phase}"] = write_json(tmp_path / f"web-{phase}.json",
            {"phase": phase, "startup_status": 200, "readiness_status": 200, "existing_account_signin": True})
    evidence = tmp_path / "evidence.xml"; evidence.write_text("<nmaprun />", encoding="utf-8")
    args = argparse.Namespace(
        plan=paths["plan"], before_inspection=paths["before"],
        after_inspection=(None if failed else paths["candidate"]),
        failed_inspection=(paths["candidate"] if failed else None),
        candidate_failure=(paths.get("failure") if failed else None),
        rollback_inspection=paths["rollback"], events=paths["events"],
        old_lock_receipt=paths["old-lock"],
        candidate_active_lock_receipt=paths["candidate-active-lock"],
        candidate_lock_receipt=paths["candidate-lock"],
        rollback_active_lock_receipt=paths["rollback-active-lock"],
        rollback_lock_receipt=paths["rollback-lock"], cluster_observations=paths["observations"],
        restore_receipt=paths.get("restore"),
        restore_receipt_digest=(values["restore"]["receipt_sha256"] if "restore" in values else None),
        before_web_check=paths["web-before-upgrade"],
        after_web_check=(None if failed else paths["web-after-upgrade"]),
        rollback_web_check=paths["web-after-rollback"], evidence_before=evidence,
        evidence_after=(None if failed else evidence), evidence_rollback=evidence,
        max_evidence_bytes=1024, max_seconds=30,
    )
    return args, paths


@pytest.mark.parametrize("restore", [False, True])
def test_successful_upgrade_and_both_rollback_branches_are_bound(tmp_path: Path, restore: bool) -> None:
    args, paths = scenario_files(tmp_path, restore=restore)
    result = upgrade.verify_scenario(args)
    assert result["status"] == "upgrade_rollback_verification_passed"
    assert result["rollback_decision"] == ("restore" if restore else "direct")
    if restore:
        assert "backup time" in result["operator_message"]
        restored = json.loads(paths["rollback"].read_text())
        restore_proof = json.loads(paths["restore"].read_text())
        assert restored["inventory"]["inventory_sha256"] != restore_proof["inventory_root_sha256"]
        assert restored["database"]["table_counts"]["analyst_sessions"] == 1


def test_failed_candidate_requires_preserved_claim_and_verified_restore(tmp_path: Path) -> None:
    args, paths = scenario_files(tmp_path, restore=False, failed=True)
    result = upgrade.verify_scenario(args)
    assert result["status"] == "failed_upgrade_restore_verification_passed"
    assert result["rollback_decision"] == "restore"
    observations_value = json.loads(paths["observations"].read_text())
    observations_value["samples"][3]["writer_owners"] = 2
    write_json(paths["observations"], observations_value)
    with pytest.raises(upgrade.UpgradeEvidenceError, match="single-writer"):
        upgrade.verify_scenario(args)


@pytest.mark.parametrize("field", ["pvc_uid", "bound_volume_uid", "qualification"])
def test_restore_rejects_wrong_backup_storage_binding(tmp_path: Path, field: str) -> None:
    args, paths = scenario_files(tmp_path, restore=True)
    receipt = json.loads(paths["restore"].read_text())
    body = {key: value for key, value in receipt.items() if key != "receipt_sha256"}
    if field == "qualification":
        body["backup_qualification_report_digest"] = "0" * 64
    else:
        body["backup_storage_identity"][field] = "wrong-backup-identity"
    changed = upgrade._receipt(body)
    write_json(paths["restore"], changed)
    args.restore_receipt_digest = changed["receipt_sha256"]
    with pytest.raises(upgrade.UpgradeEvidenceError, match="planned source and fresh target"):
        upgrade.verify_scenario(args)


def test_stale_candidate_lock_receipt_cannot_prove_post_shutdown_release(tmp_path: Path) -> None:
    args, paths = scenario_files(tmp_path, restore=False)
    receipt = json.loads(paths["candidate-lock"].read_text())
    receipt["checked_at"] = "2026-10-12T00:06:00+00:00"
    body = {key: value for key, value in receipt.items() if key != "attestation"}
    receipt["attestation"] = {"algorithm": "sha256", "digest": upgrade._digest(body)}
    write_json(paths["candidate-lock"], receipt)
    observations_value = json.loads(paths["observations"].read_text())
    observations_value["samples"][2]["writer_lock_attestation_sha256"] = receipt["attestation"]["digest"]
    write_json(paths["observations"], observations_value)
    with pytest.raises(upgrade.UpgradeEvidenceError, match="chronology"):
        upgrade.verify_scenario(args)


@pytest.mark.parametrize(
    "mismatch",
    ["scenario", "phase", "pod", "storage", "image", "generation"],
)
def test_candidate_active_writer_receipt_rejects_wrong_identity(
    tmp_path: Path, mismatch: str,
) -> None:
    args, paths = scenario_files(tmp_path, restore=False)
    receipt = json.loads(paths["candidate-active-lock"].read_text())
    if mismatch == "scenario":
        receipt["scenario"]["id"] = "upgrade-other-scenario"
    elif mismatch == "phase":
        receipt["scenario"]["phase"] = "rollback-writer-active"
    elif mismatch == "pod":
        receipt["deployment"]["pod_uid"] = "wrong-pod"
    elif mismatch == "storage":
        receipt["storage"]["pvc_uid"] = "wrong-pvc"
    elif mismatch == "image":
        receipt["runtime"]["image"] = OLD_IMAGE
    else:
        receipt["deployment"]["generation"] = 99
    body = {key: value for key, value in receipt.items() if key != "attestation"}
    receipt["attestation"] = {"algorithm": "sha256", "digest": upgrade._digest(body)}
    write_json(paths["candidate-active-lock"], receipt)

    with pytest.raises(upgrade.UpgradeEvidenceError, match="exact active phase"):
        upgrade.verify_scenario(args)


def test_cluster_observation_binds_active_writer_receipt_digest(tmp_path: Path) -> None:
    args, paths = scenario_files(tmp_path, restore=False)
    value = json.loads(paths["observations"].read_text())
    value["samples"][1]["writer_lock_attestation_sha256"] = "0" * 64
    write_json(paths["observations"], value)

    with pytest.raises(upgrade.UpgradeEvidenceError, match="single-writer"):
        upgrade.verify_scenario(args)


def test_failed_candidate_observation_must_match_measured_writer_count(tmp_path: Path) -> None:
    args, paths = scenario_files(tmp_path, restore=False, failed=True)
    value = json.loads(paths["observations"].read_text())
    assert value["samples"][1]["writer_owners"] == 0
    value["samples"][1]["writer_owners"] = 1
    write_json(paths["observations"], value)

    with pytest.raises(upgrade.UpgradeEvidenceError, match="single-writer"):
        upgrade.verify_scenario(args)


def test_record_failure_rejects_a_ready_candidate(tmp_path: Path) -> None:
    _args, paths = scenario_files(tmp_path, restore=False, failed=True)
    evidence = write_json(tmp_path / "failure-evidence.json", {
        "scenario_id": SCENARIO, "phase": "candidate-failure",
        "observed_at": "2026-10-12T00:10:00+00:00",
        "runtime": {"pod_uid": "pod-new", "image_id": "docker-pullable://" + NEW_IMAGE},
        "container": {"terminated": False, "exit_code": 0, "reason": "Running"},
        "startup_status": 200, "readiness_status": 200,
    })
    args = argparse.Namespace(
        failed_inspection=paths["candidate"], scenario_id=SCENARIO, image=NEW_IMAGE,
        contract=write_json(tmp_path / "contract.json", contract_envelope(image_schema_contract(), NEW_IMAGE)),
        failure_stage="during-migration", failure_evidence=evidence,
    )
    with pytest.raises(upgrade.UpgradeEvidenceError, match="successful candidate"):
        upgrade.record_candidate_failure(args)


def test_completed_healthy_migration_cannot_be_relabeled_as_failed(tmp_path: Path) -> None:
    contract = image_schema_contract()
    counts = {"imports": 1}
    inspection = inspection_receipt(
        phase="failed-candidate", status="failed_candidate_inspection_recorded",
        image=NEW_IMAGE, contract=contract, generation=8, pod="pod-new",
        attachment="attachment-old", pvc="pvc-old", pv="pv-old",
        qualification="c" * 64, inventory="f" * 64,
        schema_version=contract["writable_schema_version"], counts=counts,
    )
    inspection["database"]["schema_state"]["schema_fingerprint_matches"] = True
    inspection = upgrade._receipt({key: value for key, value in inspection.items() if key != "receipt_sha256"})
    inspection_path = write_json(tmp_path / "healthy-inspection.json", inspection)
    evidence_path = write_json(tmp_path / "failure-evidence.json", {
        "scenario_id": SCENARIO, "phase": "candidate-failure",
        "observed_at": "2026-10-12T00:08:00+00:00",
        "runtime": {"pod_uid": "pod-new", "image_id": "docker-pullable://" + NEW_IMAGE},
        "container": {"terminated": True, "exit_code": 1, "reason": "Injected"},
        "startup_status": 503, "readiness_status": 503,
    })
    with pytest.raises(upgrade.UpgradeEvidenceError, match="healthy migration"):
        upgrade.record_candidate_failure(argparse.Namespace(
            failed_inspection=inspection_path, scenario_id=SCENARIO, image=NEW_IMAGE,
            contract=write_json(tmp_path / "contract.json", contract_envelope(contract, NEW_IMAGE)),
            failure_stage="during-migration", failure_evidence=evidence_path,
        ))


def test_cluster_observation_recorder_enforces_ordered_single_writer_counts(tmp_path: Path) -> None:
    identity = {
        "deployment_uid": "deployment-uid-12345678", "deployment_generation": 7,
        "pod_uid": "pod-old", "node_uid": "node-old",
        "storage_attachment_identity": "attachment-old", "pvc_uid": "pvc-old",
        "bound_volume_uid": "pv-old", "qualification_report_digest": "f" * 64,
        "image": OLD_IMAGE, "application_version": "0.14.0-dev", "build_id": "build-old",
    }
    old_writer = write_json(
        tmp_path / "old-writer.json", lock_receipt("old-writer-released", identity),
    )
    candidate_identity = {**identity, "deployment_generation": 8, "pod_uid": "pod-new"}
    candidate_writer = write_json(
        tmp_path / "candidate-writer.json",
        lock_receipt("candidate-writer-active", candidate_identity, observed="contended"),
    )
    base = dict(
        scenario_id=SCENARIO, phase="old-stopped", ready_pods=0, writer_owners=0,
        deployment_uid="deployment-uid-12345678", deployment_generation=7,
        pod_uid="pod-old", node_uid="node-old", storage_attachment_identity="attachment-old",
        pvc_uid="pvc-old", bound_volume_uid="pv-old", previous=None,
        writer_receipt=old_writer,
    )
    first = upgrade.record_cluster_observation(argparse.Namespace(**base))
    previous = write_json(tmp_path / "observations.json", first)
    second = upgrade.record_cluster_observation(argparse.Namespace(
        **{**base, "phase": "candidate-ready", "ready_pods": 1, "writer_owners": 1,
           "deployment_generation": 8, "pod_uid": "pod-new", "previous": previous,
           "writer_receipt": candidate_writer}
    ))
    assert [item["phase"] for item in second["samples"]] == ["old-stopped", "candidate-ready"]
    failed_with_live_writer = upgrade.record_cluster_observation(argparse.Namespace(
        **{**base, "phase": "candidate-failed", "ready_pods": 0, "writer_owners": 1,
           "deployment_generation": 8, "pod_uid": "pod-new", "previous": previous,
           "writer_receipt": candidate_writer}
    ))
    assert failed_with_live_writer["samples"][-1]["writer_owners"] == 1
    with pytest.raises(upgrade.UpgradeEvidenceError, match="counts"):
        upgrade.record_cluster_observation(argparse.Namespace(
            **{**base, "phase": "candidate-ready", "ready_pods": 2, "writer_owners": 2,
               "writer_receipt": candidate_writer}
        ))


def test_runtime_image_includes_upgrade_tool() -> None:
    dockerfile = (Path(__file__).resolve().parents[1] / "Dockerfile").read_text(encoding="utf-8")
    assert "nct_kubernetes_upgrade.py /opt/nct/tools/nct_kubernetes_upgrade.py" in dockerfile
