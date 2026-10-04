from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import time

import pytest
from fastapi.testclient import TestClient

from app.artifacts import (
    canonical_artifact_path, artifact_root_for, register_artifact_bytes,
    register_artifact_file,
)
from app.evidence_maintenance import (
    EvidenceMaintenanceBlocked,
    clear_recovery_required,
    evidence_maintenance,
    evidence_mutation,
    mark_recovery_required,
    recovery_required,
)
from app.storage_health import (
    _init_compaction_journal,
    _journal_item,
    analyze_storage,
    backfill_storage,
    compact_storage,
    recover_incomplete_compactions,
)


def collection(root: Path, run_id: str, content: bytes = b"same exact evidence") -> Path:
    directory = root / "device-configs" / run_id
    directory.mkdir(parents=True)
    evidence = directory / "stdout.txt"
    evidence.write_bytes(content)
    manifest = {
        "run_id": run_id,
        "status": "completed",
        "created_at": "2026-10-04T01:00:00+00:00",
        "completed_at": "2026-10-04T01:01:00+00:00",
        "operator": "tester",
        "local_output_name": "stdout.txt",
    }
    (directory / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return evidence


def ready_plan(tmp_path: Path, count: int = 2):
    sources = [collection(tmp_path, f"run-{index}") for index in range(count)]
    db_path = tmp_path / "analyzer.db"
    assert backfill_storage(db_path)["issue_count"] == 0
    report = analyze_storage(db_path)
    assert report["compaction"]["enabled"] is True
    return db_path, sources, report


def test_exact_compaction_preserves_paths_records_and_is_idempotent(tmp_path):
    db_path, sources, report = ready_plan(tmp_path)
    before_manifests = [path.with_name("manifest.json").read_bytes() for path in sources]
    before_observations = report["observation_count"]

    result = compact_storage(db_path, report["compaction"]["plan_id"])

    canonical = canonical_artifact_path(
        artifact_root_for(db_path), report["compaction"]["eligible_files"][0]["sha256"]
    )
    assert result["replaced_file_count"] == 2
    assert result["estimated_file_length_savings"] == 2 * len(b"same exact evidence")
    assert result["references_removed"] == 0
    assert all(path.is_file() and path.read_bytes() == b"same exact evidence" for path in sources)
    assert all(path.stat().st_ino == canonical.stat().st_ino for path in sources)
    assert [path.with_name("manifest.json").read_bytes() for path in sources] == before_manifests
    after = analyze_storage(db_path)
    assert after["observation_count"] == before_observations
    assert after["reclaimable_bytes"] == 0
    assert after["compaction"]["status"] == "nothing_to_compact"


def test_compaction_plan_survives_reads_but_not_source_change(tmp_path):
    db_path, sources, report = ready_plan(tmp_path, 1)
    assert analyze_storage(db_path)["compaction"]["plan_id"] == report["compaction"]["plan_id"]
    sources[0].write_bytes(b"changed after confirmation")
    with pytest.raises(ValueError, match="Storage changed since the dry run"):
        compact_storage(db_path, report["compaction"]["plan_id"])
    assert sources[0].read_bytes() == b"changed after confirmation"


def test_compaction_plan_changes_when_provenance_reference_changes(tmp_path):
    db_path, sources, report = ready_plan(tmp_path, 1)
    register_artifact_file(
        db_path=db_path,
        source_path=sources[0],
        source_kind="device_collection",
        source_ref="run-0",
        original_filename="stdout.txt",
        observation_key="additional-reviewed-reference",
    )
    updated = analyze_storage(db_path)
    assert updated["compaction"]["plan_id"] != report["compaction"]["plan_id"]
    with pytest.raises(ValueError, match="Storage changed since the dry run"):
        compact_storage(db_path, report["compaction"]["plan_id"])


def test_permission_mismatch_and_existing_links_are_left_unchanged(tmp_path):
    db_path, sources, _ = ready_plan(tmp_path)
    sources[0].chmod(0o600)
    extra = sources[1].with_name("unexplained-link.txt")
    os.link(sources[1], extra)
    report = analyze_storage(db_path)
    reasons = {item["reason"] for item in report["compaction"]["skipped_files"]}
    assert "security_metadata_mismatch" in reasons
    assert "unexplained_existing_hard_links" in reasons
    assert report["compaction"]["enabled"] is False


def test_extended_attribute_mismatch_is_left_unchanged(tmp_path):
    if not hasattr(os, "setxattr"):
        pytest.skip("Extended attributes are unavailable")
    db_path, sources, _ = ready_plan(tmp_path, 1)
    try:
        os.setxattr(sources[0], "user.nct-test", b"source-only")
    except OSError:
        pytest.skip("Test filesystem does not support user extended attributes")
    report = analyze_storage(db_path)
    assert "security_metadata_mismatch" in {
        item["reason"] for item in report["compaction"]["skipped_files"]
    }
    assert report["compaction"]["enabled"] is False


def test_replacement_failure_keeps_original_and_records_restored(tmp_path, monkeypatch):
    import app.storage_health as storage

    db_path, sources, report = ready_plan(tmp_path, 1)
    original_inode = sources[0].stat().st_ino
    original_replace = storage.os.replace

    def fail_replacement(source, destination):
        if str(source).endswith(".compact"):
            raise OSError("simulated replacement failure")
        return original_replace(source, destination)

    monkeypatch.setattr(storage.os, "replace", fail_replacement)
    result = compact_storage(db_path, report["compaction"]["plan_id"])
    assert result["replaced_file_count"] == 0
    assert result["issue_count"] == 1
    assert sources[0].stat().st_ino == original_inode
    assert not recovery_required(db_path)


def test_canonical_corruption_after_preparation_restores_original(tmp_path, monkeypatch):
    import app.storage_health as storage

    db_path, sources, report = ready_plan(tmp_path, 1)
    original_inode = sources[0].stat().st_ino
    canonical = tmp_path / report["compaction"]["eligible_files"][0]["canonical_path"]
    original_link = storage.os.link

    def corrupt_after_link(source, destination):
        result = original_link(source, destination)
        if Path(source) == canonical and str(destination).endswith(".compact"):
            canonical.write_bytes(b"corrupt canonical")
        return result

    monkeypatch.setattr(storage.os, "link", corrupt_after_link)
    result = compact_storage(db_path, report["compaction"]["plan_id"])
    assert result["replaced_file_count"] == 0
    assert sources[0].stat().st_ino == original_inode
    assert sources[0].read_bytes() == b"same exact evidence"
    assert result["report"]["compaction"]["status"] == "blocked"


def test_failed_restoration_persistently_blocks_evidence_changes(tmp_path, monkeypatch):
    import app.storage_health as storage

    db_path, _, report = ready_plan(tmp_path, 1)
    canonical = tmp_path / report["compaction"]["eligible_files"][0]["canonical_path"]
    original_link = storage.os.link

    def corrupt_after_link(source, destination):
        result = original_link(source, destination)
        if Path(source) == canonical and str(destination).endswith(".compact"):
            canonical.write_bytes(b"corrupt canonical")
        return result

    monkeypatch.setattr(storage.os, "link", corrupt_after_link)
    monkeypatch.setattr(storage, "_restore_original", lambda *args, **kwargs: (_ for _ in ()).throw(OSError("restore failed")))
    with pytest.raises(EvidenceMaintenanceBlocked, match="requires recovery"):
        compact_storage(db_path, report["compaction"]["plan_id"])
    assert recovery_required(db_path)
    with pytest.raises(EvidenceMaintenanceBlocked, match="recovery"):
        register_artifact_bytes(
            db_path=db_path, content=b"new", source_kind="test", source_ref="blocked"
        )
    with pytest.raises(EvidenceMaintenanceBlocked, match="recovery"):
        backfill_storage(db_path)


def test_real_replaced_journal_state_is_restored_after_restart(tmp_path):
    db_path, sources, report = ready_plan(tmp_path, 1)
    candidate = report["compaction"]["eligible_files"][0]
    source = sources[0]
    canonical = tmp_path / candidate["canonical_path"]
    original_inode = source.stat().st_ino
    _init_compaction_journal(db_path)
    recovery_dir = tmp_path / ".artifact-compaction-recovery" / "crash"
    recovery_dir.mkdir(parents=True)
    recovery = recovery_dir / "item.recovery"
    item = {
        **candidate,
        "compaction_id": "crash",
        "item_id": "item",
        "source_path": str(source),
        "canonical_path": str(canonical),
        "recovery_path": str(recovery),
    }
    _journal_item(db_path, item, "preparing")
    os.link(source, recovery)
    _journal_item(db_path, item, "prepared")
    replacement = source.with_name(".interrupted.compact")
    os.link(canonical, replacement)
    os.replace(replacement, source)
    _journal_item(db_path, item, "replaced")
    assert source.stat().st_ino == canonical.stat().st_ino

    recovered = recover_incomplete_compactions(db_path)

    assert recovered == {"resolved": 1, "recovery_required": 0}
    assert source.stat().st_ino == original_inode
    assert not recovery.exists()
    assert not recovery_required(db_path)


def test_preparing_state_rechecks_original_content_before_clearing(tmp_path):
    db_path, sources, report = ready_plan(tmp_path, 1)
    candidate = report["compaction"]["eligible_files"][0]
    source = sources[0]
    canonical = tmp_path / candidate["canonical_path"]
    _init_compaction_journal(db_path)
    recovery = (
        tmp_path / ".artifact-compaction-recovery" / "preparing-corrupt"
        / "preparing-item.recovery"
    )
    item = {
        **candidate,
        "compaction_id": "preparing-corrupt",
        "item_id": "preparing-item",
        "source_path": str(source),
        "canonical_path": str(canonical),
        "recovery_path": str(recovery),
    }
    _journal_item(db_path, item, "preparing")
    source.write_bytes(b"X" * candidate["size_bytes"])
    os.utime(
        source,
        ns=(candidate["source_fingerprint"]["mtime_ns"],
            candidate["source_fingerprint"]["mtime_ns"]),
    )

    recovered = recover_incomplete_compactions(db_path)

    assert recovered["recovery_required"] == 1
    assert recovery_required(db_path)
    assert source.read_bytes() != b"same exact evidence"


def test_verified_interrupted_state_finishes_cleanup_without_rollback(tmp_path):
    db_path, sources, report = ready_plan(tmp_path, 1)
    candidate = report["compaction"]["eligible_files"][0]
    source = sources[0]
    canonical = tmp_path / candidate["canonical_path"]
    _init_compaction_journal(db_path)
    recovery_dir = tmp_path / ".artifact-compaction-recovery" / "verified-crash"
    recovery_dir.mkdir(parents=True)
    recovery = recovery_dir / "verified-item.recovery"
    item = {
        **candidate,
        "compaction_id": "verified-crash",
        "item_id": "verified-item",
        "source_path": str(source),
        "canonical_path": str(canonical),
        "recovery_path": str(recovery),
    }
    os.link(source, recovery)
    replacement = source.with_name(".verified.compact")
    os.link(canonical, replacement)
    os.replace(replacement, source)
    _journal_item(db_path, item, "verified")

    recovered = recover_incomplete_compactions(db_path)

    assert recovered == {"resolved": 1, "recovery_required": 0}
    assert source.stat().st_ino == canonical.stat().st_ino
    assert not recovery.exists()


def test_verified_interrupted_state_rechecks_hash_and_restores_original(tmp_path):
    db_path, sources, report = ready_plan(tmp_path, 1)
    candidate = report["compaction"]["eligible_files"][0]
    source = sources[0]
    canonical = tmp_path / candidate["canonical_path"]
    original_inode = source.stat().st_ino
    _init_compaction_journal(db_path)
    recovery_dir = tmp_path / ".artifact-compaction-recovery" / "verified-corrupt"
    recovery_dir.mkdir(parents=True)
    recovery = recovery_dir / "verified-corrupt-item.recovery"
    item = {
        **candidate,
        "compaction_id": "verified-corrupt",
        "item_id": "verified-corrupt-item",
        "source_path": str(source),
        "canonical_path": str(canonical),
        "recovery_path": str(recovery),
    }
    os.link(source, recovery)
    replacement = source.with_name(".verified-corrupt.compact")
    os.link(canonical, replacement)
    os.replace(replacement, source)
    _journal_item(db_path, item, "verified")
    canonical.write_bytes(b"CORRUPT")

    recovered = recover_incomplete_compactions(db_path)

    assert recovered == {"resolved": 1, "recovery_required": 0}
    assert source.stat().st_ino == original_inode
    assert source.read_bytes() == b"same exact evidence"
    assert not recovery.exists()


def test_verified_corruption_without_recovery_link_blocks_mutations(tmp_path):
    db_path, sources, report = ready_plan(tmp_path, 1)
    candidate = report["compaction"]["eligible_files"][0]
    source = sources[0]
    canonical = tmp_path / candidate["canonical_path"]
    _init_compaction_journal(db_path)
    recovery = (
        tmp_path / ".artifact-compaction-recovery" / "verified-missing"
        / "verified-missing-item.recovery"
    )
    item = {
        **candidate,
        "compaction_id": "verified-missing",
        "item_id": "verified-missing-item",
        "source_path": str(source),
        "canonical_path": str(canonical),
        "recovery_path": str(recovery),
    }
    replacement = source.with_name(".verified-missing.compact")
    os.link(canonical, replacement)
    os.replace(replacement, source)
    _journal_item(db_path, item, "verified")
    canonical.write_bytes(b"CORRUPT")

    recovered = recover_incomplete_compactions(db_path)

    assert recovered["recovery_required"] == 1
    assert recovery_required(db_path)
    with pytest.raises(EvidenceMaintenanceBlocked):
        register_artifact_bytes(
            db_path=db_path, content=b"blocked", source_kind="test", source_ref="blocked"
        )


def test_replaced_journal_failure_restores_original_before_gate_releases(tmp_path, monkeypatch):
    import app.storage_health as storage

    db_path, sources, report = ready_plan(tmp_path, 1)
    original_inode = sources[0].stat().st_ino
    original_journal = storage._journal_item

    def fail_replaced(db, item, state, detail=None):
        if state == "replaced":
            raise storage.sqlite3.OperationalError("simulated replaced journal failure")
        return original_journal(db, item, state, detail)

    monkeypatch.setattr(storage, "_journal_item", fail_replaced)
    result = compact_storage(db_path, report["compaction"]["plan_id"])

    assert result["replaced_file_count"] == 0
    assert result["issue_count"] == 1
    assert sources[0].stat().st_ino == original_inode
    assert not recovery_required(db_path)
    with evidence_mutation(db_path):
        pass


def test_completed_journal_failure_keeps_persistent_recovery_block(tmp_path, monkeypatch):
    import app.storage_health as storage

    db_path, _, report = ready_plan(tmp_path, 1)
    original_journal = storage._journal_item

    def fail_completed(db, item, state, detail=None):
        if state == "completed":
            raise storage.sqlite3.OperationalError("simulated completed journal failure")
        return original_journal(db, item, state, detail)

    monkeypatch.setattr(storage, "_journal_item", fail_completed)
    with pytest.raises(EvidenceMaintenanceBlocked, match="requires recovery"):
        compact_storage(db_path, report["compaction"]["plan_id"])

    assert recovery_required(db_path)
    with pytest.raises(EvidenceMaintenanceBlocked):
        with evidence_mutation(db_path):
            pass


def test_missing_recovery_link_blocks_restart_and_concurrent_work(tmp_path):
    db_path, sources, report = ready_plan(tmp_path, 1)
    candidate = report["compaction"]["eligible_files"][0]
    _init_compaction_journal(db_path)
    item = {
        **candidate,
        "compaction_id": "broken",
        "item_id": "broken-item",
        "source_path": str(sources[0]),
        "canonical_path": str(tmp_path / candidate["canonical_path"]),
        "recovery_path": str(
            tmp_path / ".artifact-compaction-recovery" / "broken"
            / "broken-item.recovery"
        ),
    }
    _journal_item(db_path, item, "replaced")
    recovered = recover_incomplete_compactions(db_path)
    assert recovered["recovery_required"] == 1
    with pytest.raises(EvidenceMaintenanceBlocked):
        with evidence_mutation(db_path):
            pass


def test_recovery_rejects_symlinked_source_without_touching_target(tmp_path):
    db_path, sources, report = ready_plan(tmp_path, 1)
    candidate = report["compaction"]["eligible_files"][0]
    source = sources[0]
    canonical = tmp_path / candidate["canonical_path"]
    _init_compaction_journal(db_path)
    recovery_dir = tmp_path / ".artifact-compaction-recovery" / "symlink-crash"
    recovery_dir.mkdir(parents=True)
    recovery = recovery_dir / "symlink-item.recovery"
    item = {
        **candidate,
        "compaction_id": "symlink-crash",
        "item_id": "symlink-item",
        "source_path": str(source),
        "canonical_path": str(canonical),
        "recovery_path": str(recovery),
    }
    os.link(source, recovery)
    replacement = source.with_name(".symlink-crash.compact")
    os.link(canonical, replacement)
    os.replace(replacement, source)
    _journal_item(db_path, item, "replaced")
    unrelated = tmp_path / "unrelated.txt"
    os.link(canonical, unrelated)
    unrelated_inode = unrelated.stat().st_ino
    source.unlink()
    source.symlink_to(unrelated)

    recovered = recover_incomplete_compactions(db_path)

    assert recovered["recovery_required"] == 1
    assert source.is_symlink()
    assert unrelated.stat().st_ino == unrelated_inode
    assert recovery.exists()


def test_recovery_rejects_same_size_same_mtime_corrupt_original(tmp_path):
    db_path, sources, report = ready_plan(tmp_path, 1)
    candidate = report["compaction"]["eligible_files"][0]
    source = sources[0]
    canonical = tmp_path / candidate["canonical_path"]
    _init_compaction_journal(db_path)
    recovery_dir = tmp_path / ".artifact-compaction-recovery" / "corrupt-recovery"
    recovery_dir.mkdir(parents=True)
    recovery = recovery_dir / "corrupt-item.recovery"
    item = {
        **candidate,
        "compaction_id": "corrupt-recovery",
        "item_id": "corrupt-item",
        "source_path": str(source),
        "canonical_path": str(canonical),
        "recovery_path": str(recovery),
    }
    os.link(source, recovery)
    replacement = source.with_name(".corrupt-recovery.compact")
    os.link(canonical, replacement)
    os.replace(replacement, source)
    _journal_item(db_path, item, "replaced")
    recovery.write_bytes(b"X" * candidate["size_bytes"])
    os.utime(
        recovery,
        ns=(candidate["source_fingerprint"]["mtime_ns"],
            candidate["source_fingerprint"]["mtime_ns"]),
    )
    canonical_inode = source.stat().st_ino

    recovered = recover_incomplete_compactions(db_path)

    assert recovered["recovery_required"] == 1
    assert recovery_required(db_path)
    assert source.stat().st_ino == canonical_inode
    assert source.read_bytes() == b"same exact evidence"
    assert recovery.exists()


def test_verified_cleanup_rejects_substituted_recovery_inode(tmp_path):
    db_path, sources, report = ready_plan(tmp_path, 1)
    candidate = report["compaction"]["eligible_files"][0]
    source = sources[0]
    canonical = tmp_path / candidate["canonical_path"]
    _init_compaction_journal(db_path)
    recovery_dir = tmp_path / ".artifact-compaction-recovery" / "substituted-recovery"
    recovery_dir.mkdir(parents=True)
    recovery = recovery_dir / "substituted-item.recovery"
    item = {
        **candidate,
        "compaction_id": "substituted-recovery",
        "item_id": "substituted-item",
        "source_path": str(source),
        "canonical_path": str(canonical),
        "recovery_path": str(recovery),
    }
    os.link(source, recovery)
    replacement = source.with_name(".substituted-recovery.compact")
    os.link(canonical, replacement)
    os.replace(replacement, source)
    _journal_item(db_path, item, "verified")
    recovery.unlink()
    recovery.write_bytes(b"same exact evidence")

    recovered = recover_incomplete_compactions(db_path)

    assert recovered["recovery_required"] == 1
    assert recovery_required(db_path)
    assert source.stat().st_ino == canonical.stat().st_ino
    assert recovery.exists()


def test_recovery_block_preserves_queued_scan_intent(tmp_path):
    import app.poc as poc

    db_path = tmp_path / "analyzer.db"
    data_dir = tmp_path / "data"
    poc.init_poc_storage(db_path)
    manifest = {
        "run_id": "1" * 32,
        "created_at": "2026-10-04T01:00:00+00:00",
        "status": "queued",
        "operator": "analyst",
        "reason": "test",
        "originating_host": "workstation",
        "interface": "eth0",
        "profile": "Standard",
    }
    poc.insert_scan_run_manifest(manifest, db_path)
    mark_recovery_required(db_path, "test recovery block")
    with poc.ACTIVE_RUNS_LOCK:
        poc.ACTIVE_RUNS.clear()

    assert poc.dispatch_next_queued_run(db_path=db_path, data_dir=data_dir) is None
    control = poc.RunControl()
    with poc.ACTIVE_RUNS_LOCK:
        poc.ACTIVE_RUNS[manifest["run_id"]] = control
    poc._scan_worker_entry(
        manifest["run_id"], control, db_path=db_path, data_dir=data_dir
    )

    assert poc.get_scan_run_plan(manifest["run_id"], db_path)["status"] == "queued"
    with poc.ACTIVE_RUNS_LOCK:
        assert manifest["run_id"] not in poc.ACTIVE_RUNS
    clear_recovery_required(db_path)


def test_maintenance_and_evidence_mutations_exclude_each_other(tmp_path):
    db_path = tmp_path / "analyzer.db"
    with evidence_mutation(db_path):
        with pytest.raises(EvidenceMaintenanceBlocked, match="active"):
            with evidence_maintenance(db_path):
                pass
    with evidence_maintenance(db_path):
        with pytest.raises(EvidenceMaintenanceBlocked, match="temporarily blocked"):
            with evidence_mutation(db_path):
                pass


def test_insufficient_free_space_stops_before_replacement(tmp_path, monkeypatch):
    import app.storage_health as storage

    db_path, sources, report = ready_plan(tmp_path, 1)
    original_inode = sources[0].stat().st_ino
    usage = shutil.disk_usage(tmp_path)
    monkeypatch.setattr(storage.shutil, "disk_usage", lambda *_: usage._replace(free=0))
    with pytest.raises(ValueError, match="1 MiB"):
        compact_storage(db_path, report["compaction"]["plan_id"])
    assert sources[0].stat().st_ino == original_inode


def test_background_storage_job_runs_reviewed_plan_to_completion(tmp_path):
    from app.storage_health import start_storage_job, storage_status

    db_path, sources, _ = ready_plan(tmp_path, 1)
    start_storage_job(db_path, "dry-run")
    for _ in range(200):
        dry_run = storage_status(db_path)
        if dry_run["status"] != "running":
            break
        time.sleep(0.01)
    assert dry_run["status"] == "complete"
    plan = dry_run["report"]["compaction"]
    assert plan["enabled"] is True

    start_storage_job(
        db_path,
        "compact",
        plan_id=plan["plan_id"],
        confirmation="REMOVE VERIFIED DUPLICATE COPIES",
    )
    for _ in range(200):
        result = storage_status(db_path)
        if result["status"] != "running":
            break
        time.sleep(0.01)
    assert result["status"] == "complete"
    assert result["compaction_result"]["replaced_file_count"] == 1
    canonical = canonical_artifact_path(
        artifact_root_for(db_path),
        dry_run["report"]["compaction"]["eligible_files"][0]["sha256"],
    )
    assert sources[0].stat().st_ino == canonical.stat().st_ino


def test_compaction_route_requires_confirmed_plan_and_same_origin(tmp_path, monkeypatch):
    import app.main as main

    calls = []
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "analyzer.db")
    monkeypatch.setattr(main, "auth_enabled", lambda: False)
    monkeypatch.setattr(
        main,
        "start_storage_job",
        lambda db, mode, **kwargs: calls.append((db, mode, kwargs))
        or {"status": "running", "mode": mode},
    )
    client = TestClient(main.app)
    body = {
        "plan_id": "a" * 64,
        "confirmation": "REMOVE VERIFIED DUPLICATE COPIES",
    }
    response = client.post("/api/system/storage/compact", json=body)
    assert response.status_code == 202
    assert calls == [(tmp_path / "analyzer.db", "compact", {
        "plan_id": "a" * 64,
        "confirmation": "REMOVE VERIFIED DUPLICATE COPIES",
    })]
    blocked = client.post(
        "/api/system/storage/compact",
        json=body,
        headers={"Origin": "https://outside.example"},
    )
    assert blocked.status_code == 403


def test_system_health_explains_and_confirms_exact_compaction():
    from app.storage_ui import storage_page

    html = storage_page().body.decode()
    assert "Remove verified duplicate copies" in html
    assert "byte-for-byte identical" in html
    assert "Scan history, evidence links, filenames, attribution" in html
    assert "filesystem timestamps and security settings" in html
    assert "REMOVE VERIFIED DUPLICATE COPIES" in html
    assert "/api/system/storage/compact" in html
    assert "estimated file-length savings" in html
    assert "measured free-space change" in html
