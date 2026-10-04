import hashlib
import json
import os
import sqlite3
import shutil
import threading
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.artifacts import (artifact_storage_summary, get_artifact, register_artifact_bytes,
                           register_artifact_file, register_finalized_files)
from app.storage_health import analyze_storage, backfill_storage, start_storage_job, storage_status


def collection(root, run_id, content=b"router evidence", status="completed", folder="device-configs"):
    directory = root / folder / run_id
    directory.mkdir(parents=True)
    filename = "stdout.txt" if folder == "device-configs" else "scan.xml"
    (directory / filename).write_bytes(content)
    manifest = {"run_id": run_id, "status": status, "created_at": "2026-09-26T10:00:00+00:00",
                "operator": "alice", "local_output_name": filename}
    (directory / "manifest.json").write_text(json.dumps(manifest))
    return directory, manifest


def snapshot(root):
    return {str(p.relative_to(root)): p.read_bytes() for p in root.rglob("*") if p.is_file()}


def test_dry_run_is_read_only_and_counts_distinct_physical_copies(tmp_path):
    collection(tmp_path, "a")
    collection(tmp_path, "b")
    before = snapshot(tmp_path)
    result = analyze_storage(tmp_path / "analyzer.db")
    assert snapshot(tmp_path) == before
    assert result["duplicate_bytes"] == len(b"router evidence")
    assert result["unique_artifact_count"] == 1
    assert result["reclaimable_bytes"] == 0  # no canonical copy verified yet
    assert result["used_bytes"] == sum(map(len, before.values()))
    assert result["compaction"]["enabled"] is False


def test_hardlinks_are_not_reclaimable_copies(tmp_path):
    first, _ = collection(tmp_path, "a")
    second, _ = collection(tmp_path, "b")
    (second / "stdout.txt").unlink()
    os.link(first / "stdout.txt", second / "stdout.txt")
    result = analyze_storage(tmp_path / "analyzer.db")
    assert result["duplicate_bytes"] == 0
    assert result["logical_bytes"] - result["used_bytes"] == len(b"router evidence")


def test_backfill_resumes_preserves_originals_and_observations(tmp_path):
    collection(tmp_path, "a")
    collection(tmp_path, "b")
    before = snapshot(tmp_path)
    db_path = tmp_path / "analyzer.db"
    first = backfill_storage(db_path)
    assert first["completed"] == 2
    assert first["issue_count"] == 0
    second = backfill_storage(db_path)
    assert second["completed"] == 0
    assert second["resumed_unchanged"] == 2
    assert all((tmp_path / name).read_bytes() == value for name, value in before.items())
    summary = artifact_storage_summary(db_path)
    assert summary["unique_artifact_count"] == 1
    assert summary["observation_count"] == 2
    result = analyze_storage(db_path)
    assert result["reclaimable_bytes"] == 2 * len(b"router evidence")
    assert result["verified_references"] == 2


def test_backfill_retries_after_checkpoint_loss_without_duplicate_observation(tmp_path):
    collection(tmp_path, "a")
    db_path = tmp_path / "analyzer.db"
    backfill_storage(db_path)
    with sqlite3.connect(db_path) as db:
        db.execute("DELETE FROM artifact_backfill")
    assert backfill_storage(db_path)["resumed_unchanged"] == 1
    assert artifact_storage_summary(db_path)["observation_count"] == 1


def test_missing_evidence_and_active_collection_block_candidates(tmp_path):
    directory, _ = collection(tmp_path, "a")
    (directory / "stdout.txt").unlink()
    collection(tmp_path, "b", status="running")
    report = analyze_storage(tmp_path / "analyzer.db")
    assert report["issue_count"] == 1
    assert report["active_collections_skipped"] == 1
    assert report["compaction"]["status"] == "blocked"
    assert report["reclaimable_bytes"] == 0


def test_corrupt_canonical_blocks_reclaim_and_backfill_does_not_overwrite(tmp_path):
    collection(tmp_path, "a")
    db_path = tmp_path / "analyzer.db"
    backfill_storage(db_path)
    canonical = next((tmp_path / "artifacts").glob("sha256/*/*"))
    canonical.write_bytes(b"damaged")
    assert backfill_storage(db_path)["issue_count"] == 1
    assert canonical.read_bytes() == b"damaged"
    report = analyze_storage(db_path)
    assert report["compaction"]["status"] == "blocked"
    assert report["reclaimable_bytes"] == 0


def test_symlinks_are_not_followed(tmp_path):
    directory, _ = collection(tmp_path, "a")
    (directory / "stdout.txt").unlink()
    (directory / "stdout.txt").symlink_to("/etc/passwd")
    report = analyze_storage(tmp_path / "analyzer.db")
    assert report["verified_references"] == 0
    assert report["issue_count"] > 0
    assert backfill_storage(tmp_path / "analyzer.db")["completed"] == 0


def test_registered_files_keep_download_paths_and_backfill_is_idempotent(tmp_path):
    directory, manifest = collection(tmp_path, "a")
    db_path = tmp_path / "analyzer.db"
    register_finalized_files(db_path, directory, manifest, "device_collection", ["stdout.txt"])
    assert manifest["artifact_registry"]["status"] == "complete"
    assert (directory / "stdout.txt").read_bytes() == b"router evidence"
    backfill_storage(db_path)
    assert artifact_storage_summary(db_path)["observation_count"] == 1
    assert analyze_storage(db_path)["duplicate_bytes"] == 0


def test_backfilled_dates_do_not_move_last_seen_backwards(tmp_path):
    db_path = tmp_path / "analyzer.db"
    for observed in ("2026-09-27T10:00:00+00:00", "2026-09-20T10:00:00+00:00"):
        record = register_artifact_bytes(db_path=db_path, content=b"same", source_kind="test", source_ref="test", observed_at=observed)
    retained = get_artifact(db_path, record["sha256"])
    assert retained["first_seen_at"].startswith("2026-09-20")
    assert retained["last_seen_at"].startswith("2026-09-27")


def test_changing_source_is_rejected(tmp_path, monkeypatch):
    import app.artifacts as artifacts
    path = tmp_path / "incoming"
    path.write_bytes(b"original")
    original = artifacts.sha256_file
    def change_after_hash(file):
        result = original(file)
        if file == path:
            path.write_bytes(b"changed")
        return result
    monkeypatch.setattr(artifacts, "sha256_file", change_after_hash)
    with pytest.raises(ValueError, match="changed"):
        register_artifact_file(db_path=tmp_path / "analyzer.db", source_path=path, source_kind="test", source_ref="test")
    assert not list((tmp_path / "artifacts").glob("sha256/*/*.tmp"))


def test_import_hash_mismatch_does_not_register_false_provenance(tmp_path):
    db_path = tmp_path / "analyzer.db"
    evidence = tmp_path / "legacy.xml"
    evidence.write_bytes(b"changed")
    with sqlite3.connect(db_path) as db:
        db.execute("CREATE TABLE imports (sha256 TEXT, filename TEXT, stored_path TEXT, imported_at TEXT)")
        db.execute("INSERT INTO imports VALUES (?, ?, ?, ?)", (hashlib.sha256(b"original").hexdigest(), "old.xml", str(evidence), "2026-09-20"))
    assert backfill_storage(db_path)["issue_count"] == 1
    assert not (tmp_path / "artifacts").exists()


def test_background_status_survives_restart_and_prevents_overlap(tmp_path, monkeypatch):
    import app.storage_health as storage
    entered, release = threading.Event(), threading.Event()
    def inspect(_):
        entered.set()
        release.wait(3)
        return {"test": True}
    monkeypatch.setattr(storage, "analyze_storage", inspect)
    db_path = tmp_path / "analyzer.db"
    start_storage_job(db_path, "dry-run")
    assert entered.wait(2)
    try:
        with pytest.raises(ValueError, match="already running"):
            start_storage_job(db_path, "backfill")
    finally:
        release.set()
    for _ in range(100):
        if storage_status(db_path)["status"] == "complete":
            break
        time.sleep(.01)
    assert storage_status(db_path)["report"] == {"test": True}
    (tmp_path / "storage-health.json").write_text('{"status":"running"}')
    assert storage_status(db_path)["status"] == "interrupted"


def manual_upload(root, registered=True):
    directory = root / "device-configs" / "upload-a"
    directory.mkdir(parents=True)
    path = directory / "uploaded-router-config.txt"
    path.write_bytes(b"original upload")
    manifest = {"run_id": "upload-a", "status": "uploaded", "operation": "manual_upload",
                "source_filename": "router config.txt", "operator": "alice",
                "completed_at": "2026-09-20T10:00:00+00:00",
                "artifact_sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
    if registered:
        record = register_artifact_file(db_path=root / "analyzer.db", source_path=path,
            source_kind="device_config_upload", source_ref="upload-a", original_filename="router config.txt",
            actor="alice", observed_at=manifest["completed_at"])
        manifest["artifact_observation_id"] = record["observation_id"]
    (directory / "manifest.json").write_text(json.dumps(manifest))
    return path


@pytest.mark.parametrize("damage", ["missing", "changed", "directory"])
def test_manual_upload_damage_blocks_inspection_and_false_backfill(tmp_path, damage):
    path = manual_upload(tmp_path)
    db_path = tmp_path / "analyzer.db"
    if damage == "missing":
        path.unlink()
    elif damage == "changed":
        path.write_bytes(b"replacement")
    else:
        shutil.rmtree(path.parent)
    report = analyze_storage(db_path)
    assert report["issue_count"] > 0
    assert report["compaction"]["status"] == "blocked"
    assert report["reclaimable_bytes"] == 0
    assert backfill_storage(db_path)["completed"] == 0
    assert artifact_storage_summary(db_path)["observation_count"] == 1


@pytest.mark.parametrize("registered", [True, False])
def test_upload_backfill_preserves_identity_and_provenance(tmp_path, registered):
    path = manual_upload(tmp_path, registered)
    db_path = tmp_path / "analyzer.db"
    before = get_artifact(db_path, hashlib.sha256(path.read_bytes()).hexdigest()) if registered else None
    assert backfill_storage(db_path)["issue_count"] == 0
    with sqlite3.connect(db_path) as db:
        db.execute("DELETE FROM artifact_backfill")
    assert backfill_storage(db_path)["issue_count"] == 0
    artifact = get_artifact(db_path, hashlib.sha256(path.read_bytes()).hexdigest())
    assert len(artifact["observations"]) == 1
    obs = artifact["observations"][0]
    assert (obs["source_kind"], obs["original_filename"], obs["actor"], obs["observed_at"]) == (
        "device_config_upload", "router config.txt", "alice", "2026-09-20T10:00:00+00:00")
    if registered:
        assert artifact["observations"] == before["observations"]


def test_traversal_import_does_not_copy_outside_storage(tmp_path):
    root = tmp_path / "data"
    root.mkdir()
    outside = tmp_path / "outside.xml"
    outside.write_bytes(b"outside")
    db_path = root / "analyzer.db"
    with sqlite3.connect(db_path) as db:
        db.execute("CREATE TABLE imports (sha256 TEXT, filename TEXT, stored_path TEXT, imported_at TEXT)")
        db.execute("INSERT INTO imports VALUES (?, ?, ?, ?)", (hashlib.sha256(b"outside").hexdigest(),
            "outside.xml", str(root / ".." / "outside.xml"), "2026-09-20"))
    assert analyze_storage(db_path)["issue_count"] > 0
    assert backfill_storage(db_path)["completed"] == 0
    assert not (root / "artifacts").exists()


def test_timed_out_scan_is_finalized(tmp_path):
    collection(tmp_path, "timeout", status="timed_out", folder="scan-runs")
    result = backfill_storage(tmp_path / "analyzer.db")
    assert result["completed"] == 1
    assert result["active_collections_skipped"] == 0


def test_import_existing_observation_not_duplicated(tmp_path):
    db_path = tmp_path / "analyzer.db"
    record = register_artifact_bytes(db_path=db_path, content=b"xml", source_kind="nmap_import",
        source_ref="upload:original", original_filename="original name.xml", actor="alice", observed_at="2026-09-20")
    with sqlite3.connect(db_path) as db:
        db.execute("CREATE TABLE imports (sha256 TEXT, filename TEXT, stored_path TEXT, imported_at TEXT)")
        db.execute("INSERT INTO imports VALUES (?, ?, ?, ?)", (record["sha256"], "original-name.xml",
            record["canonical_path"], "2026-09-20"))
    assert backfill_storage(db_path)["issue_count"] == 0
    assert artifact_storage_summary(db_path)["observation_count"] == 1


def test_checkpoint_does_not_hide_missing_observation(tmp_path):
    manual_upload(tmp_path)
    db_path = tmp_path / "analyzer.db"
    backfill_storage(db_path)
    with sqlite3.connect(db_path) as db:
        db.execute("DELETE FROM artifact_observations")
    assert backfill_storage(db_path)["completed"] == 1
    assert artifact_storage_summary(db_path)["observation_count"] == 1


def test_checkpoint_does_not_hide_changed_expected_hash(tmp_path):
    path = manual_upload(tmp_path)
    db_path = tmp_path / "analyzer.db"
    backfill_storage(db_path)
    manifest_path = path.parent / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["artifact_sha256"] = "f" * 64
    manifest_path.write_text(json.dumps(manifest))
    assert backfill_storage(db_path)["issue_count"] > 0
    assert analyze_storage(db_path)["compaction"]["status"] == "blocked"


@pytest.mark.parametrize("role,expected", [(None, 401), ("viewer", 403), ("analyst", 403), ("admin", 200)])
def test_storage_routes_require_administrator(tmp_path, monkeypatch, role, expected):
    import app.main as main
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "analyzer.db")
    monkeypatch.setattr(main, "auth_enabled", lambda: True)
    monkeypatch.setattr(main, "session_identity", lambda *args: {"username": "test", "role": role} if role else None)
    client = TestClient(main.app)
    assert client.get("/api/system/storage").status_code == expected
    assert client.get("/api/system/analysis-status").status_code == expected
    assert client.get("/api/system/analysis-versions").status_code == expected
    if role != "admin":
        assert client.get("/api/system/analysis-status/missing/inputs").status_code == expected
        assert client.get(
            "/api/system/analysis-status/missing/inputs/nmap_xml/source-records"
        ).status_code == expected
        assert client.get(
            "/api/system/analysis-status/missing/inputs/nmap_xml/saved-calculations"
        ).status_code == expected
        assert client.get(
            "/api/system/analysis-versions/bad/results?representative_result_id=result"
        ).status_code == expected
        assert client.post("/api/system/storage/backfill").status_code == expected
    else:
        assert client.get("/settings/system-health").status_code == 200
        assert client.get("/api/system/analysis-status?limit=101").status_code == 422
        assert client.get("/api/system/analysis-versions?limit=101").status_code == 422
        assert client.get(
            "/api/system/analysis-versions/bad/results?representative_result_id=result"
        ).status_code == 400
        assert client.get("/api/system/analysis-status/missing/inputs").status_code == 404
        assert client.get(
            "/api/system/analysis-status/missing/inputs/nmap_xml/source-records?limit=101"
        ).status_code == 422
        assert client.get(
            "/api/system/analysis-status/missing/inputs/nmap_xml/saved-calculations?limit=101"
        ).status_code == 422
        assert client.post("/api/system/storage/delete").status_code == 400
        assert client.post("/api/system/storage/dry-run", headers={"Origin": "https://unrelated.example"}).status_code == 403
