from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import subprocess
import sys

import pytest


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import nct_kubernetes_recovery as recovery  # noqa: E402


def identity(name: str, value: str) -> str:
    return json.dumps({
        "namespace": "nct", "pvc": name,
        "pvc_uid": f"{value}1111111-2222-4333-8444-555555555555",
        "bound_volume_uid": f"{value}aaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
    })


def fixture_data(root: Path) -> dict:
    root.mkdir()
    (root / recovery.WRITER_LOCK_NAME).write_bytes(b"")
    artifact = root / "artifacts" / "sha256" / "ab" / "abcdef"
    artifact.parent.mkdir(parents=True)
    content = b"exact retained evidence\n"
    artifact.write_bytes(content)
    duplicate = root / "imports" / "duplicate.xml"
    duplicate.parent.mkdir()
    os.link(artifact, duplicate)
    (root / "packages").mkdir()
    (root / "packages" / "portable.zip").write_bytes(b"package")
    db_path = root / "analyzer.db"
    db = sqlite3.connect(db_path)
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA wal_autocheckpoint=0")
    db.execute("CREATE TABLE artifact_registry (sha256 TEXT PRIMARY KEY, size_bytes INTEGER, canonical_path TEXT)")
    digest = hashlib.sha256(content).hexdigest()
    db.execute("INSERT INTO artifact_registry VALUES (?, ?, ?)",
               (digest, len(content), "/data/artifacts/sha256/ab/abcdef"))
    db.execute("CREATE TABLE imports (sha256 TEXT, filename TEXT, stored_path TEXT, imported_at TEXT)")
    db.execute("INSERT INTO imports VALUES (?, ?, ?, ?)",
               (digest, "duplicate.xml", "/data/imports/duplicate.xml", "2026-10-12T00:00:00Z"))
    db.execute("""CREATE TABLE artifact_observations (
                   source_kind TEXT, source_ref TEXT, original_filename TEXT, sha256 TEXT,
                   observation_id TEXT, metadata_json TEXT, observed_at TEXT)""")
    db.execute("INSERT INTO artifact_observations VALUES (?, ?, ?, ?, ?, ?, ?)",
               ("nmap_import", digest, "duplicate.xml", digest, "observation-1", "{}",
                "2026-10-12T00:00:00Z"))
    db.execute("CREATE TABLE retained_records (id INTEGER PRIMARY KEY, value TEXT)")
    db.execute("INSERT INTO retained_records(value) VALUES ('one')")
    db.commit()
    db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    reader = sqlite3.connect(db_path)
    reader.execute("BEGIN")
    reader.execute("SELECT COUNT(*) FROM retained_records").fetchone()
    db.execute("INSERT INTO retained_records(value) VALUES ('wal-resident')")
    db.commit()
    db.close()
    assert (root / "analyzer.db-wal").exists()
    return {"reader": reader, "digest": digest, "content": content}


def backup_args(source: Path, backup: Path, backup_id: str = "backup-20261012") -> argparse.Namespace:
    backup.mkdir(parents=True, exist_ok=True)
    return argparse.Namespace(
        source=source, backup_root=backup, backup_id=backup_id,
        source_identity=identity("nct-data", "1"),
        backup_identity=identity("nct-backup", "2"),
        source_qualification_report_digest="a" * 64,
        backup_qualification_report_digest="c" * 64,
        image="registry.example/nct@sha256:" + "b" * 64,
        application_version="0.14.0-dev", build_id="test-build",
        max_files=10_000, max_bytes=1024**3, max_seconds=60,
    )


def restore_args(backup: Path, target: Path, backup_id: str = "backup-20261012") -> argparse.Namespace:
    target.mkdir(parents=True, exist_ok=True)
    receipt = json.loads((backup / "receipts" / f"{backup_id}.json").read_text())
    return argparse.Namespace(
        backup_root=backup, backup_id=backup_id,
        backup_identity=identity("nct-backup", "2"),
        target=target, target_identity=identity("nct-restore", "3"),
        expected_source_identity=identity("nct-data", "1"),
        expected_receipt_digest=receipt["receipt_sha256"],
        backup_qualification_report_digest="c" * 64,
        target_qualification_report_digest="d" * 64,
        receipt_path=target.parent / f"{backup_id}-restore-receipt.json",
        max_files=10_000, max_bytes=1024**3, max_seconds=60,
    )


def source_state(root: Path) -> dict[str, tuple[bytes, int, int, int]]:
    return {
        path.relative_to(root).as_posix(): (
            path.read_bytes(), path.stat().st_mode, path.stat().st_mtime_ns, path.stat().st_ctime_ns,
        )
        for path in root.rglob("*") if path.is_file()
    }


def public_source_inventory(root: Path) -> list[dict]:
    items = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        if relative == recovery.WRITER_LOCK_NAME:
            continue
        mode = stat.S_IMODE(path.stat().st_mode)
        if path.is_dir():
            items.append({"path": relative, "kind": "directory", "mode": mode, "size": 0,
                          "sha256": hashlib.sha256(b"").hexdigest()})
        else:
            payload = path.read_bytes()
            items.append({"path": relative, "kind": "file", "mode": mode, "size": len(payload),
                          "sha256": hashlib.sha256(payload).hexdigest()})
    return sorted(items, key=lambda item: item["path"])


def test_cold_backup_and_empty_target_restore_preserve_wal_artifacts_and_hardlinks(tmp_path: Path) -> None:
    source, backup, target = tmp_path / "source", tmp_path / "backup", tmp_path / "target"
    fixture = fixture_data(source)
    try:
        expected_inventory = public_source_inventory(source)
        backup_receipt = recovery.create_backup(backup_args(source, backup))
        manifest = json.loads((backup / "backup-20261012" / "manifest.json").read_text())
        assert manifest["inventory"] == expected_inventory
    finally:
        fixture["reader"].close()
    assert backup_receipt["status"] == "backup_verified"
    paths = {item["path"] for item in manifest["inventory"]}
    assert {"analyzer.db", "analyzer.db-wal", "analyzer.db-shm"} <= paths
    assert "artifacts/sha256/ab/abcdef" in paths
    assert "imports/duplicate.xml" in paths
    result = recovery.restore_backup(restore_args(backup, target))
    assert result["status"] == "restore_verification_passed"
    assert result["source_image"] == "registry.example/nct@sha256:" + "b" * 64
    assert result["source_application_version"] == "0.14.0-dev"
    assert result["source_build_id"] == "test-build"
    assert result["backup_receipt_sha256"] == backup_receipt["receipt_sha256"]
    assert json.loads((tmp_path / "backup-20261012-restore-receipt.json").read_text())["receipt_sha256"] == result["receipt_sha256"]
    assert result["artifact_registry_verified"] == 1
    assert result["retained_evidence_verified"] == 1
    assert (target / "artifacts" / "sha256" / "ab" / "abcdef").read_bytes() == fixture["content"]
    db = sqlite3.connect(target / "analyzer.db")
    try:
        assert db.execute("SELECT COUNT(*) FROM retained_records").fetchone()[0] == 2
    finally:
        db.close()
    assert not (target / recovery.WRITER_LOCK_NAME).exists()


def test_backup_does_not_change_source_bytes_or_metadata(tmp_path: Path) -> None:
    source, backup = tmp_path / "source", tmp_path / "backup"
    fixture = fixture_data(source)
    before = source_state(source)
    try:
        recovery.create_backup(backup_args(source, backup))
        assert source_state(source) == before
    finally:
        fixture["reader"].close()


def test_backup_requires_preexisting_writer_lock(tmp_path: Path) -> None:
    source, backup = tmp_path / "source", tmp_path / "backup"
    fixture = fixture_data(source)
    (source / recovery.WRITER_LOCK_NAME).unlink()
    try:
        with pytest.raises(recovery.RecoveryError, match="existing NCT writer lock"):
            recovery.create_backup(backup_args(source, backup))
    finally:
        fixture["reader"].close()
    assert not (source / recovery.WRITER_LOCK_NAME).exists()


def test_nested_backup_and_restore_paths_are_rejected_without_creation(tmp_path: Path) -> None:
    source, backup = tmp_path / "source", tmp_path / "backup"
    fixture = fixture_data(source)
    try:
        nested_backup = source / "nested-backup"
        args = backup_args(source, backup)
        args.backup_root = nested_backup
        with pytest.raises(recovery.RecoveryError, match="must be separate"):
            recovery.create_backup(args)
        assert not nested_backup.exists()
        recovery.create_backup(backup_args(source, backup))
    finally:
        fixture["reader"].close()
    nested_target = backup / "nested-target"
    restore = restore_args(backup, tmp_path / "unused-target")
    restore.target = nested_target
    with pytest.raises(recovery.RecoveryError, match="must be separate"):
        recovery.restore_backup(restore)
    assert not nested_target.exists()


def test_backup_capacity_preflight_fails_before_archive(tmp_path: Path, monkeypatch) -> None:
    source, backup = tmp_path / "source", tmp_path / "backup"
    fixture = fixture_data(source)
    monkeypatch.setattr(recovery.shutil, "disk_usage", lambda _path: type("Usage", (), {"free": 0})())
    try:
        with pytest.raises(recovery.RecoveryError, match="lacks space"):
            recovery.create_backup(backup_args(source, backup))
    finally:
        fixture["reader"].close()
    assert not (backup / "backup-20261012" / "payload.tar").exists()


def test_backup_reports_failure_if_final_backup_root_sync_fails(tmp_path: Path, monkeypatch) -> None:
    source, backup = tmp_path / "source", tmp_path / "backup"
    fixture = fixture_data(source)
    real_sync = recovery._fsync_directory
    root_syncs = 0

    def fail_second_root_sync(path: Path) -> None:
        nonlocal root_syncs
        if path == backup:
            root_syncs += 1
            if root_syncs == 2:
                raise recovery.RecoveryError("simulated final backup root sync failure")
        real_sync(path)

    monkeypatch.setattr(recovery, "_fsync_directory", fail_second_root_sync)
    try:
        with pytest.raises(recovery.RecoveryError, match="final backup root sync"):
            recovery.create_backup(backup_args(source, backup))
    finally:
        fixture["reader"].close()
    assert root_syncs == 2


def test_fd_capture_rejects_entry_replaced_by_symlink(tmp_path: Path, monkeypatch) -> None:
    source = tmp_path / "source"
    source.mkdir()
    outside = tmp_path / "outside"
    outside.write_text("outside")
    (source / "swap").write_text("inside")
    real_open = recovery.os.open
    replaced = False

    def replace_then_open(path, flags, mode=0o777, *, dir_fd=None):
        nonlocal replaced
        if path == "swap" and dir_fd is not None and not replaced:
            replaced = True
            (source / "swap").unlink()
            (source / "swap").symlink_to(outside)
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(recovery.os, "open", replace_then_open)
    with pytest.raises(recovery.RecoveryError, match="changed while opening"):
        recovery._fd_tree(source, copy_to=tmp_path / "copy", max_files=10, max_bytes=1000)


def test_backup_rejects_database_backed_active_work(tmp_path: Path) -> None:
    source, backup = tmp_path / "source", tmp_path / "backup"
    fixture = fixture_data(source)
    db = sqlite3.connect(source / "analyzer.db")
    db.execute("CREATE TABLE scan_runs (status TEXT)")
    db.execute("INSERT INTO scan_runs VALUES ('running')")
    db.commit()
    db.close()
    try:
        with pytest.raises(recovery.RecoveryError, match="active work"):
            recovery.create_backup(backup_args(source, backup))
    finally:
        fixture["reader"].close()


def test_backup_rejects_escaping_artifact_reference_and_special_file(tmp_path: Path) -> None:
    source, backup = tmp_path / "source", tmp_path / "backup"
    fixture = fixture_data(source)
    db = sqlite3.connect(source / "analyzer.db")
    db.execute("UPDATE artifact_registry SET canonical_path='/outside/evidence'")
    db.commit()
    db.close()
    try:
        with pytest.raises(recovery.RecoveryError, match="outside /data"):
            recovery.create_backup(backup_args(source, backup, "backup-escape1"))
        os.mkfifo(source / "unsafe-fifo")
        with pytest.raises(recovery.RecoveryError, match="special file"):
            recovery.create_backup(backup_args(source, backup, "backup-special1"))
    finally:
        fixture["reader"].close()


def test_backup_rejects_case_collisions(tmp_path: Path) -> None:
    source, backup = tmp_path / "source", tmp_path / "backup"
    fixture = fixture_data(source)
    (source / "CaseName").write_text("one")
    (source / "casename").write_text("two")
    try:
        with pytest.raises(recovery.RecoveryError, match="case-colliding"):
            recovery.create_backup(backup_args(source, backup))
    finally:
        fixture["reader"].close()


def test_backup_fails_closed_when_application_writer_lock_is_held(tmp_path: Path) -> None:
    source, backup = tmp_path / "source", tmp_path / "backup"
    fixture = fixture_data(source)
    lock = source / recovery.WRITER_LOCK_NAME
    code = (
        "import fcntl,os,sys,time;"
        "fd=os.open(sys.argv[1],os.O_RDWR|os.O_CREAT,0o600);"
        "fcntl.lockf(fd,fcntl.LOCK_EX,1,0,os.SEEK_SET);"
        "print('locked',flush=True);time.sleep(30)"
    )
    process = subprocess.Popen([sys.executable, "-c", code, str(lock)], stdout=subprocess.PIPE, text=True)
    try:
        assert process.stdout.readline().strip() == "locked"
        with pytest.raises(recovery.RecoveryError, match="still running"):
            recovery.create_backup(backup_args(source, backup))
    finally:
        process.terminate()
        process.wait(timeout=5)
        fixture["reader"].close()


def test_backup_rejects_links_and_active_work_without_removing_source(tmp_path: Path) -> None:
    source, backup = tmp_path / "source", tmp_path / "backup"
    fixture = fixture_data(source)
    try:
        active = source / "scan-runs" / "one"
        active.mkdir(parents=True)
        (active / "manifest.json").write_text(json.dumps({"status": "running"}))
        with pytest.raises(recovery.RecoveryError, match="active work"):
            recovery.create_backup(backup_args(source, backup, "backup-active1"))
        (active / "manifest.json").write_text(json.dumps({"status": "completed"}))
        (source / "unsafe-link").symlink_to(source / "analyzer.db")
        with pytest.raises(recovery.RecoveryError, match="link or special"):
            recovery.create_backup(backup_args(source, backup, "backup-unsafe1"))
        assert (source / "analyzer.db").exists()
    finally:
        fixture["reader"].close()


def test_restore_refuses_nonempty_target_and_changed_or_reused_identities(tmp_path: Path) -> None:
    source, backup, target = tmp_path / "source", tmp_path / "backup", tmp_path / "target"
    fixture = fixture_data(source)
    try:
        recovery.create_backup(backup_args(source, backup))
    finally:
        fixture["reader"].close()
    target.mkdir()
    (target / "existing").write_text("keep")
    with pytest.raises(recovery.RecoveryError, match="empty"):
        recovery.restore_backup(restore_args(backup, target))
    changed = restore_args(backup, tmp_path / "fresh")
    changed.backup_identity = identity("different-backup", "9")
    with pytest.raises(recovery.RecoveryError, match="identity changed"):
        recovery.restore_backup(changed)
    reused = restore_args(backup, tmp_path / "other")
    reused.target_identity = reused.backup_identity
    with pytest.raises(recovery.RecoveryError, match="must all differ"):
        recovery.restore_backup(reused)
    assert (target / "existing").read_text() == "keep"


def test_restore_detects_archive_tampering_and_preserves_backup(tmp_path: Path) -> None:
    source, backup, target = tmp_path / "source", tmp_path / "backup", tmp_path / "target"
    fixture = fixture_data(source)
    try:
        recovery.create_backup(backup_args(source, backup))
    finally:
        fixture["reader"].close()
    archive = backup / "backup-20261012" / "payload.tar"
    original = archive.read_bytes()
    archive.write_bytes(original[:-512])
    with pytest.raises(recovery.RecoveryError, match="digest or size changed"):
        recovery.restore_backup(restore_args(backup, target))
    assert archive.exists()
    assert target.is_dir() and not any(target.iterdir())


def test_restore_rejects_wrong_external_receipt_digest_and_malformed_manifest(tmp_path: Path) -> None:
    source, backup = tmp_path / "source", tmp_path / "backup"
    fixture = fixture_data(source)
    try:
        recovery.create_backup(backup_args(source, backup))
    finally:
        fixture["reader"].close()
    wrong = restore_args(backup, tmp_path / "wrong")
    wrong.expected_receipt_digest = "0" * 64
    with pytest.raises(recovery.RecoveryError, match="separately recorded"):
        recovery.restore_backup(wrong)
    manifest = backup / "backup-20261012" / "manifest.json"
    manifest.write_text(json.dumps({"schema_version": 1}), encoding="utf-8")
    with pytest.raises(recovery.RecoveryError, match="tool version"):
        recovery.restore_backup(restore_args(backup, tmp_path / "malformed"))


def test_restore_preserves_file_and_directory_modes(tmp_path: Path) -> None:
    source, backup, target = tmp_path / "source", tmp_path / "backup", tmp_path / "target"
    fixture = fixture_data(source)
    os.chmod(source / "packages", 0o750)
    os.chmod(source / "packages" / "portable.zip", 0o640)
    try:
        recovery.create_backup(backup_args(source, backup))
    finally:
        fixture["reader"].close()
    recovery.restore_backup(restore_args(backup, target))
    assert stat.S_IMODE((target / "packages").stat().st_mode) == 0o750
    assert stat.S_IMODE((target / "packages" / "portable.zip").stat().st_mode) == 0o640


def test_json_write_fails_closed_when_durable_sync_fails(tmp_path: Path, monkeypatch) -> None:
    path = tmp_path / "receipt.json"

    def fail_sync(_fd):
        raise OSError("simulated sync failure")

    monkeypatch.setattr(recovery.os, "fsync", fail_sync)
    with pytest.raises(OSError, match="simulated sync failure"):
        recovery._write_json(path, {"status": "test"})


def test_termination_receipt_is_bounded_and_rejects_symlink_target(tmp_path: Path) -> None:
    receipt = tmp_path / "termination.json"
    recovery._write_termination_receipt(receipt, {"status": "restore_verification_passed"})
    assert json.loads(receipt.read_text()) == {"status": "restore_verification_passed"}
    receipt.unlink()
    outside = tmp_path / "outside"
    outside.write_text("keep")
    receipt.symlink_to(outside)
    with pytest.raises(recovery.RecoveryError, match="could not be written"):
        recovery._write_termination_receipt(receipt, {"status": "changed"})
    assert outside.read_text() == "keep"
    with pytest.raises(recovery.RecoveryError, match="termination-message limit"):
        recovery._write_termination_receipt(tmp_path / "large", {"value": "x" * 5000})


def test_runtime_image_contains_recovery_tool() -> None:
    dockerfile = (Path(__file__).resolve().parents[1] / "Dockerfile").read_text(encoding="utf-8")
    assert "COPY scripts/nct_kubernetes_recovery.py /opt/nct/tools/nct_kubernetes_recovery.py" in dockerfile
