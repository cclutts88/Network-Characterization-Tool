from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

import pytest

from scripts import qualify_kubernetes_storage as qualification


def test_isolated_storage_qualification_passes_and_cleans_up(tmp_path: Path) -> None:
    report = qualification.qualify_storage(tmp_path, "test-driver:test-volume")

    assert report["overall"] == "pass"
    assert {item["id"]: item["status"] for item in report["checks"]} == {
        "root": "pass",
        "advisory_file_lock": "pass",
        "atomic_rename_and_fsync": "pass",
        "sqlite_wal": "pass",
        "bounded_resources": "pass",
    }
    assert report["cleanup"]["status"] == "pass"
    assert report["declared"]["storage_identity"] == "test-driver:test-volume"
    assert report["declared"]["accepted"] is True
    assert report["measured"]["workspace_mode"] == "0700"
    atomic = next(item for item in report["checks"] if item["id"] == "atomic_rename_and_fsync")
    assert atomic["facts"]["replacements"] == qualification.REPLACE_ITERATIONS
    assert atomic["facts"]["observer_reads"] > 0
    sqlite = next(item for item in report["checks"] if item["id"] == "sqlite_wal")
    assert sqlite["facts"]["checkpoint"] == [0, 0, 0]
    assert sqlite["facts"]["wal_bytes_after_checkpoint"] == 0
    assert qualification.verify_report_digest(report) is True
    assert not list(tmp_path.glob(f"{qualification.WORKSPACE_PREFIX}*"))


def test_cli_returns_bounded_json_and_removes_workspace(tmp_path: Path) -> None:
    completed = subprocess.run(
        [
            sys.executable,
            str(Path(qualification.__file__).resolve()),
            "--root",
            str(tmp_path),
            "--storage-identity",
            "local:test",
        ],
        capture_output=True,
        text=True,
        timeout=qualification.OVERALL_TIMEOUT_SECONDS + 5,
    )
    assert completed.returncode == 0, completed.stderr
    assert len(completed.stdout.encode()) <= qualification.MAX_REPORT_BYTES
    report = json.loads(completed.stdout)
    assert report["overall"] == "pass"
    assert qualification.verify_report_digest(report) is True
    assert not list(tmp_path.iterdir())


def test_symlink_root_and_empty_declared_identity_fail_closed(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "link"
    link.symlink_to(target, target_is_directory=True)

    linked = qualification.qualify_storage(link, "linked")
    missing_identity = qualification.qualify_storage(target, "   ")

    assert linked["overall"] == "fail"
    assert linked["checks"][0]["status"] == "fail"
    assert missing_identity["overall"] == "fail"
    assert not list(target.iterdir())


def test_oversized_declared_identity_is_bounded_and_fails_closed(tmp_path: Path) -> None:
    identity = "x" * (qualification.MAX_STORAGE_IDENTITY_BYTES + 1)
    report = qualification.qualify_storage(tmp_path, identity)
    assert report["overall"] == "fail"
    assert report["declared"]["storage_identity"] is None
    assert report["declared"]["accepted"] is False
    assert len(qualification._canonical_bytes(report)) <= qualification.MAX_REPORT_BYTES


def test_workspace_creation_rejects_preexisting_and_escaped_names(tmp_path: Path) -> None:
    root, root_fd, _facts = qualification._validate_root(tmp_path)
    name = qualification.WORKSPACE_PREFIX + "a" * 32
    (tmp_path / name).mkdir()
    try:
        with pytest.raises(FileExistsError):
            qualification._create_workspace(root_fd, root, name)
        with pytest.raises(ValueError, match="contained and safe"):
            qualification._create_workspace(root_fd, root, "../escape")
    finally:
        os.close(root_fd)


def test_failed_or_timed_out_worker_makes_overall_result_fail(tmp_path: Path, monkeypatch) -> None:
    def failed_worker(check_id: str, _timeout: float, **_identities) -> dict:
        if check_id == "advisory_file_lock":
            return qualification._result(check_id, "fail", "simulated lock failure", time.monotonic())
        return qualification._result(check_id, "pass", "simulated pass", time.monotonic())

    monkeypatch.setattr(qualification, "_run_worker", failed_worker)
    report = qualification._qualify_storage_in_process(
        tmp_path,
        "failure-test",
        workspace_name=qualification.WORKSPACE_PREFIX + "c" * 32,
        workspace_token="d" * 64,
    )
    assert report["overall"] == "fail"
    assert next(item for item in report["checks"] if item["id"] == "advisory_file_lock")["status"] == "fail"

    timed = qualification._run_process(
        [sys.executable, "-c", "import time; time.sleep(5)"],
        timeout=0.05,
        start_new_session=True,
    )
    assert timed["timed_out"] is True
    assert timed["reaped"] is True


def test_report_digest_detects_alteration(tmp_path: Path) -> None:
    report = qualification.qualify_storage(tmp_path, "digest-test")
    assert qualification.verify_report_digest(report) is True
    report["declared"]["storage_identity"] = "altered"
    assert qualification.verify_report_digest(report) is False


def test_cleanup_refuses_nested_directory_and_reports_failure(tmp_path: Path) -> None:
    root, root_fd, _facts = qualification._validate_root(tmp_path)
    root_value = os.fstat(root_fd)
    name = qualification.WORKSPACE_PREFIX + "b" * 32
    workspace, workspace_identity = qualification._create_workspace(root_fd, root, name)
    workspace_fd = qualification._open_workspace(root_fd, name, workspace_identity)
    (workspace / "unexpected-directory").mkdir()
    try:
        result = qualification._cleanup_workspace(
            root_fd,
            workspace_fd,
            (root_value.st_dev, root_value.st_ino),
            name,
            workspace_identity,
        )
        assert result["status"] == "fail"
        assert workspace.is_dir()
    finally:
        os.close(workspace_fd)
        os.close(root_fd)
        shutil.rmtree(workspace)


@pytest.mark.parametrize(
    "facts",
    [
        {"journal_mode": "delete", "checkpoint": [0, 0, 0], "integrity": "ok"},
        {"journal_mode": "wal", "checkpoint": [1, 0, 0], "integrity": "ok"},
        {"journal_mode": "wal", "checkpoint": [0, 1, 0], "integrity": "ok"},
        {"journal_mode": "wal", "checkpoint": [0, 0, 0], "integrity": "corrupt"},
        {"journal_mode": "wal", "checkpoint": [0, 0], "integrity": "ok"},
    ],
)
def test_sqlite_child_facts_fail_closed(facts: dict) -> None:
    assert qualification._sqlite_child_facts_are_valid(facts) is False


def test_worker_requires_orchestrator_descriptors_and_token() -> None:
    completed = subprocess.run(
        [
            sys.executable,
            str(Path(qualification.__file__).resolve()),
            "--worker-check",
            "advisory_file_lock",
        ],
        capture_output=True,
        text=True,
        timeout=5,
    )
    assert completed.returncode == 2
    assert "orchestrator token" in completed.stderr


def test_worker_descriptor_validation_rejects_wrong_token(tmp_path: Path) -> None:
    root, root_fd, _facts = qualification._validate_root(tmp_path)
    root_value = os.fstat(root_fd)
    name = qualification.WORKSPACE_PREFIX + "e" * 32
    workspace, workspace_identity = qualification._create_workspace(root_fd, root, name)
    workspace_fd = qualification._open_workspace(root_fd, name, workspace_identity)
    qualification._create_workspace_token(workspace_fd, "f" * 64)
    try:
        with pytest.raises(ValueError, match="marker"):
            qualification._validate_worker_descriptors(
                root_fd,
                workspace_fd,
                expected_root=(root_value.st_dev, root_value.st_ino),
                expected_workspace=workspace_identity,
                expected_token="0" * 64,
            )
    finally:
        for entry in os.listdir(workspace_fd):
            os.unlink(entry, dir_fd=workspace_fd)
        os.close(workspace_fd)
        os.rmdir(name, dir_fd=root_fd)
        os.close(root_fd)


def test_controller_timeout_fails_closed_and_does_not_claim_cleanup(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(
        qualification,
        "_run_process",
        lambda *_args, **_kwargs: {
            "returncode": -9,
            "timed_out": True,
            "reaped": True,
            "output_limited": True,
            "stdout": "",
            "stderr": "",
            "duration_seconds": qualification.OVERALL_TIMEOUT_SECONDS,
        },
    )
    report = qualification.qualify_storage(tmp_path, "timeout-test")
    assert report["overall"] == "fail"
    assert report["cleanup"]["status"] == "unavailable"
    assert next(item for item in report["checks"] if item["id"] == "controller")["status"] == "fail"


def test_controller_rejects_altered_child_report(tmp_path: Path, monkeypatch) -> None:
    valid = qualification._controller_failure_report("identity", "original", "workspace")
    valid["declared"]["storage_identity"] = "altered-after-digest"
    monkeypatch.setattr(
        qualification,
        "_run_process",
        lambda *_args, **_kwargs: {
            "returncode": 1,
            "timed_out": False,
            "reaped": True,
            "output_limited": True,
            "stdout": json.dumps(valid),
            "stderr": "",
            "duration_seconds": 0.01,
        },
    )
    report = qualification.qualify_storage(tmp_path, "identity")
    assert report["overall"] == "fail"
    assert "integrity validation" in report["checks"][0]["detail"]


def test_observer_facts_require_both_payloads_and_every_acknowledgement() -> None:
    old_digest = "a" * 64
    new_digest = "b" * 64
    only_original = {
        "observations": qualification.REPLACE_ITERATIONS + 1,
        "seen_digests": [old_digest],
    }
    too_few = {
        "observations": qualification.REPLACE_ITERATIONS,
        "seen_digests": sorted([old_digest, new_digest]),
    }
    complete = {
        "observations": qualification.REPLACE_ITERATIONS + 1,
        "seen_digests": sorted([old_digest, new_digest]),
    }
    assert qualification._replacement_observer_facts_are_valid(only_original, old_digest, new_digest) is False
    assert qualification._replacement_observer_facts_are_valid(too_few, old_digest, new_digest) is False
    assert qualification._replacement_observer_facts_are_valid(complete, old_digest, new_digest) is True


def test_continuous_observer_rejects_unlink_pause_then_rename(tmp_path: Path) -> None:
    root, root_fd, _facts = qualification._validate_root(tmp_path)
    name = qualification.WORKSPACE_PREFIX + "3" * 32
    workspace, workspace_identity = qualification._create_workspace(root_fd, root, name)
    workspace_fd = qualification._open_workspace(root_fd, name, workspace_identity)
    target_name = "fault-target.bin"
    source_name = "fault-source.bin"
    old_payload = b"old-exact-payload"
    new_payload = b"new-exact-payload"
    old_digest = qualification.hashlib.sha256(old_payload).hexdigest()
    new_digest = qualification.hashlib.sha256(new_payload).hexdigest()
    qualification._write_file_at(workspace_fd, target_name, old_payload)
    observer = qualification._start_continuous_observer(
        workspace_fd, target_name, old_digest, new_digest,
    )
    try:
        os.unlink(target_name, dir_fd=workspace_fd)
        observer.wait(timeout=1)
        qualification._write_file_at(workspace_fd, source_name, new_payload)
        os.replace(
            source_name, target_name,
            src_dir_fd=workspace_fd, dst_dir_fd=workspace_fd,
        )
        stdout, _stderr = observer.communicate(timeout=1)
        facts = json.loads(stdout)
        assert observer.returncode == 41
        assert facts["error"] == "target_missing"
    finally:
        if observer.poll() is None:
            observer.kill()
            observer.communicate(timeout=1)
        for entry in os.listdir(workspace_fd):
            os.unlink(entry, dir_fd=workspace_fd)
        os.close(workspace_fd)
        os.rmdir(name, dir_fd=root_fd)
        os.close(root_fd)


def test_controller_binds_self_consistent_report_to_request_and_exit_code(tmp_path: Path, monkeypatch) -> None:
    source_sha256 = qualification.hashlib.sha256(Path(qualification.__file__).resolve().read_bytes()).hexdigest()
    report = qualification._controller_failure_report("different", "failure", "workspace")
    assert qualification.verify_report_digest(report)
    assert not qualification._controller_report_matches_request(
        report,
        storage_identity="requested",
        source_sha256=source_sha256,
        returncode=1,
    )
    report["declared"]["storage_identity"] = "requested"
    report["declared"]["storage_identity_sha256"] = qualification.hashlib.sha256(b"requested").hexdigest()
    report["tool"]["source_sha256"] = source_sha256
    report["attestation"]["digest"] = qualification.report_digest(report)
    assert qualification._controller_report_matches_request(
        report,
        storage_identity="requested",
        source_sha256=source_sha256,
        returncode=1,
    )
    assert not qualification._controller_report_matches_request(
        report,
        storage_identity="requested",
        source_sha256=source_sha256,
        returncode=0,
    )


def test_double_timeout_returns_bounded_unreaped_result(monkeypatch) -> None:
    class Pipe:
        def close(self) -> None:
            pass

    class StubbornProcess:
        pid = 99123
        returncode = None
        stdout = Pipe()
        stderr = Pipe()

        def communicate(self, timeout=None):
            raise subprocess.TimeoutExpired(["stubborn"], timeout)

        def kill(self) -> None:
            pass

        def wait(self, timeout=None):
            raise subprocess.TimeoutExpired(["stubborn"], timeout)

        def poll(self):
            return None

    monkeypatch.setattr(qualification.subprocess, "Popen", lambda *_args, **_kwargs: StubbornProcess())
    result = qualification._run_process(
        ["stubborn"], timeout=0.01, start_new_session=False,
    )
    assert result["timed_out"] is True
    assert result["reaped"] is False
    assert result["output_limited"] is True
    assert "did not terminate" in result["stderr"]


def test_open_descriptor_does_not_follow_replaced_workspace_name(tmp_path: Path) -> None:
    root, root_fd, _facts = qualification._validate_root(tmp_path)
    root_value = os.fstat(root_fd)
    name = qualification.WORKSPACE_PREFIX + "1" * 32
    workspace, workspace_identity = qualification._create_workspace(root_fd, root, name)
    workspace_fd = qualification._open_workspace(root_fd, name, workspace_identity)
    token = "2" * 64
    qualification._create_workspace_token(workspace_fd, token)
    moved = tmp_path / f"{name}-moved"
    workspace.rename(moved)
    workspace.mkdir(mode=0o700)
    replacement_file = workspace / "must-remain"
    replacement_file.write_text("replacement")
    try:
        qualification._validate_worker_descriptors(
            root_fd,
            workspace_fd,
            expected_root=(root_value.st_dev, root_value.st_ino),
            expected_workspace=workspace_identity,
            expected_token=token,
        )
        result = qualification._check_file_lock(workspace_fd)
        assert result["status"] == "pass"
        assert (moved / "advisory-lock.bin").is_file()
        assert not (workspace / "advisory-lock.bin").exists()
        cleanup = qualification._cleanup_workspace(
            root_fd,
            workspace_fd,
            (root_value.st_dev, root_value.st_ino),
            name,
            workspace_identity,
        )
        assert cleanup["status"] == "fail"
        assert replacement_file.read_text() == "replacement"
    finally:
        os.close(workspace_fd)
        os.close(root_fd)
        shutil.rmtree(workspace)
        shutil.rmtree(moved)
