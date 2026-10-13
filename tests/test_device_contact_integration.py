from __future__ import annotations

import json
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import threading
import time

from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest

from app import device_configs
from app.device_contact_work import (
    get_device_contact_run,
    mark_device_contact_active,
    mark_device_contact_starting,
    request_device_contact_cancellation,
)
from app.work_coordination import WorkLeaseLost


KEY_PLAN = {
    "operator": "analyst.one",
    "reason": "HTTP lifecycle test",
    "originating_host": "nct-test",
    "vendor": "vyos",
    "device_type": "router",
    "device_address": "192.0.2.10",
    "username": "operator",
    "ssh_port": 22,
    "key_path": "/keys/test-id",
    "authentication_mode": "key",
    "accountability_interface": "eth0",
}


PASSWORD_PLAN = {
    **KEY_PLAN,
    "key_path": None,
    "authentication_mode": "password_prompt",
}


class _FakeProcess:
    def __init__(self) -> None:
        self.returncode = None

    def poll(self):
        return self.returncode

    def terminate(self) -> None:
        self.returncode = 0

    def kill(self) -> None:
        self.returncode = -9

    def wait(self, timeout=None):
        self.returncode = 0 if self.returncode is None else self.returncode
        return self.returncode


def _http_app() -> FastAPI:
    app = FastAPI()
    app.include_router(device_configs.router)
    return app


def _isolate_http_device_storage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> tuple[Path, Path]:
    db_path = tmp_path / "analyzer.db"
    config_dir = tmp_path / "device-configs"
    monkeypatch.setattr(device_configs, "DB_PATH", db_path)
    monkeypatch.setattr(device_configs, "CONFIG_DIR", config_dir)
    monkeypatch.setenv("NCT_ACTIVE_COLLECTION_MODE", "enabled")
    monkeypatch.setenv("NCT_AUTH_MODE", "disabled")
    monkeypatch.setattr(
        "app.derived_jobs.start_derived_job_worker", lambda *_args, **_kwargs: None
    )
    with device_configs._INTERACTIVE_SESSIONS_LOCK:
        device_configs._INTERACTIVE_SESSIONS.clear()
    return db_path, config_dir


def _capture_stub(interface: str, work_dir: Path):
    work_dir.mkdir(parents=True, exist_ok=True)
    (work_dir / "accountability.pcap").write_bytes(b"P" * 96)
    (work_dir / "capture-stderr.txt").write_text("capture test\n")
    return _FakeProcess(), None, ["tcpdump", "-i", interface]


def _fence(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    db_path = tmp_path / "analyzer.db"
    root = tmp_path / "device-configs"
    run_id = "a" * 32
    run_dir = root / run_id
    run_dir.mkdir(parents=True)
    monkeypatch.setattr(device_configs, "DB_PATH", db_path)
    monkeypatch.setattr(device_configs, "CONFIG_DIR", root)
    fence = device_configs.acquire_device_contact_fence(
        run_id,
        operation_kind="configuration_pull",
        subject_key="192.0.2.10:22",
        request={"device_address": "192.0.2.10", "authentication_mode": "key"},
        created_by="analyst.one",
        db_path=db_path,
    )
    work_dir = device_configs._device_contact_staging_dir(run_dir, fence)
    assert mark_device_contact_starting(db_path, fence.claim) is True
    mark_device_contact_active(db_path, fence.claim)
    return db_path, run_id, run_dir, work_dir, fence


def test_real_capture_files_are_fenced_and_journaled_before_promotion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    db_path, run_id, run_dir, work_dir, fence = _fence(tmp_path, monkeypatch)
    files = {
        "accountability.pcap": b"pcap-bytes",
        "capture-stderr.txt": b"tcpdump: listening on eth0\n",
        "stdout.txt": b"device output\n",
        "stderr.txt": b"",
        "router-config.txt": b"hostname router\n",
    }
    for name, value in files.items():
        (work_dir / name).write_bytes(value)

    publication_id = device_configs._promote_device_contact_files(
        work_dir, run_dir, fence
    )

    assert all((run_dir / name).read_bytes() == value for name, value in files.items())
    with sqlite3.connect(db_path) as connection:
        row = connection.execute(
            "SELECT state, files_json FROM device_contact_publications WHERE publication_id = ?",
            (publication_id,),
        ).fetchone()
    assert row is not None and row[0] == "files_moved"
    assert {item["filename"] for item in json.loads(row[1])} == set(files)
    fence.stop()


def test_saved_cancellation_terminates_blocking_contact_child(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    db_path, run_id, _run_dir, _work_dir, fence = _fence(tmp_path, monkeypatch)

    def cancel() -> None:
        time.sleep(0.25)
        request_device_contact_cancellation(
            db_path, run_id, requested_by="analyst.one", reason="Stop test contact"
        )

    thread = threading.Thread(target=cancel)
    thread.start()
    started = time.monotonic()
    with pytest.raises(device_configs.DeviceContactConflict, match="Cancellation"):
        device_configs._run_fenced_process(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            fence,
            timeout=40,
        )
    thread.join(timeout=2)
    assert time.monotonic() - started < 3
    fence.stop()


def test_lost_owner_terminates_blocking_contact_child(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _db_path, _run_id, _run_dir, _work_dir, fence = _fence(tmp_path, monkeypatch)

    def lose_owner() -> None:
        time.sleep(0.25)
        fence._lost.set()
        fence._terminate_processes()

    thread = threading.Thread(target=lose_owner)
    thread.start()
    started = time.monotonic()
    with pytest.raises(WorkLeaseLost):
        device_configs._run_fenced_process(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            fence,
            timeout=40,
        )
    thread.join(timeout=2)
    assert time.monotonic() - started < 3
    fence.stop()


def test_terminal_database_failure_leaves_presentation_manifest_unpublished(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    db_path, run_id, run_dir, work_dir, fence = _fence(tmp_path, monkeypatch)
    original = {"run_id": run_id, "status": "running"}
    (run_dir / "manifest.json").write_text(json.dumps(original))
    (work_dir / "stdout.txt").write_text("partial output")
    publication_id = device_configs._promote_device_contact_files(
        work_dir, run_dir, fence
    )
    manifest = {"run_id": run_id, "status": "completed"}

    def fail(*_args, **_kwargs):
        manifest["summary_verification_status"] = "verified"
        raise RuntimeError("injected database failure")

    monkeypatch.setattr(device_configs, "_finalize_device_collection", fail)
    with pytest.raises(RuntimeError, match="database failure"):
        device_configs.finalize_device_contact(
            run_dir, manifest, fence, publication_id
        )

    assert json.loads((run_dir / "manifest.json").read_text()) == original
    with sqlite3.connect(db_path) as connection:
        publication = connection.execute(
            "SELECT state FROM device_contact_publications WHERE publication_id = ?",
            (publication_id,),
        ).fetchone()
    assert publication == ("files_moved",)
    assert get_device_contact_run(db_path, run_id)["state"] == "contact_active"


def test_database_first_recovery_marks_missing_manifest_for_review(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    db_path, run_id, _run_dir, _work_dir, fence = _fence(tmp_path, monkeypatch)
    fence.stop()

    result = device_configs.recover_interrupted_device_collections()

    assert run_id in result["interrupted_run_ids"]
    assert run_id in result["unreadable_run_ids"]
    assert get_device_contact_run(db_path, run_id)["state"] == "needs_attention"


def test_terminal_manifest_write_failure_is_repaired_from_database(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    db_path, run_id, run_dir, work_dir, fence = _fence(tmp_path, monkeypatch)
    original = {"run_id": run_id, "status": "running"}
    (run_dir / "manifest.json").write_text(json.dumps(original))
    (work_dir / "stdout.txt").write_text("complete output")
    publication_id = device_configs._promote_device_contact_files(
        work_dir, run_dir, fence
    )
    manifest = {
        "run_id": run_id,
        "status": "completed",
        "success": True,
        "completed_at": "2026-10-12T12:00:00Z",
    }
    real_write = device_configs._write_json_atomic

    def fail_manifest_write(*_args, **_kwargs):
        raise OSError("injected presentation write failure")

    monkeypatch.setattr(device_configs, "_write_json_atomic", fail_manifest_write)
    with pytest.raises(OSError, match="presentation write failure"):
        device_configs.finalize_device_contact(
            run_dir, manifest, fence, publication_id
        )

    assert get_device_contact_run(db_path, run_id)["state"] == "complete"
    assert json.loads((run_dir / "manifest.json").read_text()) == original
    with sqlite3.connect(db_path) as connection:
        assert connection.execute(
            "SELECT presentation_synced FROM device_contact_runs WHERE run_id = ?",
            (run_id,),
        ).fetchone() == (0,)

    monkeypatch.setattr(device_configs, "_write_json_atomic", real_write)
    result = device_configs.recover_interrupted_device_collections()

    assert run_id in result["interrupted_run_ids"]
    assert json.loads((run_dir / "manifest.json").read_text())["status"] == "completed"
    with sqlite3.connect(db_path) as connection:
        assert connection.execute(
            "SELECT presentation_synced FROM device_contact_runs WHERE run_id = ?",
            (run_id,),
        ).fetchone() == (1,)


def test_admin_can_close_missing_evidence_tree_without_adopting_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    db_path, run_id, run_dir, _work_dir, fence = _fence(tmp_path, monkeypatch)
    fence.stop()
    shutil.rmtree(run_dir)
    result = device_configs.recover_interrupted_device_collections()
    assert run_id in result["unreadable_run_ids"]
    assert get_device_contact_run(db_path, run_id)["state"] == "needs_attention"
    monkeypatch.setattr(
        device_configs, "_device_contact_admin", lambda _request: "admin.one"
    )

    response = device_configs.review_close_device_contact_run(
        run_id,
        device_configs.DeviceContactReviewClosure(
            reason="Former processes stopped; missing evidence tree was not adopted",
            former_processes_stopped=True,
            files_stable=True,
            disposition="failed",
        ),
        object(),
    )

    assert response["status"] == "closed_after_admin_review"
    run = get_device_contact_run(db_path, run_id)
    assert run["state"] == "failed"
    assert run["reviews"][0]["file_review"]["evidence_tree_status"] == "absent"
    assert run["reviews"][0]["file_review"]["adoption_status"] == "not_adopted"


def test_admin_can_close_unsafe_evidence_tree_without_following_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    db_path, run_id, run_dir, _work_dir, fence = _fence(tmp_path, monkeypatch)
    fence.stop()
    shutil.rmtree(run_dir)
    outside = tmp_path / "outside-evidence"
    outside.mkdir()
    (outside / "must-not-be-read.txt").write_text("untrusted")
    run_dir.symlink_to(outside, target_is_directory=True)
    result = device_configs.recover_interrupted_device_collections()
    assert run_id in result["unreadable_run_ids"]
    assert get_device_contact_run(db_path, run_id)["state"] == "needs_attention"
    monkeypatch.setattr(
        device_configs, "_device_contact_admin", lambda _request: "admin.one"
    )

    response = device_configs.review_close_device_contact_run(
        run_id,
        device_configs.DeviceContactReviewClosure(
            reason="Former processes stopped; unsafe evidence path was not followed",
            former_processes_stopped=True,
            files_stable=True,
            disposition="failed",
        ),
        object(),
    )

    assert response["status"] == "closed_after_admin_review"
    run = get_device_contact_run(db_path, run_id)
    assert run["state"] == "failed"
    review = run["reviews"][0]["file_review"]
    assert review["evidence_tree_status"] == "unsafe"
    assert review["adoption_status"] == "not_adopted"
    assert (outside / "must-not-be-read.txt").read_text() == "untrusted"


def test_admin_file_review_includes_exact_attempt_private_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _db_path, _run_id, run_dir, work_dir, fence = _fence(tmp_path, monkeypatch)
    (work_dir / "capture-stderr.txt").write_text("partial capture diagnostics")
    (work_dir / "accountability.pcap").write_bytes(b"partial pcap")

    review = device_configs._review_stable_collection_files(
        run_dir, fence.claim.attempt_number
    )

    assert review["attempt_number"] == fence.claim.attempt_number
    assert review["stability_interval_ms"] == 250
    assert {item["filename"] for item in review["files"]} == {
        f"attempt/{fence.claim.attempt_number}/capture-stderr.txt",
        f"attempt/{fence.claim.attempt_number}/accountability.pcap",
    }
    fence.stop()


def test_password_http_lifecycle_completes_without_retaining_secret(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    db_path, config_dir = _isolate_http_device_storage(tmp_path, monkeypatch)
    secret = "NCT-unique-password-never-retain-7419"
    reads = iter(("Password:", "Authentication succeeded"))
    checks = iter((False, True))
    monkeypatch.setattr(device_configs, "start_accountability_capture", _capture_stub)
    monkeypatch.setattr(device_configs, "stop_accountability_capture", lambda *_: None)
    monkeypatch.setattr(device_configs.subprocess, "Popen", lambda *_a, **_k: _FakeProcess())
    monkeypatch.setattr(device_configs, "_read_pty", lambda *_a, **_k: next(reads))
    monkeypatch.setattr(device_configs, "_control_check", lambda *_a, **_k: next(checks))

    def complete_collection(session):
        output = session.run_dir / session.preview["local_output_name"]
        output.write_text("system { host-name edge-router; }\ninterfaces { ethernet eth0; }\n")
        (session.run_dir / "stdout.txt").write_text(output.read_text())
        (session.run_dir / "command-history.txt").write_text("show configuration\n")
        return device_configs._finish_interactive_session(
            session,
            status="completed",
            stderr="",
            failure_class=None,
            exit_code=0,
            extra={
                "local_output_name": session.preview["local_output_name"],
                "output_truncated": False,
                "retained_output_bytes": output.stat().st_size,
                "command_history_status": "captured",
                "command_history_truncated": False,
                "command_history_artifact": "command-history.txt",
            },
        )

    monkeypatch.setattr(device_configs, "_run_interactive_collection", complete_collection)
    with TestClient(_http_app(), base_url="https://testserver") as client:
        started = client.post(
            "/api/device-configs/interactive/start", json=PASSWORD_PLAN
        )
        assert started.status_code == 200, started.text
        assert started.json()["status"] == "waiting_for_password"
        run_id = started.json()["run_id"]
        submitted = client.post(
            f"/api/device-configs/interactive/{started.json()['session_id']}/password",
            json={"password": secret},
        )

    assert submitted.status_code == 200, submitted.text
    result = submitted.json()
    assert result["status"] == "completed"
    assert result["credentials_stored"] is False
    durable = get_device_contact_run(db_path, run_id)
    assert durable is not None and durable["state"] == "complete"
    assert durable["attempts"][0]["state"] == "complete"
    assert durable["request"]["authentication_mode"] == "password_prompt"
    retained_manifest = json.loads(
        (config_dir / run_id / "manifest.json").read_text()
    )
    assert retained_manifest["credentials_stored"] is False
    assert retained_manifest["credential_retention"] == "none"
    assert secret not in json.dumps(result)
    assert secret not in json.dumps(durable)
    secret_bytes = secret.encode()
    retained_files = [path for path in tmp_path.rglob("*") if path.is_file()]
    assert retained_files
    assert all(secret_bytes not in path.read_bytes() for path in retained_files)


def test_key_preflight_http_lifecycle_reaches_terminal_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    db_path, config_dir = _isolate_http_device_storage(tmp_path, monkeypatch)
    monkeypatch.setattr(
        device_configs,
        "key_preflight",
        lambda _path: {"status": "ready", "message": "Test key is readable"},
    )
    monkeypatch.setattr(device_configs, "start_accountability_capture", _capture_stub)
    monkeypatch.setattr(device_configs, "stop_accountability_capture", lambda *_: None)
    monkeypatch.setattr(
        device_configs,
        "_run_fenced_process",
        lambda args, _fence, **_kwargs: subprocess.CompletedProcess(
            args=args, returncode=0, stdout="", stderr=""
        ),
    )

    with TestClient(_http_app(), base_url="https://testserver") as client:
        response = client.post("/api/device-configs/preflight", json=KEY_PLAN)

    assert response.status_code == 200, response.text
    result = response.json()
    assert result["status"] == "ready"
    run_id = result["accountability_run_id"]
    durable = get_device_contact_run(db_path, run_id)
    assert durable is not None and durable["state"] == "complete"
    assert durable["attempts"][0]["contact_started_at"]
    assert durable["attempts"][0]["completed_at"]
    manifest = json.loads((config_dir / run_id / "manifest.json").read_text())
    assert manifest["operation"] == "ssh_preflight"
    assert manifest["status"] == "completed"
    assert manifest["contact_phase"] == "complete"
    assert {item["name"] for item in result["accountability_artifacts"]} >= {
        "accountability.pcap", "capture-stderr.txt",
    }


def test_key_collection_http_lifecycle_reaches_terminal_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    db_path, config_dir = _isolate_http_device_storage(tmp_path, monkeypatch)
    monkeypatch.setattr(
        device_configs,
        "key_preflight",
        lambda _path: {"status": "ready", "message": "Test key is readable"},
    )
    monkeypatch.setattr(device_configs, "start_accountability_capture", _capture_stub)
    monkeypatch.setattr(device_configs, "stop_accountability_capture", lambda *_: None)

    def history(_args, _input, path, _fence=None):
        path.write_text("show configuration\n")
        return "captured", None, False

    def collect(args, *, input_text, output_path, timeout, fence=None):
        output_path.write_text(
            "system { host-name edge-router; }\n"
            "interfaces { ethernet eth0 { address 192.0.2.10/24; } }\n"
        )
        return subprocess.CompletedProcess(
            args=args, returncode=0, stdout="", stderr=""
        ), False

    monkeypatch.setattr(device_configs, "_capture_history_to_file", history)
    monkeypatch.setattr(device_configs, "_stream_command_to_file", collect)

    with TestClient(_http_app(), base_url="https://testserver") as client:
        response = client.post("/api/device-configs/execute", json=KEY_PLAN)

    assert response.status_code == 200, response.text
    result = response.json()
    assert result["status"] == "completed"
    run_id = result["run_id"]
    durable = get_device_contact_run(db_path, run_id)
    assert durable is not None and durable["state"] == "complete"
    assert durable["attempts"][0]["state"] == "complete"
    manifest = json.loads((config_dir / run_id / "manifest.json").read_text())
    assert manifest["operation"] == "configuration_pull"
    assert manifest["status"] == "completed"
    assert manifest["contact_phase"] == "complete"
    assert manifest["credentials_stored"] is False
    names = {item["name"] for item in result["artifacts"]}
    assert "accountability.pcap" in names
    assert "command-history.txt" in names
    assert any(name.endswith("-config.txt") for name in names)
