from __future__ import annotations

import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sqlite3
import tarfile
import threading
import time

import pytest
pytest.importorskip("fcntl")
from fastapi.testclient import TestClient

spec = importlib.util.spec_from_file_location("update_host", Path(__file__).parents[1] / "scripts/nct_update_host.py")
host_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(host_module)


def image_archive(path, *, tags=None, extra=False, multiple=False):
    config = json.dumps({"architecture": "amd64", "os": "linux", "rootfs": {"diff_ids": ["sha256:" + hashlib.sha256(b"retained layer").hexdigest()]}}).encode()
    image_id = "sha256:" + hashlib.sha256(config).hexdigest()
    entries = {"config.json": config, "layer.tar": b"retained layer"}
    manifest = {"Config": "config.json", "Layers": ["layer.tar"], "RepoTags": tags or []}
    entries["manifest.json"] = json.dumps([manifest] * (2 if multiple else 1)).encode()
    if extra:
        entries["other-image.json"] = b"{}"
    with tarfile.open(path, "w") as archive:
        for name, content in entries.items():
            info = tarfile.TarInfo(name)
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))
    return image_id


def package(tmp_path, *, member="image.tar", link=False, duplicate=False, wrong_digest=False, tags=None, extra=False, multiple=False):
    image_path = tmp_path / "image.tar"
    image_id = image_archive(image_path, tags=tags, extra=extra, multiple=multiple)
    release = {"contract": "nct-update-v1", "image_config_id": image_id,
        "image_sha256": "0" * 64 if wrong_digest else host_module.digest_file(image_path),
        "build_id": "nct-test-new", "build_commit": "b" * 40,
        "source_builds": [{"build_id": "old", "build_commit": "a" * 40}]}
    target = tmp_path / "release.tar.gz"
    with tarfile.open(target, "w:gz") as archive:
        content = json.dumps(release).encode()
        info = tarfile.TarInfo("release.json")
        info.size = len(content)
        archive.addfile(info, io.BytesIO(content))
        if duplicate:
            archive.addfile(info, io.BytesIO(content))
        if link:
            info = tarfile.TarInfo(member)
            info.type, info.linkname = tarfile.SYMTYPE, "/etc/passwd"
            archive.addfile(info)
        else:
            info = tarfile.TarInfo(member)
            info.size = image_path.stat().st_size
            with image_path.open("rb") as stream:
                archive.addfile(info, stream)
    return target, release


def test_package_accepts_one_tagless_image_and_embedded_checksum(tmp_path):
    archive, release = package(tmp_path)
    assert host_module.validate_package(archive, tmp_path / "extracted") == release


@pytest.mark.parametrize("options", [
    {"member": "../image.tar"}, {"member": "/image.tar"}, {"link": True},
    {"duplicate": True}, {"wrong_digest": True}, {"tags": ["installed:latest"]},
    {"extra": True}, {"multiple": True},
])
def test_package_rejects_unsafe_or_ambiguous_release_without_extraction(tmp_path, options):
    archive, _ = package(tmp_path, **options)
    with pytest.raises((ValueError, KeyError)):
        host_module.validate_package(archive, tmp_path / "extracted")
    assert not (tmp_path / "extracted").exists()


def configuration(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    with sqlite3.connect(data / "analyzer.db") as db:
        db.execute("CREATE TABLE evidence (id TEXT PRIMARY KEY, source TEXT)")
        db.execute("INSERT INTO evidence VALUES ('one','retained')")
    (data / "evidence.xml").write_text("original exact bytes")
    return {"state_dir": str(tmp_path / "management"), "data_dir": str(data), "container": "nct",
        "console_container": "console", "console_image_id": "sha256:" + "c" * 64,
        "application_url": "https://nct.test:8445", "console_url": "https://nct.test:8446",
        "maintenance_lock": str(tmp_path / "maintenance.lock")}


class Engine:
    def __init__(self, config):
        self.calls = []
        self.items = {"old": {"Id": "old", "Image": "sha256:" + "a" * 64, "Name": "/nct",
            "Config": {"Env": ["NCT_AUTH_MODE=local"], "Labels": {}, "Cmd": ["uvicorn", "app.main:app"]},
            "State": {"Running": True, "Status": "running"},
            "Mounts": [{"Destination": "/data", "Type": "bind", "Source": config["data_dir"]}],
            "HostConfig": {"RestartPolicy": {"Name": "on-failure", "MaximumRetryCount": 4}}}}

    def inspect(self, name):
        for value in self.items.values():
            if name in (value["Id"], value["Name"].lstrip("/")):
                return copy.deepcopy(value)
        raise ValueError("not found")

    def exists(self, name):
        try:
            return self.inspect(name)
        except ValueError:
            return None

    def command(self, *args):
        self.calls.append(args)
        if args[:2] == ("ps", "-aq"):
            return "\n".join(self.items)
        if args[0] in {"stop", "start", "update", "rename"}:
            target = self.items[self.inspect(args[-2] if args[0] == "rename" else args[-1])["Id"]]
            if args[0] == "stop":
                target["State"] = {"Running": False, "Status": "exited"}
            elif args[0] == "start":
                target["State"] = {"Running": True, "Status": "running"}
            elif args[0] == "update":
                policy = args[1].split("=", 1)[1].split(":")
                target["HostConfig"]["RestartPolicy"] = {"Name": policy[0], "MaximumRetryCount": int(policy[1]) if len(policy) > 1 else 0}
            else:
                target["Name"] = "/" + args[-1]
        return ""

    def create(self, name, config):
        original = copy.deepcopy(self.items["old"])
        original.update(Id="new", Name="/" + name, Image=config["Image"], Config=config, HostConfig=config["HostConfig"])
        original["State"] = {"Running": False, "Status": "created"}
        self.items["new"] = original
        return "new"


class StorageHost(host_module.Host):
    """Real cold backup/restore, simulated Docker process state."""
    def helper(self, image, mode, *, root=None, immutable=True):
        root = Path(root or self.data)
        if mode == "active":
            return []
        files = {p.relative_to(root).as_posix(): host_module.digest_file(p) for p in root.rglob("*") if p.is_file()}
        return {"restore_files": files, "files": {k: v for k, v in files.items() if k != "analyzer.db"},
            "artifact_registry": [], "database": {"tables": {"evidence": 1}}}

    def compatibility(self, *_args, **_kwargs):
        pass

    def checkpoint(self, image):
        with sqlite3.connect(self.data / "analyzer.db") as db:
            db.execute("PRAGMA wal_checkpoint(TRUNCATE)")

    def verify_health(self, state, original=False):
        if getattr(self, "fail_candidate", False) and not original:
            (self.data / "evidence.xml").write_text("candidate damaged bytes")
            raise ValueError("Candidate failed startup")
        return {"status": "ok"}


def planned_host(tmp_path):
    config = configuration(tmp_path)
    engine = Engine(config)
    host = StorageHost(config, engine)
    folder = host.root / ("1" * 32)
    (folder / "release").mkdir(parents=True)
    image = folder / "release/image.tar"
    image.write_bytes(b"candidate image")
    state = {"id": "1" * 32, "actor": "analyst", "original": engine.inspect("old"),
        "candidate_image_id": "sha256:" + "b" * 64,
        "original_build": {"build_id": "old", "build_commit": "a" * 40},
        "manifest": {"image_config_id": "sha256:" + "b" * 64, "image_sha256": host_module.digest_file(image)},
        "plan_digest": "d" * 64}
    host.phase(state, "validated")
    return host, engine


def test_handoff_is_expiring_one_use_and_not_a_console_session(tmp_path):
    host = host_module.Host(configuration(tmp_path))
    code = host.token("analyst")
    with pytest.raises(PermissionError):
        host.identity(code)
    assert host.identity(code, "handoff", consume=True) == "analyst"
    with pytest.raises(PermissionError):
        host.identity(code, "handoff", consume=True)
    expired = host.token("analyst", seconds=-1)
    with pytest.raises(PermissionError):
        host.identity(expired, "handoff")


def test_access_code_process_does_not_interrupt_service_owned_operation(tmp_path):
    host, engine = planned_host(tmp_path)
    host.phase(host.read(), "candidate_created")
    host_module.Host(host.config, engine)
    assert host.read()["phase"] == "candidate_created"
    host_module.Host(host.config, engine, reconcile=True)
    assert host.read()["phase"] == "interrupted"


def test_exclusive_conflict_does_not_change_current_operation(tmp_path):
    host, _ = planned_host(tmp_path)
    before = host.read()
    with host.exclusive(), pytest.raises(ValueError):
        host.apply("d" * 64, "other")
    assert host.read() == before


def test_real_backup_and_failed_candidate_restore_preserve_both_versions(tmp_path):
    host, engine = planned_host(tmp_path)
    host.fail_candidate = True
    host.apply("d" * 64, "analyst")
    state = host.read()
    assert state["phase"] == "awaiting_restore_sign_in"
    assert (host.data / "evidence.xml").read_text() == "original exact bytes"
    assert Path(state["quarantine_path"]).joinpath("evidence.xml").read_text() == "candidate damaged bytes"
    assert engine.inspect("nct")["Id"] == "old"
    assert engine.inspect("old")["HostConfig"]["RestartPolicy"] == {"Name": "on-failure", "MaximumRetryCount": 4}


def test_success_waits_for_real_sign_in_and_does_not_start_old_image(tmp_path):
    host, engine = planned_host(tmp_path)
    host.apply("d" * 64, "analyst")
    assert host.read()["phase"] == "awaiting_sign_in"
    assert host.read()["backup_verified"]
    assert host.read()["evidence_verified"]
    assert not host.read().get("controller_sign_in_verified")
    assert not engine.inspect("old")["State"]["Running"]
    assert engine.inspect("nct")["Id"] == "new"


def test_corrupt_backup_keeps_old_image_stopped_and_preserves_candidate_data(tmp_path):
    host, engine = planned_host(tmp_path)
    host.apply("d" * 64, "analyst")
    (host.root / host.read()["id"] / "backup.tar.gz").write_bytes(b"corrupt")
    with pytest.raises(ValueError, match="checksum"):
        host.rollback("analyst")
    assert host.read()["phase"] == "interrupted"
    assert not engine.inspect("old")["State"]["Running"]
    assert (host.data / "evidence.xml").read_text() == "original exact bytes"


def test_wrong_target_and_shared_writer_are_refused(tmp_path):
    host, engine = planned_host(tmp_path)
    with pytest.raises(ValueError, match="identity changed"):
        host.target(expected_id="unrelated")
    other = copy.deepcopy(engine.items["old"])
    other.update(Id="other", Name="/other")
    engine.items["other"] = other
    with pytest.raises(ValueError, match="Another container"):
        host.target()


def test_lifecycle_restart_preserves_retry_limit(tmp_path):
    host, engine = planned_host(tmp_path)
    host.lifecycle("restart", "analyst")
    assert engine.inspect("old")["HostConfig"]["RestartPolicy"] == {"Name": "on-failure", "MaximumRetryCount": 4}


@pytest.mark.parametrize("crash_at", ["before_first", "between", "after_second"])
def test_interrupted_restore_reconciles_exact_folder_identities(tmp_path, monkeypatch, crash_at):
    host, engine = planned_host(tmp_path)
    host.apply("d" * 64, "analyst")
    rename = host_module.os.rename
    count = 0
    class Crash(BaseException):
        pass
    def interrupted(source, destination):
        nonlocal count
        count += 1
        if crash_at == "before_first" and count == 1 or crash_at == "between" and count == 2:
            raise Crash()
        result = rename(source, destination)
        if crash_at == "after_second" and count == 2:
            raise Crash()
        return result
    with monkeypatch.context() as patch:
        patch.setattr(host_module.os, "rename", interrupted)
        with pytest.raises(Crash):
            host.rollback("analyst")
    resumed = StorageHost(host.config, engine, reconcile=True)
    resumed.rollback("analyst")
    assert resumed.read()["phase"] == "awaiting_restore_sign_in"
    assert (host.data / "evidence.xml").read_text() == "original exact bytes"
    assert Path(resumed.read()["quarantine_path"]).exists()


def test_unexplained_missing_data_is_never_treated_as_a_journaled_gap(tmp_path):
    host, engine = planned_host(tmp_path)
    host.apply("d" * 64, "analyst")
    host_module.os.rename(host.data, host.data.with_name("unexplained"))
    with pytest.raises(ValueError, match="disappeared without"):
        host.rollback("analyst")
    assert not engine.inspect("old")["State"]["Running"]


def test_failed_restored_readiness_fences_original_container(tmp_path):
    host, engine = planned_host(tmp_path)
    host.apply("d" * 64, "analyst")
    host.verify_health = lambda *args, **kwargs: (_ for _ in ()).throw(ValueError("not ready"))
    with pytest.raises(ValueError, match="remains stopped"):
        host.rollback("analyst")
    assert not engine.inspect("old")["State"]["Running"]
    assert engine.inspect("old")["HostConfig"]["RestartPolicy"]["Name"] == "no"


def test_repeated_verification_removes_only_disposable_copies(tmp_path):
    host, _ = planned_host(tmp_path)
    host.apply("d" * 64, "analyst")
    for _ in range(3):
        assert host.verify_backup()["verified"]
    assert not list(host.data.parent.glob("nct-verification-*"))
    assert not list(host.data.parent.glob("nct-backup-verification-*"))
    assert Path(host.read()["backup_path"]).is_file()
    assert (host.data / "evidence.xml").is_file()


def test_terminal_and_gui_maintenance_share_the_same_lock(tmp_path):
    import subprocess
    host, _ = planned_host(tmp_path)
    script = Path(__file__).parents[1] / "scripts/nct-maintenance-lock.sh"
    with host.exclusive():
        result = subprocess.run(["sh", "-c", '. "$1"; nct_maintenance_lock "$2"', "lock-test", str(script), host.config["maintenance_lock"]], capture_output=True, text=True)
    assert result.returncode == 2
    assert "another NCT update or recovery operation" in result.stderr


class RepairHost(StorageHost):
    def work_tool(self, state, mode, *arguments):
        if mode == "preview":
            return {"safe_to_apply": True, "affected_count": 1, "blockers": [], "plan_digest": "e" * 64,
                "scans": [{"run_id": "queued", "action": "preserve_queue"}, {"run_id": "interrupted", "action": "interrupt_for_review"}]}
        if getattr(self, "fail_after_write", False):
            with sqlite3.connect(self.data / "analyzer.db") as db:
                db.execute("INSERT INTO evidence VALUES ('changed','repair')")
            raise ValueError("Repair helper stopped after writing its transaction")
        return {"status": "repaired"}


def repair_host(tmp_path):
    host, engine = planned_host(tmp_path)
    return RepairHost(host.config, engine), engine


def test_repair_preview_lists_actions_and_cancel_preserves_queue(tmp_path):
    host, engine = repair_host(tmp_path)
    host.prepare_repair("analyst")
    state = host.read()
    assert state["phase"] == "repair_review"
    assert state["backup_verified"]
    assert state["repair_summary"]["preserved_scan_queue"] == 1
    assert state["repair_summary"]["categories"][0]["actions"][1] == {"action": "interrupt_for_review", "record": "interrupted"}
    assert not engine.inspect("old")["State"]["Running"]
    host.cancel_repair("analyst")
    assert host.read()["phase"] == "restored"
    assert engine.inspect("old")["State"]["Running"]
    assert (host.data / "evidence.xml").read_text() == "original exact bytes"


def test_repair_refuses_changed_plan_then_requires_fresh_sign_in(tmp_path):
    from app.scan_work_recovery import scan_contact_paused
    host, engine = repair_host(tmp_path)
    host.prepare_repair("analyst")
    with pytest.raises(ValueError, match="current safe"):
        host.apply_repair("changed-plan", "analyst")
    assert not engine.inspect("old")["State"]["Running"]
    host.apply_repair("e" * 64, "analyst")
    assert host.read()["phase"] == "awaiting_repair_sign_in"
    assert host.read()["controller_sign_in_verified"] is False
    assert scan_contact_paused(host.data)


def test_repair_failure_after_write_holds_stopped_and_backup_can_restore(tmp_path):
    host, engine = repair_host(tmp_path)
    host.prepare_repair("analyst")
    host.fail_after_write = True
    with pytest.raises(ValueError, match="after writing"):
        host.apply_repair("e" * 64, "analyst")
    assert host.read()["phase"] == "interrupted"
    assert not engine.inspect("old")["State"]["Running"]
    host.rollback("analyst")
    with sqlite3.connect(host.data / "analyzer.db") as db:
        assert db.execute("SELECT COUNT(*) FROM evidence").fetchone()[0] == 1
    with sqlite3.connect(Path(host.read()["quarantine_path"]) / "analyzer.db") as db:
        assert db.execute("SELECT COUNT(*) FROM evidence").fetchone()[0] == 2


def test_repair_writer_lock_failure_still_exposes_recovery(tmp_path, monkeypatch):
    host, engine = repair_host(tmp_path)
    with monkeypatch.context() as patch:
        patch.setattr(host, "writer_lock", lambda: (_ for _ in ()).throw(ValueError("writer still owns data")))
        with pytest.raises(ValueError, match="writer still"):
            host.prepare_repair("analyst")
    assert host.read()["phase"] == "interrupted"
    assert not engine.inspect("old")["State"]["Running"]
    host.rollback("analyst")
    assert host.read()["phase"] == "awaiting_restore_sign_in"


def test_update_marker_fences_all_work_even_if_malformed(tmp_path):
    from app.scan_work_recovery import scan_contact_paused, passive_contact_paused, device_contact_paused, local_processing_paused, storage_maintenance_paused
    root = tmp_path / "evidence"
    (root / "recovery").mkdir(parents=True)
    marker = root / "recovery/update-maintenance.json"
    marker.write_text("incomplete marker")
    assert all(check(root) for check in (scan_contact_paused, passive_contact_paused, device_contact_paused, local_processing_paused, storage_maintenance_paused))


def test_restoration_never_inherits_candidate_sign_in_verification(tmp_path):
    host, engine = planned_host(tmp_path)
    host.apply("d" * 64, "analyst")
    state = host.read()
    host.phase(state, "complete", controller_sign_in_verified=True)
    host.rollback("analyst")
    assert host.read()["phase"] == "awaiting_restore_sign_in"
    assert host.read()["controller_sign_in_verified"] is False


def test_finalization_never_clears_another_operations_collection_pause(tmp_path):
    host, _ = planned_host(tmp_path)
    host.apply("d" * 64, "analyst")
    state = host.read()
    host.phase(state, "release_intent", verified_runtime_id="new", verified_result_phase="complete", controller_sign_in_verified=True)
    marker = host.data / "recovery/update-maintenance.json"
    marker.write_text(json.dumps({"operation": "different"}))
    with pytest.raises(ValueError, match="pause identity changed"):
        host.finalize(state)
    assert marker.exists()
    resumed = StorageHost(host.config, host.engine, reconcile=True)
    assert resumed.read()["phase"] == "interrupted"
    assert marker.exists()


def test_changed_operator_policy_revokes_existing_console_session(tmp_path):
    host = host_module.Host(configuration(tmp_path))
    token = host.token("analyst", "session", 3600)
    assert host.identity(token) == "analyst"
    host.config["allowed_operators"] = ["administrator"]
    with pytest.raises(PermissionError, match="policy restricts"):
        host.identity(token)
    code = host.token("host-recovery", "session", 3600)
    assert host.identity(code) == "host-recovery"


def test_console_readiness_requires_the_independent_helper(monkeypatch):
    import app.recovery_console as console
    monkeypatch.setattr(console, "local_request", lambda *a, **kw: (_ for _ in ()).throw(OSError("not listening")))
    assert TestClient(console.app).get("/health").status_code == 503


def test_chunked_management_body_stops_at_limit_before_authentication(monkeypatch):
    import asyncio
    import app.recovery_console as console
    from starlette.requests import Request
    chunks = iter([b"x" * 20000, b"y" * 20000, b"must not be consumed"])
    consumed = []
    async def receive():
        chunk = next(chunks)
        consumed.append(chunk)
        return {"type": "http.request", "body": chunk, "more_body": True}
    monkeypatch.setattr(console, "local_request", lambda *a, **kw: pytest.fail("Oversized unauthenticated input reached helper"))
    request = Request({"type": "http", "method": "POST", "path": "/api/exchange", "headers": []}, receive)
    response = asyncio.run(console.proxy("exchange", request))
    assert response.status_code == 409
    assert b"too large" in response.body
    assert len(consumed) == 2


def test_configuration_change_invalidates_apply_without_stopping_original(tmp_path):
    host, engine = planned_host(tmp_path)
    engine.items["old"]["HostConfig"]["RestartPolicy"]["MaximumRetryCount"] = 9
    with pytest.raises(ValueError, match="configuration changed"):
        host.apply("d" * 64, "analyst")
    assert engine.inspect("old")["State"]["Running"]
    assert host.read()["phase"] == "validated"


@pytest.mark.parametrize("crash_at", ["unlink", "normal_start"])
def test_final_restart_replays_without_losing_new_normal_outputs(tmp_path, monkeypatch, crash_at):
    class Crash(BaseException):
        pass
    host, engine = planned_host(tmp_path)
    host.apply("d" * 64, "analyst")
    state = host.read()
    host.phase(state, "release_intent", verified_runtime_id="new", verified_result_phase="complete", controller_sign_in_verified=True)
    marker = host.data / "recovery/update-maintenance.json"
    original_unlink, original_command = Path.unlink, engine.command
    def unlink(path, *args, **kwargs):
        result = original_unlink(path, *args, **kwargs)
        if path == marker and crash_at == "unlink":
            raise Crash()
        return result
    def command(*args):
        result = original_command(*args)
        if args == ("start", "new") and crash_at == "normal_start":
            (host.data / "new-normal-output.txt").write_text("retained after release")
            raise Crash()
        return result
    with monkeypatch.context() as patch:
        patch.setattr(Path, "unlink", unlink)
        patch.setattr(engine, "command", command)
        with pytest.raises(Crash):
            host.finalize(state)
    assert host.read()["release_restart_started"] is True
    stops = sum(call[0] == "stop" for call in engine.calls)
    resumed = StorageHost(host.config, engine, reconcile=True)
    assert resumed.read()["phase"] == "complete"
    assert not marker.exists() and engine.inspect("new")["State"]["Running"]
    if crash_at == "normal_start":
        assert (host.data / "new-normal-output.txt").read_text() == "retained after release"
        assert sum(call[0] == "stop" for call in engine.calls) == stops


def test_failed_final_restart_proves_stop_before_reinstating_pause(tmp_path):
    host, engine = planned_host(tmp_path)
    host.apply("d" * 64, "analyst")
    state = host.read()
    host.phase(state, "release_intent", verified_runtime_id="new", verified_result_phase="complete", controller_sign_in_verified=True)
    host.fail_candidate = True
    with pytest.raises(ValueError, match="Candidate failed"):
        host.finalize(state)
    assert host.read()["phase"] == "interrupted"
    assert not engine.inspect("new")["State"]["Running"]
    assert (host.data / "recovery/update-maintenance.json").exists()


def test_console_refuses_cross_origin_and_unknown_actions(monkeypatch):
    import app.recovery_console as console
    monkeypatch.setattr(console, "local_request", lambda *a, **kw: {"contract": "nct-update-v1", "status": "ready"})
    app = console.app
    client = TestClient(app)
    assert client.get("/health").json()["contract"] == "nct-update-v1"
    assert client.post("/api/start", json={}, headers={"Origin": "https://unrelated.test", "X-NCT-Recovery": "1"}).status_code == 403
    assert client.post("/api/start", json={}).status_code == 403
    assert client.post("/api/shell", json={}, headers={"X-NCT-Recovery": "1"}).status_code == 404


def test_console_exchange_hides_token_in_http_only_cookie(monkeypatch):
    import app.recovery_console as console
    monkeypatch.setattr(console, "local_request", lambda *a, **kw: {"token": "private-session", "actor": "analyst"})
    client = TestClient(console.app)
    response = client.post("/api/exchange", json={"code": "once"}, headers={"X-NCT-Recovery": "1"})
    assert response.json() == {"actor": "analyst"}
    assert "HttpOnly" in response.headers["set-cookie"]
    assert "Secure" in response.headers["set-cookie"]
    assert response.headers["cache-control"] == "no-store"


def test_update_pages_explain_offline_intake_and_backup_time():
    from app.update_ui import updates_page, console_page
    assert "Updates and Recovery" in updates_page().body.decode()
    html = console_page().body.decode()
    assert "image checksum is included" in html
    assert "independently" in html
    assert "Operator Guide" in html
    assert "var(--panel)" in html


def test_recovery_feedback_survives_status_polling():
    import shutil
    import subprocess
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is unavailable; run recovery_feedback_runtime.mjs separately")
    result = subprocess.run([node, str(Path(__file__).with_name("recovery_feedback_runtime.mjs"))], capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
