from __future__ import annotations

import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sqlite3
import stat
import tarfile
import threading
import time

import pytest
pytest.importorskip("fcntl")
from fastapi.testclient import TestClient

from app import schema_compatibility as schema
from app.evidence_retirement import (
    active_encounter_sql,
    init_evidence_retirement_storage,
    retire_evidence,
)
from app.evidence_retirement_sources import NMAP_IMPORT, nmap_import_adapter
import app.retirement_guard as guard_module
from app.retirement_guard import (
    BINDING_FILE,
    HIGH_WATER_FILE,
    HOLD_FILE,
    PROVISIONING_FILE,
    check_retirement_guard,
    mark_retirement_restore_hold,
    provision_retirement_guard,
    reconcile_retirement_restore,
)
from app.scan_history_index import init_scan_history_index_storage

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


def test_first_update_creates_missing_retirement_guard_before_inspection(
    tmp_path, monkeypatch,
):
    config = configuration(tmp_path)
    host = host_module.Host(config, Engine(config))
    assert not host.retirement_guard.exists()

    def provision(_image, _command, **_kwargs):
        assert host.retirement_guard.is_dir()
        (host.retirement_guard / PROVISIONING_FILE).write_text(
            json.dumps({"contract": "nct-retirement-guard-v1"})
        )

    monkeypatch.setattr(host, "retirement_helper", provision)

    assert host.provision_retirement_guard("candidate") == {
        "contract": "nct-retirement-guard-v1"
    }


def test_retirement_guard_refuses_link_without_changing_target(tmp_path):
    config = configuration(tmp_path)
    canary = tmp_path / "unrelated-storage"
    canary.mkdir(mode=0o755)
    before = canary.lstat()
    linked = tmp_path / "retirement-guard"
    linked.symlink_to(canary, target_is_directory=True)
    config["retirement_guard_dir"] = str(linked)
    host = host_module.Host(config, Engine(config))

    with pytest.raises(ValueError, match="outside evidence data|owned directory|linked"):
        host.ensure_retirement_guard_storage()

    after = canary.lstat()
    assert linked.is_symlink()
    assert stat.S_IMODE(after.st_mode) == stat.S_IMODE(before.st_mode) == 0o755
    assert list(canary.iterdir()) == []


def test_retirement_guard_refuses_linked_recovery_root_before_creation(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    with sqlite3.connect(data / "analyzer.db") as db:
        db.execute("CREATE TABLE evidence (id TEXT PRIMARY KEY)")
    target = tmp_path / "unrelated-root"
    target.mkdir(mode=0o755)
    before = target.lstat()
    linked_root = tmp_path / "linked-recovery-root"
    linked_root.symlink_to(target, target_is_directory=True)
    config = {
        "state_dir": str(linked_root / "management"),
        "data_dir": str(data),
        "retirement_guard_dir": str(linked_root / "retirement-guard"),
        "container": "nct",
        "console_container": "console",
        "console_image_id": "sha256:" + "c" * 64,
        "application_url": "https://nct.test:8445",
        "console_url": "https://nct.test:8446",
        "maintenance_lock": str(tmp_path / "maintenance.lock"),
    }
    host = host_module.Host(config, Engine(config))

    with pytest.raises(ValueError, match="owner-protected"):
        host.ensure_retirement_guard_storage()

    after = target.lstat()
    assert stat.S_IMODE(after.st_mode) == stat.S_IMODE(before.st_mode) == 0o755
    assert not (target / "retirement-guard").exists()


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
            "NetworkSettings": {"Networks": {"bridge": {}}},
            "Mounts": [{"Destination": "/data", "Type": "bind", "Source": config["data_dir"]}],
            "HostConfig": {"Binds": [config["data_dir"] + ":/data:rw"],
                           "RestartPolicy": {"Name": "on-failure", "MaximumRetryCount": 4}}}}

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
        index = 1
        identifier = "new"
        while identifier in self.items:
            index += 1
            identifier = f"new-{index}"
        mounts = []
        for binding in config["HostConfig"].get("Binds", []):
            source, destination, *_options = binding.split(":")
            mounts.append({"Destination": destination, "Type": "bind", "Source": source,
                           "RW": not _options or _options[0] != "ro"})
        original.update(Id=identifier, Name="/" + name, Image=config["Image"], Config=config,
                        HostConfig=config["HostConfig"], Mounts=mounts,
                        NetworkSettings={"Networks": {
                            host_module.expected_network_name(config): {}
                        }})
        original["State"] = {"Running": False, "Status": "created"}
        self.items[identifier] = original
        return identifier


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

    def candidate_runtime_contract(self, state):
        return {
            "build_id": state["manifest"].get("build_id", "candidate"),
            "build_commit": state["manifest"].get("build_commit", "b" * 40),
            "schema": {
                "writable_schema_version": 9,
                "readable_schema_versions": [8, 9],
                "data_layout_contract": schema.DATA_LAYOUT_CONTRACT,
            },
            "guard_contract": "nct-retirement-guard-v1",
        }

    def checkpoint(self, image):
        with sqlite3.connect(self.data / "analyzer.db") as db:
            db.execute("PRAGMA wal_checkpoint(TRUNCATE)")

    def provision_retirement_guard(self, image):
        return {"contract": "nct-retirement-guard-v1"}

    def mark_retirement_restore_hold(self, image, operation_id):
        return {"state": "hold", "operation_id": operation_id}

    def reconcile_retirement_restore(self, image, operation_id):
        return {"state": "ready", "revision": 0, "event_digest": "root"}

    def runtime_supports_retirement_guard(self, target):
        return True

    def verify_health(self, state, original=False):
        if getattr(self, "fail_candidate", False) and not original:
            (self.data / "evidence.xml").write_text("candidate damaged bytes")
            raise ValueError("Candidate failed startup")
        return {"status": "ok"}


class VirginGuardHost(StorageHost):
    """Exercise the real independent provisioner before any runtime can bind it."""

    def provision_retirement_guard(self, image):
        return provision_retirement_guard(
            self.retirement_guard,
            installation_id=self.config["container"],
            data_identity=self.retirement_data_identity,
        )

    def mark_retirement_restore_hold(self, image, operation_id):
        raise AssertionError("a candidate that never started cannot require restore")

    def reconcile_retirement_restore(self, image, operation_id):
        raise AssertionError("a candidate that never started cannot require reconcile")


class EarlyStartVirginGuardHost(VirginGuardHost):
    """Run the exact v8-to-v9 and guard reconciliation after early start failure."""

    def mark_retirement_restore_hold(self, image, operation_id):
        return mark_retirement_restore_hold(
            self.retirement_guard,
            data_identity=self.retirement_data_identity,
            operation_id=operation_id,
            detail="before replacing live evidence with a verified backup",
        ).__dict__

    def reconcile_retirement_restore(self, image, operation_id):
        db_path = self.data / "analyzer.db"
        attempt = schema.begin_schema_migration(db_path)
        init_evidence_retirement_storage(db_path)
        schema.complete_schema_migration(db_path, attempt)
        return reconcile_retirement_restore(
            db_path,
            data_dir=self.data,
            guard_dir=self.retirement_guard,
            data_identity=self.retirement_data_identity,
            operation_id=operation_id,
        ).__dict__

    def runtime_supports_retirement_guard(self, target):
        return False


class FirstBindInterruptedHost(EarlyStartVirginGuardHost):
    """Model candidate startup dying during its normal first guard binding."""

    def verify_health(self, state, original=False):
        if not original and not getattr(self, "first_bind_attempted", False):
            self.first_bind_attempted = True
            db_path = self.data / "analyzer.db"
            attempt = schema.begin_schema_migration(db_path)
            init_evidence_retirement_storage(db_path)
            schema.complete_schema_migration(db_path, attempt)
            try:
                check_retirement_guard(
                    db_path,
                    data_dir=self.data,
                    guard_dir=self.retirement_guard,
                    data_identity=self.retirement_data_identity,
                )
            except BaseException as exc:
                raise ValueError(
                    "candidate disappeared during first retirement binding"
                ) from exc
        return super().verify_health(state, original=original)


class CompatibleRecoveryHost(EarlyStartVirginGuardHost):
    """Fail once after a protected write, then accept only the pinned candidate."""

    def runtime_supports_retirement_guard(self, target):
        return (
            target.get("Image") == "sha256:" + "b" * 64
            and host_module.Host.runtime_supports_retirement_guard(self, target)
        )

    def check_retirement_guard(self, image):
        return check_retirement_guard(
            self.data / "analyzer.db",
            data_dir=self.data,
            guard_dir=self.retirement_guard,
            data_identity=self.retirement_data_identity,
        ).__dict__

    def verify_health(self, state, original=False):
        if not original and not getattr(self, "failed_once", False):
            self.failed_once = True
            db_path = self.data / "analyzer.db"
            attempt = schema.begin_schema_migration(db_path)
            init_evidence_retirement_storage(db_path)
            schema.complete_schema_migration(db_path, attempt)
            check_retirement_guard(
                db_path,
                data_dir=self.data,
                guard_dir=self.retirement_guard,
                data_identity=self.retirement_data_identity,
            )
            retire_evidence(
                db_path,
                source_family=NMAP_IMPORT,
                encounter_id="observation-retired",
                actor="analyst",
                reason="qualification failure-path retirement",
                adapter=nmap_import_adapter(),
            )
            check_retirement_guard(
                db_path,
                data_dir=self.data,
                guard_dir=self.retirement_guard,
                data_identity=self.retirement_data_identity,
            )
            (self.data / "evidence.xml").write_text("candidate later bytes")
            raise ValueError("candidate failed after protected retirement")
        return {"status": "ok"}


def _replace_database_with_exact_v8(path: Path) -> None:
    path.unlink()
    with sqlite3.connect(path) as db:
        db.executescript(
            (Path(__file__).parent / "fixtures/phase5_r1_schema.sql").read_text()
        )
        v7_fingerprint = schema.schema_fingerprint(db)
        for version, identity in enumerate(schema.MIGRATION_PLAN[:7], 1):
            db.execute(
                "INSERT INTO nct_schema_migrations VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    identity, version, "v8-updater-fixture", "fixture", "completed", 1,
                    "fixture", "fixture", "fixture", v7_fingerprint,
                    v7_fingerprint, None,
                ),
            )
        db.execute(schema.HISTORY_INTENT_DDL)
        db.execute(
            "INSERT INTO nct_schema_state VALUES (1,7,7,?,?,?,?,?,?)",
            (
                schema.DATA_LAYOUT_CONTRACT,
                schema.migration_plan_digest(schema.MIGRATION_PLAN[:7]),
                v7_fingerprint, "v8-updater-fixture", "fixture", "fixture",
            ),
        )
    init_scan_history_index_storage.__wrapped__(path)
    with sqlite3.connect(path) as db:
        v8_fingerprint = schema.schema_fingerprint(db)
        db.execute(
            "INSERT INTO nct_schema_migrations VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                schema.HISTORY_RULES_MIGRATION_ID, 8, "v8-updater-fixture", "fixture",
                "completed", 1, "fixture", "fixture", "fixture",
                v7_fingerprint, v8_fingerprint, None,
            ),
        )
        db.execute(
            """UPDATE nct_schema_state
                  SET schema_contract_version=8,schema_version=8,
                      migration_plan_digest=?,schema_fingerprint=?""",
            (
                schema.migration_plan_digest(schema.MIGRATION_PLAN[:8]),
                v8_fingerprint,
            ),
        )


def planned_host(tmp_path, host_class=StorageHost):
    config = configuration(tmp_path)
    engine = Engine(config)
    host = host_class(config, engine)
    folder = host.root / ("1" * 32)
    (folder / "release").mkdir(parents=True)
    image = folder / "release/image.tar"
    image.write_bytes(b"candidate image")
    state = {"id": "1" * 32, "actor": "analyst", "original": engine.inspect("old"),
        "candidate_image_id": "sha256:" + "b" * 64,
        "candidate_runtime_env": {
            "NCT_APP_VERSION": "test-version",
            "NCT_BUILD_ID": "candidate",
            "NCT_BUILD_COMMIT": "b" * 40,
        },
        "original_build": {"build_id": "old", "build_commit": "a" * 40},
        "manifest": {
            "build_id": "candidate", "build_commit": "b" * 40,
            "image_config_id": "sha256:" + "b" * 64,
            "image_sha256": host_module.digest_file(image),
        },
        "plan_digest": "d" * 64}
    host.phase(state, "validated")
    return host, engine


def test_candidate_replacement_always_receives_required_protected_guard(tmp_path):
    host, _engine = planned_host(tmp_path)
    replacement = host.replacement(host.read())
    environment = {
        item.split("=", 1)[0]: item.split("=", 1)[1]
        for item in replacement["Env"] if "=" in item
    }
    assert environment["NCT_RETIREMENT_GUARD_MODE"] == "required"
    assert environment["NCT_RETIREMENT_GUARD_DIR"] == "/run/nct-retirement-guard"
    assert environment["NCT_RETIREMENT_DATA_IDENTITY"] == host.retirement_data_identity
    assert any(
        item == f"{host.retirement_guard}:/run/nct-retirement-guard:rw"
        for item in replacement["HostConfig"]["Binds"]
    )


def test_runtime_guard_support_requires_exact_host_bind_source_type_and_mode(tmp_path):
    host, _engine = planned_host(tmp_path)
    target = {
        "Config": {"Env": [
            "NCT_RETIREMENT_GUARD_MODE=required",
            "NCT_RETIREMENT_GUARD_DIR=/run/nct-retirement-guard",
            "NCT_RETIREMENT_DATA_IDENTITY=" + host.retirement_data_identity,
        ]},
        "Mounts": [{
            "Type": "bind", "Source": str(host.retirement_guard),
            "Destination": "/run/nct-retirement-guard", "RW": True,
        }],
    }
    assert host_module.Host.runtime_supports_retirement_guard(host, target)
    target["Mounts"][0]["Source"] = str(tmp_path / "wrong")
    assert not host_module.Host.runtime_supports_retirement_guard(host, target)
    target["Mounts"][0]["Source"] = str(host.retirement_guard)
    target["Mounts"][0]["Type"] = "volume"
    assert not host_module.Host.runtime_supports_retirement_guard(host, target)


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


def test_first_v8_upgrade_create_failure_restarts_without_binding_virgin_guard(
    tmp_path, monkeypatch,
):
    host, engine = planned_host(tmp_path, VirginGuardHost)
    _replace_database_with_exact_v8(host.data / "analyzer.db")

    def fail_before_candidate_exists(*_args, **_kwargs):
        raise ValueError("simulated container create refusal")

    monkeypatch.setattr(engine, "create", fail_before_candidate_exists)
    host.apply("d" * 64, "analyst")

    state = host.read()
    assert state["phase"] == "awaiting_restore_sign_in"
    assert state["candidate_may_have_written"] is False
    assert state["completion_kind"] == "original_reconciliation"
    assert state["recovery_outcome"] == {
        "backup_swapped": False,
        "later_evidence_preserved": False,
    }
    assert engine.inspect("old")["State"]["Running"] is True
    assert schema.schema_state(host.data / "analyzer.db")["schema_version"] == 8
    assert (host.retirement_guard / PROVISIONING_FILE).is_file()
    assert not (host.retirement_guard / BINDING_FILE).exists()
    assert not (host.retirement_guard / HIGH_WATER_FILE).exists()
    assert not (host.retirement_guard / HOLD_FILE).exists()
    assert not state.get("quarantine_path")


def test_first_v8_upgrade_early_start_failure_recovers_virgin_guard_and_stays_fenced(
    tmp_path, monkeypatch,
):
    host, engine = planned_host(tmp_path, EarlyStartVirginGuardHost)
    _replace_database_with_exact_v8(host.data / "analyzer.db")
    original_command = engine.command

    def fail_before_candidate_start(*arguments):
        if arguments == ("start", "new"):
            raise ValueError("simulated early candidate start refusal")
        return original_command(*arguments)

    monkeypatch.setattr(engine, "command", fail_before_candidate_start)
    host.apply("d" * 64, "analyst")

    state = host.read()
    assert state["phase"] == "interrupted"
    assert state["candidate_may_have_written"] is True
    assert "restart policy remains disabled" in state["detail"]
    assert (host.data / "evidence.xml").read_text() == "original exact bytes"
    assert schema.schema_state(host.data / "analyzer.db")["schema_version"] == 9
    status = check_retirement_guard(
        host.data / "analyzer.db",
        data_dir=host.data,
        guard_dir=host.retirement_guard,
        data_identity=host.retirement_data_identity,
    )
    assert status.ready and status.revision == 0
    assert not (host.retirement_guard / HOLD_FILE).exists()
    assert (host.retirement_guard / BINDING_FILE).is_file()
    assert (host.retirement_guard / HIGH_WATER_FILE).is_file()
    assert (host.retirement_guard / "virgin-restore-binding.json").is_file()
    assert engine.inspect("old")["State"]["Running"] is False
    assert engine.inspect("old")["HostConfig"]["RestartPolicy"]["Name"] == "no"


def _prepare_v8_compatible_restore(tmp_path):
    host, engine = planned_host(tmp_path, CompatibleRecoveryHost)
    _replace_database_with_exact_v8(host.data / "analyzer.db")
    with sqlite3.connect(host.data / "analyzer.db") as db:
        db.execute(
            "INSERT INTO analyst_users VALUES (?,?,?,?,?,?,?,?)",
            (
                "admin", "Range Administrator", "admin", "salt", "hash", 0,
                "now", "fixture",
            ),
        )
        db.executemany(
            "INSERT INTO artifact_registry VALUES (?,?,?,?,?,?)",
            [
                ("1" * 64, 14, "application/xml", "/data/retired.xml", "now", "now"),
                ("2" * 64, 13, "application/xml", "/data/active.xml", "now", "now"),
            ],
        )
        db.executemany(
            "INSERT INTO artifact_observations VALUES (?,?,?,?,?,?,?,?)",
            [
                ("observation-retired", "1" * 64, "nmap_import", "import-retired", "now", "retired.xml", "analyst", "{}"),
                ("observation-active", "2" * 64, "nmap_import", "import-active", "now", "active.xml", "analyst", "{}"),
            ],
        )
    (host.data / "retired.xml").write_text("retired bytes")
    (host.data / "active.xml").write_text("active bytes")
    state = host.read()
    state["manifest"].update(build_id="candidate", build_commit="b" * 40)
    host.prepare_compatible_recovery_proof(state)
    host.phase(state, "validated")
    host.apply("d" * 64, "analyst")
    return host, engine


def test_v8_restore_returns_on_exact_compatible_runtime_with_retirement_preserved(
    tmp_path,
):
    host, engine = _prepare_v8_compatible_restore(tmp_path)
    state = host.read()
    assert state["phase"] == "awaiting_compatible_recovery"
    assert state["retirement"]["revision"] == 1
    assert state["retirement"]["state"] == "ready"
    assert engine.inspect("old")["State"]["Running"] is False
    assert engine.inspect("old")["HostConfig"]["RestartPolicy"]["Name"] == "no"
    assert (host.data / "evidence.xml").read_text() == "original exact bytes"
    assert Path(state["quarantine_path"]).joinpath("evidence.xml").read_text() == "candidate later bytes"

    host.resume_compatible_recovery("analyst")
    state = host.read()
    assert state["phase"] == "awaiting_restore_sign_in"
    assert state["compatible_runtime_recovery"] is True
    runtime = engine.inspect("nct")
    assert runtime["Id"] == state["compatible_recovery_runtime_id"]
    assert runtime["Image"] == "sha256:" + "b" * 64
    assert runtime["State"]["Running"] is True
    assert runtime["HostConfig"]["RestartPolicy"]["Name"] == "no"
    with sqlite3.connect(host.data / "analyzer.db") as db:
        active_sql, active_parameters = active_encounter_sql(
            NMAP_IMPORT, "o.observation_id",
        )
        rows = db.execute(
            "SELECT observation_id FROM artifact_observations o WHERE "
            + active_sql + " ORDER BY observation_id",
            active_parameters,
        ).fetchall()
        account = db.execute(
            "SELECT username,display_name,role,password_salt,password_hash,disabled "
            "FROM analyst_users WHERE username='admin'"
        ).fetchone()
    assert rows == [("observation-active",)]
    assert account == (
        "admin", "Range Administrator", "admin", "salt", "hash", 0,
    )
    assert (host.data / "retired.xml").read_text() == "retired bytes"
    assert (host.data / "active.xml").read_text() == "active bytes"


def test_compatible_recovery_existing_account_and_final_restart_complete(
    tmp_path, monkeypatch,
):
    host, engine = _prepare_v8_compatible_restore(tmp_path)
    host.resume_compatible_recovery("analyst")

    class Cookie:
        name = "nct_session"

    class Response:
        status = 200

        def __init__(self, value):
            self.value = value

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    class Opener:
        def __init__(self):
            self.responses = iter((
                {"authenticated": True},
                {"analyst": {"username": "admin", "role": "admin"}},
            ))

        def open(self, *_args, **_kwargs):
            return Response(next(self.responses))

    monkeypatch.setattr(
        host_module.ssl, "create_default_context", lambda **_kwargs: object(),
    )
    monkeypatch.setattr(
        host_module.http.cookiejar, "CookieJar", lambda: [Cookie()],
    )
    monkeypatch.setattr(
        host_module.urllib.request, "build_opener", lambda *_args: Opener(),
    )
    monkeypatch.setattr(
        host_module.json, "load", lambda response: response.value,
    )

    result = host.confirm(
        "admin", "temporary local value", "recovery-console",
    )
    state = host.read()
    assert state["phase"] == "restored"
    assert state["controller_sign_in_verified"] is True
    assert result["operation"]["phase"] == "restored"
    runtime = engine.inspect("nct")
    assert runtime["State"]["Running"] is True
    assert runtime["HostConfig"]["RestartPolicy"]["Name"] == "on-failure"
    assert not (host.data / "recovery" / "update-maintenance.json").exists()
    assert engine.inspect("old")["State"]["Running"] is False
    assert engine.inspect("old")["HostConfig"]["RestartPolicy"]["Name"] == "no"


def test_compatible_recovery_create_interruption_is_safe_to_retry(tmp_path, monkeypatch):
    host, engine = _prepare_v8_compatible_restore(tmp_path)
    original_create = engine.create
    interrupted = False

    def interrupt_once(name, config):
        nonlocal interrupted
        if name == "nct" and not interrupted:
            interrupted = True
            raise ValueError("simulated compatible runtime create interruption")
        return original_create(name, config)

    monkeypatch.setattr(engine, "create", interrupt_once)
    with pytest.raises(ValueError, match="create interruption"):
        host.resume_compatible_recovery("analyst")
    assert host.read()["phase"] == "compatible_recovery_create_intent"
    assert engine.inspect("old")["State"]["Running"] is False
    monkeypatch.setattr(engine, "create", original_create)
    host.resume_compatible_recovery("analyst")
    assert host.read()["phase"] == "awaiting_restore_sign_in"


def test_compatible_recovery_adopts_exact_container_created_before_host_loss(
    tmp_path, monkeypatch,
):
    host, engine = _prepare_v8_compatible_restore(tmp_path)
    original_create = engine.create
    interrupted = False

    class SimulatedHostLoss(BaseException):
        pass

    def create_then_lose_host(name, config):
        nonlocal interrupted
        identity = original_create(name, config)
        if name == "nct" and not interrupted:
            interrupted = True
            raise SimulatedHostLoss()
        return identity

    monkeypatch.setattr(engine, "create", create_then_lose_host)
    with pytest.raises(SimulatedHostLoss):
        host.resume_compatible_recovery("analyst")
    assert host.read()["phase"] == "compatible_recovery_create_intent"
    assert engine.inspect("nct")["State"]["Running"] is False

    restarted = CompatibleRecoveryHost(host.config, engine, reconcile=True)
    restarted.failed_once = True
    restarted.resume_compatible_recovery("analyst")
    assert restarted.read()["phase"] == "awaiting_restore_sign_in"
    assert restarted.read()["compatible_recovery_runtime_id"] == engine.inspect("nct")["Id"]


@pytest.mark.parametrize(
    "change",
    ["command", "environment", "capability", "restart", "port", "mount", "network"],
)
def test_compatible_recovery_refuses_drift_after_create_before_host_receipt(
    tmp_path, monkeypatch, change,
):
    host, engine = _prepare_v8_compatible_restore(tmp_path)
    original_create = engine.create

    class SimulatedHostLoss(BaseException):
        pass

    def create_then_lose_host(name, config):
        identity = original_create(name, config)
        if name == "nct":
            raise SimulatedHostLoss()
        return identity

    monkeypatch.setattr(engine, "create", create_then_lose_host)
    with pytest.raises(SimulatedHostLoss):
        host.resume_compatible_recovery("analyst")
    current = engine.items[engine.inspect("nct")["Id"]]
    if change == "command":
        current["Config"]["Cmd"] = ["sh", "-c", "sleep infinity"]
    elif change == "environment":
        current["Config"]["Env"].append("UNREVIEWED=1")
    elif change == "capability":
        current["HostConfig"]["CapAdd"] = ["SYS_ADMIN"]
    elif change == "restart":
        current["HostConfig"]["RestartPolicy"] = {
            "Name": "always", "MaximumRetryCount": 0,
        }
    elif change == "port":
        current["HostConfig"]["PortBindings"] = {
            "8080/tcp": [{"HostIp": "0.0.0.0", "HostPort": "1"}],
        }
    elif change == "mount":
        current["Mounts"].append({
            "Destination": "/host", "Type": "bind",
            "Source": str(tmp_path), "RW": True,
        })
    else:
        current["NetworkSettings"]["Networks"]["unreviewed"] = {}

    restarted = CompatibleRecoveryHost(host.config, engine, reconcile=True)
    restarted.failed_once = True
    with pytest.raises(ValueError, match="configuration differs|mount contract|network identity"):
        restarted.resume_compatible_recovery("analyst")
    assert engine.inspect("nct")["State"]["Running"] is False
    assert engine.inspect("old")["State"]["Running"] is False


def test_compatible_recovery_start_crash_is_safe_to_retry_after_helper_restart(
    tmp_path, monkeypatch,
):
    host, engine = _prepare_v8_compatible_restore(tmp_path)
    original_health = host.verify_health
    interrupted = False

    class SimulatedHostCrash(BaseException):
        pass

    def crash_after_start(state, original=False):
        nonlocal interrupted
        if not interrupted:
            interrupted = True
            raise SimulatedHostCrash()
        return original_health(state, original=original)

    monkeypatch.setattr(host, "verify_health", crash_after_start)
    with pytest.raises(SimulatedHostCrash):
        host.resume_compatible_recovery("analyst")
    assert host.read()["phase"] == "compatible_recovery_start_intent"
    assert engine.inspect("nct")["State"]["Running"] is True

    restarted = CompatibleRecoveryHost(host.config, engine, reconcile=True)
    restarted.failed_once = True
    restarted.resume_compatible_recovery("analyst")
    assert restarted.read()["phase"] == "awaiting_restore_sign_in"
    assert engine.inspect("nct")["State"]["Running"] is True


@pytest.mark.parametrize("change", ["image", "mount"])
def test_compatible_recovery_refuses_changed_runtime_identity(tmp_path, change):
    host, engine = _prepare_v8_compatible_restore(tmp_path)
    state = host.read()
    host._compatible_recovery_container(state)
    current = engine.items[state["compatible_recovery_runtime_id"]]
    if change == "image":
        current["Image"] = "sha256:" + "d" * 64
    else:
        guard_mount = next(
            item for item in current["Mounts"]
            if item["Destination"] == "/run/nct-retirement-guard"
        )
        guard_mount["Source"] = str(tmp_path / "wrong-guard")
    with pytest.raises(
        ValueError,
        match="identity changed|guard binding|mount contract|unrelated container",
    ):
        host.resume_compatible_recovery("analyst")
    assert engine.inspect("old")["State"]["Running"] is False


def test_first_v8_candidate_binding_crash_restores_through_journaled_partial_root(
    tmp_path, monkeypatch,
):
    host, engine = planned_host(tmp_path, FirstBindInterruptedHost)
    _replace_database_with_exact_v8(host.data / "analyzer.db")
    original_atomic = guard_module._atomic_receipt
    interrupted = False

    class Crash(BaseException):
        pass

    def interrupt_first_high_water(path, body):
        nonlocal interrupted
        if path.name == HIGH_WATER_FILE and not interrupted:
            interrupted = True
            raise Crash()
        return original_atomic(path, body)

    monkeypatch.setattr(
        guard_module, "_atomic_receipt", interrupt_first_high_water,
    )
    host.apply("d" * 64, "analyst")

    state = host.read()
    assert interrupted
    assert state["phase"] == "interrupted"
    assert state["candidate_may_have_written"] is True
    assert "restart policy remains disabled" in state["detail"]
    status = check_retirement_guard(
        host.data / "analyzer.db",
        data_dir=host.data,
        guard_dir=host.retirement_guard,
        data_identity=host.retirement_data_identity,
    )
    assert status.ready and status.revision == 0
    assert (host.retirement_guard / guard_module.INITIAL_BIND_FILE).is_file()
    assert (host.retirement_guard / guard_module.VIRGIN_RESTORE_FILE).is_file()
    assert not (host.retirement_guard / HOLD_FILE).exists()
    assert (host.data / "evidence.xml").read_text() == "original exact bytes"
    assert engine.inspect("old")["State"]["Running"] is False
    assert engine.inspect("old")["HostConfig"]["RestartPolicy"]["Name"] == "no"


def test_success_waits_for_real_sign_in_and_does_not_start_old_image(tmp_path):
    host, engine = planned_host(tmp_path)
    host.apply("d" * 64, "analyst")
    assert host.read()["phase"] == "awaiting_sign_in"
    assert host.read()["backup_verified"]
    assert host.read()["evidence_verified"]
    assert not host.read().get("controller_sign_in_verified")
    assert not engine.inspect("old")["State"]["Running"]
    assert engine.inspect("nct")["Id"] == "new"


def test_proven_fresh_first_session_creates_durable_release_intent(tmp_path, monkeypatch):
    config = configuration(tmp_path)
    for name in ("ca.pem", "cert.pem", "key.pem"):
        (tmp_path / name).write_text(name)
    config["ca_file"] = str(tmp_path / "ca.pem")
    engine = Engine(config)
    original = engine.items["old"]
    original["Name"] = "/retained"
    original["State"] = {"Running": False, "Status": "exited"}
    original["HostConfig"]["RestartPolicy"] = {"Name": "no", "MaximumRetryCount": 0}
    candidate = copy.deepcopy(original)
    candidate.update(Id="new", Name="/nct", Image=original["Image"])
    candidate["State"] = {"Running": True, "Status": "running"}
    engine.items["new"] = candidate
    engine.items["console"] = {
        "Id": "console", "Image": config["console_image_id"], "Name": "/console",
        "Config": {"Env": []}, "HostConfig": {"RestartPolicy": {"Name": "no", "MaximumRetryCount": 0}},
        "State": {"Running": False, "Status": "exited"}, "Mounts": [],
    }
    host = StorageHost(config, engine)
    operation_id = "e" * 32
    proof = {
        "contract": "nct-fresh-handoff-v1", "operation_id": operation_id,
        "expected_admin": "admin", "expires_at": time.time() + 600,
        "application_image_id": candidate["Image"],
        "console_image_id": config["console_image_id"],
        "original_container_id": original["Id"],
        "original_runtime_sha256": hashlib.sha256(host_module.canonical(host_module.runtime_snapshot(original))).hexdigest(),
        "ca_file": str(tmp_path / "ca.pem"), "ca_sha256": host_module.digest_file(tmp_path / "ca.pem"),
        "cert_file": str(tmp_path / "cert.pem"), "cert_sha256": host_module.digest_file(tmp_path / "cert.pem"),
        "key_file": str(tmp_path / "key.pem"), "key_sha256": host_module.digest_file(tmp_path / "key.pem"),
    }
    binding = {
        "application_url": config["application_url"], "console_url": config["console_url"],
        "data_dir": str(host.data), "container": config["container"],
        "console_container": config["console_container"],
        "console_image_id": config["console_image_id"], "ca_file": config.get("ca_file"),
    }
    proof["runtime_config_sha256"] = hashlib.sha256(host_module.canonical(binding)).hexdigest()
    operation_dir = host.root / operation_id
    operation_dir.mkdir()
    (operation_dir / "fresh-handoff.json").write_bytes(host_module.canonical(proof))
    state = {
        "id": operation_id, "kind": "enable_console", "phase": "awaiting_sign_in",
        "actor": "host-installer", "original": copy.deepcopy(original),
        "candidate_id": "new", "candidate_image_id": candidate["Image"],
        "fresh_handoff": proof,
    }
    candidate_sha256 = hashlib.sha256(host_module.canonical(host_module.runtime_snapshot(candidate))).hexdigest()
    state["candidate_runtime_sha256"] = candidate_sha256
    (operation_dir / "candidate-runtime.json").write_bytes(host_module.canonical({
        "container_id": "new", "sha256": candidate_sha256,
    }))
    host_module.save(host.root / "operation.json", state)
    checked = []
    monkeypatch.setattr(host_module, "verify_fresh_empty", lambda *a, **kw: checked.append((a, kw)))

    class Response:
        def __enter__(self): return self
        def __exit__(self, *_): return False
    monkeypatch.setattr(host_module.ssl, "create_default_context", lambda **kwargs: object())
    monkeypatch.setattr(host_module.urllib.request, "urlopen", lambda *a, **kw: Response())
    monkeypatch.setattr(host_module.json, "load", lambda response: {"analyst": {"username": "admin", "role": "admin"}})
    result = host.confirm_fresh_session(operation_id, "admin", "s" * 64)
    saved = host.read()
    assert result == {"accepted": True}
    assert checked and checked[0][1]["expected_session_token"] == "s" * 64
    assert saved["phase"] == "release_intent"
    assert saved["controller_sign_in_verified"] is True
    assert saved["verification_mode"] == "fresh_normal_sign_in"


def test_completed_and_obsolete_fresh_markers_are_not_applicable(tmp_path):
    config = configuration(tmp_path)
    engine = Engine(config)
    host = StorageHost(config, engine)
    operation_id = "a" * 32
    host_module.save(host.root / "operation.json", {
        "id": operation_id,
        "kind": "enable_console",
        "phase": "complete",
        "controller_sign_in_verified": True,
        "verification_mode": "fresh_normal_sign_in",
        "fresh_handoff": {
            "contract": "nct-fresh-handoff-v1",
            "operation_id": operation_id,
        },
    })
    assert host.confirm_fresh_session(operation_id, "admin", "s" * 64) == {
        "accepted": False,
        "disposition": "not_applicable",
    }
    host_module.save(host.root / "operation.json", {
        "id": "b" * 32,
        "kind": "update",
        "phase": "validated",
        "activity": {"active": True, "step": "review", "label": "Review"},
    })
    assert host.confirm_fresh_session(operation_id, "admin", "s" * 64) == {
        "accepted": False,
        "disposition": "not_applicable",
    }
    assert host.fresh_session_disposition(operation_id, busy=True) == {
        "accepted": False,
        "disposition": "not_applicable",
    }
    assert host.read()["activity"]["active"] is True
    host_module.save(host.root / "operation.json", {
        "id": operation_id,
        "kind": "enable_console",
        "phase": "awaiting_sign_in",
    })
    assert host.fresh_session_disposition(operation_id, busy=True) == {
        "accepted": True,
        "disposition": "finishing",
    }


def test_console_sign_in_fallback_completes_fresh_marker_for_later_login(
    tmp_path, monkeypatch
):
    config = configuration(tmp_path)
    engine = Engine(config)
    host = StorageHost(config, engine)
    operation_id = "c" * 32
    original = engine.inspect("old")
    host_module.save(host.root / "operation.json", {
        "id": operation_id,
        "kind": "enable_console",
        "phase": "awaiting_sign_in",
        "actor": "host-installer",
        "original": original,
        "candidate_id": original["Id"],
        "candidate_image_id": original["Image"],
        "release_restart_started": True,
        "fresh_handoff": {
            "contract": "nct-fresh-handoff-v1",
            "operation_id": operation_id,
        },
    })

    class Cookie:
        name = "nct_session"

    class Response:
        def __init__(self, value):
            self.status = 200
            self.value = value

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    class Opener:
        def __init__(self):
            self.responses = iter((
                {"authenticated": True},
                {"analyst": {"username": "admin", "role": "admin"}},
            ))

        def open(self, *_args, **_kwargs):
            return Response(next(self.responses))

    monkeypatch.setattr(host_module.ssl, "create_default_context", lambda **_kwargs: object())
    monkeypatch.setattr(host_module.http.cookiejar, "CookieJar", lambda: [Cookie()])
    monkeypatch.setattr(host_module.urllib.request, "build_opener", lambda *_args: Opener())
    monkeypatch.setattr(host_module.json, "load", lambda response: response.value)

    host.confirm("admin", "temporary local value", "recovery-console")
    saved = host.read()
    assert saved["phase"] == "complete"
    assert saved["controller_sign_in_verified"] is True
    assert "verification_mode" not in saved
    assert json.loads(
        (host.data / "recovery" / "fresh-handoff-complete.json").read_text()
    ) == {
        "contract": "nct-fresh-handoff-complete-v1",
        "operation_id": operation_id,
    }
    assert host.confirm_fresh_session(operation_id, "admin", "s" * 64) == {
        "accepted": False,
        "disposition": "not_applicable",
    }


@pytest.mark.parametrize("change", ["missing", "expired", "operation", "receipt"])
def test_fresh_session_never_bypasses_missing_or_changed_proof(tmp_path, change):
    config = configuration(tmp_path)
    engine = Engine(config)
    host = StorageHost(config, engine)
    operation_id = "e" * 32
    proof = {"contract": "nct-fresh-handoff-v1", "operation_id": operation_id,
        "expected_admin": "admin", "expires_at": time.time() + 600}
    operation_dir = host.root / operation_id
    operation_dir.mkdir()
    (operation_dir / "fresh-handoff.json").write_bytes(host_module.canonical(proof))
    state = {"id": operation_id, "kind": "enable_console", "phase": "awaiting_sign_in",
        "original": engine.inspect("old"), "fresh_handoff": proof}
    if change == "missing": state.pop("fresh_handoff")
    elif change == "expired": proof["expires_at"] = time.time() - 1
    elif change == "operation": proof["operation_id"] = "f" * 32
    else: (operation_dir / "fresh-handoff.json").write_text("{}")
    host_module.save(host.root / "operation.json", state)
    before = host.read()
    with pytest.raises(PermissionError):
        host.confirm_fresh_session(operation_id, "admin", "s" * 64)
    assert host.read() == before


def test_corrupt_backup_keeps_old_image_stopped_and_preserves_candidate_data(tmp_path):
    host, engine = planned_host(tmp_path)
    host.apply("d" * 64, "analyst")
    (host.root / host.read()["id"] / "backup.tar.gz").write_bytes(b"corrupt")
    with pytest.raises(ValueError, match="checksum"):
        host.rollback("analyst")
    assert host.read()["phase"] == "interrupted"
    assert not engine.inspect("old")["State"]["Running"]
    assert (host.data / "evidence.xml").read_text() == "original exact bytes"


def test_apply_failure_survives_successful_original_recovery(tmp_path, monkeypatch):
    host, engine = planned_host(tmp_path)
    planned = host.read()
    planned["candidate_may_have_written"] = False
    host_module.save(host.root / "operation.json", planned)
    monkeypatch.setattr(host, "compatibility", lambda state: (_ for _ in ()).throw(ValueError("exact compatibility failure")))

    host.apply("d" * 64, "analyst")

    saved = host.read()
    assert saved["phase"] == "awaiting_restore_sign_in"
    assert saved["detail"].startswith("The original installation restarted")
    assert saved["apply_failure"]["phase"] == "fence_intent"
    assert saved["apply_failure"]["detail"] == "exact compatibility failure"
    assert saved["apply_failure"]["recorded_at"] <= saved["updated_at"]
    assert host.public()["apply_failure"] == saved["apply_failure"]
    assert engine.inspect("old")["State"]["Running"] is True

    class Cookie:
        name = "nct_session"

    class Response:
        status = 200

        def __init__(self, value):
            self.value = value

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    class Opener:
        def __init__(self):
            self.responses = iter((
                {"authenticated": True},
                {"analyst": {"username": "admin", "role": "admin"}},
            ))

        def open(self, *_args, **_kwargs):
            return Response(next(self.responses))

    monkeypatch.setattr(host_module.ssl, "create_default_context", lambda **_kwargs: object())
    monkeypatch.setattr(host_module.http.cookiejar, "CookieJar", lambda: [Cookie()])
    monkeypatch.setattr(host_module.urllib.request, "build_opener", lambda *_args: Opener())
    monkeypatch.setattr(host_module.json, "load", lambda response: response.value)

    result = host.confirm("admin", "temporary local value", "recovery-console")
    terminal = host.read()
    assert terminal["phase"] == "restored"
    assert terminal["recovery_outcome"] == {"backup_swapped": False, "later_evidence_preserved": False}
    assert terminal["apply_failure"] == saved["apply_failure"]
    assert result["operation"]["apply_failure"] == saved["apply_failure"]
    diagnostic = host.diagnose()
    assert diagnostic["operation"]["apply_failure"] == saved["apply_failure"]
    assert diagnostic["operation"]["completion_kind"] == "original_reconciliation"


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


def test_interruption_after_retirement_reconciliation_resumes_before_app_start(
    tmp_path, monkeypatch,
):
    host, engine = planned_host(tmp_path)
    host.apply("d" * 64, "analyst")
    reconciliations = []
    original_reconcile = StorageHost.reconcile_retirement_restore

    def record_reconciliation(self, image, operation_id):
        reconciliations.append(operation_id)
        return original_reconcile(self, image, operation_id)

    monkeypatch.setattr(
        StorageHost, "reconcile_retirement_restore", record_reconciliation,
    )
    original_command = engine.command

    class Crash(BaseException):
        pass

    crashed = False

    def interrupt_before_start(*arguments):
        nonlocal crashed
        if arguments[0] == "start" and not crashed:
            crashed = True
            raise Crash()
        return original_command(*arguments)

    monkeypatch.setattr(engine, "command", interrupt_before_start)
    with pytest.raises(Crash):
        host.rollback("analyst")

    resumed = StorageHost(host.config, engine, reconcile=True)
    resumed.rollback("analyst")
    assert reconciliations == [host.read()["id"], host.read()["id"]]
    assert resumed.read()["phase"] == "awaiting_restore_sign_in"
    assert engine.inspect("old")["State"]["Running"] is True


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


def test_restore_never_restarts_an_older_runtime_without_exact_guard_mount(tmp_path):
    host, engine = planned_host(tmp_path)
    host.apply("d" * 64, "analyst")
    host.runtime_supports_retirement_guard = lambda _target: False
    with pytest.raises(ValueError, match="restart policy remains disabled"):
        host.rollback("analyst")
    original = engine.inspect("old")
    assert original["State"]["Running"] is False
    assert original["HostConfig"]["RestartPolicy"]["Name"] == "no"


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


def mount_plan(tmp_path):
    host, engine = planned_host(tmp_path)
    engine.items["old"]["Mounts"].append({"Destination": "/reference", "Type": "bind",
        "Source": "/reference-source", "RW": False, "Mode": "ro", "Propagation": "rprivate"})
    state = host.read()
    state["original"] = engine.inspect("old")
    host_module.save(host.root / "operation.json", state)
    return host, engine


def test_reordered_mounts_allow_full_backup_and_apply(tmp_path):
    host, engine = mount_plan(tmp_path)
    original = host.read()["original"]
    engine.items["old"]["Mounts"].reverse()
    host.apply("d" * 64, "analyst")
    state = host.read()
    assert state["phase"] == "awaiting_sign_in"
    assert state["backup_verified"] and state["evidence_verified"]
    assert state["original"] == original
    assert state["plan_digest"] == "d" * 64


@pytest.mark.parametrize("field,value", [
    ("Source", "/different"), ("Destination", "/different"), ("Type", "volume"),
    ("RW", True), ("Mode", "rw"), ("Propagation", "shared"),
    ("Options", {"changed": True}), ("Unexpected", "new-value"),
])
def test_actual_mount_drift_refused_before_any_stop(tmp_path, field, value):
    host, engine = mount_plan(tmp_path)
    engine.items["old"]["Mounts"][1][field] = value
    before = host.read()
    with pytest.raises(ValueError, match="configuration changed"):
        host.apply("d" * 64, "analyst")
    assert host.read() == before
    assert not any(call[0] in {"stop", "rename", "start"} for call in engine.calls)
    assert not (host.root / before["id"] / "backup.tar.gz").exists()


@pytest.mark.parametrize("change", ["missing", "duplicate", "image", "config", "hostconfig"])
def test_runtime_drift_refused_before_fence(tmp_path, change):
    host, engine = mount_plan(tmp_path)
    current = engine.items["old"]
    if change == "missing":
        current["Mounts"].pop()
    elif change == "duplicate":
        current["Mounts"].append(copy.deepcopy(current["Mounts"][1]))
    elif change == "image":
        current["Image"] = "sha256:" + "f" * 64
    elif change == "config":
        current["Config"]["Env"].reverse()
        current["Config"]["Env"].append("CHANGED=1")
    else:
        current["HostConfig"]["RestartPolicy"]["MaximumRetryCount"] = 9
    before = host.read()
    with pytest.raises(ValueError, match="configuration changed"):
        host.apply("d" * 64, "analyst")
    assert host.read() == before
    assert engine.inspect("old")["State"]["Running"]
    assert not any(call[0] in {"stop", "rename", "start"} for call in engine.calls)


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
    assert "Update failure that started recovery" in html
    assert "Start the checked recovery version" in html
    assert "/resume-compatible" in html
    assert "START COMPATIBLE RECOVERY" in html


def test_recovery_feedback_survives_status_polling():
    import shutil
    import subprocess
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is unavailable; run recovery_feedback_runtime.mjs separately")
    result = subprocess.run([node, str(Path(__file__).with_name("recovery_feedback_runtime.mjs"))], capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
