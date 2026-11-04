#!/usr/bin/env python3
"""Trusted terminal upgrade of an installed helper/console, never a GUI upload.

Application identity, evidence and application operation receipts are not replaced.
An interrupted transaction requires explicit rollback before another upgrade.
"""
import argparse
import copy
import fcntl
import hashlib
import http.client
import json
import os
from pathlib import Path
import secrets
import shlex
import socket
import stat
import subprocess
import tarfile
import tempfile
import time

from nct_update_host import Docker, Host, canonical, digest_file, save, sync_directory
from build_nct_range_package import verify_manifest

FILES = ("nct_update_host.py", "nct_update_work.py", "nct-range-data-check.py")
BASE_HASHES = {
    "nct_update_host.py": {"49252e8761c94167470154f945d39355443145a046e6f924db6a031d9804ffee"},
    "nct_update_work.py": {"c89c7b61d547d7a643d11af26bf4163ea55a014a9fc377ee3a1c85c113481135"},
    "nct-range-data-check.py": {"8ed5b3e4f7fd4d517df823e78613be5617eb2051db8475edc443757594c27a38"},
}
FRESH_R2 = "0.16.0-range-test-20261102-fresh-r2"
FRESH_R2_COMMIT = "ba2124aad40dc9f4f718c2799db35d9703a5f89d"
BASELINES = {
    (FRESH_R2, FRESH_R2_COMMIT): {
        "files": {name: values for name, values in BASE_HASHES.items()},
        "app_config_digest": "sha256:015d686a5ccd182a8037db34b756ad89223ff4ebfd65b5e0f55244cc128454a5",
        "console_config_digest": "sha256:d6f0b78a5a5513c1840a6fe609872ba4b9aa66d3fffb6a3302b39b6911fdc5e2",
    },
}
SERVICE = "nct-recovery-host.service"
# The sealed Recovery-r4 bridge injects this compatibility identity before it
# calls the earlier lifecycle contract. Current Fresh-r2 admission is governed
# by BASELINES; this hook remains only so the sealed bridge can still be tested
# and recovered without changing that already-issued package.
OLD_CONSOLE = None


def protected(path, directory=False):
    path = Path(path)
    if not path.is_absolute() or path.resolve() != path:
        raise ValueError("Recovery paths must be absolute without symbolic links")
    for item in (path, *path.parents):
        value = item.stat()
        if value.st_uid != 0 or value.st_mode & 0o022:
            raise ValueError("Recovery paths must be root-owned and not writable by other users")
    if directory != path.is_dir() or (not directory and not path.is_file()):
        raise ValueError("Unexpected recovery path type")
    return path


def host_configuration(value):
    value = copy.deepcopy(value)
    # Docker may materialize the unset default as False after create. Both mean
    # the OOM killer remains enabled; True is deliberately never normalized away.
    if value.get("OomKillDisable") is None:
        value["OomKillDisable"] = False
    return value


def fingerprint(item):
    # Docker inspection order is not an identity. Runtime counters are not config.
    return hashlib.sha256(canonical({"Id": item["Id"], "Image": item["Image"],
        "Config": item["Config"], "HostConfig": host_configuration(item["HostConfig"]),
        "Mounts": sorted(item["Mounts"], key=lambda m: canonical(m))})).hexdigest()


def replace_bytes(path, payload):
    temporary = path.with_name(path.name + ".recovery-upgrade-new")
    if temporary.exists():
        if temporary.is_symlink() or not temporary.is_file():
            raise ValueError("Unexpected interrupted helper temporary path")
        temporary.unlink()  # Only the protected, dedicated staging file, never evidence.
    with temporary.open("xb") as stream:
        os.chmod(temporary, 0o600)
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    sync_directory(path.parent)


class Upgrade:
    def __init__(self, config_path, source, image, *, engine=None, service=None, unit=None):
        self.path, self.source = Path(config_path), Path(source)
        self.engine = engine or Docker()
        self.service = service or (lambda verb: subprocess.run(["systemctl", verb, SERVICE], check=True, timeout=60))
        self.unit = Path(unit or "/etc/systemd/system/" + SERVICE)
        self.image = image
        self.config = json.loads(self.path.read_text())
        self.state = Path(self.config["state_dir"])
        self.journal_path = self.path.parent / "helper-upgrade.json"

    def phase(self, journal, phase):
        journal.update(phase=phase, updated_at=time.time())
        save(self.journal_path, journal)
        print(phase.replace("_", " "), flush=True)

    def operation(self):
        path = self.state / "operation.json"
        raw = path.read_bytes() if path.exists() else b""
        operation = json.loads(raw) if raw else {"phase": "idle"}
        if operation.get("phase") not in {"idle", "complete", "restored"} or operation.get("activity", {}).get("active"):
            raise ValueError("Finish the current update/recovery before upgrading its helper")
        if operation["phase"] != "idle" and operation.get("controller_sign_in_verified") is not True:
            raise ValueError("Existing recovery account verification is unfinished")
        for receipt in self.state.glob("nct-maintenance-helper-*.json"):
            if json.loads(receipt.read_text()).get("phase") != "stopped":
                raise ValueError("A saved maintenance worker needs review")
        return hashlib.sha256(raw).hexdigest()

    def check_service(self):
        lines = [line.split("=", 1)[1] for line in self.unit.read_text().splitlines() if line.startswith("ExecStart=")]
        if len(lines) != 1:
            raise ValueError("Expected one protected helper service command")
        command = shlex.split(lines[0])
        if len(command) != 4 or command[1:] != [str(self.path.parent / "nct_update_host.py"), "--config", str(self.path)]:
            raise ValueError("The helper service does not use the reviewed installation paths")
        protected(command[0])
        subprocess.run([command[0], "-c", "import sys; assert sys.version_info >= (3,9)"], check=True, timeout=10)
        pid = subprocess.check_output(["systemctl", "show", "--property=MainPID", "--value", SERVICE], timeout=10).decode().strip()
        if not pid.isdigit() or int(pid) < 1:
            raise ValueError("The helper service has no running owner")
        if Path("/proc", pid, "status").stat().st_uid != 0 or Path("/proc", pid, "cmdline").read_bytes().rstrip(b"\0").split(b"\0") != [v.encode() for v in command]:
            raise ValueError("The running service is not the exact reviewed helper")

    def image_config_digest(self, image):
        # New image stores report a manifest digest as .Id; older stores report
        # the configuration digest. Export the pinned immutable runtime to prove
        # its configuration bytes against the transfer archive on either engine.
        with tempfile.TemporaryDirectory(prefix="nct-console-image-check-") as folder:
            archive = Path(folder) / "image.tar"
            self.engine.command("save", "-o", str(archive), image)
            with tarfile.open(archive) as stream:
                manifests = json.load(stream.extractfile("manifest.json"))
                if len(manifests) != 1:
                    raise ValueError("Expected one exact console image")
                member = stream.getmember(manifests[0]["Config"])
                if not member.isfile() or member.size > 1024**2:
                    raise ValueError("Invalid console image configuration")
                return "sha256:" + hashlib.sha256(stream.extractfile(member).read()).hexdigest()

    def preflight(self):
        protected(self.path)
        protected(self.path.parent, True)
        protected(self.state, True)
        protected(self.unit)
        for kind in ("launch", "control"):
            protected(self.state / ("sockets/" + kind), True)
            if self.config.get(kind + "_socket") != str(self.state / ("sockets/" + kind) / (kind + ".sock")):
                raise ValueError("Management socket configuration changed")
        protected(self.state / "spool", True)
        if json.loads(self.path.read_text()) != self.config:
            raise ValueError("Installed helper configuration changed")
        protected(Path(self.config["maintenance_lock"]).parent, True)
        self.check_service()
        app = self.engine.inspect(self.config["container"])
        env = dict(v.split("=", 1) for v in app["Config"].get("Env", []) if "=" in v)
        baseline_key = (env.get("NCT_BUILD_ID"), env.get("NCT_BUILD_COMMIT"))
        baseline = BASELINES.get(baseline_key)
        if baseline is None or app["State"].get("Running") is not True:
            raise ValueError("This helper upgrade requires one exact running supported application baseline")
        for name in FILES:
            protected(self.path.parent / name)
            if digest_file(self.path.parent / name) not in baseline["files"][name]:
                raise ValueError("Installed helper does not match the exact application baseline: " + name)
        if self.config.get("contract") != "nct-update-v1":
            raise ValueError("Installed console baseline is unsupported")
        verify_manifest(self.source.parent)
        release = json.loads((self.source.parent / "release.json").read_text())
        if release.get("contract") != "nct-full-range-package-v1":
            raise ValueError("A complete verified full release package is required")
        declared = release.get("helper_upgrade_source")
        if (not isinstance(declared, dict)
            or (declared.get("build_id"), declared.get("build_commit")) != baseline_key
            or declared.get("host_sha256") != digest_file(self.path.parent / "nct_update_host.py")
            or declared.get("app_image_id") != baseline["app_config_digest"]
            or declared.get("console_image_id") != baseline["console_config_digest"]):
            raise ValueError("The full package does not declare this exact installed helper stack")
        image = json.loads(self.engine.command("image", "inspect", self.image))[0]
        env = dict(v.split("=", 1) for v in image["Config"].get("Env", []) if "=" in v)
        expected = release["images"][release["console_image"]]["archive_config_digest"]
        if self.image_config_digest(image["Id"]) != expected or env.get("NCT_BUILD_COMMIT") != release["commit"] or env.get("NCT_BUILD_ID") != release["build_id"]:
            raise ValueError("Use the pinned console from the new full release")
        bindings = {v["package"]:v["sha256"] for v in release["source_bindings"]}
        for name in (*FILES, "nct-upgrade-recovery.py", "build_nct_range_package.py"):
            if digest_file(self.source / name) != bindings.get("scripts/" + name):
                raise ValueError("Release helper sources do not match the checked full package")
        data_mounts = [m for m in app["Mounts"] if m["Destination"] == "/data"]
        if (self.image_config_digest(app["Image"]) != baseline["app_config_digest"]
            or len(data_mounts) != 1 or data_mounts[0]["Type"] != "bind"
            or data_mounts[0]["Source"] != self.config.get("data_dir") or not data_mounts[0]["RW"]
            or app["HostConfig"].get("Privileged")
            or any(m["Destination"].startswith("/data/") or m["Destination"] in {"/", "/run/docker.sock", "/var/run/docker.sock"} for m in app["Mounts"])):
            raise ValueError("The application no longer has the supported evidence and host-access configuration")
        console = self.engine.inspect(self.config["console_container"])
        runtime = console["HostConfig"]
        if (self.config.get("console_image_id") != console["Image"]
            or self.image_config_digest(console["Image"]) != baseline["console_config_digest"]
            or runtime.get("Privileged") or not runtime.get("ReadonlyRootfs")):
            raise ValueError("Existing console image or security configuration changed")
        if runtime.get("CapDrop") != ["ALL"] or runtime.get("CapAdd") or runtime.get("SecurityOpt") not in (["no-new-privileges"], ["no-new-privileges:true"]):
            raise ValueError("Console restrictions changed")
        if runtime.get("IpcMode") not in {None, "", "private", "shareable"} or runtime.get("NetworkMode") not in {None, "", "default", "bridge"} or any(runtime.get(k) for k in ("PidMode", "Devices", "DeviceRequests", "VolumesFrom")):
            raise ValueError("Unsupported console namespaces or devices")
        tls = {}
        for suffix in ("crt", "key"):
            matches = [m for m in app["Mounts"] if m["Destination"] in {"/run/tls/nct-server."+suffix, "/run/tls/server."+suffix}]
            if len(matches) != 1 or matches[0]["Type"] != "bind" or matches[0]["RW"]:
                raise ValueError("Expected reviewed application TLS mounts")
            tls[suffix] = protected(matches[0]["Source"])
        mounts = {"/run/nct-recovery":(self.state / "sockets/control", False),
                  "/staging":(self.state / "spool", True),
                  "/run/tls/server.crt":(tls["crt"], False), "/run/tls/server.key":(tls["key"], False)}
        if len(console["Mounts"]) != len(mounts) or len({m["Destination"] for m in console["Mounts"]}) != len(mounts):
            raise ValueError("Existing console has an unsupported mount")
        for mount in console["Mounts"]:
            match = mounts.get(mount["Destination"])
            if not match or mount["Type"] != "bind" or mount["Source"] != str(match[0]) or mount["RW"] != match[1]:
                raise ValueError("Console mount source or access changed")
        self.service("is-active")
        return {"app": app, "console": console, "image": image["Id"], "release_env":{
                    k:v for k,v in dict(v.split("=",1) for v in image["Config"].get("Env",[]) if "=" in v).items() if k in {"NCT_BUILD_ID","NCT_BUILD_COMMIT"}},
                "operation": self.operation(), "config_sha256":digest_file(self.path),
                "baseline": {"build_id": baseline_key[0], "build_commit": baseline_key[1],
                    "app_config_digest": baseline["app_config_digest"],
                    "console_config_digest": baseline["console_config_digest"]},
                "source_hashes": {name:digest_file(self.source / name) for name in FILES}}

    def unchanged_app(self, journal):
        if fingerprint(self.engine.inspect(self.config["container"])) != journal["app_fingerprint"] or self.operation() != journal["operation"]:
            raise ValueError("Application configuration or saved recovery operation changed; inspect the upgrade journal")

    def ready(self, config):
        # The helper's unauthenticated readiness route grants no action capability.
        deadline = time.monotonic() + 40
        while time.monotonic() < deadline:
            connection = http.client.HTTPConnection("localhost", timeout=3)
            try:
                connection.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                connection.sock.settimeout(3)
                connection.sock.connect(config["control_socket"])
                connection.request("GET", "/ready")
                response = connection.getresponse()
                if response.status == 200 and json.loads(response.read(4096)).get("contract") == "nct-update-v1":
                    break
            except (OSError, ValueError, http.client.HTTPException):
                time.sleep(.25)
            finally:
                connection.close()
        else:
            raise ValueError("The installed helper did not become ready")
        host = Host(config, self.engine)
        host.wait_url(config["console_url"] + "/health", lambda v: v.get("contract") == "nct-update-v1")
        host.wait_url(config["application_url"] + "/health/readiness", lambda v: v.get("healthy") is True)

    def apply(self):
        # Hold the same application maintenance lock for the entire transaction.
        lock = os.open(self.config["maintenance_lock"], os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if self.journal_path.exists():
                raise ValueError("An upgrade journal already exists; inspect it and use --rollback for unfinished work")
            plan = self.preflight()
            backup = self.path.parent / ("helper-before-" + secrets.token_hex(8))
            backup.mkdir(mode=0o700)
            journal = {"contract":"nct-helper-upgrade-v1", "phase":"prepared", "backup":str(backup),
                "config_path":str(self.path), "unit_sha256":digest_file(self.unit),
                "config_sha256":plan["config_sha256"],
                "app_fingerprint":fingerprint(plan["app"]), "operation":plan["operation"],
                "old_console":plan["console"], "new_image":plan["image"], "source_hashes":plan["source_hashes"],
                "retained_name":self.config["console_container"]+"-before-"+secrets.token_hex(6),
                "candidate_name":self.config["console_container"]+"-upgrade-"+secrets.token_hex(12)}
            journal["backup_hashes"] = {}
            for path in (self.path, *(self.path.parent / n for n in FILES)):
                replace_bytes(backup / path.name, path.read_bytes())
                journal["backup_hashes"][path.name] = digest_file(backup / path.name)
            self.phase(journal, "prepared")
            try:
                self.phase(journal, "stop_intent")
                self.service("stop")
                self.engine.command("stop", plan["console"]["Id"])
                self.unchanged_app(journal)
                if digest_file(self.path) != journal["config_sha256"] or fingerprint(self.engine.inspect(plan["console"]["Id"])) != fingerprint(plan["console"]):
                    raise ValueError("Installed helper or console configuration changed")
                if digest_file(self.unit) != journal["unit_sha256"]:
                    raise ValueError("The helper service configuration changed")
                self.phase(journal, "files_intent")
                for name, expected in journal["source_hashes"].items():
                    payload = (self.source / name).read_bytes()
                    if hashlib.sha256(payload).hexdigest() != expected:
                        raise ValueError("Release helper content changed")
                    replace_bytes(self.path.parent / name, payload)
                config = {**self.config, "console_image_id":plan["image"]}
                journal["new_config_sha256"] = hashlib.sha256(canonical(config)).hexdigest()
                self.phase(journal, "config_intent")
                save(self.path, config)
                self.phase(journal, "console_intent")
                self.engine.command("rename", plan["console"]["Id"], journal["retained_name"])
                runtime = copy.deepcopy(plan["console"]["Config"])
                runtime.pop("Hostname", None)
                runtime["Image"] = plan["image"]
                runtime["Env"] = [v for v in runtime.get("Env",[]) if v.split("=",1)[0] not in plan["release_env"]] + [k+"="+v for k,v in plan["release_env"].items()]
                runtime["HostConfig"] = copy.deepcopy(plan["console"]["HostConfig"])
                runtime["Labels"] = {**(runtime.get("Labels") or {}), "nct.helper-upgrade":journal["candidate_name"]}
                journal["candidate_runtime"] = runtime
                self.phase(journal, "create_intent")
                self.engine.create(journal["candidate_name"], runtime)
                created = self.engine.inspect(journal["candidate_name"])
                env = dict(v.split("=",1) for v in created["Config"].get("Env",[]) if "=" in v)
                if any(env.get(k) != v for k,v in plan["release_env"].items()):
                    raise ValueError("Created console release identity differs")
                journal["new_console_id"] = created["Id"]
                journal["new_console_fingerprint"] = fingerprint(created)
                self.phase(journal, "rename_intent")
                self.engine.command("rename", created["Id"], self.config["console_container"])
                self.phase(journal, "start_intent")
                self.service("start")
                self.engine.command("start", created["Id"])
                self.ready(config)
                self.unchanged_app(journal)
                self.engine.command("stop", created["Id"])
                self.phase(journal, "complete")
                print("Helper and console upgraded. NCT application and evidence were not replaced.", flush=True)
            except Exception:
                self.restore(journal)
                raise
        finally:
            os.close(lock)

    def restore(self, journal):
        self.unchanged_app(journal)
        protected(self.path)
        protected(self.journal_path)
        if digest_file(self.path) not in {journal["config_sha256"], journal.get("new_config_sha256")}:
            raise ValueError("Helper configuration changed; recovery halted")
        if digest_file(self.unit) != journal["unit_sha256"]:
            raise ValueError("Helper service configuration changed; preserve the upgrade journal")
        backup = protected(Path(journal["backup"]), True)
        if backup.parent != self.path.parent or not backup.name.startswith("helper-before-"):
            raise ValueError("Unexpected helper backup location")
        if set(journal.get("backup_hashes", {})) != {self.path.name, *FILES}:
            raise ValueError("Saved helper file hashes are incomplete; recovery halted")
        for name, expected in journal["backup_hashes"].items():
            if name not in {self.path.name, *FILES} or digest_file(protected(backup / name)) != expected:
                raise ValueError("Saved helper content changed; recovery halted")
        self.phase(journal, "rollback_intent")
        self.service("stop")
        name = self.config["console_container"]
        current = self.engine.exists(name)
        original = journal["old_console"]
        orphan = self.engine.exists(journal["candidate_name"])
        if orphan:
            expected = journal.get("candidate_runtime", {})
            config = copy.deepcopy(orphan["Config"])
            config.pop("Hostname", None)
            compare = copy.deepcopy(expected)
            compare.pop("HostConfig", None)
            if config != compare or host_configuration(orphan["HostConfig"]) != host_configuration(expected.get("HostConfig", {})):
                raise ValueError("Interrupted candidate identity changed; administrator review required")
            journal["new_console_id"] = orphan["Id"]
            self.phase(journal, "rollback_intent")
            self.engine.command("stop", orphan["Id"])
            self.engine.command("rm", orphan["Id"])
        if current and current["Id"] != original["Id"]:
            if current["Id"] != journal.get("new_console_id") or fingerprint(current) != journal.get("new_console_fingerprint"):
                raise ValueError("Ambiguous console identity; preserve the journal for administrator review")
            self.engine.command("stop", current["Id"])
            self.engine.command("rm", current["Id"])
        saved = self.engine.inspect(original["Id"])
        if fingerprint(saved) != fingerprint(original):
            raise ValueError("Original console configuration changed")
        if not current or current["Id"] != original["Id"]:
            self.engine.command("rename", original["Id"], name)
        for path in (self.path, *(self.path.parent / n for n in FILES)):
            replace_bytes(path, (backup / path.name).read_bytes())
        self.service("start")
        self.engine.command("start", original["Id"])
        self.ready(json.loads(self.path.read_text()))
        if not original["State"]["Running"]:
            self.engine.command("stop", original["Id"])
        self.unchanged_app(journal)
        self.phase(journal, "rolled_back")

    def rollback(self):
        protected(self.path)
        protected(self.path.parent, True)
        protected(self.journal_path)
        protected(Path(self.config["maintenance_lock"]).parent, True)
        journal = json.loads(self.journal_path.read_text())
        if journal.get("contract") != "nct-helper-upgrade-v1" or journal.get("config_path") != str(self.path):
            raise ValueError("Upgrade journal identity is invalid")
        if journal["phase"] in {"complete", "rolled_back"}:
            raise ValueError("This upgrade is already finished; do not replay recovery")
        lock = os.open(self.config["maintenance_lock"], os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.restore(journal)
        finally:
            os.close(lock)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=Path("/opt/nct-recovery/config.json"))
    parser.add_argument("--console-image", required=True)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--apply", action="store_true")
    group.add_argument("--rollback", action="store_true")
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("Run on the NCT host as administrator")
    os.umask(0o077)
    upgrade = Upgrade(args.config, Path(__file__).parent, args.console_image)
    if args.rollback:
        upgrade.rollback()
    elif args.apply:
        upgrade.apply()
    else:
        upgrade.preflight()
        print("Checks passed. NCT is unchanged. Use --apply during the maintenance window.")
