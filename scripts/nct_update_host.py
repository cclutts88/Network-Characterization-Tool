#!/usr/bin/env python3
"""Trusted, locally installed recovery authority. No uploaded code is executed.

Run as a host service, never in the NCT application container. Two Unix listeners
separate launch-only application access from authenticated console operations.
"""
from __future__ import annotations

import argparse
import contextlib
import copy
import fcntl
import hashlib
import gzip
import http.client
import http.cookiejar
from http.server import BaseHTTPRequestHandler
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import socketserver
import sqlite3
import stat
import subprocess
import tempfile
import tarfile
import threading
import time
import urllib.parse
import urllib.request
import ssl

CONTRACT = "nct-update-v1"
MAX_UPLOAD = 12 * 1024**3
MAX_IMAGE = 30 * 1024**3
TERMINAL = {"complete", "restored", "failed", "interrupted"}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def restart_policy(target):
    policy = target["HostConfig"]["RestartPolicy"]
    name = policy["Name"] or "no"
    return name + (":" + str(policy["MaximumRetryCount"]) if name == "on-failure" and policy.get("MaximumRetryCount") else "")


def digest_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024**2), b""):
            digest.update(block)
    return digest.hexdigest()


def save(path, value):
    temporary = path.with_suffix(".tmp")
    with open(temporary, "wb") as stream:
        stream.write(canonical(value))
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def file_identity(path):
    value = path.lstat()
    if not stat.S_ISDIR(value.st_mode):
        raise ValueError("Recovery folder is not a regular directory")
    return [value.st_dev, value.st_ino]


def run(args, *, timeout=120, input_file=None):
    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
        process = subprocess.Popen(args, stdin=input_file, stdout=output, stderr=errors)
        deadline = time.monotonic() + timeout
        try:
            while process.poll() is None:
                if time.monotonic() > deadline or os.fstat(output.fileno()).st_size + os.fstat(errors.fileno()).st_size > 8 * 1024**2:
                    raise ValueError("Host operation exceeded its time or output limit")
                time.sleep(.05)
            if process.returncode:
                raise ValueError("Trusted host operation failed: " + args[0] + " " + args[1])
            if os.fstat(output.fileno()).st_size > 8 * 1024**2:
                raise ValueError("Host operation output exceeds its limit")
            output.seek(0)
            return output.read(8 * 1024**2).decode()
        finally:
            if process.poll() is None:
                process.kill()
            process.wait()


class Docker:
    def inspect(self, name):
        return json.loads(run(["docker", "container", "inspect", name]))[0]

    def exists(self, name):
        for item in self.inventory():
            if name == item["Id"] or "/" + name in item["Names"]:
                return self.inspect(item["Id"])
        return None

    def command(self, *args):
        return run(["docker", *args], timeout=180)

    def create(self, name, config):
        result = self.api("POST", "/containers/create?name=" + urllib.parse.quote(name), config)
        return result["Id"]

    def inventory(self):
        return self.api("GET", "/containers/json?all=true")

    def api(self, method, path, body=None):
        connection = http.client.HTTPConnection("localhost", timeout=60)
        connection.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.sock.settimeout(60)
        connection.sock.connect("/var/run/docker.sock")
        try:
            connection.request(method, path, None if body is None else canonical(body),
                               {"Content-Type": "application/json"})
            response = connection.getresponse()
            result = json.loads(response.read(1024**2))
            if response.status not in {200, 201}:
                raise ValueError("Docker refused the management operation")
            return result
        finally:
            connection.close()


def bounded_tar(stream, *, max_entries, max_size):
    """Parse fixed headers before tarfile can allocate PAX/long-name metadata."""
    count, deadline = 0, time.monotonic() + 900
    while True:
        header = stream.read(512)
        if len(header) != 512:
            raise ValueError("Archive is truncated")
        if not any(header):
            trailing = stream.read(10241)
            if len(trailing) > 10240 or any(trailing):
                raise ValueError("Archive has trailing or excessive entries")
            return
        entry = tarfile.TarInfo.frombuf(header, "utf-8", "strict")
        count += 1
        if count > max_entries or entry.type not in {tarfile.REGTYPE, tarfile.AREGTYPE} or not 0 <= entry.size <= max_size:
            raise ValueError("Archive has excessive, linked, special or extended-metadata entries")
        start = stream.tell()
        yield entry, stream
        remaining = entry.size - (stream.tell() - start)
        if remaining < 0:
            raise ValueError("Archive member exceeded its boundary")
        while remaining:
            block = stream.read(min(1024**2, remaining))
            if not block or time.monotonic() > deadline:
                raise ValueError("Archive is truncated or exceeded its processing time")
            remaining -= len(block)
        padding = (-entry.size) % 512
        if len(stream.read(padding)) != padding:
            raise ValueError("Archive padding is truncated")


def validate_package(path: Path, destination: Path, *, with_size=False):
    """Only two regular files; no extraction of user-controlled paths or scripts."""
    destination.mkdir(mode=0o700)
    try:
        with gzip.open(path, "rb") as archive:
            manifest = None
            seen = set()
            for entry, source in bounded_tar(archive, max_entries=2, max_size=MAX_IMAGE):
                if entry.name not in {"release.json", "image.tar"} or entry.name in seen or not entry.isfile():
                    raise ValueError("Use an NCT update package containing only release.json and image.tar")
                limit = 32 * 1024 if entry.name == "release.json" else MAX_IMAGE
                if entry.size <= 0 or entry.size > limit:
                    raise ValueError("Package member exceeds its size limit")
                if shutil.disk_usage(destination).free < entry.size + 1024**3:
                    raise ValueError("Insufficient space for the expanded package member")
                seen.add(entry.name)
                with open(destination / entry.name, "xb") as output:
                    remaining = entry.size
                    while remaining:
                        block = source.read(min(1024**2, remaining))
                        if not block:
                            raise ValueError("Package is truncated")
                        output.write(block)
                        remaining -= len(block)
                    output.flush()
                    os.fsync(output.fileno())
            if seen != {"release.json", "image.tar"}:
                raise ValueError("Update package is incomplete")
        manifest = json.loads((destination / "release.json").read_text())
        required = {"contract", "image_config_id", "image_sha256", "build_id", "build_commit", "source_builds"}
        if set(manifest) != required or manifest["contract"] != CONTRACT:
            raise ValueError("Unsupported update package contract")
        for key in ("image_sha256", "build_commit"):
            if not isinstance(manifest[key], str) or not re.fullmatch("[0-9a-f]{40,64}", manifest[key]):
                raise ValueError("Package identity is invalid")
        if not re.fullmatch("sha256:[0-9a-f]{64}", manifest["image_config_id"]):
            raise ValueError("Package image must have an immutable image ID")
        if not isinstance(manifest["build_id"], str) or not re.fullmatch("[A-Za-z0-9._-]{1,150}", manifest["build_id"]):
            raise ValueError("Package build identity is invalid")
        if not isinstance(manifest["source_builds"], list) or not 1 <= len(manifest["source_builds"]) <= 32:
            raise ValueError("Package must name its tested source builds")
        for source in manifest["source_builds"]:
            if not isinstance(source, dict) or set(source) != {"build_id", "build_commit"}:
                raise ValueError("Package source-build contract is invalid")
        if digest_file(destination / "image.tar") != manifest["image_sha256"]:
            raise ValueError("Release image checksum does not match")
        expanded = validate_image_archive(destination / "image.tar", manifest["image_config_id"])
        return (manifest, expanded) if with_size else manifest
    except Exception as exc:
        shutil.rmtree(destination)
        raise ValueError(str(exc) if isinstance(exc, ValueError) else "Invalid NCT package structure") from exc


def validate_image_archive(path, image_id):
    """Tagless Docker archive with exactly one image and only referenced content."""
    with path.open("rb") as archive:
        entries = {}
        manifests = None
        for member, stream in bounded_tar(archive, max_entries=256, max_size=MAX_IMAGE):
            offset = stream.tell()
            if len(entries) >= 256 or member.name in entries or not member.isfile() or member.size > MAX_IMAGE:
                raise ValueError("Image archive has duplicate, excessive or non-file entries")
            parts = Path(member.name)
            if parts.is_absolute() or ".." in parts.parts:
                raise ValueError("Unsafe image archive member")
            if member.name == "manifest.json":
                if member.size > 32768:
                    raise ValueError("Image manifest exceeds its size limit")
                manifests = json.loads(stream.read(member.size))
            elif member.size <= 1024**2:
                entries[member.name] = {"offset": offset, "size": member.size, "sha256": hashlib.sha256(stream.read(member.size)).hexdigest()}
                continue
            entries[member.name] = {"offset": offset, "size": member.size, "sha256": None}
        if "manifest.json" not in entries or manifests is None:
            raise ValueError("Image archive lacks its bounded Docker manifest")
        if not isinstance(manifests, list) or len(manifests) != 1:
            raise ValueError("Update archives must contain exactly one release image")
        item = manifests[0]
        if item.get("RepoTags") not in ([], None) or not isinstance(item.get("Layers"), list):
            raise ValueError("Update image must be tagless to preserve installed release tags")
        expected = {"manifest.json", item["Config"], *item["Layers"]}
        if set(entries) != expected or entries[item["Config"]]["size"] > 1024**2:
            raise ValueError("Image archive contains unreferenced data or an invalid configuration")
        if "sha256:" + entries[item["Config"]]["sha256"] != image_id:
            raise ValueError("Image configuration digest differs from the release identity")
        archive.seek(entries[item["Config"]]["offset"])
        config = json.loads(archive.read(entries[item["Config"]]["size"]))
        diff_ids = config.get("rootfs", {}).get("diff_ids", [])
        if not isinstance(diff_ids, list) or len(diff_ids) != len(item["Layers"]):
            raise ValueError("Image layer identities are incomplete")
        expanded, checked = 0, {}
        maximum = min(MAX_IMAGE, max(0, shutil.disk_usage(path.parent).free - 1024**3))
        deadline = time.monotonic() + 900
        for name, expected in zip(item["Layers"], diff_ids):
            if name not in checked:
                member = entries[name]
                archive.seek(member["offset"])
                prefix = archive.read(2)
                archive.seek(member["offset"])
                limited = SliceReader(archive, member["size"])
                source = gzip.GzipFile(fileobj=limited) if prefix == b"\x1f\x8b" else limited
                digest = hashlib.sha256()
                try:
                    while True:
                        block = source.read(1024**2)
                        if not block:
                            break
                        expanded += len(block)
                        if expanded > maximum or time.monotonic() > deadline:
                            raise ValueError("Expanded release layers exceed available space or processing limits")
                        digest.update(block)
                finally:
                    if source is not limited:
                        source.close()
                checked[name] = "sha256:" + digest.hexdigest()
            if checked[name] != expected:
                raise ValueError("Release layer content does not match the image configuration")
        return expanded


class SliceReader:
    """Prevent a compressed layer reader from consuming the next tar member."""
    def __init__(self, stream, remaining):
        self.stream, self.remaining = stream, remaining

    def read(self, size=-1):
        size = self.remaining if size < 0 else min(size, self.remaining)
        block = self.stream.read(size)
        self.remaining -= len(block)
        return block


class Host:
    def __init__(self, config, engine=None, *, reconcile=False):
        self.config = config
        policy = config.get("allowed_operators", "all")
        if policy != "all" and (not isinstance(policy, list) or any(not isinstance(actor, str) or not re.fullmatch("[a-z0-9][a-z0-9._-]{1,63}", actor) for actor in policy)):
            raise ValueError("Recovery access policy must be all or an explicit username list")
        self.root = Path(config["state_dir"])
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.root, 0o700)
        self.data = Path(config["data_dir"])
        if self.data.is_symlink() or not self.data.is_absolute() or self.data == self.root or self.data in self.root.parents or self.root in self.data.parents:
            raise ValueError("Recovery state must be outside the exact evidence directory")
        self.engine = engine or Docker()
        self.mutex = threading.Lock()
        self.worker_guard = threading.Lock()
        self.last_access = time.monotonic()
        with self.db() as db:
            db.execute("CREATE TABLE IF NOT EXISTS tokens (hash TEXT PRIMARY KEY, actor TEXT, kind TEXT, expires REAL)")
        self.current = self.root / "operation.json"
        if reconcile and self.current.exists():
            state = self.read()
            if state.get("phase") == "release_intent":
                try:
                    self.finalize(state)
                except Exception as exc:
                    self.phase(state, "interrupted", detail="Final verification requires review: " + str(exc)[:300])
            elif state.get("phase") not in TERMINAL and state.get("phase") not in {"awaiting_sign_in", "awaiting_restore_sign_in", "awaiting_repair_sign_in"}:
                self.phase(state, "interrupted", detail="Host service restarted. Inspect and restore the verified backup before continuing.")
        if reconcile:
            for receipt in self.root.glob("nct-maintenance-helper-*.json"):
                item = json.loads(receipt.read_text())
                if item["phase"] == "stopped":
                    continue
                helper = self.engine.exists(item["name"])
                if helper:
                    if helper["Image"] != item["image"]:
                        raise ValueError("Interrupted helper identity changed; host recovery is fenced")
                    self.stop_exact(helper)
                    self.engine.command("rm", helper["Id"])
                save(receipt, {**item, "phase": "stopped"})

    @contextlib.contextmanager
    def db(self):
        connection = sqlite3.connect(self.root / "sessions.db", timeout=10)
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def token(self, actor, kind="handoff", seconds=120):
        token = secrets.token_urlsafe(40)
        with self.db() as db:
            db.execute("DELETE FROM tokens WHERE expires < ?", (time.time(),))
            db.execute("INSERT INTO tokens VALUES (?,?,?,?)", (hashlib.sha256(token.encode()).hexdigest(), actor, kind, time.time() + seconds))
        return token

    def identity(self, token, kind="session", consume=False):
        hashed = hashlib.sha256(token.encode()).hexdigest()
        with self.db() as db:
            if consume:
                db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT actor FROM tokens WHERE hash=? AND kind=? AND expires>?", (hashed, kind, time.time())).fetchone()
            if not row:
                raise PermissionError("Recovery session expired or access code was already used")
            policy = self.config.get("allowed_operators", "all")
            if policy != "all" and row[0] != "host-recovery" and row[0] not in policy:
                raise PermissionError("Deployment policy restricts this operator's recovery access")
            if consume:
                db.execute("DELETE FROM tokens WHERE hash=?", (hashed,))
        return row[0]

    def read(self):
        return json.loads(self.current.read_text()) if self.current.exists() else {"phase": "idle"}

    def phase(self, state, phase, **values):
        state.update(values, phase=phase, updated_at=time.time())
        event = {"phase": phase, "at": state["updated_at"], "actor": state.get("actor"),
                 "plan_digest": state.get("plan_digest"), "original_id": state.get("original", {}).get("Id"),
                 "candidate_id": state.get("candidate_id"), "swap": state.get("swap")}
        with (self.root / (state["id"] + ".events.jsonl")).open("ab") as stream:
            stream.write(canonical(event) + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
        save(self.current, state)
        receipt = self.root / (state["id"] + ".json")
        save(receipt, state)

    def target(self, *, expected_id=None, name=None):
        target = self.engine.inspect(name or self.config["container"])
        if any(m["Destination"].startswith("/data/") for m in target["Mounts"]):
            raise ValueError("Nested evidence mounts require a separately qualified backup adapter")
        if target["HostConfig"].get("Privileged") or any(m["Destination"] in {"/var/run/docker.sock", "/run/docker.sock", "/"} for m in target["Mounts"]):
            raise ValueError("NCT application must not have unrestricted host or Docker control")
        if expected_id and target["Id"] != expected_id:
            raise ValueError("NCT container identity changed; review the recovery plan")
        mounts = [m for m in target["Mounts"] if m["Destination"] == "/data"]
        if len(mounts) != 1 or mounts[0]["Type"] != "bind" or Path(mounts[0]["Source"]).resolve() != self.data.resolve():
            raise ValueError("NCT does not use the configured exact evidence folder")
        # Inspect all containers, including stopped ones with automatic restart enabled.
        inventory = self.engine.inventory() if hasattr(self.engine, "inventory") else [self.engine.inspect(item) for item in self.engine.command("ps", "-aq", "--no-trunc").split()]
        for summary in inventory:
            other = summary
            if other["Id"] == target["Id"]:
                continue
            for mount in other.get("Mounts", []):
                source = Path(mount["Source"]).resolve()
                if source == self.data.resolve() or source in self.data.resolve().parents or self.data.resolve() in source.parents:
                    other = self.engine.inspect(summary["Id"])
                    if other["State"]["Running"] or other["HostConfig"]["RestartPolicy"]["Name"] not in {"no", ""}:
                        raise ValueError("Another container can write the evidence directory")
        return target

    def helper(self, image, mode, *, root=None, immutable=True):
        tool = str(Path(__file__).with_name("nct-range-data-check.py").resolve())
        # A live mode=ro SQLite reader may need WAL/SHM housekeeping even when
        # there is no current sidecar. Stopped immutable checks remain mount-RO.
        mount_mode = ",readonly" if immutable else ""
        raw = self.run_helper(image, ["--read-only",
            "--mount", f"type=bind,src={root or self.data},dst=/data{mount_mode}",
            "--mount", f"type=bind,src={tool},dst=/nct-check.py,readonly"],
            ["/nct-check.py", mode, "--root", "/data", *(["--immutable"] if immutable else [])])
        return json.loads(raw or "[]")

    def run_helper(self, image, options, command):
        self.engine.command("image", "inspect", image)  # Never substitute an unverified missing image.
        name = "nct-maintenance-helper-" + secrets.token_hex(12)
        receipt = self.root / (name + ".json")
        save(receipt, {"name": name, "image": image, "phase": "create_intent"})
        try:
            return self.engine.command("run", "--pull=never", "--name", name, "--network", "none", "--entrypoint", "python", "-e", "PYTHONPATH=/app",
                *options, image, *command)
        finally:
            helper = self.engine.exists(name)
            if helper:
                if helper["Image"] != image:
                    raise ValueError("Helper identity mismatch; maintenance halted")
                self.engine.command("update", "--restart=no", helper["Id"])
                self.engine.command("stop", helper["Id"])
                if self.engine.inspect(helper["Id"])["State"]["Running"]:
                    raise ValueError("Maintenance helper did not stop; writer handoff refused")
                self.engine.command("rm", helper["Id"])
            save(receipt, {"name": name, "image": image, "phase": "stopped"})

    def diagnose(self):
        target = self.target()
        return {"container_id": target["Id"], "image_config_id": target["Image"],
                "state": target["State"]["Status"], "health": target["State"].get("Health", {}).get("Status", "not configured"),
                "free_bytes": shutil.disk_usage(self.data).free, "operation": self.public()}

    def public(self):
        state = self.read()
        allowed = {"id", "phase", "detail", "actor", "build_id", "build_commit", "running_build_id", "running_build_commit", "updated_at", "plan_digest", "package_sha256", "controller_sign_in_verified", "evidence_verified", "backup_verified", "backup_at", "quarantine_path", "backup_path", "preserved_paths", "repair_summary", "kind", "completion_kind"}
        return {k: v for k, v in state.items() if k in allowed}

    def launch(self, actor):
        console = self.engine.inspect(self.config["console_container"])
        if console["Image"] != self.config["console_image_id"]:
            raise ValueError("Recovery console image does not match its installed identity")
        self.engine.command("start", self.config["console_container"])
        self.wait_url(self.config["console_url"] + "/health", lambda value: value.get("contract") == CONTRACT)
        self.last_access = time.monotonic()
        return {"url": self.config["console_url"] + "/#handoff=" + self.token(actor)}

    def wait_url(self, url, accept):
        for _ in range(40):
            try:
                # Host-provisioned private CA/cert; never globally disable TLS verification.
                context = ssl.create_default_context(cafile=self.config.get("ca_file"))
                with urllib.request.urlopen(url, timeout=3, context=context) as response:
                    value = json.load(response)
                if accept(value):
                    return value
            except (OSError, ValueError):
                pass
            time.sleep(1)
        raise ValueError("The expected management endpoint did not become ready")

    @contextlib.contextmanager
    def exclusive(self):
        if not self.mutex.acquire(blocking=False):
            raise ValueError("Another recovery operation is already running")
        lock_path = Path(self.config["maintenance_lock"])
        lock_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield
        finally:
            os.close(descriptor)
            self.mutex.release()

    def stage(self, stream, length, actor):
        if not 0 < length <= MAX_UPLOAD:
            raise ValueError("Package must be between 1 byte and 12 GiB")
        with self.exclusive():
            staged = sum(p.stat().st_size for p in self.root.glob("*/upload.tar.gz"))
            if staged + length > 24 * 1024**3 or len(list(self.root.glob("*/upload.tar.gz"))) >= 4:
                raise ValueError("Private staging quota reached. An administrator must archive completed packages before another upload.")
            if self.read()["phase"] not in {"idle", "complete", "restored", "failed", "validated"}:
                raise ValueError("Resolve the current recovery operation before uploading another package")
            if shutil.disk_usage(self.root).free < length + 1024**3:
                raise ValueError("Insufficient private staging space")
            operation_id = secrets.token_hex(16)
            folder = self.root / operation_id
            folder.mkdir(mode=0o700)
            archive = folder / "upload.tar.gz"
            with open(archive, "xb") as output:
                remaining = length
                while remaining:
                    block = stream.read(min(1024**2, remaining))
                    if not block:
                        raise ValueError("Upload disconnected before completion")
                    output.write(block)
                    remaining -= len(block)
                output.flush()
                os.fsync(output.fileno())
            manifest, expanded = validate_package(archive, folder / "release", with_size=True)
            docker_root = Path(self.engine.command("info", "--format", "{{.DockerRootDir}}").strip())
            if not docker_root.is_absolute() or not docker_root.is_dir() or shutil.disk_usage(docker_root).free < 2 * expanded + 1024**3:
                raise ValueError("Insufficient or unverified space in the local Docker image store")
            target = self.target()
            original_build = json.loads(self.engine.command("exec", target["Id"], "python", "-c",
                "import json; from app.build_info import BUILD_ID,BUILD_COMMIT; print(json.dumps({'build_id':BUILD_ID,'build_commit':BUILD_COMMIT}))"))
            if original_build not in manifest["source_builds"]:
                raise ValueError("This package has not been qualified for the exact installed source build")
            self.run_helper(target["Image"], ["--read-only"], ["-c", "from app.scan_work_recovery import UPDATE_PAUSE_CONTRACT; assert UPDATE_PAUSE_CONTRACT=='nct-update-pause-v1'"])
            image_path = folder / "release" / "image.tar"
            with image_path.open("rb") as source:
                loaded = run(["docker", "load"], input_file=source, timeout=900)
            loaded_ids = re.findall(r"^Loaded image(?: ID)?: (sha256:[0-9a-f]{64})$", loaded, re.MULTILINE)
            if len(loaded_ids) != 1:
                raise ValueError("Docker did not identify one loaded, tagless release image")
            candidate = json.loads(run(["docker", "image", "inspect", loaded_ids[0]]))[0]
            env = dict(item.split("=", 1) for item in candidate["Config"].get("Env", []) if "=" in item)
            if env.get("NCT_BUILD_ID") != manifest["build_id"] or env.get("NCT_BUILD_COMMIT") != manifest["build_commit"]:
                raise ValueError("Loaded image build identity does not match the package")
            used = sum(p.stat().st_size for p in self.data.rglob("*") if p.is_file())
            if shutil.disk_usage(self.data).free < 3 * used + 1024**3:
                raise ValueError("Insufficient space for a verified backup, restore and failed-data preservation")
            state = {"id": operation_id, "actor": actor, "manifest": manifest, "original": target,
                     "candidate_image_id": candidate["Id"],
                     "package_sha256": digest_file(archive), "build_id": manifest["build_id"],
                     "build_commit": manifest["build_commit"], "original_build": original_build}
            state["plan_digest"] = hashlib.sha256(canonical(state)).hexdigest()
            self.compatibility(state, preview=True)
            self.phase(state, "validated", detail="Package and exact source build match. Apply takes a cold backup before replacing NCT. Checksums verify integrity; use a trusted release source.")
            return self.public()

    def checkpoint(self, image):
        self.run_helper(image, ["--mount", f"type=bind,src={self.data},dst=/data"], ["-c",
            "import sqlite3; d=sqlite3.connect('/data/analyzer.db'); r=d.execute('PRAGMA wal_checkpoint(TRUNCATE)').fetchone(); d.close(); assert r[0]==0, 'Checkpoint busy'"])

    def hold_collection(self, state):
        path = self.data / "recovery" / "update-maintenance.json"
        path.parent.mkdir(mode=0o700, exist_ok=True)
        if path.exists() and json.loads(path.read_text()).get("operation") != state["id"]:
            raise ValueError("A different update owns the collection pause")
        save(path, {"contract": "nct-update-pause-v1", "operation": state["id"], "actor": state["actor"]})

    def finalize(self, state):
        target = self.target(expected_id=state["verified_runtime_id"])
        expected_image = state["original"]["Image"] if state["verified_result_phase"] == "restored" else state["candidate_image_id"]
        if target["Image"] != expected_image:
            raise ValueError("Verified runtime image changed before finalization")
        path = self.data / "recovery" / "update-maintenance.json"
        if path.is_symlink():
            raise ValueError("Collection pause identity changed; finalization halted")
        if path.exists():
            if json.loads(path.read_text()).get("operation") != state["id"]:
                raise ValueError("Collection pause identity changed; finalization halted")
        elif not state.get("release_restart_started"):
            raise ValueError("Verified collection pause is missing before finalization")
        try:
            if path.exists():
                self.stop_exact(target)
                lock = self.writer_lock()
                try:
                    self.checkpoint(expected_image)
                    self.phase(state, "release_intent", release_restart_started=True,
                        detail="Account verified. Restarting the exact version to activate its normal background services.")
                    path.unlink()
                    sync_directory(path.parent)
                finally:
                    os.close(lock)
            target = self.target(expected_id=state["verified_runtime_id"])
            if not target["State"]["Running"]:
                self.engine.command("start", target["Id"])
            self.verify_health(state, original=state["verified_result_phase"] == "restored")
            self.engine.command("update", "--restart=" + restart_policy(state["original"]), target["Id"])
        except Exception as exc:
            # New normal work may have run after release. Preserve it; only an
            # explicit verified restore may return to the saved backup time.
            try:
                self.stop_exact(self.target(expected_id=state["verified_runtime_id"]))
                self.hold_collection(state)
            except Exception as fencing_error:
                self.phase(state, "interrupted", detail="Final restart failed and a safe stop could not be proved. Inspect the exact NCT runtime before recovery: " + str(fencing_error)[:200])
                raise
            self.phase(state, "interrupted", detail="Final restart halted with NCT stopped and collection paused: " + str(exc)[:250])
            raise
        self.phase(state, state["verified_result_phase"], detail="Exact build, readiness, existing-account sign-in and retained evidence verified. Review any remaining unfinished-work recovery gates in NCT.")

    def stop_exact(self, target):
        self.engine.command("update", "--restart=no", target["Id"])
        self.engine.command("stop", "--time", "60", target["Id"])
        if self.engine.inspect(target["Id"])["State"]["Running"]:
            raise ValueError("The original writer did not stop")

    def writer_lock(self):
        descriptor = os.open(self.data / ".analyzer.db.nct-writer.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.lockf(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB, 1, 0)
        except BaseException:
            os.close(descriptor)
            raise ValueError("Another application writer still owns the evidence directory")
        return descriptor

    def backup(self, state):
        folder = self.root / state["id"]
        footprint = sum(path.stat().st_size for path in self.data.rglob("*") if path.is_file())
        required = 3 * footprint + 1024**3
        if min(shutil.disk_usage(self.root).free, shutil.disk_usage(self.data.parent).free) < required:
            raise ValueError("Insufficient space for cold backup, independent verification and a later restore")
        inventory = self.helper(state["original"]["Image"], "snapshot")
        save(folder / "before.json", inventory)
        archive = folder / "backup.tar.gz"
        metadata = self.data.stat()
        state["data_metadata"] = {"uid": metadata.st_uid, "gid": metadata.st_gid, "mode": stat.S_IMODE(metadata.st_mode)}
        with tarfile.open(archive, "w:gz", dereference=True) as output:
            # Reject links and special files before adding anything.
            for path in sorted(self.data.rglob("*")):
                mode = path.lstat().st_mode
                if not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
                    raise ValueError("Evidence contains a link or special file; backup refused")
                output.add(path, arcname=path.relative_to(self.data).as_posix(), recursive=False)
        with archive.open("rb") as stream:
            os.fsync(stream.fileno())
        checksum = digest_file(archive)
        state["backup_sha256"] = checksum
        state["backup_unpacked_bytes"] = sum(p.stat().st_size for p in self.data.rglob("*") if p.is_file())
        restored = self.extract_backup(state, "backup-verification")
        if self.helper(state["original"]["Image"], "snapshot", root=restored) != inventory:
            raise ValueError("Independently restored backup does not match retained evidence")
        self.remove_verification_copy(restored)
        state["backup_verified"] = True
        state["backup_at"] = time.time()
        state["backup_path"] = str(archive)

    def remove_verification_copy(self, path):
        path = Path(path)
        allowed = ("nct-backup-verification-", "nct-verification-", "nct-work-verification-")
        if path.parent != self.data.parent or not path.name.startswith(allowed) or path.is_symlink():
            raise ValueError("Disposable verification path is outside its permitted area")
        shutil.rmtree(path)
        sync_directory(path.parent)

    def extract_backup(self, state, name):
        folder = self.root / state["id"]
        archive = folder / "backup.tar.gz"
        if digest_file(archive) != state["backup_sha256"]:
            raise ValueError("Cold backup checksum failed; original data will not be replaced")
        destination = self.data.parent / ("nct-" + name + "-" + state["id"])
        if destination.exists():
            if name in {"verification", "backup-verification", "work-verification"}:
                self.remove_verification_copy(destination)
            elif name == "restored" and state.get("restore_extraction_path") == str(destination) and not state.get("swap") and not destination.is_symlink():
                shutil.rmtree(destination)  # Journaled incomplete backup-derived scratch only.
                sync_directory(destination.parent)
            else:
                raise ValueError("An earlier restore folder requires reconciliation before another extraction")
        if shutil.disk_usage(self.data.parent).free < state.get("backup_unpacked_bytes", archive.stat().st_size * 4) + 1024**3:
            raise ValueError("Insufficient space to restore and verify the cold backup")
        if name == "restored":
            self.phase(state, "restore_extract_intent", restore_extraction_path=str(destination))
        destination.mkdir(mode=0o700)
        with tarfile.open(archive, "r:gz") as source:
            for member in source:
                path = Path(member.name)
                if path.is_absolute() or ".." in path.parts or not (member.isfile() or member.isdir()):
                    raise ValueError("Backup contains an unsafe entry")
                target = destination / path
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True, mode=0o700)
                    os.chmod(target, member.mode & 0o777)
                    os.chown(target, member.uid, member.gid)
                else:
                    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                    with target.open("xb") as output:
                        shutil.copyfileobj(source.extractfile(member), output)
                        output.flush()
                        os.fsync(output.fileno())
                    os.chmod(target, member.mode & 0o777)
                    os.chown(target, member.uid, member.gid)
        metadata = state.get("data_metadata", {"uid": 0, "gid": 0, "mode": 0o700})
        os.chmod(destination, metadata["mode"])
        os.chown(destination, metadata["uid"], metadata["gid"])
        sync_directory(destination)
        sync_directory(destination.parent)
        return destination

    def compatibility(self, state, preview=False):
        # The image-owned schema gate runs on a disposable consistent SQLite backup.
        # It may write that copy; it never opens retained evidence for writing.
        copied = self.root / state["id"] / ("schema-preview" if preview else "schema-cold-check")
        copied.mkdir(mode=0o700)
        source = sqlite3.connect(self.data.joinpath("analyzer.db").as_uri() + "?mode=ro", uri=True, timeout=15)
        try:
            with sqlite3.connect(copied / "analyzer.db") as destination:
                deadline = time.monotonic() + 60
                def progress(*_):
                    if time.monotonic() > deadline:
                        raise ValueError("Schema preview timed out")
                source.backup(destination, pages=256, progress=progress)
        finally:
            source.close()
        result = self.run_helper(state["candidate_image_id"], ["--read-only", "--mount", f"type=bind,src={copied},dst=/data"], ["-c",
            "import json; from pathlib import Path; from app.scan_work_recovery import UPDATE_PAUSE_CONTRACT; assert UPDATE_PAUSE_CONTRACT=='nct-update-pause-v1'; from app.schema_compatibility import begin_schema_migration; begin_schema_migration(Path('/data/analyzer.db')); print(json.dumps({'status':'pass'}))"])
        report = json.loads(result)
        if report.get("status") != "pass":
            raise ValueError("Replacement image did not accept the exact saved schema")
        save(self.root / state["id"] / ("schema-preview.json" if preview else "schema-preflight.json"), report)

    def replacement(self, state):
        original = state["original"]
        config = copy.deepcopy(original["Config"])
        config.pop("Hostname", None)
        config.pop("Domainname", None)
        config["Image"] = state["candidate_image_id"]
        config["Labels"] = {**(config.get("Labels") or {}), "org.nct.update-operation": state["id"]}
        config["Env"] = [item for item in config.get("Env", []) if not item.startswith(("NCT_BUILD_ID=", "NCT_BUILD_COMMIT=", "NCT_APP_VERSION="))]
        host = copy.deepcopy(original["HostConfig"])
        if host.get("AutoRemove") or host.get("NetworkMode", "").startswith("container:") or host.get("VolumesFrom"):
            raise ValueError("Shared-container or auto-remove deployment requires a qualified adapter")
        host["RestartPolicy"] = {"Name": "no", "MaximumRetryCount": 0}
        config["HostConfig"] = host
        return config

    def verify_health(self, state, original=False):
        expected = state["original_build"] if original else state["manifest"]
        value = self.wait_url(self.config["application_url"] + "/health",
            lambda value: value.get("status") == "ok" and value.get("build_id") == expected["build_id"]
            and value.get("build_commit") == expected["build_commit"])
        self.wait_url(self.config["application_url"] + "/health/readiness", lambda value: value.get("status") in {"ok", "ready"})
        state["running_build_id"], state["running_build_commit"] = value["build_id"], value["build_commit"]
        return value

    def verify_evidence(self, state, allowed_manifests=()):
        folder = self.root / state["id"]
        before = json.loads((folder / "before.json").read_text())
        after = self.helper(state["candidate_image_id"], "snapshot")
        for name, identity in before["files"].items():
            if after["files"].get(name) != identity:
                path = Path(name)
                if allowed_manifests and (name == "recovery/scan-work-paused.json" or path.name == "manifest.json" and any(part in allowed_manifests for part in path.parts)):
                    continue
                raise ValueError("A retained evidence file changed during the update")
        if after["artifact_registry"] != before["artifact_registry"]:
            raise ValueError("Registered evidence identities changed during the update")
        for table, count in before["database"]["tables"].items():
            if table in {"scan_history_index_dirty", "scan_history_groups", "scan_history_memberships"}:
                continue  # Disposable history index; retained scan_runs still checked.
            if after["database"]["tables"].get(table, -1) < count:
                raise ValueError("A saved record count decreased during the update")
        save(folder / "after.json", after)
        state["evidence_verified"] = True

    def apply(self, plan_digest, actor):
        with self.exclusive():
            state = self.read()
            if state["phase"] != "validated" or not secrets.compare_digest(state["plan_digest"], plan_digest):
                raise ValueError("Apply requires the current validated plan")
            current = self.target(expected_id=state["original"]["Id"])
            if any(current.get(key) != state["original"].get(key) for key in ("Image", "Config", "HostConfig", "Mounts")):
                raise ValueError("NCT configuration changed after validation; review a fresh plan")
            if not current["State"]["Running"]:
                raise ValueError("NCT stopped after validation; investigate before applying this update")
            if digest_file(self.root / state["id"] / "release" / "image.tar") != state["manifest"]["image_sha256"]:
                raise ValueError("Staged image changed after validation")
            self.replacement(state)  # Refuse unsupported deployments before stopping.
            state["actor"] = actor
            self.phase(state, "fence_intent", detail="Stopping the original writer before checking and backing up evidence.")
            lock = None
            try:
                self.stop_exact(state["original"])
                lock = self.writer_lock()
                self.checkpoint(state["original"]["Image"])
                self.helper(state["original"]["Image"], "active")
                self.compatibility(state)
                self.backup(state)
                self.phase(state, "backup_verified", detail="Cold backup was independently restored and matched. Replacing NCT.")
                self.phase(state, "replace_intent", candidate_may_have_written=True)
                self.hold_collection(state)
                rollback_name = "nct-rollback-" + state["id"]
                self.engine.command("rename", state["original"]["Id"], rollback_name)
                candidate = self.engine.create(self.config["container"], self.replacement(state))
                self.phase(state, "candidate_created", candidate_id=candidate)
                os.close(lock)
                lock = None
                self.engine.command("start", candidate)
                self.verify_health(state)
                self.stop_exact(self.engine.inspect(candidate))
                lock = self.writer_lock()
                self.checkpoint(state["candidate_image_id"])
                self.verify_evidence(state)
                os.close(lock)
                lock = None
                self.engine.command("start", candidate)
                self.verify_health(state)
                self.phase(state, "awaiting_sign_in", completion_kind="update", detail="Build, health and retained evidence passed. Verify an existing NCT account before finishing.")
            except Exception as exc:
                if lock is not None:
                    os.close(lock)
                    lock = None
                self.phase(state, "interrupted", detail=str(exc)[:400])
                try:
                    self.restore(state, actor)
                except Exception as restore_error:
                    self.phase(state, "interrupted", detail="Restore halted: " + str(restore_error)[:350])
            finally:
                if lock is not None:
                    os.close(lock)

    def restore(self, state, actor):
        original = self.engine.inspect(state["original"]["Id"])
        if original["Image"] != state["original"]["Image"]:
            raise ValueError("Original image identity changed; restore halted")
        current = self.engine.exists(self.config["container"])
        if current and current["Id"] != original["Id"]:
            if current["Config"].get("Labels", {}).get("org.nct.update-operation") != state["id"]:
                raise ValueError("An unrelated replacement occupies the NCT name; restore halted")
            self.stop_exact(current)
        self.stop_exact(original)
        self.target_by_original(state)
        lock = [self.writer_lock() if self.data.exists() else None]
        try:
            return self.restore_locked(state, actor, original, current, lock)
        finally:
            if lock[0] is not None:
                os.close(lock[0])

    def restore_locked(self, state, actor, original, current, lock):
        self.phase(state, "restore_intent", actor=actor, controller_sign_in_verified=False, evidence_verified=False, completion_kind="backup_restore",
            detail="Preserving candidate data and restoring the verified pre-update backup.")
        if state.get("candidate_may_have_written"):
            if not state.get("backup_verified"):
                raise ValueError("No verified pre-update backup; old image will remain stopped")
            before = json.loads((self.root / state["id"] / "before.json").read_text())
            if not state.get("swap"):
                if not self.data.is_dir() or self.data.is_symlink():
                    raise ValueError("Evidence folder disappeared without a journaled restore")
                restored = self.extract_backup(state, "restored")
                if self.helper(original["Image"], "snapshot", root=restored) != before:
                    raise ValueError("Restored inventory differs; old image will remain stopped")
                quarantine = self.data.parent / ("nct-preserved-" + state["id"])
                if quarantine.exists():
                    raise ValueError("Preservation folder already exists without a matching swap record")
                swap = {"restored_path": str(restored), "quarantine_path": str(quarantine),
                        "data_identity": file_identity(self.data), "restored_identity": file_identity(restored)}
                state.setdefault("preserved_paths", []).append(str(quarantine))
                self.phase(state, "restore_swap_intent", swap=swap, quarantine_path=str(quarantine))
            self.reconcile_swap(state, before)
        else:
            self.helper(original["Image"], "snapshot")
        if current and current["Id"] != original["Id"]:
            self.engine.command("rename", current["Id"], "nct-preserved-container-" + state["id"] + "-" + secrets.token_hex(4))
        if self.engine.inspect(original["Id"])["Name"].lstrip("/") != self.config["container"]:
            self.engine.command("rename", original["Id"], self.config["container"])
        # Release the old-directory writer guard before the original application
        # starts. The caller still holds the installation-wide maintenance lock.
        # The restored inode is guarded by the application's own startup lock.
        if lock[0] is not None:
            os.close(lock[0])
            lock[0] = None
        self.hold_collection(state)
        try:
            self.engine.command("start", original["Id"])
            self.verify_health(state, original=True)
        except Exception:
            self.stop_exact(original)
            raise ValueError("Restored NCT did not pass readiness; it remains stopped for review")
        self.engine.command("update", "--restart=" + restart_policy(state["original"]), original["Id"])
        self.phase(state, "awaiting_restore_sign_in", evidence_verified=True,
            detail="Original NCT is running at the backup time. Preserved post-backup data remains separate. Verify an existing account against this restored version before finishing.")

    def reconcile_swap(self, state, before):
        swap = state["swap"]
        restored, quarantine = Path(swap["restored_path"]), Path(swap["quarantine_path"])
        if restored != self.data.parent / ("nct-restored-" + state["id"]) or quarantine != self.data.parent / ("nct-preserved-" + state["id"]):
            raise ValueError("Saved restore paths do not belong to this exact operation")
        data_id = file_identity(self.data) if self.data.exists() else None
        restored_id = file_identity(restored) if restored.exists() else None
        quarantine_id = file_identity(quarantine) if quarantine.exists() else None
        old_id, new_id = swap["data_identity"], swap["restored_identity"]
        if (data_id, restored_id, quarantine_id) == (old_id, new_id, None):
            os.rename(self.data, quarantine)
            sync_directory(self.data.parent)
            data_id, quarantine_id = None, old_id
        if (data_id, restored_id, quarantine_id) == (None, new_id, old_id):
            os.rename(restored, self.data)
            sync_directory(self.data.parent)
            data_id, restored_id = new_id, None
        if (data_id, restored_id, quarantine_id) != (new_id, None, old_id):
            raise ValueError("Saved restore folder identities do not match the actual swap state")
        if self.helper(state["original"]["Image"], "snapshot") != before:
            raise ValueError("Restored evidence changed after the recorded swap; old image remains stopped")
        self.phase(state, "restore_data_verified")

    def target_by_original(self, state):
        # Reuse the same shared-writer checks after rename without guessing a new ID.
        return self.target(expected_id=state["original"]["Id"], name=state["original"]["Id"])

    def rollback(self, actor):
        with self.exclusive():
            state = self.read()
            if state["phase"] not in {"awaiting_sign_in", "awaiting_restore_sign_in", "awaiting_repair_sign_in", "complete", "interrupted", "failed", "repair_review"} or "original" not in state:
                raise ValueError("There is no retained update plan to restore")
            try:
                self.restore(state, actor)
            except Exception as exc:
                self.phase(state, "interrupted", detail="Restore halted: " + str(exc)[:350])
                raise

    def confirm(self, username, password, actor):
        with self.exclusive():
            state = self.read()
            phase = state["phase"]
            if phase not in {"awaiting_sign_in", "awaiting_restore_sign_in", "awaiting_repair_sign_in"}:
                raise ValueError("This update is not awaiting sign-in verification")
            original = phase != "awaiting_sign_in"
            runtime_id = state["original"]["Id"] if original else state["candidate_id"]
            self.target(expected_id=runtime_id)
            self.verify_health(state, original=original)
            # Authenticate against the actual replacement HTTP service. Password is
            # used only for this request and is never written to the recovery journal.
            context = ssl.create_default_context(cafile=self.config.get("ca_file"))
            request = urllib.request.Request(self.config["application_url"] + "/api/auth/login",
                data=canonical({"username": username, "password": password}), headers={"Content-Type": "application/json"})
            cookies = http.cookiejar.CookieJar()
            opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context), urllib.request.HTTPCookieProcessor(cookies), urllib.request.ProxyHandler({}))
            with opener.open(request, timeout=15) as response:
                result = json.load(response)
                if response.status != 200 or result.get("authenticated") is not True or not any(cookie.name == "nct_session" for cookie in cookies):
                    raise ValueError("Existing account sign-in was not verified")
            with opener.open(self.config["application_url"] + "/api/auth/me", timeout=15) as response:
                identity = json.load(response)
                if identity.get("analyst", {}).get("username") != username:
                    raise ValueError("Replacement did not accept the authenticated session")
            self.engine.command("update", "--restart=" + restart_policy(state["original"]), runtime_id)
            self.phase(state, "release_intent", controller_sign_in_verified=True, actor=actor,
                verified_runtime_id=runtime_id, verified_result_phase="restored" if original else "complete")
            self.finalize(state)
            return {"url": self.config["application_url"], "operation": self.public()}

    def lifecycle(self, action, actor):
        with self.exclusive():
            if self.read()["phase"] not in {"idle", "validated", "complete", "restored", "failed"}:
                raise ValueError("Resolve the interrupted update before controlling NCT")
            target = self.target()
            if action == "start":
                self.engine.command("start", target["Id"])
            else:
                if action not in {"stop", "restart"}:
                    raise ValueError("Unsupported recovery action")
                self.stop_exact(target)
                if action == "restart":
                    self.engine.command("start", target["Id"])
                self.engine.command("update", "--restart=" + restart_policy(target), target["Id"])
            receipt = {"action": action, "actor": actor, "container_id": target["Id"], "at": time.time()}
            save(self.root / ("control-" + secrets.token_hex(12) + ".json"), receipt)
            return receipt

    def verify_backup(self):
        with self.exclusive():
            state = self.read()
            if not state.get("backup_verified"):
                raise ValueError("No completed cold backup has been recorded")
            restored = self.extract_backup(state, "verification")
            before = json.loads((self.root / state["id"] / "before.json").read_text())
            if self.helper(state["original"]["Image"], "snapshot", root=restored) != before:
                raise ValueError("Backup restore inventory did not match")
            self.remove_verification_copy(restored)
            return {"verified": True, "backup_time": state["id"], "detail": "Cold backup checksum and restored evidence match."}

    def work_tool(self, state, mode, *arguments):
        tool = str(Path(__file__).with_name("nct_update_work.py").resolve())
        # SQLite can need WAL/SHM housekeeping even for a read-only connection.
        # Preview on a verified backup-derived copy, never a writable live mount.
        root = self.extract_backup(state, "work-verification") if mode == "preview" else self.data
        mount = f"type=bind,src={root},dst=/data"
        result = self.run_helper(state["original"]["Image"], ["--mount", mount,
            "--mount", f"type=bind,src={tool},dst=/nct-work.py,readonly"], ["/nct-work.py", mode, *arguments])
        value = json.loads(result)
        if mode == "preview":
            self.remove_verification_copy(root)
        return value

    def prepare_repair(self, actor):
        with self.exclusive():
            if self.read()["phase"] not in {"idle", "validated", "complete", "restored", "failed"}:
                raise ValueError("Resolve the current recovery before preparing an unfinished-work repair")
            original = self.target()
            env = dict(item.split("=", 1) for item in original["Config"].get("Env", []) if "=" in item)
            operation_id = secrets.token_hex(16)
            (self.root / operation_id).mkdir(mode=0o700)
            state = {"id": operation_id, "kind": "repair", "actor": actor, "original": original,
                "candidate_image_id": original["Image"], "original_build": {"build_id": env.get("NCT_BUILD_ID"), "build_commit": env.get("NCT_BUILD_COMMIT")}}
            self.phase(state, "fence_intent", detail="Stopping NCT and creating a verified backup before reviewing unfinished work.")
            lock = None
            try:
                self.stop_exact(original)
                lock = self.writer_lock()
                self.checkpoint(original["Image"])
                self.backup(state)
                plan = self.work_tool(state, "preview")
                save(self.root / operation_id / "work-plan.json", plan)
                summary = {"safe_to_apply": plan["safe_to_apply"], "affected_count": plan["affected_count"], "blockers": plan.get("blockers", []),
                    "preserved_scan_queue": sum(item.get("action") == "preserve_queue" for item in plan.get("scans", []))}
                summary["categories"] = [
                    {"category": key, "actions": [
                        {"action": item.get("action", "review"), "record": str(item.get("run_id") or item.get("occurrence_id") or item.get("schedule_id") or item.get("attempt_id") or item.get("lease_key") or "saved work")[:100]}
                        for item in plan.get(key, [])[:100]]}
                    for key in ("scans", "schedules", "schedule_occurrences", "schedule_chunks", "arkime_pulls", "device_contacts", "pipeline_attempts", "storage_maintenance") if plan.get(key)]
                self.phase(state, "repair_review", plan_digest=plan["plan_digest"], repair_summary=summary,
                    detail="Review the proposed unfinished-work repair. NCT remains stopped. Completed evidence and valid waiting scans are preserved; repaired collection stays paused for review.")
            except Exception as exc:
                self.phase(state, "interrupted", detail="Work check halted: " + str(exc)[:350])
                raise
            finally:
                if lock is not None:
                    os.close(lock)

    def apply_repair(self, plan_digest, actor):
        with self.exclusive():
            state = self.read()
            if state["phase"] != "repair_review" or state.get("plan_digest") != plan_digest or not state["repair_summary"]["safe_to_apply"]:
                raise ValueError("Repair requires the current safe, reviewed plan")
            original = self.target(expected_id=state["original"]["Id"])
            if original["State"]["Running"]:
                raise ValueError("The reviewed application is no longer stopped")
            if digest_file(self.root / state["id"] / "backup.tar.gz") != state["backup_sha256"]:
                raise ValueError("Repair backup checksum no longer matches")
            lock = self.writer_lock()
            self.phase(state, "repair_intent", actor=actor, candidate_may_have_written=True)
            try:
                result = self.work_tool(state, "apply", "--plan-digest", plan_digest, "--actor", actor,
                    "--backup-path", state["backup_path"], "--backup-sha256", state["backup_sha256"])
                save(self.root / state["id"] / "work-result.json", result)
                self.checkpoint(original["Image"])
                plan = json.loads((self.root / state["id"] / "work-plan.json").read_text())
                allowed = {item["run_id"] for item in plan.get("scans", []) if item.get("action") != "preserve_queue"}
                self.verify_evidence(state, allowed_manifests=allowed | {"__repair__"})
                self.phase(state, "repair_verified", detail="Repair and retained evidence verified. Restarting NCT with recovery gates preserved.")
            except Exception as exc:
                self.phase(state, "interrupted", detail="Repair halted; NCT remains stopped: " + str(exc)[:300])
                raise
            finally:
                os.close(lock)
            try:
                self.hold_collection(state)
                self.engine.command("start", original["Id"])
                self.verify_health(state, original=True)
            except Exception:
                self.stop_exact(original)
                self.phase(state, "interrupted", detail="Repaired NCT did not pass readiness and remains stopped.")
                raise
            self.engine.command("update", "--restart=" + restart_policy(state["original"]), original["Id"])
            self.phase(state, "awaiting_repair_sign_in", controller_sign_in_verified=False, completion_kind="work_repair",
                detail="Repair and retained evidence passed. Verify an existing account, then review recovery gates in NCT before resuming collection.")

    def cancel_repair(self, actor):
        with self.exclusive():
            state = self.read()
            if state["phase"] != "repair_review":
                raise ValueError("No stopped unfinished-work preview is awaiting a decision")
            original = self.target(expected_id=state["original"]["Id"])
            self.phase(state, "repair_cancel_intent", actor=actor)
            try:
                self.engine.command("start", original["Id"])
                self.verify_health(state, original=True)
                self.engine.command("update", "--restart=" + restart_policy(state["original"]), original["Id"])
                self.phase(state, "restored", completion_kind="preview_cancel", detail="Unfinished-work preview closed without repair. NCT resumed its previous queue and automation settings.")
            except Exception:
                self.stop_exact(original)
                self.phase(state, "interrupted", detail="NCT did not pass readiness and remains stopped.")
                raise


class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


class Handler(BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.request.settimeout(60)
    def log_message(self, *_):
        pass  # No tokens, request bodies, raw container output or passwords in logs.

    def reply(self, status, value):
        body = canonical(value)
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def json_body(self):
        length = int(self.headers.get("Content-Length", "0"))
        if not 0 < length <= 32768:
            raise ValueError("Invalid management request size")
        return json.loads(self.rfile.read(length))

    def handle_request(self):
        host = self.server.host
        if self.server.launch_only:
            if self.command != "POST" or self.path != "/launch":
                raise PermissionError("Application socket supports only console launch")
            body = self.json_body()
            actor = body.get("actor", "")
            if not re.fullmatch("[a-z0-9][a-z0-9._-]{1,63}", actor):
                raise ValueError("Signed-in operator identity is required")
            allowed = host.config.get("allowed_operators", "all")
            if allowed != "all" and actor not in allowed:
                raise PermissionError("Deployment policy restricts recovery access")
            return host.launch(actor)
        if self.path == "/ready" and self.command == "GET":
            return {"contract": CONTRACT, "status": "ready"}
        if self.path == "/exchange" and self.command == "POST":
            actor = host.identity(self.json_body().get("code", ""), "handoff", consume=True)
            return {"token": host.token(actor, "session", 3600), "actor": actor}
        actor = host.identity(self.headers.get("Authorization", "").removeprefix("Bearer "))
        host.last_access = time.monotonic()
        if self.command == "GET" and self.path == "/status":
            return {"operation": host.public(), "application_url": host.config["application_url"], "actor": actor,
                "upload_available_bytes": max(0, min(MAX_UPLOAD, shutil.disk_usage(host.root).free - 2 * 1024**3))}
        if self.command == "GET" and self.path == "/diagnose":
            return host.diagnose()
        if self.command == "POST" and self.path == "/upload":
            return host.stage(self.rfile, int(self.headers.get("Content-Length", "0")), actor)
        if self.command == "POST" and self.path in {"/apply", "/rollback", "/prepare-repair", "/apply-repair", "/cancel-repair"}:
            body = self.json_body()
            if self.path == "/apply":
                state = host.read()
                if state.get("plan_digest") != body.get("plan_digest"):
                    raise ValueError("The displayed plan is no longer current")
                if state["phase"] != "validated":
                    return host.public()  # Duplicate requests never start a second update.
                work = lambda: host.apply(body["plan_digest"], actor)
            elif self.path == "/rollback":
                if body.get("confirm") != "RESTORE":
                    raise ValueError("Confirm restore to the saved backup time")
                work = lambda: host.rollback(actor)
            elif self.path == "/prepare-repair":
                work = lambda: host.prepare_repair(actor)
            elif self.path == "/apply-repair":
                work = lambda: host.apply_repair(body.get("plan_digest"), actor)
            else:
                if body.get("confirm") != "RESUME":
                    raise ValueError("Confirm that existing queues and automation may resume")
                work = lambda: host.cancel_repair(actor)
            if not host.worker_guard.acquire(blocking=False):
                return {"accepted": True, "operation": host.public()}
            if host.mutex.locked():
                host.worker_guard.release()
                raise ValueError("Another maintenance operation is running")
            def background():
                try:
                    work()
                except Exception as exc:
                    # A rejected action never edits another action's live journal.
                    save(host.root / ("rejected-" + secrets.token_hex(12) + ".json"),
                         {"actor": actor, "detail": str(exc)[:400], "at": time.time()})
                finally:
                    host.worker_guard.release()
            threading.Thread(target=background, daemon=True).start()
            return {"accepted": True}
        if self.command == "POST" and self.path == "/verify-sign-in":
            body = self.json_body()
            return host.confirm(body.get("username", ""), body.get("password", ""), actor)
        if self.command == "POST" and self.path == "/verify-backup":
            return host.verify_backup()
        if self.command == "POST" and self.path in {"/start", "/stop", "/restart"}:
            self.json_body()
            return host.lifecycle(self.path[1:], actor)
        if self.command == "POST" and self.path == "/close":
            if host.read()["phase"] not in {"idle", "validated", "complete", "restored", "failed"}:
                raise ValueError("Keep the console open until recovery is resolved")
            def close():
                time.sleep(3)
                if not host.mutex.locked() and not host.worker_guard.locked() and host.read()["phase"] in {"idle", "validated", "complete", "restored", "failed"}:
                    host.engine.command("stop", host.config["console_container"])
            threading.Thread(target=close, daemon=True).start()
            return {"url": host.config["application_url"]}
        raise ValueError("Unsupported management operation")

    def dispatch(self):
        try:
            self.reply(200, self.handle_request())
        except PermissionError as exc:
            self.reply(403, {"detail": str(exc)})
        except (ValueError, OSError, subprocess.SubprocessError, sqlite3.Error) as exc:
            self.reply(409, {"detail": str(exc)[:400]})
        except Exception:
            self.reply(409, {"detail": "The recovery request was invalid or could not be verified"})

    do_GET = dispatch
    do_POST = dispatch


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--access-code", action="store_true", help="Print a short-lived, one-use host recovery code")
    args = parser.parse_args()
    os.umask(0o077)
    config = json.loads(args.config.read_text())
    service_lock = None
    if not args.access_code:
        state_root = Path(config["state_dir"])
        state_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        service_lock = os.open(state_root / "service.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        fcntl.flock(service_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    host = Host(config, reconcile=not args.access_code)
    if args.access_code:
        host.launch("host-recovery")
        print("Recovery URL: " + config["console_url"])
        print("One-use recovery code (expires in 2 minutes): " + host.token("host-recovery"))
        return
    servers = []
    for key, launch_only in (("launch_socket", True), ("control_socket", False)):
        path = Path(config[key])
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if path.exists():
            if not stat.S_ISSOCK(path.lstat().st_mode):
                raise ValueError("Management socket path is not a socket")
            path.unlink()
        server = Server(str(path), Handler)
        server.host, server.launch_only = host, launch_only
        os.chmod(path, 0o600)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        servers.append(server)
    while True:
        time.sleep(15)
        try:
            target = host.target()
            state = host.read()["phase"]
            unhealthy = target["State"]["Status"] == "restarting" or target["State"].get("Health", {}).get("Status") == "unhealthy" or target["State"]["Status"] == "exited" and target["State"].get("ExitCode", 0) != 0
            if (unhealthy or state == "interrupted") and state in {"idle", "complete", "restored", "interrupted", "awaiting_sign_in", "awaiting_restore_sign_in", "awaiting_repair_sign_in"}:
                # GUI is available, but independent host-issued authentication remains
                # mandatory when the application cannot provide a signed-in handoff.
                console = host.engine.inspect(config["console_container"])
                if console["Image"] != config["console_image_id"]:
                    raise ValueError("Recovery console identity changed")
                if not console["State"]["Running"]:
                    host.engine.command("start", config["console_container"])
            elif state in {"idle", "validated", "complete", "restored", "failed"} and time.monotonic() - host.last_access > 900 and not host.mutex.locked() and not host.worker_guard.locked():
                console = host.engine.inspect(config["console_container"])
                if console["State"]["Running"]:
                    host.engine.command("stop", config["console_container"])
        except (ValueError, OSError, subprocess.SubprocessError):
            pass


if __name__ == "__main__":
    main()
