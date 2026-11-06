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
COMPATIBLE_RECOVERY_CONTRACT = "nct-compatible-recovery-v1"
MAX_UPLOAD = 12 * 1024**3
MAX_IMAGE = 30 * 1024**3
TERMINAL = {"complete", "restored", "failed", "interrupted"}
COMPATIBLE_RECOVERY_PHASES = {
    "awaiting_compatible_recovery",
    "compatible_recovery_create_intent",
    "compatible_recovery_created",
    "compatible_recovery_start_intent",
}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def verify_fresh_empty(*args, **kwargs):
    path = Path(__file__).with_name("nct_fresh_handoff.py")
    spec = importlib.util.spec_from_file_location("nct_fresh_handoff", path)
    if spec is None or spec.loader is None:
        raise ValueError("The installed fresh-handoff verifier is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.verify_empty(*args, **kwargs)


def runtime_snapshot(value):
    return {
        "container_id": value["Id"], "image_id": value["Image"],
        "path": value.get("Path"), "args": list(value.get("Args") or []),
        "config": value.get("Config") or {},
        "host_config": value.get("HostConfig") or {},
        "mounts": sorted(
            list(value.get("Mounts") or []),
            key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":")),
        ),
    }


def runtime_create_semantics(value):
    """Reconstruct the complete create-time contract from Docker inspection."""
    inspected = "Id" in value and isinstance(value.get("Config"), dict)
    config = copy.deepcopy(value.get("Config") if inspected else value)
    # Docker assigns these two values even when the create request deliberately
    # omitted them. They are runtime identity, not caller-controlled behavior.
    config.pop("Hostname", None)
    config.pop("Domainname", None)
    # The in-memory test adapter retains HostConfig inside Config while the real
    # Docker API stores it separately. Normalize both forms to the API request.
    embedded_host = config.pop("HostConfig", None)
    host = copy.deepcopy(
        value.get("HostConfig") if inspected else embedded_host or {}
    )
    # Docker represents the unset OOM-kill flag as false after create.  Record
    # that exact semantic value in both the protected request and observation.
    host["OomKillDisable"] = bool(host.get("OomKillDisable"))
    config["HostConfig"] = host
    return config


def expected_network_name(config):
    mode = str((config.get("HostConfig") or {}).get("NetworkMode") or "default")
    return "bridge" if mode == "default" else mode


def validate_runtime_network(value, config):
    """Refuse a same-label container attached to an unapproved network."""
    network_settings = value.get("NetworkSettings")
    if not isinstance(network_settings, dict):
        raise ValueError("Compatible recovery runtime network identity is unavailable")
    networks = network_settings.get("Networks")
    if not isinstance(networks, dict) or set(networks) != {expected_network_name(config)}:
        raise ValueError("Compatible recovery runtime network identity changed")


def expected_bind_mounts(config):
    host = config.get("HostConfig") or {}
    expected = []
    for binding in host.get("Binds") or []:
        parts = binding.rsplit(":", 2)
        if len(parts) < 2:
            raise ValueError("Compatible recovery bind contract is invalid")
        source, destination = parts[0], parts[1]
        mode = parts[2] if len(parts) == 3 else "rw"
        expected.append({
            "destination": destination,
            "type": "bind",
            "source": str(Path(source).resolve()),
            "rw": "ro" not in mode.split(","),
        })
    for mount in host.get("Mounts") or []:
        if mount.get("Type") != "bind":
            raise ValueError("Compatible recovery supports exact bind mounts only")
        expected.append({
            "destination": mount.get("Target"),
            "type": "bind",
            "source": str(Path(mount.get("Source", "")).resolve()),
            "rw": not bool(mount.get("ReadOnly")),
        })
    if set((config.get("Volumes") or {})) - {
        item["destination"] for item in expected
    }:
        raise ValueError("Compatible recovery refuses implicit evidence volumes")
    return sorted(expected, key=lambda item: canonical(item))


def validate_runtime_mounts(value, config):
    observed = []
    for mount in value.get("Mounts") or []:
        if mount.get("Type") != "bind":
            raise ValueError("Compatible recovery runtime mount type changed")
        observed.append({
            "destination": mount.get("Destination"),
            "type": "bind",
            "source": str(Path(mount.get("Source", "")).resolve()),
            "rw": bool(mount.get("RW")),
        })
    if sorted(observed, key=lambda item: canonical(item)) != expected_bind_mounts(config):
        raise ValueError("Compatible recovery runtime mount contract changed")


def protected_root_file(path, trusted_root, label):
    path = Path(path).absolute()
    trusted_root = Path(trusted_root).absolute()
    try:
        relative = path.relative_to(trusted_root)
    except ValueError as exc:
        raise ValueError(label + " is outside its protected root") from exc
    current = trusted_root
    for part in (Path("."), *relative.parts):
        if part != Path("."):
            current = current / part
        details = current.lstat()
        if stat.S_ISLNK(details.st_mode) or details.st_uid != 0 or details.st_mode & 0o022:
            raise ValueError(label + " is not root-owned and protected")
        if current == path:
            if not stat.S_ISREG(details.st_mode):
                raise ValueError(label + " is not a regular file")
        elif not stat.S_ISDIR(details.st_mode):
            raise ValueError(label + " has an unsafe parent path")
    return path


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


def run(args, *, timeout=120, input_file=None, max_output_bytes=8 * 1024**2):
    if not 0 < max_output_bytes <= 64 * 1024**2:
        raise ValueError("Invalid bounded host output limit")
    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
        process = subprocess.Popen(args, stdin=input_file, stdout=output, stderr=errors)
        deadline = time.monotonic() + timeout
        try:
            while process.poll() is None:
                if time.monotonic() > deadline or os.fstat(output.fileno()).st_size + os.fstat(errors.fileno()).st_size > max_output_bytes:
                    raise ValueError("Host operation exceeded its time or output limit")
                time.sleep(.05)
            if process.returncode:
                raise ValueError("Trusted host operation failed: " + args[0] + " " + args[1])
            if os.fstat(output.fileno()).st_size + os.fstat(errors.fileno()).st_size > max_output_bytes:
                raise ValueError("Host operation output exceeds its limit")
            output.seek(0)
            return output.read(max_output_bytes).decode()
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

    def command(self, *args, max_output_bytes=8 * 1024**2):
        return run(["docker", *args], timeout=180, max_output_bytes=max_output_bytes)

    def create(self, name, config):
        result = self.api("POST", "/containers/create?name=" + urllib.parse.quote(name), config)
        return result["Id"]

    def inventory(self):
        return self.api("GET", "/containers/json?all=true")

    def observe(self, name):
        return self.api("GET", "/containers/" + urllib.parse.quote(name, safe="") + "/json", timeout=3)

    def api(self, method, path, body=None, *, timeout=60):
        connection = http.client.HTTPConnection("localhost", timeout=timeout)
        connection.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.sock.settimeout(timeout)
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
        self.retirement_guard = Path(
            config.get("retirement_guard_dir", self.root.parent / "retirement-guard")
        ).absolute()
        if (
            not self.retirement_guard.is_absolute()
            or self.retirement_guard == self.data
            or self.retirement_guard in self.data.parents
            or self.data in self.retirement_guard.parents
        ):
            raise ValueError("Retirement guard storage must be outside evidence data")
        self.retirement_data_identity = "bind:" + str(self.data.resolve())
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
            elif (
                state.get("phase") not in TERMINAL
                and state.get("phase") not in {
                    "awaiting_sign_in", "awaiting_restore_sign_in",
                    "awaiting_repair_sign_in", *COMPATIBLE_RECOVERY_PHASES,
                }
            ):
                self.phase(state, "interrupted", detail="Host service restarted. Review the saved operation and recovery diagnostics before continuing.")
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
        if state.get("activity"):
            state["activity"] = {**state["activity"], "active": False}
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

    def activity(self, state, step, label, *, completed=None, total=None, unit=None, force=False):
        """Bounded display checkpoint under the operation lock, never a work authority."""
        now = time.time()
        previous = state.get("activity", {})
        fresh = previous.get("step") != step or not previous.get("active")
        value = {"step": step, "label": label, "started_at": now if fresh else previous["started_at"],
                 "updated_at": now, "active": True}
        if completed is not None:
            if type(completed) is not int or completed < 0 or type(total) is not int or total < completed or unit not in {"bytes", "files"}:
                raise ValueError("Invalid measured activity")
            value.update(completed=completed, total=total, unit=unit)
        # A single writer owns these calls; do not let an obsolete checkpoint
        # overwrite a newer operation/phase after interruption or finalization.
        if not fresh and not force and 0 <= now - previous["updated_at"] < 2:
            return
        saved = self.read()
        if (saved.get("id"), saved.get("phase")) != (state.get("id"), state.get("phase")):
            raise ValueError("Activity no longer belongs to the current operation")
        state["activity"] = value
        save(self.current, state)
        # No event per file and no growing per-artifact progress history.

    @contextlib.contextmanager
    def activity_scope(self):
        """End display activity on return/error while still holding the work lock."""
        operation = self.read().get("id")
        try:
            yield
        finally:
            state = self.read()
            if state.get("id") == operation and state.get("activity", {}).get("active"):
                state["activity"]["active"] = False
                save(self.current, state)

    def measured_digest(self, path, state, step, label):
        total, completed = path.stat().st_size, 0
        digest = hashlib.sha256()
        self.activity(state, step, label, completed=0, total=total, unit="bytes", force=True)
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024**2), b""):
                digest.update(block)
                completed += len(block)
                self.activity(state, step, label, completed=completed, total=total, unit="bytes")
        self.activity(state, step, label, completed=completed, total=total, unit="bytes", force=True)
        return digest.hexdigest()

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
        inspected = json.loads(self.engine.command("image", "inspect", image))
        image = inspected[0]["Id"]
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", image):
            raise ValueError("Maintenance helper requires an immutable local image")
        readonly, mounts = False, []
        iterator = iter(options)
        for option in iterator:
            if option == "--read-only":
                readonly = True
            elif option == "--mount":
                value = next(iterator, None)
                if not isinstance(value, str):
                    raise ValueError("Incomplete maintenance mount")
                fields = {}
                for item in value.split(","):
                    key, separator, setting = item.partition("=")
                    if key in fields or key not in {"type", "src", "dst", "readonly"} or (key != "readonly" and not separator):
                        raise ValueError("Unsupported maintenance mount")
                    fields[key] = setting if separator else True
                if fields.get("type") != "bind" or not all(isinstance(fields.get(k), str) and Path(fields[k]).is_absolute() for k in ("src", "dst")) or fields.get("readonly", True) is not True:
                    raise ValueError("Maintenance mounts require explicit absolute bind paths")
                mounts.append({"Type": "bind", "Source": fields["src"], "Target": fields["dst"], "ReadOnly": "readonly" in fields})
            else:
                raise ValueError("Unsupported maintenance helper option")
        name = "nct-maintenance-helper-" + secrets.token_hex(12)
        receipt = self.root / (name + ".json")
        save(receipt, {"name": name, "image": image, "phase": "create_intent"})
        try:
            # Engine create never pulls an image. This also supports older CLIs
            # without --pull=never while preserving the offline guarantee.
            identity = self.engine.create(name, {"Image": image, "Entrypoint": ["python"], "Cmd": command,
                "Env": ["PYTHONPATH=/app"], "AttachStdout": True, "AttachStderr": True,
                "Tty": False, "HostConfig": {"NetworkMode": "none", "ReadonlyRootfs": readonly,
                    "Mounts": mounts, "RestartPolicy": {"Name": "no"},
                    # Schema compatibility checks use Python's temporary-file
                    # support. Keep the image read-only while providing a
                    # bounded, non-persistent workspace for those checks.
                    "Tmpfs": {"/tmp": "rw,noexec,nosuid,nodev,size=64m,mode=1777"}}})
            helper = self.engine.inspect(identity)
            if helper["Image"] != image or helper["State"]["Running"]:
                raise ValueError("Created maintenance helper identity/state mismatch")
            output = self.engine.command("start", "--attach", identity, max_output_bytes=64 * 1024**2)
            completed = self.engine.inspect(identity)
            if completed["State"]["Running"] or completed["State"].get("ExitCode") != 0:
                raise ValueError("Maintenance helper did not complete successfully")
            return output
        finally:
            helper = self.engine.exists(name)
            if helper:
                if helper["Image"] != image:
                    raise ValueError("Helper identity mismatch; maintenance halted")
                fence_error = None
                try:
                    self.engine.command("update", "--restart=no", helper["Id"])
                except ValueError as error:
                    fence_error = error
                self.engine.command("stop", helper["Id"])
                if self.engine.inspect(helper["Id"])["State"]["Running"]:
                    raise ValueError("Maintenance helper did not stop; writer handoff refused")
                if fence_error is not None:
                    raise ValueError("Maintenance helper stopped but restart-policy verification failed; handoff refused") from fence_error
                self.engine.command("rm", helper["Id"])
            save(receipt, {"name": name, "image": image, "phase": "stopped"})

    def ensure_retirement_guard_storage(self):
        protected_root = self.root.parent.absolute()
        if self.retirement_guard.parent != protected_root:
            raise ValueError(
                "Retirement guard storage must be a direct child of the recovery root"
            )
        root_info = protected_root.lstat()
        if (
            stat.S_ISLNK(root_info.st_mode)
            or not stat.S_ISDIR(root_info.st_mode)
            or root_info.st_uid != os.geteuid()
            or root_info.st_mode & 0o022
            or protected_root.resolve(strict=True) != protected_root
        ):
            raise ValueError("Recovery root is not owner-protected storage")
        data_path = self.data.resolve(strict=True)
        guard_path = self.retirement_guard.resolve(strict=False)
        if (
            guard_path == data_path
            or guard_path in data_path.parents
            or data_path in guard_path.parents
        ):
            raise ValueError("Retirement guard storage must remain outside evidence data")
        created = False
        try:
            os.mkdir(self.retirement_guard, mode=0o700)
            created = True
        except FileExistsError:
            pass
        guard_info = self.retirement_guard.lstat()
        if (
            stat.S_ISLNK(guard_info.st_mode)
            or not stat.S_ISDIR(guard_info.st_mode)
            or guard_info.st_uid != os.geteuid()
        ):
            raise ValueError("Retirement guard storage is not an owned directory")
        if created and stat.S_IMODE(guard_info.st_mode) != 0o700:
            os.chmod(self.retirement_guard, 0o700)
            guard_info = self.retirement_guard.lstat()
        if stat.S_IMODE(guard_info.st_mode) != 0o700:
            raise ValueError("Existing retirement guard storage is not private")
        if self.retirement_guard.resolve(strict=True) != self.retirement_guard:
            raise ValueError("Retirement guard storage may not use linked paths")

    def retirement_helper(self, image, command, *, include_data=False, data_readonly=False):
        self.ensure_retirement_guard_storage()
        options = ["--read-only", "--mount", (
            f"type=bind,src={self.retirement_guard},dst=/retirement-guard"
        )]
        if include_data:
            suffix = ",readonly" if data_readonly else ""
            options += [
                "--mount", f"type=bind,src={self.data},dst=/data{suffix}",
            ]
        return self.run_helper(image, options, command)

    def provision_retirement_guard(self, image):
        """Provision only independent host authority; never open live evidence."""
        self.ensure_retirement_guard_storage()
        provisioning = self.retirement_guard / "provisioning.json"
        if not provisioning.exists():
            if any(self.retirement_guard.iterdir()):
                raise ValueError("Unrecognized retirement guard state blocks update")
            self.retirement_helper(
                image,
                [
                    "-m", "app.retirement_guard_cli", "provision",
                    "--guard-dir", "/retirement-guard",
                    "--installation-id", self.config["container"],
                    "--data-identity", self.retirement_data_identity,
                ],
            )
        return json.loads(provisioning.read_text(encoding="utf-8"))

    def migrate_restored_retirement_schema(self, image):
        """Apply the candidate's exact migration after a verified backup swap."""
        self.retirement_helper(
            image,
            [
                "-c",
                "from pathlib import Path; "
                "from app.schema_compatibility import begin_schema_migration,complete_schema_migration; "
                "p=Path('/data/analyzer.db'); a=begin_schema_migration(p); "
                "complete_schema_migration(p,a)",
            ],
            include_data=True,
        )

    def check_retirement_guard(self, image):
        status = self.retirement_helper(
            image,
            [
                "-m", "app.retirement_guard_cli", "check",
                "--db", "/data/analyzer.db", "--data-dir", "/data",
                "--guard-dir", "/retirement-guard",
                "--data-identity", self.retirement_data_identity,
            ],
            include_data=True,
        )
        return json.loads(status)

    def mark_retirement_restore_hold(self, image, operation_id):
        return json.loads(self.retirement_helper(
            image,
            [
                "-m", "app.retirement_guard_cli", "mark-restore-hold",
                "--guard-dir", "/retirement-guard",
                "--data-identity", self.retirement_data_identity,
                "--operation-id", operation_id,
                "--detail", "before replacing live evidence with a verified backup",
            ],
        ))

    def reconcile_retirement_restore(self, image, operation_id):
        self.migrate_restored_retirement_schema(image)
        status = json.loads(self.retirement_helper(
            image,
            [
                "-m", "app.retirement_guard_cli", "reconcile-restore",
                "--db", "/data/analyzer.db", "--data-dir", "/data",
                "--guard-dir", "/retirement-guard",
                "--data-identity", self.retirement_data_identity,
                "--operation-id", operation_id,
            ],
            include_data=True,
        ))
        if status.get("state") != "ready":
            raise ValueError("Restored retirement authority did not become ready")
        return status

    def runtime_supports_retirement_guard(self, target):
        env = dict(
            item.split("=", 1) for item in target["Config"].get("Env", [])
            if "=" in item
        )
        mounted = any(
            item.get("Type") == "bind"
            and Path(str(item.get("Source") or "")).resolve()
            == self.retirement_guard.resolve()
            and
            item.get("Destination") == "/run/nct-retirement-guard"
            and item.get("RW") is True
            for item in target.get("Mounts", [])
        )
        return (
            env.get("NCT_RETIREMENT_GUARD_MODE") == "required"
            and env.get("NCT_RETIREMENT_GUARD_DIR") == "/run/nct-retirement-guard"
            and env.get("NCT_RETIREMENT_DATA_IDENTITY") == self.retirement_data_identity
            and mounted
        )

    def diagnose(self):
        target = self.target()
        return {"container_id": target["Id"], "image_config_id": target["Image"],
                "state": target["State"]["Status"], "health": target["State"].get("Health", {}).get("Status", "not configured"),
                "free_bytes": shutil.disk_usage(self.data).free, "operation": self.public()}

    def public(self):
        state = self.read()
        allowed = {"id", "phase", "detail", "actor", "build_id", "build_commit", "running_build_id", "running_build_commit", "updated_at", "plan_digest", "package_sha256", "controller_sign_in_verified", "evidence_verified", "backup_verified", "backup_at", "quarantine_path", "backup_path", "preserved_paths", "repair_summary", "kind", "completion_kind", "activity", "recovery_outcome", "verification_mode", "apply_failure", "compatible_recovery"}
        value = {k: v for k, v in state.items() if k in allowed}
        marker = state.get("candidate_may_have_written")
        value["recovery_guidance"] = "backup_restore" if marker is True else "original_reconciliation" if marker is False else "unknown"
        value["installed_build_id"] = state.get("original_build", {}).get("build_id")
        return value

    def runtime_status(self):
        observed = time.time()
        try:
            inspect = getattr(self.engine, "observe", self.engine.inspect)
            target = inspect(self.config["container"])
            operation = self.read()
            known = {
                operation.get("original", {}).get("Id"),
                operation.get("candidate_id"),
                operation.get("compatible_recovery_runtime_id"),
            }
            if operation.get("original") and target.get("Id") not in known:
                raise ValueError("Configured runtime identity changed")
            state = target["State"]
            if type(state.get("Running")) is not bool or not isinstance(state.get("Status"), str):
                raise ValueError("Incomplete runtime observation")
            return {"available": True, "observed_at": observed, "running": state["Running"], "status": state["Status"]}
        except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
            return {"available": False, "observed_at": observed}

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
            candidate_runtime_env = {
                key: env.get(key)
                for key in ("NCT_APP_VERSION", "NCT_BUILD_ID", "NCT_BUILD_COMMIT")
            }
            if any(
                not isinstance(value, str) or not value or len(value) > 200
                for value in candidate_runtime_env.values()
            ):
                raise ValueError("Loaded image runtime identity is incomplete")
            used = sum(p.stat().st_size for p in self.data.rglob("*") if p.is_file())
            if shutil.disk_usage(self.data).free < 3 * used + 1024**3:
                raise ValueError("Insufficient space for a verified backup, restore and failed-data preservation")
            state = {"id": operation_id, "actor": actor, "manifest": manifest, "original": target,
                     "candidate_may_have_written": False,
                     "candidate_image_id": candidate["Id"],
                     "candidate_runtime_env": candidate_runtime_env,
                     "package_sha256": digest_file(archive), "build_id": manifest["build_id"],
                     "build_commit": manifest["build_commit"], "original_build": original_build}
            self.compatibility(state, preview=True)
            self.prepare_compatible_recovery_proof(state)
            state["plan_digest"] = hashlib.sha256(canonical(state)).hexdigest()
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
        self.activity(state, "final_restart", "Account verified — finishing NCT's restart and checking readiness", force=True)
        target = self.target(expected_id=state["verified_runtime_id"])
        expected_image = state.get("verified_runtime_image_id") or (
            state["original"]["Image"]
            if state["verified_result_phase"] == "restored"
            else state["candidate_image_id"]
        )
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
            self.activity(state, "final_restart", "Account verified — finishing NCT's restart and checking readiness", force=True)
            target = self.target(expected_id=state["verified_runtime_id"])
            if not target["State"]["Running"]:
                self.engine.command("start", target["Id"])
            self.verify_health(
                state,
                original=state.get(
                    "verified_runtime_uses_original",
                    state["verified_result_phase"] == "restored",
                ),
            )
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
        terminal_phase = state["verified_result_phase"]
        self.phase(state, terminal_phase, detail="Exact build, readiness, existing-account sign-in and retained evidence verified. Review any remaining unfinished-work recovery gates in NCT.")
        if self.completed_fresh_enablement(state):
            recovery = self.data / "recovery"
            recovery.mkdir(mode=0o700, exist_ok=True)
            if recovery.is_symlink():
                raise ValueError("Fresh-install completion receipt directory is linked")
            save(recovery / "fresh-handoff-complete.json", {
                "contract": "nct-fresh-handoff-complete-v1",
                "operation_id": state["id"],
            })

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
        self.activity(state, "inventory", "Checking retained accounts and evidence before backup", force=True)
        inventory = self.helper(state["original"]["Image"], "snapshot")
        save(folder / "before.json", inventory)
        archive = folder / "backup.tar.gz"
        metadata = self.data.stat()
        state["data_metadata"] = {"uid": metadata.st_uid, "gid": metadata.st_gid, "mode": stat.S_IMODE(metadata.st_mode)}
        completed = 0
        self.activity(state, "backup_create", "Creating backup — source bytes processed", completed=0, total=footprint, unit="bytes", force=True)
        host = self
        class Reader:
            def __init__(self, stream):
                self.stream = stream
            def read(self, size):
                nonlocal completed
                block = self.stream.read(size)
                completed += len(block)
                host.activity(state, "backup_create", "Creating backup — source bytes processed", completed=completed, total=footprint, unit="bytes")
                return block
        with tarfile.open(archive, "w:gz", dereference=True) as output:
            # Reject links and special files before adding anything.
            for path in sorted(self.data.rglob("*")):
                mode = path.lstat().st_mode
                if not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
                    raise ValueError("Evidence contains a link or special file; backup refused")
                info = output.gettarinfo(str(path), arcname=path.relative_to(self.data).as_posix())
                if info.isfile():
                    with path.open("rb") as source:
                        output.addfile(info, Reader(source))
                else:
                    output.addfile(info)
        self.activity(state, "backup_create", "Creating backup — source bytes processed", completed=completed, total=footprint, unit="bytes", force=True)
        with archive.open("rb") as stream:
            os.fsync(stream.fileno())
        checksum = self.measured_digest(archive, state, "backup_hash", "Checking the backup checksum")
        state["backup_sha256"] = checksum
        state["backup_unpacked_bytes"] = sum(p.stat().st_size for p in self.data.rglob("*") if p.is_file())
        restored = self.extract_backup(state, "backup-verification")
        self.activity(state, "backup_compare", "Comparing independently restored backup with retained evidence", force=True)
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
        if self.measured_digest(archive, state, "restore_hash", "Checking backup integrity before extracting a separate copy") != state["backup_sha256"]:
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
        total = state.get("backup_unpacked_bytes")
        completed = 0
        label = "Preparing the verified backup copy for installation recovery" if name == "restored" else "Extracting a separate backup verification copy — live evidence is unchanged"
        self.activity(state, "backup_extract", label, completed=0 if type(total) is int else None, total=total, unit="bytes", force=True)
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
                        incoming = source.extractfile(member)
                        for block in iter(lambda: incoming.read(1024**2), b""):
                            output.write(block)
                            completed += len(block)
                            self.activity(state, "backup_extract", label, completed=completed if type(total) is int else None, total=total, unit="bytes")
                        output.flush()
                        os.fsync(output.fileno())
                    os.chmod(target, member.mode & 0o777)
                    os.chown(target, member.uid, member.gid)
        metadata = state.get("data_metadata", {"uid": 0, "gid": 0, "mode": 0o700})
        os.chmod(destination, metadata["mode"])
        os.chown(destination, metadata["uid"], metadata["gid"])
        sync_directory(destination)
        sync_directory(destination.parent)
        self.activity(state, "backup_extract", label, completed=completed if type(total) is int else None, total=total, unit="bytes", force=True)
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

    def candidate_runtime_contract(self, state):
        """Read the immutable candidate's recovery capability without retained data."""
        result = self.run_helper(
            state["candidate_image_id"], ["--read-only"], [
                "-c",
                "import json; "
                "from app.build_info import BUILD_ID,BUILD_COMMIT; "
                "from app.schema_compatibility import image_schema_contract; "
                "from app.retirement_guard import GUARD_CONTRACT; "
                "print(json.dumps({'build_id':BUILD_ID,'build_commit':BUILD_COMMIT,"
                "'schema':image_schema_contract(),'guard_contract':GUARD_CONTRACT},"
                "sort_keys=True))",
            ],
        )
        value = json.loads(result)
        schema_contract = value.get("schema") or {}
        if (
            value.get("build_id") != state["manifest"]["build_id"]
            or value.get("build_commit") != state["manifest"]["build_commit"]
            or value.get("guard_contract") != "nct-retirement-guard-v1"
            or schema_contract.get("writable_schema_version") != 9
            or schema_contract.get("data_layout_contract") != "nct-data-layout-v1"
            or 8 not in schema_contract.get("readable_schema_versions", [])
            or 9 not in schema_contract.get("readable_schema_versions", [])
        ):
            raise ValueError(
                "Replacement image cannot provide the exact protected recovery runtime"
            )
        return value

    def prepare_compatible_recovery_proof(self, state):
        contract = self.candidate_runtime_contract(state)
        proof = {
            "contract": COMPATIBLE_RECOVERY_CONTRACT,
            "operation_id": state["id"],
            "image_id": state["candidate_image_id"],
            "build_id": state["manifest"]["build_id"],
            "build_commit": state["manifest"]["build_commit"],
            "schema": contract["schema"],
            "guard_contract": contract["guard_contract"],
            "runtime_config_sha256": hashlib.sha256(
                canonical(runtime_create_semantics(self.replacement(state)))
            ).hexdigest(),
        }
        receipt = self.root / state["id"] / "compatible-recovery.json"
        save(receipt, proof)
        state["compatible_recovery_proof_sha256"] = digest_file(receipt)
        return proof

    def compatible_recovery_proof(self, state):
        receipt = self.root / state["id"] / "compatible-recovery.json"
        protected_root_file(receipt, self.root, "Compatible recovery proof")
        if digest_file(receipt) != state.get("compatible_recovery_proof_sha256"):
            raise ValueError("Compatible recovery proof changed")
        proof = json.loads(receipt.read_text(encoding="utf-8"))
        contract = self.candidate_runtime_contract(state)
        expected = {
            "contract": COMPATIBLE_RECOVERY_CONTRACT,
            "operation_id": state["id"],
            "image_id": state["candidate_image_id"],
            "build_id": state["manifest"]["build_id"],
            "build_commit": state["manifest"]["build_commit"],
            "schema": contract["schema"],
            "guard_contract": contract["guard_contract"],
            "runtime_config_sha256": hashlib.sha256(
                canonical(runtime_create_semantics(self.replacement(state)))
            ).hexdigest(),
        }
        if proof != expected:
            raise ValueError("Compatible recovery proof does not match this operation")
        return proof

    def validate_compatible_recovery_runtime(self, state, proof, current):
        expected = self.replacement(state)
        observed = runtime_create_semantics(current)
        observed_sha256 = hashlib.sha256(canonical(observed)).hexdigest()
        if observed_sha256 != proof.get("runtime_config_sha256"):
            raise ValueError(
                "Compatible recovery runtime configuration differs from its protected proof"
            )
        validate_runtime_network(current, expected)
        validate_runtime_mounts(current, expected)
        if current.get("Image") != proof.get("image_id"):
            raise ValueError("Compatible recovery image identity changed")
        return hashlib.sha256(canonical(runtime_snapshot(current))).hexdigest()

    def replacement(self, state):
        original = state["original"]
        config = copy.deepcopy(original["Config"])
        config.pop("Hostname", None)
        config.pop("Domainname", None)
        config["Image"] = state["candidate_image_id"]
        config["Labels"] = {**(config.get("Labels") or {}), "org.nct.update-operation": state["id"]}
        config["Env"] = [item for item in config.get("Env", []) if not item.startswith((
            "NCT_BUILD_ID=", "NCT_BUILD_COMMIT=", "NCT_APP_VERSION=",
            "NCT_RETIREMENT_GUARD_MODE=", "NCT_RETIREMENT_GUARD_DIR=",
            "NCT_RETIREMENT_DATA_IDENTITY=",
        ))]
        runtime_env = state.get("candidate_runtime_env")
        if (
            not isinstance(runtime_env, dict)
            or set(runtime_env) != {"NCT_APP_VERSION", "NCT_BUILD_ID", "NCT_BUILD_COMMIT"}
            or runtime_env.get("NCT_BUILD_ID") != state["manifest"]["build_id"]
            or runtime_env.get("NCT_BUILD_COMMIT") != state["manifest"]["build_commit"]
            or any(not isinstance(value, str) or not value for value in runtime_env.values())
        ):
            raise ValueError("Compatible recovery runtime identity is incomplete")
        config["Env"] += [
            f"{key}={runtime_env[key]}"
            for key in ("NCT_APP_VERSION", "NCT_BUILD_ID", "NCT_BUILD_COMMIT")
        ]
        config["Env"] += [
            "NCT_RETIREMENT_GUARD_MODE=required",
            "NCT_RETIREMENT_GUARD_DIR=/run/nct-retirement-guard",
            "NCT_RETIREMENT_DATA_IDENTITY=" + self.retirement_data_identity,
        ]
        host = copy.deepcopy(original["HostConfig"])
        if host.get("AutoRemove") or host.get("NetworkMode", "").startswith("container:") or host.get("VolumesFrom"):
            raise ValueError("Shared-container or auto-remove deployment requires a qualified adapter")
        host["RestartPolicy"] = {"Name": "no", "MaximumRetryCount": 0}
        host["OomKillDisable"] = bool(host.get("OomKillDisable"))
        binds = [
            item for item in (host.get("Binds") or [])
            if ":/run/nct-retirement-guard" not in item
        ]
        binds.append(f"{self.retirement_guard}:/run/nct-retirement-guard:rw")
        host["Binds"] = binds
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
            # Docker may return inspect mounts in a different order. Compare every
            # full record, preserving duplicates, while retaining exact config checks.
            if (any(current.get(key) != state["original"].get(key) for key in ("Image", "Config", "HostConfig"))
                    or sorted(map(canonical, current["Mounts"])) != sorted(map(canonical, state["original"]["Mounts"]))):
                raise ValueError("NCT configuration changed after validation; review a fresh plan")
            if not current["State"]["Running"]:
                raise ValueError("NCT stopped after validation; investigate before applying this update")
            if digest_file(self.root / state["id"] / "release" / "image.tar") != state["manifest"]["image_sha256"]:
                raise ValueError("Staged image changed after validation")
            self.replacement(state)  # Refuse unsupported deployments before stopping.
            state["actor"] = actor
            self.phase(state, "fence_intent", detail="Stopping the original writer before checking and backing up evidence.")
            self.activity(state, "stop", "Stopping NCT for the update", force=True)
            lock = None
            try:
                self.stop_exact(state["original"])
                lock = self.writer_lock()
                self.activity(state, "saved_data", "Checking saved data and unfinished work — NCT is stopped", force=True)
                self.checkpoint(state["original"]["Image"])
                self.helper(state["original"]["Image"], "active")
                self.compatibility(state)
                # Provision independent authority before backup without opening or
                # changing the live database. The candidate performs the exact
                # schema migration and binds that authority only after the verified
                # cold backup exists.
                self.provision_retirement_guard(state["candidate_image_id"])
                self.backup(state)
                self.phase(state, "backup_verified", detail="Cold backup was independently restored and matched. Replacing NCT.")
                # Creating a stopped container cannot touch the retained data bind.
                # Keep this exact pre-write state so a create failure can restart
                # the unchanged older runtime without inventing a restore hold for
                # a newly provisioned, not-yet-bound retirement guard.
                self.phase(state, "replace_intent", candidate_may_have_written=False)
                self.activity(state, "install", "Installing the checked release — collection remains paused", force=True)
                self.hold_collection(state)
                rollback_name = "nct-rollback-" + state["id"]
                self.engine.command("rename", state["original"]["Id"], rollback_name)
                candidate = self.engine.create(self.config["container"], self.replacement(state))
                self.phase(state, "candidate_created", candidate_id=candidate)
                self.activity(state, "start", "Starting and checking the installed release", force=True)
                # From this durable intent onward, Docker start may execute candidate
                # code against /data even if the host command later reports failure.
                self.phase(state, "candidate_start_intent", candidate_may_have_written=True)
                os.close(lock)
                lock = None
                self.engine.command("start", candidate)
                self.verify_health(state)
                self.activity(state, "evidence", "Checking retained evidence in the installed release", force=True)
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
                failure = {
                    "phase": state.get("phase", "unknown"),
                    "detail": str(exc)[:400],
                    "recorded_at": time.time(),
                }
                self.phase(state, "interrupted", apply_failure=failure, detail=failure["detail"])
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
        restoring = bool(state.get("candidate_may_have_written"))
        outcome = "backup_restore" if restoring else "original_reconciliation" if state.get("candidate_may_have_written") is False else "original_restart_unknown_history"
        self.phase(state, "restore_intent", actor=actor, controller_sign_in_verified=False, evidence_verified=False, completion_kind=outcome,
            detail="Restoring the verified backup and preserving later evidence separately." if restoring else "Checking and restarting the original installation. No backup data swap is being performed.")
        self.activity(state, "recovery", state["detail"], force=True)
        if state.get("candidate_may_have_written"):
            if not state.get("backup_verified"):
                raise ValueError("No verified pre-update backup; old image will remain stopped")
            before = json.loads((self.root / state["id"] / "before.json").read_text())
            if not state.get("swap"):
                self.mark_retirement_restore_hold(
                    state["candidate_image_id"], state["id"],
                )
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
            self.reconcile_swap(
                state,
                before,
                verify_snapshot=not state.get("restore_data_verified", False),
            )
            retirement = self.reconcile_retirement_restore(
                state["candidate_image_id"], state["id"],
            )
            self.phase(
                state,
                "restore_retirement_reconciled",
                restore_data_verified=True,
                retirement_restore_reconciled=True,
                retirement=retirement,
            )
            state["recovery_outcome"] = {"backup_swapped": True, "later_evidence_preserved": True}
        else:
            self.helper(original["Image"], "snapshot")
            state["recovery_outcome"] = {"backup_swapped": False, "later_evidence_preserved": False}
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
        refreshed_original = self.engine.inspect(original["Id"])
        if restoring and not self.runtime_supports_retirement_guard(refreshed_original):
            try:
                proof = self.compatible_recovery_proof(state)
            except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
                raise ValueError(
                    "The restored image cannot enforce protected retirement state or the "
                    "migrated schema; its restart policy remains disabled and it stays stopped"
                ) from None
            self.phase(
                state,
                "awaiting_compatible_recovery",
                compatible_recovery={
                    "available": True,
                    "build_id": proof["build_id"],
                    "build_commit": proof["build_commit"],
                },
                detail=(
                    "The verified backup and protected retirement history are restored. "
                    "The older runtime is safely stopped. Review and explicitly start the "
                    "preflighted compatible recovery runtime to return NCT to service."
                ),
            )
            return
        try:
            self.engine.command("start", original["Id"])
            self.verify_health(state, original=True)
        except Exception:
            self.stop_exact(original)
            raise ValueError("Restored NCT did not pass readiness; it remains stopped for review")
        self.engine.command("update", "--restart=" + restart_policy(state["original"]), original["Id"])
        self.phase(state, "awaiting_restore_sign_in", evidence_verified=True,
            detail=("NCT is running from the verified backup. Later evidence remains preserved separately. " if restoring else "The original installation restarted without a backup data swap. " + ("Earlier replacement-write history is unknown; retain administrator review. " if outcome == "original_restart_unknown_history" else "")) + "Verify an existing NCT account before finishing.")

    def _compatible_recovery_container(self, state):
        proof = self.compatible_recovery_proof(state)
        original = self.engine.inspect(state["original"]["Id"])
        self.stop_exact(original)
        original_name = original["Name"].lstrip("/")
        parked_name = "nct-restored-original-" + state["id"]
        if original_name == self.config["container"]:
            self.engine.command("rename", original["Id"], parked_name)
        elif original_name != parked_name and not original_name.startswith("nct-rollback-"):
            raise ValueError("Restored original container identity changed")

        current = self.engine.exists(self.config["container"])
        saved_id = state.get("compatible_recovery_runtime_id")
        if current is not None:
            if saved_id and current["Id"] != saved_id:
                raise ValueError("An unrelated container occupies the NCT name")
            if not saved_id and state.get("phase") != "compatible_recovery_create_intent":
                raise ValueError(
                    "Compatible recovery container exists without this operation's create intent"
                )
            labels = current.get("Config", {}).get("Labels", {}) or {}
            if (
                current.get("Image") != proof["image_id"]
                or labels.get("org.nct.update-operation") != state["id"]
            ):
                raise ValueError("Compatible recovery container identity changed")
            saved_id = current["Id"]
        elif saved_id:
            current = self.engine.inspect(saved_id)
            if current["Name"].lstrip("/") != self.config["container"]:
                raise ValueError("Compatible recovery container name changed")
        else:
            self.phase(
                state, "compatible_recovery_create_intent",
                detail="Creating the preflighted compatible recovery runtime while all writers remain stopped.",
            )
            saved_id = self.engine.create(
                self.config["container"], self.replacement(state),
            )
            current = self.engine.inspect(saved_id)

        current = self.target(expected_id=saved_id)
        snapshot_sha256 = self.validate_compatible_recovery_runtime(
            state, proof, current,
        )
        if not self.runtime_supports_retirement_guard(current):
            raise ValueError("Compatible recovery runtime lost its protected guard binding")
        recorded = state.get("compatible_recovery_runtime_sha256")
        if recorded and recorded != snapshot_sha256:
            raise ValueError("Compatible recovery runtime configuration changed")
        self.phase(
            state, "compatible_recovery_created",
            compatible_recovery_runtime_id=saved_id,
            compatible_recovery_runtime_sha256=snapshot_sha256,
            detail="Compatible recovery runtime created and fenced from automatic restart.",
        )
        return current

    def resume_compatible_recovery(self, actor):
        """Explicitly return a migrated restore with protected state to service."""
        with self.exclusive():
            state = self.read()
            if state.get("phase") not in COMPATIBLE_RECOVERY_PHASES:
                raise ValueError("No compatible recovery runtime is awaiting explicit start")
            if not (
                state.get("candidate_may_have_written") is True
                and state.get("backup_verified") is True
                and state.get("restore_data_verified") is True
                and state.get("retirement_restore_reconciled") is True
                and state.get("swap")
            ):
                raise ValueError("Verified restore prerequisites are incomplete")
            state["actor"] = actor
            proof = self.compatible_recovery_proof(state)
            retirement = self.check_retirement_guard(state["candidate_image_id"])
            expected = state.get("retirement") or {}
            if (
                retirement.get("state") != "ready"
                or retirement.get("revision") != expected.get("revision")
                or retirement.get("event_digest") != expected.get("event_digest")
            ):
                raise ValueError("Protected retirement authority changed after restore")
            self.hold_collection(state)
            current = self.engine.exists(self.config["container"])
            if current is not None:
                labels = current.get("Config", {}).get("Labels", {}) or {}
                if current["Id"] == state["original"]["Id"]:
                    self.stop_exact(current)
                elif (
                    current.get("Image") == state["candidate_image_id"]
                    and labels.get("org.nct.update-operation") == state["id"]
                ):
                    # Validate before stop_exact can normalize a hostile restart
                    # policy and hide drift from the protected create proof.
                    self.validate_compatible_recovery_runtime(state, proof, current)
                    self.stop_exact(current)
                else:
                    raise ValueError("An unrelated container occupies the NCT name")
            lock = self.writer_lock()
            target = None
            try:
                target = self._compatible_recovery_container(state)
            finally:
                os.close(lock)
            try:
                self.phase(
                    state, "compatible_recovery_start_intent",
                    detail="Starting the exact preflighted runtime against the verified restored evidence.",
                )
                self.engine.command("start", target["Id"])
                self.verify_health(state)
                self.stop_exact(self.engine.inspect(target["Id"]))
                lock = self.writer_lock()
                try:
                    self.checkpoint(state["candidate_image_id"])
                    self.verify_evidence(state)
                finally:
                    os.close(lock)
                self.engine.command("start", target["Id"])
                self.verify_health(state)
            except Exception as exc:
                if target is not None:
                    self.stop_exact(self.engine.inspect(target["Id"]))
                self.phase(
                    state,
                    "awaiting_compatible_recovery",
                    compatible_recovery={
                        **(state.get("compatible_recovery") or {}),
                        "available": True,
                        "last_failure": str(exc)[:250],
                    },
                    detail=(
                        "Compatible recovery did not pass readiness and retained-evidence "
                        "checks. Every NCT writer remains stopped; review before retrying."
                    ),
                )
                raise
            self.phase(
                state,
                "awaiting_restore_sign_in",
                completion_kind="compatible_runtime_restore",
                compatible_runtime_recovery=True,
                evidence_verified=True,
                detail=(
                    "The verified backup is running on the exact compatible recovery "
                    "runtime. Verify an existing NCT account before the final restart."
                ),
            )
            return self.public()

    def reconcile_swap(self, state, before, *, verify_snapshot=True):
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
        if verify_snapshot and self.helper(state["original"]["Image"], "snapshot") != before:
            raise ValueError("Restored evidence changed after the recorded swap; old image remains stopped")
        self.phase(state, "restore_data_verified", restore_data_verified=True)

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
        with self.exclusive(), self.activity_scope():
            state = self.read()
            phase = state["phase"]
            if phase not in {"awaiting_sign_in", "awaiting_restore_sign_in", "awaiting_repair_sign_in"}:
                raise ValueError("This update is not awaiting sign-in verification")
            compatible_recovery = bool(
                phase == "awaiting_restore_sign_in"
                and state.get("compatible_runtime_recovery") is True
            )
            original = phase != "awaiting_sign_in" and not compatible_recovery
            runtime_id = (
                state["compatible_recovery_runtime_id"]
                if compatible_recovery else
                state["original"]["Id"] if original else state["candidate_id"]
            )
            self.activity(state, "account", "Checking the existing NCT account — password is not saved", force=True)
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
            restored_result = phase == "awaiting_restore_sign_in"
            self.phase(
                state, "release_intent", controller_sign_in_verified=True,
                actor=actor, verified_runtime_id=runtime_id,
                verified_runtime_image_id=(
                    state["original"]["Image"] if original
                    else state["candidate_image_id"]
                ),
                verified_runtime_uses_original=original,
                verified_result_phase="restored" if restored_result else "complete",
            )
            self.finalize(state)
            return {"url": self.config["application_url"], "operation": self.public()}

    @staticmethod
    def completed_fresh_enablement(state):
        proof = state.get("fresh_handoff")
        return (
            state.get("phase") == "complete"
            and state.get("kind") == "enable_console"
            and state.get("controller_sign_in_verified") is True
            and isinstance(proof, dict)
            and proof.get("contract") == "nct-fresh-handoff-v1"
            and proof.get("operation_id") == state.get("id")
        )

    def fresh_session_disposition(self, operation_id, *, busy=False):
        """Classify stale or already-finished immutable fresh markers."""
        state = self.read()
        if operation_id != state.get("id") or self.completed_fresh_enablement(state):
            return {"accepted": False, "disposition": "not_applicable"}
        if (state.get("phase") == "release_intent" and state.get("kind") == "enable_console"
                and state.get("controller_sign_in_verified") is True):
            return {"accepted": True, "disposition": "finishing"}
        if busy and state.get("phase") == "awaiting_sign_in" and state.get("kind") == "enable_console":
            return {"accepted": True, "disposition": "finishing"}
        if busy:
            return {"accepted": False, "disposition": "recovery_required"}
        return None

    def confirm_fresh_session(self, operation_id, username, session_token):
        """Accept only the first normal sign-in bound to an exact fresh receipt."""
        with self.exclusive():
            disposition = self.fresh_session_disposition(operation_id)
            if disposition is not None:
                return disposition
        with self.exclusive(), self.activity_scope():
            state = self.read()
            proof = state.get("fresh_handoff")
            if state.get("phase") != "awaiting_sign_in" or state.get("kind") != "enable_console":
                raise PermissionError("No proven fresh installation is awaiting its first sign-in")
            if not isinstance(proof, dict) or proof.get("contract") != "nct-fresh-handoff-v1":
                raise PermissionError("Fresh-install proof is unavailable; use recovery sign-in verification")
            if operation_id != state.get("id") or proof.get("operation_id") != state.get("id"):
                raise PermissionError("Fresh-install operation identity differs")
            receipt = self.root / state["id"] / "fresh-handoff.json"
            try:
                protected_root_file(receipt, self.root, "Fresh-install proof")
            except (OSError, ValueError) as exc:
                raise PermissionError("Fresh-install proof changed; use recovery sign-in verification") from exc
            if receipt.read_bytes() != canonical(proof):
                raise PermissionError("Fresh-install proof changed; use recovery sign-in verification")
            if time.time() > float(proof.get("expires_at", 0)):
                raise PermissionError("Fresh-install proof expired; use recovery sign-in verification")
            if username != proof.get("expected_admin") or not isinstance(session_token, str) or len(session_token) < 40:
                raise PermissionError("The first signed-in Administrator does not match the fresh installation")
            binding = {
                "application_url": self.config["application_url"],
                "console_url": self.config["console_url"],
                "data_dir": str(self.data),
                "container": self.config["container"],
                "console_container": self.config["console_container"],
                "console_image_id": self.config["console_image_id"],
                "ca_file": self.config.get("ca_file"),
            }
            if hashlib.sha256(canonical(binding)).hexdigest() != proof.get("runtime_config_sha256"):
                raise PermissionError("Fresh-install recovery configuration changed")
            runtime_id = state.get("candidate_id")
            target = self.target(expected_id=runtime_id)
            if target["Image"] != proof.get("application_image_id") or state["original"]["Id"] != proof.get("original_container_id"):
                raise PermissionError("Fresh-install runtime identity changed")
            if hashlib.sha256(canonical(runtime_snapshot(state["original"]))).hexdigest() != proof.get("original_runtime_sha256"):
                raise PermissionError("Fresh-install original runtime record changed")
            candidate_receipt = self.root / state["id"] / "candidate-runtime.json"
            expected_candidate = {
                "container_id": runtime_id,
                "sha256": state.get("candidate_runtime_sha256"),
            }
            current_candidate_sha256 = hashlib.sha256(canonical(runtime_snapshot(target))).hexdigest()
            try:
                protected_root_file(candidate_receipt, self.root, "Fresh-install runtime proof")
            except (OSError, ValueError) as exc:
                raise PermissionError("Fresh-install replacement runtime changed") from exc
            if (candidate_receipt.read_bytes() != canonical(expected_candidate)
                    or current_candidate_sha256 != state.get("candidate_runtime_sha256")):
                raise PermissionError("Fresh-install replacement runtime changed")
            console = self.engine.inspect(self.config["console_container"])
            if console["Image"] != proof.get("console_image_id"):
                raise PermissionError("Fresh-install recovery console identity changed")
            for path_key, hash_key in (("ca_file", "ca_sha256"), ("cert_file", "cert_sha256"), ("key_file", "key_sha256")):
                path = Path(proof.get(path_key, ""))
                try:
                    protected_root_file(path, self.data.parent, "Fresh-install TLS material")
                except (OSError, ValueError) as exc:
                    raise PermissionError("Fresh-install TLS material changed") from exc
                if digest_file(path) != proof.get(hash_key):
                    raise PermissionError("Fresh-install TLS material changed")
            self.verify_health(state)
            verify_fresh_empty(
                self.data / "analyzer.db", self.data, username,
                expected_session_token=session_token,
            )
            context = ssl.create_default_context(cafile=self.config.get("ca_file"))
            request = urllib.request.Request(
                self.config["application_url"] + "/api/auth/me",
                headers={"Cookie": "nct_session=" + session_token},
            )
            with urllib.request.urlopen(request, timeout=15, context=context) as response:
                identity = json.load(response)
            analyst = identity.get("analyst") or {}
            if analyst.get("username") != username or analyst.get("role") != "admin":
                raise PermissionError("The normal NCT session did not identify the expected Administrator")
            self.engine.command("update", "--restart=" + restart_policy(state["original"]), runtime_id)
            self.phase(
                state, "release_intent", controller_sign_in_verified=True,
                actor=username, verified_runtime_id=runtime_id,
                verified_result_phase="complete", verification_mode="fresh_normal_sign_in",
                detail="First normal Administrator sign-in verified. Finishing the protected restart.",
            )
            return {"accepted": True}

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
        with self.exclusive(), self.activity_scope():
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
            state = {"id": operation_id, "kind": "repair", "actor": actor, "original": original, "candidate_may_have_written": False,
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
            if self.command != "POST" or self.path not in {"/launch", "/fresh-sign-in"}:
                raise PermissionError("Application socket supports only recovery launch or the proven fresh sign-in handoff")
            body = self.json_body()
            if self.path == "/fresh-sign-in":
                if not host.worker_guard.acquire(blocking=False):
                    return host.fresh_session_disposition(
                        body.get("operation_id", ""), busy=True,
                    )
                try:
                    result = host.confirm_fresh_session(
                        body.get("operation_id", ""), body.get("username", ""),
                        body.get("session_token", ""),
                    )
                except Exception:
                    host.worker_guard.release()
                    raise
                if result.get("accepted") is not True:
                    host.worker_guard.release()
                    return result
                def finish_fresh():
                    try:
                        time.sleep(1)
                        with host.exclusive():
                            state = host.read()
                            if state.get("phase") == "release_intent":
                                host.finalize(state)
                    except Exception as exc:
                        with host.exclusive():
                            state = host.read()
                            host.phase(state, "interrupted", detail="Fresh-install final restart requires review: " + str(exc)[:300])
                    finally:
                        host.worker_guard.release()
                threading.Thread(target=finish_fresh, daemon=True).start()
                return result
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
                "runtime": host.runtime_status(), "observed_at": time.time(),
                "upload_available_bytes": max(0, min(MAX_UPLOAD, shutil.disk_usage(host.root).free - 2 * 1024**3))}
        if self.command == "GET" and self.path == "/diagnose":
            return host.diagnose()
        if self.command == "POST" and self.path == "/upload":
            return host.stage(self.rfile, int(self.headers.get("Content-Length", "0")), actor)
        if self.command == "POST" and self.path in {"/apply", "/rollback", "/resume-compatible", "/prepare-repair", "/apply-repair", "/cancel-repair"}:
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
            elif self.path == "/resume-compatible":
                if body.get("confirm") != "START COMPATIBLE RECOVERY":
                    raise ValueError("Confirm the checked compatible recovery runtime")
                work = lambda: host.resume_compatible_recovery(actor)
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
