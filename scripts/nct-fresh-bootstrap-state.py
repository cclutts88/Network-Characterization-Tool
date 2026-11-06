#!/usr/bin/env python3
"""Own and verify the one resumable empty-install Administrator handoff."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
from datetime import datetime, timezone


CONTRACT = "nct-fresh-bootstrap-resume:1"


def normalized_mounts(value) -> list[dict]:
    """Keep every Docker mount field while ignoring inspect-list order."""
    return sorted(
        list(value or []),
        key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":")),
    )


def normalized_capabilities(value) -> list[str]:
    return sorted(
        str(item).upper().removeprefix("CAP_") for item in (value or [])
    )


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def inspect_container(name: str) -> dict:
    result = subprocess.run(
        ["docker", "inspect", name], text=True, capture_output=True
    )
    if result.returncode:
        raise ValueError("the recorded bootstrap container is unavailable")
    values = json.loads(result.stdout)
    if len(values) != 1:
        raise ValueError("the bootstrap container identity is ambiguous")
    return values[0]


def expected_command(container_port: int) -> list[str]:
    return [
        "app.main:app", "--host", "0.0.0.0", "--port", str(container_port),
        "--loop", "asyncio", "--http", "h11",
        "--ssl-certfile", "/run/tls/nct-server.crt",
        "--ssl-keyfile", "/run/tls/nct-server.key",
    ]


def runtime_snapshot(args: argparse.Namespace) -> dict:
    value = inspect_container(args.container)
    host = value.get("HostConfig") or {}
    config = value.get("Config") or {}
    state = value.get("State") or {}
    if value.get("Name") != "/" + args.container:
        raise ValueError("the bootstrap container name changed")
    if not state.get("Running"):
        raise ValueError("the bootstrap container is not running")
    if value.get("Image") != args.image_id or config.get("Image") != args.image_reference:
        raise ValueError("the bootstrap image identity changed")
    if value.get("Path") != "uvicorn" or list(value.get("Args") or []) != expected_command(args.container_port):
        raise ValueError("the bootstrap application command changed")
    if host.get("Privileged") is not False:
        raise ValueError("the bootstrap container became privileged")
    if normalized_capabilities(host.get("CapAdd")) != ["NET_RAW"] or normalized_capabilities(host.get("CapDrop")):
        raise ValueError("the bootstrap capability contract changed")
    if host.get("SecurityOpt") not in (None, []):
        raise ValueError("the bootstrap security options changed")
    restart = host.get("RestartPolicy") or {}
    if restart.get("Name") != "unless-stopped" or int(restart.get("MaximumRetryCount") or 0) != 0:
        raise ValueError("the bootstrap restart policy changed")
    network_mode = host.get("NetworkMode")
    # Docker reports its ordinary, uncustomized bridge network as either
    # "default" (older engines) or "bridge" (newer engines).
    if network_mode not in {"default", "bridge"}:
        raise ValueError("the bootstrap network mode changed")
    expected_port = {
        f"{args.container_port}/tcp": [
            {"HostIp": args.bind_address, "HostPort": str(args.host_port)}
        ]
    }
    if (host.get("PortBindings") or {}) != expected_port:
        raise ValueError("the bootstrap port binding changed")

    data_dir = args.data_dir.resolve()
    guard_dir = args.retirement_guard_dir.resolve()
    if (data_dir == guard_dir or data_dir.is_relative_to(guard_dir)
            or guard_dir.is_relative_to(data_dir)):
        raise ValueError("the bootstrap retirement authority is not separate from evidence data")
    expected_mounts = {
        "/data": (data_dir, True, "bind"),
        "/run/nct-retirement-guard": (guard_dir, True, "bind"),
        "/run/tls/nct-server.crt": (args.cert_file.resolve(), False, "bind"),
        "/run/tls/nct-server.key": (args.key_file.resolve(), False, "bind"),
        "/run/secrets/nct_bootstrap_password": (args.secret_file.resolve(), False, "bind"),
    }
    observed_mounts = {}
    for mount in value.get("Mounts") or []:
        destination = mount.get("Destination")
        if destination in observed_mounts:
            raise ValueError("the bootstrap container has a duplicate mount")
        observed_mounts[destination] = (
            Path(str(mount.get("Source", ""))).resolve(), bool(mount.get("RW")),
            str(mount.get("Type", "")),
        )
    if observed_mounts != expected_mounts:
        raise ValueError("the bootstrap mount contract changed")

    env = {}
    for item in config.get("Env") or []:
        key, separator, value_text = item.partition("=")
        if separator:
            env[key] = value_text
    expected_env = {
        "NCT_AUTH_MODE": "local",
        "NCT_SESSION_HOURS": "12",
        "NCT_COOKIE_SECURE": "1",
        "NCT_BOOTSTRAP_ADMIN": args.admin_user,
        "NCT_BOOTSTRAP_PASSWORD_FILE": "/run/secrets/nct_bootstrap_password",
        "NCT_RETIREMENT_GUARD_MODE": "required",
        "NCT_RETIREMENT_GUARD_DIR": "/run/nct-retirement-guard",
        "NCT_RETIREMENT_DATA_IDENTITY": "bind:" + str(data_dir),
    }
    if any(env.get(key) != expected for key, expected in expected_env.items()):
        raise ValueError("the bootstrap environment contract changed")
    unexpected_bootstrap = sorted(
        key for key in env if key.startswith("NCT_BOOTSTRAP_") and key not in expected_env
    )
    if unexpected_bootstrap:
        raise ValueError("the bootstrap environment contains unexpected controls")
    return {
        "container_id": value["Id"],
        "image_id": value["Image"],
        "command": [value["Path"], *list(value.get("Args") or [])],
        "mounts": {
            destination: {"source": str(source), "writable": writable, "type": mount_type}
            for destination, (source, writable, mount_type) in sorted(observed_mounts.items())
        },
        "port_binding": expected_port,
        "restart_policy": restart,
        "network_mode": network_mode,
        "cap_add": normalized_capabilities(host.get("CapAdd")),
        "environment": expected_env,
    }


def write_atomic(path: Path, value: dict, *, exclusive: bool = False) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if exclusive and path.exists():
        raise ValueError("a fresh-install resume receipt already exists")
    descriptor, temporary = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(value, stream, sort_keys=True, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        if exclusive and path.exists():
            raise ValueError("a fresh-install resume receipt appeared concurrently")
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def expected_receipt(args: argparse.Namespace, runtime: dict) -> dict:
    return {
        "contract": CONTRACT,
        "phase": "awaiting_password",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "container": args.container,
        "image_reference": args.image_reference,
        "admin_user": args.admin_user,
        "range_ip": args.range_ip,
        "bind_address": args.bind_address,
        "host_port": args.host_port,
        "container_port": args.container_port,
        "data_dir": str(args.data_dir.resolve()),
        "retirement_guard_dir": str(args.retirement_guard_dir.resolve()),
        "cert_file": str(args.cert_file.resolve()),
        "cert_sha256": sha256_file(args.cert_file),
        "key_file": str(args.key_file.resolve()),
        "key_sha256": sha256_file(args.key_file),
        "secret_file": str(args.secret_file.resolve()),
        "secret_sha256": sha256_file(args.secret_file),
        "archive_sha256": sha256_file(args.archive),
        "runtime": runtime,
    }


def read_receipt(path: Path) -> dict:
    path = path.absolute()
    if (path.name != "fresh-resume.json" or path.parent.name != "bootstrap"
            or path.parent.parent.name != "deployment"):
        raise ValueError("the fresh-install resume receipt is outside its protected location")
    trusted_root = path.parent.parent.parent
    current = trusted_root
    for part in (Path("."), "deployment", "bootstrap", "fresh-resume.json"):
        if part != Path("."):
            current = current / part
        details = current.lstat()
        if stat.S_ISLNK(details.st_mode) or details.st_uid != 0 or details.st_mode & 0o022:
            raise ValueError("the fresh-install resume receipt is not root-owned and protected")
        if current == path:
            if not stat.S_ISREG(details.st_mode):
                raise ValueError("the fresh-install resume receipt is missing or unsafe")
        elif not stat.S_ISDIR(details.st_mode):
            raise ValueError("the fresh-install resume receipt has an unsafe parent path")
    if not path.is_file():
        raise ValueError("the fresh-install resume receipt is missing or unsafe")
    value = json.loads(path.read_text(encoding="utf-8"))
    if value.get("contract") != CONTRACT:
        raise ValueError("the fresh-install resume receipt contract is unsupported")
    if value.get("phase") not in {"awaiting_password", "password_committed", "runtime_ready"}:
        raise ValueError("the fresh-install resume phase is unsupported")
    return value


def validate(args: argparse.Namespace) -> dict:
    receipt = read_receipt(args.receipt)
    runtime = runtime_snapshot(args)
    current = expected_receipt(args, runtime)
    for key in (
        "container", "image_reference", "admin_user", "range_ip", "bind_address",
        "host_port", "container_port", "data_dir", "retirement_guard_dir",
        "cert_file", "cert_sha256",
        "key_file", "key_sha256", "secret_file", "secret_sha256",
        "archive_sha256", "runtime",
    ):
        if receipt.get(key) != current[key]:
            raise ValueError(f"fresh-install resume receipt mismatch: {key}")
    return receipt


def final_runtime(receipt: dict) -> dict:
    value = inspect_container(receipt["container"])
    host = value.get("HostConfig") or {}
    config = value.get("Config") or {}
    state = value.get("State") or {}
    if not state.get("Running") or value.get("Image") != receipt["runtime"]["image_id"]:
        raise ValueError("the final fresh-install runtime or image identity changed")
    if value.get("Path") != "uvicorn" or list(value.get("Args") or []) != expected_command(receipt["container_port"]):
        raise ValueError("the final fresh-install command changed")
    if (host.get("Privileged") is not False
            or normalized_capabilities(host.get("CapAdd")) != ["NET_RAW"]
            or normalized_capabilities(host.get("CapDrop"))):
        raise ValueError("the final fresh-install capability contract changed")
    restart = host.get("RestartPolicy") or {}
    if restart.get("Name") != "unless-stopped" or int(restart.get("MaximumRetryCount") or 0) != 0:
        raise ValueError("the final fresh-install restart policy changed")
    if host.get("NetworkMode") not in {"default", "bridge"}:
        raise ValueError("the final fresh-install network mode changed")
    expected_port = {
        f'{receipt["container_port"]}/tcp': [{
            "HostIp": receipt["bind_address"], "HostPort": str(receipt["host_port"])
        }]
    }
    if (host.get("PortBindings") or {}) != expected_port:
        raise ValueError("the final fresh-install port binding changed")
    data_dir = Path(receipt["data_dir"]).resolve()
    guard_dir = Path(receipt["retirement_guard_dir"]).resolve()
    if (data_dir == guard_dir or data_dir.is_relative_to(guard_dir)
            or guard_dir.is_relative_to(data_dir)):
        raise ValueError("the final retirement authority is not separate from evidence data")
    expected_mounts = {
        "/data": (data_dir, True, "bind"),
        "/run/nct-retirement-guard": (guard_dir, True, "bind"),
        "/run/tls/nct-server.crt": (Path(receipt["cert_file"]).resolve(), False, "bind"),
        "/run/tls/nct-server.key": (Path(receipt["key_file"]).resolve(), False, "bind"),
    }
    observed_mounts = {}
    for mount in value.get("Mounts") or []:
        destination = mount.get("Destination")
        if destination in observed_mounts:
            raise ValueError("the final fresh-install runtime has a duplicate mount")
        observed_mounts[destination] = (
            Path(str(mount.get("Source", ""))).resolve(), bool(mount.get("RW")),
            str(mount.get("Type", "")),
        )
    if observed_mounts != expected_mounts:
        raise ValueError("the final fresh-install mount contract changed")
    env = {}
    for item in config.get("Env") or []:
        key, separator, value_text = item.partition("=")
        if separator:
            env[key] = value_text
    expected_env = {
        "NCT_AUTH_MODE": "local", "NCT_SESSION_HOURS": "12", "NCT_COOKIE_SECURE": "1",
        "NCT_RETIREMENT_GUARD_MODE": "required",
        "NCT_RETIREMENT_GUARD_DIR": "/run/nct-retirement-guard",
        "NCT_RETIREMENT_DATA_IDENTITY": "bind:" + receipt["data_dir"],
    }
    if any(env.get(key) != expected for key, expected in expected_env.items()) or any(
        key.startswith("NCT_BOOTSTRAP_") for key in env
    ):
        raise ValueError("the final fresh-install authentication environment changed")
    return {
        "container_id": value["Id"], "image_id": value["Image"],
        "path": value["Path"], "args": list(value.get("Args") or []),
        "config": config, "host_config": host,
        "mounts": normalized_mounts(value.get("Mounts")),
    }


def common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--container", required=True)
    parser.add_argument("--image-reference", required=True)
    parser.add_argument("--image-id", required=True)
    parser.add_argument("--admin-user", required=True)
    parser.add_argument("--range-ip", required=True)
    parser.add_argument("--bind-address", required=True)
    parser.add_argument("--host-port", type=int, required=True)
    parser.add_argument("--container-port", type=int, required=True)
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument("--retirement-guard-dir", type=Path, required=True)
    parser.add_argument("--cert-file", type=Path, required=True)
    parser.add_argument("--key-file", type=Path, required=True)
    parser.add_argument("--secret-file", type=Path, required=True)
    parser.add_argument("--archive", type=Path, required=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="action", required=True)
    create = subparsers.add_parser("create")
    common(create)
    verify = subparsers.add_parser("verify")
    common(verify)
    mark = subparsers.add_parser("mark-password-committed")
    mark.add_argument("--receipt", type=Path, required=True)
    mark.add_argument("--container-id", required=True)
    mark.add_argument("--admin-user", required=True)
    ready = subparsers.add_parser("mark-runtime-ready")
    ready.add_argument("--receipt", type=Path, required=True)
    ready.add_argument("--admin-user", required=True)
    ready.add_argument("--release", type=Path, required=True)
    ready.add_argument("--manifest", type=Path, required=True)
    ready.add_argument("--archive", type=Path, required=True)
    verify_ready = subparsers.add_parser("verify-runtime-ready")
    verify_ready.add_argument("--receipt", type=Path, required=True)
    verify_ready.add_argument("--admin-user", required=True)
    verify_ready.add_argument("--release", type=Path, required=True)
    verify_ready.add_argument("--manifest", type=Path, required=True)
    verify_ready.add_argument("--archive", type=Path, required=True)
    args = parser.parse_args()
    if args.action == "mark-password-committed":
        receipt = read_receipt(args.receipt)
        if receipt["runtime"]["container_id"] != args.container_id or receipt["admin_user"] != args.admin_user:
            raise ValueError("the password completion does not belong to this fresh installation")
        receipt["phase"] = "password_committed"
        receipt["password_committed_at"] = datetime.now(timezone.utc).isoformat()
        write_atomic(args.receipt, receipt)
        return 0
    if args.action in {"mark-runtime-ready", "verify-runtime-ready"}:
        receipt = read_receipt(args.receipt)
        expected_phase = "password_committed" if args.action == "mark-runtime-ready" else "runtime_ready"
        if receipt["phase"] != expected_phase or receipt["admin_user"] != args.admin_user:
            raise ValueError("the final runtime does not follow the committed fresh Administrator step")
        for path, label in ((args.release, "release"), (args.manifest, "manifest"), (args.archive, "archive")):
            if not path.is_file() or path.is_symlink():
                raise ValueError(f"the fresh-install {label} record is missing or unsafe")
        if sha256_file(args.archive) != receipt["archive_sha256"]:
            raise ValueError("the fresh-install image archive changed")
        if sha256_file(Path(receipt["cert_file"])) != receipt["cert_sha256"] or sha256_file(Path(receipt["key_file"])) != receipt["key_sha256"]:
            raise ValueError("the fresh-install TLS material changed")
        observed_runtime = final_runtime(receipt)
        if args.action == "verify-runtime-ready":
            if (receipt.get("release_sha256") != sha256_file(args.release)
                    or receipt.get("package_manifest_sha256") != sha256_file(args.manifest)
                    or receipt.get("final_runtime") != observed_runtime):
                raise ValueError("the completed fresh-install ownership receipt no longer matches")
            return 0
        receipt.update({
            "phase": "runtime_ready",
            "runtime_ready_at": datetime.now(timezone.utc).isoformat(),
            "release_sha256": sha256_file(args.release),
            "package_manifest_sha256": sha256_file(args.manifest),
            "final_runtime": observed_runtime,
        })
        write_atomic(args.receipt, receipt)
        return 0
    runtime = runtime_snapshot(args)
    if args.action == "create":
        write_atomic(args.receipt, expected_receipt(args, runtime), exclusive=True)
    else:
        validate(args)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        raise SystemExit(f"Fresh-install resume validation failed: {exc}")
