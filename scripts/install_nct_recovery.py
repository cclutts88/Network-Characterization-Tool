#!/usr/bin/env python3
"""One-time host installation; never run from the uploaded release package."""
import argparse
import copy
import hashlib
import ipaddress
import json
import os
import re
import stat
from pathlib import Path
import secrets
import shlex
import shutil
import subprocess
import sys
import time
import urllib.parse

from nct_update_host import Docker, Host, canonical, restart_policy, save
from nct_fresh_handoff import verify_empty


def _normalized_mounts(value):
    """Keep every Docker mount field while ignoring inspect-list order."""
    return sorted(
        list(value or []),
        key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":")),
    )


def recovery_python():
    path = Path(sys.executable).resolve()
    if sys.version_info < (3, 9) or not path.is_absolute() or not os.access(path, os.X_OK):
        raise ValueError("Recovery requires an executable Python 3.9 or newer")
    if any(char.isspace() or char in '%\\"' for char in str(path)) or str(path).startswith(("/root/", "/home/", "/run/user/")):
        raise ValueError("Recovery Python must be accessible to the protected host service")
    return str(path)


def service_command(interpreter, trusted, config_path):
    def quote(value):
        text = str(value)
        if any(ord(char) < 32 for char in text):
            raise ValueError("Service paths may not contain control characters")
        return '"' + text.replace('\\', '\\\\').replace('"', '\\"').replace('%', '%%').replace('$', '$$') + '"'
    return "ExecStart=" + " ".join(quote(value) for value in (interpreter, trusted / "nct_update_host.py", "--config", config_path))


def access_command(interpreter, trusted, config_path):
    return shlex.join([interpreter, str(trusted / "nct_update_host.py"), "--config", str(config_path), "--access-code"])


def _runtime_snapshot(value):
    return {
        "container_id": value["Id"], "image_id": value["Image"],
        "path": value.get("Path"), "args": list(value.get("Args") or []),
        "config": value.get("Config") or {},
        "host_config": value.get("HostConfig") or {},
        "mounts": _normalized_mounts(value.get("Mounts")),
    }


def _trusted_root_file(path, trusted_root, label):
    path = Path(path).absolute()
    trusted_root = Path(trusted_root).absolute()
    try:
        relative = path.relative_to(trusted_root)
    except ValueError as exc:
        raise ValueError(f"The fresh-install {label} is outside its protected root") from exc
    current = trusted_root
    for part in (Path("."), *relative.parts):
        if part != Path("."):
            current = current / part
        details = current.lstat()
        if stat.S_ISLNK(details.st_mode) or details.st_uid != 0 or details.st_mode & 0o022:
            raise ValueError(f"The fresh-install {label} is not root-owned and protected")
        if current == path:
            if not stat.S_ISREG(details.st_mode):
                raise ValueError(f"The fresh-install {label} is not a regular file")
        elif not stat.S_ISDIR(details.st_mode):
            raise ValueError(f"The fresh-install {label} has an unsafe parent path")
    return path


def _sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 ** 2), b""):
            digest.update(block)
    return digest.hexdigest()


def _fresh_release_proof(host, original, expected_admin, release_file,
                         bootstrap_receipt_file, package_manifest_file):
    if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{1,63}", expected_admin):
        raise ValueError("The expected fresh-install Administrator is invalid")
    release_file = Path(release_file)
    if not release_file.is_file() or release_file.is_symlink():
        raise ValueError("The exact fresh-install release record is missing or linked")
    bootstrap_receipt_file = _trusted_root_file(
        bootstrap_receipt_file, host.data.parent,
        "ownership receipt",
    )
    expected_receipt = host.data.parent / "deployment" / "bootstrap" / "fresh-resume.json"
    if bootstrap_receipt_file != expected_receipt.absolute():
        raise ValueError("The fresh-install ownership receipt is not in its protected location")
    package_manifest_file = Path(package_manifest_file)
    if not package_manifest_file.is_file() or package_manifest_file.is_symlink():
        raise ValueError("The fresh-install package manifest is missing or linked")
    release_bytes = release_file.read_bytes()
    release = json.loads(release_bytes)
    if release.get("contract") != "nct-full-range-package-v1" or not isinstance(release.get("fresh_install"), dict):
        raise ValueError("The release is not an exact qualified fresh-install package")
    env = dict(value.split("=", 1) for value in original["Config"].get("Env", []) if "=" in value)
    if release.get("build_id") != env.get("NCT_BUILD_ID") or release.get("commit") != env.get("NCT_BUILD_COMMIT"):
        raise ValueError("The fresh-install release identity differs from the running application")
    application_reference = release.get("application_image", "")
    console_reference = release.get("console_image", "")
    images = release.get("images") or {}
    application_image = host.engine.inspect(application_reference)
    console_image = host.engine.inspect(console_reference)
    if application_image["Id"] != original["Image"] or console_image["Id"] != host.config["console_image_id"]:
        raise ValueError("The loaded application or recovery image differs from the fresh-install release")
    application_ids = {value for value in (images.get(application_reference) or {}).values() if isinstance(value, str) and value.startswith("sha256:")}
    console_ids = {value for value in (images.get(console_reference) or {}).values() if isinstance(value, str) and value.startswith("sha256:")}
    if original["Image"] not in application_ids or host.config["console_image_id"] not in console_ids:
        raise ValueError("The fresh-install release does not pin the running immutable image identities")
    ownership = json.loads(bootstrap_receipt_file.read_text(encoding="utf-8"))
    if ownership.get("contract") != "nct-fresh-bootstrap-resume:1" or ownership.get("phase") != "runtime_ready":
        raise ValueError("The root-owned fresh-install runtime receipt is incomplete")
    if ownership.get("admin_user") != expected_admin or Path(ownership.get("data_dir", "")).resolve() != host.data.resolve():
        raise ValueError("The fresh-install owner or evidence directory differs")
    if ownership.get("release_sha256") != hashlib.sha256(release_bytes).hexdigest() or ownership.get("package_manifest_sha256") != _sha256_file(package_manifest_file):
        raise ValueError("The fresh-install package records differ from the root-owned receipt")
    if ownership.get("final_runtime") != _runtime_snapshot(original):
        raise ValueError("The final fresh-install runtime changed after its ownership receipt")
    for configured, saved_path, saved_hash, label in (
        (host.config.get("ca_file"), None, None, "CA"),
        (ownership.get("cert_file"), ownership.get("cert_file"), ownership.get("cert_sha256"), "certificate"),
        (ownership.get("key_file"), ownership.get("key_file"), ownership.get("key_sha256"), "key"),
    ):
        if label == "CA":
            if not configured or not Path(configured).is_file() or Path(configured).is_symlink():
                raise ValueError("The fresh-install CA file is missing or linked")
        elif not saved_path or Path(saved_path).is_symlink() or _sha256_file(saved_path) != saved_hash:
            raise ValueError(f"The fresh-install TLS {label} changed")
    verify_empty(host.data / "analyzer.db", host.data, expected_admin)
    issued = time.time()
    binding = {
        "application_url": host.config["application_url"],
        "console_url": host.config["console_url"],
        "data_dir": str(host.data),
        "container": host.config["container"],
        "console_container": host.config["console_container"],
        "console_image_id": host.config["console_image_id"],
        "ca_file": host.config.get("ca_file"),
    }
    return {
        "contract": "nct-fresh-handoff-v1",
        "expected_admin": expected_admin,
        "issued_at": issued,
        "expires_at": issued + 24 * 3600,
        "release_sha256": hashlib.sha256(release_bytes).hexdigest(),
        "release_build_id": release["build_id"],
        "release_commit": release["commit"],
        "package_manifest_sha256": ownership["package_manifest_sha256"],
        "bootstrap_receipt_sha256": _sha256_file(bootstrap_receipt_file),
        "application_image_id": application_image["Id"],
        "console_image_id": console_image["Id"],
        "original_container_id": original["Id"],
        "original_runtime_sha256": hashlib.sha256(canonical(_runtime_snapshot(original))).hexdigest(),
        "cert_file": ownership["cert_file"], "cert_sha256": ownership["cert_sha256"],
        "key_file": ownership["key_file"], "key_sha256": ownership["key_sha256"],
        "ca_file": host.config["ca_file"], "ca_sha256": _sha256_file(host.config["ca_file"]),
        "runtime_config_sha256": hashlib.sha256(canonical(binding)).hexdigest(),
    }


def enable_console(host, original, container, *, require_reconciled=False, locked_guard=None,
                   fresh_expected_admin=None, fresh_release_file=None,
                   fresh_bootstrap_receipt=None, fresh_package_manifest=None):
    engine, state = host.engine, host.root
    launch_dir = Path(host.config["launch_socket"]).parent
    candidate = copy.deepcopy(original["Config"])
    candidate.pop("Hostname", None)
    candidate["Image"] = original["Image"]
    candidate["HostConfig"] = copy.deepcopy(original["HostConfig"])
    candidate["HostConfig"]["RestartPolicy"] = {"Name": "no", "MaximumRetryCount": 0}
    candidate["HostConfig"]["Binds"] = list(candidate["HostConfig"].get("Binds") or []) + [f"{launch_dir}:/run/nct-update:ro"]
    candidate["Env"] = [value for value in candidate.get("Env", []) if not value.startswith("NCT_UPDATE_LAUNCH_SOCKET=")] + ["NCT_UPDATE_LAUNCH_SOCKET=/run/nct-update/launch.sock"]
    retained = container + "-before-recovery-" + secrets.token_hex(5)
    with host.exclusive():
        if locked_guard is not None:
            locked_guard()
        prior_id = None
        if require_reconciled:
            previous = host.read()
            if previous.get("phase") not in {"complete", "restored"} or not previous.get("controller_sign_in_verified"):
                raise ValueError("Verify the reconciled existing account before continuing setup")
            host.target(expected_id=original["Id"])
            prior_id = previous["id"]
            if not re.fullmatch(r"[0-9a-f]{32}", prior_id):
                raise ValueError("Invalid prior recovery operation identity")
            receipt = state / prior_id / "reconciled-operation.json"
            if receipt.exists():
                if receipt.read_bytes() != canonical(previous):
                    raise ValueError("The retained reconciliation receipt differs")
            else:
                with receipt.open("xb") as record:
                    record.write(canonical(previous))
        fresh_proof = None
        fresh_values = (fresh_expected_admin, fresh_release_file,
                        fresh_bootstrap_receipt, fresh_package_manifest)
        if any(value is not None for value in fresh_values):
            if not all(fresh_values) or require_reconciled:
                raise ValueError("Fresh handoff requires all exact ownership and package records together")
            fresh_proof = _fresh_release_proof(
                host, original, fresh_expected_admin, fresh_release_file,
                fresh_bootstrap_receipt, fresh_package_manifest,
            )
        operation_id = secrets.token_hex(16)
        (state / operation_id).mkdir(mode=0o700)
        if fresh_proof is not None:
            fresh_proof["operation_id"] = operation_id
            with (state / operation_id / "fresh-handoff.json").open("xb") as record:
                record.write(canonical(fresh_proof))
        env = dict(value.split("=", 1) for value in original["Config"]["Env"] if "=" in value)
        build = {"build_id": env.get("NCT_BUILD_ID"), "build_commit": env.get("NCT_BUILD_COMMIT")}
        operation = {"id": operation_id, "kind": "enable_console", "actor": "host-installer",
            "candidate_may_have_written": False,
            "original": original, "original_build": build, "manifest": build,
            "candidate_image_id": original["Image"], "prior_operation_id": prior_id,
            "fresh_handoff": fresh_proof, **build}
        if fresh_proof is not None:
            candidate["Env"] = [
                value for value in candidate.get("Env", [])
                if not value.startswith("NCT_FRESH_HANDOFF_OPERATION=")
            ] + ["NCT_FRESH_HANDOFF_OPERATION=" + operation_id]
        host.phase(operation, "fence_intent", detail="Enabling the independent console on the exact existing NCT image.")
        replacement_id = None
        writer = None
        try:
            host.stop_exact(original)
            writer = host.writer_lock()
            host.checkpoint(original["Image"])
            host.helper(original["Image"], "active")
            host.backup(operation)
            host.phase(operation, "backup_verified")
            host.phase(operation, "replace_intent", candidate_may_have_written=True)
            host.hold_collection(operation)
            engine.command("rename", original["Id"], retained)
            candidate["Labels"] = {**(candidate.get("Labels") or {}), "org.nct.update-operation": operation_id}
            replacement_id = engine.create(container, candidate)
            replacement = engine.inspect(replacement_id)
            candidate_runtime_sha256 = hashlib.sha256(canonical(_runtime_snapshot(replacement))).hexdigest()
            with (state / operation_id / "candidate-runtime.json").open("xb") as record:
                record.write(canonical({"container_id": replacement_id, "sha256": candidate_runtime_sha256}))
            host.phase(operation, "candidate_created", candidate_id=replacement_id,
                       candidate_runtime_sha256=candidate_runtime_sha256)
            os.close(writer)
            writer = None
            engine.command("start", replacement_id)
            host.verify_health(operation)
            host.stop_exact(engine.inspect(replacement_id))
            writer = host.writer_lock()
            host.checkpoint(original["Image"])
            host.verify_evidence(operation)
            os.close(writer)
            writer = None
            engine.command("start", replacement_id)
            host.verify_health(operation)
            detail = (
                "Recovery console enabled. Sign in once through the normal NCT page to finish this proven fresh installation."
                if fresh_proof is not None else
                "Recovery console enabled. Open Updates & Recovery and verify an existing NCT account before resuming collection."
            )
            host.phase(operation, "awaiting_sign_in", completion_kind="console_enable", detail=detail)
        except Exception as exc:
            if writer is not None:
                os.close(writer)
                writer = None
            host.phase(operation, "interrupted", detail="Console setup interrupted: " + str(exc)[:300])
            host.restore(operation, "host-installer")
            raise
        finally:
            if writer is not None:
                os.close(writer)
    return retained


def install(args):
    interpreter = recovery_python()
    if os.geteuid() != 0:
        raise ValueError("Run the one-time recovery installer as root on the NCT host")
    if not args.enable_container:
        raise ValueError("Review the installation instructions, then use --enable-container to recreate the exact current NCT image with the launch-only socket")
    fresh_values = tuple(getattr(args, name, None) for name in (
        "fresh_expected_admin", "fresh_release_file", "fresh_bootstrap_receipt",
        "fresh_package_manifest",
    ))
    if any(value is not None for value in fresh_values) and not all(fresh_values):
        raise ValueError("Fresh handoff requires all exact ownership and package records together")
    for path in fresh_values[1:]:
        if path and (not Path(path).is_file() or Path(path).is_symlink()):
            raise ValueError("An exact fresh-install ownership or package record is missing or linked")
    engine = Docker()
    original = engine.inspect(args.container)
    image = json.loads(engine.command("image", "inspect", args.console_image))[0]
    for value in (args.application_url, args.console_url):
        parsed = urllib.parse.urlsplit(value)
        if parsed.scheme != "https" or parsed.username or parsed.password or parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
            raise ValueError("Management addresses must be explicit HTTPS origins without credentials or paths")
    console = urllib.parse.urlsplit(args.console_url)
    if not console.port or args.console_url.rstrip("/") == args.application_url.rstrip("/"):
        raise ValueError("Choose an independent HTTPS management port")
    ipaddress.ip_address(args.bind_address)
    state = args.state_dir.resolve()
    trusted = args.install_dir.resolve()
    service_exec = service_command(interpreter, trusted, trusted / "config.json")
    if state.exists() and any(state.iterdir()):
        raise ValueError("Recovery state already exists. Preserve its receipts; do not overwrite an installed helper")
    if engine.exists(args.console_container):
        raise ValueError("Recovery container already exists; inspect its installed configuration")
    trusted.mkdir(mode=0o700, parents=True, exist_ok=True)
    state.mkdir(mode=0o700, parents=True, exist_ok=True)
    for name in ("nct_update_host.py", "nct-range-data-check.py", "nct_update_work.py", "nct_fresh_handoff.py"):
        shutil.copyfile(Path(__file__).with_name(name), trusted / name)
        os.chmod(trusted / name, 0o600)
    sockets = state / "sockets"
    launch_dir, control_dir = sockets / "launch", sockets / "control"
    for directory in (launch_dir, control_dir, state / "spool"):
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    config = {"contract": "nct-update-v1", "state_dir": str(state), "data_dir": str(args.data_dir.resolve()),
        "container": args.container, "console_container": args.console_container, "console_image_id": image["Id"],
        "application_url": args.application_url.rstrip("/"), "console_url": args.console_url.rstrip("/"),
        "ca_file": str(args.ca_file.resolve()), "launch_socket": str(launch_dir / "launch.sock"),
        "control_socket": str(control_dir / "control.sock"),
        "maintenance_lock": str(args.data_dir.resolve().parent / "deployment" / "maintenance.lock"),
        "allowed_operators": "all"}
    config_path = trusted / "config.json"
    save(config_path, config)
    host = Host(config, engine)
    host.target(expected_id=original["Id"])
    if dict(item.split("=", 1) for item in original["Config"].get("Env", [])).get("NCT_AUTH_MODE") != "local":
        raise ValueError("Enable local NCT accounts before installing GUI recovery")
    # Read-only work check before the one-time application restart.
    host.helper(original["Image"], "active", immutable=False)
    host.run_helper(original["Image"], ["--read-only"], ["-c", "from app.scan_work_recovery import UPDATE_PAUSE_CONTRACT; assert UPDATE_PAUSE_CONTRACT=='nct-update-pause-v1'"])
    tls = []
    for source, destination in ((args.cert_file, "/run/tls/server.crt"), (args.key_file, "/run/tls/server.key")):
        if not source.is_file():
            raise ValueError("Recovery HTTPS certificate or key is missing")
        tls.append(f"{source.resolve()}:{destination}:ro")
    console_config = {"Image": image["Id"], "Entrypoint": [], "Cmd": ["uvicorn", "app.recovery_console:app", "--host", "0.0.0.0", "--port", "8446", "--ssl-certfile", "/run/tls/server.crt", "--ssl-keyfile", "/run/tls/server.key"],
        "Env": ["NCT_RECOVERY_SOCKET=/run/nct-recovery/control.sock", "NCT_RECOVERY_SPOOL=/staging"],
        "ExposedPorts": {"8446/tcp": {}}, "HostConfig": {"RestartPolicy": {"Name": "no"},
            "Binds": [f"{control_dir}:/run/nct-recovery:ro", f"{state / 'spool'}:/staging", *tls],
            "ReadonlyRootfs": True, "CapDrop": ["ALL"], "SecurityOpt": ["no-new-privileges:true"],
            "Tmpfs": {"/tmp": "rw,noexec,nosuid,size=16m"},
            "PortBindings": {"8446/tcp": [{"HostIp": args.bind_address, "HostPort": str(console.port)}]}}}
    engine.create(args.console_container, console_config)
    unit = "\n".join(["[Unit]", "Description=NCT on-demand update and recovery host helper", "After=docker.service", "Requires=docker.service", "[Service]", "Type=simple",
        service_exec, "Restart=on-failure", "UMask=0077", "NoNewPrivileges=true", "ProtectHome=true", "[Install]", "WantedBy=multi-user.target", ""])
    unit_path = Path("/etc/systemd/system/nct-recovery-host.service")
    unit_path.parent.mkdir(parents=True, exist_ok=True)
    unit_path.write_text(unit)
    subprocess.run(["systemctl", "daemon-reload"], check=True)
    subprocess.run(["systemctl", "enable", "--now", "nct-recovery-host.service"], check=True)
    host.launch("host-installer")  # Prove the independent GUI and broker before stopping NCT.
    retained = enable_console(
        host, original, args.container,
        fresh_expected_admin=getattr(args, "fresh_expected_admin", None),
        fresh_release_file=getattr(args, "fresh_release_file", None),
        fresh_bootstrap_receipt=getattr(args, "fresh_bootstrap_receipt", None),
        fresh_package_manifest=getattr(args, "fresh_package_manifest", None),
    )
    if getattr(args, "fresh_expected_admin", None):
        print("Recovery helper installed. Sign in once through the normal NCT page to finish this fresh installation.")
    else:
        print("Recovery helper installed. Collection stays paused until existing-account verification.")
        print("Open NCT → Account and settings → Updates & Recovery.")
    print("If NCT is unavailable: " + access_command(interpreter, trusted, config_path))
    print("The previous application container remains stopped: " + retained)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--container", default="nct")
    parser.add_argument("--console-container", default="nct-recovery-console")
    parser.add_argument("--console-image", required=True, help="Pinned locally available image containing this console")
    parser.add_argument("--application-url", required=True)
    parser.add_argument("--console-url", required=True)
    parser.add_argument("--bind-address", required=True)
    parser.add_argument("--data-dir", type=Path, default=Path("/var/lib/nct/data"))
    parser.add_argument("--state-dir", type=Path, default=Path("/var/lib/nct/deployment/recovery-console"))
    parser.add_argument("--install-dir", type=Path, default=Path("/opt/nct-recovery"))
    parser.add_argument("--cert-file", required=True, type=Path)
    parser.add_argument("--key-file", required=True, type=Path)
    parser.add_argument("--ca-file", required=True, type=Path)
    parser.add_argument("--fresh-expected-admin")
    parser.add_argument("--fresh-release-file", type=Path)
    parser.add_argument("--fresh-bootstrap-receipt", type=Path)
    parser.add_argument("--fresh-package-manifest", type=Path)
    parser.add_argument("--enable-container", action="store_true")
    install(parser.parse_args())
