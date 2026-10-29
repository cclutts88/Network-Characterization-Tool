#!/usr/bin/env python3
"""One-time host installation; never run from the uploaded release package."""
import argparse
import copy
import ipaddress
import json
import os
from pathlib import Path
import secrets
import shlex
import shutil
import subprocess
import sys
import urllib.parse

from nct_update_host import Docker, Host, canonical, restart_policy, save


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


def install(args):
    interpreter = recovery_python()
    if os.geteuid() != 0:
        raise ValueError("Run the one-time recovery installer as root on the NCT host")
    if not args.enable_container:
        raise ValueError("Review the installation instructions, then use --enable-container to recreate the exact current NCT image with the launch-only socket")
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
    for name in ("nct_update_host.py", "nct-range-data-check.py", "nct_update_work.py"):
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
    candidate = copy.deepcopy(original["Config"])
    candidate.pop("Hostname", None)
    candidate["Image"] = original["Image"]
    candidate["HostConfig"] = copy.deepcopy(original["HostConfig"])
    candidate["HostConfig"]["RestartPolicy"] = {"Name": "no", "MaximumRetryCount": 0}
    candidate["HostConfig"]["Binds"] = list(candidate["HostConfig"].get("Binds") or []) + [f"{launch_dir}:/run/nct-update:ro"]
    candidate["Env"] = [value for value in candidate.get("Env", []) if not value.startswith("NCT_UPDATE_LAUNCH_SOCKET=")] + ["NCT_UPDATE_LAUNCH_SOCKET=/run/nct-update/launch.sock"]
    retained = args.container + "-before-recovery-" + secrets.token_hex(5)
    with host.exclusive():
        operation_id = secrets.token_hex(16)
        (state / operation_id).mkdir(mode=0o700)
        env = dict(value.split("=", 1) for value in original["Config"]["Env"] if "=" in value)
        build = {"build_id": env.get("NCT_BUILD_ID"), "build_commit": env.get("NCT_BUILD_COMMIT")}
        operation = {"id": operation_id, "kind": "enable_console", "actor": "host-installer",
            "original": original, "original_build": build, "manifest": build,
            "candidate_image_id": original["Image"], **build}
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
            replacement_id = engine.create(args.container, candidate)
            host.phase(operation, "candidate_created", candidate_id=replacement_id)
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
            host.phase(operation, "awaiting_sign_in", completion_kind="console_enable", detail="Recovery console enabled. Open Updates & Recovery and verify an existing NCT account before resuming collection.")
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
    parser.add_argument("--enable-container", action="store_true")
    install(parser.parse_args())
