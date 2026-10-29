#!/usr/bin/env python3
"""Continue an interrupted console installation without replacing its host service."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess

from install_nct_recovery import enable_console
from nct_update_host import Host, canonical


def preflight(host, application_image, console_image, build_id, build_commit, cert_file, key_file):
    if not all(re.fullmatch(r"sha256:[0-9a-f]{64}", value) for value in (application_image, console_image)) or not re.fullmatch(r"[0-9a-f]{40}", build_commit):
        raise ValueError("Supply the exact verified release identities")
    previous = host.read()
    if previous.get("kind") != "enable_console" or previous.get("phase") not in {"restored", "complete"} or not previous.get("controller_sign_in_verified"):
        raise ValueError("Reconcile and verify the previous installation first")
    original = host.target()
    if original["Image"] != application_image or not original["State"]["Running"]:
        raise ValueError("The expected running NCT image is required")
    env = dict(value.split("=", 1) for value in original["Config"].get("Env", []) if "=" in value)
    if env.get("NCT_BUILD_ID") != build_id or env.get("NCT_BUILD_COMMIT") != build_commit:
        raise ValueError("The running release identity differs")
    if env.get("NCT_AUTH_MODE") != "local":
        raise ValueError("Existing local accounts are required")
    if any(m["Destination"] == "/run/nct-update" for m in original["Mounts"]) or env.get("NCT_UPDATE_LAUNCH_SOCKET"):
        raise ValueError("The launch socket is already configured; inspect instead of recreating")
    if Path(host.config["launch_socket"]) != host.root / "sockets/launch/launch.sock":
        raise ValueError("The installed launch socket location differs")
    console = host.engine.inspect(host.config["console_container"])
    runtime = console["HostConfig"]
    if console["Image"] != console_image or host.config["console_image_id"] != console_image:
        raise ValueError("The installed console image differs")
    if not runtime.get("ReadonlyRootfs") or runtime.get("CapDrop") != ["ALL"] or runtime.get("CapAdd") or runtime.get("SecurityOpt") not in (["no-new-privileges"], ["no-new-privileges:true"]) or runtime.get("Privileged"):
        raise ValueError("The console restrictions differ")
    if runtime.get("IpcMode") not in {None, "", "private", "shareable"}:
        raise ValueError("Unexpected console host namespaces or devices")
    if any(runtime.get(key) for key in ("PidMode", "Devices", "DeviceRequests", "VolumesFrom")) or runtime.get("NetworkMode") not in {None, "", "default", "bridge"}:
        raise ValueError("Unexpected console host namespaces or devices")
    expected = {"/run/nct-recovery": (host.root / "sockets/control", False), "/staging": (host.root / "spool", True),
        "/run/tls/server.crt": (Path(cert_file), False), "/run/tls/server.key": (Path(key_file), False)}
    if not all(Path(v).is_file() and not Path(v).is_symlink() for v in (cert_file, key_file)):
        raise ValueError("Reviewed TLS files are required")
    if len(console["Mounts"]) != len(expected):
        raise ValueError("Unexpected console host access")
    for mount in console["Mounts"]:
        match = expected.get(mount["Destination"])
        if not match or mount["Type"] != "bind" or Path(mount["Source"]).resolve() != match[0].resolve() or mount["RW"] != match[1]:
            raise ValueError("Unexpected console host access")
    subprocess.run(["systemctl", "is-active", "--quiet", "nct-recovery-host.service"], check=True)
    host.verify_health({"manifest": {"build_id": build_id, "build_commit": build_commit}})
    host.helper(original["Image"], "active", immutable=False)
    return previous, original


def finish(host, application_image, console_image, build_id, build_commit, cert_file, key_file):
    arguments = (application_image, console_image, build_id, build_commit, cert_file, key_file)
    previous, original = preflight(host, *arguments)
    host.launch("host-installer")
    def locked_guard():
        current_previous, current = preflight(host, *arguments)
        if canonical(previous) != canonical(current_previous) or any(current[k] != original[k] for k in ("Id", "Image", "Config", "HostConfig", "Mounts")):
            raise ValueError("The reviewed installation changed before continuation")
    return enable_console(host, original, host.config["container"], require_reconciled=True, locked_guard=locked_guard)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=Path("/opt/nct-recovery/config.json"))
    parser.add_argument("--application-image", required=True)
    parser.add_argument("--console-image", required=True)
    parser.add_argument("--build-id", required=True)
    parser.add_argument("--build-commit", required=True)
    parser.add_argument("--cert-file", required=True, type=Path)
    parser.add_argument("--key-file", required=True, type=Path)
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise ValueError("Run on the NCT host as root")
    retained = finish(Host(json.loads(args.config.read_text())), args.application_image, args.console_image, args.build_id, args.build_commit, args.cert_file, args.key_file)
    print("Console connection enabled; verify an existing account before collection resumes.")
    print("Retained stopped application: " + retained)


if __name__ == "__main__":
    main()
