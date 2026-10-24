#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shlex
import shutil
import sqlite3
import stat
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any


class FreshInstallError(RuntimeError):
    pass


def _json_digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _paths_overlap(left: str, right: str) -> bool:
    left_path = os.path.normpath(left)
    right_path = os.path.normpath(right)
    try:
        common = os.path.commonpath((left_path, right_path))
    except ValueError:
        return False
    return common in (left_path, right_path)


def check_isolation(
    inspected: Any,
    target_id: str,
    old_type: str,
    old_source: str,
    old_path: str,
    new_bind_path: str = "",
) -> dict[str, Any]:
    if not isinstance(inspected, list):
        raise FreshInstallError("container isolation inspection must be a list")
    checked = 0
    for candidate in inspected:
        if str(candidate.get("Id") or "") == target_id:
            continue
        checked += 1
        name = str(candidate.get("Name") or "unknown").lstrip("/")
        for mount in candidate.get("Mounts") or []:
            mount_type = str(mount.get("Type") or "")
            mount_source = str(mount.get("Name") or "") if mount_type == "volume" else str(mount.get("Source") or "")
            mount_path = os.path.normpath(str(mount.get("Source") or ""))
            shares_old = old_type == "volume" and mount_type == "volume" and mount_source == old_source
            if mount_path:
                shares_old = shares_old or _paths_overlap(old_path, mount_path)
            if shares_old:
                raise FreshInstallError(f"another container shares or overlaps NCT data: {name}")
            if new_bind_path and mount_path and _paths_overlap(new_bind_path, mount_path):
                raise FreshInstallError(f"fresh data path overlaps a mount used by container: {name}")
    return {"contract": "nct-fresh-install-isolation:1", "other_containers_checked": checked}


def _write_json(path: Path | None, value: Any) -> None:
    payload = json.dumps(value, indent=2, sort_keys=True) + "\n"
    if path is None:
        print(payload, end="")
        return
    path.write_text(payload, encoding="utf-8")
    try:
        path.chmod(0o600)
    except PermissionError:
        pass


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def inventory(root: Path) -> dict[str, Any]:
    root = root.resolve()
    if not root.is_dir():
        raise FreshInstallError(f"inventory root is not a directory: {root}")
    # The mount-point directory belongs to the host or volume driver and is not
    # archived as retained NCT content. Every object below it is inventoried.
    rows: list[dict[str, Any]] = []
    hardlinks: dict[tuple[int, int], list[str]] = {}
    total_bytes = 0
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        relative = path.relative_to(root).as_posix()
        info = path.lstat()
        if stat.S_ISREG(info.st_mode):
            kind = "file"
        elif stat.S_ISDIR(info.st_mode):
            kind = "directory"
        elif stat.S_ISLNK(info.st_mode):
            kind = "symlink"
        else:
            raise FreshInstallError(f"unsupported filesystem object: {relative}")
        row: dict[str, Any] = {
            "path": relative,
            "kind": kind,
            "mode": stat.S_IMODE(info.st_mode),
            "uid": info.st_uid,
            "gid": info.st_gid,
        }
        if kind == "file":
            row["size"] = info.st_size
            row["sha256"] = _file_sha256(path)
            total_bytes += info.st_size
            if info.st_nlink > 1:
                hardlinks.setdefault((info.st_dev, info.st_ino), []).append(relative)
        elif kind == "symlink":
            row["target"] = os.readlink(path)
        rows.append(row)
    link_sets = sorted(sorted(paths) for paths in hardlinks.values() if len(paths) > 1)
    result = {
        "contract": "nct-fresh-install-inventory:1",
        "file_count": sum(row["kind"] == "file" for row in rows),
        "directory_count": sum(row["kind"] == "directory" for row in rows),
        "symlink_count": sum(row["kind"] == "symlink" for row in rows),
        "total_file_bytes": total_bytes,
        "entries": rows,
        "hardlink_sets": link_sets,
    }
    result["inventory_digest"] = _json_digest(result)
    return result


SUMMARY_TABLES = {
    "accounts": "analyst_users",
    "network_scopes": "network_scopes",
    "saved_networks": "saved_networks",
    "scan_runs": "scan_runs",
    "scan_schedules": "scan_schedules",
    "scan_profiles": "scan_profiles",
    "device_collections": "device_collections",
    "artifact_observations": "artifact_observations",
    "arkime_imports": "arkime_imports",
    "investigation_notes": "analyst_investigation_notes",
}


@contextmanager
def _database_snapshot(root: Path):
    """Read one private, WAL-complete copy without touching retained NCT data."""
    source = root / "analyzer.db"
    if not source.is_file():
        yield None
        return
    with tempfile.TemporaryDirectory(prefix="nct-fresh-db-") as temp:
        snapshot_root = Path(temp)
        snapshot = snapshot_root / "analyzer.db"
        shutil.copy2(source, snapshot)
        for suffix in ("-wal", "-shm"):
            sidecar = root / f"analyzer.db{suffix}"
            if sidecar.exists():
                shutil.copy2(sidecar, snapshot_root / sidecar.name)
        db = sqlite3.connect(snapshot)
        try:
            db.execute("BEGIN")
            yield db
        finally:
            db.rollback()
            db.close()


def data_summary(root: Path) -> dict[str, Any]:
    inv = inventory(root)
    db_path = root / "analyzer.db"
    counts: dict[str, int | None] = {name: 0 for name in SUMMARY_TABLES}
    present_tables: list[str] = []
    if db_path.exists():
        with _database_snapshot(root) as db:
            assert db is not None
            present_tables = sorted(
                row[0]
                for row in db.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
                )
            )
            for label, table in SUMMARY_TABLES.items():
                if table in present_tables:
                    counts[label] = int(db.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0])
    return {
        "contract": "nct-fresh-install-summary:1",
        "database_present": db_path.exists(),
        "counts": counts,
        "database_table_count": len(present_tables),
        "file_count": inv["file_count"],
        "directory_count": inv["directory_count"],
        "symlink_count": inv["symlink_count"],
        "total_file_bytes": inv["total_file_bytes"],
        "inventory_digest": inv["inventory_digest"],
        "excluded_from_fresh_install": [
            "retained Nmap and imported scan evidence",
            "device collections and configuration evidence",
            "Arkime sources, receipts and retained results",
            "accounts and sessions",
            "Network Scopes, Saved Networks and Mission Environment declarations",
            "scan profiles, schedules and queue state",
            "notes, layouts, preferences and other settings",
            "unfinished work, recovery state and storage-maintenance state",
        ],
    }


def _validate_runtime(inspect_path: Path, data_source: str, mount_type: str) -> dict[str, Any]:
    inspected = json.loads(inspect_path.read_text(encoding="utf-8"))
    if isinstance(inspected, list):
        if len(inspected) != 1:
            raise FreshInstallError("container inspection must contain exactly one object")
        inspected = inspected[0]
    config = inspected.get("Config") or {}
    host = inspected.get("HostConfig") or {}
    configured_user = str(config.get("User") or "")
    if configured_user not in {"", "0", "0:0", "root"}:
        raise FreshInstallError("custom container users are not supported by fresh installation")
    if host.get("Privileged"):
        raise FreshInstallError("privileged NCT containers are not supported by fresh installation")
    mounts = inspected.get("Mounts") or []
    data_mounts = [item for item in mounts if item.get("Destination") == "/data"]
    if len(data_mounts) != 1:
        raise FreshInstallError("expected exactly one /data mount")
    actual = data_mounts[0]
    actual_source = actual.get("Name") if actual.get("Type") == "volume" else actual.get("Source")
    if actual.get("Type") != mount_type or actual_source != data_source:
        raise FreshInstallError("the inspected /data mount does not match the reviewed source")

    bootstrap_destinations = {"/run/nct-bootstrap"}
    for entry in config.get("Env") or []:
        name, _, value = str(entry).partition("=")
        if name == "NCT_BOOTSTRAP_PASSWORD_FILE" and value:
            bootstrap_destinations.add(value)

    retained_mounts: list[dict[str, str]] = []
    allowed_destinations = {"/run/tls/nct-server.crt", "/run/tls/nct-server.key"}
    for item in mounts:
        destination = item.get("Destination")
        if destination == "/data" or destination in bootstrap_destinations:
            continue
        if destination not in allowed_destinations or item.get("Type") != "bind" or item.get("RW"):
            raise FreshInstallError(f"unsupported non-data mount: {destination or 'unknown'}")
        retained_mounts.append(
            {"source": str(item.get("Source") or ""), "destination": destination, "mode": "ro"}
        )
    if {item["destination"] for item in retained_mounts} not in (set(), allowed_destinations):
        raise FreshInstallError("TLS certificate and key mounts must both be present or both absent")

    nct_env: dict[str, str] = {}
    omitted_env: list[str] = []
    allowed_env = {"NCT_AUTH_MODE", "NCT_SESSION_HOURS", "NCT_COOKIE_SECURE"}
    image_identity_env = {"NCT_APP_VERSION", "NCT_BUILD_COMMIT", "NCT_BUILD_ID"}
    for entry in config.get("Env") or []:
        name, _, value = str(entry).partition("=")
        if not name.startswith("NCT_"):
            continue
        if name in {"NCT_BOOTSTRAP_ADMIN", "NCT_BOOTSTRAP_PASSWORD_FILE", "NCT_BOOTSTRAP_PASSWORD"}:
            continue
        if name in allowed_env:
            nct_env[name] = value
        elif name not in image_identity_env:
            omitted_env.append(name)
    nct_env.setdefault("NCT_AUTH_MODE", "local")
    nct_env.setdefault("NCT_SESSION_HOURS", "12")
    nct_env.setdefault("NCT_COOKIE_SECURE", "1" if retained_mounts else "0")
    if nct_env["NCT_AUTH_MODE"] != "local":
        raise FreshInstallError(
            "fresh installation requires NCT_AUTH_MODE=local so the new Administrator can be verified"
        )

    bindings = host.get("PortBindings") or {}
    rendered_bindings: list[dict[str, str]] = []
    for container_port, entries in sorted(bindings.items()):
        for entry in entries or []:
            host_port = str(entry.get("HostPort") or "")
            host_ip = str(entry.get("HostIp") or "")
            if not host_port.isdigit() or not 1 <= int(host_port) <= 65535:
                raise FreshInstallError("saved host port is invalid")
            rendered_bindings.append(
                {"container": container_port, "host_ip": host_ip, "host_port": host_port}
            )
    if len(rendered_bindings) != 1:
        raise FreshInstallError("fresh installation requires exactly one saved web port binding")
    command = config.get("Cmd") or []
    if not isinstance(command, list) or "uvicorn" not in command or "app.main:app" not in command:
        raise FreshInstallError("saved NCT command is not the supported application command")
    entrypoint = config.get("Entrypoint") or []
    if entrypoint not in ([], None):
        raise FreshInstallError("custom container entrypoints are not supported")
    caps = sorted(
        str(capability).removeprefix("CAP_") for capability in (host.get("CapAdd") or [])
    )
    if any(capability not in {"NET_RAW"} for capability in caps):
        raise FreshInstallError("unsupported added Linux capability")
    network_mode = str(host.get("NetworkMode") or "default")
    if network_mode.startswith("container:") or network_mode in {"host", "none"}:
        raise FreshInstallError(f"unsupported network mode: {network_mode}")
    attached_networks = sorted(((inspected.get("NetworkSettings") or {}).get("Networks") or {}).keys())
    expected_network = "bridge" if network_mode == "default" else network_mode
    if attached_networks and attached_networks != [expected_network]:
        raise FreshInstallError("multiple or unexpected attached Docker networks are not supported")
    restart = host.get("RestartPolicy") or {}
    restart_name = str(restart.get("Name") or "no")
    restart_max = int(restart.get("MaximumRetryCount") or 0)
    if restart_name not in {"no", "always", "unless-stopped", "on-failure"}:
        raise FreshInstallError("unsupported restart policy")
    scheme = "https" if retained_mounts else "http"
    host_ip = rendered_bindings[0]["host_ip"]
    health_host = "127.0.0.1" if host_ip in {"", "0.0.0.0", "::"} else host_ip
    if ":" in health_host and not health_host.startswith("["):
        health_host = f"[{health_host}]"
    return {
        "hostname": str(config.get("Hostname") or ""),
        "environment": nct_env,
        "omitted_environment_names": sorted(set(omitted_env)),
        "command": command,
        "cap_add": caps,
        "security_opt": list(host.get("SecurityOpt") or []),
        "read_only_rootfs": bool(host.get("ReadonlyRootfs")),
        "network_mode": network_mode,
        "attached_networks": attached_networks,
        "port_bindings": rendered_bindings,
        "retained_mounts": retained_mounts,
        "tls_certificate_source": next(
            (item["source"] for item in retained_mounts if item["destination"].endswith(".crt")), ""
        ),
        "tls_key_source": next(
            (item["source"] for item in retained_mounts if item["destination"].endswith(".key")), ""
        ),
        "restart_policy": {"name": restart_name, "maximum_retry_count": restart_max},
        "health_url": f"{scheme}://{health_host}:{rendered_bindings[0]['host_port']}/health",
        "login_url": f"{scheme}://{health_host}:{rendered_bindings[0]['host_port']}/api/auth/login",
        "me_url": f"{scheme}://{health_host}:{rendered_bindings[0]['host_port']}/api/auth/me",
        "tls_treatment": "reuse exact read-only certificate and key mounts" if retained_mounts else "retain existing HTTP mode",
        "network_treatment": "reuse exact saved bind address, host port and Docker network",
        "integration_treatment": (
            "Do not carry prior connector, credential-file, automatic-collection or deployment-specific "
            "NCT environment settings into the blank installation; review them again after setup."
        ),
    }


def create_plan(args: argparse.Namespace) -> dict[str, Any]:
    runtime = _validate_runtime(args.inspect, args.data_source, args.mount_type)
    runtime["tls_certificate_sha256"] = getattr(args, "tls_certificate_sha256", "")
    runtime["tls_key_sha256"] = getattr(args, "tls_key_sha256", "")
    for name in ("tls_certificate_sha256", "tls_key_sha256"):
        digest = runtime[name]
        if digest and (len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest)):
            raise FreshInstallError(f"{name} must be an exact lowercase SHA-256 digest")
    summary = json.loads(args.summary.read_text(encoding="utf-8"))
    inventory_value = json.loads(args.inventory.read_text(encoding="utf-8"))
    plan = {
        "contract": "nct-explicit-fresh-install:1",
        "created_at": args.created_at,
        "container_name": args.container,
        "container_id": args.container_id,
        "prior_state": args.prior_state,
        "image_ref": args.image_ref,
        "image_id": args.image_id,
        "old_data": {"type": args.mount_type, "source": args.data_source},
        "new_data": {"type": args.mount_type, "source": args.new_data_source},
        "retained_old_container_name": args.retained_container,
        "backup": {"path": str(args.backup), "sha256": args.backup_sha256},
        "source_inventory_digest": inventory_value["inventory_digest"],
        "summary": summary,
        "runtime": runtime,
        "fresh_install_effect": (
            "The replacement starts with one new Administrator account and no inherited "
            "evidence, scopes, saved networks, profiles, schedules, notes or settings."
        ),
        "rollback_boundary": (
            "The stopped retained container, exact old image, old data source and verified "
            "backup remain unchanged for explicit rollback."
        ),
    }
    plan["plan_digest"] = _json_digest(plan)
    plan["confirmation"] = f"FRESH-{plan['plan_digest'][:12]}"
    return plan


def _restart_value(policy: dict[str, Any]) -> str:
    name = policy["name"]
    maximum = int(policy.get("maximum_retry_count") or 0)
    return f"on-failure:{maximum}" if name == "on-failure" and maximum else name


def render_create(
    plan: dict[str, Any], bootstrap: bool, admin: str, secret_path: str, docker_timeout: int
) -> str:
    runtime = plan["runtime"]
    if docker_timeout <= 0:
        raise FreshInstallError("Docker create timeout must be positive")
    command = [
        "timeout", "-k", "5", str(docker_timeout), "docker", "create",
        "--name", plan["container_name"], "--restart", "no",
    ]
    if runtime["hostname"]:
        command += ["--hostname", runtime["hostname"]]
    if runtime["network_mode"] not in {"default", "bridge"}:
        command += ["--network", runtime["network_mode"]]
    for capability in runtime["cap_add"]:
        command += ["--cap-add", capability]
    for option in runtime["security_opt"]:
        command += ["--security-opt", option]
    if runtime["read_only_rootfs"]:
        command.append("--read-only")
    for binding in runtime["port_bindings"]:
        prefix = f"{binding['host_ip']}:" if binding["host_ip"] else ""
        command += ["-p", f"{prefix}{binding['host_port']}:{binding['container']}"]
    data = plan["new_data"]
    command += ["-v", f"{data['source']}:/data"]
    for mount in runtime["retained_mounts"]:
        command += ["-v", f"{mount['source']}:{mount['destination']}:ro"]
    for name, value in sorted(runtime["environment"].items()):
        command += ["-e", f"{name}={value}"]
    if bootstrap:
        command += [
            "-e", f"NCT_BOOTSTRAP_ADMIN={admin}",
            "-e", "NCT_BOOTSTRAP_PASSWORD_FILE=/run/nct-fresh-bootstrap/password",
            "-v", f"{secret_path}:/run/nct-fresh-bootstrap/password:ro",
        ]
    command += [plan["image_id"], *runtime["command"]]
    return "#!/bin/sh\nset -eu\n" + " ".join(shlex.quote(part) for part in command) + "\n"


def load_plan(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    expected = value.pop("plan_digest", None)
    confirmation = value.pop("confirmation", None)
    if not isinstance(expected, str) or expected != _json_digest(value):
        raise FreshInstallError("plan digest does not match its content")
    if confirmation != f"FRESH-{expected[:12]}":
        raise FreshInstallError("plan confirmation does not match its digest")
    value["plan_digest"] = expected
    value["confirmation"] = confirmation
    return value


FRESH_ZERO_TABLES = (
    "network_scopes",
    "saved_networks",
    "scan_runs",
    "scan_schedules",
    "device_collections",
    "artifact_observations",
    "arkime_imports",
    "arkime_session_receipts",
    "arkime_summary_imports",
    "arkime_summary_receipts",
    "arkime_pull_profiles",
    "arkime_pull_runs",
    "analyst_investigation_notes",
    "analyst_workspace_layouts",
    "analyst_view_preferences",
    "pipeline_jobs",
    "pipeline_job_requests",
    "device_contact_runs",
    "device_scope_assignments",
    "endpoint_entities",
    "service_entities",
    "entity_assessments",
)


def verify_fresh(root: Path, admin: str) -> dict[str, Any]:
    db_path = root / "analyzer.db"
    if not db_path.is_file():
        raise FreshInstallError("fresh database was not initialized")
    with _database_snapshot(root) as db:
        assert db is not None
        integrity = db.execute("PRAGMA integrity_check").fetchone()[0]
        if integrity != "ok":
            raise FreshInstallError(f"fresh database integrity check failed: {integrity}")
        tables = {
            row[0]
            for row in db.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
            )
        }
        if "analyst_users" not in tables:
            raise FreshInstallError("fresh Administrator table is unavailable")
        users = db.execute(
            "SELECT username, role, disabled FROM analyst_users ORDER BY username"
        ).fetchall()
        if users != [(admin, "admin", 0)]:
            raise FreshInstallError("fresh installation does not contain exactly the new active Administrator")
        nonempty: dict[str, int] = {}
        for table in FRESH_ZERO_TABLES:
            if table in tables:
                count = int(db.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0])
                if count:
                    nonempty[table] = count
        if nonempty:
            raise FreshInstallError(f"fresh installation inherited operator data: {nonempty}")
    evidence_paths = [
        root / "imports",
        root / "artifacts",
        root / "device-configs",
        root / "arkime",
    ]
    inherited_files = sorted(
        path.relative_to(root).as_posix()
        for folder in evidence_paths
        if folder.exists()
        for path in folder.rglob("*")
        if path.is_file()
    )
    if inherited_files:
        raise FreshInstallError(f"fresh installation contains retained evidence files: {inherited_files[:5]}")
    return {
        "contract": "nct-explicit-fresh-install-verification:1",
        "database_integrity": "ok",
        "administrator": admin,
        "administrator_count": 1,
        "inherited_operator_rows": 0,
        "inherited_evidence_files": 0,
        "ready_for_first_sign_in": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="NCT explicit fresh-install support tool")
    sub = parser.add_subparsers(dest="command", required=True)
    inv = sub.add_parser("inventory")
    inv.add_argument("--root", type=Path, required=True)
    inv.add_argument("--output", type=Path)
    summary = sub.add_parser("summary")
    summary.add_argument("--root", type=Path, required=True)
    summary.add_argument("--output", type=Path)
    plan = sub.add_parser("plan")
    plan.add_argument("--inspect", type=Path, required=True)
    plan.add_argument("--summary", type=Path, required=True)
    plan.add_argument("--inventory", type=Path, required=True)
    plan.add_argument("--container", required=True)
    plan.add_argument("--container-id", required=True)
    plan.add_argument("--prior-state", required=True)
    plan.add_argument("--image-ref", required=True)
    plan.add_argument("--image-id", required=True)
    plan.add_argument("--mount-type", choices=("bind", "volume"), required=True)
    plan.add_argument("--data-source", required=True)
    plan.add_argument("--new-data-source", required=True)
    plan.add_argument("--retained-container", required=True)
    plan.add_argument("--backup", type=Path, required=True)
    plan.add_argument("--backup-sha256", required=True)
    plan.add_argument("--tls-certificate-sha256", default="")
    plan.add_argument("--tls-key-sha256", default="")
    plan.add_argument("--created-at", required=True)
    plan.add_argument("--output", type=Path)
    render = sub.add_parser("render-create")
    render.add_argument("--plan", type=Path, required=True)
    render.add_argument("--output", type=Path)
    render.add_argument("--admin", required=True)
    render.add_argument("--secret-path", required=True)
    render.add_argument("--bootstrap", action="store_true")
    render.add_argument("--docker-timeout", type=int, required=True)
    runtime = sub.add_parser("validate-runtime")
    runtime.add_argument("--plan", type=Path, required=True)
    runtime.add_argument("--inspect", type=Path, required=True)
    isolation = sub.add_parser("check-isolation")
    isolation.add_argument("--target-id", required=True)
    isolation.add_argument("--old-type", choices=("bind", "volume"), required=True)
    isolation.add_argument("--old-source", required=True)
    isolation.add_argument("--old-path", required=True)
    isolation.add_argument("--new-bind-path", default="")
    get = sub.add_parser("get")
    get.add_argument("--plan", type=Path, required=True)
    get.add_argument("--field", required=True)
    fresh = sub.add_parser("verify-fresh")
    fresh.add_argument("--root", type=Path, required=True)
    fresh.add_argument("--admin", required=True)
    fresh.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "inventory":
            _write_json(args.output, inventory(args.root))
        elif args.command == "summary":
            _write_json(args.output, data_summary(args.root))
        elif args.command == "plan":
            _write_json(args.output, create_plan(args))
        elif args.command == "render-create":
            value = load_plan(args.plan)
            rendered = render_create(
                value, args.bootstrap, args.admin, args.secret_path, args.docker_timeout
            )
            if args.output is None:
                print(rendered, end="")
            else:
                args.output.write_text(rendered, encoding="utf-8")
                args.output.chmod(0o700)
        elif args.command == "get":
            value: Any = load_plan(args.plan)
            for part in args.field.split("."):
                value = value[part]
            if isinstance(value, (dict, list)):
                print(json.dumps(value, sort_keys=True))
            else:
                print(value)
        elif args.command == "validate-runtime":
            value = load_plan(args.plan)
            actual = _validate_runtime(
                args.inspect, value["old_data"]["source"], value["old_data"]["type"]
            )
            expected = dict(value["runtime"])
            expected.pop("tls_certificate_sha256", None)
            expected.pop("tls_key_sha256", None)
            actual_restart = actual.pop("restart_policy")
            expected.pop("restart_policy")
            if actual_restart != {"name": "no", "maximum_retry_count": 0}:
                raise FreshInstallError("reviewed container is not held with restart disabled")
            if actual != expected:
                raise FreshInstallError("container runtime changed after preview")
            print("runtime-match")
        elif args.command == "check-isolation":
            inspected = json.load(os.fdopen(os.dup(0), "r", encoding="utf-8"))
            _write_json(
                None,
                check_isolation(
                    inspected, args.target_id, args.old_type, args.old_source,
                    args.old_path, args.new_bind_path,
                ),
            )
        elif args.command == "verify-fresh":
            _write_json(args.output, verify_fresh(args.root, args.admin))
        return 0
    except (FreshInstallError, OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        parser.exit(2, f"Fresh installation refused: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
