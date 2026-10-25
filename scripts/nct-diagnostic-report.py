#!/usr/bin/env python3
"""Build a bounded, read-only NCT host diagnostic report.

This helper runs through the exact local NCT image.  The operator shell wrapper
mounts its private probe directory and NCT data read-only, while the output
directory is the only writable mount.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import shutil
import sqlite3
import time
from typing import Any


MAX_LOG_BYTES = 256 * 1024
MAX_LOG_LINES = 400
SQL_DEADLINE_SECONDS = 10.0
ACTIVE_DATABASE_STATES = (
    ("scan_runs", "status", ("queued", "dispatching", "running", "awaiting_fallback_approval")),
    ("pipeline_job_attempts", "state", ("queued", "running")),
    ("pipeline_admission_intents", "state", ("pending", "waiting", "retrying", "paused")),
    ("scan_foundation_processing_attempts", "status", ("running",)),
    ("device_contact_runs", "state", ("waiting", "preparing", "contact_starting", "contact_active", "needs_attention")),
    ("device_contact_attempts", "state", ("preparing", "contact_starting", "contact_active", "needs_attention")),
    ("scan_schedule_occurrences", "state", ("waiting", "preparing", "active", "needs_attention")),
    ("scan_schedule_chunks", "state", ("waiting", "preparing", "active", "needs_attention")),
    ("work_leases", "state", ("active", "recovery_required")),
    ("artifact_compaction_journal", "state", ("preparing", "prepared", "replaced", "verified", "recovery-required")),
)
LOG_SIGNALS = {
    "error": re.compile(r"(?i)\b(error|exception|traceback|failed|failure)\b"),
    "warning": re.compile(r"(?i)\b(warn(?:ing)?|degraded)\b"),
    "startup": re.compile(r"(?i)\b(starting|startup|started)\b"),
    "shutdown": re.compile(r"(?i)\b(stopping|shutdown|stopped|exiting)\b"),
    "database_locked": re.compile(r"(?i)database\s+is\s+locked"),
    "out_of_memory": re.compile(r"(?i)\b(out of memory|oom(?:[_ -]?killed)?)\b"),
    "restart": re.compile(r"(?i)\brestart(?:ed|ing|s)?\b"),
    "migration": re.compile(r"(?i)\b(migrat(?:e|ed|ing|ion)|schema)\b"),
    "scan_queue": re.compile(r"(?i)\b(scan|queue|schedule|dispatch)\b"),
}
SENSITIVE_LOG_SIGNAL = re.compile(
    r"(?i)(authorization|password|passwd|token|secret|api[_-]?key|cookie|session|"
    r"private\s+key|BEGIN\s+[A-Z ]*PRIVATE\s+KEY|https?://[^\s/:@]+:[^\s/@]+@)"
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def read_text(path: Path, limit: int = MAX_LOG_BYTES) -> str:
    if not path.exists() or not path.is_file():
        return ""
    data = path.read_bytes()[: limit + 1]
    if len(data) > limit:
        data = data[:limit] + b"\n[diagnostic input truncated]\n"
    return data.decode("utf-8", errors="replace")


def read_json(path: Path, default: Any) -> Any:
    text = read_text(path)
    if not text:
        return default
    try:
        return json.loads(text)
    except (TypeError, ValueError):
        return default


def read_key_values(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in read_text(path, 64 * 1024).splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        if re.fullmatch(r"[A-Z0-9_]+", key):
            values[key] = value.strip()
    return values


def summarize_logs(text: str) -> dict[str, Any]:
    """Return bounded signal counts without retaining arbitrary log content."""
    all_lines = text.splitlines()
    lines = all_lines[-MAX_LOG_LINES:]
    return {
        "raw_lines_retained": False,
        "lines_observed": len(lines),
        "earlier_lines_omitted": max(0, len(all_lines) - len(lines)),
        "sensitive_lines_observed": sum(bool(SENSITIVE_LOG_SIGNAL.search(line)) for line in lines),
        "signal_counts": {
            name: sum(bool(pattern.search(line)) for line in lines)
            for name, pattern in LOG_SIGNALS.items()
        },
    }


def _tables(connection: sqlite3.Connection) -> set[str]:
    return {
        str(row[0])
        for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
    }


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def stable_database_snapshot(data_root: Path, snapshot_root: Path) -> tuple[Path | None, str | None]:
    """Copy SQLite files without opening the retained database and verify stability."""
    names = ("analyzer.db", "analyzer.db-wal", "analyzer.db-journal")
    present = tuple(name for name in names if (data_root / name).is_file())
    if "analyzer.db" not in present:
        return None, "analyzer.db is not present"
    snapshot_root.mkdir(mode=0o700, parents=True, exist_ok=False)
    try:
        for name in present:
            shutil.copyfile(data_root / name, snapshot_root / name)
            (snapshot_root / name).chmod(0o600)
        first_names = tuple(name for name in names if (data_root / name).is_file())
        first = {name: _sha256(data_root / name) for name in first_names}
        second_names = tuple(name for name in names if (data_root / name).is_file())
        second = {name: _sha256(data_root / name) for name in second_names}
        copied = {name: _sha256(snapshot_root / name) for name in present}
        if first_names != present or second_names != present or first != second or copied != second:
            return None, "database files changed while the read-only snapshot was copied"
        return snapshot_root, None
    except OSError as exc:
        return None, f"database snapshot unavailable: {exc.__class__.__name__}"


def _bounded_query(
    connection: sqlite3.Connection,
    sql: str,
    parameters: tuple = (),
    *,
    max_rows: int = 1_001,
) -> tuple[list[tuple], bool]:
    deadline = time.monotonic() + SQL_DEADLINE_SECONDS

    def stop_when_expired() -> int:
        return 1 if time.monotonic() >= deadline else 0

    connection.set_progress_handler(stop_when_expired, 5_000)
    try:
        cursor = connection.execute(sql, parameters)
        rows = cursor.fetchmany(max_rows + 1)
        return rows[:max_rows], len(rows) > max_rows
    finally:
        connection.set_progress_handler(None, 0)


def database_report(data_root: Path) -> dict[str, Any]:
    db_path = data_root / "analyzer.db"
    related = {}
    for name in ("analyzer.db", "analyzer.db-wal", "analyzer.db-shm", "analyzer.db-journal"):
        path = data_root / name
        related[name] = path.stat().st_size if path.exists() and path.is_file() else None
    result: dict[str, Any] = {
        "status": "not_checked",
        "reason": "analyzer.db is not present",
        "files": related,
        "quick_check": None,
        "foreign_key_errors": None,
        "unfinished_work": None,
        "summary_counts": None,
    }
    if not db_path.exists():
        return result
    try:
        uri = f"file:{db_path.as_posix()}?mode=ro"
        connection = sqlite3.connect(uri, uri=True, timeout=2)
        connection.execute("PRAGMA query_only=ON")
        try:
            connection.execute("BEGIN")
            tables = _tables(connection)
            quick, quick_truncated = _bounded_query(connection, "PRAGMA quick_check(1)", max_rows=1)
            foreign, foreign_truncated = _bounded_query(
                connection, "PRAGMA foreign_key_check", max_rows=1_000
            )
            unfinished: list[dict[str, Any]] = []
            for table, column, states in ACTIVE_DATABASE_STATES:
                if table not in tables:
                    continue
                if table == "pipeline_admission_intents":
                    rows, _ = _bounded_query(
                        connection,
                        "SELECT state, activity_state, COUNT(*) FROM pipeline_admission_intents "
                        "WHERE state='pending' OR activity_state IN ('waiting','retrying','paused') "
                        "GROUP BY state, activity_state ORDER BY state, activity_state",
                    )
                    for state, activity_state, count in rows:
                        unfinished.append({
                            "table": table,
                            "state": f"{state}/{activity_state}",
                            "count": int(count),
                        })
                    continue
                placeholders = ",".join("?" for _ in states)
                rows, _ = _bounded_query(
                    connection,
                    f'SELECT "{column}", COUNT(*) FROM "{table}" '
                    f'WHERE "{column}" IN ({placeholders}) GROUP BY "{column}" ORDER BY "{column}"',
                    tuple(states),
                )
                unfinished.extend(
                    {"table": table, "state": str(state), "count": int(count)}
                    for state, count in rows
                )
            count_tables = {
                "analyst_accounts": "analyst_users",
                "scan_runs": "scan_runs",
                "scan_schedules": "scan_schedules",
                "device_collections": "device_config_runs",
                "saved_networks": "saved_networks",
                "network_scopes": "network_scopes",
                "registered_artifacts": "artifact_registry",
            }
            summaries = {}
            for label, table in count_tables.items():
                if table in tables:
                    count_rows, _ = _bounded_query(
                        connection, f'SELECT COUNT(*) FROM "{table}"', max_rows=1
                    )
                    summaries[label] = int(count_rows[0][0])
            result.update(
                status="ok" if quick == [("ok",)] and not quick_truncated and not foreign else "needs_attention",
                reason=None if quick == [("ok",)] and not quick_truncated and not foreign else "database validation reported a problem",
                quick_check=quick[0][0] if quick else "unavailable",
                foreign_key_errors=len(foreign),
                foreign_key_errors_truncated=foreign_truncated,
                unfinished_work=unfinished,
                summary_counts=summaries,
            )
        finally:
            if connection.in_transaction:
                connection.rollback()
            connection.close()
    except sqlite3.Error as exc:
        result.update(status="not_checked", reason=f"read-only database inspection unavailable: {exc.__class__.__name__}")
    except (OSError, ValueError) as exc:
        result.update(status="not_checked", reason=f"database inspection unavailable: {exc.__class__.__name__}")
    return result


def safe_mounts(items: Any) -> list[dict[str, Any]]:
    if not isinstance(items, list):
        return []
    safe = []
    for item in items[:100]:
        if not isinstance(item, dict):
            continue
        safe.append({
            "type": item.get("Type"),
            "source": item.get("Name") if item.get("Type") == "volume" else item.get("Source"),
            "destination": item.get("Destination"),
            "read_only": not bool(item.get("RW", False)),
        })
    return safe


def safe_ports(value: Any) -> dict[str, list[dict[str, str]]]:
    if not isinstance(value, dict):
        return {}
    result = {}
    for container_port, bindings in list(value.items())[:100]:
        if not isinstance(bindings, list):
            continue
        result[str(container_port)] = [
            {"host_ip": str(item.get("HostIp", "")), "host_port": str(item.get("HostPort", ""))}
            for item in bindings[:20]
            if isinstance(item, dict)
        ]
    return result


def state_changed(before: dict[str, str], after: dict[str, str]) -> bool:
    keys = ("CONTAINER_ID", "STATE", "RESTART_COUNT", "STARTED_AT", "FINISHED_AT")
    return any(before.get(key) != after.get(key) for key in keys)


def status_label(report: dict[str, Any]) -> str:
    if report["collection"]["state_changed_during_report"]:
        return "partial"
    if report["database"]["status"] != "ok":
        return "partial" if report["database"]["status"] == "not_checked" else "needs_attention"
    if report["database"].get("unfinished_work"):
        return "needs_attention"
    return "complete"


def next_step(report: dict[str, Any]) -> str:
    state = report["container"].get("state", "unknown")
    health = report["container"].get("health", "unknown")
    container_name = report["container"].get("name") or "nct"
    installed_recovery = (
        "sh scripts/nct-recover-installed.sh --container " + container_name
    )
    unfinished_repair = (
        "sh scripts/nct-reset-unfinished.sh --container " + container_name
    )
    database = report["database"]
    if state == "restarting":
        return "Do not repeatedly restart or remove NCT. Preserve this report, then preview the exact installed-build recovery: " + installed_recovery
    if report["collection"]["state_changed_during_report"]:
        return "The container changed while the report was collected. Preserve this report and rerun once before choosing a recovery action."
    if database["status"] == "needs_attention" or database.get("unfinished_work"):
        return "Preserve this report. Preview the evidence-preserving unfinished-work repair: " + unfinished_repair
    if database["status"] == "not_checked":
        return "The database check was unavailable. Preserve this partial report and keep NCT data unchanged. Preview " + installed_recovery + "; it must stop rather than bypass an unreadable work check."
    if state == "running" and health in {"healthy", "none", "unknown"}:
        return "Preserve this report and continue normal investigation. A reset is not recommended from this result."
    if state == "running":
        return "NCT is running but not healthy. Preserve this report, then preview " + installed_recovery + "; do not restart blindly."
    if state in {"exited", "dead", "created", "paused"}:
        return "Do not delete, rename or recreate the container or its data. Preserve this report, then preview " + installed_recovery + "."
    return "Some checks were unavailable. Preserve this partial report and rerun with approved administrator access or provide it to the Range administrator."


def render_text(report: dict[str, Any]) -> str:
    container = report["container"]
    database = report["database"]
    storage = report["storage"]
    work = database.get("unfinished_work")
    unfinished = "Not checked — " + database.get("reason", "unavailable") if work is None else (
        "Needs attention — " + ", ".join(f"{item['table']} {item['state']}: {item['count']}" for item in work)
        if work else "OK — no known unfinished work states"
    )
    db_text = (
        "OK — read-only quick check and foreign keys passed"
        if database["status"] == "ok"
        else ("Needs attention — " if database["status"] == "needs_attention" else "Not checked — ")
        + str(database.get("reason") or "unavailable")
    )
    port_text = json.dumps(container.get("ports", {}), sort_keys=True) if container.get("ports") else "Not checked or no saved bindings"
    mount_text = json.dumps(container.get("data_mount"), sort_keys=True) if container.get("data_mount") else "Not checked"
    disk = storage.get("filesystem")
    disk_text = "Not checked"
    if isinstance(disk, dict):
        disk_text = f"{disk['free_bytes']} bytes free of {disk['total_bytes']}"
    host_disk = storage.get("host_report_filesystem") or []
    host_disk_text = "Not checked" if not host_disk else " | ".join(host_disk[-2:])
    lines = [
        "NCT READ-ONLY DIAGNOSTIC REPORT",
        "",
        "What happened",
        "-------------",
        f"Report completeness: {report['collection']['completeness']}",
        "This command did not restart, reset, repair or change NCT.",
        "",
        "What is safe to do next",
        "-----------------------",
        report["collection"]["next_step"],
        "",
        "Operator summary",
        "----------------",
        f"Container: {container.get('name', 'unknown')}",
        f"State: {container.get('state', 'unknown')}",
        f"Health: {container.get('health', 'unknown')}",
        f"Image ID: {container.get('image_id', 'unknown')}",
        f"Build: {report['build'].get('build_id') or 'unavailable'} · {report['build'].get('build_commit') or 'unavailable'}",
        f"HTTPS port: {port_text}",
        f"Data storage: {mount_text}",
        f"Disk space: {disk_text}",
        f"Host report storage: {host_disk_text}",
        f"Database check: {db_text}",
        f"Unfinished work: {unfinished}",
        "",
        "Privacy",
        "-------",
        "Passwords, tokens, environment values, private keys, raw device configurations, raw retained evidence and raw database rows are excluded.",
        "Raw log text is not retained. Only bounded signal counts are included. Host paths, container names, IP addresses and work timestamps may still be sensitive. Review this report before sharing it.",
        "The report stayed on this host; nothing was uploaded.",
        "",
        "Technical details (JSON)",
        "------------------------",
        json.dumps(report, indent=2, sort_keys=True),
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--probe-dir", type=Path, required=True)
    parser.add_argument("--data-root", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--container")
    parser.add_argument("--database-only-output", type=Path)
    parser.add_argument("--database-input", type=Path)
    args = parser.parse_args()
    probe = args.probe_dir.resolve()
    if args.database_only_output:
        database_output = args.database_only_output.resolve()
        snapshot_root = database_output.parent / ".database-snapshot"
        report: dict[str, Any]
        try:
            snapshot, reason = stable_database_snapshot(args.data_root, snapshot_root)
            if snapshot is None:
                report = {
                    "status": "not_checked",
                    "reason": reason,
                    "files": {
                        name: (args.data_root / name).stat().st_size
                        if (args.data_root / name).is_file() else None
                        for name in ("analyzer.db", "analyzer.db-wal", "analyzer.db-shm", "analyzer.db-journal")
                    },
                    "quick_check": None,
                    "foreign_key_errors": None,
                    "unfinished_work": None,
                    "summary_counts": None,
                }
            else:
                report = database_report(snapshot)
        finally:
            shutil.rmtree(snapshot_root, ignore_errors=True)
        database_output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        database_output.chmod(0o600)
        return 0
    if not args.output or not args.container:
        parser.error("--output and --container are required unless --database-only-output is used")
    output = args.output.resolve()
    output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    before = read_key_values(probe / "container-before.env")
    after = read_key_values(probe / "container-after.env")
    mounts = safe_mounts(read_json(probe / "mounts.json", []))
    data_mounts = [item for item in mounts if item.get("destination") == "/data"]
    ports = safe_ports(read_json(probe / "ports.json", {}))
    restart_policy = read_json(probe / "restart-policy.json", {})
    try:
        disk = shutil.disk_usage(args.data_root)
        filesystem = {"total_bytes": disk.total, "used_bytes": disk.used, "free_bytes": disk.free}
    except OSError:
        filesystem = None
    try:
        from app.build_info import APP_VERSION, BUILD_COMMIT, BUILD_ID
        build = {"application_version": APP_VERSION, "build_id": BUILD_ID, "build_commit": BUILD_COMMIT}
    except Exception:
        build = {"application_version": None, "build_id": None, "build_commit": None}
    retained_database = (
        read_json(args.database_input.resolve(), None)
        if args.database_input else None
    )
    if not isinstance(retained_database, dict):
        retained_database = database_report(args.data_root)
    report: dict[str, Any] = {
        "report_contract": "nct-read-only-diagnostic:1",
        "collected_at": utc_now(),
        "container": {
            "name": args.container,
            "container_id": before.get("CONTAINER_ID"),
            "state": before.get("STATE", "unknown"),
            "health": before.get("HEALTH", "unknown"),
            "restart_count": int(before.get("RESTART_COUNT", "0") or 0),
            "exit_code": before.get("EXIT_CODE"),
            "oom_killed": before.get("OOM_KILLED"),
            "started_at": before.get("STARTED_AT"),
            "finished_at": before.get("FINISHED_AT"),
            "image_id": before.get("IMAGE_ID"),
            "restart_policy": restart_policy,
            "ports": ports,
            "data_mount": data_mounts[0] if len(data_mounts) == 1 else None,
            "data_mount_count": len(data_mounts),
        },
        "build": build,
        "storage": {
            "filesystem": filesystem,
            "host_report_filesystem": read_text(
                probe / "host-disk.txt", 16 * 1024
            ).splitlines(),
            "database_files": {
                name: (args.data_root / name).stat().st_size
                if (args.data_root / name).exists() and (args.data_root / name).is_file() else None
                for name in ("analyzer.db", "analyzer.db-wal", "analyzer.db-shm", "analyzer.db-journal")
            },
        },
        "database": retained_database,
        "logs": summarize_logs(read_text(probe / "logs.raw")),
        "collection": {
            "probe_errors": read_text(probe / "probe-errors.txt", 64 * 1024).splitlines(),
            "state_changed_during_report": state_changed(before, after),
            "container_after": {
                key.lower(): after.get(key)
                for key in ("CONTAINER_ID", "STATE", "RESTART_COUNT", "STARTED_AT", "FINISHED_AT")
            },
            "docker_version": read_text(probe / "docker-version.txt", 16 * 1024).strip() or None,
        },
    }
    report["collection"]["completeness"] = status_label(report)
    report["collection"]["next_step"] = next_step(report)
    text = render_text(report)
    output.write_text(text, encoding="utf-8")
    output.chmod(0o600)
    json_path = output.with_suffix(".json")
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    json_path.chmod(0o600)
    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    checksum_path = output.with_suffix(output.suffix + ".sha256")
    checksum_path.write_text(f"{digest}  {output}\n", encoding="ascii")
    checksum_path.chmod(0o600)
    print(json.dumps({
        "report": str(output),
        "json": str(json_path),
        "checksum": str(checksum_path),
        "sha256": digest,
        "size_bytes": output.stat().st_size,
        "completeness": report["collection"]["completeness"],
        "next_step": report["collection"]["next_step"],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
