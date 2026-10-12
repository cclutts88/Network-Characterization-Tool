"""Bounded, side-effect-free live health measurements for System Health."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import shutil
import sqlite3
import threading
import time

from app.database import connect_database
from app.kubernetes_health_client import kubernetes_health_snapshot


_CGROUP_ROOT = Path("/sys/fs/cgroup")
_PROC_STATUS = Path("/proc/self/status")
_MAX_KERNEL_FILE_BYTES = 64 * 1024
_WORKLOAD_QUERY_BUDGET_SECONDS = 0.05
_ATTEMPT_STATES = ("queued", "running", "completed", "failed", "interrupted")
_INTAKE_STATES = ("waiting", "retrying", "paused", "complete", "needs_scope", "blocked")


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _unavailable(*, scope: str, unit: str, source: str) -> dict:
    return {"status": "unavailable", "scope": scope, "unit": unit, "source": source}


def _read_fixed_text(path: Path, limit: int = _MAX_KERNEL_FILE_BYTES) -> str | None:
    try:
        with path.open("r", encoding="utf-8", errors="strict") as handle:
            value = handle.read(limit + 1)
    except (OSError, UnicodeError):
        return None
    return value if len(value) <= limit else None


def _positive_int(text: str | None) -> int | None:
    try:
        value = int((text or "").strip())
    except (TypeError, ValueError):
        return None
    return value if value >= 0 else None


def _process_memory() -> dict:
    scope = "NCT application process"
    source = "Linux process status"
    text = _read_fixed_text(_PROC_STATUS)
    if text is None:
        return _unavailable(scope=scope, unit="bytes", source=source)
    values: dict[str, int] = {}
    for line in text.splitlines():
        name, separator, raw = line.partition(":")
        if not separator or name not in {"VmRSS", "VmHWM"}:
            continue
        fields = raw.strip().split()
        if len(fields) != 2 or fields[1].lower() != "kb":
            continue
        parsed = _positive_int(fields[0])
        if parsed is not None:
            values[name] = parsed * 1024
    if "VmRSS" not in values or "VmHWM" not in values:
        return _unavailable(scope=scope, unit="bytes", source=source)
    return {
        "status": "available",
        "scope": scope,
        "unit": "bytes",
        "source": source,
        "current_bytes": values["VmRSS"],
        "peak_bytes": values["VmHWM"],
    }


def _container_memory() -> dict:
    scope = "Current Linux control group"
    source = "Linux cgroup v2 memory files"
    current = _positive_int(_read_fixed_text(_CGROUP_ROOT / "memory.current", 4096))
    peak = _positive_int(_read_fixed_text(_CGROUP_ROOT / "memory.peak", 4096))
    maximum_text = _read_fixed_text(_CGROUP_ROOT / "memory.max", 4096)
    if current is None:
        return _unavailable(scope=scope, unit="bytes", source=source)
    maximum = None if (maximum_text or "").strip() == "max" else _positive_int(maximum_text)
    result = {
        "status": "available",
        "scope": scope,
        "unit": "bytes",
        "source": source,
        "current_bytes": current,
        "peak_bytes": peak,
        "limit_bytes": maximum,
        "limited": maximum is not None,
    }
    return result


def _container_cpu_usage_seconds() -> float | None:
    text = _read_fixed_text(_CGROUP_ROOT / "cpu.stat", 4096)
    if text is None:
        return None
    for line in text.splitlines():
        fields = line.split()
        if len(fields) == 2 and fields[0] == "usage_usec":
            value = _positive_int(fields[1])
            return value / 1_000_000 if value is not None else None
    return None


def _container_cpu_allowance() -> float | None:
    text = _read_fixed_text(_CGROUP_ROOT / "cpu.max", 4096)
    fields = text.split() if text else []
    if len(fields) != 2 or fields[0] == "max":
        return None
    quota = _positive_int(fields[0])
    period = _positive_int(fields[1])
    if quota is None or not period:
        return None
    return quota / period


def _filesystem_measurement(data_dir: Path) -> dict:
    scope = "Filesystem containing retained NCT data"
    source = "Filesystem capacity statistics"
    try:
        usage = shutil.disk_usage(data_dir)
    except OSError:
        return _unavailable(scope=scope, unit="bytes", source=source)
    return {
        "status": "available",
        "scope": scope,
        "unit": "bytes",
        "source": source,
        "total_bytes": usage.total,
        "used_bytes": usage.used,
        "available_bytes": usage.free,
    }


def _database_measurement(db_path: Path) -> dict:
    scope = "SQLite database and its WAL/SHM side files"
    source = "Fixed database-file metadata"
    total = 0
    present = 0
    for path in (db_path, Path(str(db_path) + "-wal"), Path(str(db_path) + "-shm")):
        try:
            if path.is_file():
                total += path.stat().st_size
                present += 1
        except OSError:
            return _unavailable(scope=scope, unit="bytes", source=source)
    return {
        "status": "available",
        "scope": scope,
        "unit": "bytes",
        "source": source,
        "total_bytes": total,
        "files_present": present,
    }


def _workload_measurement(db_path: Path) -> dict:
    scope = "Saved analysis attempts and intake activity"
    source = "Time-bounded read-only SQLite aggregate"
    unavailable = _unavailable(scope=scope, unit="records", source=source)
    if not db_path.is_file():
        return unavailable
    deadline = time.monotonic() + _WORKLOAD_QUERY_BUDGET_SECONDS
    connection = None
    try:
        connection = connect_database(
            db_path,
            read_only=True,
            busy_timeout_ms=25,
        )
        connection.execute("PRAGMA query_only = ON")

        def stop_when_over_budget() -> int:
            return int(time.monotonic() > deadline)

        connection.set_progress_handler(stop_when_over_budget, 100)
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' "
                "AND name IN ('pipeline_job_attempts','pipeline_admission_intents')"
            )
        }
        if tables != {"pipeline_job_attempts", "pipeline_admission_intents"}:
            return unavailable
        attempts = {state: 0 for state in _ATTEMPT_STATES}
        for state, count in connection.execute(
            "SELECT state, COUNT(*) FROM pipeline_job_attempts "
            "WHERE state IN ('queued','running','completed','failed','interrupted') "
            "GROUP BY state"
        ):
            if state in attempts:
                attempts[state] = int(count)
        intake = {state: 0 for state in _INTAKE_STATES}
        for state, count in connection.execute(
            "SELECT activity_state, COUNT(*) FROM pipeline_admission_intents "
            "WHERE activity_state IN "
            "('waiting','retrying','paused','complete','needs_scope','blocked') "
            "GROUP BY activity_state"
        ):
            if state in intake:
                intake[state] = int(count)
        if time.monotonic() > deadline:
            return unavailable
        return {
            "status": "available",
            "scope": scope,
            "unit": "records",
            "source": source,
            "attempts": attempts,
            "intake": intake,
        }
    except (OSError, sqlite3.Error):
        return unavailable
    finally:
        if connection is not None:
            connection.close()


class LocalRuntimeHealthProvider:
    """Samples local process and cgroup CPU without persisting measurement state."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._last_process: tuple[float, float] | None = None
        self._last_container: tuple[float, float] | None = None

    @staticmethod
    def _cpu_result(
        *, previous: tuple[float, float] | None, now: float, used: float | None,
        scope: str, source: str, allowance: float | None = None,
    ) -> tuple[dict, tuple[float, float] | None]:
        base = {"scope": scope, "unit": "percent", "source": source}
        if used is None:
            return {"status": "unavailable", **base}, previous
        current = (now, used)
        if previous is None or now <= previous[0] or used < previous[1]:
            return {"status": "warming_up", **base}, current
        elapsed = now - previous[0]
        if elapsed < 0.01:
            return {"status": "warming_up", **base}, current
        percent_one_cpu = max(0.0, (used - previous[1]) / elapsed * 100)
        result = {
            "status": "available",
            **base,
            "percent_of_one_cpu": round(percent_one_cpu, 1),
            "sample_interval_seconds": round(elapsed, 3),
        }
        if allowance is not None and allowance > 0:
            result["allowance_cpus"] = round(allowance, 3)
            result["percent_of_allowance"] = round(percent_one_cpu / allowance, 1)
        else:
            result["allowance_cpus"] = None
            result["percent_of_allowance"] = None
        return result, current

    def snapshot(self, db_path: Path, data_dir: Path) -> dict:
        with self._lock:
            now = time.monotonic()
            process_used = time.process_time()
            container_used = _container_cpu_usage_seconds()
            allowance = _container_cpu_allowance()
            process_cpu, self._last_process = self._cpu_result(
                previous=self._last_process,
                now=now,
                used=process_used,
                scope="NCT application process",
                source="Process CPU clock over a monotonic interval",
            )
            container_cpu, self._last_container = self._cpu_result(
                previous=self._last_container,
                now=now,
                used=container_used,
                scope="Current Linux control group",
                source="Linux cgroup v2 CPU usage over a monotonic interval",
                allowance=allowance,
            )
        measurements = {
            "process_cpu": process_cpu,
            "process_memory": _process_memory(),
            "container_cpu": container_cpu,
            "container_memory": _container_memory(),
            "data_filesystem": _filesystem_measurement(Path(data_dir)),
            "database_files": _database_measurement(Path(db_path)),
        }
        workload = _workload_measurement(Path(db_path))
        states = [item["status"] for item in measurements.values()] + [workload["status"]]
        overall = "available" if all(state == "available" for state in states) else "partial"
        return {
            "status": overall,
            "provider": "local",
            "sampled_at": _utc_now(),
            "sample_age_seconds": 0,
            "refresh_after_seconds": 5,
            "measurements": measurements,
            "workload": workload,
            "orchestrator": kubernetes_health_snapshot(),
        }


_LOCAL_PROVIDER = LocalRuntimeHealthProvider()


def runtime_health_snapshot(db_path: Path, data_dir: Path) -> dict:
    return _LOCAL_PROVIDER.snapshot(Path(db_path), Path(data_dir))
