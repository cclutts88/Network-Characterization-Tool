from __future__ import annotations

import json
from pathlib import Path
import sqlite3

import app.runtime_health as runtime_health


def _health_tables(db_path: Path) -> None:
    with sqlite3.connect(db_path) as db:
        db.executescript(
            """
            CREATE TABLE pipeline_job_attempts (
                job_id TEXT NOT NULL, attempt_number INTEGER NOT NULL,
                state TEXT NOT NULL, requested_by TEXT NOT NULL
            );
            CREATE TABLE pipeline_admission_intents (activity_state TEXT NOT NULL);
            CREATE TABLE work_leases (state TEXT NOT NULL);
            INSERT INTO pipeline_job_attempts VALUES
                ('job-1', 1, 'queued', 'alice'),
                ('job-2', 1, 'running', 'bob'),
                ('job-3', 1, 'failed', 'carol');
            INSERT INTO pipeline_admission_intents VALUES ('waiting'), ('retrying'), ('complete');
            """
        )


def test_first_cpu_sample_warms_then_reports_monotonic_delta(monkeypatch, tmp_path):
    provider = runtime_health.LocalRuntimeHealthProvider()
    times = iter([10.0, 15.0])
    process = iter([2.0, 3.0])
    container = iter([4.0, 6.0])
    monkeypatch.setattr(runtime_health.time, "monotonic", lambda: next(times))
    monkeypatch.setattr(runtime_health.time, "process_time", lambda: next(process))
    monkeypatch.setattr(runtime_health, "_container_cpu_usage_seconds", lambda: next(container))
    monkeypatch.setattr(runtime_health, "_container_cpu_allowance", lambda: 2.0)
    monkeypatch.setattr(runtime_health, "_process_memory", lambda: {"status": "available"})
    monkeypatch.setattr(runtime_health, "_container_memory", lambda: {"status": "available"})
    monkeypatch.setattr(runtime_health, "_filesystem_measurement", lambda _path: {"status": "available"})
    monkeypatch.setattr(runtime_health, "_database_measurement", lambda _path: {"status": "available"})
    monkeypatch.setattr(runtime_health, "_workload_measurement", lambda _path: {"status": "available"})

    first = provider.snapshot(tmp_path / "missing.db", tmp_path)
    second = provider.snapshot(tmp_path / "missing.db", tmp_path)

    assert first["measurements"]["process_cpu"]["status"] == "warming_up"
    assert first["measurements"]["container_cpu"]["status"] == "warming_up"
    assert second["measurements"]["process_cpu"]["percent_of_one_cpu"] == 20.0
    assert second["measurements"]["container_cpu"]["percent_of_one_cpu"] == 40.0
    assert second["measurements"]["container_cpu"]["percent_of_allowance"] == 20.0


def test_unavailable_cgroup_metrics_are_not_reported_as_zero(monkeypatch):
    monkeypatch.setattr(runtime_health, "_read_fixed_text", lambda *_args, **_kwargs: None)
    assert runtime_health._container_memory()["status"] == "unavailable"
    assert runtime_health._container_cpu_usage_seconds() is None
    assert runtime_health._container_cpu_allowance() is None


def test_cgroup_v1_container_metrics_support_explicit_root_controller_paths(
    monkeypatch, tmp_path,
):
    cgroup = tmp_path / "cgroup"
    memory = cgroup / "memory"
    cpu = cgroup / "cpu,cpuacct"
    memory.mkdir(parents=True)
    cpu.mkdir(parents=True)
    (memory / "memory.usage_in_bytes").write_text("1048576\n", encoding="utf-8")
    (memory / "memory.max_usage_in_bytes").write_text("2097152\n", encoding="utf-8")
    (memory / "memory.limit_in_bytes").write_text("4194304\n", encoding="utf-8")
    (cpu / "cpuacct.usage").write_text("2500000000\n", encoding="utf-8")
    (cpu / "cpu.cfs_quota_us").write_text("200000\n", encoding="utf-8")
    (cpu / "cpu.cfs_period_us").write_text("100000\n", encoding="utf-8")
    proc_cgroup = tmp_path / "self.cgroup"
    proc_cgroup.write_text("5:memory:/\n4:cpu,cpuacct:/\n", encoding="utf-8")
    monkeypatch.setattr(runtime_health, "_CGROUP_ROOT", cgroup)
    monkeypatch.setattr(runtime_health, "_PROC_SELF_CGROUP", proc_cgroup)

    result = runtime_health._container_memory()

    assert result["status"] == "available"
    assert result["current_bytes"] == 1048576
    assert result["peak_bytes"] == 2097152
    assert result["limit_bytes"] == 4194304
    assert result["limited"] is True
    assert result["source"] == "Linux control-group memory files"
    assert runtime_health._container_cpu_usage_seconds() == 2.5
    assert runtime_health._container_cpu_allowance() == 2.0


def test_cgroup_v1_container_metrics_follow_kernel_reported_relative_path(
    monkeypatch, tmp_path,
):
    cgroup = tmp_path / "cgroup"
    memory = cgroup / "memory" / "docker" / "container-id"
    cpu = cgroup / "cpu,cpuacct" / "docker" / "container-id"
    memory.mkdir(parents=True)
    cpu.mkdir(parents=True)
    proc_cgroup = tmp_path / "self.cgroup"
    proc_cgroup.write_text(
        "5:memory:/docker/container-id\n4:cpu,cpuacct:/docker/container-id\n",
        encoding="utf-8",
    )
    (memory / "memory.usage_in_bytes").write_text("1024\n", encoding="utf-8")
    (memory / "memory.max_usage_in_bytes").write_text("2048\n", encoding="utf-8")
    (memory / "memory.limit_in_bytes").write_text(
        str((1 << 63) - 4096), encoding="utf-8",
    )
    (cpu / "cpuacct.usage").write_text("1000000000\n", encoding="utf-8")
    (cpu / "cpu.cfs_quota_us").write_text("-1\n", encoding="utf-8")
    (cpu / "cpu.cfs_period_us").write_text("100000\n", encoding="utf-8")
    monkeypatch.setattr(runtime_health, "_CGROUP_ROOT", cgroup)
    monkeypatch.setattr(runtime_health, "_PROC_SELF_CGROUP", proc_cgroup)

    result = runtime_health._container_memory()

    assert result["status"] == "available"
    assert result["current_bytes"] == 1024
    assert result["peak_bytes"] == 2048
    assert result["limit_bytes"] is None
    assert result["limited"] is False
    assert runtime_health._container_cpu_usage_seconds() == 1.0
    assert runtime_health._container_cpu_allowance() is None


def test_cgroup_v2_metrics_take_precedence_over_v1_fallback(monkeypatch, tmp_path):
    cgroup = tmp_path / "cgroup"
    cgroup.mkdir()
    (cgroup / "memory.current").write_text("300\n", encoding="utf-8")
    (cgroup / "memory.peak").write_text("400\n", encoding="utf-8")
    (cgroup / "memory.max").write_text("max\n", encoding="utf-8")
    (cgroup / "cpu.stat").write_text("usage_usec 500000\n", encoding="utf-8")
    (cgroup / "cpu.max").write_text("100000 100000\n", encoding="utf-8")
    v1_memory = cgroup / "memory"
    v1_memory.mkdir()
    (v1_memory / "memory.usage_in_bytes").write_text("999\n", encoding="utf-8")
    monkeypatch.setattr(runtime_health, "_CGROUP_ROOT", cgroup)
    monkeypatch.setattr(runtime_health, "_PROC_SELF_CGROUP", tmp_path / "missing")

    result = runtime_health._container_memory()

    assert result["current_bytes"] == 300
    assert result["peak_bytes"] == 400
    assert result["limited"] is False
    assert runtime_health._container_cpu_usage_seconds() == 0.5
    assert runtime_health._container_cpu_allowance() == 1.0


def test_cgroup_v1_rejects_unsafe_kernel_reported_relative_path(monkeypatch, tmp_path):
    cgroup = tmp_path / "cgroup"
    memory = cgroup / "memory"
    memory.mkdir(parents=True)
    proc_cgroup = tmp_path / "self.cgroup"
    proc_cgroup.write_text("5:memory:/../../outside\n", encoding="utf-8")
    (memory / "memory.usage_in_bytes").write_text("777\n", encoding="utf-8")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "memory.usage_in_bytes").write_text("999\n", encoding="utf-8")
    monkeypatch.setattr(runtime_health, "_CGROUP_ROOT", cgroup)
    monkeypatch.setattr(runtime_health, "_PROC_SELF_CGROUP", proc_cgroup)

    assert runtime_health._container_memory()["status"] == "unavailable"


def test_cgroup_v1_never_mixes_nested_and_controller_root_measurements(
    monkeypatch, tmp_path,
):
    cgroup = tmp_path / "cgroup"
    memory_root = cgroup / "memory"
    memory_nested = memory_root / "docker" / "container-id"
    cpu_root = cgroup / "cpu,cpuacct"
    cpu_nested = cpu_root / "docker" / "container-id"
    memory_nested.mkdir(parents=True)
    cpu_nested.mkdir(parents=True)
    proc_cgroup = tmp_path / "self.cgroup"
    proc_cgroup.write_text(
        "5:memory:/docker/container-id\n4:cpu,cpuacct:/docker/container-id\n",
        encoding="utf-8",
    )
    (memory_nested / "memory.usage_in_bytes").write_text("1024\n", encoding="utf-8")
    (memory_root / "memory.max_usage_in_bytes").write_text("9999\n", encoding="utf-8")
    (memory_root / "memory.limit_in_bytes").write_text("9999\n", encoding="utf-8")
    (cpu_nested / "cpuacct.usage").write_text("1000000000\n", encoding="utf-8")
    (cpu_nested / "cpu.cfs_quota_us").write_text("200000\n", encoding="utf-8")
    (cpu_root / "cpu.cfs_period_us").write_text("100000\n", encoding="utf-8")
    monkeypatch.setattr(runtime_health, "_CGROUP_ROOT", cgroup)
    monkeypatch.setattr(runtime_health, "_PROC_SELF_CGROUP", proc_cgroup)

    memory_result = runtime_health._container_memory()

    assert memory_result["current_bytes"] == 1024
    assert memory_result["peak_bytes"] is None
    assert memory_result["limit_bytes"] is None
    assert memory_result["limited"] is False
    assert runtime_health._container_cpu_usage_seconds() == 1.0
    assert runtime_health._container_cpu_allowance() is None


def test_cgroup_v1_requires_readable_process_controller_identity(
    monkeypatch, tmp_path,
):
    cgroup = tmp_path / "cgroup"
    memory = cgroup / "memory"
    cpu = cgroup / "cpu,cpuacct"
    memory.mkdir(parents=True)
    cpu.mkdir(parents=True)
    (memory / "memory.usage_in_bytes").write_text("777\n", encoding="utf-8")
    (cpu / "cpuacct.usage").write_text("1000000000\n", encoding="utf-8")
    monkeypatch.setattr(runtime_health, "_CGROUP_ROOT", cgroup)
    monkeypatch.setattr(runtime_health, "_PROC_SELF_CGROUP", tmp_path / "missing")

    assert runtime_health._container_memory()["status"] == "unavailable"
    assert runtime_health._container_cpu_usage_seconds() is None


def test_cgroup_v1_requires_requested_controller_in_process_identity(
    monkeypatch, tmp_path,
):
    cgroup = tmp_path / "cgroup"
    memory = cgroup / "memory"
    cpu = cgroup / "cpu,cpuacct"
    memory.mkdir(parents=True)
    cpu.mkdir(parents=True)
    (memory / "memory.usage_in_bytes").write_text("777\n", encoding="utf-8")
    (cpu / "cpuacct.usage").write_text("1000000000\n", encoding="utf-8")
    proc_cgroup = tmp_path / "self.cgroup"
    proc_cgroup.write_text("7:blkio:/\n", encoding="utf-8")
    monkeypatch.setattr(runtime_health, "_CGROUP_ROOT", cgroup)
    monkeypatch.setattr(runtime_health, "_PROC_SELF_CGROUP", proc_cgroup)

    assert runtime_health._container_memory()["status"] == "unavailable"
    assert runtime_health._container_cpu_usage_seconds() is None


def test_database_size_uses_only_fixed_main_wal_and_shm_files(tmp_path):
    db_path = tmp_path / "analyzer.db"
    db_path.write_bytes(b"db")
    Path(str(db_path) + "-wal").write_bytes(b"wal")
    (tmp_path / "unrelated.bin").write_bytes(b"not-counted")

    result = runtime_health._database_measurement(db_path)

    assert result["status"] == "available"
    assert result["total_bytes"] == 5
    assert result["files_present"] == 2
    assert not Path(str(db_path) + "-shm").exists()


def test_workload_query_is_read_only_bounded_and_fixed_shape(tmp_path):
    db_path = tmp_path / "analyzer.db"
    _health_tables(db_path)
    before = db_path.read_bytes()
    before_mtime = db_path.stat().st_mtime_ns

    result = runtime_health._workload_measurement(db_path)

    assert result == {
        "status": "available",
        "scope": "Saved analysis attempts and intake activity",
        "unit": "records",
        "source": "Time-bounded read-only SQLite aggregate",
        "attempts": {
            "queued": 1, "running": 1, "completed": 0, "failed": 1, "interrupted": 0,
        },
        "intake": {
            "waiting": 1, "retrying": 1, "paused": 0, "complete": 1,
            "needs_scope": 0, "blocked": 0,
        },
        "operator_status": {
            "waiting": 3, "processing": 1, "recovering": 0,
            "needs_attention": 1, "stopped_for_safety": 0,
        },
    }
    assert db_path.read_bytes() == before
    assert db_path.stat().st_mtime_ns == before_mtime


def test_workload_query_returns_unavailable_for_missing_schema_and_contention(
    monkeypatch, tmp_path,
):
    db_path = tmp_path / "analyzer.db"
    sqlite3.connect(db_path).close()
    assert runtime_health._workload_measurement(db_path)["status"] == "unavailable"


def test_workload_query_returns_unavailable_when_time_budget_is_exceeded(
    monkeypatch, tmp_path,
):
    db_path = tmp_path / "analyzer.db"
    _health_tables(db_path)
    calls = 0

    def elapsed():
        nonlocal calls
        calls += 1
        return 0.0 if calls == 1 else 1.0

    monkeypatch.setattr(runtime_health.time, "monotonic", elapsed)
    assert runtime_health._workload_measurement(db_path)["status"] == "unavailable"

    def locked(*_args, **_kwargs):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(runtime_health, "connect_database", locked)
    assert runtime_health._workload_measurement(db_path)["status"] == "unavailable"


def test_snapshot_is_bounded_and_does_not_expose_paths_or_identifiers(monkeypatch, tmp_path):
    db_path = tmp_path / "secret-location" / "analyzer.db"
    db_path.parent.mkdir()
    _health_tables(db_path)
    provider = runtime_health.LocalRuntimeHealthProvider()
    result = provider.snapshot(db_path, db_path.parent)
    encoded = json.dumps(result)

    assert set(result) == {
        "status", "provider", "sampled_at", "sample_age_seconds",
        "refresh_after_seconds", "measurements", "workload", "orchestrator",
    }
    assert set(result["measurements"]) == {
        "process_cpu", "process_memory", "container_cpu", "container_memory",
        "data_filesystem", "database_files",
    }
    for measurement in result["measurements"].values():
        assert {"status", "scope", "unit", "source"}.issubset(measurement)
    assert {"status", "scope", "unit", "source"}.issubset(result["workload"])
    assert result["sample_age_seconds"] == 0
    assert result["refresh_after_seconds"] == 5
    assert str(tmp_path) not in encoded
    assert "secret-location" not in encoded
    assert len(encoded) < 6000


def test_snapshot_does_not_create_missing_database_or_walk_data(tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    nested = data_dir / "evidence" / "do-not-read.bin"
    nested.parent.mkdir()
    nested.write_bytes(b"evidence")
    before = sorted(path.relative_to(tmp_path) for path in tmp_path.rglob("*"))

    runtime_health.LocalRuntimeHealthProvider().snapshot(data_dir / "missing.db", data_dir)

    after = sorted(path.relative_to(tmp_path) for path in tmp_path.rglob("*"))
    assert after == before
    assert nested.read_bytes() == b"evidence"


def test_unavailable_kubernetes_adapter_does_not_change_local_measurements(monkeypatch, tmp_path):
    db_path = tmp_path / "analyzer.db"
    _health_tables(db_path)
    monkeypatch.setattr(runtime_health, "kubernetes_health_snapshot", lambda: {
        "provider": "kubernetes",
        "status": "unavailable",
        "sampled_at": None,
        "last_successful_sampled_at": None,
        "deployment": {"status": "unavailable"},
        "metrics": {"status": "unavailable"},
    })

    result = runtime_health.LocalRuntimeHealthProvider().snapshot(db_path, tmp_path)

    assert result["orchestrator"]["status"] == "unavailable"
    assert result["provider"] == "local"
    assert result["measurements"]["data_filesystem"]["status"] == "available"
    assert result["workload"]["status"] == "available"

