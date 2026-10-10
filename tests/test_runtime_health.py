from __future__ import annotations

import json
from pathlib import Path
import sqlite3

import app.runtime_health as runtime_health


def _health_tables(db_path: Path) -> None:
    with sqlite3.connect(db_path) as db:
        db.executescript(
            """
            CREATE TABLE pipeline_job_attempts (state TEXT NOT NULL);
            CREATE TABLE pipeline_admission_intents (activity_state TEXT NOT NULL);
            INSERT INTO pipeline_job_attempts VALUES ('queued'), ('running'), ('failed');
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

