from __future__ import annotations

import time

import app.runtime_trends as trends


def test_series_recomputes_near_peak_for_new_maximum_and_breaks_on_gaps() -> None:
    series = trends._Series(unit="percent", basis="test")
    series.add(0.0, 50.0, "2026-10-10T00:00:00+00:00")
    series.add(5.0, 50.0, "2026-10-10T00:00:05+00:00")
    assert series.snapshot()["longest_near_peak_seconds"] == 5.0

    series.add(10.0, 100.0, "2026-10-10T00:00:10+00:00")
    changed = series.snapshot()
    assert changed["current"] == 100.0
    assert changed["maximum"] == 100.0
    assert changed["longest_near_peak_seconds"] == 0.0

    series.add(15.0, 96.0, "2026-10-10T00:00:15+00:00")
    series.add(20.0, None, "2026-10-10T00:00:20+00:00")
    series.add(25.0, 95.0, "2026-10-10T00:00:25+00:00")
    series.add(30.0, 96.0, "2026-10-10T00:00:30+00:00")
    series.add(38.0, 96.0, "2026-10-10T00:00:38+00:00")
    result = series.snapshot()
    assert result["longest_near_peak_seconds"] == 5.0
    assert result["unavailable_samples"] == 1
    assert result["sampling_attempts"] == 8


def test_series_is_bounded_by_time_and_attempt_count() -> None:
    series = trends._Series(unit="bytes", basis="test")
    for index in range(800):
        series.add(float(index * 5), float(index), f"sample-{index}")
    result = series.snapshot()
    assert result["sampling_attempts"] <= trends.MAX_ATTEMPTS
    assert len(series.attempts) <= trends.MAX_ATTEMPTS
    assert series.attempts[0][0] >= series.attempts[-1][0] - trends.WINDOW_SECONDS


def test_sampler_tracks_cpu_and_memory_with_separate_baselines(monkeypatch) -> None:
    sampler = trends.RuntimeTrendSampler()
    process_cpu = iter([1.0, 2.0, 4.0])
    container_cpu = iter([10.0, 12.0, 16.0])
    process_memory = iter([100.0, 200.0, 300.0])
    container_memory = iter([400.0, 500.0, 600.0])
    monkeypatch.setattr(trends.time, "process_time", lambda: next(process_cpu))
    monkeypatch.setattr(trends, "_container_cpu_usage_seconds", lambda: next(container_cpu))
    monkeypatch.setattr(trends, "_container_cpu_allowance", lambda: 2.0)
    monkeypatch.setattr(
        trends, "_process_memory",
        lambda: {"status": "available", "current_bytes": next(process_memory)},
    )
    monkeypatch.setattr(
        trends, "_container_memory",
        lambda: {"status": "available", "current_bytes": next(container_memory)},
    )

    sampler.sample_once(sampled_at=0.0, sampled_at_utc="sample-0")
    sampler.sample_once(sampled_at=5.0, sampled_at_utc="sample-1")
    sampler.sample_once(sampled_at=10.0, sampled_at_utc="sample-2")
    result = sampler.snapshot()
    assert result["metrics"]["process_cpu"]["average"] == 30.0
    assert result["metrics"]["process_cpu"]["maximum"] == 40.0
    assert result["metrics"]["container_cpu"]["average"] == 30.0
    assert result["metrics"]["container_cpu"]["basis"] == "Percent of 2-CPU container allowance"
    assert result["metrics"]["process_memory"]["average"] == 200.0
    assert result["metrics"]["process_memory"]["maximum"] == 300.0
    assert result["metrics"]["container_memory"]["average"] == 500.0
    assert result["metrics"]["container_memory"]["maximum"] == 600.0


def test_container_cpu_basis_change_starts_new_segment(monkeypatch) -> None:
    sampler = trends.RuntimeTrendSampler()
    process_cpu = iter([0.0, 1.0, 2.0, 3.0])
    container_cpu = iter([0.0, 1.0, 2.0, 3.0])
    allowance = iter([None, None, 2.0, 2.0])
    monkeypatch.setattr(trends.time, "process_time", lambda: next(process_cpu))
    monkeypatch.setattr(trends, "_container_cpu_usage_seconds", lambda: next(container_cpu))
    monkeypatch.setattr(trends, "_container_cpu_allowance", lambda: next(allowance))
    monkeypatch.setattr(trends, "_process_memory", lambda: {"status": "unavailable"})
    monkeypatch.setattr(trends, "_container_memory", lambda: {"status": "unavailable"})

    for index in range(4):
        sampler.sample_once(sampled_at=float(index * 5), sampled_at_utc=f"sample-{index}")
    result = sampler.snapshot()["metrics"]["container_cpu"]
    assert result["basis"] == "Percent of 2-CPU container allowance"
    assert result["sampling_attempts"] == 2
    assert result["available_samples"] == 1
    assert result["maximum"] == 10.0
    assert result["current"] == 10.0


def test_metric_failures_are_isolated_and_counted(monkeypatch) -> None:
    sampler = trends.RuntimeTrendSampler()
    process_cpu = iter([0.0, 1.0])
    monkeypatch.setattr(trends.time, "process_time", lambda: next(process_cpu))
    monkeypatch.setattr(trends, "_container_cpu_usage_seconds", lambda: (_ for _ in ()).throw(OSError("no cgroup")))
    monkeypatch.setattr(trends, "_container_cpu_allowance", lambda: 1.0)
    monkeypatch.setattr(trends, "_process_memory", lambda: {"status": "available", "current_bytes": 123})
    monkeypatch.setattr(trends, "_container_memory", lambda: (_ for _ in ()).throw(RuntimeError("unavailable")))

    sampler.sample_once(sampled_at=0.0, sampled_at_utc="sample-0")
    sampler.sample_once(sampled_at=5.0, sampled_at_utc="sample-1")
    result = sampler.snapshot()["metrics"]
    assert result["process_cpu"]["available_samples"] == 1
    assert result["process_memory"]["available_samples"] == 2
    assert result["container_cpu"]["unavailable_samples"] == 2
    assert result["container_memory"]["unavailable_samples"] == 2
    assert result["container_cpu"]["status"] == "unavailable"
    assert result["container_memory"]["status"] == "unavailable"


def test_first_valid_cpu_counter_is_warming_but_memory_failure_is_unavailable(monkeypatch) -> None:
    sampler = trends.RuntimeTrendSampler()
    monkeypatch.setattr(trends.time, "process_time", lambda: 1.0)
    monkeypatch.setattr(trends, "_container_cpu_usage_seconds", lambda: 2.0)
    monkeypatch.setattr(trends, "_container_cpu_allowance", lambda: 1.0)
    monkeypatch.setattr(trends, "_process_memory", lambda: {"status": "unavailable"})
    monkeypatch.setattr(trends, "_container_memory", lambda: {"status": "unavailable"})

    sampler.sample_once(sampled_at=0.0, sampled_at_utc="sample-0")
    result = sampler.snapshot()["metrics"]
    assert result["process_cpu"]["status"] == "warming_up"
    assert result["container_cpu"]["status"] == "warming_up"
    assert result["process_memory"]["status"] == "unavailable"
    assert result["container_memory"]["status"] == "unavailable"


def test_failed_first_cpu_counter_is_unavailable(monkeypatch) -> None:
    sampler = trends.RuntimeTrendSampler()
    monkeypatch.setattr(
        trends.time,
        "process_time",
        lambda: (_ for _ in ()).throw(OSError("no process counter")),
    )
    monkeypatch.setattr(trends, "_container_cpu_usage_seconds", lambda: None)
    monkeypatch.setattr(trends, "_container_cpu_allowance", lambda: None)
    monkeypatch.setattr(trends, "_process_memory", lambda: {"status": "available", "current_bytes": 1})
    monkeypatch.setattr(trends, "_container_memory", lambda: {"status": "available", "current_bytes": 1})

    sampler.sample_once(sampled_at=0.0, sampled_at_utc="sample-0")
    result = sampler.snapshot()["metrics"]
    assert result["process_cpu"]["status"] == "unavailable"
    assert result["container_cpu"]["status"] == "unavailable"


def test_sampler_lifecycle_resets_and_stops_cleanly(monkeypatch) -> None:
    sampler = trends.RuntimeTrendSampler()
    monkeypatch.setattr(trends, "SAMPLE_INTERVAL_SECONDS", 0.01)
    assert sampler.start() is True
    assert sampler.start() is False
    time.sleep(0.03)
    assert sampler.snapshot()["status"] in {"running", "degraded"}
    assert sampler.stop() is True
    assert sampler.snapshot()["status"] == "stopped"
    assert sampler.start() is True
    assert sampler.snapshot()["metrics"]["process_memory"]["sampling_attempts"] <= 1
    assert sampler.stop() is True


def test_unexpected_sampler_failure_records_gap_for_every_metric(monkeypatch) -> None:
    sampler = trends.RuntimeTrendSampler()
    monkeypatch.setattr(trends, "SAMPLE_INTERVAL_SECONDS", 0.01)
    monkeypatch.setattr(
        sampler,
        "sample_once",
        lambda **_kwargs: (_ for _ in ()).throw(RuntimeError("unexpected")),
    )
    assert sampler.start() is True
    time.sleep(0.03)
    assert sampler.stop() is True
    result = sampler.snapshot()
    assert result["status"] == "stopped"
    for item in result["metrics"].values():
        assert item["status"] == "unavailable"
        assert item["sampling_attempts"] > 0
        assert item["available_samples"] == 0
        assert item["unavailable_samples"] == item["sampling_attempts"]
