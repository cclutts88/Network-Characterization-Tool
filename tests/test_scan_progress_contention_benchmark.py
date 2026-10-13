from scripts.benchmark_scan_progress_contention import run_benchmark


def test_scan_progress_contention_benchmark_has_exact_final_state(tmp_path):
    result = run_benchmark(tmp_path / "benchmark.db", cycles=12)

    assert result["passed"] is True
    assert result["failures"] == []
    assert all(result["checks"].values())
    assert result["timings"]["progress"]["count"] == 12
    assert result["timings"]["read"]["count"] == 24
    assert result["overlap"]["max_concurrent_writer_lanes"] == 3
    assert result["overlap"]["writer_overlap_seconds"] > 0
