import json

import pytest

from scripts.summarize_phase0_core_benchmark import summarize
from scripts.benchmark_phase0_core import expected_workload_names


def _run(repeat: int, *, foundation: bool, wall: float = 1.0) -> dict:
    cache = {
        "cache_supported": foundation,
        "cold_search_calls": 24,
        "warm_search_calls": 0 if foundation else 24,
        "warm_cache_hits": 24 if foundation else None,
    }
    return {
        "repeat": repeat,
        "passed": True,
        "failures": [],
        "runner_sha256": "a" * 64,
        "runner_version": "phase0-core-benchmark:1",
        "comparison_statistic": "median of three fresh-process repeats",
        "corpus": {"manifest_sha256": "b" * 64},
        "target": {
            "revision": ("f" if foundation else "m") * 40,
            "source_digest_sha256": ("d" if foundation else "c") * 64,
            "container_image_id": "sha256:" + "e" * 64,
            "identity_evidence": {
                "type": "externally-verified-controller-attestations",
                "validated": True,
                "git": {
                    "verification_method": "controller:git-rev-parse-status-and-source-digest",
                    "clean": True,
                    "revision": ("f" if foundation else "m") * 40,
                    "source_digest_sha256": ("d" if foundation else "c") * 64,
                },
                "container_image": {
                    "verification_method": "controller:docker-image-inspect",
                    "image_id": "sha256:" + "e" * 64,
                    "container_id": f"{1 if foundation else 0}{repeat:063d}",
                    "fresh_container": True,
                    "network_mode": "none",
                    "source_mount_read_only": True,
                    "corpus_mount_read_only": True,
                },
            },
        },
        "limits": {
            "relative": {
                "foundation_over_main_ratio": 2.0,
                "wall_seconds_allowance": 0.5,
                "cpu_seconds_allowance": 0.5,
                "peak_rss_bytes_allowance": 128,
            }
        },
        "expected_workloads": expected_workload_names(),
        "metrics": {
            name: {"wall_seconds": wall, "cpu_seconds": wall}
            for name in expected_workload_names()
        },
        "total": {
            "wall_seconds": wall,
            "cpu_seconds": wall,
            "peak_rss_bytes": 1000 if not foundation else 1100,
        },
        "correctness": {
            "enrichment": {
                **cache,
                "candidate_associations": 240,
                "cves": 24,
                "cache_database_bytes": 10 if foundation else 0,
                "retained_data_root_bytes": 100,
            },
            "nmap_files": 9,
            "device_files": 4,
            "history": {
                "hosts_added": 1,
                "hosts_no_longer_confirmed": 1,
                "version_changes": 1,
                "ports_added": 2,
                "ports_no_longer_observed": 1,
            },
        },
        "limitations": ["core only"],
    }


def _write_runs(tmp_path, *, foundation: bool, walls=(1.0, 1.1, 0.9)):
    paths = []
    for repeat, wall in enumerate(walls, start=1):
        path = tmp_path / f"{'foundation' if foundation else 'main'}-{repeat}.json"
        path.write_text(json.dumps(_run(repeat, foundation=foundation, wall=wall)))
        paths.append(path)
    return paths


def test_phase0_summary_accepts_three_exact_runs_and_cache_difference(tmp_path):
    result = summarize(
        _write_runs(tmp_path, foundation=False),
        _write_runs(tmp_path, foundation=True, walls=(1.2, 1.3, 1.1)),
    )

    assert result["passed"] is True
    assert result["failures"] == []
    first = expected_workload_names()[0]
    assert result["stable_main"]["median_metrics"][first]["wall_seconds"] == 1.0
    assert result["foundation"]["median_metrics"][first]["wall_seconds"] == 1.2


def test_phase0_summary_fails_regression_and_identity_drift(tmp_path):
    main = _write_runs(tmp_path, foundation=False)
    foundation = _write_runs(tmp_path, foundation=True, walls=(3.0, 3.0, 3.0))
    result = summarize(main, foundation)
    assert result["passed"] is False
    assert any("regression limit exceeded" in item for item in result["failures"])

    changed = json.loads(foundation[2].read_text())
    changed["runner_sha256"] = "9" * 64
    foundation[2].write_text(json.dumps(changed))
    with pytest.raises(ValueError, match="identity differs"):
        summarize(main, foundation)


def test_phase0_summary_rejects_failed_or_reused_repeat(tmp_path):
    main = _write_runs(tmp_path, foundation=False)
    foundation = _write_runs(tmp_path, foundation=True)
    failed = json.loads(foundation[0].read_text())
    failed["passed"] = False
    failed["failures"] = ["simulated"]
    foundation[0].write_text(json.dumps(failed))
    with pytest.raises(ValueError, match="failed benchmark repeat"):
        summarize(main, foundation)

    foundation = _write_runs(tmp_path, foundation=True)
    duplicate = json.loads(foundation[2].read_text())
    duplicate["repeat"] = 2
    foundation[2].write_text(json.dumps(duplicate))
    with pytest.raises(ValueError, match="exactly 1, 2 and 3"):
        summarize(main, foundation)


def test_phase0_summary_rejects_identically_missing_workload(tmp_path):
    main = _write_runs(tmp_path, foundation=False)
    foundation = _write_runs(tmp_path, foundation=True)
    missing = expected_workload_names()[0]
    for path in main + foundation:
        run = json.loads(path.read_text())
        del run["metrics"][missing]
        run["expected_workloads"].remove(missing)
        path.write_text(json.dumps(run))

    with pytest.raises(ValueError, match="complete canonical workload set"):
        summarize(main, foundation)


def test_phase0_summary_rejects_cross_branch_correctness_drift(tmp_path):
    main = _write_runs(tmp_path, foundation=False)
    foundation = _write_runs(tmp_path, foundation=True)
    for path in foundation:
        run = json.loads(path.read_text())
        run["correctness"]["history"]["ports_added"] = 3
        path.write_text(json.dumps(run))

    with pytest.raises(ValueError, match="canonical oracle"):
        summarize(main, foundation)


@pytest.mark.parametrize(
    ("section", "field", "value"),
    [
        ("git", "verification_method", None),
        ("git", "clean", False),
        ("container_image", "verification_method", None),
        ("container_image", "network_mode", "bridge"),
        ("container_image", "source_mount_read_only", False),
        ("container_image", "corpus_mount_read_only", False),
    ],
)
def test_phase0_summary_rejects_incomplete_raw_attestation(tmp_path, section, field, value):
    main = _write_runs(tmp_path, foundation=False)
    foundation = _write_runs(tmp_path, foundation=True)
    changed = json.loads(foundation[0].read_text())
    changed["target"]["identity_evidence"][section][field] = value
    foundation[0].write_text(json.dumps(changed))

    with pytest.raises(ValueError, match="lacks required external identity attestations"):
        summarize(main, foundation)


def test_phase0_summary_rejects_total_only_regression(tmp_path):
    main = _write_runs(tmp_path, foundation=False)
    foundation = _write_runs(tmp_path, foundation=True)
    for path in foundation:
        run = json.loads(path.read_text())
        for metric in run["metrics"].values():
            metric["wall_seconds"] = 1.0
            metric["cpu_seconds"] = 1.0
        run["total"]["wall_seconds"] = 3.0
        run["total"]["cpu_seconds"] = 3.0
        path.write_text(json.dumps(run))

    result = summarize(main, foundation)
    assert result["passed"] is False
    assert "whole-run wall_seconds regression limit exceeded" in result["failures"]
    assert "whole-run cpu_seconds regression limit exceeded" in result["failures"]
