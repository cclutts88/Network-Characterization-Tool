import json

import pytest

from scripts.benchmark_phase0_http import COMMON_WORKLOADS, expected_workloads, request_order
from scripts.summarize_phase0_http_benchmark import (
    EXPECTED_FOUNDATION,
    _expected_common,
    summarize,
)


def _run(repeat: int, foundation: bool, wall: float = 1.0) -> dict:
    revision = ("f" if foundation else "a") * 40
    source = ("d" if foundation else "c") * 64
    changes = [] if foundation else [
        "device_analysis_cache", "device_collections", "scan_analysis_cache",
    ]
    return {
        "repeat": repeat,
        "passed": True,
        "failures": [],
        "foundation_capabilities": foundation,
        "runner_version": "phase0-http-benchmark:1",
        "runner_sha256": "1" * 64,
        "comparison_statistic": "median of three fresh-process repeats",
        "corpus": {"manifest_sha256": "2" * 64},
        "target": {
            "revision": revision,
            "source_digest_sha256": source,
            "container_image_id": "sha256:" + "3" * 64,
            "identity_evidence": {
                "type": "externally-verified-controller-attestations",
                "validated": True,
                "git": {
                    "verification_method": "controller:git-rev-parse-status-and-source-digest",
                    "clean": True,
                    "revision": revision,
                    "source_digest_sha256": source,
                },
                "container_image": {
                    "verification_method": "controller:docker-image-inspect",
                    "image_id": "sha256:" + "3" * 64,
                    "container_id": f"{1 if foundation else 0}{repeat:063d}",
                    "fresh_container": True,
                    "network_mode": "none",
                    "source_mount_read_only": True,
                    "corpus_mount_read_only": True,
                },
            },
        },
        "request_session": {
            "kind": "one fixed ordered in-process TestClient session",
            "order": request_order(foundation),
            "background_work_disabled_before_measurement": True,
            "staging_complete_before_measurement": True,
        },
        "limits": {
            "absolute": {"fixed": 1},
            "relative": {
                "foundation_over_main_ratio": 2.0,
                "wall_seconds_allowance": 0.5,
                "cpu_seconds_allowance": 0.5,
                "peak_rss_bytes_allowance": 128,
            },
        },
        "metrics": {
            name: {"wall_seconds": wall, "cpu_seconds": wall, "response_bytes": 100}
            for name in expected_workloads(foundation)
        },
        "correctness": {
            "staged": {"nmap_files": 9, "device_files": 4},
            "common": _expected_common(foundation=foundation),
            "foundation": EXPECTED_FOUNDATION if foundation else None,
            "database_logical_sha256_before": "5" * 64,
            "database_logical_sha256_after": ("5" if foundation else "6") * 64,
            "database_logical_state_unchanged": foundation,
            "database_main_file_before": "7" * 64,
            "database_main_file_after": ("7" if foundation else "8") * 64,
            "database_tables_changed_by_requests": changes,
            "allowed_database_table_changes": changes,
            "evidence_sha256_unchanged": ("4" if foundation else "3") * 64,
        },
        "total": {"peak_rss_bytes": 1000 if not foundation else 1100},
        "limitations": ["in-process"],
    }


def _write(tmp_path, foundation: bool, walls=(1.0, 1.1, 0.9)):
    paths = []
    for repeat, wall in enumerate(walls, 1):
        path = tmp_path / f"{'foundation' if foundation else 'main'}-{repeat}.json"
        path.write_text(json.dumps(_run(repeat, foundation, wall)))
        paths.append(path)
    return paths


def test_http_summary_accepts_exact_six_run_comparison(tmp_path):
    result = summarize(
        _write(tmp_path, False),
        _write(tmp_path, True, (1.2, 1.3, 1.1)),
    )
    assert result["passed"] is True
    assert result["failures"] == []
    assert set(result["common_endpoint_comparisons"]) == set(COMMON_WORKLOADS)
    assert result["stable_main"]["correctness"]["common"]["map"]["interfaces"] == 2
    assert result["foundation"]["correctness"]["common"]["map"]["interfaces"] == 1000


def test_http_summary_rejects_missing_capability_and_mutation_drift(tmp_path):
    main = _write(tmp_path, False)
    foundation = _write(tmp_path, True)
    changed = json.loads(foundation[0].read_text())
    del changed["metrics"][expected_workloads(True)[0]]
    foundation[0].write_text(json.dumps(changed))
    with pytest.raises(ValueError, match="fixed capability matrix"):
        summarize(main, foundation)

    foundation = _write(tmp_path, True)
    changed = json.loads(foundation[0].read_text())
    changed["correctness"]["database_tables_changed_by_requests"] = ["unexpected"]
    foundation[0].write_text(json.dumps(changed))
    with pytest.raises(ValueError, match="mutation oracle"):
        summarize(main, foundation)


def test_http_summary_rejects_session_or_database_state_drift(tmp_path):
    main = _write(tmp_path, False)
    foundation = _write(tmp_path, True)
    changed = json.loads(foundation[0].read_text())
    changed["request_session"]["order"] = list(reversed(changed["request_session"]["order"]))
    foundation[0].write_text(json.dumps(changed))
    with pytest.raises(ValueError, match="request-session declaration"):
        summarize(main, foundation)

    foundation = _write(tmp_path, True)
    changed = json.loads(foundation[0].read_text())
    changed["correctness"]["database_logical_sha256_after"] = "9" * 64
    foundation[0].write_text(json.dumps(changed))
    with pytest.raises(ValueError, match="changed logical database state"):
        summarize(main, foundation)


def test_http_summary_rejects_evidence_identity_drift_within_one_branch(tmp_path):
    main = _write(tmp_path, False)
    foundation = _write(tmp_path, True)
    changed = json.loads(foundation[0].read_text())
    changed["correctness"]["evidence_sha256_unchanged"] = "9" * 64
    foundation[0].write_text(json.dumps(changed))
    with pytest.raises(ValueError, match="foundation retained evidence identity differs"):
        summarize(main, foundation)


def test_http_summary_reports_common_endpoint_regression(tmp_path):
    main = _write(tmp_path, False)
    foundation = _write(tmp_path, True)
    for path in foundation:
        run = json.loads(path.read_text())
        for name in COMMON_WORKLOADS:
            run["metrics"][name]["wall_seconds"] = 3.0
            run["metrics"][name]["cpu_seconds"] = 3.0
        path.write_text(json.dumps(run))
    result = summarize(main, foundation)
    assert result["passed"] is False
    assert any("relative limit exceeded" in item for item in result["failures"])
