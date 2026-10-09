import json
from pathlib import Path
import subprocess
import sys

from scripts.benchmark_phase0_core import _source_digest
from scripts.benchmark_phase0_http import (
    COMMON_WORKLOADS,
    FOUNDATION_WORKLOADS,
    expected_workloads,
    request_order,
)
from scripts.generate_phase0_benchmark_corpus import generate_corpus
from scripts.summarize_phase0_http_benchmark import EXPECTED_FOUNDATION, _expected_common


def test_http_capability_matrix_is_fixed_and_ordered():
    assert request_order(False) == COMMON_WORKLOADS
    assert request_order(True) == COMMON_WORKLOADS + FOUNDATION_WORKLOADS
    assert expected_workloads(True) == sorted(COMMON_WORKLOADS + FOUNDATION_WORKLOADS)
    assert len(set(expected_workloads(True))) == 15


def test_foundation_http_runner_executes_complete_public_matrix(tmp_path):
    root = Path(__file__).resolve().parents[1]
    corpus = tmp_path / "corpus"
    generate_corpus(corpus)
    source_digest, _ = _source_digest(root)
    git = tmp_path / "git.json"
    image = tmp_path / "image.json"
    output = tmp_path / "result.json"
    git.write_text(json.dumps({
        "verification_method": "controller:git-rev-parse-status-and-source-digest",
        "revision": "a" * 40,
        "clean": True,
        "source_digest_sha256": source_digest,
    }))
    image.write_text(json.dumps({
        "verification_method": "controller:docker-image-inspect",
        "image_id": "sha256:" + "b" * 64,
        "container_id": "c" * 64,
        "fresh_container": True,
        "network_mode": "none",
        "source_mount_read_only": True,
        "corpus_mount_read_only": True,
    }))
    completed = subprocess.run([
        sys.executable, str(root / "scripts" / "benchmark_phase0_http.py"),
        "--target-root", str(root), "--corpus", str(corpus),
        "--data-root", str(tmp_path / "data"),
        "--git-attestation", str(git), "--image-attestation", str(image),
        "--repeat", "1", "--foundation-capabilities", "--output", str(output),
    ], cwd=root, capture_output=True, text=True, timeout=120)
    assert completed.returncode == 0, completed.stderr
    result = json.loads(output.read_text())
    assert result["passed"] is True
    assert set(result["metrics"]) == set(expected_workloads(True))
    assert result["correctness"]["common"] == _expected_common(foundation=True)
    assert result["correctness"]["foundation"] == EXPECTED_FOUNDATION
    assert result["correctness"]["database_tables_changed_by_requests"] == []
    assert result["correctness"]["database_logical_state_unchanged"] is True
    assert result["correctness"]["database_logical_sha256_before"] == result["correctness"]["database_logical_sha256_after"]
    assert result["request_session"]["order"] == request_order(True)
    assert result["request_session"]["background_work_disabled_before_measurement"] is True
    assert result["correctness"]["evidence_sha256_unchanged"]
