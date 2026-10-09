import hashlib
import json
from pathlib import Path

import pytest

from scripts.benchmark_phase0_core import (
    ABSOLUTE_LIMITS,
    COMPARISON_STATISTIC,
    RELATIVE_LIMITS,
    _source_digest,
    run_once,
)
from scripts.generate_phase0_benchmark_corpus import generate_corpus


def _attestations(target: Path) -> tuple[dict, dict]:
    source_digest, _ = _source_digest(target)
    return (
        {
            "verification_method": "controller:git-rev-parse-status-and-source-digest",
            "revision": "a" * 40,
            "clean": True,
            "source_digest_sha256": source_digest,
        },
        {
            "verification_method": "controller:docker-image-inspect",
            "image_id": "sha256:" + "b" * 64,
            "container_id": "c" * 64,
            "fresh_container": True,
            "network_mode": "none",
            "source_mount_read_only": True,
            "corpus_mount_read_only": True,
        },
    )


def test_phase0_core_worker_runs_exact_corpus_with_predeclared_limits(tmp_path):
    corpus = tmp_path / "corpus"
    generate_corpus(corpus)
    target = Path(__file__).resolve().parents[1]
    git_attestation, image_attestation = _attestations(target)

    result = run_once(
        target,
        corpus,
        tmp_path / "empty-data",
        git_attestation=git_attestation,
        image_attestation=image_attestation,
        repeat=1,
    )

    assert result["passed"] is True
    assert result["failures"] == []
    assert result["comparison_statistic"] == COMPARISON_STATISTIC
    assert result["limits"] == {
        "absolute": ABSOLUTE_LIMITS,
        "relative": RELATIVE_LIMITS,
    }
    assert result["correctness"]["nmap_files"] == 9
    assert result["correctness"]["device_files"] == 4
    assert result["correctness"]["history"] == {
        "hosts_added": 1,
        "hosts_no_longer_confirmed": 1,
        "version_changes": 1,
        "ports_added": 2,
        "ports_no_longer_observed": 1,
    }
    assert result["correctness"]["enrichment"]["cold_search_calls"] == 24
    assert result["correctness"]["enrichment"]["warm_search_calls"] == 0
    assert result["total"]["peak_rss_bytes"] > 0
    assert result["target"]["source_file_count"] > 20
    assert result["target"]["identity_evidence"]["type"] == "externally-verified-controller-attestations"
    assert result["retained_state"]["data_root_bytes"] >= result["correctness"]["enrichment"]["cache_database_bytes"]
    assert result["retained_state"]["data_root_file_count"] >= 9


def test_phase0_core_worker_refuses_reused_state(tmp_path):
    corpus = tmp_path / "corpus"
    generate_corpus(corpus)
    target = Path(__file__).resolve().parents[1]
    git_attestation, image_attestation = _attestations(target)
    data_root = tmp_path / "existing-data"
    data_root.mkdir()

    try:
        run_once(
            target, corpus, data_root,
            git_attestation=git_attestation, image_attestation=image_attestation, repeat=1,
        )
    except ValueError as exc:
        assert "must not exist" in str(exc)
    else:
        raise AssertionError("Benchmark reused an existing data directory")


def test_phase0_core_worker_rejects_changed_file_with_rewritten_manifest(tmp_path):
    corpus = tmp_path / "corpus"
    generate_corpus(corpus)
    changed = corpus / "nmap" / "small_tcp.xml"
    changed.write_bytes(changed.read_bytes() + b"\n")
    manifest_path = corpus / "phase0-benchmark-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    for entry in manifest["files"]:
        if entry["path"] == "nmap/small_tcp.xml":
            content = changed.read_bytes()
            entry["size_bytes"] = len(content)
            entry["sha256"] = hashlib.sha256(content).hexdigest()
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    target = Path(__file__).resolve().parents[1]
    git_attestation, image_attestation = _attestations(target)

    with pytest.raises(ValueError, match="canonical generator"):
        run_once(target, corpus, tmp_path / "data", git_attestation, image_attestation, 1)


def test_phase0_core_worker_rejects_linked_corpus_ancestor(tmp_path):
    real_parent = tmp_path / "real"
    real_parent.mkdir()
    generate_corpus(real_parent / "corpus")
    linked_parent = tmp_path / "linked"
    try:
        linked_parent.symlink_to(real_parent, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("Directory links are unavailable on this host")
    target = Path(__file__).resolve().parents[1]
    git_attestation, image_attestation = _attestations(target)

    with pytest.raises(ValueError, match="ancestors is linked"):
        run_once(target, linked_parent / "corpus", tmp_path / "data", git_attestation, image_attestation, 1)


def test_phase0_core_worker_rejects_unverified_target_identity(tmp_path):
    corpus = tmp_path / "corpus"
    generate_corpus(corpus)
    target = Path(__file__).resolve().parents[1]
    git_attestation, image_attestation = _attestations(target)
    git_attestation["source_digest_sha256"] = "0" * 64

    with pytest.raises(ValueError, match="source digest"):
        run_once(target, corpus, tmp_path / "data", git_attestation, image_attestation, 1)
