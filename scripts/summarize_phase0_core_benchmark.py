"""Validate and summarize three stable-main and three foundation core runs."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import statistics

try:
    from scripts.benchmark_phase0_core import expected_workload_names
    from scripts.generate_phase0_benchmark_corpus import corpus_files
except ModuleNotFoundError:  # Direct execution from a mounted scripts directory.
    from benchmark_phase0_core import expected_workload_names
    from generate_phase0_benchmark_corpus import corpus_files


def _load(paths: list[Path], label: str) -> list[dict]:
    if len(paths) != 3:
        raise ValueError(f"{label} requires exactly three run files")
    runs = [json.loads(path.read_text(encoding="utf-8")) for path in paths]
    if {int(run.get("repeat", 0)) for run in runs} != {1, 2, 3}:
        raise ValueError(f"{label} repeats must be exactly 1, 2 and 3")
    for run in runs:
        if not run.get("passed") or run.get("failures"):
            raise ValueError(f"{label} contains a failed benchmark repeat")
        evidence = run.get("target", {}).get("identity_evidence", {})
        git = evidence.get("git", {})
        container = evidence.get("container_image", {})
        if (
            evidence.get("type") != "externally-verified-controller-attestations"
            or evidence.get("validated") is not True
            or git.get("verification_method") != "controller:git-rev-parse-status-and-source-digest"
            or git.get("clean") is not True
            or git.get("revision") != run["target"].get("revision")
            or git.get("source_digest_sha256") != run["target"].get("source_digest_sha256")
            or container.get("verification_method") != "controller:docker-image-inspect"
            or container.get("image_id") != run["target"].get("container_image_id")
            or len(str(container.get("container_id") or "")) != 64
            or container.get("fresh_container") is not True
            or container.get("network_mode") != "none"
            or container.get("source_mount_read_only") is not True
            or container.get("corpus_mount_read_only") is not True
        ):
            raise ValueError(f"{label} lacks required external identity attestations")
    for field in ("revision", "source_digest_sha256", "container_image_id"):
        values = {run["target"][field] for run in runs}
        if len(values) != 1:
            raise ValueError(f"{label} does not retain one exact target {field}")
    return sorted(runs, key=lambda item: item["repeat"])


def _median_metrics(runs: list[dict]) -> dict:
    names = set(expected_workload_names())
    if any(set(run["metrics"]) != names or run.get("expected_workloads") != sorted(names) for run in runs):
        raise ValueError("Benchmark repeat does not contain the complete canonical workload set")
    return {
        name: {
            key: statistics.median(run["metrics"][name][key] for run in runs)
            for key in ("wall_seconds", "cpu_seconds")
        }
        for name in sorted(names)
    }


def _expected_correctness() -> dict:
    _, oracle = corpus_files()
    history = oracle["history"]
    return {
        "nmap_files": len(oracle["nmap_files"]),
        "device_files": len(oracle["devices"]["parsed_counts"]),
        "history": {
            "hosts_added": len(history["hosts_added"]),
            "hosts_no_longer_confirmed": len(history["hosts_no_longer_confirmed"]),
            "version_changes": history["version_changes"],
            "ports_added": history["ports_added"],
            "ports_no_longer_observed": history["ports_no_longer_observed"],
        },
        "enrichment": {
            "cold_search_calls": oracle["enrichment"]["unique_product_version_queries"],
            "candidate_associations": 240,
            "cves": 24,
        },
    }


def _common_correctness(run: dict) -> dict:
    correctness = run["correctness"]
    enrichment = correctness["enrichment"]
    return {
        "nmap_files": correctness["nmap_files"],
        "device_files": correctness["device_files"],
        "history": correctness["history"],
        "enrichment": {
            "cold_search_calls": enrichment["cold_search_calls"],
            "candidate_associations": enrichment["candidate_associations"],
            "cves": enrichment["cves"],
        },
    }


def summarize(main_paths: list[Path], foundation_paths: list[Path]) -> dict:
    main = _load(main_paths, "stable main")
    foundation = _load(foundation_paths, "foundation")
    identities = {
        "runner_sha256": {run["runner_sha256"] for run in main + foundation},
        "runner_version": {run["runner_version"] for run in main + foundation},
        "corpus_manifest_sha256": {run["corpus"]["manifest_sha256"] for run in main + foundation},
        "container_image_id": {run["target"]["container_image_id"] for run in main + foundation},
        "comparison_statistic": {run["comparison_statistic"] for run in main + foundation},
        "limits": {json.dumps(run["limits"], sort_keys=True) for run in main + foundation},
    }
    mismatches = [name for name, values in identities.items() if len(values) != 1]
    if mismatches:
        raise ValueError("Comparison identity differs across runs: " + ", ".join(mismatches))
    container_ids = [
        run["target"]["identity_evidence"]["container_image"]["container_id"]
        for run in main + foundation
    ]
    if len(set(container_ids)) != len(container_ids):
        raise ValueError("Each benchmark repeat requires a unique fresh container")
    for label, runs in (("stable main", main), ("foundation", foundation)):
        source = runs[0]["target"]["source_digest_sha256"]
        if any(run["target"]["source_digest_sha256"] != source for run in runs):
            raise ValueError(f"{label} source changed between repeats")
        correctness = json.dumps(runs[0]["correctness"], sort_keys=True)
        if any(json.dumps(run["correctness"], sort_keys=True) != correctness for run in runs):
            raise ValueError(f"{label} correctness changed between repeats")
        if any(_common_correctness(run) != _expected_correctness() for run in runs):
            raise ValueError(f"{label} correctness does not match the canonical oracle")

    if any(_common_correctness(left) != _common_correctness(right) for left, right in zip(main, foundation)):
        raise ValueError("Stable and foundation core correctness differs")

    main_metrics = _median_metrics(main)
    foundation_metrics = _median_metrics(foundation)
    if set(main_metrics) != set(foundation_metrics):
        raise ValueError("Stable and foundation runs do not contain the same comparable workloads")
    limits = main[0]["limits"]["relative"]
    failures = []
    comparisons = {}
    for name in sorted(main_metrics):
        comparisons[name] = {}
        for key, allowance_name in (
            ("wall_seconds", "wall_seconds_allowance"),
            ("cpu_seconds", "cpu_seconds_allowance"),
        ):
            baseline = main_metrics[name][key]
            observed = foundation_metrics[name][key]
            ceiling = max(
                baseline * float(limits["foundation_over_main_ratio"]),
                baseline + float(limits[allowance_name]),
            )
            passed = observed <= ceiling
            comparisons[name][key] = {
                "main_median": baseline,
                "foundation_median": observed,
                "foundation_ceiling": ceiling,
                "passed": passed,
            }
            if not passed:
                failures.append(f"{name} {key} regression limit exceeded")
    main_peak = statistics.median(run["total"]["peak_rss_bytes"] for run in main)
    foundation_peak = statistics.median(run["total"]["peak_rss_bytes"] for run in foundation)
    peak_ceiling = max(
        main_peak * float(limits["foundation_over_main_ratio"]),
        main_peak + float(limits["peak_rss_bytes_allowance"]),
    )
    peak_passed = foundation_peak <= peak_ceiling
    if not peak_passed:
        failures.append("whole-run peak memory regression limit exceeded")
    total_comparisons = {}
    for key, allowance_name in (
        ("wall_seconds", "wall_seconds_allowance"),
        ("cpu_seconds", "cpu_seconds_allowance"),
    ):
        baseline = statistics.median(run["total"][key] for run in main)
        observed = statistics.median(run["total"][key] for run in foundation)
        ceiling = max(
            baseline * float(limits["foundation_over_main_ratio"]),
            baseline + float(limits[allowance_name]),
        )
        passed = observed <= ceiling
        total_comparisons[key] = {
            "main_median": baseline,
            "foundation_median": observed,
            "foundation_ceiling": ceiling,
            "passed": passed,
        }
        if not passed:
            failures.append(f"whole-run {key} regression limit exceeded")

    stable_cache = main[0]["correctness"]["enrichment"]
    foundation_cache = foundation[0]["correctness"]["enrichment"]
    if stable_cache["cache_supported"] or stable_cache["warm_search_calls"] != 24:
        failures.append("stable repeated-search baseline was not preserved")
    if (
        not foundation_cache["cache_supported"]
        or foundation_cache["cold_search_calls"] != 24
        or foundation_cache["warm_search_calls"] != 0
        or foundation_cache["warm_cache_hits"] != 24
    ):
        failures.append("foundation persistent query-cache acceptance failed")
    return {
        "benchmark": "phase0-core-engine-comparison-summary",
        "comparison_statistic": main[0]["comparison_statistic"],
        "identities": {name: next(iter(values)) for name, values in identities.items()},
        "stable_main": {
            "revision": main[0]["target"]["revision"],
            "source_digest_sha256": main[0]["target"]["source_digest_sha256"],
            "median_metrics": main_metrics,
            "median_peak_rss_bytes": main_peak,
            "correctness": main[0]["correctness"],
        },
        "foundation": {
            "revision": foundation[0]["target"]["revision"],
            "source_digest_sha256": foundation[0]["target"]["source_digest_sha256"],
            "median_metrics": foundation_metrics,
            "median_peak_rss_bytes": foundation_peak,
            "correctness": foundation[0]["correctness"],
        },
        "relative_comparisons": comparisons,
        "peak_memory_comparison": {
            "main_median": main_peak,
            "foundation_median": foundation_peak,
            "foundation_ceiling": peak_ceiling,
            "passed": peak_passed,
        },
        "whole_run_comparisons": total_comparisons,
        "failures": failures,
        "passed": not failures,
        "limitations": main[0]["limitations"],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--main-run", type=Path, action="append", required=True)
    parser.add_argument("--foundation-run", type=Path, action="append", required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = summarize(args.main_run, args.foundation_run)
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    if not result["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
