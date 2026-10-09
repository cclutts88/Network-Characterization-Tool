"""Validate and summarize three stable and three foundation HTTP benchmark runs."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import statistics

try:
    from scripts.benchmark_phase0_http import (
        COMMON_WORKLOADS, address_digest, expected_workloads, request_order,
    )
except ModuleNotFoundError:
    from benchmark_phase0_http import (
        COMMON_WORKLOADS, address_digest, expected_workloads, request_order,
    )


def _load(paths: list[Path], label: str, foundation: bool) -> list[dict]:
    if len(paths) != 3:
        raise ValueError(f"{label} requires exactly three run files")
    runs = [json.loads(path.read_text(encoding="utf-8")) for path in paths]
    if {run.get("repeat") for run in runs} != {1, 2, 3}:
        raise ValueError(f"{label} repeats must be exactly 1, 2 and 3")
    for run in runs:
        if not run.get("passed") or run.get("failures"):
            raise ValueError(f"{label} contains a failed repeat")
        if run.get("foundation_capabilities") is not foundation:
            raise ValueError(f"{label} capability declaration is wrong")
        if set(run.get("metrics") or {}) != set(expected_workloads(foundation)):
            raise ValueError(f"{label} does not contain the fixed capability matrix")
        evidence = run.get("target", {}).get("identity_evidence", {})
        git, container = evidence.get("git", {}), evidence.get("container_image", {})
        if (
            evidence.get("type") != "externally-verified-controller-attestations"
            or
            evidence.get("validated") is not True
            or git.get("verification_method") != "controller:git-rev-parse-status-and-source-digest"
            or git.get("clean") is not True
            or git.get("revision") != run["target"].get("revision")
            or git.get("source_digest_sha256") != run["target"].get("source_digest_sha256")
            or container.get("verification_method") != "controller:docker-image-inspect"
            or container.get("image_id") != run["target"].get("container_image_id")
            or len(str(container.get("container_id") or "")) != 64
            or container.get("network_mode") != "none"
            or container.get("source_mount_read_only") is not True
            or container.get("corpus_mount_read_only") is not True
            or container.get("fresh_container") is not True
        ):
            raise ValueError(f"{label} lacks required external identity evidence")
        session = run.get("request_session", {})
        if (
            session.get("kind") != "one fixed ordered in-process TestClient session"
            or session.get("order") != request_order(foundation)
            or session.get("background_work_disabled_before_measurement") is not True
            or session.get("staging_complete_before_measurement") is not True
        ):
            raise ValueError(f"{label} request-session declaration is wrong")
    for field in ("revision", "source_digest_sha256", "container_image_id"):
        if len({run["target"][field] for run in runs}) != 1:
            raise ValueError(f"{label} target {field} changed between repeats")
    return sorted(runs, key=lambda run: run["repeat"])


def _expected_common(*, foundation: bool) -> dict:
    map_summary = {
        "devices": 1, "gateways": 0, "interfaces": 1000, "subnets": 0,
        "hosts": 4188, "relationships": 1041, "nmap_records_read": 4315,
        "configuration_records_read": 4, "mac_observations": 4315,
        "mac_identified_hosts": 4188, "mac_conflicts": 0,
        "arp_neighbors": 0, "topology_neighbors": 0, "switchport_links": 0,
    } if foundation else {
        "devices": 1, "gateways": 1, "interfaces": 2, "subnets": 2,
        "hosts": 4188, "relationships": 47, "nmap_records_read": 4315,
        "configuration_records_read": 4, "mac_observations": 4315,
        "mac_identified_hosts": 4188, "mac_conflicts": 0,
        "arp_neighbors": 0, "topology_neighbors": 0, "switchport_links": 0,
    }
    return {
        "current": {
            "status": "analysis_network_complete", "host_count": 4188,
            "hosts": 4188, "scan_count": 7,
            "unique_host_addresses": 4188,
            "ordered_host_addresses_sha256":
                "09dcf4ae04213b940e824b8aeaf73ac0b71db509f46dd3fef26d7e558e2325b1",
        },
        "hunt": {
            "status": "hunting_network_complete", "host_count": 4188,
            "finding_count": 6125,
        },
        "map": map_summary,
        "reach": {"hosts": 4188, "devices": 0 if foundation else 1, "saved_networks": 0},
    }


EXPECTED_FOUNDATION = {
    "inventory_subnet": "10.20.0.0/24",
    "current_filtered_total": 120,
    "current_first_count": 100,
    "current_last_count": 20,
    "current_ordered_addresses_sha256": address_digest(
        [f"10.20.0.{index}" for index in range(1, 121)]
    ),
    "current_page_overlap_count": 0,
    "export_count": 120,
    "export_addresses_sha256": address_digest(
        [f"10.20.0.{index}" for index in range(1, 121)]
    ),
    "lfa_member_count": 120,
    "processed_scope_count": 1,
    "processed_endpoint_total": 120,
    "processed_first_count": 100,
    "processed_last_count": 20,
    "processed_ordered_addresses_sha256": address_digest(
        sorted(f"10.20.0.{index}" for index in range(1, 121))
    ),
    "processed_page_overlap_count": 0,
    "latest_contract": "latest-supported-nmap-observations:1",
    "service_total": 1,
}


def _validate_correctness(runs: list[dict], foundation: bool) -> None:
    expected_changes = [] if foundation else [
        "device_analysis_cache", "device_collections", "scan_analysis_cache",
    ]
    for run in runs:
        value = run["correctness"]
        if value["staged"] != {"nmap_files": 9, "device_files": 4}:
            raise ValueError("Staged canonical evidence count is wrong")
        if value["common"] != _expected_common(foundation=foundation):
            raise ValueError("Common HTTP correctness oracle mismatch")
        if value["foundation"] != (EXPECTED_FOUNDATION if foundation else None):
            raise ValueError("Foundation HTTP correctness oracle mismatch")
        if value["database_tables_changed_by_requests"] != expected_changes:
            raise ValueError("Request-path database mutation oracle mismatch")
        if value["allowed_database_table_changes"] != expected_changes:
            raise ValueError("Allowed request-path database mutation declaration mismatch")
        if value["database_logical_state_unchanged"] is not foundation:
            raise ValueError("Request-path logical database state declaration mismatch")
        if foundation:
            if value["database_logical_sha256_before"] != value["database_logical_sha256_after"]:
                raise ValueError("Foundation request path changed logical database state")
            if value["database_main_file_before"] != value["database_main_file_after"]:
                raise ValueError("Foundation request path changed the database file")
        elif value["database_logical_sha256_before"] == value["database_logical_sha256_after"]:
            raise ValueError("Stable request path did not record the expected cache writes")
        evidence_digest = value.get("evidence_sha256_unchanged")
        if not isinstance(evidence_digest, str) or len(evidence_digest) != 64:
            raise ValueError("Exact retained evidence identity is missing")


def _medians(runs: list[dict], names: list[str]) -> dict:
    return {
        name: {
            key: statistics.median(run["metrics"][name][key] for run in runs)
            for key in ("wall_seconds", "cpu_seconds", "response_bytes")
        }
        for name in names
    }


def summarize(main_paths: list[Path], foundation_paths: list[Path]) -> dict:
    main = _load(main_paths, "stable main", False)
    foundation = _load(foundation_paths, "foundation", True)
    all_runs = main + foundation
    identities = {
        key: {json.dumps(run[key], sort_keys=True) if isinstance(run[key], dict) else run[key] for run in all_runs}
        for key in ("runner_version", "runner_sha256", "comparison_statistic", "limits")
    }
    identities["corpus_manifest_sha256"] = {run["corpus"]["manifest_sha256"] for run in all_runs}
    identities["container_image_id"] = {run["target"]["container_image_id"] for run in all_runs}
    mismatches = [key for key, values in identities.items() if len(values) != 1]
    if mismatches:
        raise ValueError("Comparison identity differs: " + ", ".join(mismatches))
    container_ids = [run["target"]["identity_evidence"]["container_image"]["container_id"] for run in all_runs]
    if len(set(container_ids)) != 6:
        raise ValueError("Each repeat requires a unique fresh container")
    _validate_correctness(main, False)
    _validate_correctness(foundation, True)
    for label, runs in (("stable main", main), ("foundation", foundation)):
        evidence_digests = {
            run["correctness"]["evidence_sha256_unchanged"] for run in runs
        }
        if len(evidence_digests) != 1:
            raise ValueError(f"{label} retained evidence identity differs between repeats")

    main_medians = _medians(main, COMMON_WORKLOADS)
    foundation_medians = _medians(foundation, expected_workloads(True))
    relative = main[0]["limits"]["relative"]
    comparisons, failures = {}, []
    for name in COMMON_WORKLOADS:
        comparisons[name] = {}
        for key, allowance_key in (
            ("wall_seconds", "wall_seconds_allowance"),
            ("cpu_seconds", "cpu_seconds_allowance"),
        ):
            baseline, observed = main_medians[name][key], foundation_medians[name][key]
            ceiling = max(
                baseline * relative["foundation_over_main_ratio"],
                baseline + relative[allowance_key],
            )
            passed = observed <= ceiling
            comparisons[name][key] = {
                "main_median": baseline, "foundation_median": observed,
                "foundation_ceiling": ceiling, "passed": passed,
            }
            if not passed:
                failures.append(f"{name} {key} relative limit exceeded")
    main_peak = statistics.median(run["total"]["peak_rss_bytes"] for run in main)
    foundation_peak = statistics.median(run["total"]["peak_rss_bytes"] for run in foundation)
    peak_ceiling = max(
        main_peak * relative["foundation_over_main_ratio"],
        main_peak + relative["peak_rss_bytes_allowance"],
    )
    if foundation_peak > peak_ceiling:
        failures.append("peak memory relative limit exceeded")
    return {
        "benchmark": "phase0-http-persistent-view-summary",
        "passed": not failures,
        "failures": failures,
        "comparison_statistic": main[0]["comparison_statistic"],
        "identities": {key: next(iter(values)) for key, values in identities.items()},
        "stable_main": {
            "revision": main[0]["target"]["revision"],
            "median_metrics": main_medians,
            "correctness": main[0]["correctness"],
        },
        "foundation": {
            "revision": foundation[0]["target"]["revision"],
            "median_metrics": foundation_medians,
            "correctness": foundation[0]["correctness"],
        },
        "common_endpoint_comparisons": comparisons,
        "peak_memory_comparison": {
            "main_median": main_peak, "foundation_median": foundation_peak,
            "foundation_ceiling": peak_ceiling, "passed": foundation_peak <= peak_ceiling,
        },
        "limitations": foundation[0]["limitations"],
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
