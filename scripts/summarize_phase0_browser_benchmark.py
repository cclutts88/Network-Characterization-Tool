"""Validate and summarize three stable and three rendered-browser benchmark runs."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import statistics
import uuid

from scripts.benchmark_phase0_http import address_digest


WORKLOADS = ("analysis", "hunt", "reach", "map")
FOUNDATION_ACTIONS = (
    "current:first-100", "current:last-20",
    "processed:first-100", "processed:last-20",
)
COMMON_ADDRESS_SHA256 = "09dcf4ae04213b940e824b8aeaf73ac0b71db509f46dd3fef26d7e558e2325b1"
EXPECTED_ANALYZE_FIRST_PAGE = [
    "10.10.0.1", "10.10.0.2", "10.10.0.3",
    *[f"10.20.0.{index}" for index in range(1, 23)],
]
HARNESS_COMPONENTS = {
    "scripts/benchmark_phase0_browser.mjs",
    "scripts/prepare_phase0_browser_data.py",
    "scripts/phase0_loopback_proxy.py",
    "scripts/run_phase0_browser_repeat.ps1",
    "scripts/sample_windows_browser.ps1",
    "scripts/snapshot_phase0_browser_state.py",
    "scripts/summarize_phase0_browser_benchmark.py",
}
EXPECTED_ACTION_CORRECTNESS = {
    "current_count": 120,
    "current_ordered_addresses_sha256": address_digest(
        [f"10.20.0.{index}" for index in range(1, 121)]
    ),
    "processed_count": 120,
    "processed_ordered_addresses_sha256": address_digest(
        sorted(f"10.20.0.{index}" for index in range(1, 121))
    ),
}
EXPECTED_MAP = {
    False: {"devices": 1, "gateways": 1, "interfaces": 2, "subnets": 2, "hosts": 4188, "relationships": 47, "nmap_records_read": 4315, "configuration_records_read": 4, "mac_observations": 4315, "mac_identified_hosts": 4188, "mac_conflicts": 0, "arp_neighbors": 0, "topology_neighbors": 0, "switchport_links": 0},
    True: {"devices": 1, "gateways": 0, "interfaces": 1000, "subnets": 0, "hosts": 4188, "relationships": 1041, "nmap_records_read": 4315, "configuration_records_read": 4, "mac_observations": 4315, "mac_identified_hosts": 4188, "mac_conflicts": 0, "arp_neighbors": 0, "topology_neighbors": 0, "switchport_links": 0},
}


def _validate_metric(metric: dict, limits: dict, *, foundation_action: bool = False) -> None:
    ready_key = "foundation_action_to_ready_ms" if foundation_action else "common_action_to_ready_ms"
    comparisons = {
        "action_to_ready_ms": limits[ready_key],
        "longest_task_ms": limits["longest_task_ms"],
        "long_task_total_ms": limits["long_task_total_ms"],
        "dom_nodes": limits["dom_nodes"],
        "js_heap_bytes": limits["js_heap_bytes"],
        "transfer_bytes": limits["transfer_bytes"],
        "request_count": limits["request_count"],
        "cls": limits["cls"],
        "lcp_ms": limits["lcp_ms"],
    }
    for field, limit in comparisons.items():
        if not isinstance(metric.get(field), (int, float)) or metric[field] > limit:
            raise ValueError(f"raw {field} limit exceeded")
    navigation = metric.get("navigation") or {}
    if not isinstance(navigation.get("load_event_ms"), (int, float)) or navigation["load_event_ms"] > limits["navigation_load_event_ms"]:
        raise ValueError("raw navigation load limit exceeded")


def _validate_correctness(workload: str, value: dict, foundation: bool) -> None:
    if workload == "analysis":
        if value.get("host_count") != 4188 or value.get("ordered_host_addresses_sha256") != COMMON_ADDRESS_SHA256 or value.get("rendered_first_page") != EXPECTED_ANALYZE_FIRST_PAGE:
            raise ValueError("Analyze exact rendered oracle mismatch")
    elif workload == "hunt":
        if value.get("host_count") != 4188 or value.get("finding_count") != 6125 or value.get("rendered_group_count") != 4188 or value.get("ordered_groups_sha256") != COMMON_ADDRESS_SHA256:
            raise ValueError("Hunt exact rendered oracle mismatch")
    elif workload == "reach":
        expected = {"saved_networks": 0, "hosts": 4188, "devices": 0 if foundation else 1, "device_collections": 0 if foundation else 1}
        if value != expected:
            raise ValueError("Reach exact rendered oracle mismatch")
    elif workload == "map":
        if value.get("summary") != EXPECTED_MAP[foundation]:
            raise ValueError("Map exact summary mismatch")
        expected = EXPECTED_MAP[foundation]
        displayed = {"devices": expected["devices"] + expected["gateways"], "interfaces": expected["interfaces"], "subnets": expected["subnets"], "hosts": expected["hosts"], "mac_observations": expected["mac_observations"], "arp_neighbors": expected["arp_neighbors"], "topology_neighbors": expected["topology_neighbors"]}
        if value.get("rendered") != displayed:
            raise ValueError("Map displayed counter mismatch")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load(paths: list[Path], label: str, foundation: bool) -> list[dict]:
    if len(paths) != 3:
        raise ValueError(f"{label} requires exactly three run files")
    runs = [json.loads(path.read_text(encoding="utf-8-sig")) for path in paths]
    if {run.get("repeat") for run in runs} != {1, 2, 3}:
        raise ValueError(f"{label} repeats must be exactly 1, 2 and 3")
    for result_path, run in zip(paths, runs):
        if run.get("benchmark") != "phase0-rendered-browser-comparison":
            raise ValueError(f"{label} contains the wrong benchmark")
        if run.get("foundation_capabilities") is not foundation:
            raise ValueError(f"{label} capability declaration is wrong")
        if run.get("passed") is not True or run.get("failures"):
            raise ValueError(f"{label} contains a failed repeat")
        if set(run.get("workloads") or {}) != set(WORKLOADS):
            raise ValueError(f"{label} does not contain the fixed page matrix")
        actions = {
            key
            for workload in run["workloads"].values()
            for key in (workload.get("actions") or {})
        }
        if actions != (set(FOUNDATION_ACTIONS) if foundation else set()):
            raise ValueError(f"{label} foundation action matrix is wrong")
        limits = run.get("limits") or {}
        for workload, workload_result in run["workloads"].items():
            for phase in ("cold", "reload"):
                _validate_metric(workload_result[phase].get("metric") or {}, limits)
                _validate_correctness(workload, workload_result[phase].get("correctness") or {}, foundation)
            for metric in (workload_result.get("actions") or {}).values():
                _validate_metric(metric, limits, foundation_action=True)
            expected_screenshots = 3 if foundation and workload == "analysis" else 2
            screenshots = workload_result.get("screenshots") or []
            if len(screenshots) != expected_screenshots:
                raise ValueError(f"{label} successful screenshot evidence is incomplete")
            for item in screenshots:
                filename = str(item.get("filename") or "")
                screenshot_path = result_path.parent / filename
                if Path(filename).name != filename or not screenshot_path.is_file() or _sha256(screenshot_path) != item.get("sha256"):
                    raise ValueError(f"{label} successful screenshot evidence is incomplete")
        analysis = run["workloads"]["analysis"]
        if analysis.get("action_correctness") != (EXPECTED_ACTION_CORRECTNESS if foundation else None):
            raise ValueError(f"{label} foundation action correctness mismatch")
        browser = run.get("browser") or {}
        if browser.get("profile_cleanup_verified") is not True:
            raise ValueError(f"{label} does not prove browser profile cleanup")
        if not (run.get("resources", {}).get("browser", {}).get("process_ids") or []):
            raise ValueError(f"{label} browser process identity is missing")
        browser_resource = run.get("resources", {}).get("browser", {})
        if browser_resource.get("process_tree_verified") is not True or len(browser_resource.get("processes") or []) != len(browser_resource.get("process_ids") or []):
            raise ValueError(f"{label} browser process tree evidence is missing")
        evidence = run.get("target", {}).get("identity_evidence", {})
        git, corpus, container = evidence.get("git", {}), evidence.get("corpus", {}), evidence.get("container", {})
        if (
            evidence.get("type") != "externally-verified-browser-controller-attestations"
            or evidence.get("validated") is not True
            or git.get("verification_method") != "controller:git-rev-parse-status-and-source-digest"
            or git.get("clean") is not True
            or git.get("revision") != run["target"].get("revision")
            or git.get("source_digest_sha256") != run["target"].get("source_digest_sha256")
            or corpus.get("verification_method") != "controller:canonical-corpus-regeneration"
            or corpus.get("manifest_sha256") != run.get("corpus_manifest_sha256")
            or container.get("verification_method") != "controller:docker-inspect-and-prewarm"
            or container.get("container_id") != run["target"].get("container_id")
            or container.get("image_id") != run["target"].get("container_image_id")
            or len(str(container.get("proxy_container_id") or "")) != 64
            or container.get("proxy_image_id") != run["target"].get("container_image_id")
            or any(container.get(key) is not True for key in ("fresh_container", "fresh_data_root", "staging_complete", "prewarm_complete", "live_http_prewarm_complete", "source_mount_read_only", "benchmark_mount_read_only", "network_internal", "loopback_only_publication"))
            or container.get("published_host_ip") != "127.0.0.1"
            or any(not str(container.get(key) or "") for key in ("source_mount_host_path", "benchmark_mount_host_path", "data_mount_host_path"))
            or len(str(container.get("network_id") or "")) != 64
        ):
            raise ValueError(f"{label} lacks required external identity evidence")
        state = run.get("retained_state") or {}
        before, after = state.get("pre") or {}, state.get("post") or {}
        if state.get("unchanged") is not True or before != after:
            raise ValueError(f"{label} retained state changed during the run")
        for field in ("database_logical_sha256", "database_main_file_sha256", "evidence_sha256"):
            if len(str(before.get(field) or "")) != 64:
                raise ValueError(f"{label} retained state identity is incomplete")
        components = run.get("harness_components") or {}
        if set(components) != HARNESS_COMPONENTS or any(len(str(value)) != 64 for value in components.values()):
            raise ValueError(f"{label} benchmark harness component identity is incomplete")
        cleanup = run.get("controller_cleanup") or {}
        runner_result = result_path.parent / "runner-result.json"
        try:
            runner_payload = json.loads(runner_result.read_text(encoding="utf-8-sig")) if runner_result.is_file() else None
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            runner_payload = None
        final_payload = dict(run)
        final_payload.pop("controller_cleanup", None)
        if (
            cleanup.get("verification_method") != "controller:post-run-resource-verification"
            or cleanup.get("run_succeeded") is not True
            or any(cleanup.get(key) is not True for key in ("app_container_removed", "relay_container_removed", "internal_network_removed", "data_root_removed", "browser_profile_removed"))
            or cleanup.get("controller_token") != container.get("controller_token")
            or not runner_result.is_file()
            or cleanup.get("runner_result_sha256") != _sha256(runner_result)
            or runner_payload != final_payload
        ):
            raise ValueError(f"{label} controller cleanup evidence is incomplete")
    for field in ("revision", "source_digest_sha256", "container_image_id"):
        if len({run["target"][field] for run in runs}) != 1:
            raise ValueError(f"{label} target {field} changed between repeats")
    if len({run["retained_state"]["pre"]["database_logical_sha256"] for run in runs}) != 1:
        raise ValueError(f"{label} starting database state differs between repeats")
    if len({run["retained_state"]["pre"]["evidence_sha256"] for run in runs}) != 1:
        raise ValueError(f"{label} starting evidence differs between repeats")
    return sorted(runs, key=lambda item: item["repeat"])


def _median_metrics(runs: list[dict]) -> dict:
    result: dict[str, dict] = {}
    for workload in WORKLOADS:
        result[workload] = {}
        for phase in ("cold", "reload"):
            result[workload][phase] = {
                field: statistics.median(
                    run["workloads"][workload][phase]["metric"][field] for run in runs
                )
                for field in (
                    "action_to_ready_ms", "dom_nodes", "js_heap_bytes", "transfer_bytes",
                    "request_count", "long_task_total_ms", "longest_task_ms", "cls", "lcp_ms",
                )
            }
    return result


def summarize(main_paths: list[Path], foundation_paths: list[Path]) -> dict:
    main = _load(main_paths, "stable main", False)
    foundation = _load(foundation_paths, "foundation", True)
    all_runs = main + foundation
    for field in ("runner_version", "runner_sha256", "harness_components", "corpus_manifest_sha256", "limits"):
        values = {json.dumps(run[field], sort_keys=True) if isinstance(run[field], dict) else run[field] for run in all_runs}
        if len(values) != 1:
            raise ValueError(f"comparison identity differs: {field}")
    browser_identities = {
        json.dumps({key: run["browser"][key] for key in ("version", "executable_sha256", "playwright_version", "node_version", "settings")}, sort_keys=True)
        for run in all_runs
    }
    if len(browser_identities) != 1:
        raise ValueError("browser identity or fixed settings differ")
    if len({run["target"]["container_id"] for run in all_runs}) != 6:
        raise ValueError("every repeat requires a unique fresh app container")
    if len({run["browser"]["profile_root_token"] for run in all_runs}) != 6:
        raise ValueError("every repeat requires a unique browser profile root")
    if len({run["target"]["container_image_id"] for run in all_runs}) != 1:
        raise ValueError("all six repeats require the same container image")
    if len({run["target"]["identity_evidence"]["container"]["network_id"] for run in all_runs}) != 6:
        raise ValueError("every repeat requires a unique internal Docker network")
    if len({run["target"]["identity_evidence"]["container"]["proxy_container_id"] for run in all_runs}) != 6:
        raise ValueError("every repeat requires a unique loopback relay container")
    data_roots = [run["target"]["identity_evidence"]["container"]["data_mount_host_path"] for run in all_runs]
    if len(set(data_roots)) != 6:
        raise ValueError("every repeat requires a unique data root")
    controller_tokens = [run["target"]["identity_evidence"]["container"]["controller_token"] for run in all_runs]
    try:
        valid_tokens = all(str(uuid.UUID(token)) == token.lower() for token in controller_tokens)
    except (ValueError, AttributeError):
        valid_tokens = False
    if len(set(controller_tokens)) != 6 or not valid_tokens:
        raise ValueError("every repeat requires a unique controller token")
    for run in all_runs:
        resources = run["resources"]
        limits = run["limits"]
        if resources["browser"]["peak_working_set_bytes"] > limits["browser_peak_working_set_bytes"]:
            raise ValueError("browser peak memory limit exceeded")
        if resources["browser"]["cpu_seconds"] > limits["browser_cpu_seconds"]:
            raise ValueError("browser CPU limit exceeded")
        if resources["app"]["peak_memory_bytes"] > limits["app_peak_memory_bytes"]:
            raise ValueError("app peak memory limit exceeded")
        if resources["app"]["cpu_seconds"] > limits["app_cpu_seconds"]:
            raise ValueError("app CPU limit exceeded")
    foundation_action_medians = {
        action: {
            field: statistics.median(
                run["workloads"]["analysis"]["actions"][action][field]
                for run in foundation
            )
            for field in ("action_to_ready_ms", "dom_nodes", "js_heap_bytes", "transfer_bytes")
        }
        for action in FOUNDATION_ACTIONS
    }
    return {
        "benchmark": "phase0-rendered-browser-summary",
        "passed": True,
        "comparison_rule": "three-repeat median under predeclared absolute limits; no relative cross-revision gate",
        "stable_main": {
            "revision": main[0]["target"]["revision"],
            "medians": _median_metrics(main),
            "browser_peak_working_set_bytes_median": statistics.median(run["resources"]["browser"]["peak_working_set_bytes"] for run in main),
            "browser_cpu_seconds_median": statistics.median(run["resources"]["browser"]["cpu_seconds"] for run in main),
            "app_peak_memory_bytes_median": statistics.median(run["resources"]["app"]["peak_memory_bytes"] for run in main),
            "app_cpu_seconds_median": statistics.median(run["resources"]["app"]["cpu_seconds"] for run in main),
        },
        "foundation": {
            "revision": foundation[0]["target"]["revision"],
            "medians": _median_metrics(foundation),
            "actions": foundation_action_medians,
            "browser_peak_working_set_bytes_median": statistics.median(run["resources"]["browser"]["peak_working_set_bytes"] for run in foundation),
            "browser_cpu_seconds_median": statistics.median(run["resources"]["browser"]["cpu_seconds"] for run in foundation),
            "app_peak_memory_bytes_median": statistics.median(run["resources"]["app"]["peak_memory_bytes"] for run in foundation),
            "app_cpu_seconds_median": statistics.median(run["resources"]["app"]["cpu_seconds"] for run in foundation),
        },
        "limits": main[0]["limits"],
        "browser": {key: main[0]["browser"][key] for key in ("version", "executable_sha256", "playwright_version", "node_version", "settings")},
        "limitations": [
            "Same-host Windows Chrome comparison only.",
            "No browser-container, Linux-browser, GPU, human-interaction, multi-process, Range, production-scale or mission performance claim.",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--main", nargs=3, type=Path, required=True)
    parser.add_argument("--foundation", nargs=3, type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = summarize(args.main, args.foundation)
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")


if __name__ == "__main__":
    main()
