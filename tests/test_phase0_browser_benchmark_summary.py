import copy
import hashlib
import json
from pathlib import Path

import pytest

from scripts.summarize_phase0_browser_benchmark import (
    COMMON_ADDRESS_SHA256,
    EXPECTED_ANALYZE_FIRST_PAGE,
    EXPECTED_ACTION_CORRECTNESS,
    EXPECTED_MAP,
    FOUNDATION_ACTIONS,
    HARNESS_COMPONENTS,
    WORKLOADS,
    summarize,
)


def _metric(value=10):
    return {
        "action_to_ready_ms": value,
        "dom_nodes": 100,
        "js_heap_bytes": 1000,
        "transfer_bytes": 2000,
        "request_count": 3,
        "long_task_total_ms": 0,
        "longest_task_ms": 0,
        "cls": 0,
        "lcp_ms": 5,
        "navigation": {"load_event_ms": value},
    }


def _run(repeat: int, foundation: bool):
    actions = {name: _metric() for name in FOUNDATION_ACTIONS} if foundation else {}
    result = {
        "benchmark": "phase0-rendered-browser-comparison",
        "runner_version": "phase0-rendered-browser:2",
        "runner_sha256": "a" * 64,
        "harness_components": {name: "b" * 64 for name in HARNESS_COMPONENTS},
        "repeat": repeat,
        "foundation_capabilities": foundation,
        "target": {
            "revision": ("2" if foundation else "1") * 40,
            "source_digest_sha256": ("d" if foundation else "c") * 64,
            "container_id": f"{repeat + (3 if foundation else 0):064x}",
            "container_image_id": "sha256:" + "e" * 64,
        },
        "corpus_manifest_sha256": "f" * 64,
        "browser": {
            "version": "155.0.8059.39",
            "executable_sha256": "9" * 64,
            "playwright_version": "1.62.1",
            "node_version": "v24.19.0",
            "profile_root_token": f"{'foundation' if foundation else 'main'}-{repeat}",
            "profile_cleanup_verified": True,
            "settings": {"viewport": "1440x900"},
        },
        "workloads": {},
        "resources": {
            "browser": {"process_ids": [repeat], "processes": [{"process_id": repeat, "parent_process_id": 0, "creation_date": "20261009120000.000000-300", "executable_path": "C:\\Chrome\\chrome.exe"}], "process_tree_verified": True, "peak_working_set_bytes": 1000, "cpu_seconds": 2},
            "app": {"peak_memory_bytes": 1000, "cpu_seconds": 1},
        },
        "retained_state": {"pre": {
            "database_logical_sha256": ("4" if foundation else "3") * 64,
            "database_main_file_sha256": ("6" if foundation else "5") * 64,
            "evidence_sha256": "7" * 64,
        }},
        "limits": {
            "common_action_to_ready_ms": 100,
            "foundation_action_to_ready_ms": 100,
            "navigation_load_event_ms": 100,
            "longest_task_ms": 100,
            "long_task_total_ms": 100,
            "dom_nodes": 1000,
            "js_heap_bytes": 10000,
            "transfer_bytes": 10000,
            "request_count": 10,
            "cls": 1,
            "lcp_ms": 100,
            "browser_peak_working_set_bytes": 2000,
            "browser_cpu_seconds": 10,
            "app_peak_memory_bytes": 2000,
            "app_cpu_seconds": 10,
        },
        "passed": True,
        "failures": [],
    }
    correctness = {
        "analysis": {"host_count": 4188, "ordered_host_addresses_sha256": COMMON_ADDRESS_SHA256, "rendered_first_page": EXPECTED_ANALYZE_FIRST_PAGE},
        "hunt": {"host_count": 4188, "finding_count": 6125, "rendered_group_count": 4188, "ordered_groups_sha256": COMMON_ADDRESS_SHA256},
        "reach": {"saved_networks": 0, "hosts": 4188, "devices": 0 if foundation else 1, "device_collections": 0 if foundation else 1},
        "map": {"summary": copy.deepcopy(EXPECTED_MAP[foundation]), "rendered": {"devices": EXPECTED_MAP[foundation]["devices"] + EXPECTED_MAP[foundation]["gateways"], "interfaces": EXPECTED_MAP[foundation]["interfaces"], "subnets": EXPECTED_MAP[foundation]["subnets"], "hosts": 4188, "mac_observations": 4315, "arp_neighbors": 0, "topology_neighbors": 0}},
    }
    for name in WORKLOADS:
        screenshot_count = 3 if foundation and name == "analysis" else 2
        result["workloads"][name] = {
            "cold": {"metric": _metric(repeat), "correctness": correctness[name]},
            "reload": {"metric": _metric(repeat + 1), "correctness": correctness[name]},
            "actions": actions if name == "analysis" else {},
            "action_correctness": EXPECTED_ACTION_CORRECTNESS if foundation and name == "analysis" else None,
            "screenshots": [{"filename": f"{name}-{index}.png", "sha256": "a" * 64} for index in range(screenshot_count)],
        }
    token = f"00000000-0000-0000-0000-{repeat + (3 if foundation else 0):012d}"
    result["target"]["identity_evidence"] = {
        "type": "externally-verified-browser-controller-attestations", "validated": True,
        "git": {"verification_method": "controller:git-rev-parse-status-and-source-digest", "clean": True, "revision": result["target"]["revision"], "source_digest_sha256": result["target"]["source_digest_sha256"]},
        "corpus": {"verification_method": "controller:canonical-corpus-regeneration", "manifest_sha256": result["corpus_manifest_sha256"]},
        "container": {"verification_method": "controller:docker-inspect-and-prewarm", "container_id": result["target"]["container_id"], "image_id": result["target"]["container_image_id"], "proxy_container_id": f"{repeat + (9 if foundation else 6):064x}", "proxy_image_id": result["target"]["container_image_id"], "fresh_container": True, "fresh_data_root": True, "staging_complete": True, "prewarm_complete": True, "live_http_prewarm_complete": True, "source_mount_read_only": True, "benchmark_mount_read_only": True, "source_mount_host_path": "C:\\target", "benchmark_mount_host_path": "C:\\benchmark", "data_mount_host_path": f"C:\\data-{token}", "network_internal": True, "loopback_only_publication": True, "published_host_ip": "127.0.0.1", "network_id": f"{repeat + (3 if foundation else 0):064x}", "controller_token": token},
    }
    result["retained_state"]["post"] = copy.deepcopy(result["retained_state"]["pre"])
    result["retained_state"]["unchanged"] = True
    result["controller_cleanup"] = {
        "verification_method": "controller:post-run-resource-verification",
        "run_succeeded": True,
        "app_container_removed": True,
        "relay_container_removed": True,
        "internal_network_removed": True,
        "data_root_removed": True,
        "browser_profile_removed": True,
        "controller_token": token,
        "runner_result_sha256": "",
    }
    return result


def _write(tmp_path: Path, runs: list[dict], prefix: str):
    paths = []
    for index, run in enumerate(runs, start=1):
        run_root = tmp_path / f"{prefix}-{index}"
        run_root.mkdir()
        for workload in run["workloads"].values():
            for screenshot in workload["screenshots"]:
                screenshot_path = run_root / screenshot["filename"]
                screenshot_path.write_bytes(f"{prefix}:{index}:{screenshot['filename']}".encode())
                screenshot["sha256"] = hashlib.sha256(screenshot_path.read_bytes()).hexdigest()
        runner_result = run_root / "runner-result.json"
        runner_payload = copy.deepcopy(run)
        runner_payload.pop("controller_cleanup")
        runner_result.write_text(json.dumps(runner_payload), encoding="utf-8")
        run["controller_cleanup"]["runner_result_sha256"] = hashlib.sha256(runner_result.read_bytes()).hexdigest()
        path = run_root / "result.json"
        path.write_text(json.dumps(run), encoding="utf-8")
        paths.append(path)
    return paths


def test_summary_accepts_exact_three_repeat_matrix(tmp_path):
    main = _write(tmp_path, [_run(index, False) for index in (1, 2, 3)], "main")
    foundation = _write(tmp_path, [_run(index, True) for index in (1, 2, 3)], "foundation")
    result = summarize(main, foundation)
    assert result["passed"] is True
    assert result["stable_main"]["medians"]["analysis"]["cold"]["action_to_ready_ms"] == 2
    assert set(result["foundation"]["actions"]) == set(FOUNDATION_ACTIONS)


@pytest.mark.parametrize(
    "mutation, message",
    [
        (lambda run: run["browser"].update(profile_cleanup_verified=False), "profile cleanup"),
        (lambda run: run["workloads"].pop("map"), "fixed page matrix"),
        (lambda run: run["retained_state"]["post"].update(evidence_sha256="bad"), "retained state changed"),
        (lambda run: run["resources"]["browser"].update(peak_working_set_bytes=3000), "browser peak memory"),
        (lambda run: run["workloads"]["analysis"]["cold"]["metric"].update(dom_nodes=2000), "raw dom_nodes limit"),
        (lambda run: run["workloads"]["map"]["reload"]["correctness"]["summary"].update(relationships=999), "Map exact summary"),
        (lambda run: run["target"]["identity_evidence"]["container"].update(network_internal=False), "external identity evidence"),
        (lambda run: run["workloads"]["hunt"].update(screenshots=[]), "screenshot evidence"),
        (lambda run: run["harness_components"].pop("scripts/phase0_loopback_proxy.py"), "harness component identity"),
        (lambda run: run["controller_cleanup"].update(data_root_removed=False), "controller cleanup evidence"),
        (lambda run: run["workloads"]["analysis"]["cold"]["correctness"].update(rendered_first_page=["wrong"] * 25), "Analyze exact rendered oracle"),
    ],
)
def test_summary_rejects_incomplete_or_over_limit_runs(tmp_path, mutation, message):
    main_runs = [_run(index, False) for index in (1, 2, 3)]
    foundation_runs = [_run(index, True) for index in (1, 2, 3)]
    mutation(foundation_runs[0])
    main = _write(tmp_path, main_runs, "main")
    foundation = _write(tmp_path, foundation_runs, "foundation")
    with pytest.raises(ValueError, match=message):
        summarize(main, foundation)


def test_summary_rejects_reused_container_identity(tmp_path):
    main_runs = [_run(index, False) for index in (1, 2, 3)]
    foundation_runs = [_run(index, True) for index in (1, 2, 3)]
    foundation_runs[0]["target"]["container_id"] = main_runs[0]["target"]["container_id"]
    foundation_runs[0]["target"]["identity_evidence"]["container"]["container_id"] = main_runs[0]["target"]["container_id"]
    main = _write(tmp_path, main_runs, "main")
    foundation = _write(tmp_path, foundation_runs, "foundation")
    with pytest.raises(ValueError, match="unique fresh app container"):
        summarize(main, foundation)


@pytest.mark.parametrize(
    "field,message",
    [
        ("data_mount_host_path", "unique data root"),
        ("controller_token", "unique controller token"),
    ],
)
def test_summary_rejects_reused_controller_identity(tmp_path, field, message):
    main_runs = [_run(index, False) for index in (1, 2, 3)]
    foundation_runs = [_run(index, True) for index in (1, 2, 3)]
    foundation_runs[0]["target"]["identity_evidence"]["container"][field] = main_runs[0]["target"]["identity_evidence"]["container"][field]
    if field == "controller_token":
        foundation_runs[0]["controller_cleanup"]["controller_token"] = main_runs[0]["controller_cleanup"]["controller_token"]
    main = _write(tmp_path, main_runs, "main")
    foundation = _write(tmp_path, foundation_runs, "foundation")
    with pytest.raises(ValueError, match=message):
        summarize(main, foundation)


def test_summary_rejects_tampered_screenshot(tmp_path):
    main = _write(tmp_path, [_run(index, False) for index in (1, 2, 3)], "main")
    foundation = _write(tmp_path, [_run(index, True) for index in (1, 2, 3)], "foundation")
    first_screenshot = json.loads(foundation[0].read_text(encoding="utf-8"))["workloads"]["analysis"]["screenshots"][0]["filename"]
    (foundation[0].parent / first_screenshot).write_bytes(b"tampered")
    with pytest.raises(ValueError, match="screenshot evidence"):
        summarize(main, foundation)


def test_summary_rejects_tampered_runner_result(tmp_path):
    main = _write(tmp_path, [_run(index, False) for index in (1, 2, 3)], "main")
    foundation = _write(tmp_path, [_run(index, True) for index in (1, 2, 3)], "foundation")
    (foundation[0].parent / "runner-result.json").write_text("tampered", encoding="utf-8")
    with pytest.raises(ValueError, match="controller cleanup evidence"):
        summarize(main, foundation)
