#!/usr/bin/env python3
"""Strict three-repeat summary for the concurrent-client benchmark."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import statistics

from scripts.benchmark_phase0_concurrent_clients import (
    CYCLES,
    EXPECTED_MAP_SUMMARY,
    EXPECTED_ORDERED_HOSTS_SHA256,
    MAX_RESPONSE_BYTES,
    REQUEST_ORDER,
    WORKER_COUNT,
    _latency,
)
from scripts.verify_phase0_concurrent_state import EXPECTED_CHANGED_TABLES


RAW_ARTIFACTS = {
    "setup.json", "preparation.json", "before.json", "client-run.json",
    "verification.json", "application.log", "application-processes.json",
    "application-resource-before.json", "application-resource-after.json",
    "container-inspection.json", "git-fresh-attestation.json",
}
EXPECTED_CLIENT_LIMITS = {
    "total_wall_seconds": 240,
    "read_p95_seconds": 30,
    "write_p95_seconds": 10,
    "request_timeout_seconds": 60,
    "response_bytes": MAX_RESPONSE_BYTES,
}
EXPECTED_RESOURCE_LIMITS = {
    "app_cpu_seconds": 240,
    "client_cpu_seconds": 240,
    "app_peak_memory_bytes": 2147483648,
    "client_peak_memory_bytes": 2147483648,
}
EXPECTED_UVICORN_ARGS = [
    "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080",
]


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _validate_result_bindings(
    result: dict, run: dict, verification: dict, failures: list[str], prefix: str
) -> None:
    if result.get("client_summary") != run.get("summary"):
        failures.append(f"{prefix}: final client summary diverges from the raw client run")
    expected_state = {
        "passed": verification.get("passed"),
        "actual_changed_tables": verification.get("actual_changed_tables"),
        "evidence_sha256": (verification.get("after") or {}).get("evidence_sha256"),
        "evidence_file_count": (verification.get("after") or {}).get("evidence_file_count"),
        "database_integrity": (verification.get("after") or {}).get("database_integrity"),
    }
    if result.get("state_verification") != expected_state:
        failures.append(f"{prefix}: final state claims diverge from raw verification")


def _validate_fixed_limits(result: dict, run: dict, failures: list[str], prefix: str) -> None:
    if (run.get("summary") or {}).get("limits") != EXPECTED_CLIENT_LIMITS:
        failures.append(f"{prefix}: client limits differ from the predeclared contract")
    if (result.get("resources") or {}).get("limits") != EXPECTED_RESOURCE_LIMITS:
        failures.append(f"{prefix}: resource limits differ from the predeclared contract")


def _validate_git_fresh_attestation(
    identity: dict, attestation: dict, failures: list[str], prefix: str
) -> None:
    if (
        attestation.get("verification_method") != "controller:git-status-and-fresh-root-preflight"
        or attestation.get("revision") != identity.get("revision")
        or attestation.get("target_root") != identity.get("target_root")
        or attestation.get("status_porcelain") != ""
        or attestation.get("clean") is not True
        or attestation.get("data_root_host_path") != identity.get("data_root_host_path")
        or attestation.get("data_root_existed_before") is not False
        or attestation.get("data_root_empty_after_creation") is not True
    ):
        failures.append(f"{prefix}: clean-source or fresh-root attestation is invalid")


def _validate_collision_bounds(collisions: list[dict], failures: list[str], prefix: str) -> None:
    if any(
        item.get("bytes", MAX_RESPONSE_BYTES["write"] + 1) > MAX_RESPONSE_BYTES["write"]
        or item.get("latency_seconds", 61) > EXPECTED_CLIENT_LIMITS["request_timeout_seconds"]
        for item in collisions
    ):
        failures.append(f"{prefix}: collision response size or timeout limit exceeded")


def _validate_raw(directory: Path, result: dict, failures: list[str], repeat: int) -> None:
    prefix = f"repeat {repeat}"
    declared = result.get("raw_artifacts") or {}
    if set(declared) != RAW_ARTIFACTS:
        failures.append(f"{prefix}: raw artifact declaration is incomplete")
        return
    for name, digest in declared.items():
        path = directory / name
        if not path.is_file() or _sha256(path) != digest:
            failures.append(f"{prefix}: raw artifact hash mismatch for {name}")
            return
    setup = _read_json(directory / "setup.json")
    preparation = _read_json(directory / "preparation.json")
    before = _read_json(directory / "before.json")
    run = _read_json(directory / "client-run.json")
    verification = _read_json(directory / "verification.json")
    processes = _read_json(directory / "application-processes.json")
    resource_before = _read_json(directory / "application-resource-before.json")
    resource_after = _read_json(directory / "application-resource-after.json")
    inspection = _read_json(directory / "container-inspection.json")
    attestation = _read_json(directory / "git-fresh-attestation.json")
    identity = result.get("identity") or {}
    _validate_result_bindings(result, run, verification, failures, prefix)
    _validate_fixed_limits(result, run, failures, prefix)
    _validate_git_fresh_attestation(identity, attestation, failures, prefix)
    if (
        preparation.get("revision") != identity.get("revision")
        or preparation.get("source_digest_sha256") != identity.get("source_digest_sha256")
        or preparation.get("corpus_manifest_sha256") != identity.get("corpus_manifest_sha256")
    ):
        failures.append(f"{prefix}: preparation identity does not bind to the result")
    if processes != identity.get("single_application_process"):
        failures.append(f"{prefix}: process capture does not bind to the result")
    application = inspection.get("application") or {}
    client = inspection.get("client") or {}
    network = inspection.get("network") or {}
    if (
        inspection.get("verification_method") != "controller:docker-inspect-sanitized"
        or application.get("id") != identity.get("app_container_id")
        or client.get("id") != identity.get("client_container_id")
        or application.get("image") != identity.get("image_id")
        or client.get("image") != identity.get("image_id")
        or network.get("id") != identity.get("network_id")
        or network.get("internal") is not True
        or application.get("networks") != [network.get("name")]
        or client.get("networks") != [network.get("name")]
        or application.get("path") != "python"
        or client.get("path") != "python"
        or application.get("args") != EXPECTED_UVICORN_ARGS
        or client.get("args") != [
            "scripts/benchmark_phase0_concurrent_clients.py", "--mode", "run",
            "--base-url", f"http://{network.get('name', '').replace('nct-phase0-concurrent-net', 'nct-phase0-concurrent-app')}:8080",
            "--setup", "/artifacts/setup.json", "--output", "/artifacts/client-run.json",
        ]
    ):
        failures.append(f"{prefix}: sanitized container inspection is incomplete or inconsistent")
    app_mounts = {item.get("destination"): item for item in application.get("mounts") or []}
    client_mounts = {item.get("destination"): item for item in client.get("mounts") or []}
    if (
        (app_mounts.get("/workspace") or {}).get("rw") is not False
        or (app_mounts.get("/benchmark") or {}).get("rw") is not False
        or (app_mounts.get("/data") or {}).get("rw") is not True
        or (client_mounts.get("/benchmark") or {}).get("rw") is not False
        or (client_mounts.get("/artifacts") or {}).get("rw") is not True
    ):
        failures.append(f"{prefix}: inspected mount permissions are incorrect")
    log = (directory / "application.log").read_text(encoding="utf-8-sig").lower()
    if any(value in log for value in ("database is locked", "database is busy", "sqlite", "traceback", "exception in asgi")):
        failures.append(f"{prefix}: application log contains a database or unhandled error")

    users = setup.get("users") or []
    records_by_user = setup.get("records") or {}
    workers = run.get("workers") or []
    if users != [f"analyst-{index:02d}" for index in range(WORKER_COUNT)]:
        failures.append(f"{prefix}: setup analyst roster is incorrect")
    if [item.get("index") for item in workers] != list(range(WORKER_COUNT)):
        failures.append(f"{prefix}: worker roster/order is incorrect")
    if len({item.get("pid") for item in workers}) != WORKER_COUNT:
        failures.append(f"{prefix}: worker process IDs are not unique")
    all_records = []
    for worker in workers:
        username = worker.get("username")
        raw_records = worker.get("records") or []
        expected_order = REQUEST_ORDER * CYCLES + ["isolation:layout"]
        if worker.get("error") is not None or [item.get("family") for item in raw_records] != expected_order:
            failures.append(f"{prefix}: {username} request sequence or error state is wrong")
            continue
        own = records_by_user.get(username) or {}
        for position, record in enumerate(raw_records):
            family = record.get("family")
            expected_status = 404 if family == "isolation:layout" else 200
            bound = MAX_RESPONSE_BYTES.get(str(family).split(":", 1)[0], MAX_RESPONSE_BYTES["write"])
            if record.get("status") != expected_status or record.get("bytes", 0) > bound:
                failures.append(f"{prefix}: {username} {family} status or response bound is wrong")
            correctness = record.get("correctness") or {}
            cycle = (position // len(REQUEST_ORDER)) + 1
            if family == "current":
                offset = ((worker["index"] + cycle - 1) % 4) * 25
                expected_addresses = [f"10.20.0.{value}" for value in range(offset + 1, offset + 26)]
                if correctness != {"offset": offset, "addresses": expected_addresses, "total": 120}:
                    failures.append(f"{prefix}: {username} Current Network oracle mismatch")
            elif family == "hunt" and correctness != {"hosts": 4188, "findings": 6125, "ordered_hosts_sha256": EXPECTED_ORDERED_HOSTS_SHA256}:
                failures.append(f"{prefix}: {username} Hunt oracle mismatch")
            elif family == "map" and correctness != EXPECTED_MAP_SUMMARY:
                failures.append(f"{prefix}: {username} Map oracle mismatch")
            elif family == "reach" and correctness != {"hosts": 4188, "devices": 0, "saved_networks": 0, "device_collections": 0}:
                failures.append(f"{prefix}: {username} Reach oracle mismatch")
            elif family == "workspace:notes" and correctness != {"note_ids": [own.get("note_id")], "owners": [username]}:
                failures.append(f"{prefix}: {username} note isolation mismatch")
            elif family == "workspace:layouts" and correctness != {"layout_ids": [own.get("layout_id")], "owners": [username]}:
                failures.append(f"{prefix}: {username} layout isolation mismatch")
            elif family == "workspace:view" and correctness != {"owner": username, "version": cycle}:
                failures.append(f"{prefix}: {username} view isolation mismatch")
            elif family == "workspace:presets" and correctness != {"preset_ids": [own.get("preset_id")], "owners": [username]}:
                failures.append(f"{prefix}: {username} preset isolation mismatch")
            elif family.startswith("write:"):
                marker = f"{username}:{cycle}"
                if correctness != {"owner": username, "version": cycle + 1, "marker": marker}:
                    failures.append(f"{prefix}: {username} {family} save oracle mismatch")
            elif family == "isolation:layout":
                neighbor = setup.get("users", [])[(worker["index"] + 1) % WORKER_COUNT]
                if correctness.get("neighbor") != neighbor or "not found" not in str(correctness.get("detail") or "").lower():
                    failures.append(f"{prefix}: {username} cross-owner mutation denial mismatch")
        all_records.extend(raw_records)
    collisions = run.get("collisions") or []
    _validate_collision_bounds(collisions, failures, prefix)
    if sorted(item.get("status") for item in collisions) != [200, 409]:
        failures.append(f"{prefix}: collision statuses are not exactly 200 and 409")
    else:
        success = next(item for item in collisions if item["status"] == 200)
        conflict = next(item for item in collisions if item["status"] == 409)
        if success.get("parsed", {}).get("version") != 2 or success.get("parsed", {}).get("content") != success.get("marker"):
            failures.append(f"{prefix}: collision success is malformed")
        if "changed" not in str(conflict.get("parsed", {}).get("detail") or "").lower():
            failures.append(f"{prefix}: collision conflict is malformed")
    summary = run.get("summary") or {}
    families = sorted({str(item.get("family")) for item in all_records})
    recomputed = {
        family: _latency([float(item["latency_seconds"]) for item in all_records if item.get("family") == family])
        for family in families
    }
    if recomputed != summary.get("family_latency"):
        failures.append(f"{prefix}: per-family latency summary does not match raw records")
    reads = [item for item in all_records if item.get("kind") == "read"]
    writes = [item for item in all_records if item.get("kind") == "write"]
    overlap = sum(
        any(read["started_ns"] <= write["ended_ns"] and read["ended_ns"] >= write["started_ns"] for write in writes)
        for read in reads
    )
    if overlap < WORKER_COUNT or overlap != summary.get("successful_reads_overlapping_write_window"):
        failures.append(f"{prefix}: raw read/write overlap proof is insufficient")
    for family, metrics in recomputed.items():
        limit = summary.get("limits", {}).get("write_p95_seconds" if family.startswith("write:") else "read_p95_seconds")
        if limit is not None and metrics["p95_seconds"] > limit:
            failures.append(f"{prefix}: {family} p95 limit exceeded")

    if (
        verification.get("passed") is not True
        or verification.get("failures") != []
        or set(verification.get("actual_changed_tables") or []) != EXPECTED_CHANGED_TABLES
        or verification.get("before") != before
        or verification.get("before", {}).get("database_integrity") != ["ok"]
        or verification.get("after", {}).get("database_integrity") != ["ok"]
        or verification.get("before", {}).get("evidence_sha256") != verification.get("after", {}).get("evidence_sha256")
        or verification.get("before", {}).get("evidence_file_count") != verification.get("after", {}).get("evidence_file_count")
    ):
        failures.append(f"{prefix}: full retained-state verification is incomplete")
    resources = result.get("resources") or {}
    app_cpu = (int(resource_after["cpu_usage_usec"]) - int(resource_before["cpu_usage_usec"])) / 1_000_000
    app_peak = int(resource_after["peak_memory_bytes"])
    client_resources = run.get("client_container_resources") or {}
    if (
        round(app_cpu, 6) != resources.get("application", {}).get("cpu_seconds")
        or app_peak != resources.get("application", {}).get("container_lifetime_peak_memory_bytes")
        or round(int(client_resources.get("cpu_usage_usec")) / 1_000_000, 6) != resources.get("clients", {}).get("cpu_seconds")
        or int(client_resources.get("peak_memory_bytes")) != resources.get("clients", {}).get("container_lifetime_peak_memory_bytes")
        or resources.get("application", {}).get("memory_scope") != "full measured container lifetime, including startup and setup"
    ):
        failures.append(f"{prefix}: resource captures do not bind to reported measurements")


def summarize(root: Path) -> dict:
    failures: list[str] = []
    results = []
    cleanup_tokens = set()
    identities: dict[str, set] = {
        key: set() for key in (
            "revision", "target_root", "image_id", "corpus_manifest_sha256", "source_digest_sha256",
            "runner_sha256", "verifier_sha256", "controller_sha256",
            "preparation_sha256", "process_capture_sha256", "resource_capture_sha256",
        )
    }
    unique: dict[str, set] = {
        key: set() for key in (
            "app_container_id", "client_container_id", "network_id", "controller_token",
            "data_root_host_path",
        )
    }
    for repeat in range(1, 4):
        directory = root / f"repeat-{repeat}"
        result_path = directory / "result.json"
        cleanup_path = directory / "cleanup.json"
        if not result_path.is_file() or not cleanup_path.is_file():
            failures.append(f"repeat {repeat}: result or cleanup evidence is missing")
            continue
        result = json.loads(result_path.read_text(encoding="utf-8-sig"))
        cleanup = json.loads(cleanup_path.read_text(encoding="utf-8-sig"))
        results.append(result)
        _validate_raw(directory, result, failures, repeat)
        if result.get("repeat") != repeat or not result.get("passed"):
            failures.append(f"repeat {repeat}: repeat identity or pass state is incorrect")
        if not (result.get("client_summary") or {}).get("passed"):
            failures.append(f"repeat {repeat}: client workload did not pass")
        if not (result.get("state_verification") or {}).get("passed"):
            failures.append(f"repeat {repeat}: retained state verification did not pass")
        identity = result.get("identity") or {}
        process = identity.get("single_application_process") or {}
        if process.get("uvicorn_application_process_count") != 1 or len(process.get("processes") or []) != 1:
            failures.append(f"repeat {repeat}: did not verify exactly one Uvicorn process")
        for key in identities:
            identities[key].add(identity.get(key))
        for key in unique:
            value = identity.get(key)
            if not value or value in unique[key]:
                failures.append(f"repeat {repeat}: {key} is missing or reused")
            unique[key].add(value)
        required_cleanup = (
            cleanup.get("run_succeeded")
            and cleanup.get("app_container_removed")
            and cleanup.get("client_container_removed")
            and cleanup.get("internal_network_removed")
            and cleanup.get("data_root_removed")
        )
        if not required_cleanup:
            failures.append(f"repeat {repeat}: cleanup proof is incomplete")
        if cleanup.get("controller_token") != identity.get("controller_token"):
            failures.append(f"repeat {repeat}: cleanup token mismatch")
        if cleanup.get("result_sha256") != _sha256(result_path):
            failures.append(f"repeat {repeat}: cleanup result hash mismatch")
        cleanup_tokens.add(cleanup.get("controller_token"))
        resources = result.get("resources") or {}
        limits = resources.get("limits") or {}
        for family in ("application", "clients"):
            measured = resources.get(family) or {}
            prefix = "app" if family == "application" else "client"
            if measured.get("cpu_seconds", 10**9) > limits.get(f"{prefix}_cpu_seconds", -1):
                failures.append(f"repeat {repeat}: {family} CPU limit exceeded")
            if measured.get("container_lifetime_peak_memory_bytes", 10**18) > limits.get(f"{prefix}_peak_memory_bytes", -1):
                failures.append(f"repeat {repeat}: {family} memory limit exceeded")
        summary = result.get("client_summary") or {}
        limits = summary.get("limits") or {}
        if summary.get("wall_seconds", 10**9) > limits.get("total_wall_seconds", -1):
            failures.append(f"repeat {repeat}: wall-time limit exceeded")
        if (summary.get("read_latency") or {}).get("p95_seconds", 10**9) > limits.get("read_p95_seconds", -1):
            failures.append(f"repeat {repeat}: read p95 limit exceeded")
        if (summary.get("write_latency") or {}).get("p95_seconds", 10**9) > limits.get("write_p95_seconds", -1):
            failures.append(f"repeat {repeat}: write p95 limit exceeded")
    if len(results) != 3:
        failures.append("exactly three complete repeats are required")
    for key, values in identities.items():
        if len(values) != 1 or None in values:
            failures.append(f"all repeats must share one exact {key}")
    if len(cleanup_tokens) != 3:
        failures.append("cleanup controller tokens are missing or reused")

    def median(path: tuple[str, ...]) -> float:
        values = []
        for result in results:
            value = result
            for key in path:
                value = value[key]
            values.append(float(value))
        return round(statistics.median(values), 6) if values else 0.0

    return {
        "benchmark_version": "phase0-concurrent-summary:1",
        "passed": not failures,
        "failures": failures,
        "repeats": len(results),
        "identity": {key: next(iter(values)) if len(values) == 1 else None for key, values in identities.items()},
        "medians": {
            "wall_seconds": median(("client_summary", "wall_seconds")),
            "throughput_requests_per_second": median(("client_summary", "throughput_requests_per_second")),
            "read_p95_seconds": median(("client_summary", "read_latency", "p95_seconds")),
            "write_p95_seconds": median(("client_summary", "write_latency", "p95_seconds")),
            "application_cpu_seconds": median(("resources", "application", "cpu_seconds")),
            "application_peak_memory_bytes": median(("resources", "application", "container_lifetime_peak_memory_bytes")),
            "client_cpu_seconds": median(("resources", "clients", "cpu_seconds")),
            "client_peak_memory_bytes": median(("resources", "clients", "container_lifetime_peak_memory_bytes")),
        },
        "limitations": [
            "Eight simulated analyst client processes against one single-process Uvicorn NCT container.",
            "No stable-main comparison, multi-worker server, multiple application containers, worker lease/checkpoint, live scan, browser, long-duration, Range, production-scale, or mission claim.",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = summarize(args.root.resolve())
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    raise SystemExit(0 if result["passed"] else 1)


if __name__ == "__main__":
    main()
