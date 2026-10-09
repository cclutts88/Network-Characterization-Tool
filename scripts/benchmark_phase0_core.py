"""Run one isolated Phase 0 core-engine benchmark repeat against an NCT checkout.

This worker is intentionally revision-neutral.  A controlling Docker command must
give it a read-only target checkout and corpus, no network, an empty data directory,
and a fresh process for every repeat.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import inspect
import json
import os
from pathlib import Path, PurePosixPath
import platform
import resource
import sys
import time

try:
    from scripts.generate_phase0_benchmark_corpus import (
        MANIFEST_NAME,
        _canonical_manifest,
        corpus_files,
    )
except ModuleNotFoundError:  # Direct execution from a mounted scripts directory.
    from generate_phase0_benchmark_corpus import (
        MANIFEST_NAME,
        _canonical_manifest,
        corpus_files,
    )


RUNNER_VERSION = "phase0-core-benchmark:1"
COMPARISON_STATISTIC = "median of three fresh-process repeats"
ABSOLUTE_LIMITS = {
    "whole_run_wall_seconds": 120.0,
    "whole_run_cpu_seconds": 120.0,
    "whole_run_peak_rss_bytes": 1_073_741_824,
    "single_nmap_parse_wall_seconds": 30.0,
    "history_compare_wall_seconds": 10.0,
    "single_device_parse_wall_seconds": 20.0,
    "enrichment_cold_wall_seconds": 30.0,
    "enrichment_warm_wall_seconds": 30.0,
    "retained_data_root_bytes": 104_857_600,
}


def expected_workload_names() -> list[str]:
    _, oracle = corpus_files()
    names = ["history:compare", "enrichment:cold", "enrichment:warm"]
    for relative in oracle["nmap_files"]:
        names.extend((f"nmap:{relative}:cold", f"nmap:{relative}:warm"))
    for relative in oracle["devices"]["parsed_counts"]:
        names.extend((f"device:{relative}:cold", f"device:{relative}:warm"))
    return sorted(names)
RELATIVE_LIMITS = {
    "foundation_over_main_ratio": 2.0,
    "wall_seconds_allowance": 0.5,
    "cpu_seconds_allowance": 0.5,
    "peak_rss_bytes_allowance": 134_217_728,
}


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _source_digest(root: Path) -> tuple[str, int]:
    candidates = [root / "requirements.txt", root / "Dockerfile"]
    candidates.extend(sorted((root / "app").rglob("*.py")))
    digest = hashlib.sha256()
    count = 0
    for path in candidates:
        if not path.is_file() or path.is_symlink():
            continue
        relative = path.relative_to(root).as_posix().encode()
        content = path.read_bytes()
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
        count += 1
    if not count:
        raise ValueError("Target checkout contains no benchmarkable source files")
    return digest.hexdigest(), count


def _path_or_ancestor_is_link(path: Path) -> bool:
    candidate = path.absolute()
    return any(item.is_symlink() for item in (candidate, *candidate.parents))


def _verify_corpus(root: Path) -> tuple[dict, str, int]:
    if _path_or_ancestor_is_link(root):
        raise ValueError("Corpus path or one of its ancestors is linked")
    manifest_path = root / MANIFEST_NAME
    if not manifest_path.is_file() or manifest_path.is_symlink():
        raise ValueError("Corpus manifest is unavailable")
    manifest_bytes = manifest_path.read_bytes()
    manifest = json.loads(manifest_bytes)
    expected_files, expected_oracle = corpus_files()
    expected_manifest = _canonical_manifest(expected_files, expected_oracle)
    if manifest != expected_manifest:
        raise ValueError("Corpus manifest does not match the canonical generator output")
    entries = manifest.get("files")
    if not isinstance(entries, list) or not entries:
        raise ValueError("Corpus manifest has no files")
    total = 0
    expected_paths = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("Corpus manifest file entry is invalid")
        raw = str(entry.get("path") or "")
        relative = PurePosixPath(raw)
        if (
            "\\" in raw or relative.is_absolute() or ".." in relative.parts
            or not relative.parts or relative.as_posix() != raw
        ):
            raise ValueError("Corpus manifest contains an unsafe file path")
        path = root.joinpath(*relative.parts)
        if _path_or_ancestor_is_link(path) or not path.is_file():
            raise ValueError(f"Corpus file is unavailable: {raw}")
        content = path.read_bytes()
        if (
            content != expected_files[raw]
            or len(content) != int(entry.get("size_bytes", -1))
            or _sha256(content) != entry.get("sha256")
        ):
            raise ValueError(f"Corpus file failed exact-content verification: {raw}")
        expected_paths.add(raw)
        total += len(content)
    actual_paths = set()
    for path in root.rglob("*"):
        if path.is_symlink():
            raise ValueError("Corpus contains a linked path")
        if path.is_file() and path != manifest_path:
            actual_paths.add(path.relative_to(root).as_posix())
    if actual_paths != expected_paths:
        raise ValueError("Corpus contains missing or unexpected files")
    return manifest, _sha256(manifest_bytes), total


def _validate_attestations(
    git_attestation: dict, image_attestation: dict, source_sha256: str
) -> tuple[str, str, dict]:
    if git_attestation.get("verification_method") != "controller:git-rev-parse-status-and-source-digest":
        raise ValueError("Git identity requires a supported external controller attestation")
    revision = str(git_attestation.get("revision") or "")
    if len(revision) != 40 or any(character not in "0123456789abcdef" for character in revision.lower()):
        raise ValueError("Git attestation does not contain an exact revision")
    if git_attestation.get("clean") is not True:
        raise ValueError("Git attestation does not prove a clean target checkout")
    if git_attestation.get("source_digest_sha256") != source_sha256:
        raise ValueError("Git attestation source digest does not match the mounted target")

    if image_attestation.get("verification_method") != "controller:docker-image-inspect":
        raise ValueError("Container identity requires a supported external controller attestation")
    image_id = str(image_attestation.get("image_id") or "")
    if not image_id.startswith("sha256:") or len(image_id) != 71:
        raise ValueError("Image attestation does not contain an exact image ID")
    if any(character not in "0123456789abcdef" for character in image_id[7:].lower()):
        raise ValueError("Image attestation contains an invalid image ID")
    container_id = str(image_attestation.get("container_id") or "")
    if len(container_id) != 64 or any(character not in "0123456789abcdef" for character in container_id.lower()):
        raise ValueError("Container attestation does not contain an exact container ID")
    required_isolation = {
        "fresh_container": True,
        "network_mode": "none",
        "source_mount_read_only": True,
        "corpus_mount_read_only": True,
    }
    if any(image_attestation.get(key) != value for key, value in required_isolation.items()):
        raise ValueError("Container attestation does not prove the required fresh isolated mounts")
    return revision, image_id, {
        "type": "externally-verified-controller-attestations",
        "validated": True,
        "git": dict(git_attestation),
        "container_image": dict(image_attestation),
    }


def _retained_state(root: Path) -> dict:
    files = []
    for path in root.rglob("*"):
        if path.is_symlink():
            raise ValueError("Retained benchmark data contains a linked path")
        if path.is_file():
            files.append({"path": path.relative_to(root).as_posix(), "size_bytes": path.stat().st_size})
    files.sort(key=lambda item: item["path"])
    return {
        "data_root_bytes": sum(item["size_bytes"] for item in files),
        "data_root_file_count": len(files),
        "files": files,
    }


def _cpu_seconds() -> float:
    own = resource.getrusage(resource.RUSAGE_SELF)
    children = resource.getrusage(resource.RUSAGE_CHILDREN)
    return own.ru_utime + own.ru_stime + children.ru_utime + children.ru_stime


def _peak_memory() -> tuple[int, str, dict]:
    peak_path = Path("/sys/fs/cgroup/memory.peak")
    try:
        value = int(peak_path.read_text().strip())
        if value > 0:
            return value, "cgroup-v2 memory.peak including child processes", {}
    except (OSError, ValueError):
        pass
    own = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024
    children = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss * 1024
    return own + children, "sum of self and child ru_maxrss upper bounds", {
        "self_peak_rss_bytes": own,
        "child_peak_rss_bytes": children,
    }


def _measure(function) -> tuple[object, dict]:
    wall_start = time.perf_counter()
    cpu_start = _cpu_seconds()
    value = function()
    return value, {
        "wall_seconds": time.perf_counter() - wall_start,
        "cpu_seconds": _cpu_seconds() - cpu_start,
    }


def _nmap_counts(parsed: dict) -> dict:
    hosts = parsed.get("hosts") or []
    ports = [port for host in hosts for port in (host.get("observed_ports") or [])]
    by_protocol: dict[str, int] = {}
    for port in ports:
        protocol = str(port.get("protocol") or "unknown").lower()
        by_protocol[protocol] = by_protocol.get(protocol, 0) + 1
    return {
        "hosts": len(hosts),
        "service_observations": len(ports),
        "service_observations_by_protocol": dict(sorted(by_protocol.items())),
        "ipv4_addresses": sum(1 for host in hosts if host.get("ip")),
        "mac_addresses": sum(1 for host in hosts if host.get("mac")),
        "traces": sum(1 for host in hosts if host.get("trace")),
        "scan_protocols": sorted(
            str(protocol).lower() for protocol in (parsed.get("coverage") or {}).get("protocols", [])
        ),
    }


def _stage_device_fixture(path: Path, config_root: Path) -> str:
    text = path.read_text(encoding="utf-8")
    run_id = hashlib.sha256(path.name.encode()).hexdigest()[:32]
    run_dir = config_root / run_id
    run_dir.mkdir(parents=True)
    retained_filename = "uploaded-evidence.txt"
    (run_dir / retained_filename).write_text(text, encoding="utf-8")
    (run_dir / "manifest.json").write_text(json.dumps({
        "run_id": run_id,
        "status": "uploaded",
        "operation": "manual_upload",
        "vendor": "cisco",
        "device_type": "router",
        "device_name": path.stem,
        "retained_filename": retained_filename,
        "output_complete": True,
        "commands": [],
    }, sort_keys=True), encoding="utf-8")
    return run_id


@contextmanager
def _target_imports(target_root: Path):
    old_path = list(sys.path)
    old_modules = {name: value for name, value in sys.modules.items() if name == "app" or name.startswith("app.")}
    for name in old_modules:
        del sys.modules[name]
    sys.path.insert(0, str(target_root))
    try:
        from app.main import parse_xml
        from app.comparison import compare_analyses
        from app.device_configs import device_collection_summary
        import app.searchsploit as searchsploit
        yield parse_xml, compare_analyses, device_collection_summary, searchsploit
    finally:
        for name in [name for name in sys.modules if name == "app" or name.startswith("app.")]:
            del sys.modules[name]
        sys.modules.update(old_modules)
        sys.path[:] = old_path


def _run_enrichment(module, corpus_root: Path, manifest: dict, data_root: Path) -> tuple[dict, dict, dict]:
    workload = json.loads((corpus_root / "enrichment" / "findings.json").read_text())
    command = corpus_root / "enrichment" / "searchsploit"
    database = command.parent
    provider = {
        "available": True,
        "command_path": str(command),
        "command_sha256": _sha256(command.read_bytes()),
        "database_path": str(database),
        "active_version": "phase0-corpus-v1",
        "archive_sha256": _sha256((database / "files_exploits.csv").read_bytes()),
        "database_updated_epoch": 1_800_000_000,
        "message": "Frozen Phase 0 benchmark provider",
    }
    os.environ["ANALYZER_DATA_DIR"] = str(data_root)
    original_search = module._search
    calls = {"count": 0}

    def counted_search(*args, **kwargs):
        calls["count"] += 1
        return original_search(*args, **kwargs)

    module._search = counted_search
    module.searchsploit_status = lambda: dict(provider)
    parameters = inspect.signature(module.enrich_hunting_with_searchsploit).parameters

    def execute():
        if "provider_status" in parameters:
            return module.enrich_hunting_with_searchsploit(workload, provider_status=provider)
        return module.enrich_hunting_with_searchsploit(workload)

    try:
        calls["count"] = 0
        cold, cold_metric = _measure(execute)
        cold_calls = calls["count"]
        calls["count"] = 0
        warm, warm_metric = _measure(execute)
        warm_calls = calls["count"]
    finally:
        module._search = original_search
    oracle = manifest["oracle"]["enrichment"]
    common = {
        "status": "searchsploit_complete",
        "query_count": oracle["unique_product_version_queries"],
        "match_count": 240,
        "cve_count": 24,
    }
    for label, result in (("cold", cold), ("warm", warm)):
        actual = {key: result.get(key) for key in common}
        if actual != common or result.get("warnings"):
            raise AssertionError(f"{label} enrichment oracle mismatch: {actual}; warnings={result.get('warnings')}")
    cache_supported = "cache_hit_count" in warm
    if cold_calls != 24:
        raise AssertionError(f"Cold enrichment executed {cold_calls} searches instead of 24")
    if cache_supported:
        if warm_calls != 0 or cold.get("cache_miss_count") != 24 or warm.get("cache_hit_count") != 24:
            raise AssertionError("Foundation enrichment cache oracle mismatch")
    elif warm_calls != 24:
        raise AssertionError("Stable baseline repeated-search oracle mismatch")
    cache_path = data_root / "analyzer.db"
    return {
        "cache_supported": cache_supported,
        "cold_search_calls": cold_calls,
        "warm_search_calls": warm_calls,
        "cold_cache_misses": cold.get("cache_miss_count"),
        "warm_cache_hits": warm.get("cache_hit_count"),
        "candidate_associations": cold["match_count"],
        "cves": cold["cve_count"],
        "cache_database_bytes": cache_path.stat().st_size if cache_path.is_file() else 0,
    }, cold_metric, warm_metric


def run_once(
    target_root: Path,
    corpus_root: Path,
    data_root: Path,
    git_attestation: dict,
    image_attestation: dict,
    repeat: int,
) -> dict:
    if data_root.exists() or data_root.is_symlink():
        raise ValueError("Data directory must not exist before a benchmark repeat")
    data_root.mkdir(parents=True)
    manifest, manifest_sha256, corpus_bytes = _verify_corpus(corpus_root)
    source_sha256, source_files = _source_digest(target_root)
    revision, image_id, identity_evidence = _validate_attestations(
        git_attestation, image_attestation, source_sha256
    )
    metrics: dict[str, dict] = {}
    correctness: dict[str, object] = {}
    total_wall = time.perf_counter()
    total_cpu = _cpu_seconds()
    with _target_imports(target_root) as (parse_xml, compare_analyses, device_summary, searchsploit):
        parsed_nmap = {}
        for relative, expected in manifest["oracle"]["nmap_files"].items():
            path = corpus_root / relative
            parsed, cold_metric = _measure(lambda path=path: parse_xml(path.read_bytes()))
            warm, warm_metric = _measure(lambda path=path: parse_xml(path.read_bytes()))
            actual = _nmap_counts(parsed)
            warm_actual = _nmap_counts(warm)
            if actual != expected or warm_actual != expected:
                raise AssertionError(f"Nmap oracle mismatch for {relative}")
            parsed_nmap[relative] = parsed
            metrics[f"nmap:{relative}:cold"] = cold_metric
            metrics[f"nmap:{relative}:warm"] = warm_metric
        correctness["nmap_files"] = len(parsed_nmap)

        before = parsed_nmap["nmap/history_before.xml"]
        after = parsed_nmap["nmap/history_after.xml"]
        comparison, comparison_metric = _measure(lambda: compare_analyses(before, after))
        expected_history = manifest["oracle"]["history"]
        history_actual = {
            "hosts_added": comparison["summary"]["hosts_added"],
            "hosts_no_longer_confirmed": comparison["summary"]["hosts_removed"],
            "version_changes": comparison["summary"]["service_changes"],
            "ports_added": comparison["summary"]["ports_added"],
            "ports_no_longer_observed": comparison["summary"]["ports_removed"],
        }
        history_expected = {
            "hosts_added": len(expected_history["hosts_added"]),
            "hosts_no_longer_confirmed": len(expected_history["hosts_no_longer_confirmed"]),
            "version_changes": expected_history["version_changes"],
            "ports_added": expected_history["ports_added"],
            "ports_no_longer_observed": expected_history["ports_no_longer_observed"],
        }
        if history_actual != history_expected:
            raise AssertionError(f"History comparison oracle mismatch: {history_actual}")
        metrics["history:compare"] = comparison_metric
        correctness["history"] = history_actual

        device_results = {}
        config_root = data_root / "device-configs"
        config_root.mkdir()
        for relative, expected in manifest["oracle"]["devices"]["parsed_counts"].items():
            path = corpus_root / relative
            run_id = _stage_device_fixture(path, config_root)
            parsed, cold_metric = _measure(
                lambda run_id=run_id: device_summary(run_id, config_root)
            )
            warm, warm_metric = _measure(
                lambda run_id=run_id: device_summary(run_id, config_root)
            )
            if parsed["counts"] != expected or warm["counts"] != expected:
                raise AssertionError(f"Device oracle mismatch for {relative}")
            device_results[relative] = parsed["counts"]
            metrics[f"device:{relative}:cold"] = cold_metric
            metrics[f"device:{relative}:warm"] = warm_metric
        correctness["device_files"] = len(device_results)

        enrichment, cold_metric, warm_metric = _run_enrichment(
            searchsploit, corpus_root, manifest, data_root
        )
        metrics["enrichment:cold"] = cold_metric
        metrics["enrichment:warm"] = warm_metric
        correctness["enrichment"] = enrichment

    expected_names = expected_workload_names()
    if sorted(metrics) != expected_names:
        raise AssertionError("Benchmark did not execute the complete canonical workload set")
    retained_state = _retained_state(data_root)
    correctness["enrichment"]["retained_data_root_bytes"] = retained_state["data_root_bytes"]

    total_metrics = {
        "wall_seconds": time.perf_counter() - total_wall,
        "cpu_seconds": _cpu_seconds() - total_cpu,
    }
    peak, peak_method, peak_detail = _peak_memory()
    total_metrics.update({"peak_rss_bytes": peak, "peak_rss_method": peak_method, **peak_detail})
    failures = []
    if total_metrics["wall_seconds"] > ABSOLUTE_LIMITS["whole_run_wall_seconds"]:
        failures.append("whole-run wall limit exceeded")
    if total_metrics["cpu_seconds"] > ABSOLUTE_LIMITS["whole_run_cpu_seconds"]:
        failures.append("whole-run CPU limit exceeded")
    if peak > ABSOLUTE_LIMITS["whole_run_peak_rss_bytes"]:
        failures.append("whole-run peak memory limit exceeded")
    for name, metric in metrics.items():
        wall = metric["wall_seconds"]
        if name.startswith("nmap:") and wall > ABSOLUTE_LIMITS["single_nmap_parse_wall_seconds"]:
            failures.append(f"{name} wall limit exceeded")
        elif name == "history:compare" and wall > ABSOLUTE_LIMITS["history_compare_wall_seconds"]:
            failures.append("history comparison wall limit exceeded")
        elif name.startswith("device:") and wall > ABSOLUTE_LIMITS["single_device_parse_wall_seconds"]:
            failures.append(f"{name} wall limit exceeded")
        elif name == "enrichment:cold" and wall > ABSOLUTE_LIMITS["enrichment_cold_wall_seconds"]:
            failures.append("cold enrichment wall limit exceeded")
        elif name == "enrichment:warm" and wall > ABSOLUTE_LIMITS["enrichment_warm_wall_seconds"]:
            failures.append("warm enrichment wall limit exceeded")
    if retained_state["data_root_bytes"] > ABSOLUTE_LIMITS["retained_data_root_bytes"]:
        failures.append("retained data-root size limit exceeded")
    runner_path = Path(__file__)
    return {
        "benchmark": "phase0-core-engine-comparison",
        "runner_version": RUNNER_VERSION,
        "runner_sha256": _sha256(runner_path.read_bytes()),
        "comparison_statistic": COMPARISON_STATISTIC,
        "repeat": repeat,
        "target": {
            "revision": revision,
            "source_digest_sha256": source_sha256,
            "source_file_count": source_files,
            "container_image_id": image_id,
            "identity_evidence": identity_evidence,
        },
        "environment": {
            "python": sys.version,
            "platform": platform.platform(),
            "machine": platform.machine(),
            "network_required": False,
            "fresh_process_required": True,
            "empty_data_directory_verified": True,
        },
        "corpus": {
            "manifest_sha256": manifest_sha256,
            "generator_version": manifest.get("generator_version"),
            "file_count": len(manifest["files"]),
            "total_bytes": corpus_bytes,
        },
        "limits": {"absolute": ABSOLUTE_LIMITS, "relative": RELATIVE_LIMITS},
        "expected_workloads": expected_names,
        "metrics": metrics,
        "total": total_metrics,
        "retained_state": retained_state,
        "correctness": correctness,
        "failures": failures,
        "passed": not failures,
        "limitations": [
            "Core parser, comparison, device-summary and offline enrichment work only.",
            "HTTP endpoints, bounded pages, persistent foundation views and rendered browser timing are not measured.",
            "Multi-process, Range, mission, production-history and physical-hardware performance are not measured.",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target-root", type=Path, required=True)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--data-root", type=Path, required=True)
    parser.add_argument("--git-attestation", type=Path, required=True)
    parser.add_argument("--image-attestation", type=Path, required=True)
    parser.add_argument("--repeat", type=int, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = run_once(
        args.target_root.resolve(), args.corpus, args.data_root,
        json.loads(args.git_attestation.read_text(encoding="utf-8")),
        json.loads(args.image_attestation.read_text(encoding="utf-8")),
        args.repeat,
    )
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    if not result["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
