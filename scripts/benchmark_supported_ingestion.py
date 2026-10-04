"""Disposable supported-ingestion acceptance benchmark; never uses production data."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil
import statistics
import tempfile
import threading
import time
import tracemalloc

from app import derived_jobs as jobs
from app.artifacts import register_artifact_bytes, register_artifact_file
from app.device_collection_authority import (
    AUTHORITY_MARKER,
    activate_manual_upload_authority,
    authority_manifest_marker,
    begin_manual_upload_authority,
)
from app.device_observations import assign_device_scope, get_device_interface_receipts
from app.evidence_scope_assignments import assign_artifact_scope
from app.ingestion_status import list_ingestion_status
from app.network_scopes import create_network_scope
from app.pipeline_intake import NMAP_INGESTION_POLICY_VERSION


def nmap_xml(hosts: int) -> bytes:
    body = []
    for index in range(hosts):
        third, fourth = divmod(index, 250)
        body.append(
            f'<host starttime="101" endtime="109"><status state="up" reason="syn-ack"/>'
            f'<address addr="10.40.{third}.{fourth + 1}" addrtype="ipv4"/><ports>'
            '<port protocol="tcp" portid="443"><state state="open"/>'
            '<service name="https"/></port></ports></host>'
        )
    return (
        '<nmaprun scanner="nmap" version="7.95" start="100">'
        '<scaninfo type="syn" protocol="tcp" numservices="1" services="443"/>'
        + ''.join(body)
        + f'<runstats><finished time="110"/><hosts up="{hosts}" down="0" total="{hosts}"/></runstats></nmaprun>'
    ).encode()


def device_config(interfaces: int) -> bytes:
    lines = ["hostname benchmark-router"]
    for index in range(interfaces):
        third, fourth = divmod(index, 250)
        lines.extend([
            f"interface Ethernet{index}",
            f" ip address 10.60.{third}.{fourth + 1} 255.255.255.0",
        ])
    return ("\n".join(lines) + "\n").encode()


def elapsed(function):
    wall = time.perf_counter()
    cpu = time.process_time()
    value = function()
    return value, time.perf_counter() - wall, time.process_time() - cpu


def manual_nmap(db_path: Path, root: Path, content: bytes, label: str) -> dict:
    observation = register_artifact_bytes(
        db_path=db_path, content=content, source_kind="nmap_import",
        source_ref=f"benchmark:{label}", original_filename=f"{label}.xml",
        actor="benchmark", pipeline_policy_version=NMAP_INGESTION_POLICY_VERSION,
    )
    scope = create_network_scope(db_path, label=f"Scope {label}", created_by="benchmark")
    assign_artifact_scope(
        db_path, artifact_observation_id=observation["observation_id"],
        scope_id=scope["scope_id"], actor="benchmark",
        reason="Disposable benchmark context", whole_artifact_confirmed=True,
    )
    jobs.dispatch_next_pipeline_intake(db_path)
    jobs.run_next_derived_job(db_path, root)
    return observation


def manual_device(db_path: Path, root: Path, content: bytes, run_id: str) -> dict:
    run_dir = root / "device-configs" / run_id
    run_dir.mkdir(parents=True)
    filename = "benchmark-config.txt"
    source = run_dir / filename
    source.write_bytes(content)
    begin_manual_upload_authority(db_path, run_id)
    artifact = register_artifact_file(
        db_path=db_path, source_path=source, source_kind="device_config_upload",
        source_ref=run_id, original_filename=filename, actor="benchmark",
        observation_key=f"device_config_upload:{run_id}:{filename}",
    )
    manifest = {
        "run_id": run_id, "operation": "manual_upload", "status": "uploaded",
        "vendor": "cisco", "device_type": "router", "device_name": run_id[:8],
        "device_address": "192.0.2.10", "operator": "benchmark",
        "created_at": "2030-01-01T00:00:00+00:00",
        "completed_at": "2030-01-01T00:00:00+00:00",
        "retained_filename": filename, "artifact_sha256": artifact["sha256"],
        "artifact_observation_id": artifact["observation_id"],
        "output_complete": True, "commands": [],
        AUTHORITY_MARKER: authority_manifest_marker(),
    }
    (run_dir / "manifest.json").write_text(json.dumps(manifest, sort_keys=True))
    activate_manual_upload_authority(
        db_path, run_id, observation_id=artifact["observation_id"],
        artifact_sha256=artifact["sha256"], retained_filename=filename,
        manifest=manifest,
    )
    jobs.dispatch_next_pipeline_intake(db_path)
    jobs.run_next_derived_job(db_path, root)
    scope = create_network_scope(db_path, label=f"Device {run_id[-8:]}", created_by="benchmark")
    assignment = assign_device_scope(
        db_path, run_id=run_id, scope_id=scope["scope_id"], actor="benchmark",
        reason="Disposable benchmark context", whole_collection_confirmed=True,
    )
    jobs.dispatch_next_pipeline_intake(db_path)
    jobs.run_next_derived_job(db_path, root)
    summary = jobs.device_summary_job_for_run(db_path, run_id)
    return {"run_id": run_id, "summary_result_id": summary["latest_attempt"]["output_id"],
            "assignment_id": assignment["assignment_id"]}


def directory_bytes(root: Path) -> int:
    return sum(path.stat().st_size for path in root.rglob("*") if path.is_file())


def run_once(revision: str, repeat: int) -> dict:
    root = Path(tempfile.mkdtemp(prefix="nct-supported-ingestion-"))
    db_path = root / "analyzer.db"
    read_errors = []
    reads = 0
    stop = threading.Event()
    try:
        tracemalloc.start()
        small_xml, large_xml = nmap_xml(3), nmap_xml(400)
        small_config, large_config = device_config(3), device_config(600)
        _, small_nmap_wall, small_nmap_cpu = elapsed(
            lambda: manual_nmap(db_path, root, small_xml, f"small-{repeat}")
        )

        def reader():
            nonlocal reads
            while not stop.is_set():
                try:
                    list_ingestion_status(db_path, limit=25)
                    reads += 1
                except Exception as exc:  # recorded as benchmark evidence
                    read_errors.append(str(exc))

        thread = threading.Thread(target=reader, daemon=True)
        thread.start()
        _, large_nmap_wall, large_nmap_cpu = elapsed(
            lambda: manual_nmap(db_path, root, large_xml, f"large-{repeat}")
        )
        stop.set(); thread.join(timeout=5)

        first_device, first_device_wall, first_device_cpu = elapsed(
            lambda: manual_device(db_path, root, large_config, f"{repeat + 1:032x}")
        )
        second_device, warm_device_wall, warm_device_cpu = elapsed(
            lambda: manual_device(db_path, root, large_config, f"{repeat + 101:032x}")
        )
        _, small_device_wall, small_device_cpu = elapsed(
            lambda: manual_device(db_path, root, small_config, f"{repeat + 201:032x}")
        )

        # Add repeated unscoped encounters to exercise first and last status pages.
        for index in range(53):
            register_artifact_bytes(
                db_path=db_path, content=small_xml, source_kind="nmap_import",
                source_ref=f"page:{repeat}:{index}", original_filename=f"page-{index}.xml",
                actor="benchmark", pipeline_policy_version=NMAP_INGESTION_POLICY_VERSION,
            )
        first_page, first_page_wall, first_page_cpu = elapsed(
            lambda: list_ingestion_status(db_path, limit=25, offset=0)
        )
        last_offset = max(0, first_page["total"] - 3)
        last_page, last_page_wall, last_page_cpu = elapsed(
            lambda: list_ingestion_status(db_path, limit=25, offset=last_offset)
        )
        first_receipts, first_receipt_wall, first_receipt_cpu = elapsed(
            lambda: get_device_interface_receipts(
                db_path, first_device["run_id"], limit=100, offset=0,
            )
        )
        receipt_total = first_receipts["pagination"]["total"]
        last_receipts, last_receipt_wall, last_receipt_cpu = elapsed(
            lambda: get_device_interface_receipts(
                db_path, first_device["run_id"], limit=100,
                offset=max(0, receipt_total - 100),
            )
        )
        _current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        return {
            "repeat": repeat, "revision": revision,
            "dataset": {
                "small_nmap_hosts": 3, "large_nmap_hosts": 400,
                "small_device_interfaces": 3, "large_device_interfaces": 600,
                "repeated_status_encounters": 53,
                "small_nmap_bytes": len(small_xml), "large_nmap_bytes": len(large_xml),
                "small_device_bytes": len(small_config), "large_device_bytes": len(large_config),
            },
            "timings_seconds": {
                "small_nmap_cold": small_nmap_wall, "large_nmap_cold": large_nmap_wall,
                "large_device_cold": first_device_wall,
                "large_device_repeated_content": warm_device_wall,
                "small_device_cold": small_device_wall,
                "status_first_page": first_page_wall, "status_last_page": last_page_wall,
                "receipts_first_page": first_receipt_wall, "receipts_last_page": last_receipt_wall,
            },
            "cpu_seconds": {
                "small_nmap_cold": small_nmap_cpu, "large_nmap_cold": large_nmap_cpu,
                "large_device_cold": first_device_cpu,
                "large_device_repeated_content": warm_device_cpu,
                "small_device_cold": small_device_cpu,
                "status_first_page": first_page_cpu, "status_last_page": last_page_cpu,
                "receipts_first_page": first_receipt_cpu, "receipts_last_page": last_receipt_cpu,
            },
            "memory_peak_bytes": peak,
            "database_bytes": db_path.stat().st_size,
            "all_disposable_files_bytes": directory_bytes(root),
            "concurrent_status_reads": reads,
            "concurrent_status_errors": read_errors,
            "preservation": {
                "repeated_device_content_reused_summary": (
                    first_device["summary_result_id"] == second_device["summary_result_id"]
                ),
                "separate_device_encounters": first_device["run_id"] != second_device["run_id"],
                "status_last_page_count": len(last_page["items"]),
                "receipt_total": receipt_total,
                "receipt_first_page_count": len(first_receipts["receipts"]),
                "receipt_last_page_count": len(last_receipts["receipts"]),
            },
        }
    finally:
        stop.set()
        jobs.stop_derived_job_worker(db_path)
        shutil.rmtree(root, ignore_errors=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--revision", required=True)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    runs = [run_once(args.revision, index) for index in range(args.repeats)]
    keys = runs[0]["timings_seconds"]
    summary = {
        key: {
            "min": min(run["timings_seconds"][key] for run in runs),
            "median": statistics.median(run["timings_seconds"][key] for run in runs),
            "max": max(run["timings_seconds"][key] for run in runs),
        }
        for key in keys
    }
    report = {
        "benchmark": "currently-supported-ingestion-development-acceptance",
        "revision": args.revision, "repeats": args.repeats,
        "runs": runs, "timing_variability_seconds": summary,
        "limitations": [
            "Synthetic disposable evidence only",
            "Single-process worker only",
            "Not a production, Range, mission, or stable-main benchmark",
            "Phase 0 representative production datasets remain unavailable",
        ],
    }
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")


if __name__ == "__main__":
    main()
