#!/usr/bin/env python3
"""Repeatable local contention benchmark for active-scan progress publication."""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import math
from pathlib import Path
import sqlite3
import tempfile
import threading
import time

from app.database import connect_database
from app.poc import (
    ScanOptions,
    ScanRunRequest,
    claim_next_queued_scan,
    prepare_scan_run,
    publish_scan_contact_starting,
    update_scan_progress,
    update_scan_progress_manifest,
)
from app.work_coordination import acquire_work_lease, renew_work_lease
from app.workspaces import save_layout


def _percentile(values: list[float], percentile: float) -> float:
    ordered = sorted(values)
    if not ordered:
        return 0.0
    return ordered[max(0, math.ceil(percentile * len(ordered)) - 1)]


def _timing(values: list[float]) -> dict:
    return {
        "count": len(values),
        "p95_ms": round(_percentile(values, 0.95) * 1000, 3),
        "max_ms": round(max(values, default=0.0) * 1000, 3),
    }


def run_benchmark(db_path: Path, *, cycles: int = 100) -> dict:
    request = ScanRunRequest(
        operator="benchmark",
        originating_host="local-benchmark",
        interface="eth0",
        profile="Custom",
        scan_options=ScanOptions(
            protocol="tcp", tcp_scope="common", discovery_mode="nmap",
        ),
        targets=["192.0.2.10/32"],
        capture=True,
        timeout_seconds=60,
    )
    prepared = prepare_scan_run(request, db_path, interfaces={"eth0"})
    manifest = claim_next_queued_scan(db_path)
    if not manifest or manifest["run_id"] != prepared["run_id"]:
        raise RuntimeError("Benchmark scan could not claim the analyzer slot")
    if not publish_scan_contact_starting(manifest, db_path=db_path):
        raise RuntimeError("Benchmark scan could not publish contact start")
    with connect_database(db_path) as db:
        db.execute(
            """CREATE TRIGGER benchmark_reject_history_delete
               BEFORE DELETE ON scan_history_memberships
               BEGIN SELECT RAISE(ABORT, 'progress rebuilt history'); END"""
        )
        db.execute(
            """CREATE TRIGGER benchmark_reject_history_insert
               BEFORE INSERT ON scan_history_memberships
               BEGIN SELECT RAISE(ABORT, 'progress rebuilt history'); END"""
        )
    layout = save_layout(
        db_path, owner="benchmark-analyst", name="Progress benchmark",
        snapshot={"cycle": 0},
    )
    derived_lease = acquire_work_lease(
        db_path,
        lease_key="benchmark:derived-heartbeat",
        work_kind="derived_result",
        work_id="benchmark-result",
        owner_id="benchmark-worker",
        lease_seconds=300,
    )
    timings = {"progress": [], "workspace": [], "heartbeat": [], "read": []}
    failures: list[str] = []
    start_barrier = threading.Barrier(4)
    writer_start_barrier = threading.Barrier(3)
    state_lock = threading.Lock()
    writer_spans: dict[str, list[float]] = {}
    active_writer_lanes = 0
    max_concurrent_writer_lanes = 0

    def record(lane: str, action) -> None:
        started = time.perf_counter()
        try:
            action()
        except Exception as exc:  # retained benchmark classifies every failure
            failures.append(f"{lane}: {type(exc).__name__}: {exc}")
        finally:
            timings[lane].append(time.perf_counter() - started)

    def progress_lane() -> None:
        nonlocal active_writer_lanes, max_concurrent_writer_lanes
        start_barrier.wait()
        with state_lock:
            writer_spans["progress"] = [time.perf_counter(), 0.0]
            active_writer_lanes += 1
            max_concurrent_writer_lanes = max(
                max_concurrent_writer_lanes, active_writer_lanes
            )
        writer_start_barrier.wait()
        for cycle in range(1, cycles + 1):
            def publish() -> None:
                update_scan_progress(
                    manifest["progress"], phase="tcp",
                    elapsed_seconds=cycle * 5, updated_at=f"cycle-{cycle}",
                )
                update_scan_progress_manifest(manifest, db_path)
            record("progress", publish)
        with state_lock:
            writer_spans["progress"][1] = time.perf_counter()
            active_writer_lanes -= 1

    def workspace_lane() -> None:
        nonlocal layout, active_writer_lanes, max_concurrent_writer_lanes
        start_barrier.wait()
        with state_lock:
            writer_spans["workspace"] = [time.perf_counter(), 0.0]
            active_writer_lanes += 1
            max_concurrent_writer_lanes = max(
                max_concurrent_writer_lanes, active_writer_lanes
            )
        writer_start_barrier.wait()
        for cycle in range(1, cycles + 1):
            def save() -> None:
                nonlocal layout
                layout = save_layout(
                    db_path, owner="benchmark-analyst", name="Progress benchmark",
                    snapshot={"cycle": cycle}, layout_id=layout["layout_id"],
                    expected_version=layout["version"],
                )
            record("workspace", save)
        with state_lock:
            writer_spans["workspace"][1] = time.perf_counter()
            active_writer_lanes -= 1

    def heartbeat_lane() -> None:
        nonlocal derived_lease, active_writer_lanes, max_concurrent_writer_lanes
        start_barrier.wait()
        with state_lock:
            writer_spans["heartbeat"] = [time.perf_counter(), 0.0]
            active_writer_lanes += 1
            max_concurrent_writer_lanes = max(
                max_concurrent_writer_lanes, active_writer_lanes
            )
        writer_start_barrier.wait()
        for _cycle in range(cycles):
            def renew() -> None:
                nonlocal derived_lease
                derived_lease = renew_work_lease(
                    db_path, derived_lease, lease_seconds=300
                )
            record("heartbeat", renew)
        with state_lock:
            writer_spans["heartbeat"][1] = time.perf_counter()
            active_writer_lanes -= 1

    def read_lane() -> None:
        start_barrier.wait()
        for _cycle in range(cycles * 2):
            def read() -> None:
                with connect_database(db_path, read_only=True) as db:
                    db.execute(
                        "SELECT status, manifest_json FROM scan_runs WHERE run_id = ?",
                        (manifest["run_id"],),
                    ).fetchone()
                    db.execute(
                        "SELECT version FROM analyst_workspace_layouts WHERE layout_id = ?",
                        (layout["layout_id"],),
                    ).fetchone()
                    db.execute(
                        "SELECT state FROM work_leases WHERE lease_key = ?",
                        (derived_lease.lease_key,),
                    ).fetchone()
            record("read", read)

    started = time.perf_counter()
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = [
            executor.submit(progress_lane), executor.submit(workspace_lane),
            executor.submit(heartbeat_lane), executor.submit(read_lane),
        ]
        for future in futures:
            future.result()
    wall_seconds = time.perf_counter() - started

    with connect_database(db_path, read_only=True) as db:
        saved_manifest = json.loads(db.execute(
            "SELECT manifest_json FROM scan_runs WHERE run_id = ?",
            (manifest["run_id"],),
        ).fetchone()[0])
        saved_layout = db.execute(
            "SELECT version, snapshot_json FROM analyst_workspace_layouts WHERE layout_id = ?",
            (layout["layout_id"],),
        ).fetchone()
        renewals = db.execute(
            """SELECT COUNT(*) FROM work_lease_events
               WHERE lease_key = ? AND event_kind = 'renewed'""",
            (derived_lease.lease_key,),
        ).fetchone()[0]
        integrity = db.execute("PRAGMA integrity_check").fetchone()[0]
        memberships = db.execute(
            "SELECT COUNT(*) FROM scan_history_memberships WHERE run_id = ?",
            (manifest["run_id"],),
        ).fetchone()[0]

    writer_overlap_seconds = max(
        0.0,
        min(span[1] for span in writer_spans.values())
        - max(span[0] for span in writer_spans.values()),
    )

    checks = {
        "no_errors": not failures,
        "final_progress_exact": saved_manifest["progress"]["elapsed_seconds"] == cycles * 5,
        "workspace_exact": (
            saved_layout[0] == cycles + 1
            and json.loads(saved_layout[1]) == {"cycle": cycles}
        ),
        "heartbeat_exact": renewals == cycles,
        "history_membership_unchanged": memberships == 1,
        "integrity_ok": integrity == "ok",
        "writer_lanes_overlapped": (
            max_concurrent_writer_lanes == 3 and writer_overlap_seconds > 0
        ),
        "p95_under_one_second": all(
            _percentile(values, 0.95) <= 1.0 for values in timings.values()
        ),
        "max_under_five_seconds": all(
            max(values, default=0.0) <= 5.0 for values in timings.values()
        ),
    }
    return {
        "benchmark": "active scan progress plus workspace, lease heartbeat, and reads",
        "cycles": cycles,
        "wall_seconds": round(wall_seconds, 3),
        "timings": {name: _timing(values) for name, values in timings.items()},
        "failures": failures,
        "overlap": {
            "max_concurrent_writer_lanes": max_concurrent_writer_lanes,
            "writer_overlap_seconds": round(writer_overlap_seconds, 6),
            "writer_lanes": sorted(writer_spans),
        },
        "checks": checks,
        "passed": all(checks.values()),
        "limits": {
            "p95_ms": 1000,
            "max_ms": 5000,
            "scope": "local single-process disposable SQLite development benchmark",
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", type=Path)
    parser.add_argument("--cycles", type=int, default=100)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.cycles < 1:
        parser.error("--cycles must be positive")
    if args.database:
        args.database.parent.mkdir(parents=True, exist_ok=True)
        result = run_benchmark(args.database, cycles=args.cycles)
    else:
        with tempfile.TemporaryDirectory(prefix="nct-scan-progress-") as folder:
            result = run_benchmark(Path(folder) / "benchmark.db", cycles=args.cycles)
    encoded = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
    print(encoded, end="")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
