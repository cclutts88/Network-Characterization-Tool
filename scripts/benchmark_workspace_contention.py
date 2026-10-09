#!/usr/bin/env python3
"""Repeatable local benchmark for NCT analyst workspace storage contention."""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import json
import math
from pathlib import Path
import platform
import random
import sqlite3
import tempfile
import threading
import time

from app.database import connect_database, configure_database
from app.investigation_notes import (
    NoteConflict,
    list_notes,
    preview_note_branch,
    save_note,
    share_note,
)
from app.view_preferences import (
    ViewPreferenceConflict,
    get_view_workspace,
    save_filter_preset,
    save_view_preference,
)
from app.workspaces import WorkspaceConflict, list_layouts, save_layout


FAMILIES = ("note", "layout", "working_view", "filter_preset")
PERCENTILE_METHOD = "nearest rank: sorted[ceil(p * n) - 1]"


def _percentile(values: list[float], percentile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    return ordered[max(0, math.ceil(percentile * len(ordered)) - 1)]


def _summary(values: list[float]) -> dict:
    return {
        "count": len(values),
        "p50_ms": round(_percentile(values, 0.50) * 1000, 3),
        "p95_ms": round(_percentile(values, 0.95) * 1000, 3),
        "max_ms": round(max(values, default=0.0) * 1000, 3),
    }


def _prepare(
    db_path: Path,
    *,
    workers: int,
    payload_bytes: int,
    recursive_items: int,
) -> tuple[list[dict], dict]:
    configure_database(db_path)
    padding = "x" * payload_bytes
    states: list[dict] = []
    for index in range(workers):
        owner = f"benchmark-analyst-{index:02d}"
        parent_id = None
        folders = []
        for depth in range(3):
            folder = save_note(
                db_path,
                owner=owner,
                parent_id=parent_id,
                title=f"Working folder {depth + 1}",
                kind="folder",
            )
            folders.append(folder)
            parent_id = folder["note_id"]
        note = save_note(
            db_path,
            owner=owner,
            parent_id=parent_id,
            title="Working note",
            kind="note",
            content=f"marker=setup;{padding}",
        )
        layout = save_layout(
            db_path,
            owner=owner,
            name="Working layout",
            snapshot={"marker": "setup", "padding": padding},
        )
        working_view = save_view_preference(
            db_path,
            owner=owner,
            page="hunt",
            snapshot={"marker": "setup", "padding": padding},
            expected_version=None,
        )
        filter_preset = save_filter_preset(
            db_path,
            owner=owner,
            page="analyze",
            name="Working preset",
            snapshot={"marker": "setup", "padding": padding},
        )
        states.append(
            {
                "owner": owner,
                "folders": folders,
                "note": note,
                "layout": layout,
                "working_view": working_view,
                "filter_preset": filter_preset,
                "updates": {family: 0 for family in FAMILIES},
                "markers": {family: "setup" for family in FAMILIES},
            }
        )

    recursive_owner = "benchmark-recursive-analyst"
    destination = save_note(
        db_path, owner=recursive_owner, title="Destination", kind="folder"
    )
    root = save_note(db_path, owner=recursive_owner, title="Large branch", kind="folder")
    for index in range(recursive_items - 1):
        save_note(
            db_path,
            owner=recursive_owner,
            parent_id=root["note_id"],
            title=f"Evidence note {index + 1:04d}",
            kind="note",
            content=f"fixture={index + 1};{padding}",
        )
    return states, {
        "owner": recursive_owner,
        "root": root,
        "destination": destination,
        "items": recursive_items,
    }


def _update(
    db_path: Path,
    state: dict,
    family: str,
    cycle: int,
    padding: str,
) -> None:
    marker = f"{state['owner']}:{family}:{cycle}"
    owner = state["owner"]
    if family == "note":
        current = state[family]
        saved = save_note(
            db_path,
            owner=owner,
            note_id=current["note_id"],
            expected_version=current["version"],
            parent_id=current["parent_id"],
            title="Working note",
            kind="note",
            content=f"marker={marker};{padding}",
        )
    elif family == "layout":
        current = state[family]
        saved = save_layout(
            db_path,
            owner=owner,
            layout_id=current["layout_id"],
            expected_version=current["version"],
            name="Working layout",
            snapshot={"marker": marker, "padding": padding},
        )
    elif family == "working_view":
        current = state[family]
        saved = save_view_preference(
            db_path,
            owner=owner,
            page="hunt",
            expected_version=current["version"],
            snapshot={"marker": marker, "padding": padding},
        )
    else:
        current = state[family]
        saved = save_filter_preset(
            db_path,
            owner=owner,
            page="analyze",
            preset_id=current["preset_id"],
            expected_version=current["version"],
            name="Working preset",
            snapshot={"marker": marker, "padding": padding},
        )
    state[family] = saved
    state["updates"][family] += 1
    state["markers"][family] = marker


def _read(db_path: Path, owner: str) -> None:
    list_notes(db_path, owner, "analyze")
    list_layouts(db_path, owner)
    get_view_workspace(db_path, owner=owner, page="hunt")
    get_view_workspace(db_path, owner=owner, page="analyze")


def _recursive(db_path: Path, state: dict) -> list[dict]:
    operations = []
    root = state["root"]

    for action, shared in (("share", True), ("unshare", False)):
        preview = preview_note_branch(
            db_path, owner=state["owner"], note_id=root["note_id"]
        )
        started = time.perf_counter()
        root = share_note(
            db_path,
            owner=state["owner"],
            note_id=root["note_id"],
            expected_version=root["version"],
            shared=shared,
            page="hunt" if shared else None,
            branch_revision=preview["branch_revision"],
        )
        operations.append(
            {"action": action, "seconds": time.perf_counter() - started}
        )

    started = time.perf_counter()
    root = save_note(
        db_path,
        owner=state["owner"],
        note_id=root["note_id"],
        expected_version=root["version"],
        parent_id=state["destination"]["note_id"],
        title="Large branch",
        kind="folder",
    )
    operations.append({"action": "move", "seconds": time.perf_counter() - started})
    state["root"] = root
    return operations


def _record_failure(failures: dict[str, list[str]], label: str, exc: Exception) -> None:
    message = str(exc)
    lowered = message.lower()
    if isinstance(exc, (NoteConflict, WorkspaceConflict, ViewPreferenceConflict)):
        category = "optimistic_conflict"
    elif isinstance(exc, sqlite3.OperationalError) and any(
        word in lowered for word in ("locked", "busy", "timeout")
    ):
        category = "locked_busy_timeout"
    else:
        category = "unexpected"
    failures[category].append(f"{label}: {type(exc).__name__}: {message}")


def _verify(db_path: Path, states: list[dict], recursive: dict) -> dict:
    failures: list[str] = []
    with connect_database(db_path, read_only=True) as db:
        db.row_factory = sqlite3.Row
        integrity_rows = [str(row[0]) for row in db.execute("PRAGMA integrity_check")]
        journal_mode = str(db.execute("PRAGMA journal_mode").fetchone()[0])
        busy_timeout_ms = int(db.execute("PRAGMA busy_timeout").fetchone()[0])

        for state in states:
            owner = state["owner"]
            note = db.execute(
                "SELECT version, content FROM analyst_investigation_notes WHERE note_id = ?",
                (state["note"]["note_id"],),
            ).fetchone()
            layout = db.execute(
                "SELECT version, snapshot_json FROM analyst_workspace_layouts WHERE layout_id = ?",
                (state["layout"]["layout_id"],),
            ).fetchone()
            view = db.execute(
                "SELECT version, snapshot_json FROM analyst_view_preferences WHERE owner = ? AND page = 'hunt'",
                (owner,),
            ).fetchone()
            preset = db.execute(
                "SELECT version, snapshot_json FROM analyst_filter_presets WHERE preset_id = ?",
                (state["filter_preset"]["preset_id"],),
            ).fetchone()
            rows = {"note": note, "layout": layout, "working_view": view, "filter_preset": preset}
            for family, row in rows.items():
                expected_version = 1 + state["updates"][family]
                actual_version = int(row["version"]) if row else None
                if actual_version != expected_version:
                    failures.append(
                        f"{owner} {family}: expected version {expected_version}, found {actual_version}"
                    )
                if row:
                    if family == "note":
                        actual_marker = str(row["content"]).split(";", 1)[0].removeprefix("marker=")
                    else:
                        actual_marker = json.loads(row["snapshot_json"])["marker"]
                    if actual_marker != state["markers"][family]:
                        failures.append(
                            f"{owner} {family}: expected marker {state['markers'][family]}, found {actual_marker}"
                        )

            for table, identity_column, identity, expected_action in (
                (
                    "analyst_investigation_note_audit",
                    "note_id",
                    state["note"]["note_id"],
                    "update",
                ),
                (
                    "analyst_workspace_layout_audit",
                    "layout_id",
                    state["layout"]["layout_id"],
                    "update",
                ),
            ):
                audit = db.execute(
                    f"SELECT action, version, actor FROM {table} WHERE {identity_column} = ? ORDER BY audit_id",
                    (identity,),
                ).fetchall()
                expected_versions = list(range(1, 2 + state["updates"]["note" if "note" in table else "layout"]))
                actual_versions = [int(row["version"]) for row in audit]
                if actual_versions != expected_versions:
                    failures.append(
                        f"{owner} {table}: expected audit versions {expected_versions}, found {actual_versions}"
                    )
                expected_actions = ["create"] + [expected_action] * (len(expected_versions) - 1)
                if [str(row["action"]) for row in audit] != expected_actions:
                    failures.append(f"{owner} {table}: audit actions are not contiguous")
                if any(str(row["actor"]) != owner for row in audit):
                    failures.append(f"{owner} {table}: unexpected audit actor")

            owner_note_count = int(
                db.execute(
                    "SELECT COUNT(*) FROM analyst_investigation_notes WHERE owner = ?",
                    (owner,),
                ).fetchone()[0]
            )
            if owner_note_count != 4:
                failures.append(f"{owner}: expected 4 owned note records, found {owner_note_count}")

        recursive_row = db.execute(
            "SELECT parent_id, version, visibility, shared_page FROM analyst_investigation_notes WHERE note_id = ?",
            (recursive["root"]["note_id"],),
        ).fetchone()
        recursive_children = db.execute(
            """SELECT parent_id, version, visibility, shared_page
               FROM analyst_investigation_notes
               WHERE owner = ? AND note_id NOT IN (?, ?)""",
            (
                recursive["owner"],
                recursive["root"]["note_id"],
                recursive["destination"]["note_id"],
            ),
        ).fetchall()
        recursive_count = int(
            db.execute(
                "SELECT COUNT(*) FROM analyst_investigation_notes WHERE owner = ?",
                (recursive["owner"],),
            ).fetchone()[0]
        )
        if recursive_count != recursive["items"] + 1:
            failures.append(
                f"recursive owner: expected {recursive['items'] + 1} records, found {recursive_count}"
            )
        if recursive_row is None or (
            str(recursive_row["parent_id"]) != recursive["destination"]["note_id"]
            or int(recursive_row["version"]) != 4
            or str(recursive_row["visibility"]) != "personal"
            or recursive_row["shared_page"] is not None
        ):
            failures.append("recursive branch final parent, version, or sharing state is incorrect")
        invalid_children = [
            row
            for row in recursive_children
            if str(row["parent_id"]) != recursive["root"]["note_id"]
            or int(row["version"]) != 3
            or str(row["visibility"]) != "personal"
            or row["shared_page"] is not None
        ]
        if len(recursive_children) != recursive["items"] - 1 or invalid_children:
            failures.append(
                "recursive descendants did not retain their exact parent, version 3, and personal sharing state"
            )
        recursive_audit = db.execute(
            """SELECT action, version, actor
               FROM analyst_investigation_note_audit
               WHERE note_id = ? ORDER BY audit_id""",
            (recursive["root"]["note_id"],),
        ).fetchall()
        expected_recursive_audit = [
            ("create", 1, recursive["owner"]),
            ("share", 2, recursive["owner"]),
            ("unshare", 3, recursive["owner"]),
            ("update", 4, recursive["owner"]),
        ]
        actual_recursive_audit = [
            (str(row["action"]), int(row["version"]), str(row["actor"]))
            for row in recursive_audit
        ]
        if actual_recursive_audit != expected_recursive_audit:
            failures.append(
                f"recursive root audit mismatch: expected {expected_recursive_audit}, found {actual_recursive_audit}"
            )

        expected_counts = {
            "ordinary_notes": len(states) * 4,
            "ordinary_layouts": len(states),
            "ordinary_working_views": len(states),
            "ordinary_filter_presets": len(states),
            "recursive_notes": recursive["items"] + 1,
        }
        actual_counts = {
            "ordinary_notes": int(
                db.execute(
                    "SELECT COUNT(*) FROM analyst_investigation_notes WHERE owner LIKE 'benchmark-analyst-%'"
                ).fetchone()[0]
            ),
            "ordinary_layouts": int(
                db.execute("SELECT COUNT(*) FROM analyst_workspace_layouts").fetchone()[0]
            ),
            "ordinary_working_views": int(
                db.execute("SELECT COUNT(*) FROM analyst_view_preferences").fetchone()[0]
            ),
            "ordinary_filter_presets": int(
                db.execute("SELECT COUNT(*) FROM analyst_filter_presets").fetchone()[0]
            ),
            "recursive_notes": recursive_count,
        }
        if actual_counts != expected_counts:
            failures.append(f"row ownership/count mismatch: expected {expected_counts}, found {actual_counts}")

    if integrity_rows != ["ok"]:
        failures.append(f"PRAGMA integrity_check returned {integrity_rows}")
    return {
        "passed": not failures,
        "failures": failures,
        "integrity_check": integrity_rows,
        "journal_mode": journal_mode,
        "busy_timeout_ms": busy_timeout_ms,
        "row_counts": actual_counts,
    }


def _passes_run_contract(
    *,
    mode: str,
    failure_counts: dict[str, int],
    verification: dict,
    read_stats: dict[str, int],
    overlap_timings: dict[str, list[float]],
) -> bool:
    overlap_proven = mode == "serial" or all(overlap_timings[family] for family in FAMILIES)
    return (
        not any(failure_counts.values())
        and verification["passed"]
        and read_stats["attempted"] == read_stats["completed"]
        and (mode == "serial" or read_stats["while_writers_active"] > 0)
        and overlap_proven
    )


def run_once(
    db_path: Path,
    *,
    mode: str,
    workers: int,
    cycles: int,
    payload_bytes: int,
    recursive_items: int,
    reader_workers: int,
    reads_per_worker: int,
    seed: int,
) -> dict:
    if mode not in {"serial", "concurrent"}:
        raise ValueError("mode must be serial or concurrent")
    states, recursive = _prepare(
        db_path,
        workers=workers,
        payload_bytes=payload_bytes,
        recursive_items=recursive_items,
    )
    padding = "x" * payload_bytes

    # Warm-up uses the same public paths and is deliberately excluded from timing.
    for state in states:
        for family in FAMILIES:
            _update(db_path, state, family, -1, padding)

    timings = {family: [] for family in FAMILIES}
    overlap_timings = {family: [] for family in FAMILIES}
    recursive_timings: list[dict] = []
    failures = {
        "locked_busy_timeout": [],
        "optimistic_conflict": [],
        "unexpected": [],
    }
    read_stats = {"attempted": 0, "completed": 0, "while_writers_active": 0}
    lock = threading.Lock()
    writers_active = threading.Event()
    recursive_active = threading.Event()
    remaining_writers = {"count": workers + 1}
    ordinary_ready_count = {"count": 0}
    ordinary_ready = threading.Event()
    recursive_started = threading.Event()
    barrier = (
        threading.Barrier(workers + reader_workers + 1)
        if mode == "concurrent"
        else None
    )

    def writer_done() -> None:
        with lock:
            remaining_writers["count"] -= 1
            if remaining_writers["count"] == 0:
                writers_active.clear()

    def ordinary_worker(index: int, state: dict) -> None:
        local = {family: [] for family in FAMILIES}
        local_overlap = {family: [] for family in FAMILIES}
        try:
            if barrier:
                barrier.wait(timeout=30)
                with lock:
                    ordinary_ready_count["count"] += 1
                    if ordinary_ready_count["count"] == workers:
                        ordinary_ready.set()
                if not recursive_started.wait(timeout=30):
                    raise TimeoutError("recursive workload did not start")
            rng = random.Random(seed + index)
            for cycle in range(cycles):
                order = list(FAMILIES)
                rng.shuffle(order)
                rotation = cycle % len(order)
                order = order[rotation:] + order[:rotation]
                for family in order:
                    began_during_recursive = recursive_active.is_set()
                    started = time.perf_counter()
                    try:
                        _update(db_path, state, family, cycle, padding)
                    except Exception as exc:  # retain all failures in report
                        with lock:
                            _record_failure(failures, f"{state['owner']} {family}", exc)
                    else:
                        elapsed = time.perf_counter() - started
                        local[family].append(elapsed)
                        if began_during_recursive or recursive_active.is_set():
                            local_overlap[family].append(elapsed)
        finally:
            with lock:
                for family in FAMILIES:
                    timings[family].extend(local[family])
                    overlap_timings[family].extend(local_overlap[family])
            writer_done()

    def recursive_worker() -> None:
        try:
            if barrier:
                barrier.wait(timeout=30)
                if not ordinary_ready.wait(timeout=30):
                    raise TimeoutError("ordinary writers did not become ready")
            recursive_active.set()
            recursive_started.set()
            try:
                operations = _recursive(db_path, recursive)
            except Exception as exc:
                with lock:
                    _record_failure(failures, "recursive folder workload", exc)
            else:
                with lock:
                    recursive_timings.extend(operations)
        finally:
            recursive_active.clear()
            writer_done()

    def reader_worker(index: int) -> None:
        if barrier:
            barrier.wait(timeout=30)
        owner = states[index % len(states)]["owner"]
        for read_index in range(reads_per_worker):
            active = writers_active.is_set()
            with lock:
                read_stats["attempted"] += 1
            try:
                _read(db_path, owner)
            except Exception as exc:
                with lock:
                    _record_failure(failures, f"reader-{index} read-{read_index}", exc)
            else:
                with lock:
                    read_stats["completed"] += 1
                    if active:
                        read_stats["while_writers_active"] += 1

    writers_active.set()
    wall_started = time.perf_counter()
    cpu_started = time.process_time()
    if mode == "serial":
        for index, state in enumerate(states):
            ordinary_worker(index, state)
        recursive_worker()
        for index in range(reader_workers):
            reader_worker(index)
    else:
        with ThreadPoolExecutor(max_workers=workers + reader_workers + 1) as pool:
            futures = [
                pool.submit(ordinary_worker, index, state)
                for index, state in enumerate(states)
            ]
            futures.append(pool.submit(recursive_worker))
            futures.extend(pool.submit(reader_worker, index) for index in range(reader_workers))
            for future in futures:
                future.result()
    wall_seconds = time.perf_counter() - wall_started
    process_cpu_seconds = time.process_time() - cpu_started

    verification = _verify(db_path, states, recursive)
    failure_counts = {f"{key}_count": len(value) for key, value in failures.items()}
    passed = _passes_run_contract(
        mode=mode,
        failure_counts=failure_counts,
        verification=verification,
        read_stats=read_stats,
        overlap_timings=overlap_timings,
    )
    return {
        "mode": mode,
        "passed": passed,
        "wall_seconds": round(wall_seconds, 4),
        "process_cpu_seconds": round(process_cpu_seconds, 4),
        "ordinary_families": {family: _summary(values) for family, values in timings.items()},
        "ordinary_during_recursive": {
            family: _summary(values) for family, values in overlap_timings.items()
        },
        "recursive_overlap_contract": {
            "required_per_family": mode == "concurrent",
            "passed": mode == "serial"
            or all(overlap_timings[family] for family in FAMILIES),
        },
        "recursive_operations": [
            {"action": item["action"], "milliseconds": round(item["seconds"] * 1000, 3)}
            for item in recursive_timings
        ],
        "reads": read_stats,
        "failures": {**failure_counts, **failures},
        "verification": verification,
    }


def _aggregate(runs: list[dict], mode: str) -> dict:
    selected = [run for run in runs if run["mode"] == mode]
    return {
        family: {
            "sample_count_per_run": selected[0]["ordinary_families"][family]["count"],
            "worst_repeat_p50_ms": max(run["ordinary_families"][family]["p50_ms"] for run in selected),
            "worst_repeat_p95_ms": max(run["ordinary_families"][family]["p95_ms"] for run in selected),
            "worst_repeat_max_ms": max(run["ordinary_families"][family]["max_ms"] for run in selected),
        }
        for family in FAMILIES
    }


def run_suite(
    output_directory: Path,
    *,
    workers: int = 8,
    cycles: int = 50,
    payload_bytes: int = 4096,
    recursive_items: int = 1000,
    reader_workers: int = 2,
    reads_per_worker: int = 50,
    repeats: int = 3,
    seed: int = 20261009,
    runtime_label: str = "unspecified local runtime",
    host_label: str = "unspecified local host",
    source_commit: str = "test fixture",
) -> dict:
    output_directory.mkdir(parents=True, exist_ok=True)
    runs = []
    for repeat in range(repeats):
        for mode in ("serial", "concurrent"):
            run = run_once(
                output_directory / f"{mode}-{repeat + 1}.db",
                mode=mode,
                workers=workers,
                cycles=cycles,
                payload_bytes=payload_bytes,
                recursive_items=recursive_items,
                reader_workers=reader_workers,
                reads_per_worker=reads_per_worker,
                seed=seed + repeat * 1000,
            )
            run["repeat"] = repeat + 1
            runs.append(run)

    aggregate = {mode: _aggregate(runs, mode) for mode in ("serial", "concurrent")}
    guardrail_failures = []
    for run in runs:
        if not run["passed"]:
            guardrail_failures.append(f"{run['mode']} repeat {run['repeat']} failed validation")
        for family in FAMILIES:
            if run["ordinary_families"][family]["max_ms"] >= 5000:
                guardrail_failures.append(
                    f"{run['mode']} repeat {run['repeat']} {family} reached 5 seconds"
                )
    for family in FAMILIES:
        serial_p95 = aggregate["serial"][family]["worst_repeat_p95_ms"]
        concurrent_p95 = aggregate["concurrent"][family]["worst_repeat_p95_ms"]
        limit = max(1000.0, serial_p95 * 10)
        aggregate["concurrent"][family]["p95_limit_ms"] = round(limit, 3)
        aggregate["concurrent"][family]["p95_within_limit"] = concurrent_p95 <= limit
        if concurrent_p95 > limit:
            guardrail_failures.append(
                f"{family} concurrent p95 {concurrent_p95} ms exceeded {limit} ms"
            )

    return {
        "schema_version": 2,
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "passed": not guardrail_failures,
        "guardrail_failures": guardrail_failures,
        "configuration": {
            "repeats_per_mode": repeats,
            "analysts": workers,
            "cycles_per_analyst": cycles,
            "operations_per_family_per_run": workers * cycles,
            "payload_bytes": payload_bytes,
            "recursive_branch_items": recursive_items,
            "reader_workers": reader_workers,
            "reads_per_worker": reads_per_worker,
            "seed": seed,
            "percentile_method": PERCENTILE_METHOD,
            "guardrails": {
                "errors_and_conflicts": 0,
                "concurrent_p95": "at most max(1000 ms, 10 times serial p95)",
                "individual_call": "less than 5000 ms",
                "reader_progress": "at least one completed read while concurrent writers are active",
            },
        },
        "environment": {
            "runtime_label": runtime_label,
            "host_label": host_label,
            "python": platform.python_version(),
            "sqlite": sqlite3.sqlite_version,
            "platform": platform.platform(),
            "source_commit": source_commit,
        },
        "aggregate": aggregate,
        "runs": runs,
        "limitations": [
            "Local disposable development benchmark; it is not Range-scale or mission-ready acceptance.",
            "Measures direct in-process storage functions, not HTTP requests or rendered page performance.",
            "Does not measure network latency, multi-process contention, cold-cache startup, or a large retained installation.",
            "Each simulated analyst owns distinct ordinary records, so optimistic conflicts are treated as failures rather than intentional test traffic.",
            "Whole-process process_time is reported as CPU time; it is not per-thread CPU attribution.",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Compare serial and concurrent NCT workspace storage workloads."
    )
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--cycles", type=int, default=50)
    parser.add_argument("--payload-bytes", type=int, default=4096)
    parser.add_argument("--recursive-items", type=int, default=1000)
    parser.add_argument("--reader-workers", type=int, default=2)
    parser.add_argument("--reads-per-worker", type=int, default=50)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--seed", type=int, default=20261009)
    parser.add_argument("--runtime-label", required=True)
    parser.add_argument("--host-label", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--database-directory", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    if not 1 <= args.workers <= 32:
        parser.error("--workers must be between 1 and 32")
    if not 1 <= args.cycles <= 10_000:
        parser.error("--cycles must be between 1 and 10,000")
    if not 0 <= args.payload_bytes <= 100_000:
        parser.error("--payload-bytes must be between 0 and 100,000")
    if not 2 <= args.recursive_items <= 1000:
        parser.error("--recursive-items must be between 2 and 1,000")
    if not 1 <= args.reader_workers <= 16 or not 1 <= args.reads_per_worker <= 10_000:
        parser.error("reader counts must be positive and bounded")
    if not 1 <= args.repeats <= 20:
        parser.error("--repeats must be between 1 and 20")

    if args.database_directory:
        result = run_suite(
            args.database_directory,
            workers=args.workers,
            cycles=args.cycles,
            payload_bytes=args.payload_bytes,
            recursive_items=args.recursive_items,
            reader_workers=args.reader_workers,
            reads_per_worker=args.reads_per_worker,
            repeats=args.repeats,
            seed=args.seed,
            runtime_label=args.runtime_label,
            host_label=args.host_label,
            source_commit=args.source_commit,
        )
    else:
        with tempfile.TemporaryDirectory(prefix="nct-workspace-benchmark-") as directory:
            result = run_suite(
                Path(directory),
                workers=args.workers,
                cycles=args.cycles,
                payload_bytes=args.payload_bytes,
                recursive_items=args.recursive_items,
                reader_workers=args.reader_workers,
                reads_per_worker=args.reads_per_worker,
                repeats=args.repeats,
                seed=args.seed,
                runtime_label=args.runtime_label,
                host_label=args.host_label,
                source_commit=args.source_commit,
            )

    encoded = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
    print(encoded, end="")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
