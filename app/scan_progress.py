from __future__ import annotations

import re


NMAP_STATS_RE = re.compile(
    r"Stats:.*?(\d+)\s+hosts?\s+completed\s+\((\d+)\s+up\)",
    re.IGNORECASE,
)


def latest_nmap_stats(text: str) -> tuple[int, int] | None:
    """Return the newest completed/up counters emitted by --stats-every."""
    matches = NMAP_STATS_RE.findall(text)
    if not matches:
        return None
    completed, up = matches[-1]
    return int(completed), int(up)


def new_scan_progress(
    hosts_total: int,
    *,
    phase: str = "queued",
    chunk_number: int | None = None,
    chunk_count: int | None = None,
    batch_hosts_total: int | None = None,
    batch_hosts_completed_before: int = 0,
    updated_at: str | None = None,
) -> dict:
    total = max(0, int(hosts_total))
    batch_total = max(0, int(batch_hosts_total or total))
    before = min(max(0, int(batch_hosts_completed_before)), batch_total)
    return {
        "phase": phase,
        "hosts_completed": 0,
        "hosts_total": total,
        "hosts_up": 0,
        "percent": 0.0,
        "scope_hosts_total": total,
        "chunk_number": chunk_number,
        "chunk_count": chunk_count,
        "batch_hosts_completed_before": before,
        "batch_hosts_completed": before,
        "batch_hosts_total": batch_total,
        "batch_percent": round((before / batch_total) * 100, 1) if batch_total else 0.0,
        "updated_at": updated_at,
    }


def update_scan_progress(
    progress: dict,
    *,
    phase: str | None = None,
    hosts_completed: int | None = None,
    hosts_total: int | None = None,
    hosts_up: int | None = None,
    batch_hosts_completed: int | None = None,
    updated_at: str | None = None,
) -> bool:
    """Update counters safely and report whether a visible value changed."""
    before = dict(progress)
    if phase is not None:
        progress["phase"] = phase
    if hosts_total is not None:
        progress["hosts_total"] = max(0, int(hosts_total))
    total = max(0, int(progress.get("hosts_total") or 0))
    if hosts_completed is not None:
        progress["hosts_completed"] = min(max(0, int(hosts_completed)), total)
    completed = min(max(0, int(progress.get("hosts_completed") or 0)), total)
    progress["hosts_completed"] = completed
    if hosts_up is not None:
        progress["hosts_up"] = min(max(0, int(hosts_up)), completed)
    progress["percent"] = round((completed / total) * 100, 1) if total else 0.0

    batch_total = max(0, int(progress.get("batch_hosts_total") or 0))
    if batch_hosts_completed is None:
        batch_hosts_completed = int(progress.get("batch_hosts_completed_before") or 0) + completed
    progress["batch_hosts_completed"] = min(
        max(0, int(batch_hosts_completed)), batch_total
    )
    progress["batch_percent"] = (
        round((progress["batch_hosts_completed"] / batch_total) * 100, 1)
        if batch_total
        else 0.0
    )
    if updated_at is not None:
        progress["updated_at"] = updated_at
    return progress != before

