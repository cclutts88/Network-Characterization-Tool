from __future__ import annotations

import re


NMAP_STATS_RE = re.compile(
    r"Stats:\s*(?P<elapsed>\d+:\d{2}:\d{2})\s+elapsed;\s*"
    r"(?P<completed>\d+)\s+hosts?\s+completed\s+\((?P<up>\d+)\s+up\)"
    r"(?:,\s*(?P<active>\d+)\s+undergoing\s+(?P<activity>[^\r\n]+))?",
    re.IGNORECASE,
)
NMAP_TIMING_RE = re.compile(
    r"(?P<phase>[^\r\n:]+?)\s+Timing:\s*About\s*"
    r"(?P<percent>\d+(?:\.\d+)?)%\s+done"
    r"(?:;\s*ETC:\s*(?P<eta>[^\s(]+)\s*"
    r"\((?P<remaining>\d+:\d{2}:\d{2})\s+remaining\))?",
    re.IGNORECASE,
)


def duration_seconds(value: str) -> int:
    hours, minutes, seconds = (int(part) for part in value.split(":"))
    return hours * 3600 + minutes * 60 + seconds


def latest_nmap_status(text: str) -> dict | None:
    """Return the newest Nmap host counters, activity, and timing estimate."""
    matches = list(NMAP_STATS_RE.finditer(text))
    if not matches:
        return None
    match = matches[-1]
    following = text[match.end():]
    next_stats = NMAP_STATS_RE.search(following)
    if next_stats:
        following = following[:next_stats.start()]
    timing = NMAP_TIMING_RE.search(following)
    result = {
        "hosts_completed": int(match.group("completed")),
        "hosts_up": int(match.group("up")),
        "elapsed_seconds": duration_seconds(match.group("elapsed")),
        "active_hosts": int(match.group("active") or 0),
        "activity": (match.group("activity") or "").strip() or None,
        "phase_percent": None,
        "eta_clock": None,
        "remaining_seconds": None,
    }
    if timing:
        result.update(
            {
                "activity": timing.group("phase").strip(),
                "phase_percent": float(timing.group("percent")),
                "eta_clock": timing.group("eta"),
                "remaining_seconds": (
                    duration_seconds(timing.group("remaining"))
                    if timing.group("remaining")
                    else None
                ),
            }
        )
    return result


def latest_nmap_stats(text: str) -> tuple[int, int] | None:
    """Return the newest completed/up counters emitted by --stats-every."""
    status = latest_nmap_status(text)
    if status is None:
        return None
    return status["hosts_completed"], status["hosts_up"]


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
        "activity": None,
        "active_hosts": 0,
        "phase_percent": None,
        "eta_clock": None,
        "remaining_seconds": None,
        "elapsed_seconds": 0,
        "deadline_remaining_seconds": None,
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
    activity: str | None = None,
    active_hosts: int | None = None,
    phase_percent: float | None = None,
    eta_clock: str | None = None,
    remaining_seconds: int | None = None,
    elapsed_seconds: int | None = None,
    deadline_remaining_seconds: int | None = None,
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
    if activity is not None:
        progress["activity"] = activity
    if active_hosts is not None:
        progress["active_hosts"] = max(0, int(active_hosts))
    if phase_percent is not None:
        progress["phase_percent"] = round(
            min(max(0.0, float(phase_percent)), 100.0), 1
        )
    if eta_clock is not None:
        progress["eta_clock"] = eta_clock
    if remaining_seconds is not None:
        progress["remaining_seconds"] = max(0, int(remaining_seconds))
    if elapsed_seconds is not None:
        progress["elapsed_seconds"] = max(0, int(elapsed_seconds))
    if deadline_remaining_seconds is not None:
        progress["deadline_remaining_seconds"] = max(
            0, int(deadline_remaining_seconds)
        )
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
