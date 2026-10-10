from __future__ import annotations

import threading
from typing import Literal


LifecyclePhase = Literal["starting", "ready", "draining", "stopped", "failed"]
ProbeName = Literal["startup", "readiness", "liveness"]

_lock = threading.Lock()
_phase: LifecyclePhase = "stopped"

_MEANINGS = {
    "startup": "Required initialization and recovery safety checks have completed.",
    "readiness": "This NCT instance can safely accept HTTP requests.",
    "liveness": "The NCT process is responsive.",
}


def begin_startup() -> None:
    _set_phase("starting")


def mark_ready() -> None:
    _set_phase("ready")


def begin_shutdown() -> None:
    _set_phase("draining")


def mark_stopped() -> None:
    _set_phase("stopped")


def mark_failed() -> None:
    _set_phase("failed")


def lifecycle_phase() -> LifecyclePhase:
    with _lock:
        return _phase


def probe_result(name: ProbeName) -> tuple[int, dict[str, object]]:
    phase = lifecycle_phase()
    if name == "liveness":
        healthy = True
        status = "live"
    elif name == "startup":
        healthy = phase in {"ready", "draining"}
        status = "started" if healthy else "not_started"
    else:
        healthy = phase == "ready"
        status = "ready" if healthy else "not_ready"
    return (
        200 if healthy else 503,
        {
            "schema_version": 1,
            "check": name,
            "status": status,
            "healthy": healthy,
            "meaning": _MEANINGS[name],
        },
    )


def _set_phase(phase: LifecyclePhase) -> None:
    global _phase
    with _lock:
        _phase = phase
