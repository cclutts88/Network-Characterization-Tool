"""Runtime admission gate for the independently stored retirement authority."""
from __future__ import annotations

from dataclasses import dataclass
from contextlib import contextmanager
import os
from pathlib import Path
import threading

from app.retirement_guard import (
    RetirementGuardStatus,
    check_retirement_guard,
    check_retirement_guard_head,
)


REQUIRED_MODE = "required"
DISABLED_MODE = "disabled"
# The reviewer must clear startup, restore, read-route and preview binding gates
# before this source-controlled latch can be changed. Environment values cannot
# bypass it.
OPERATOR_CONTROLS_AVAILABLE = False
_LOCK = threading.RLock()
_STATUS = RetirementGuardStatus(
    "hold", "retirement guard has not been checked", None, None, None,
)


class RetirementRuntimeError(RuntimeError):
    pass


@contextmanager
def retirement_commit_window():
    """Serialize one local retirement commit with its protected-head advance."""
    with _LOCK:
        yield


@dataclass(frozen=True)
class RetirementRuntimeConfig:
    mode: str
    guard_dir: Path | None
    data_identity: str | None


def runtime_config() -> RetirementRuntimeConfig:
    # A release that understands retirement must never silently run without its
    # independent high-water authority. Tests and deliberately inert developer
    # previews opt out explicitly; production defaults to protected admission.
    mode = os.environ.get("NCT_RETIREMENT_GUARD_MODE", REQUIRED_MODE).strip().lower()
    if mode not in {DISABLED_MODE, REQUIRED_MODE}:
        raise RetirementRuntimeError("NCT_RETIREMENT_GUARD_MODE is invalid")
    guard_value = os.environ.get("NCT_RETIREMENT_GUARD_DIR", "").strip()
    identity = os.environ.get("NCT_RETIREMENT_DATA_IDENTITY", "").strip()
    if mode == REQUIRED_MODE and (not guard_value or not identity):
        raise RetirementRuntimeError(
            "Required retirement guard paths and data identity are not configured"
        )
    return RetirementRuntimeConfig(
        mode=mode,
        guard_dir=Path(guard_value).absolute() if guard_value else None,
        data_identity=identity or None,
    )


def validate_retirement_runtime(db_path: Path, data_dir: Path) -> RetirementGuardStatus:
    """Check and, when valid, advance the protected high-water receipt."""
    global _STATUS
    with _LOCK:
        config = runtime_config()
        if config.mode == DISABLED_MODE:
            status = RetirementGuardStatus(
                "hold",
                "operator retirement controls are disabled until the host guard is provisioned",
                None,
                None,
                None,
            )
        else:
            assert config.guard_dir is not None and config.data_identity is not None
            status = check_retirement_guard(
                db_path,
                data_dir=data_dir,
                guard_dir=config.guard_dir,
                data_identity=config.data_identity,
            )
        _STATUS = status
    return status


def retirement_runtime_status() -> RetirementGuardStatus:
    with _LOCK:
        return _STATUS


def validate_retirement_projection_runtime(
    db_path: Path, data_dir: Path,
) -> RetirementGuardStatus:
    """Perform a bounded live guard check before an ordinary evidence API read."""
    global _STATUS
    with _LOCK:
        config = runtime_config()
        if config.mode == DISABLED_MODE:
            return _STATUS
        assert config.guard_dir is not None and config.data_identity is not None
        status = check_retirement_guard_head(
            db_path,
            data_dir=data_dir,
            guard_dir=config.guard_dir,
            data_identity=config.data_identity,
        )
        _STATUS = status
    return status


def retirement_controls_available() -> bool:
    return OPERATOR_CONTROLS_AVAILABLE


def require_retirement_controls_ready() -> RetirementGuardStatus:
    if not OPERATOR_CONTROLS_AVAILABLE:
        raise RetirementRuntimeError(
            "operator retirement controls have not passed the independent quality gate"
        )
    config = runtime_config()
    status = retirement_runtime_status()
    if config.mode != REQUIRED_MODE or not status.ready:
        raise RetirementRuntimeError(status.reason)
    return status


def require_retirement_startup_ready(db_path: Path, data_dir: Path) -> RetirementGuardStatus:
    """Validate required protected state before any projection worker can start."""
    config = runtime_config()
    status = validate_retirement_runtime(db_path, data_dir)
    if config.mode == REQUIRED_MODE and not status.ready:
        raise RetirementRuntimeError(
            f"protected retirement authority blocked startup: {status.reason}"
        )
    return status
