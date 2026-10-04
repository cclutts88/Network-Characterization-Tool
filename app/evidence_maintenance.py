"""Single-process exclusion for evidence-changing work and storage maintenance."""
from __future__ import annotations

from contextlib import contextmanager
from functools import wraps
import inspect
import json
import os
from pathlib import Path
import threading


class EvidenceMaintenanceBlocked(RuntimeError):
    pass


class _Gate:
    def __init__(self) -> None:
        self.condition = threading.Condition(threading.RLock())
        self.mutations = 0
        self.maintenance = False


_GATES: dict[str, _Gate] = {}
_GATES_LOCK = threading.Lock()


def _key(db_path: Path) -> str:
    return str(Path(db_path).resolve())


def _gate(db_path: Path) -> _Gate:
    key = _key(db_path)
    with _GATES_LOCK:
        return _GATES.setdefault(key, _Gate())


def recovery_root(db_path: Path) -> Path:
    return Path(db_path).parent / ".artifact-compaction-recovery"


def recovery_required_path(db_path: Path) -> Path:
    return recovery_root(db_path) / "RECOVERY_REQUIRED.json"


def recovery_required(db_path: Path) -> bool:
    return recovery_required_path(db_path).is_file()


def evidence_mutations_blocked(db_path: Path) -> bool:
    gate = _gate(db_path)
    with gate.condition:
        return recovery_required(db_path) or gate.maintenance


def _fsync_directory(path: Path) -> None:
    if os.name != "posix":
        return
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def mark_recovery_required(db_path: Path, detail: str) -> None:
    path = recovery_required_path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps({"detail": detail}), encoding="utf-8")
    with temporary.open("rb") as stream:
        os.fsync(stream.fileno())
    temporary.replace(path)
    _fsync_directory(path.parent)


def clear_recovery_required(db_path: Path) -> None:
    path = recovery_required_path(db_path)
    existed = path.exists()
    path.unlink(missing_ok=True)
    if existed:
        _fsync_directory(path.parent)


@contextmanager
def evidence_mutation(db_path: Path):
    gate = _gate(db_path)
    with gate.condition:
        if recovery_required(db_path):
            raise EvidenceMaintenanceBlocked(
                "Evidence changes are blocked until interrupted compaction recovery is resolved"
            )
        if gate.maintenance:
            raise EvidenceMaintenanceBlocked(
                "Evidence changes are temporarily blocked while exact-content compaction runs"
            )
        gate.mutations += 1
    try:
        yield
    finally:
        with gate.condition:
            gate.mutations -= 1
            gate.condition.notify_all()


@contextmanager
def evidence_maintenance(db_path: Path, *, allow_recovery: bool = False):
    gate = _gate(db_path)
    with gate.condition:
        if recovery_required(db_path) and not allow_recovery:
            raise EvidenceMaintenanceBlocked(
                "Compaction recovery must be resolved before maintenance can continue"
            )
        if gate.maintenance or gate.mutations:
            raise EvidenceMaintenanceBlocked(
                "Evidence-changing work is active; retry maintenance after it finishes"
            )
        gate.maintenance = True
    try:
        yield
    finally:
        with gate.condition:
            gate.maintenance = False
            gate.condition.notify_all()


def guarded_evidence_mutation(path_resolver):
    """Decorate a complete sync or async evidence-changing operation."""
    def decorate(function):
        if inspect.iscoroutinefunction(function):
            @wraps(function)
            async def async_wrapper(*args, **kwargs):
                with evidence_mutation(Path(path_resolver(*args, **kwargs))):
                    return await function(*args, **kwargs)
            async_wrapper.__signature__ = inspect.signature(function, eval_str=True)
            return async_wrapper

        @wraps(function)
        def wrapper(*args, **kwargs):
            with evidence_mutation(Path(path_resolver(*args, **kwargs))):
                return function(*args, **kwargs)
        wrapper.__signature__ = inspect.signature(function, eval_str=True)
        return wrapper
    return decorate
