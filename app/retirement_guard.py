"""Out-of-backup retirement high-water authority.

The guard directory is provisioned by the host on storage that is not included in
the mission-data backup.  It mirrors immutable retirement receipts and prevents an
older database restore from silently making retired evidence active again.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
from typing import Iterator
import uuid

from app.database import connect_database


GUARD_CONTRACT = "nct-retirement-guard-v1"
PROVISIONING_FILE = "provisioning.json"
BINDING_FILE = "lineage-binding.json"
HIGH_WATER_FILE = "high-water.json"
HOLD_FILE = "projection-hold.json"


class RetirementGuardError(RuntimeError):
    pass


@dataclass(frozen=True)
class RetirementGuardStatus:
    state: str
    reason: str
    lineage_id: str | None
    revision: int | None
    event_digest: str | None

    @property
    def ready(self) -> bool:
        return self.state == "ready"


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _canonical(value: object) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False,
    )


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _receipt(value: dict) -> dict:
    body = dict(value)
    body["receipt_sha256"] = _digest(body)
    return body


def _read_receipt(path: Path) -> dict:
    try:
        status = path.lstat()
        if stat.S_ISLNK(status.st_mode) or not stat.S_ISREG(status.st_mode):
            raise RetirementGuardError(f"{path.name} is not a regular receipt")
        if hasattr(os, "geteuid") and status.st_uid != os.geteuid():
            raise RetirementGuardError(f"{path.name} has the wrong owner")
        if status.st_mode & 0o077:
            raise RetirementGuardError(f"{path.name} has unsafe permissions")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "r", encoding="utf-8") as stream:
            value = json.load(stream)
    except (OSError, json.JSONDecodeError) as exc:
        raise RetirementGuardError(f"{path.name} is missing or unreadable") from exc
    if not isinstance(value, dict):
        raise RetirementGuardError(f"{path.name} is not a receipt")
    supplied = value.pop("receipt_sha256", None)
    if not isinstance(supplied, str) or supplied != _digest(value):
        raise RetirementGuardError(f"{path.name} receipt digest is invalid")
    return value


def _atomic_receipt(path: Path, value: dict) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    payload = (_canonical(_receipt(value)) + "\n").encode("utf-8")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def _secure_directory(path: Path) -> None:
    try:
        status = path.lstat()
    except OSError as exc:
        raise RetirementGuardError("retirement guard directory is unavailable") from exc
    if stat.S_ISLNK(status.st_mode) or not stat.S_ISDIR(status.st_mode):
        raise RetirementGuardError("retirement guard path is not a directory")
    if hasattr(os, "geteuid") and status.st_uid != os.geteuid():
        raise RetirementGuardError("retirement guard directory has the wrong owner")
    if status.st_mode & 0o022:
        raise RetirementGuardError(
            "retirement guard directory is writable by another account"
        )


def _separate_paths(data_dir: Path, guard_dir: Path) -> tuple[Path, Path]:
    data = data_dir.resolve()
    guard = guard_dir.absolute()
    comparable_guard = guard.resolve()
    if (
        comparable_guard == data
        or comparable_guard in data.parents
        or data in comparable_guard.parents
    ):
        raise RetirementGuardError(
            "retirement guard storage must be separate from mission-data storage"
        )
    return data, guard


@contextmanager
def _guard_lock(guard_dir: Path) -> Iterator[None]:
    lock_path = guard_dir / ".retirement-guard.lock"
    descriptor = os.open(
        lock_path,
        os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    lock_status = os.fstat(descriptor)
    if (
        (hasattr(os, "geteuid") and lock_status.st_uid != os.geteuid())
        or lock_status.st_mode & 0o077
    ):
        os.close(descriptor)
        raise RetirementGuardError("retirement guard lock has unsafe ownership or permissions")
    try:
        try:
            import fcntl

            fcntl.flock(descriptor, fcntl.LOCK_EX)
        except ImportError:  # pragma: no cover - production images are Linux
            import msvcrt

            msvcrt.locking(descriptor, msvcrt.LK_LOCK, 1)
        yield
    finally:
        try:
            try:
                import fcntl

                fcntl.flock(descriptor, fcntl.LOCK_UN)
            except ImportError:  # pragma: no cover - production images are Linux
                import msvcrt

                msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
        finally:
            os.close(descriptor)


def provision_retirement_guard(
    guard_dir: Path, *, installation_id: str, data_identity: str,
) -> dict:
    """Create one host-authorized fresh/pre-retirement admission receipt."""
    guard = guard_dir.absolute()
    installation_id = str(installation_id or "").strip()
    data_identity = str(data_identity or "").strip()
    if not installation_id or not data_identity:
        raise RetirementGuardError("installation and data identities are required")
    if guard.is_symlink():
        raise RetirementGuardError("retirement guard path cannot be a symlink")
    guard.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(guard, 0o700)
    _secure_directory(guard)
    provisioning = guard / PROVISIONING_FILE
    if provisioning.exists() or any(guard.iterdir()):
        raise RetirementGuardError("retirement guard is already provisioned")
    (guard / "events").mkdir(mode=0o700)
    (guard / "audit").mkdir(mode=0o700)
    body = {
        "contract": GUARD_CONTRACT,
        "installation_id": installation_id,
        "data_identity": data_identity,
        "admission": "host-provisioned-fresh-or-pre-retirement",
        "provisioned_at": _now(),
    }
    _atomic_receipt(provisioning, body)
    return body


def _provisioning(guard_dir: Path, data_identity: str) -> dict:
    value = _read_receipt(guard_dir / PROVISIONING_FILE)
    if value.get("contract") != GUARD_CONTRACT:
        raise RetirementGuardError("retirement guard contract is unsupported")
    if value.get("admission") != "host-provisioned-fresh-or-pre-retirement":
        raise RetirementGuardError("retirement guard admission is not authoritative")
    if value.get("data_identity") != data_identity:
        raise RetirementGuardError("retirement guard belongs to different data storage")
    return value


def _binding_body(provisioning: dict, lineage_id: str) -> dict:
    return {
        "contract": GUARD_CONTRACT,
        "installation_id": provisioning["installation_id"],
        "data_identity": provisioning["data_identity"],
        "lineage_id": lineage_id,
        "initial_revision": 0,
        "initial_event_digest": "root",
        "bound_at": _now(),
    }


def _read_binding(guard_dir: Path, provisioning: dict) -> dict | None:
    path = guard_dir / BINDING_FILE
    if not path.exists():
        return None
    value = _read_receipt(path)
    for key in ("contract", "installation_id", "data_identity"):
        expected = GUARD_CONTRACT if key == "contract" else provisioning[key]
        if value.get(key) != expected:
            raise RetirementGuardError("retirement lineage binding ownership changed")
    if (
        not isinstance(value.get("lineage_id"), str)
        or value.get("initial_revision") != 0
        or value.get("initial_event_digest") != "root"
    ):
        raise RetirementGuardError("retirement lineage binding is invalid")
    return value


def _mirrored_event_paths(guard_dir: Path) -> list[Path]:
    events = guard_dir / "events"
    _secure_directory(events)
    return sorted(events.glob("*.json"))


def _event_receipts(db: sqlite3.Connection) -> tuple[str, list[dict]]:
    lineage = db.execute(
        "SELECT lineage_id FROM evidence_retirement_lineage WHERE singleton=1"
    ).fetchone()
    if lineage is None:
        raise RetirementGuardError("retirement lineage is missing")
    rows = db.execute(
        """SELECT revision,event_id,lineage_id,source_family,encounter_id,
                  identity_snapshot_json,identity_snapshot_sha256,
                  previous_event_digest,event_digest,identity_count,sealed,
                  actor,reason,retired_at
             FROM evidence_retirement_events ORDER BY revision"""
    ).fetchall()
    previous = "root"
    receipts: list[dict] = []
    for row in rows:
        (
            revision, event_id, lineage_id, source_family, encounter_id,
            snapshot_json, snapshot_sha256, previous_digest, event_digest,
            identity_count, sealed, actor, reason, retired_at,
        ) = row
        if lineage_id != lineage[0] or sealed != 1 or previous_digest != previous:
            raise RetirementGuardError("retirement event chain is inconsistent")
        try:
            snapshot = json.loads(snapshot_json)
        except json.JSONDecodeError as exc:
            raise RetirementGuardError("retirement identity snapshot is unreadable") from exc
        if _canonical(snapshot) != snapshot_json:
            raise RetirementGuardError("retirement identity snapshot is not canonical")
        if hashlib.sha256(snapshot_json.encode("utf-8")).hexdigest() != snapshot_sha256:
            raise RetirementGuardError("retirement identity snapshot digest is invalid")
        identities = snapshot.get("identities") if isinstance(snapshot, dict) else None
        if not isinstance(identities, dict) or len(identities) != identity_count:
            raise RetirementGuardError("retirement identity count is inconsistent")
        indexed = {
            item[0]: item[1] for item in db.execute(
                """SELECT identity_namespace,identity_value
                     FROM evidence_retirement_identities
                    WHERE revision=? ORDER BY identity_namespace""",
                (revision,),
            )
        }
        if indexed != identities:
            raise RetirementGuardError("retirement identity index is inconsistent")
        body = {
            "event_id": event_id,
            "lineage_id": lineage_id,
            "source_family": source_family,
            "encounter_id": encounter_id,
            "identity_snapshot_sha256": snapshot_sha256,
            "previous_event_digest": previous_digest,
            "identity_count": identity_count,
            "actor": actor,
            "reason": reason,
            "retired_at": retired_at,
        }
        if _digest(body) != event_digest:
            raise RetirementGuardError("retirement event digest is invalid")
        receipts.append({
            **body,
            "revision": int(revision),
            "event_digest": event_digest,
            "identity_snapshot": snapshot,
        })
        previous = event_digest
    return str(lineage[0]), receipts


def _head(lineage_id: str, receipts: list[dict]) -> dict:
    latest = receipts[-1] if receipts else None
    return {
        "lineage_id": lineage_id,
        "revision": int(latest["revision"]) if latest else 0,
        "event_digest": str(latest["event_digest"]) if latest else "root",
    }


def _high_water_body(provisioning: dict, head: dict) -> dict:
    return {
        "contract": GUARD_CONTRACT,
        "installation_id": provisioning["installation_id"],
        "data_identity": provisioning["data_identity"],
        **head,
        "updated_at": _now(),
    }


def _read_high_water(guard_dir: Path, provisioning: dict) -> dict | None:
    path = guard_dir / HIGH_WATER_FILE
    if not path.exists():
        return None
    value = _read_receipt(path)
    for key in ("contract", "installation_id", "data_identity"):
        expected = (
            GUARD_CONTRACT if key == "contract" else provisioning[key]
        )
        if value.get(key) != expected:
            raise RetirementGuardError("retirement high-water ownership changed")
    try:
        revision = int(value["revision"])
    except (KeyError, TypeError, ValueError) as exc:
        raise RetirementGuardError("retirement high-water revision is invalid") from exc
    if revision < 0 or not isinstance(value.get("lineage_id"), str):
        raise RetirementGuardError("retirement high-water identity is invalid")
    if not isinstance(value.get("event_digest"), str):
        raise RetirementGuardError("retirement high-water digest is invalid")
    value["revision"] = revision
    return value


def _event_path(guard_dir: Path, event: dict) -> Path:
    return guard_dir / "events" / (
        f"{int(event['revision']):020d}-{event['event_digest']}.json"
    )


def _mirror_events(guard_dir: Path, events: list[dict]) -> None:
    for event in events:
        path = _event_path(guard_dir, event)
        body = {"contract": GUARD_CONTRACT, **event}
        if path.exists():
            if _read_receipt(path) != body:
                raise RetirementGuardError("mirrored retirement event changed")
            continue
        _atomic_receipt(path, body)


def _validate_mirrored_events(
    guard_dir: Path, events: list[dict], through_revision: int,
) -> None:
    known = {
        _event_path(guard_dir, event): {"contract": GUARD_CONTRACT, **event}
        for event in events
    }
    actual = set(_mirrored_event_paths(guard_dir))
    required = {
        path for path, body in known.items()
        if int(body["revision"]) <= through_revision
    }
    if not required <= actual or not actual <= set(known):
        raise RetirementGuardError("mirrored retirement event set is incomplete or unexpected")
    for path in actual:
        body = known[path]
        if _read_receipt(path) != body:
            raise RetirementGuardError("mirrored retirement event changed")


def _is_ancestor(receipt: dict, head: dict, events: list[dict]) -> bool:
    if receipt["lineage_id"] != head["lineage_id"]:
        return False
    if receipt["revision"] == 0:
        return receipt["event_digest"] == "root"
    return any(
        int(event["revision"]) == int(receipt["revision"])
        and event["event_digest"] == receipt["event_digest"]
        for event in events
    )


def _advance_locked(
    guard_dir: Path, provisioning: dict, current: dict, desired: dict,
    events: list[dict],
) -> dict:
    if current["lineage_id"] != desired["lineage_id"]:
        raise RetirementGuardError("retirement lineage does not match the guard")
    if current["revision"] > desired["revision"]:
        return current
    if current["revision"] == desired["revision"]:
        if current["event_digest"] != desired["event_digest"]:
            raise RetirementGuardError(
                "retirement head diverged at the same revision"
            )
        return current
    if not _is_ancestor(current, desired, events):
        raise RetirementGuardError("retirement high-water is not an event ancestor")
    _mirror_events(
        guard_dir,
        [event for event in events if int(event["revision"]) > current["revision"]],
    )
    value = _high_water_body(provisioning, desired)
    _atomic_receipt(guard_dir / HIGH_WATER_FILE, value)
    return value


def _audit_path(guard_dir: Path, kind: str) -> Path:
    return guard_dir / "audit" / f"{_now().replace(':', '')}-{kind}-{uuid.uuid4().hex}.json"


def _hold_locked(guard_dir: Path, *, reason: str, detail: str) -> RetirementGuardStatus:
    body = {
        "contract": GUARD_CONTRACT,
        "state": "hold",
        "reason": reason,
        "detail": detail[:1000],
        "recorded_at": _now(),
    }
    hold_path = guard_dir / HOLD_FILE
    if not hold_path.exists():
        _atomic_receipt(hold_path, body)
        _atomic_receipt(_audit_path(guard_dir, "hold"), body)
    return RetirementGuardStatus("hold", reason, None, None, None)


def mark_retirement_restore_hold(
    guard_dir: Path, *, data_identity: str, operation_id: str, detail: str,
) -> RetirementGuardStatus:
    guard = guard_dir.absolute()
    _secure_directory(guard)
    with _guard_lock(guard):
        _provisioning(guard, data_identity)
        _secure_directory(guard / "events")
        _secure_directory(guard / "audit")
        return _hold_locked(
            guard,
            reason="restore requires retirement reconciliation",
            detail=f"{operation_id}: {detail}",
        )


def check_retirement_guard(
    db_path: Path, *, data_dir: Path, guard_dir: Path, data_identity: str,
) -> RetirementGuardStatus:
    """Bind, compare or advance the independent guard; never clear a hold."""
    guard = guard_dir.absolute()
    authority_validated = False
    try:
        _, guard = _separate_paths(data_dir, guard_dir)
        _secure_directory(guard)
        with _guard_lock(guard):
            provisioning = _provisioning(guard, data_identity)
            _secure_directory(guard / "events")
            _secure_directory(guard / "audit")
            authority_validated = True
            if (guard / HOLD_FILE).exists():
                hold = _read_receipt(guard / HOLD_FILE)
                return RetirementGuardStatus(
                    "hold", str(hold.get("reason") or "retirement hold"),
                    None, None, None,
                )
            with connect_database(db_path, read_only=True) as db:
                lineage_id, events = _event_receipts(db)
            desired = _head(lineage_id, events)
            binding = _read_binding(guard, provisioning)
            current = _read_high_water(guard, provisioning)
            if binding is None:
                if current is not None or _mirrored_event_paths(guard):
                    return _hold_locked(
                        guard,
                        reason="retirement lineage binding is missing",
                        detail="Protected retirement state exists without its one-time binding.",
                    )
                if desired["revision"] != 0:
                    return _hold_locked(
                        guard,
                        reason="retirement lineage binding is missing",
                        detail="The database already contains retirement events.",
                    )
                binding = _binding_body(provisioning, lineage_id)
                _atomic_receipt(guard / BINDING_FILE, binding)
                current = _high_water_body(provisioning, desired)
                _atomic_receipt(guard / HIGH_WATER_FILE, current)
            if binding["lineage_id"] != desired["lineage_id"]:
                return _hold_locked(
                    guard,
                    reason="retirement lineage does not match the guard",
                    detail="The data and one-time lineage binding differ.",
                )
            if current is None:
                return _hold_locked(
                    guard,
                    reason="retirement high-water receipt is missing",
                    detail="The one-time lineage binding has already been consumed.",
                )
            if current["lineage_id"] != desired["lineage_id"]:
                return _hold_locked(
                    guard,
                    reason="retirement lineage does not match the guard",
                    detail="The data and independent retirement authority differ.",
                )
            if current["revision"] > desired["revision"]:
                return _hold_locked(
                    guard,
                    reason="restored data predates the retirement high-water receipt",
                    detail="Projection reads and workers require reconciliation.",
                )
            if (
                current["revision"] == desired["revision"]
                and current["event_digest"] != desired["event_digest"]
            ):
                return _hold_locked(
                    guard,
                    reason="retirement history diverged at the same revision",
                    detail="Projection reads and workers require reconciliation.",
                )
            _validate_mirrored_events(
                guard, events, min(current["revision"], desired["revision"]),
            )
            current = _advance_locked(
                guard, provisioning, current, desired, events,
            )
            return RetirementGuardStatus(
                "ready", "retirement guard matches the database",
                str(current["lineage_id"]), int(current["revision"]),
                str(current["event_digest"]),
            )
    except (RetirementGuardError, OSError, sqlite3.Error) as exc:
        try:
            if authority_validated:
                _secure_directory(guard)
                with _guard_lock(guard):
                    return _hold_locked(
                        guard, reason="retirement guard validation failed", detail=str(exc),
                    )
        except Exception:
            pass
        return RetirementGuardStatus(
            "hold", f"retirement guard unavailable: {exc}", None, None, None,
        )

