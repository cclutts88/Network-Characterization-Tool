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
RECONCILIATION_DIR = "restore-reconciliations"
VIRGIN_RESTORE_FILE = "virgin-restore-binding.json"
INITIAL_BIND_FILE = "initial-binding.json"
INITIAL_BIND_COMPLETE_FILE = "initial-binding-complete.json"


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


def _initial_binding_expectation(provisioning: dict, desired: dict) -> dict:
    return {
        "contract": GUARD_CONTRACT,
        "state": "initial-binding",
        "installation_id": provisioning["installation_id"],
        "data_identity": provisioning["data_identity"],
        **desired,
    }


def _read_initial_binding_intent(
    guard_dir: Path, provisioning: dict,
) -> dict | None:
    path = guard_dir / INITIAL_BIND_FILE
    if not path.exists():
        return None
    value = _read_receipt(path)
    expected = {
        "contract": GUARD_CONTRACT,
        "state": "initial-binding",
        "installation_id": provisioning["installation_id"],
        "data_identity": provisioning["data_identity"],
    }
    if any(value.get(key) != item for key, item in expected.items()):
        raise RetirementGuardError("initial retirement binding intent changed")
    if (
        not isinstance(value.get("lineage_id"), str)
        or value.get("revision") != 0
        or value.get("event_digest") != "root"
    ):
        raise RetirementGuardError("initial retirement binding intent is invalid")
    return value


def _read_initial_binding_completion(
    guard_dir: Path, provisioning: dict,
) -> dict | None:
    path = guard_dir / INITIAL_BIND_COMPLETE_FILE
    if not path.exists():
        return None
    value = _read_receipt(path)
    expected = {
        "contract": GUARD_CONTRACT,
        "state": "initial-binding-complete",
        "installation_id": provisioning["installation_id"],
        "data_identity": provisioning["data_identity"],
    }
    if any(value.get(key) != item for key, item in expected.items()):
        raise RetirementGuardError("initial retirement completion receipt changed")
    if (
        not isinstance(value.get("lineage_id"), str)
        or value.get("revision") != 0
        or value.get("event_digest") != "root"
    ):
        raise RetirementGuardError("initial retirement completion receipt is invalid")
    return value


def _read_virgin_restore_intent(
    guard_dir: Path, provisioning: dict,
) -> dict | None:
    path = guard_dir / VIRGIN_RESTORE_FILE
    if not path.exists():
        return None
    value = _read_receipt(path)
    expected = {
        "contract": GUARD_CONTRACT,
        "state": "virgin-restore-binding",
        "installation_id": provisioning["installation_id"],
        "data_identity": provisioning["data_identity"],
    }
    if any(value.get(key) != item for key, item in expected.items()):
        raise RetirementGuardError("virgin restore binding intent changed")
    if (
        not isinstance(value.get("operation_id"), str)
        or not value["operation_id"]
        or not isinstance(value.get("lineage_id"), str)
        or value.get("revision") != 0
        or value.get("event_digest") != "root"
    ):
        raise RetirementGuardError("virgin restore binding intent is invalid")
    return value


def _complete_initial_binding(
    guard_dir: Path,
    provisioning: dict,
    desired: dict,
    *,
    binding: dict | None,
    high_water: dict | None,
) -> tuple[dict, dict]:
    """Publish the initial root through a durable, restart-safe intent."""
    if desired["revision"] != 0 or desired["event_digest"] != "root":
        raise RetirementGuardError(
            "initial retirement binding requires an empty lineage"
        )
    if _mirrored_event_paths(guard_dir):
        raise RetirementGuardError(
            "initial retirement binding cannot replace protected events"
        )
    intent = _read_initial_binding_intent(guard_dir, provisioning)
    completion = _read_initial_binding_completion(guard_dir, provisioning)
    expected = _initial_binding_expectation(provisioning, desired)
    if intent is None:
        if binding is not None or high_water is not None:
            raise RetirementGuardError(
                "partial retirement binding has no initial intent"
            )
        _atomic_receipt(
            guard_dir / INITIAL_BIND_FILE,
            {**expected, "recorded_at": _now()},
        )
    elif any(intent.get(key) != value for key, value in expected.items()):
        raise RetirementGuardError(
            "initial retirement binding intent does not match the database"
        )
    if completion is not None:
        completed_expected = {
            **expected,
            "state": "initial-binding-complete",
        }
        if any(
            completion.get(key) != value
            for key, value in completed_expected.items()
        ):
            raise RetirementGuardError(
                "initial retirement completion does not match the database"
            )
        if binding is None or high_water is None:
            raise RetirementGuardError(
                "completed retirement authority is now incomplete"
            )
    if binding is None:
        if high_water is not None:
            raise RetirementGuardError(
                "retirement high-water exists without its initial binding"
            )
        _atomic_receipt(
            guard_dir / BINDING_FILE,
            _binding_body(provisioning, desired["lineage_id"]),
        )
    elif binding.get("lineage_id") != desired["lineage_id"]:
        raise RetirementGuardError("initial retirement binding lineage changed")
    if high_water is None:
        _atomic_receipt(
            guard_dir / HIGH_WATER_FILE,
            _high_water_body(provisioning, desired),
        )
    elif any(high_water.get(key) != value for key, value in desired.items()):
        raise RetirementGuardError("initial retirement high-water changed")
    binding = _read_binding(guard_dir, provisioning)
    high_water = _read_high_water(guard_dir, provisioning)
    if binding is None or high_water is None:
        raise RetirementGuardError("initial retirement binding did not complete")
    if completion is None:
        _atomic_receipt(
            guard_dir / INITIAL_BIND_COMPLETE_FILE,
            {
                **expected,
                "state": "initial-binding-complete",
                "recorded_at": _now(),
            },
        )
    return binding, high_water


def _recover_virgin_restore_binding(
    guard_dir: Path,
    provisioning: dict,
    *,
    db_path: Path,
    operation_id: str,
    binding: dict | None,
    high_water: dict | None,
) -> tuple[dict, dict]:
    """Finish the one safe unbound first-upgrade restore, idempotently.

    The host can provision authority before its verified cold backup while the
    source database is still v8. If the first candidate starts but fails before
    startup binds that authority, restore migration produces a new, empty v9
    lineage under the exact operation hold. This receipt makes the two-file
    binding write restart-safe without allowing an existing protected lineage to
    be reset.
    """
    intent_path = guard_dir / VIRGIN_RESTORE_FILE
    if _mirrored_event_paths(guard_dir):
        raise RetirementGuardError(
            "a virgin restore cannot replace protected retirement events"
        )
    with connect_database(db_path, read_only=True) as db:
        lineage_id, events = _event_receipts(db)
        schema = db.execute(
            "SELECT schema_version FROM nct_schema_state WHERE singleton=1"
        ).fetchone()
        migration = db.execute(
            """SELECT status FROM nct_schema_migrations
                 WHERE migration_id='nct-evidence-retirement-v9'"""
        ).fetchone()
        identity_count = int(db.execute(
            "SELECT COUNT(*) FROM evidence_retirement_identities"
        ).fetchone()[0])
        lineage_count = int(db.execute(
            "SELECT COUNT(*) FROM evidence_retirement_lineage"
        ).fetchone()[0])
        trigger = db.execute(
            "SELECT sql FROM sqlite_master WHERE type='trigger' "
            "AND name='evidence_retirement_lineage_no_update'"
        ).fetchone()
    if (
        events
        or schema is None or int(schema[0]) != 9
        or migration is None or migration[0] != "completed"
        or identity_count != 0 or lineage_count != 1
        or trigger is None or not str(trigger[0]).strip()
    ):
        raise RetirementGuardError(
            "unbound retirement authority requires an exact empty v9 restore"
        )
    desired = _head(lineage_id, events)
    expected = {
        "contract": GUARD_CONTRACT,
        "state": "virgin-restore-binding",
        "operation_id": operation_id,
        "installation_id": provisioning["installation_id"],
        "data_identity": provisioning["data_identity"],
        **desired,
    }
    initial_intent = _read_initial_binding_intent(guard_dir, provisioning)
    initial_completion = _read_initial_binding_completion(
        guard_dir, provisioning,
    )
    intent = _read_virgin_restore_intent(guard_dir, provisioning)
    restore_intent_exists = intent is not None
    if intent is not None:
        if any(intent.get(key) != value for key, value in expected.items()):
            raise RetirementGuardError(
                "virgin restore binding belongs to another operation"
            )
    else:
        if high_water is not None or initial_completion is not None:
            raise RetirementGuardError(
                "completed retirement authority cannot use virgin recovery"
            )
        if binding is not None and (
            initial_intent is None
            or binding.get("lineage_id") != initial_intent.get("lineage_id")
        ):
            raise RetirementGuardError(
                "partial retirement binding has no matching initial intent"
            )
        intent = {**expected, "recorded_at": _now()}
        _atomic_receipt(intent_path, intent)
        restore_intent_exists = True

    if binding is None:
        _atomic_receipt(
            guard_dir / BINDING_FILE,
            _binding_body(provisioning, lineage_id),
        )
    elif binding.get("lineage_id") != lineage_id:
        if (
            not restore_intent_exists
            or initial_intent is None
            or initial_completion is not None
            or high_water is not None
            or binding.get("lineage_id") != initial_intent.get("lineage_id")
        ):
            raise RetirementGuardError("virgin restore binding lineage changed")
        # The one-time initial root was never completed: its durable intent and
        # missing high-water prove the binding-only receipt is an interrupted
        # publication, not protected authority. The exact restore operation may
        # now replace it with the verified empty restored lineage.
        _atomic_receipt(
            guard_dir / BINDING_FILE,
            _binding_body(provisioning, lineage_id),
        )
    if high_water is None:
        _atomic_receipt(
            guard_dir / HIGH_WATER_FILE,
            _high_water_body(provisioning, desired),
        )
    elif any(high_water.get(key) != value for key, value in desired.items()):
        raise RetirementGuardError("virgin restore high-water changed")
    binding = _read_binding(guard_dir, provisioning)
    high_water = _read_high_water(guard_dir, provisioning)
    if binding is None or high_water is None:
        raise RetirementGuardError("virgin restore binding did not complete")
    if not any((guard_dir / "audit").glob("*-virgin-restore-bound-*.json")):
        _atomic_receipt(
            _audit_path(guard_dir, "virgin-restore-bound"),
            {**expected, "recorded_at": _now()},
        )
    return binding, high_water


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


def _restore_reconciliation_path(guard_dir: Path, operation_id: str) -> Path:
    operation_digest = hashlib.sha256(operation_id.encode("utf-8")).hexdigest()
    return guard_dir / RECONCILIATION_DIR / f"{operation_digest}.json"


def _validate_restore_reconciliation(
    receipt: dict,
    *,
    operation_id: str,
    data_identity: str,
    high_water: dict,
) -> None:
    expected = {
        "contract": GUARD_CONTRACT,
        "state": "restore-reconciled",
        "operation_id": operation_id,
        "data_identity": data_identity,
        "lineage_id": high_water["lineage_id"],
        "revision": high_water["revision"],
        "event_digest": high_water["event_digest"],
    }
    if any(receipt.get(key) != value for key, value in expected.items()):
        raise RetirementGuardError(
            "retirement restore reconciliation receipt does not match this operation"
        )


def _hold_locked(
    guard_dir: Path, *, reason: str, detail: str, operation_id: str | None = None,
) -> RetirementGuardStatus:
    body = {
        "contract": GUARD_CONTRACT,
        "state": "hold",
        "reason": reason,
        "detail": detail[:1000],
        "operation_id": operation_id,
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
            operation_id=operation_id,
        )


def reconcile_retirement_restore(
    db_path: Path,
    *,
    data_dir: Path,
    guard_dir: Path,
    data_identity: str,
    operation_id: str,
) -> RetirementGuardStatus:
    """Reapply protected tail receipts to a restored database, then release its hold.

    Only the exact host-recorded restore operation may use this path. The restored
    database must be the same lineage and a verified prefix of the independent
    mirrored chain. No source bytes are copied or deleted.
    """
    guard = guard_dir.absolute()
    operation_id = str(operation_id or "").strip()
    if not operation_id:
        raise RetirementGuardError("restore operation identity is required")
    _separate_paths(data_dir, guard)
    _secure_directory(guard)
    with _guard_lock(guard):
        provisioning = _provisioning(guard, data_identity)
        _secure_directory(guard / "events")
        _secure_directory(guard / "audit")
        (guard / RECONCILIATION_DIR).mkdir(mode=0o700, exist_ok=True)
        _secure_directory(guard / RECONCILIATION_DIR)
        hold_path = guard / HOLD_FILE
        reconciliation_path = _restore_reconciliation_path(guard, operation_id)
        reconciliation = (
            _read_receipt(reconciliation_path)
            if reconciliation_path.exists() else None
        )
        if hold_path.exists():
            hold = _read_receipt(hold_path)
            if (
                hold.get("reason") != "restore requires retirement reconciliation"
                or hold.get("operation_id") != operation_id
            ):
                raise RetirementGuardError(
                    "retirement restore hold belongs to another operation"
                )
        elif reconciliation is None:
            raise RetirementGuardError("retirement restore hold is missing")
        binding = _read_binding(guard, provisioning)
        high_water = _read_high_water(guard, provisioning)
        if binding is None or high_water is None:
            if reconciliation is not None or not hold_path.exists():
                raise RetirementGuardError(
                    "retirement guard binding is incomplete"
                )
            binding, high_water = _recover_virgin_restore_binding(
                guard,
                provisioning,
                db_path=db_path,
                operation_id=operation_id,
                binding=binding,
                high_water=high_water,
            )
        if reconciliation is not None:
            _validate_restore_reconciliation(
                reconciliation,
                operation_id=operation_id,
                data_identity=data_identity,
                high_water=high_water,
            )
        mirrored_paths = _mirrored_event_paths(guard)
        mirrored = [_read_receipt(path) for path in mirrored_paths]
        mirrored.sort(key=lambda item: int(item.get("revision", -1)))
        with connect_database(db_path) as db:
            lineage_id, current = _event_receipts(db)
            # A verified pre-v9 backup has no retirement lineage. The candidate's
            # exact v9 migration creates an empty lineage before this function is
            # called, but that new random identity cannot replace the independently
            # protected lineage. Adopt the protected identity only while the new
            # ledger is provably empty and the exact completed v9 migration exists.
            if lineage_id != binding["lineage_id"] and not current:
                schema = db.execute(
                    "SELECT schema_version FROM nct_schema_state WHERE singleton=1"
                ).fetchone()
                migration = db.execute(
                    """SELECT status FROM nct_schema_migrations
                        WHERE migration_id='nct-evidence-retirement-v9'"""
                ).fetchone()
                identity_count = int(db.execute(
                    "SELECT COUNT(*) FROM evidence_retirement_identities"
                ).fetchone()[0])
                lineage_count = int(db.execute(
                    "SELECT COUNT(*) FROM evidence_retirement_lineage"
                ).fetchone()[0])
                trigger = db.execute(
                    "SELECT sql FROM sqlite_master WHERE type='trigger' "
                    "AND name='evidence_retirement_lineage_no_update'"
                ).fetchone()
                if (
                    schema is None or int(schema[0]) != 9
                    or migration is None or migration[0] != "completed"
                    or identity_count != 0 or lineage_count != 1
                    or trigger is None or not str(trigger[0]).strip()
                ):
                    raise RetirementGuardError(
                        "restored retirement lineage does not match the guard"
                    )
                db.execute("BEGIN IMMEDIATE")
                db.execute("DROP TRIGGER evidence_retirement_lineage_no_update")
                db.execute(
                    "UPDATE evidence_retirement_lineage SET lineage_id=? "
                    "WHERE singleton=1 AND lineage_id=?",
                    (binding["lineage_id"], lineage_id),
                )
                db.execute(str(trigger[0]))
                db.commit()
                lineage_id, current = _event_receipts(db)
            if lineage_id != binding["lineage_id"] or lineage_id != high_water["lineage_id"]:
                raise RetirementGuardError("restored retirement lineage does not match the guard")
            current_head = _head(lineage_id, current)
            if current_head["revision"] > high_water["revision"]:
                raise RetirementGuardError("restored retirement state is ahead of protected state")
            for event in current:
                if not any(
                    int(item.get("revision", -1)) == int(event["revision"])
                    and item.get("event_digest") == event["event_digest"]
                    for item in mirrored
                ) and int(event["revision"]) <= int(high_water["revision"]):
                    raise RetirementGuardError("restored retirement chain diverges from protected state")
            missing = [
                item for item in mirrored
                if int(current_head["revision"]) < int(item.get("revision", -1))
                <= int(high_water["revision"])
            ]
            if missing:
                db.execute("BEGIN IMMEDIATE")
                previous = current_head["event_digest"]
                expected_revision = int(current_head["revision"]) + 1
                for item in missing:
                    revision = int(item["revision"])
                    snapshot = item.get("identity_snapshot")
                    identities = snapshot.get("identities") if isinstance(snapshot, dict) else None
                    if (
                        revision != expected_revision
                        or item.get("previous_event_digest") != previous
                        or not isinstance(identities, dict)
                    ):
                        raise RetirementGuardError("protected retirement tail is not contiguous")
                    snapshot_json = _canonical(snapshot)
                    db.execute(
                        """INSERT INTO evidence_retirement_events(
                               revision,event_id,lineage_id,source_family,encounter_id,
                               identity_snapshot_json,identity_snapshot_sha256,
                               previous_event_digest,event_digest,identity_count,sealed,
                               actor,reason,retired_at
                           ) VALUES (?,?,?,?,?,?,?,?,?,?,0,?,?,?)""",
                        (
                            revision, item["event_id"], item["lineage_id"],
                            item["source_family"], item["encounter_id"], snapshot_json,
                            item["identity_snapshot_sha256"], item["previous_event_digest"],
                            item["event_digest"], int(item["identity_count"]),
                            item["actor"], item["reason"], item["retired_at"],
                        ),
                    )
                    db.executemany(
                        """INSERT INTO evidence_retirement_identities(
                               revision,source_family,encounter_id,
                               identity_namespace,identity_value
                           ) VALUES (?,?,?,?,?)""",
                        [
                            (
                                revision, item["source_family"], item["encounter_id"],
                                namespace, value,
                            )
                            for namespace, value in sorted(identities.items())
                        ],
                    )
                    db.execute(
                        "UPDATE evidence_retirement_events SET sealed=1 WHERE revision=?",
                        (revision,),
                    )
                    previous = item["event_digest"]
                    expected_revision += 1
                db.commit()
            lineage_id, restored = _event_receipts(db)
            if _head(lineage_id, restored) != {
                "lineage_id": high_water["lineage_id"],
                "revision": high_water["revision"],
                "event_digest": high_water["event_digest"],
            }:
                raise RetirementGuardError("restored retirement state did not reconcile")
        audit = {
            "contract": GUARD_CONTRACT,
            "state": "restore-reconciled",
            "operation_id": operation_id,
            "data_identity": data_identity,
            "lineage_id": high_water["lineage_id"],
            "revision": high_water["revision"],
            "event_digest": high_water["event_digest"],
            "recorded_at": _now(),
        }
        if reconciliation is None:
            # This operation-bound receipt is the durable restart fence. It must
            # exist before the hold can be removed so a crash in that window is
            # an idempotent retry, never an unguarded or unrecoverable restore.
            _atomic_receipt(reconciliation_path, audit)
            _atomic_receipt(_audit_path(guard, "restore-reconciled"), audit)
        if hold_path.exists():
            hold_path.unlink()
        directory = os.open(guard, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    return check_retirement_guard(
        db_path,
        data_dir=data_dir,
        guard_dir=guard,
        data_identity=data_identity,
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
            initial_intent = _read_initial_binding_intent(guard, provisioning)
            initial_completion = _read_initial_binding_completion(
                guard, provisioning,
            )
            virgin_restore = _read_virgin_restore_intent(guard, provisioning)
            initial_superseded = (
                initial_intent is not None
                and initial_completion is None
                and virgin_restore is not None
                and virgin_restore.get("lineage_id") == desired["lineage_id"]
            )
            if initial_completion is not None and binding is None:
                return _hold_locked(
                    guard,
                    reason="retirement lineage binding is missing",
                    detail="The completed one-time binding receipt is no longer present.",
                )
            if initial_completion is not None and current is None:
                return _hold_locked(
                    guard,
                    reason="retirement high-water receipt is missing",
                    detail="The completed one-time high-water receipt is no longer present.",
                )
            if (
                binding is None
                or current is None
                or initial_intent is not None
                and initial_completion is None
                and not initial_superseded
            ):
                if (
                    desired["revision"] != 0
                    or _mirrored_event_paths(guard)
                ):
                    reason = (
                        "retirement initial binding is incomplete"
                        if binding is not None or initial_intent is not None
                        else "retirement initial binding is missing"
                    )
                    return _hold_locked(
                        guard,
                        reason=reason,
                        detail="Protected retirement state exists before the root binding completed.",
                    )
                try:
                    binding, current = _complete_initial_binding(
                        guard,
                        provisioning,
                        desired,
                        binding=binding,
                        high_water=current,
                    )
                except RetirementGuardError as exc:
                    return _hold_locked(
                        guard,
                        reason="retirement initial binding is incomplete",
                        detail=str(exc),
                    )
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


def check_retirement_guard_head(
    db_path: Path, *, data_dir: Path, guard_dir: Path, data_identity: str,
) -> RetirementGuardStatus:
    """Verify the live database head against protected state without advancing it.

    Startup and the retirement write path perform the full event-chain and mirror
    validation. Ordinary API requests use this bounded O(1) check so an out-of-band
    restore or protected-state failure is noticed immediately without rescanning the
    complete immutable history for every page request.
    """
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
                lineage = db.execute(
                    "SELECT lineage_id FROM evidence_retirement_lineage WHERE singleton=1"
                ).fetchone()
                if lineage is None:
                    raise RetirementGuardError("retirement lineage is missing")
                latest = db.execute(
                    """SELECT revision,event_digest FROM evidence_retirement_events
                         WHERE sealed=1 ORDER BY revision DESC LIMIT 1"""
                ).fetchone()
            desired = {
                "lineage_id": str(lineage[0]),
                "revision": int(latest[0]) if latest else 0,
                "event_digest": str(latest[1]) if latest else "root",
            }
            binding = _read_binding(guard, provisioning)
            current = _read_high_water(guard, provisioning)
            if binding is None or current is None:
                return _hold_locked(
                    guard,
                    reason="protected retirement authority is incomplete",
                    detail="The lineage binding or high-water receipt is missing.",
                )
            if binding["lineage_id"] != desired["lineage_id"]:
                return _hold_locked(
                    guard,
                    reason="retirement lineage does not match the guard",
                    detail="The live data and one-time lineage binding differ.",
                )
            if (
                current["lineage_id"] != desired["lineage_id"]
                or int(current["revision"]) != desired["revision"]
                or current["event_digest"] != desired["event_digest"]
            ):
                return _hold_locked(
                    guard,
                    reason="live retirement head does not match protected state",
                    detail=(
                        "The running database and independent high-water receipt differ; "
                        "projection reads require host reconciliation."
                    ),
                )
            if desired["revision"] > 0:
                head_paths = list(
                    (guard / "events").glob(f"{desired['revision']:020d}-*.json")
                )
                if len(head_paths) != 1:
                    return _hold_locked(
                        guard,
                        reason="protected retirement event head is incomplete",
                        detail="The mirrored head receipt is missing or ambiguous.",
                    )
                event = _read_receipt(head_paths[0])
                if (
                    event.get("lineage_id") != desired["lineage_id"]
                    or int(event.get("revision") or -1) != desired["revision"]
                    or event.get("event_digest") != desired["event_digest"]
                ):
                    return _hold_locked(
                        guard,
                        reason="protected retirement event head is inconsistent",
                        detail="The mirrored head receipt does not match the high-water receipt.",
                    )
            return RetirementGuardStatus(
                "ready", "retirement guard head matches the live database",
                desired["lineage_id"], desired["revision"], desired["event_digest"],
            )
    except (RetirementGuardError, OSError, sqlite3.Error, ValueError) as exc:
        try:
            if authority_validated:
                _secure_directory(guard)
                with _guard_lock(guard):
                    return _hold_locked(
                        guard,
                        reason="retirement guard head validation failed",
                        detail=str(exc),
                    )
        except Exception:
            pass
        return RetirementGuardStatus(
            "hold", f"retirement guard unavailable: {exc}", None, None, None,
        )

