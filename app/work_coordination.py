from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import sqlite3
import uuid

from app.database import connect_database, initialize_once_per_database


DEFAULT_LEASE_SECONDS = 30
MIN_LEASE_SECONDS = 5
MAX_LEASE_SECONDS = 300


class WorkLeaseConflict(RuntimeError):
    pass


class WorkLeaseLost(WorkLeaseConflict):
    pass


class WorkRecoveryRequired(WorkLeaseConflict):
    pass


@dataclass(frozen=True)
class WorkLease:
    lease_key: str
    work_kind: str
    work_id: str
    lease_id: str
    owner_id: str
    fencing_epoch: int
    acquired_at: str
    renewed_at: str
    expires_at: str

    def as_claim(self) -> dict[str, object]:
        return {
            "lease_key": self.lease_key,
            "lease_id": self.lease_id,
            "lease_owner": self.owner_id,
            "lease_epoch": self.fencing_epoch,
            "lease_expires_at": self.expires_at,
        }


def _bounded(value: object, label: str, *, maximum: int = 240) -> str:
    text = str(value or "").strip()
    if not text or len(text) > maximum or "\x00" in text:
        raise ValueError(f"{label} is invalid")
    return text


def _lease_seconds(value: int | float) -> int:
    seconds = int(value)
    if seconds < MIN_LEASE_SECONDS or seconds > MAX_LEASE_SECONDS:
        raise ValueError(
            f"Lease duration must be between {MIN_LEASE_SECONDS} and "
            f"{MAX_LEASE_SECONDS} seconds"
        )
    return seconds


def _db_time(connection: sqlite3.Connection, seconds: int) -> tuple[str, str]:
    modifier = f"+{_lease_seconds(seconds)} seconds"
    row = connection.execute(
        """SELECT strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
                  strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)""",
        (modifier,),
    ).fetchone()
    if row is None or not row[0] or not row[1]:
        raise WorkLeaseConflict("The database clock is unavailable")
    return str(row[0]), str(row[1])


def _event(
    connection: sqlite3.Connection,
    *,
    lease_key: str,
    fencing_epoch: int,
    lease_id: str | None,
    owner_id: str | None,
    event_kind: str,
    recorded_at: str,
    detail: str | None = None,
) -> None:
    connection.execute(
        """INSERT INTO work_lease_events(
               event_id, lease_key, fencing_epoch, lease_id, owner_id,
               event_kind, recorded_at, detail
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            uuid.uuid4().hex,
            lease_key,
            int(fencing_epoch),
            lease_id,
            owner_id,
            event_kind,
            recorded_at,
            (detail or "")[:500] or None,
        ),
    )


@initialize_once_per_database
def init_work_coordination_storage(db_path: Path) -> None:
    with connect_database(db_path) as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS work_leases (
                lease_key TEXT PRIMARY KEY,
                work_kind TEXT NOT NULL,
                work_id TEXT NOT NULL,
                fencing_epoch INTEGER NOT NULL CHECK(fencing_epoch >= 1),
                lease_id TEXT,
                owner_id TEXT,
                state TEXT NOT NULL CHECK(state IN (
                    'active', 'released', 'recovery_required'
                )),
                acquired_at TEXT,
                renewed_at TEXT,
                expires_at TEXT,
                released_at TEXT,
                recovery_reason TEXT,
                CHECK(
                    (state = 'active' AND lease_id IS NOT NULL
                        AND owner_id IS NOT NULL AND acquired_at IS NOT NULL
                        AND renewed_at IS NOT NULL AND expires_at IS NOT NULL
                        AND released_at IS NULL AND recovery_reason IS NULL)
                    OR
                    (state = 'released' AND lease_id IS NULL AND owner_id IS NULL
                        AND expires_at IS NULL AND released_at IS NOT NULL
                        AND recovery_reason IS NULL)
                    OR
                    (state = 'recovery_required' AND lease_id IS NULL
                        AND owner_id IS NULL AND expires_at IS NULL
                        AND recovery_reason IS NOT NULL)
                )
            );
            CREATE TABLE IF NOT EXISTS work_lease_events (
                event_id TEXT PRIMARY KEY,
                lease_key TEXT NOT NULL,
                fencing_epoch INTEGER NOT NULL CHECK(fencing_epoch >= 1),
                lease_id TEXT,
                owner_id TEXT,
                event_kind TEXT NOT NULL CHECK(event_kind IN (
                    'acquired', 'renewed', 'released', 'expired',
                    'recovery_required', 'recovery_cleared'
                )),
                recorded_at TEXT NOT NULL,
                detail TEXT
            );
            CREATE INDEX IF NOT EXISTS work_lease_event_history
                ON work_lease_events(lease_key, fencing_epoch, recorded_at, event_id);
            """
        )


def acquire_work_lease_on_connection(
    connection: sqlite3.Connection,
    *,
    lease_key: str,
    work_kind: str,
    work_id: str,
    owner_id: str,
    lease_seconds: int = DEFAULT_LEASE_SECONDS,
    expired_policy: str = "reclaim",
) -> WorkLease:
    key = _bounded(lease_key, "Lease key")
    kind = _bounded(work_kind, "Work kind", maximum=80)
    identity = _bounded(work_id, "Work identity")
    owner = _bounded(owner_id, "Lease owner")
    if expired_policy not in {"reclaim", "recovery_required"}:
        raise ValueError("Unknown expired-lease policy")
    now, expires = _db_time(connection, lease_seconds)
    current = connection.execute(
        """SELECT work_kind, work_id, fencing_epoch, lease_id, owner_id,
                  state, expires_at
             FROM work_leases WHERE lease_key = ?""",
        (key,),
    ).fetchone()
    if current is None:
        epoch = 1
    else:
        current_kind, current_id, current_epoch, current_lease, current_owner, state, current_expiry = current
        if state == "recovery_required":
            raise WorkRecoveryRequired(
                "This work is stopped for safety and requires administrator recovery"
            )
        if state == "active" and current_expiry and current_expiry > now:
            raise WorkLeaseConflict("Another NCT worker is still responsible for this work")
        if state == "active":
            _event(
                connection,
                lease_key=key,
                fencing_epoch=int(current_epoch),
                lease_id=current_lease,
                owner_id=current_owner,
                event_kind="expired",
                recorded_at=now,
                detail="The saved lease expired before a replacement attempted ownership.",
            )
            if expired_policy == "recovery_required":
                reason = "The previous owner expired; automatic takeover is prohibited."
                connection.execute(
                    """UPDATE work_leases
                          SET lease_id = NULL, owner_id = NULL,
                              state = 'recovery_required', expires_at = NULL,
                              released_at = ?, recovery_reason = ?
                        WHERE lease_key = ? AND fencing_epoch = ?
                          AND state = 'active' AND expires_at <= ?""",
                    (now, reason, key, int(current_epoch), now),
                )
                _event(
                    connection,
                    lease_key=key,
                    fencing_epoch=int(current_epoch),
                    lease_id=None,
                    owner_id=None,
                    event_kind="recovery_required",
                    recorded_at=now,
                    detail=reason,
                )
                raise WorkRecoveryRequired(
                    "The former owner may still exist; administrator recovery is required"
                )
        epoch = int(current_epoch) + 1
    lease_id = uuid.uuid4().hex
    connection.execute(
        """INSERT INTO work_leases(
               lease_key, work_kind, work_id, fencing_epoch, lease_id, owner_id,
               state, acquired_at, renewed_at, expires_at, released_at,
               recovery_reason
           ) VALUES (?, ?, ?, ?, ?, ?, 'active', ?, ?, ?, NULL, NULL)
           ON CONFLICT(lease_key) DO UPDATE SET
               work_kind = excluded.work_kind,
               work_id = excluded.work_id,
               fencing_epoch = excluded.fencing_epoch,
               lease_id = excluded.lease_id,
               owner_id = excluded.owner_id,
               state = 'active',
               acquired_at = excluded.acquired_at,
               renewed_at = excluded.renewed_at,
               expires_at = excluded.expires_at,
               released_at = NULL,
               recovery_reason = NULL""",
        (key, kind, identity, epoch, lease_id, owner, now, now, expires),
    )
    _event(
        connection,
        lease_key=key,
        fencing_epoch=epoch,
        lease_id=lease_id,
        owner_id=owner,
        event_kind="acquired",
        recorded_at=now,
    )
    return WorkLease(key, kind, identity, lease_id, owner, epoch, now, now, expires)


def acquire_work_lease(
    db_path: Path,
    **kwargs,
) -> WorkLease:
    init_work_coordination_storage(db_path)
    connection = connect_database(db_path)
    try:
        connection.execute("BEGIN IMMEDIATE")
        lease = acquire_work_lease_on_connection(connection, **kwargs)
        connection.commit()
        return lease
    except WorkRecoveryRequired:
        # The recovery-required transition is itself the safety result. Keep it even
        # though acquisition is refused.
        connection.commit()
        raise
    except BaseException:
        connection.rollback()
        raise
    finally:
        connection.close()


def assert_work_lease_on_connection(
    connection: sqlite3.Connection,
    lease: WorkLease | dict[str, object],
) -> None:
    key = str(lease.lease_key if isinstance(lease, WorkLease) else lease["lease_key"])
    lease_id = str(lease.lease_id if isinstance(lease, WorkLease) else lease["lease_id"])
    owner = str(lease.owner_id if isinstance(lease, WorkLease) else lease["lease_owner"])
    epoch = int(lease.fencing_epoch if isinstance(lease, WorkLease) else lease["lease_epoch"])
    row = connection.execute(
        """SELECT 1 FROM work_leases
            WHERE lease_key = ? AND lease_id = ? AND owner_id = ?
              AND fencing_epoch = ? AND state = 'active'
              AND expires_at > strftime('%Y-%m-%dT%H:%M:%fZ', 'now')""",
        (key, lease_id, owner, epoch),
    ).fetchone()
    if row is None:
        raise WorkLeaseLost("This NCT worker no longer owns the saved work")


def renew_work_lease(
    db_path: Path,
    lease: WorkLease | dict[str, object],
    *,
    lease_seconds: int = DEFAULT_LEASE_SECONDS,
) -> WorkLease:
    init_work_coordination_storage(db_path)
    with connect_database(db_path) as connection:
        connection.execute("BEGIN IMMEDIATE")
        return renew_work_lease_on_connection(
            connection, lease, lease_seconds=lease_seconds
        )


def renew_work_lease_on_connection(
    connection: sqlite3.Connection,
    lease: WorkLease | dict[str, object],
    *,
    lease_seconds: int = DEFAULT_LEASE_SECONDS,
) -> WorkLease:
    key = str(lease.lease_key if isinstance(lease, WorkLease) else lease["lease_key"])
    lease_id = str(lease.lease_id if isinstance(lease, WorkLease) else lease["lease_id"])
    owner = str(lease.owner_id if isinstance(lease, WorkLease) else lease["lease_owner"])
    epoch = int(lease.fencing_epoch if isinstance(lease, WorkLease) else lease["lease_epoch"])
    now, expires = _db_time(connection, lease_seconds)
    changed = connection.execute(
        """UPDATE work_leases
              SET renewed_at = ?, expires_at = ?
            WHERE lease_key = ? AND lease_id = ? AND owner_id = ?
              AND fencing_epoch = ? AND state = 'active' AND expires_at > ?""",
        (now, expires, key, lease_id, owner, epoch, now),
    ).rowcount
    if changed != 1:
        raise WorkLeaseLost("This NCT worker can no longer renew the saved work")
    row = connection.execute(
        """SELECT work_kind, work_id, acquired_at
             FROM work_leases WHERE lease_key = ?""",
        (key,),
    ).fetchone()
    _event(
        connection,
        lease_key=key,
        fencing_epoch=epoch,
        lease_id=lease_id,
        owner_id=owner,
        event_kind="renewed",
        recorded_at=now,
    )
    return WorkLease(key, row[0], row[1], lease_id, owner, epoch, row[2], now, expires)


def release_work_lease_on_connection(
    connection: sqlite3.Connection,
    lease: WorkLease | dict[str, object],
    *,
    detail: str | None = None,
) -> str:
    assert_work_lease_on_connection(connection, lease)
    key = str(lease.lease_key if isinstance(lease, WorkLease) else lease["lease_key"])
    lease_id = str(lease.lease_id if isinstance(lease, WorkLease) else lease["lease_id"])
    owner = str(lease.owner_id if isinstance(lease, WorkLease) else lease["lease_owner"])
    epoch = int(lease.fencing_epoch if isinstance(lease, WorkLease) else lease["lease_epoch"])
    now, _ = _db_time(connection, DEFAULT_LEASE_SECONDS)
    changed = connection.execute(
        """UPDATE work_leases
              SET lease_id = NULL, owner_id = NULL, state = 'released',
                  renewed_at = ?, expires_at = NULL, released_at = ?,
                  recovery_reason = NULL
            WHERE lease_key = ? AND lease_id = ? AND owner_id = ?
              AND fencing_epoch = ? AND state = 'active'""",
        (now, now, key, lease_id, owner, epoch),
    ).rowcount
    if changed != 1:
        raise WorkLeaseLost("This NCT worker can no longer release the saved work")
    _event(
        connection,
        lease_key=key,
        fencing_epoch=epoch,
        lease_id=lease_id,
        owner_id=owner,
        event_kind="released",
        recorded_at=now,
        detail=detail,
    )
    return now


def release_work_lease(
    db_path: Path,
    lease: WorkLease | dict[str, object],
    *,
    detail: str | None = None,
) -> str:
    init_work_coordination_storage(db_path)
    with connect_database(db_path) as connection:
        connection.execute("BEGIN IMMEDIATE")
        return release_work_lease_on_connection(connection, lease, detail=detail)


def recover_abandoned_work_lease_on_connection(
    connection: sqlite3.Connection,
    lease: WorkLease | dict[str, object],
    *,
    recovery_required: bool,
    detail: str,
) -> str:
    """Close an exact former-process claim without treating expiry as ownership."""
    key = str(lease.lease_key if isinstance(lease, WorkLease) else lease["lease_key"])
    lease_id = str(lease.lease_id if isinstance(lease, WorkLease) else lease["lease_id"])
    owner = str(lease.owner_id if isinstance(lease, WorkLease) else lease["lease_owner"])
    epoch = int(lease.fencing_epoch if isinstance(lease, WorkLease) else lease["lease_epoch"])
    now, _ = _db_time(connection, DEFAULT_LEASE_SECONDS)
    state = "recovery_required" if recovery_required else "released"
    changed = connection.execute(
        """UPDATE work_leases
              SET lease_id = NULL, owner_id = NULL, state = ?,
                  renewed_at = ?, expires_at = NULL, released_at = ?,
                  recovery_reason = ?
            WHERE lease_key = ? AND lease_id = ? AND owner_id = ?
              AND fencing_epoch = ? AND state = 'active'""",
        (
            state, now, now, detail[:500] if recovery_required else None,
            key, lease_id, owner, epoch,
        ),
    ).rowcount
    if changed != 1:
        raise WorkLeaseLost("The former saved-work claim no longer matches")
    _event(
        connection,
        lease_key=key,
        fencing_epoch=epoch,
        lease_id=None if recovery_required else lease_id,
        owner_id=None if recovery_required else owner,
        event_kind="recovery_required" if recovery_required else "released",
        recorded_at=now,
        detail=detail,
    )
    return now


def clear_work_recovery(
    db_path: Path,
    lease_key: str,
    *,
    detail: str,
) -> bool:
    """Clear a safety stop only after the caller has independently verified recovery."""
    init_work_coordination_storage(db_path)
    key = _bounded(lease_key, "Lease key")
    explanation = _bounded(detail, "Recovery detail", maximum=500)
    with connect_database(db_path) as connection:
        connection.execute("BEGIN IMMEDIATE")
        row = connection.execute(
            "SELECT fencing_epoch, state FROM work_leases WHERE lease_key = ?",
            (key,),
        ).fetchone()
        if row is None or row[1] != "recovery_required":
            return False
        now, _ = _db_time(connection, DEFAULT_LEASE_SECONDS)
        changed = connection.execute(
            """UPDATE work_leases
                  SET state = 'released', released_at = ?, renewed_at = ?,
                      recovery_reason = NULL
                WHERE lease_key = ? AND fencing_epoch = ?
                  AND state = 'recovery_required'""",
            (now, now, key, int(row[0])),
        ).rowcount
        if changed != 1:
            raise WorkLeaseConflict("The safety-stop state changed during recovery")
        _event(
            connection,
            lease_key=key,
            fencing_epoch=int(row[0]),
            lease_id=None,
            owner_id=None,
            event_kind="recovery_cleared",
            recorded_at=now,
            detail=explanation,
        )
        return True


def work_lease_status(db_path: Path, lease_key: str) -> dict[str, object] | None:
    if not Path(db_path).is_file():
        return None
    with connect_database(db_path, read_only=True) as connection:
        if connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'work_leases'"
        ).fetchone() is None:
            return None
        row = connection.execute(
            """SELECT lease_key, work_kind, work_id, fencing_epoch, state,
                      acquired_at, renewed_at, expires_at, released_at,
                      recovery_reason,
                      CASE WHEN state = 'active'
                         AND expires_at > strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                           THEN 1 ELSE 0 END
                 FROM work_leases WHERE lease_key = ?""",
            (_bounded(lease_key, "Lease key"),),
        ).fetchone()
    if row is None:
        return None
    return {
        "lease_key": row[0],
        "work_kind": row[1],
        "work_id": row[2],
        "fencing_epoch": int(row[3]),
        "state": row[4],
        "acquired_at": row[5],
        "renewed_at": row[6],
        "expires_at": row[7],
        "released_at": row[8],
        "recovery_reason": row[9],
        "currently_owned": bool(row[10]),
    }
