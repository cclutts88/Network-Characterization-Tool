from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import sqlite3
from typing import Callable
import uuid

from app.database import connect_database, initialize_once_per_database
from app.work_coordination import (
    WorkLease,
    WorkLeaseConflict,
    assert_work_lease_on_connection,
    acquire_work_lease_on_connection,
    init_work_coordination_storage,
    recover_abandoned_work_lease_on_connection,
    release_work_lease_on_connection,
    renew_work_lease_on_connection,
)


DEVICE_CONTACT_CAPACITY_LEASE_KEY = "device-contact-capacity"


class DeviceContactConflict(RuntimeError):
    pass


@dataclass(frozen=True)
class DeviceContactClaim:
    run_id: str
    attempt_number: int
    owner_id: str
    run_lease: WorkLease
    capacity_lease: WorkLease


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _bounded(value: object, label: str, maximum: int = 240) -> str:
    text = str(value or "").strip()
    if not text or len(text) > maximum or "\x00" in text:
        raise ValueError(f"{label} is invalid")
    return text


def _db_now(connection: sqlite3.Connection) -> str:
    return str(connection.execute(
        "SELECT strftime('%Y-%m-%dT%H:%M:%fZ', 'now')"
    ).fetchone()[0])


@initialize_once_per_database
def init_device_contact_work_storage(db_path: Path) -> None:
    init_work_coordination_storage(db_path)
    with connect_database(db_path) as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS device_contact_runs (
                run_id TEXT PRIMARY KEY CHECK(length(run_id) = 32),
                operation_kind TEXT NOT NULL,
                subject_key TEXT NOT NULL,
                request_json TEXT NOT NULL,
                request_digest TEXT NOT NULL CHECK(length(request_digest) = 64),
                state TEXT NOT NULL CHECK(state IN (
                    'waiting', 'preparing', 'contact_starting', 'contact_active',
                    'complete', 'cancelled', 'failed', 'needs_attention'
                )),
                contact_phase TEXT NOT NULL CHECK(contact_phase IN (
                    'not_started', 'preparing', 'contact_starting',
                    'contact_active', 'contact_stopped', 'uncertain', 'complete'
                )),
                cancellation_requested INTEGER NOT NULL DEFAULT 0
                    CHECK(cancellation_requested IN (0, 1)),
                retry_count INTEGER NOT NULL DEFAULT 0 CHECK(retry_count IN (0, 1)),
                active_attempt_number INTEGER,
                created_at TEXT NOT NULL,
                created_by TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                completed_at TEXT,
                status_reason TEXT,
                terminal_manifest_json TEXT,
                presentation_synced INTEGER NOT NULL DEFAULT 0
                    CHECK(presentation_synced IN (0, 1))
            );
            CREATE INDEX IF NOT EXISTS device_contact_run_state
                ON device_contact_runs(state, created_at, run_id);
            CREATE TABLE IF NOT EXISTS device_contact_attempts (
                run_id TEXT NOT NULL,
                attempt_number INTEGER NOT NULL CHECK(attempt_number >= 1),
                owner_id TEXT NOT NULL,
                state TEXT NOT NULL CHECK(state IN (
                    'preparing', 'contact_starting', 'contact_active',
                    'complete', 'cancelled', 'failed', 'abandoned',
                    'needs_attention'
                )),
                contact_phase TEXT NOT NULL CHECK(contact_phase IN (
                    'preparing', 'contact_starting', 'contact_active',
                    'contact_stopped', 'uncertain', 'complete'
                )),
                run_lease_key TEXT NOT NULL,
                run_lease_id TEXT NOT NULL,
                run_lease_epoch INTEGER NOT NULL CHECK(run_lease_epoch >= 1),
                capacity_lease_key TEXT NOT NULL,
                capacity_lease_id TEXT NOT NULL,
                capacity_lease_epoch INTEGER NOT NULL CHECK(capacity_lease_epoch >= 1),
                started_at TEXT NOT NULL,
                contact_started_at TEXT,
                contact_stopped_at TEXT,
                completed_at TEXT,
                status_reason TEXT,
                PRIMARY KEY(run_id, attempt_number),
                FOREIGN KEY(run_id) REFERENCES device_contact_runs(run_id)
                    ON DELETE RESTRICT
            );
            CREATE TABLE IF NOT EXISTS device_contact_controls (
                control_id TEXT PRIMARY KEY CHECK(length(control_id) = 32),
                run_id TEXT NOT NULL,
                control_kind TEXT NOT NULL CHECK(control_kind IN (
                    'cancel_requested', 'admin_closed'
                )),
                requested_at TEXT NOT NULL,
                requested_by TEXT NOT NULL,
                reason TEXT NOT NULL,
                FOREIGN KEY(run_id) REFERENCES device_contact_runs(run_id)
                    ON DELETE RESTRICT
            );
            CREATE INDEX IF NOT EXISTS device_contact_control_history
                ON device_contact_controls(run_id, requested_at, control_id);
            CREATE TABLE IF NOT EXISTS device_contact_reviews (
                review_id TEXT PRIMARY KEY CHECK(length(review_id) = 32),
                run_id TEXT NOT NULL,
                attempt_number INTEGER NOT NULL,
                reviewed_at TEXT NOT NULL,
                reviewed_by TEXT NOT NULL,
                former_processes_stopped INTEGER NOT NULL CHECK(former_processes_stopped = 1),
                files_stable INTEGER NOT NULL CHECK(files_stable = 1),
                file_review_json TEXT NOT NULL,
                disposition TEXT NOT NULL CHECK(disposition IN ('cancelled', 'failed')),
                reason TEXT NOT NULL,
                FOREIGN KEY(run_id, attempt_number)
                    REFERENCES device_contact_attempts(run_id, attempt_number)
            );
            CREATE TABLE IF NOT EXISTS device_contact_publications (
                publication_id TEXT PRIMARY KEY CHECK(length(publication_id) = 32),
                run_id TEXT NOT NULL,
                attempt_number INTEGER NOT NULL,
                state TEXT NOT NULL CHECK(state IN ('prepared', 'files_moved', 'committed')),
                files_json TEXT NOT NULL,
                prepared_at TEXT NOT NULL,
                files_moved_at TEXT,
                committed_at TEXT,
                UNIQUE(run_id, attempt_number),
                FOREIGN KEY(run_id, attempt_number)
                    REFERENCES device_contact_attempts(run_id, attempt_number)
            );
            CREATE TRIGGER IF NOT EXISTS device_contact_run_plan_immutable
            BEFORE UPDATE OF operation_kind, subject_key, request_json,
                request_digest, created_at, created_by
            ON device_contact_runs
            BEGIN
                SELECT RAISE(ABORT, 'Device contact run plan is immutable');
            END;
            CREATE TRIGGER IF NOT EXISTS device_contact_attempt_binding_immutable
            BEFORE UPDATE OF run_id, attempt_number, owner_id, run_lease_key,
                run_lease_id, run_lease_epoch, capacity_lease_key,
                capacity_lease_id, capacity_lease_epoch, started_at
            ON device_contact_attempts
            BEGIN
                SELECT RAISE(ABORT, 'Device contact attempt binding is immutable');
            END;
            """
        )
        run_columns = {
            str(row[1])
            for row in connection.execute("PRAGMA table_info(device_contact_runs)")
        }
        if "terminal_manifest_json" not in run_columns:
            connection.execute(
                "ALTER TABLE device_contact_runs ADD COLUMN terminal_manifest_json TEXT"
            )
        if "presentation_synced" not in run_columns:
            connection.execute(
                """ALTER TABLE device_contact_runs
                   ADD COLUMN presentation_synced INTEGER NOT NULL DEFAULT 0
                   CHECK(presentation_synced IN (0, 1))"""
            )


def create_device_contact_run(
    db_path: Path,
    *,
    operation_kind: str,
    subject_key: str,
    request: dict[str, object],
    created_by: str,
    run_id: str | None = None,
) -> str:
    init_device_contact_work_storage(db_path)
    identity = run_id or uuid.uuid4().hex
    if len(identity) != 32:
        raise ValueError("Run identity is invalid")
    request_json = _canonical(request)
    with connect_database(db_path) as connection:
        now = _db_now(connection)
        connection.execute(
            """INSERT INTO device_contact_runs(
                   run_id, operation_kind, subject_key, request_json,
                   request_digest, state, contact_phase, cancellation_requested,
                   retry_count, active_attempt_number, created_at, created_by,
                   updated_at, completed_at, status_reason,
                   terminal_manifest_json, presentation_synced
               ) VALUES (?, ?, ?, ?, ?, 'waiting', 'not_started', 0, 0, NULL,
                         ?, ?, ?, NULL, NULL, NULL, 0)""",
            (
                identity,
                _bounded(operation_kind, "Operation kind", 80),
                _bounded(subject_key, "Subject key"),
                request_json,
                _digest(request),
                now,
                _bounded(created_by, "Creator"),
                now,
            ),
        )
    return identity


def _attempt_leases(row: sqlite3.Row | tuple) -> tuple[dict[str, object], dict[str, object]]:
    owner = row[0]
    return (
        {
            "lease_key": row[1], "lease_id": row[2],
            "lease_epoch": int(row[3]), "lease_owner": owner,
        },
        {
            "lease_key": row[4], "lease_id": row[5],
            "lease_epoch": int(row[6]), "lease_owner": owner,
        },
    )


def claim_device_contact_run(
    db_path: Path,
    run_id: str,
    *,
    owner_id: str,
    lease_seconds: int = 30,
) -> DeviceContactClaim:
    init_device_contact_work_storage(db_path)
    owner = _bounded(owner_id, "Lease owner")
    with connect_database(db_path) as connection:
        connection.execute("BEGIN IMMEDIATE")
        run = connection.execute(
            """SELECT state, cancellation_requested, retry_count
                 FROM device_contact_runs WHERE run_id = ?""",
            (run_id,),
        ).fetchone()
        if run is None:
            raise KeyError("Unknown device-contact run")
        if bool(run[1]) or run[0] == "cancelled":
            raise DeviceContactConflict("This device-contact run is cancelled")
        if run[0] != "waiting":
            raise DeviceContactConflict("This device-contact run is not waiting")
        attempt_number = int(connection.execute(
            """SELECT COALESCE(MAX(attempt_number), 0) + 1
                 FROM device_contact_attempts WHERE run_id = ?""",
            (run_id,),
        ).fetchone()[0])
        run_lease = acquire_work_lease_on_connection(
            connection,
            lease_key=f"device-contact-run:{run_id}",
            work_kind="device-contact-run",
            work_id=f"{run_id}:{attempt_number}",
            owner_id=owner,
            lease_seconds=lease_seconds,
            expired_policy="recovery_required",
        )
        capacity_lease = acquire_work_lease_on_connection(
            connection,
            lease_key=DEVICE_CONTACT_CAPACITY_LEASE_KEY,
            work_kind="device-contact-capacity",
            work_id=f"{run_id}:{attempt_number}",
            owner_id=owner,
            lease_seconds=lease_seconds,
            expired_policy="recovery_required",
        )
        now = _db_now(connection)
        connection.execute(
            """INSERT INTO device_contact_attempts(
                   run_id, attempt_number, owner_id, state, contact_phase,
                   run_lease_key, run_lease_id, run_lease_epoch,
                   capacity_lease_key, capacity_lease_id, capacity_lease_epoch,
                   started_at
               ) VALUES (?, ?, ?, 'preparing', 'preparing', ?, ?, ?, ?, ?, ?, ?)""",
            (
                run_id, attempt_number, owner,
                run_lease.lease_key, run_lease.lease_id, run_lease.fencing_epoch,
                capacity_lease.lease_key, capacity_lease.lease_id,
                capacity_lease.fencing_epoch, now,
            ),
        )
        changed = connection.execute(
            """UPDATE device_contact_runs
                  SET state = 'preparing', contact_phase = 'preparing',
                      active_attempt_number = ?, updated_at = ?, status_reason = NULL
                WHERE run_id = ? AND state = 'waiting'
                  AND cancellation_requested = 0""",
            (attempt_number, now, run_id),
        ).rowcount
        if changed != 1:
            raise DeviceContactConflict("The device-contact run changed before claim")
        return DeviceContactClaim(
            run_id, attempt_number, owner, run_lease, capacity_lease
        )


def _assert_claim(
    connection: sqlite3.Connection,
    claim: DeviceContactClaim,
) -> None:
    assert_work_lease_on_connection(connection, claim.run_lease)
    assert_work_lease_on_connection(connection, claim.capacity_lease)
    row = connection.execute(
        """SELECT owner_id, run_lease_id, run_lease_epoch,
                  capacity_lease_id, capacity_lease_epoch
             FROM device_contact_attempts
            WHERE run_id = ? AND attempt_number = ?""",
        (claim.run_id, claim.attempt_number),
    ).fetchone()
    expected = (
        claim.owner_id,
        claim.run_lease.lease_id,
        claim.run_lease.fencing_epoch,
        claim.capacity_lease.lease_id,
        claim.capacity_lease.fencing_epoch,
    )
    if row != expected:
        raise WorkLeaseConflict("The device-contact attempt binding changed")


def assert_device_contact_claim_on_connection(
    connection: sqlite3.Connection,
    claim: DeviceContactClaim,
) -> None:
    """Prove both contact leases and their immutable attempt binding."""
    _assert_claim(connection, claim)


def assert_device_contact_claim(db_path: Path, claim: DeviceContactClaim) -> None:
    with connect_database(db_path) as connection:
        connection.execute("BEGIN IMMEDIATE")
        _assert_claim(connection, claim)


def device_contact_cancellation_requested(
    db_path: Path,
    claim: DeviceContactClaim,
) -> bool:
    with connect_database(db_path) as connection:
        connection.execute("BEGIN IMMEDIATE")
        _assert_claim(connection, claim)
        row = connection.execute(
            "SELECT cancellation_requested FROM device_contact_runs WHERE run_id = ?",
            (claim.run_id,),
        ).fetchone()
        if row is None:
            raise DeviceContactConflict("The device-contact run is missing")
        return bool(row[0])


def prepare_device_contact_publication(
    db_path: Path,
    claim: DeviceContactClaim,
    files: list[dict[str, object]],
) -> str:
    """Durably journal exact attempt files before any retained-path rename."""
    files_json = _canonical(files)
    with connect_database(db_path) as connection:
        connection.execute("BEGIN IMMEDIATE")
        _assert_claim(connection, claim)
        cancelled = connection.execute(
            "SELECT cancellation_requested FROM device_contact_runs WHERE run_id = ?",
            (claim.run_id,),
        ).fetchone()
        if cancelled is None or bool(cancelled[0]):
            raise DeviceContactConflict("Cancellation is pending for this device contact")
        existing = connection.execute(
            """SELECT publication_id, state, files_json
                 FROM device_contact_publications
                WHERE run_id = ? AND attempt_number = ?""",
            (claim.run_id, claim.attempt_number),
        ).fetchone()
        if existing is not None:
            if existing[2] != files_json:
                raise DeviceContactConflict("The device-contact publication inventory changed")
            return str(existing[0])
        publication_id = uuid.uuid4().hex
        connection.execute(
            """INSERT INTO device_contact_publications(
                   publication_id, run_id, attempt_number, state, files_json,
                   prepared_at, files_moved_at, committed_at
               ) VALUES (?, ?, ?, 'prepared', ?, ?, NULL, NULL)""",
            (
                publication_id, claim.run_id, claim.attempt_number,
                files_json, _db_now(connection),
            ),
        )
        return publication_id


def publish_device_contact_files_moved(
    db_path: Path,
    claim: DeviceContactClaim,
    publication_id: str,
    move_callback: Callable[[], None],
) -> None:
    """Fence filesystem promotion behind the exact live claim and durable journal."""
    with connect_database(db_path) as connection:
        connection.execute("BEGIN IMMEDIATE")
        _assert_claim(connection, claim)
        cancelled = connection.execute(
            "SELECT cancellation_requested FROM device_contact_runs WHERE run_id = ?",
            (claim.run_id,),
        ).fetchone()
        if cancelled is None or bool(cancelled[0]):
            raise DeviceContactConflict("Cancellation is pending for this device contact")
        row = connection.execute(
            """SELECT state FROM device_contact_publications
                WHERE publication_id = ? AND run_id = ? AND attempt_number = ?""",
            (publication_id, claim.run_id, claim.attempt_number),
        ).fetchone()
        if row != ("prepared",):
            raise DeviceContactConflict("The device-contact publication is not prepared")
        move_callback()
        _assert_claim(connection, claim)
        changed = connection.execute(
            """UPDATE device_contact_publications
                  SET state = 'files_moved', files_moved_at = ?
                WHERE publication_id = ? AND state = 'prepared'""",
            (_db_now(connection), publication_id),
        ).rowcount
        if changed != 1:
            raise DeviceContactConflict("The device-contact publication changed")


def commit_device_contact_publication_on_connection(
    connection: sqlite3.Connection,
    claim: DeviceContactClaim,
    publication_id: str,
) -> None:
    _assert_claim(connection, claim)
    changed = connection.execute(
        """UPDATE device_contact_publications
              SET state = 'committed', committed_at = ?
            WHERE publication_id = ? AND run_id = ? AND attempt_number = ?
              AND state = 'files_moved'""",
        (
            _db_now(connection), publication_id,
            claim.run_id, claim.attempt_number,
        ),
    ).rowcount
    if changed != 1:
        raise DeviceContactConflict("The device-contact files were not safely published")


def mark_device_contact_presentation_synced(
    db_path: Path, run_id: str,
) -> None:
    with connect_database(db_path) as connection:
        changed = connection.execute(
            """UPDATE device_contact_runs
                  SET presentation_synced = 1
                WHERE run_id = ? AND terminal_manifest_json IS NOT NULL""",
            (run_id,),
        ).rowcount
        if changed != 1:
            raise DeviceContactConflict("The terminal presentation receipt is unavailable")


def list_unsynced_device_contact_presentations(
    db_path: Path,
) -> list[dict[str, object]]:
    init_device_contact_work_storage(db_path)
    with connect_database(db_path, read_only=True) as connection:
        rows = connection.execute(
            """SELECT r.run_id,
                      (SELECT MAX(a.attempt_number)
                         FROM device_contact_attempts a
                        WHERE a.run_id = r.run_id),
                      r.terminal_manifest_json
                 FROM device_contact_runs r
                WHERE r.presentation_synced = 0
                  AND r.terminal_manifest_json IS NOT NULL
                ORDER BY r.completed_at, r.run_id"""
        ).fetchall()
    return [
        {
            "run_id": row[0], "attempt_number": row[1],
            "manifest": json.loads(row[2]),
        }
        for row in rows
    ]


def list_open_device_contact_runs(db_path: Path) -> list[dict[str, object]]:
    """Return database-authoritative runs that startup must reconcile."""
    init_device_contact_work_storage(db_path)
    with connect_database(db_path, read_only=True) as connection:
        rows = connection.execute(
            """SELECT r.run_id, r.operation_kind, r.state, r.contact_phase,
                      r.active_attempt_number, r.request_json, r.created_by,
                      p.state
                 FROM device_contact_runs r
                 LEFT JOIN device_contact_publications p
                   ON p.run_id = r.run_id
                  AND p.attempt_number = r.active_attempt_number
                WHERE r.active_attempt_number IS NOT NULL
                   OR r.state IN ('waiting', 'preparing', 'contact_starting',
                                  'contact_active', 'needs_attention')
                ORDER BY r.created_at, r.run_id"""
        ).fetchall()
    return [
        {
            "run_id": row[0], "operation_kind": row[1], "state": row[2],
            "contact_phase": row[3], "active_attempt_number": row[4],
            "request": json.loads(row[5]), "created_by": row[6],
            "publication_state": row[7],
        }
        for row in rows
    ]


def get_device_contact_attempt_for_review(
    db_path: Path, run_id: str,
) -> dict[str, object] | None:
    init_device_contact_work_storage(db_path)
    with connect_database(db_path, read_only=True) as connection:
        row = connection.execute(
            """SELECT attempt_number, state, contact_phase
                 FROM device_contact_attempts
                WHERE run_id = ? AND state = 'needs_attention'
                ORDER BY attempt_number DESC LIMIT 1""",
            (run_id,),
        ).fetchone()
    if row is None:
        return None
    return {
        "attempt_number": int(row[0]), "state": row[1], "contact_phase": row[2]
    }


def renew_device_contact_claim(
    db_path: Path,
    claim: DeviceContactClaim,
    *,
    lease_seconds: int = 30,
) -> DeviceContactClaim:
    with connect_database(db_path) as connection:
        connection.execute("BEGIN IMMEDIATE")
        _assert_claim(connection, claim)
        run_lease = renew_work_lease_on_connection(
            connection, claim.run_lease, lease_seconds=lease_seconds
        )
        capacity_lease = renew_work_lease_on_connection(
            connection, claim.capacity_lease, lease_seconds=lease_seconds
        )
        return DeviceContactClaim(
            claim.run_id, claim.attempt_number, claim.owner_id,
            run_lease, capacity_lease,
        )


def request_device_contact_cancellation(
    db_path: Path,
    run_id: str,
    *,
    requested_by: str,
    reason: str,
) -> str:
    init_device_contact_work_storage(db_path)
    with connect_database(db_path) as connection:
        connection.execute("BEGIN IMMEDIATE")
        row = connection.execute(
            "SELECT state FROM device_contact_runs WHERE run_id = ?", (run_id,)
        ).fetchone()
        if row is None:
            raise KeyError("Unknown device-contact run")
        if row[0] in {"complete", "cancelled", "failed"}:
            raise DeviceContactConflict("This device-contact run is already closed")
        now = _db_now(connection)
        control_id = uuid.uuid4().hex
        explanation = _bounded(reason, "Cancellation reason", 500)
        connection.execute(
            """INSERT INTO device_contact_controls(
                   control_id, run_id, control_kind, requested_at,
                   requested_by, reason
               ) VALUES (?, ?, 'cancel_requested', ?, ?, ?)""",
            (control_id, run_id, now, _bounded(requested_by, "Requester"), explanation),
        )
        if row[0] == "waiting":
            connection.execute(
                """UPDATE device_contact_runs
                      SET state = 'cancelled', cancellation_requested = 1,
                          completed_at = ?, updated_at = ?, status_reason = ?
                    WHERE run_id = ? AND state = 'waiting'""",
                (now, now, explanation, run_id),
            )
        else:
            connection.execute(
                """UPDATE device_contact_runs
                      SET cancellation_requested = 1, updated_at = ?, status_reason = ?
                    WHERE run_id = ?""",
                (now, explanation, run_id),
            )
        return control_id


def mark_device_contact_starting(
    db_path: Path,
    claim: DeviceContactClaim,
) -> bool:
    """Fence the last pre-contact boundary; False means cancellation won."""
    with connect_database(db_path) as connection:
        connection.execute("BEGIN IMMEDIATE")
        _assert_claim(connection, claim)
        row = connection.execute(
            """SELECT state, cancellation_requested
                 FROM device_contact_runs WHERE run_id = ?""",
            (claim.run_id,),
        ).fetchone()
        if row != ("preparing", 0):
            if row and bool(row[1]):
                now = _db_now(connection)
                connection.execute(
                    """UPDATE device_contact_attempts
                          SET state = 'cancelled', completed_at = ?,
                              status_reason = 'Cancelled before device contact'
                        WHERE run_id = ? AND attempt_number = ?""",
                    (now, claim.run_id, claim.attempt_number),
                )
                connection.execute(
                    """UPDATE device_contact_runs
                          SET state = 'cancelled', contact_phase = 'not_started',
                              completed_at = ?, updated_at = ?, active_attempt_number = NULL
                        WHERE run_id = ?""",
                    (now, now, claim.run_id),
                )
                release_work_lease_on_connection(
                    connection, claim.capacity_lease,
                    detail="Cancellation won before device contact.",
                )
                release_work_lease_on_connection(
                    connection, claim.run_lease,
                    detail="Cancellation won before device contact.",
                )
                return False
            raise DeviceContactConflict("The device-contact run cannot start contact")
        now = _db_now(connection)
        connection.execute(
            """UPDATE device_contact_attempts
                  SET state = 'contact_starting', contact_phase = 'contact_starting',
                      contact_started_at = ?
                WHERE run_id = ? AND attempt_number = ? AND state = 'preparing'""",
            (now, claim.run_id, claim.attempt_number),
        )
        connection.execute(
            """UPDATE device_contact_runs
                  SET state = 'contact_starting', contact_phase = 'contact_starting',
                      updated_at = ?
                WHERE run_id = ?""",
            (now, claim.run_id),
        )
        return True


def mark_device_contact_active(db_path: Path, claim: DeviceContactClaim) -> None:
    with connect_database(db_path) as connection:
        connection.execute("BEGIN IMMEDIATE")
        _assert_claim(connection, claim)
        now = _db_now(connection)
        changed = connection.execute(
            """UPDATE device_contact_attempts
                  SET state = 'contact_active', contact_phase = 'contact_active'
                WHERE run_id = ? AND attempt_number = ?
                  AND state = 'contact_starting'""",
            (claim.run_id, claim.attempt_number),
        ).rowcount
        if changed != 1:
            raise DeviceContactConflict("Device contact did not reach its active boundary")
        connection.execute(
            """UPDATE device_contact_runs
                  SET state = 'contact_active', contact_phase = 'contact_active',
                      updated_at = ? WHERE run_id = ?""",
            (now, claim.run_id),
        )


def publish_device_contact_terminal(
    db_path: Path,
    claim: DeviceContactClaim,
    *,
    outcome: str,
    reason: str,
    transaction_callback: Callable[[sqlite3.Connection], None] | None = None,
    terminal_manifest: dict[str, object] | None = None,
) -> None:
    if outcome not in {"complete", "cancelled", "failed"}:
        raise ValueError("Unknown device-contact outcome")
    with connect_database(db_path) as connection:
        connection.execute("BEGIN IMMEDIATE")
        _assert_claim(connection, claim)
        run = connection.execute(
            "SELECT cancellation_requested FROM device_contact_runs WHERE run_id = ?",
            (claim.run_id,),
        ).fetchone()
        if outcome == "complete" and run and bool(run[0]):
            raise DeviceContactConflict("Cancellation is pending for this device contact")
        if transaction_callback is not None:
            transaction_callback(connection)
            _assert_claim(connection, claim)
        now = _db_now(connection)
        phase = "complete" if outcome == "complete" else "contact_stopped"
        explanation = _bounded(reason, "Terminal reason", 500)
        connection.execute(
            """UPDATE device_contact_attempts
                  SET state = ?, contact_phase = ?, contact_stopped_at = ?,
                      completed_at = ?, status_reason = ?
                WHERE run_id = ? AND attempt_number = ?""",
            (
                outcome, phase, now, now, explanation,
                claim.run_id, claim.attempt_number,
            ),
        )
        connection.execute(
            """UPDATE device_contact_runs
                  SET state = ?, contact_phase = ?, active_attempt_number = NULL,
                      completed_at = ?, updated_at = ?, status_reason = ?,
                      terminal_manifest_json = ?, presentation_synced = 0
                WHERE run_id = ?""",
            (
                outcome, phase, now, now, explanation,
                _canonical(terminal_manifest) if terminal_manifest is not None else None,
                claim.run_id,
            ),
        )
        release_work_lease_on_connection(
            connection, claim.capacity_lease, detail=explanation
        )
        release_work_lease_on_connection(
            connection, claim.run_lease, detail=explanation
        )


def recover_abandoned_device_contact(
    db_path: Path,
    run_id: str,
    *,
    former_process_ended: bool,
    force_review: bool = False,
) -> str:
    if former_process_ended is not True:
        raise ValueError("Former process termination must be verified")
    init_device_contact_work_storage(db_path)
    with connect_database(db_path) as connection:
        connection.execute("BEGIN IMMEDIATE")
        run = connection.execute(
            """SELECT state, contact_phase, retry_count, active_attempt_number
                 FROM device_contact_runs WHERE run_id = ?""",
            (run_id,),
        ).fetchone()
        if run is None:
            raise KeyError("Unknown device-contact run")
        if run[3] is None:
            return str(run[0])
        attempt = connection.execute(
            """SELECT owner_id, run_lease_key, run_lease_id, run_lease_epoch,
                      capacity_lease_key, capacity_lease_id, capacity_lease_epoch
                 FROM device_contact_attempts
                WHERE run_id = ? AND attempt_number = ?""",
            (run_id, int(run[3])),
        ).fetchone()
        if attempt is None:
            raise DeviceContactConflict("The active device-contact attempt is missing")
        run_lease, capacity_lease = _attempt_leases(attempt)
        pre_contact = run[1] in {"not_started", "preparing"}
        reason = (
            "NCT restarted before device contact. No device was contacted; start a new collection with fresh settings and credentials."
            if pre_contact and not force_review else
            "Former process may have contacted the device; administrator review is required."
        )
        safely_stopped_before_contact = pre_contact and not force_review
        recovery_required = not safely_stopped_before_contact
        recover_abandoned_work_lease_on_connection(
            connection, capacity_lease,
            recovery_required=recovery_required, detail=reason,
        )
        recover_abandoned_work_lease_on_connection(
            connection, run_lease,
            recovery_required=recovery_required, detail=reason,
        )
        now = _db_now(connection)
        attempt_state = "failed" if safely_stopped_before_contact else "needs_attention"
        attempt_phase = "contact_stopped" if safely_stopped_before_contact else "uncertain"
        connection.execute(
            """UPDATE device_contact_attempts
                  SET state = ?, contact_phase = ?, completed_at = ?,
                      status_reason = ?
                WHERE run_id = ? AND attempt_number = ?""",
            (attempt_state, attempt_phase, now, reason, run_id, int(run[3])),
        )
        if safely_stopped_before_contact:
            connection.execute(
                """UPDATE device_contact_runs
                      SET state = 'failed', contact_phase = 'contact_stopped',
                          active_attempt_number = NULL, completed_at = ?,
                          updated_at = ?, status_reason = ?
                    WHERE run_id = ?""",
                (now, now, reason, run_id),
            )
            return "failed"
        connection.execute(
            """UPDATE device_contact_runs
                  SET state = 'needs_attention', contact_phase = 'uncertain',
                      active_attempt_number = NULL, updated_at = ?,
                      status_reason = ? WHERE run_id = ?""",
            (now, reason, run_id),
        )
        return "needs_attention"


def _clear_exact_recovery(
    connection: sqlite3.Connection,
    lease: dict[str, object],
    *,
    now: str,
    detail: str,
) -> None:
    changed = connection.execute(
        """UPDATE work_leases
              SET state = 'released', released_at = ?, renewed_at = ?,
                  recovery_reason = NULL
            WHERE lease_key = ? AND fencing_epoch = ?
              AND state = 'recovery_required'""",
        (now, now, lease["lease_key"], int(lease["lease_epoch"])),
    ).rowcount
    if changed != 1:
        raise DeviceContactConflict("The exact device-contact safety stop changed")
    connection.execute(
        """INSERT INTO work_lease_events(
               event_id, lease_key, fencing_epoch, lease_id, owner_id,
               event_kind, recorded_at, detail
           ) VALUES (?, ?, ?, NULL, NULL, 'recovery_cleared', ?, ?)""",
        (
            uuid.uuid4().hex, lease["lease_key"], int(lease["lease_epoch"]),
            now, detail[:500],
        ),
    )


def close_device_contact_after_review(
    db_path: Path,
    run_id: str,
    *,
    reviewed_by: str,
    reason: str,
    former_processes_stopped: bool,
    files_stable: bool,
    file_review: dict[str, object],
    disposition: str = "failed",
) -> str:
    if former_processes_stopped is not True:
        raise ValueError("Former device-contact processes must be confirmed stopped")
    if files_stable is not True:
        raise ValueError("Retained files must be confirmed stable")
    if disposition not in {"cancelled", "failed"}:
        raise ValueError("Unknown review disposition")
    review_json = _canonical(file_review)
    if not file_review:
        raise ValueError("File stability evidence is required")
    with connect_database(db_path) as connection:
        connection.execute("BEGIN IMMEDIATE")
        run = connection.execute(
            """SELECT state FROM device_contact_runs WHERE run_id = ?""", (run_id,)
        ).fetchone()
        if run != ("needs_attention",):
            raise DeviceContactConflict("This device-contact run is not awaiting review")
        attempt = connection.execute(
            """SELECT attempt_number, owner_id, run_lease_key, run_lease_id,
                      run_lease_epoch, capacity_lease_key, capacity_lease_id,
                      capacity_lease_epoch
                 FROM device_contact_attempts
                WHERE run_id = ? AND state = 'needs_attention'
                ORDER BY attempt_number DESC LIMIT 1""",
            (run_id,),
        ).fetchone()
        if attempt is None:
            raise DeviceContactConflict("The interrupted attempt is missing")
        run_lease, capacity_lease = _attempt_leases(attempt[1:])
        now = _db_now(connection)
        explanation = _bounded(reason, "Review reason", 500)
        _clear_exact_recovery(
            connection, capacity_lease, now=now, detail=explanation
        )
        _clear_exact_recovery(connection, run_lease, now=now, detail=explanation)
        review_id = uuid.uuid4().hex
        reviewer = _bounded(reviewed_by, "Reviewer")
        connection.execute(
            """INSERT INTO device_contact_reviews(
                   review_id, run_id, attempt_number, reviewed_at, reviewed_by,
                   former_processes_stopped, files_stable, file_review_json,
                   disposition, reason
               ) VALUES (?, ?, ?, ?, ?, 1, 1, ?, ?, ?)""",
            (
                review_id, run_id, int(attempt[0]), now, reviewer,
                review_json, disposition, explanation,
            ),
        )
        connection.execute(
            """INSERT INTO device_contact_controls(
                   control_id, run_id, control_kind, requested_at,
                   requested_by, reason
               ) VALUES (?, ?, 'admin_closed', ?, ?, ?)""",
            (uuid.uuid4().hex, run_id, now, reviewer, explanation),
        )
        connection.execute(
            """UPDATE device_contact_attempts
                  SET state = ?, contact_phase = 'contact_stopped',
                      completed_at = ?, status_reason = ?
                WHERE run_id = ? AND attempt_number = ?""",
            (disposition, now, explanation, run_id, int(attempt[0])),
        )
        connection.execute(
            """UPDATE device_contact_runs
                  SET state = ?, contact_phase = 'contact_stopped',
                      completed_at = ?, updated_at = ?, status_reason = ?
                WHERE run_id = ?""",
            (disposition, now, now, explanation, run_id),
        )
        return review_id


def get_device_contact_run(db_path: Path, run_id: str) -> dict[str, object] | None:
    init_device_contact_work_storage(db_path)
    with connect_database(db_path, read_only=True) as connection:
        run = connection.execute(
            """SELECT run_id, operation_kind, subject_key, request_json,
                      request_digest, state, contact_phase, cancellation_requested,
                      retry_count, active_attempt_number, created_at, created_by,
                      updated_at, completed_at, status_reason
                 FROM device_contact_runs WHERE run_id = ?""",
            (run_id,),
        ).fetchone()
        if run is None:
            return None
        attempts = connection.execute(
            """SELECT attempt_number, owner_id, state, contact_phase,
                      run_lease_key, run_lease_id, run_lease_epoch,
                      capacity_lease_key, capacity_lease_id, capacity_lease_epoch,
                      started_at, contact_started_at, contact_stopped_at,
                      completed_at, status_reason
                 FROM device_contact_attempts WHERE run_id = ?
                ORDER BY attempt_number""",
            (run_id,),
        ).fetchall()
        controls = connection.execute(
            """SELECT control_kind, requested_at, requested_by, reason
                 FROM device_contact_controls WHERE run_id = ?
                ORDER BY requested_at, control_id""",
            (run_id,),
        ).fetchall()
        reviews = connection.execute(
            """SELECT review_id, attempt_number, reviewed_at, reviewed_by,
                      former_processes_stopped, files_stable, file_review_json,
                      disposition, reason
                 FROM device_contact_reviews WHERE run_id = ?
                ORDER BY reviewed_at, review_id""",
            (run_id,),
        ).fetchall()
    run_keys = (
        "run_id", "operation_kind", "subject_key", "request_json",
        "request_digest", "state", "contact_phase", "cancellation_requested",
        "retry_count", "active_attempt_number", "created_at", "created_by",
        "updated_at", "completed_at", "status_reason",
    )
    attempt_keys = (
        "attempt_number", "owner_id", "state", "contact_phase",
        "run_lease_key", "run_lease_id", "run_lease_epoch",
        "capacity_lease_key", "capacity_lease_id", "capacity_lease_epoch",
        "started_at", "contact_started_at", "contact_stopped_at",
        "completed_at", "status_reason",
    )
    result = dict(zip(run_keys, run))
    result["request"] = json.loads(str(result.pop("request_json")))
    result["cancellation_requested"] = bool(result["cancellation_requested"])
    result["attempts"] = [dict(zip(attempt_keys, row)) for row in attempts]
    result["controls"] = [
        dict(zip(("control_kind", "requested_at", "requested_by", "reason"), row))
        for row in controls
    ]
    result["reviews"] = [
        {
            **dict(zip((
                "review_id", "attempt_number", "reviewed_at", "reviewed_by",
                "former_processes_stopped", "files_stable", "file_review_json",
                "disposition", "reason",
            ), row)),
            "file_review": json.loads(row[6]),
        }
        for row in reviews
    ]
    return result
