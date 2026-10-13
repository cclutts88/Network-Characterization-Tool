from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
import uuid
from typing import Callable

from app.database import connect_database, initialize_once_per_database
from app.work_coordination import (
    WorkLease,
    WorkLeaseConflict,
    WorkRecoveryRequired,
    acquire_work_lease_on_connection,
    assert_work_lease_on_connection,
    init_work_coordination_storage,
    release_work_lease_on_connection,
)


OCCURRENCE_OPEN_STATES = ("waiting", "preparing", "active", "needs_attention")
CHUNK_STATES = ("waiting", "preparing", "active", "complete", "cancelled", "needs_attention")


def canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def content_digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def schedule_definition_contract(schedule: dict) -> dict:
    """Return only fields whose change creates a new schedule definition."""
    keys = (
        "name", "profile_id", "profile_version", "profile_name", "profile_snapshot",
        "targets", "manual_targets", "saved_network_ids", "saved_networks",
        "reviewed_scope_associations", "network_scope_context", "network_scope_status",
        "no_strike", "interface", "cadence", "first_run_at", "cadence_hours",
        "interval_minutes", "reason", "originating_host", "timeout_seconds",
        "chunking_enabled", "chunk_size", "chunk_delay_seconds", "fallback_policy",
    )
    return {key: schedule.get(key) for key in keys}


def definition_identity(schedule: dict) -> tuple[int, str, dict]:
    version = max(1, int(schedule.get("definition_version") or 1))
    contract = schedule_definition_contract(schedule)
    return version, content_digest(contract), contract


def deterministic_occurrence_id(
    schedule_id: str,
    definition_version: int,
    due_at: str,
    trigger_kind: str,
    trigger_key: str,
) -> str:
    identity_time = due_at if trigger_kind == "scheduled" else "manual-request"
    return content_digest(
        [schedule_id, int(definition_version), identity_time, trigger_kind, trigger_key]
    )[:32]


@initialize_once_per_database
def init_scheduled_work_storage(db_path: Path) -> None:
    init_work_coordination_storage(db_path)
    with connect_database(db_path) as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS scan_schedule_definitions (
                schedule_id TEXT NOT NULL,
                definition_version INTEGER NOT NULL CHECK(definition_version >= 1),
                definition_digest TEXT NOT NULL CHECK(length(definition_digest) = 64),
                contract_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                created_by TEXT NOT NULL,
                PRIMARY KEY(schedule_id, definition_version),
                UNIQUE(schedule_id, definition_digest),
                FOREIGN KEY(schedule_id) REFERENCES scan_schedules(schedule_id)
                    ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS scan_schedule_occurrences (
                occurrence_id TEXT PRIMARY KEY CHECK(length(occurrence_id) = 32),
                schedule_id TEXT NOT NULL,
                definition_version INTEGER NOT NULL,
                definition_digest TEXT NOT NULL CHECK(length(definition_digest) = 64),
                due_at TEXT NOT NULL,
                trigger_kind TEXT NOT NULL CHECK(trigger_kind IN ('scheduled', 'manual')),
                trigger_key TEXT NOT NULL,
                actor TEXT NOT NULL,
                state TEXT NOT NULL CHECK(state IN (
                    'waiting', 'preparing', 'active', 'complete', 'cancelled',
                    'missed', 'needs_attention'
                )),
                frozen_json TEXT NOT NULL,
                frozen_digest TEXT NOT NULL CHECK(length(frozen_digest) = 64),
                first_missed_due_at TEXT,
                latest_missed_due_at TEXT,
                skipped_due_count INTEGER NOT NULL DEFAULT 0 CHECK(skipped_due_count >= 0),
                created_at TEXT NOT NULL,
                started_at TEXT,
                completed_at TEXT,
                status_reason TEXT,
                UNIQUE(schedule_id, definition_version, due_at, trigger_kind, trigger_key),
                FOREIGN KEY(schedule_id, definition_version)
                    REFERENCES scan_schedule_definitions(schedule_id, definition_version)
            );
            CREATE UNIQUE INDEX IF NOT EXISTS one_open_schedule_occurrence
                ON scan_schedule_occurrences(schedule_id)
                WHERE state IN ('waiting', 'preparing', 'active', 'needs_attention');
            CREATE INDEX IF NOT EXISTS schedule_occurrence_history
                ON scan_schedule_occurrences(schedule_id, created_at DESC, occurrence_id);
            CREATE TABLE IF NOT EXISTS scan_schedule_chunks (
                occurrence_id TEXT NOT NULL,
                chunk_number INTEGER NOT NULL CHECK(chunk_number >= 1),
                targets_json TEXT NOT NULL,
                targets_digest TEXT NOT NULL CHECK(length(targets_digest) = 64),
                target_count INTEGER NOT NULL CHECK(target_count >= 1),
                state TEXT NOT NULL CHECK(state IN (
                    'waiting', 'preparing', 'active', 'complete', 'cancelled',
                    'needs_attention'
                )),
                contact_phase TEXT NOT NULL CHECK(contact_phase IN (
                    'not_started', 'preparing', 'contact_starting', 'contact_active',
                    'contact_stopped', 'complete', 'uncertain'
                )),
                scan_run_id TEXT UNIQUE,
                last_fencing_epoch INTEGER CHECK(last_fencing_epoch IS NULL OR last_fencing_epoch >= 1),
                attempt_count INTEGER NOT NULL DEFAULT 0 CHECK(attempt_count >= 0),
                created_at TEXT NOT NULL,
                started_at TEXT,
                completed_at TEXT,
                status_reason TEXT,
                PRIMARY KEY(occurrence_id, chunk_number),
                FOREIGN KEY(occurrence_id) REFERENCES scan_schedule_occurrences(occurrence_id)
                    ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS schedule_chunk_state
                ON scan_schedule_chunks(occurrence_id, state, chunk_number);
            CREATE TABLE IF NOT EXISTS scan_schedule_recovery_reviews (
                review_id TEXT PRIMARY KEY,
                occurrence_id TEXT NOT NULL UNIQUE,
                reviewed_by TEXT NOT NULL,
                reviewed_at TEXT NOT NULL,
                reason TEXT NOT NULL,
                confirmed_former_contact_stopped INTEGER NOT NULL CHECK(
                    confirmed_former_contact_stopped = 1
                ),
                FOREIGN KEY(occurrence_id) REFERENCES scan_schedule_occurrences(occurrence_id)
            );
            CREATE TRIGGER IF NOT EXISTS scan_schedule_definition_no_update
            BEFORE UPDATE ON scan_schedule_definitions
            BEGIN
                SELECT RAISE(ABORT, 'Schedule definitions are immutable');
            END;
            CREATE TRIGGER IF NOT EXISTS scan_schedule_occurrence_frozen_fields
            BEFORE UPDATE OF schedule_id, definition_version, definition_digest,
                due_at, trigger_kind, trigger_key, actor, frozen_json, frozen_digest,
                first_missed_due_at, latest_missed_due_at, skipped_due_count, created_at
            ON scan_schedule_occurrences
            BEGIN
                SELECT RAISE(ABORT, 'Schedule occurrence plan is immutable');
            END;
            CREATE TRIGGER IF NOT EXISTS scan_schedule_chunk_frozen_fields
            BEFORE UPDATE OF occurrence_id, chunk_number, targets_json, targets_digest,
                target_count, created_at
            ON scan_schedule_chunks
            BEGIN
                SELECT RAISE(ABORT, 'Schedule chunk plan is immutable');
            END;
            CREATE TRIGGER IF NOT EXISTS scan_schedule_chunk_complete_irreversible
            BEFORE UPDATE OF state ON scan_schedule_chunks
            WHEN OLD.state = 'complete' AND NEW.state != 'complete'
            BEGIN
                SELECT RAISE(ABORT, 'Completed schedule chunks cannot reopen');
            END;
            """
        )


def _db_now(connection: sqlite3.Connection) -> str:
    return str(connection.execute(
        "SELECT strftime('%Y-%m-%dT%H:%M:%fZ', 'now')"
    ).fetchone()[0])


def register_schedule_definition_on_connection(
    connection: sqlite3.Connection,
    schedule: dict,
    *,
    created_by: str,
) -> tuple[int, str]:
    version, digest, contract = definition_identity(schedule)
    connection.execute(
        """INSERT OR IGNORE INTO scan_schedule_definitions(
               schedule_id, definition_version, definition_digest, contract_json,
               created_at, created_by
           ) VALUES (?, ?, ?, ?, ?, ?)""",
        (
            schedule["schedule_id"], version, digest, canonical_json(contract),
            _db_now(connection), str(created_by).strip() or "system",
        ),
    )
    row = connection.execute(
        """SELECT definition_digest, contract_json
             FROM scan_schedule_definitions
            WHERE schedule_id = ? AND definition_version = ?""",
        (schedule["schedule_id"], version),
    ).fetchone()
    if row is None or tuple(row) != (digest, canonical_json(contract)):
        raise RuntimeError("The saved schedule definition identity changed")
    return version, digest


def register_schedule_definition(
    db_path: Path,
    schedule: dict,
    *,
    created_by: str,
) -> tuple[int, str]:
    init_scheduled_work_storage(db_path)
    with connect_database(db_path) as connection:
        connection.execute("BEGIN IMMEDIATE")
        return register_schedule_definition_on_connection(
            connection, schedule, created_by=created_by
        )


def migrate_legacy_schedules(db_path: Path) -> list[str]:
    """Give legacy definitions identity and close any ambiguous active batch."""
    init_scheduled_work_storage(db_path)
    migrated_attention: list[str] = []
    with connect_database(db_path) as connection:
        connection.execute("BEGIN IMMEDIATE")
        rows = connection.execute(
            "SELECT schedule_id, definition_json FROM scan_schedules"
        ).fetchall()
        for schedule_id, definition_json in rows:
            schedule = json.loads(definition_json)
            changed = False
            if not schedule.get("definition_version"):
                schedule["definition_version"] = 1
                changed = True
            version, digest, _contract = definition_identity(schedule)
            if schedule.get("definition_digest") != digest:
                schedule["definition_digest"] = digest
                changed = True
            register_schedule_definition_on_connection(
                connection,
                schedule,
                created_by=schedule.get("created_by") or "legacy-migration",
            )
            active = bool(schedule.get("active_batch_id")) or schedule.get("batch_status") in {
                "queued", "running", "recovery_pending", "paused_after_current_chunk",
                "failed_to_dispatch",
            }
            if active:
                due_at = str(
                    schedule.get("last_occurrence_started_at")
                    or schedule.get("next_run_at")
                    or schedule.get("updated_at")
                    or schedule.get("created_at")
                    or datetime.now(timezone.utc).replace(microsecond=0).isoformat()
                )
                trigger_key = f"legacy:{schedule.get('active_batch_id') or schedule_id}"
                occurrence_id = deterministic_occurrence_id(
                    schedule_id, version, due_at, "scheduled", trigger_key
                )
                reason = (
                    "Legacy active schedule state was ambiguous during schema upgrade; "
                    "the occurrence will not resume"
                )
                now = _db_now(connection)
                frozen = {
                    "legacy_migration": True,
                    "legacy_definition": schedule_definition_contract(schedule),
                    "ordered_chunks": schedule.get("active_target_chunks") or [],
                    "due_at": due_at,
                }
                connection.execute(
                    """INSERT OR IGNORE INTO scan_schedule_occurrences(
                           occurrence_id, schedule_id, definition_version,
                           definition_digest, due_at, trigger_kind, trigger_key, actor,
                           state, frozen_json, frozen_digest, skipped_due_count,
                           created_at, completed_at, status_reason
                       ) VALUES (?, ?, ?, ?, ?, 'scheduled', ?, 'legacy-migration',
                                 'needs_attention', ?, ?, 0, ?, ?, ?)""",
                    (
                        occurrence_id, schedule_id, version, digest, due_at, trigger_key,
                        canonical_json(frozen), content_digest(frozen), now, now, reason,
                    ),
                )
                completed = int(schedule.get("completed_chunk_count") or 0)
                active_number = int(schedule.get("active_chunk_number") or completed + 1)
                for number, targets in enumerate(
                    schedule.get("active_target_chunks") or [], start=1
                ):
                    state = "complete" if number <= completed else (
                        "needs_attention" if number == active_number else "waiting"
                    )
                    phase = "complete" if state == "complete" else (
                        "uncertain" if state == "needs_attention" else "not_started"
                    )
                    connection.execute(
                        """INSERT OR IGNORE INTO scan_schedule_chunks(
                               occurrence_id, chunk_number, targets_json, targets_digest,
                               target_count, state, contact_phase, created_at,
                               completed_at, status_reason
                           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (
                            occurrence_id, number, canonical_json(targets),
                            content_digest(targets), len(targets), state, phase, now,
                            now if state in {"complete", "needs_attention"} else None,
                            reason if state == "needs_attention" else None,
                        ),
                    )
                schedule["enabled"] = False
                schedule["batch_status"] = "needs_attention"
                schedule["active_batch_id"] = occurrence_id
                schedule["last_occurrence_batch_id"] = occurrence_id
                schedule["last_occurrence_status"] = "needs_attention"
                schedule["next_run_at"] = None
                schedule["last_dispatch_note"] = reason
                changed = True
                migrated_attention.append(schedule_id)
            if changed:
                connection.execute(
                    """UPDATE scan_schedules
                          SET definition_json = ? WHERE schedule_id = ?""",
                    (json.dumps(schedule, sort_keys=True), schedule_id),
                )
    return migrated_attention


@dataclass(frozen=True)
class PreparedOccurrence:
    occurrence_id: str
    schedule_id: str
    state: str
    chunk_count: int
    created: bool


def prepare_occurrence(
    db_path: Path,
    *,
    schedule: dict,
    due_at: str,
    trigger_kind: str,
    trigger_key: str,
    actor: str,
    frozen_contract: dict,
    chunks: list[list[str]],
    next_due_at: str | None,
    first_missed_due_at: str | None = None,
    latest_missed_due_at: str | None = None,
    skipped_due_count: int = 0,
    transaction_guard: Callable[[sqlite3.Connection], None] | None = None,
) -> PreparedOccurrence:
    if trigger_kind not in {"scheduled", "manual"}:
        raise ValueError("Unknown schedule trigger")
    if not chunks or any(not chunk for chunk in chunks):
        raise ValueError("A scheduled occurrence requires at least one non-empty chunk")
    init_scheduled_work_storage(db_path)
    version, digest, contract = definition_identity(schedule)
    occurrence_id = deterministic_occurrence_id(
        schedule["schedule_id"], version, due_at, trigger_kind, trigger_key
    )
    plan_basis = {
        "schedule_id": schedule["schedule_id"],
        "definition_version": version,
        "definition_digest": digest,
        "trigger_kind": trigger_kind,
        "trigger_key": trigger_key,
        "actor": actor,
        "frozen_contract": frozen_contract,
        "ordered_chunks": chunks,
    }
    frozen = {
        **frozen_contract,
        "schedule_id": schedule["schedule_id"],
        "definition_version": version,
        "definition_digest": digest,
        "definition": contract,
        "due_at": due_at,
        "trigger_kind": trigger_kind,
        "trigger_key": trigger_key,
        "actor": actor,
        "ordered_chunks": chunks,
        "idempotency_digest": content_digest(plan_basis),
    }
    frozen_json = canonical_json(frozen)
    frozen_digest = content_digest(frozen)
    with connect_database(db_path) as connection:
        connection.execute("BEGIN IMMEDIATE")
        row = connection.execute(
            "SELECT definition_json FROM scan_schedules WHERE schedule_id = ?",
            (schedule["schedule_id"],),
        ).fetchone()
        if row is None:
            raise KeyError("Scan schedule not found")
        current = json.loads(row[0])
        if definition_identity(current)[:2] != (version, digest):
            raise RuntimeError("The schedule changed while its occurrence was prepared")
        if transaction_guard is not None:
            transaction_guard(connection)
        frozen_global = frozen_contract.get("global_no_strike") or {}
        if "revision" in frozen_global:
            live_global = connection.execute(
                "SELECT COALESCE(MAX(revision), 0) FROM global_no_strike_history"
            ).fetchone()
            if int(live_global[0] if live_global else 0) != int(frozen_global["revision"]):
                raise RuntimeError(
                    "The Global No-Strike list changed while this occurrence was prepared"
                )
        register_schedule_definition_on_connection(
            connection, current, created_by=actor
        )
        existing = connection.execute(
            """SELECT state, frozen_json FROM scan_schedule_occurrences
                WHERE occurrence_id = ?""",
            (occurrence_id,),
        ).fetchone()
        if existing is not None:
            retained = json.loads(existing[1])
            if retained.get("idempotency_digest") != frozen["idempotency_digest"]:
                raise WorkLeaseConflict(
                    "This occurrence request was already accepted with a different frozen plan"
                )
            return PreparedOccurrence(
                occurrence_id, schedule["schedule_id"], existing[0], len(chunks), False
            )
        blocked = connection.execute(
            """SELECT occurrence_id, state FROM scan_schedule_occurrences
                WHERE schedule_id = ?
                  AND state IN ('waiting','preparing','active','needs_attention')
                LIMIT 1""",
            (schedule["schedule_id"],),
        ).fetchone()
        if blocked is not None:
            raise WorkLeaseConflict(
                "This schedule already has an occurrence waiting, active, or needing attention"
            )
        now = _db_now(connection)
        connection.execute(
            """INSERT INTO scan_schedule_occurrences(
                   occurrence_id, schedule_id, definition_version,
                   definition_digest, due_at, trigger_kind, trigger_key, actor,
                   state, frozen_json, frozen_digest, first_missed_due_at,
                   latest_missed_due_at, skipped_due_count, created_at
               ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'waiting', ?, ?, ?, ?, ?, ?)""",
            (
                occurrence_id, schedule["schedule_id"], version, digest, due_at,
                trigger_kind, trigger_key, actor, frozen_json, frozen_digest,
                first_missed_due_at, latest_missed_due_at, int(skipped_due_count), now,
            ),
        )
        for number, targets in enumerate(chunks, start=1):
            targets_json = canonical_json(targets)
            connection.execute(
                """INSERT INTO scan_schedule_chunks(
                       occurrence_id, chunk_number, targets_json, targets_digest,
                       target_count, state, contact_phase, created_at
                   ) VALUES (?, ?, ?, ?, ?, 'waiting', 'not_started', ?)""",
                (
                    occurrence_id, number, targets_json, content_digest(targets),
                    len(targets), now,
                ),
            )
        current["next_run_at"] = next_due_at
        current["batch_status"] = "waiting"
        current["active_batch_id"] = occurrence_id
        current["active_chunk_number"] = 0
        current["active_chunk_count"] = len(chunks)
        current["completed_chunk_count"] = 0
        current["resume_after_chunk"] = 0
        current["active_target_chunks"] = chunks
        current["last_occurrence_batch_id"] = occurrence_id
        current["last_occurrence_status"] = "waiting"
        current["last_dispatch_note"] = "Due now — waiting for scanner"
        if next_due_at is None and current.get("cadence") == "once":
            current["enabled"] = False
        current["updated_at"] = now
        connection.execute(
            """UPDATE scan_schedules
                  SET name = ?, profile_id = ?, profile_version = ?, definition_json = ?
                WHERE schedule_id = ?""",
            (
                current["name"], current["profile_id"], current["profile_version"],
                json.dumps(current, sort_keys=True), current["schedule_id"],
            ),
        )
    return PreparedOccurrence(
        occurrence_id, schedule["schedule_id"], "waiting", len(chunks), True
    )


def occurrence_record(row: tuple | None) -> dict | None:
    if row is None:
        return None
    return {
        "occurrence_id": row[0], "schedule_id": row[1],
        "definition_version": int(row[2]), "definition_digest": row[3],
        "due_at": row[4], "trigger_kind": row[5], "trigger_key": row[6],
        "actor": row[7], "state": row[8], "frozen": json.loads(row[9]),
        "frozen_digest": row[10], "first_missed_due_at": row[11],
        "latest_missed_due_at": row[12], "skipped_due_count": int(row[13]),
        "created_at": row[14], "started_at": row[15], "completed_at": row[16],
        "status_reason": row[17],
    }


def get_occurrence(db_path: Path, occurrence_id: str) -> dict | None:
    init_scheduled_work_storage(db_path)
    with connect_database(db_path, read_only=True) as connection:
        row = connection.execute(
            """SELECT occurrence_id, schedule_id, definition_version,
                      definition_digest, due_at, trigger_kind, trigger_key, actor,
                      state, frozen_json, frozen_digest, first_missed_due_at,
                      latest_missed_due_at, skipped_due_count, created_at,
                      started_at, completed_at, status_reason
                 FROM scan_schedule_occurrences WHERE occurrence_id = ?""",
            (occurrence_id,),
        ).fetchone()
        result = occurrence_record(row)
        if result is None:
            return None
        chunks = connection.execute(
            """SELECT chunk_number, targets_json, targets_digest, target_count,
                      state, contact_phase, scan_run_id, last_fencing_epoch,
                      attempt_count, created_at, started_at, completed_at, status_reason
                 FROM scan_schedule_chunks WHERE occurrence_id = ?
                ORDER BY chunk_number""",
            (occurrence_id,),
        ).fetchall()
    result["chunks"] = [
        {
            "chunk_number": int(item[0]), "targets": json.loads(item[1]),
            "targets_digest": item[2], "target_count": int(item[3]),
            "state": item[4], "contact_phase": item[5], "scan_run_id": item[6],
            "last_fencing_epoch": item[7], "attempt_count": int(item[8]),
            "created_at": item[9], "started_at": item[10],
            "completed_at": item[11], "status_reason": item[12],
        }
        for item in chunks
    ]
    return result


def list_schedule_occurrences(
    db_path: Path, schedule_id: str, *, limit: int = 20
) -> list[dict]:
    init_scheduled_work_storage(db_path)
    with connect_database(db_path, read_only=True) as connection:
        rows = connection.execute(
            """SELECT occurrence_id FROM scan_schedule_occurrences
                WHERE schedule_id = ? ORDER BY created_at DESC, occurrence_id DESC
                LIMIT ?""",
            (schedule_id, max(1, min(int(limit), 100))),
        ).fetchall()
    return [item for row in rows if (item := get_occurrence(db_path, row[0]))]


def claim_next_chunk(
    db_path: Path,
    occurrence_id: str,
    *,
    owner_id: str,
    lease_seconds: int = 30,
) -> tuple[dict, WorkLease] | None:
    init_scheduled_work_storage(db_path)
    with connect_database(db_path) as connection:
        connection.execute("BEGIN IMMEDIATE")
        occurrence = connection.execute(
            "SELECT state FROM scan_schedule_occurrences WHERE occurrence_id = ?",
            (occurrence_id,),
        ).fetchone()
        if occurrence is None:
            raise KeyError("Scheduled occurrence not found")
        if occurrence[0] == "needs_attention":
            raise WorkRecoveryRequired("This occurrence requires administrator review")
        if occurrence[0] in {"complete", "cancelled", "missed"}:
            return None
        row = connection.execute(
            """SELECT chunk_number, targets_json, state, contact_phase, scan_run_id
                 FROM scan_schedule_chunks
                WHERE occurrence_id = ? AND state NOT IN ('complete','cancelled')
                ORDER BY chunk_number LIMIT 1""",
            (occurrence_id,),
        ).fetchone()
        if row is None:
            return None
        number, targets_json, state, phase, scan_run_id = row
        if state == "needs_attention" or phase in {"contact_starting", "contact_active", "uncertain"}:
            raise WorkRecoveryRequired("The next schedule chunk requires administrator review")
        policy = "reclaim" if phase in {"not_started", "preparing"} else "recovery_required"
        lease = acquire_work_lease_on_connection(
            connection,
            lease_key=f"schedule-chunk:{occurrence_id}:{int(number)}",
            work_kind="scheduled_scan_chunk",
            work_id=f"{occurrence_id}:{int(number)}",
            owner_id=owner_id,
            lease_seconds=lease_seconds,
            expired_policy=policy,
        )
        now = _db_now(connection)
        changed = connection.execute(
            """UPDATE scan_schedule_chunks
                  SET state = 'preparing', contact_phase = 'preparing',
                      last_fencing_epoch = ?, attempt_count = attempt_count + 1,
                      started_at = COALESCE(started_at, ?), status_reason = NULL
                WHERE occurrence_id = ? AND chunk_number = ?
                  AND state IN ('waiting','preparing')
                  AND contact_phase IN ('not_started','preparing')""",
            (lease.fencing_epoch, now, occurrence_id, int(number)),
        ).rowcount
        if changed != 1:
            raise WorkLeaseConflict("The next schedule chunk changed before it was claimed")
        connection.execute(
            """UPDATE scan_schedule_occurrences
                  SET state = 'preparing', started_at = COALESCE(started_at, ?)
                WHERE occurrence_id = ? AND state IN ('waiting','preparing')""",
            (now, occurrence_id),
        )
        if scan_run_id:
            run_row = connection.execute(
                "SELECT manifest_json FROM scan_runs WHERE run_id = ?",
                (scan_run_id,),
            ).fetchone()
            if run_row is None:
                raise WorkLeaseConflict("The scan bound to this chunk is missing")
            manifest = json.loads(run_row[0])
            if manifest.get("started_at"):
                raise WorkRecoveryRequired(
                    "The bound scan may have started contact and cannot be rebound"
                )
            manifest["status"] = "queued"
            manifest.pop("execution_claim", None)
            manifest["work_claim"] = {
                **lease.as_claim(),
                "occurrence_id": occurrence_id,
                "chunk_number": int(number),
            }
            changed = connection.execute(
                """UPDATE scan_runs SET status = 'queued', manifest_json = ?
                     WHERE run_id = ? AND status IN ('queued','dispatching')""",
                (json.dumps(manifest, sort_keys=True), scan_run_id),
            ).rowcount
            if changed != 1:
                raise WorkLeaseConflict(
                    "The bound scan changed before its new owner could adopt it"
                )
        return (
            {
                "occurrence_id": occurrence_id, "chunk_number": int(number),
                "targets": json.loads(targets_json), "scan_run_id": scan_run_id,
            },
            lease,
        )


def bind_chunk_scan_run(
    db_path: Path,
    *,
    occurrence_id: str,
    chunk_number: int,
    scan_run_id: str,
    lease: WorkLease | dict[str, object],
) -> str:
    init_scheduled_work_storage(db_path)
    with connect_database(db_path) as connection:
        connection.execute("BEGIN IMMEDIATE")
        assert_work_lease_on_connection(connection, lease)
        row = connection.execute(
            """SELECT scan_run_id, state FROM scan_schedule_chunks
                WHERE occurrence_id = ? AND chunk_number = ?""",
            (occurrence_id, int(chunk_number)),
        ).fetchone()
        if row is None:
            raise KeyError("Scheduled chunk not found")
        if row[0] and row[0] != scan_run_id:
            raise WorkLeaseConflict("This schedule chunk is already bound to another scan")
        connection.execute(
            """UPDATE scan_schedule_chunks SET scan_run_id = ?
                WHERE occurrence_id = ? AND chunk_number = ?""",
            (scan_run_id, occurrence_id, int(chunk_number)),
        )
    return scan_run_id


def bind_chunk_scan_run_on_connection(
    connection: sqlite3.Connection,
    *,
    occurrence_id: str,
    chunk_number: int,
    scan_run_id: str,
    lease: WorkLease | dict[str, object],
) -> str:
    assert_work_lease_on_connection(connection, lease)
    row = connection.execute(
        """SELECT scan_run_id FROM scan_schedule_chunks
            WHERE occurrence_id = ? AND chunk_number = ?""",
        (occurrence_id, int(chunk_number)),
    ).fetchone()
    if row is None:
        raise KeyError("Scheduled chunk not found")
    if row[0] and row[0] != scan_run_id:
        raise WorkLeaseConflict("This schedule chunk is already bound to another scan")
    connection.execute(
        """UPDATE scan_schedule_chunks SET scan_run_id = ?
            WHERE occurrence_id = ? AND chunk_number = ?""",
        (scan_run_id, occurrence_id, int(chunk_number)),
    )
    return scan_run_id


def mark_chunk_contact_starting(
    db_path: Path,
    *,
    occurrence_id: str,
    chunk_number: int,
    lease: WorkLease | dict[str, object],
) -> None:
    init_scheduled_work_storage(db_path)
    with connect_database(db_path) as connection:
        connection.execute("BEGIN IMMEDIATE")
        mark_chunk_contact_starting_on_connection(
            connection,
            occurrence_id=occurrence_id,
            chunk_number=chunk_number,
            lease=lease,
        )


def mark_chunk_contact_starting_on_connection(
    connection: sqlite3.Connection,
    *,
    occurrence_id: str,
    chunk_number: int,
    lease: WorkLease | dict[str, object],
) -> None:
    """Publish contact start under a caller-owned transaction and current fence."""
    assert_work_lease_on_connection(connection, lease)
    changed = connection.execute(
        """UPDATE scan_schedule_chunks
              SET state = 'active', contact_phase = 'contact_starting'
            WHERE occurrence_id = ? AND chunk_number = ?
              AND state = 'preparing' AND contact_phase = 'preparing'
              AND scan_run_id IS NOT NULL""",
        (occurrence_id, int(chunk_number)),
    ).rowcount
    if changed != 1:
        raise WorkLeaseConflict("The schedule chunk is not ready to start contact")
    connection.execute(
        "UPDATE scan_schedule_occurrences SET state = 'active' WHERE occurrence_id = ?",
        (occurrence_id,),
    )


def abandon_chunk_after_worker_error(
    db_path: Path,
    *,
    occurrence_id: str,
    chunk_number: int,
    lease: WorkLease | dict[str, object],
    reason: str,
) -> str:
    """Release pre-contact work or fail closed after a claimed-worker error."""
    init_scheduled_work_storage(db_path)
    with connect_database(db_path) as connection:
        connection.execute("BEGIN IMMEDIATE")
        assert_work_lease_on_connection(connection, lease)
        row = connection.execute(
            """SELECT contact_phase FROM scan_schedule_chunks
                 WHERE occurrence_id = ? AND chunk_number = ?""",
            (occurrence_id, int(chunk_number)),
        ).fetchone()
        if row is None:
            raise KeyError("Scheduled chunk not found")
        if row[0] in {"not_started", "preparing"}:
            connection.execute(
                """UPDATE scan_schedule_chunks
                      SET state = 'waiting', contact_phase = 'not_started',
                          status_reason = ?
                    WHERE occurrence_id = ? AND chunk_number = ?""",
                (reason[:500], occurrence_id, int(chunk_number)),
            )
            connection.execute(
                """UPDATE scan_schedule_occurrences SET state = 'waiting',
                          status_reason = ? WHERE occurrence_id = ?""",
                (reason[:500], occurrence_id),
            )
            release_work_lease_on_connection(
                connection, lease, detail="Released after a pre-contact worker error"
            )
            return "waiting"
        return publish_chunk_terminal_on_connection(
            connection,
            occurrence_id=occurrence_id,
            chunk_number=int(chunk_number),
            terminal_state="needs_attention",
            reason=reason,
            lease=lease,
        )


def publish_chunk_terminal(
    db_path: Path,
    *,
    occurrence_id: str,
    chunk_number: int,
    terminal_state: str,
    reason: str,
    lease: WorkLease | dict[str, object],
) -> dict:
    if terminal_state not in {"complete", "cancelled", "needs_attention"}:
        raise ValueError("Unknown schedule chunk terminal state")
    init_scheduled_work_storage(db_path)
    with connect_database(db_path) as connection:
        connection.execute("BEGIN IMMEDIATE")
        publish_chunk_terminal_on_connection(
            connection,
            occurrence_id=occurrence_id,
            chunk_number=chunk_number,
            terminal_state=terminal_state,
            reason=reason,
            lease=lease,
        )
    return get_occurrence(db_path, occurrence_id) or {}


def publish_chunk_terminal_on_connection(
    connection: sqlite3.Connection,
    *,
    occurrence_id: str,
    chunk_number: int,
    terminal_state: str,
    reason: str,
    lease: WorkLease | dict[str, object],
    contact_started: bool = True,
) -> str:
    if terminal_state not in {"complete", "cancelled", "needs_attention"}:
        raise ValueError("Unknown schedule chunk terminal state")
    assert_work_lease_on_connection(connection, lease)
    now = _db_now(connection)
    phase = "complete" if terminal_state == "complete" else (
        ("contact_stopped" if contact_started else "not_started")
        if terminal_state == "cancelled" else "uncertain"
    )
    changed = connection.execute(
        """UPDATE scan_schedule_chunks
              SET state = ?, contact_phase = ?, completed_at = ?, status_reason = ?
            WHERE occurrence_id = ? AND chunk_number = ?
              AND state IN ('preparing','active')""",
        (
            terminal_state, phase, now, reason[:500], occurrence_id,
            int(chunk_number),
        ),
    ).rowcount
    if changed != 1:
        raise WorkLeaseConflict("The schedule chunk can no longer publish its result")
    if terminal_state == "cancelled":
        connection.execute(
            """UPDATE scan_schedule_chunks
                  SET state = 'cancelled', contact_phase = 'not_started',
                      completed_at = ?, status_reason = ?
                WHERE occurrence_id = ? AND chunk_number > ? AND state = 'waiting'""",
            (now, "Occurrence cancelled before this chunk started", occurrence_id, int(chunk_number)),
        )
    release_work_lease_on_connection(
        connection, lease, detail=f"Chunk {chunk_number}: {terminal_state}"
    )
    remaining = int(connection.execute(
        """SELECT COUNT(*) FROM scan_schedule_chunks
            WHERE occurrence_id = ? AND state NOT IN ('complete','cancelled')""",
        (occurrence_id,),
    ).fetchone()[0])
    if terminal_state == "needs_attention":
        occurrence_state = "needs_attention"
    elif terminal_state == "cancelled":
        occurrence_state = "cancelled"
    elif remaining == 0:
        occurrence_state = "complete"
    else:
        occurrence_state = "waiting"
    connection.execute(
        """UPDATE scan_schedule_occurrences
              SET state = ?, completed_at = CASE WHEN ? IN ('complete','cancelled','needs_attention')
                                                 THEN ? ELSE completed_at END,
                  status_reason = ?
            WHERE occurrence_id = ?""",
        (occurrence_state, occurrence_state, now, reason[:500], occurrence_id),
    )
    return occurrence_state


def recover_schedule_occurrences(
    db_path: Path, *, owner_process_ended: bool = False
) -> list[str]:
    """Close post-contact orphaned work; leave pre-contact work safely claimable."""
    init_scheduled_work_storage(db_path)
    recovered: list[str] = []
    with connect_database(db_path) as connection:
        connection.execute("BEGIN IMMEDIATE")
        expiry_filter = (
            "" if owner_process_ended
            else "AND l.expires_at <= strftime('%Y-%m-%dT%H:%M:%fZ', 'now')"
        )
        rows = connection.execute(
            """SELECT c.occurrence_id, c.chunk_number, c.contact_phase, c.state,
                      l.fencing_epoch, l.lease_id, l.owner_id
                 FROM scan_schedule_chunks c
                 JOIN work_leases l
                   ON l.lease_key = ('schedule-chunk:' || c.occurrence_id || ':' || c.chunk_number)
                WHERE l.state = 'active'
                  """ + expiry_filter + """
                  AND c.state IN ('preparing','active')"""
        ).fetchall()
        now = _db_now(connection)
        for occurrence_id, number, phase, _state, epoch, lease_id, owner_id in rows:
            lease_key = f"schedule-chunk:{occurrence_id}:{int(number)}"
            if phase in {"not_started", "preparing"}:
                connection.execute(
                    """UPDATE scan_schedule_chunks
                          SET state = 'waiting', contact_phase = 'not_started',
                              status_reason = 'Previous owner ended before network contact; safe to retry'
                        WHERE occurrence_id = ? AND chunk_number = ?""",
                    (occurrence_id, int(number)),
                )
                connection.execute(
                    """UPDATE work_leases
                          SET lease_id = NULL, owner_id = NULL, state = 'released',
                              expires_at = NULL, released_at = ?, renewed_at = ?
                        WHERE lease_key = ?""",
                    (now, now, lease_key),
                )
                connection.execute(
                    """INSERT INTO work_lease_events(
                           event_id, lease_key, fencing_epoch, lease_id, owner_id,
                           event_kind, recorded_at, detail
                       ) VALUES (?, ?, ?, ?, ?, 'released', ?, ?)""",
                    (
                        uuid.uuid4().hex, lease_key, int(epoch), lease_id, owner_id,
                        now, "Previous owner ended before network contact; safe to retry",
                    ),
                )
            else:
                reason = "The former worker may still be scanning; this occurrence will not resume"
                connection.execute(
                    """UPDATE scan_schedule_chunks
                          SET state = 'needs_attention', contact_phase = 'uncertain',
                              completed_at = ?, status_reason = ?
                        WHERE occurrence_id = ? AND chunk_number = ?""",
                    (now, reason, occurrence_id, int(number)),
                )
                connection.execute(
                    """UPDATE scan_schedule_occurrences
                          SET state = 'needs_attention', completed_at = ?, status_reason = ?
                        WHERE occurrence_id = ?""",
                    (now, reason, occurrence_id),
                )
                connection.execute(
                    """UPDATE work_leases
                          SET lease_id = NULL, owner_id = NULL, state = 'recovery_required',
                              expires_at = NULL, released_at = ?, recovery_reason = ?
                        WHERE lease_key = ?""",
                    (now, reason, lease_key),
                )
                connection.execute(
                    """INSERT INTO work_lease_events(
                           event_id, lease_key, fencing_epoch, lease_id, owner_id,
                           event_kind, recorded_at, detail
                       ) VALUES (?, ?, ?, ?, ?, 'recovery_required', ?, ?)""",
                    (
                        uuid.uuid4().hex, lease_key, int(epoch), lease_id, owner_id,
                        now, reason,
                    ),
                )
                connection.execute(
                    "UPDATE scan_schedules SET definition_json = json_set(definition_json, '$.enabled', 0, '$.batch_status', 'needs_attention', '$.last_dispatch_note', ?) WHERE schedule_id = (SELECT schedule_id FROM scan_schedule_occurrences WHERE occurrence_id = ?)",
                    (reason, occurrence_id),
                )
                recovered.append(occurrence_id)
        connection.execute(
            """UPDATE scan_schedule_occurrences SET state = 'waiting'
                WHERE state = 'preparing' AND occurrence_id IN (
                    SELECT occurrence_id FROM scan_schedule_chunks
                    GROUP BY occurrence_id
                    HAVING SUM(CASE WHEN state IN ('active','preparing') THEN 1 ELSE 0 END) = 0
                       AND SUM(CASE WHEN state = 'needs_attention' THEN 1 ELSE 0 END) = 0
                )"""
        )
    return sorted(set(recovered))


def close_reviewed_occurrence(
    db_path: Path,
    occurrence_id: str,
    *,
    reviewed_by: str,
    reason: str,
    confirmed_former_contact_stopped: bool,
) -> dict:
    """Close ambiguous work only after an operator verifies former contact stopped."""
    actor = str(reviewed_by or "").strip()
    explanation = str(reason or "").strip()
    if not confirmed_former_contact_stopped:
        raise ValueError("Confirm that the former scanner is stopped")
    if not actor or len(actor) > 120:
        raise ValueError("Reviewer identity is required")
    if len(explanation) < 8 or len(explanation) > 500:
        raise ValueError("A recovery reason between 8 and 500 characters is required")
    init_scheduled_work_storage(db_path)
    with connect_database(db_path) as connection:
        connection.execute("BEGIN IMMEDIATE")
        occurrence = connection.execute(
            """SELECT schedule_id, state FROM scan_schedule_occurrences
                 WHERE occurrence_id = ?""",
            (occurrence_id,),
        ).fetchone()
        if occurrence is None:
            raise KeyError("Scheduled occurrence not found")
        if occurrence[1] != "needs_attention":
            raise WorkLeaseConflict("Only an occurrence needing attention can be closed")
        now = _db_now(connection)
        rows = connection.execute(
            """SELECT chunk_number, state, scan_run_id FROM scan_schedule_chunks
                 WHERE occurrence_id = ? ORDER BY chunk_number""",
            (occurrence_id,),
        ).fetchall()
        scan_run_ids = {row[2] for row in rows if row[2]}
        for number, state, _scan_run_id in rows:
            lease_key = f"schedule-chunk:{occurrence_id}:{int(number)}"
            lease_row = connection.execute(
                """SELECT fencing_epoch, state FROM work_leases
                     WHERE lease_key = ?""",
                (lease_key,),
            ).fetchone()
            if lease_row and lease_row[1] == "active":
                raise WorkLeaseConflict(
                    "The former scanner still has an active saved ownership record"
                )
            if lease_row and lease_row[1] == "recovery_required":
                connection.execute(
                    """UPDATE work_leases
                          SET state = 'released', released_at = ?, renewed_at = ?,
                              recovery_reason = NULL
                        WHERE lease_key = ? AND state = 'recovery_required'""",
                    (now, now, lease_key),
                )
                connection.execute(
                    """INSERT INTO work_lease_events(
                           event_id, lease_key, fencing_epoch, lease_id, owner_id,
                           event_kind, recorded_at, detail
                       ) VALUES (?, ?, ?, NULL, NULL, 'recovery_cleared', ?, ?)""",
                    (
                        uuid.uuid4().hex, lease_key, int(lease_row[0]), now,
                        f"{actor}: {explanation}",
                    ),
                )
            if state == "waiting":
                connection.execute(
                    """UPDATE scan_schedule_chunks
                          SET state = 'cancelled', contact_phase = 'not_started',
                              completed_at = ?, status_reason = ?
                        WHERE occurrence_id = ? AND chunk_number = ?""",
                    (
                        now, "Cancelled during reviewed recovery; never started",
                        occurrence_id, int(number),
                    ),
                )
        capacity = connection.execute(
            """SELECT lease_key, work_id, fencing_epoch, state
                 FROM work_leases WHERE lease_key = 'scan-capacity:primary'"""
        ).fetchone()
        if capacity and capacity[3] == "recovery_required" and capacity[1] in scan_run_ids:
            connection.execute(
                """UPDATE work_leases
                      SET state = 'released', released_at = ?, renewed_at = ?,
                          recovery_reason = NULL
                    WHERE lease_key = ? AND fencing_epoch = ?
                      AND state = 'recovery_required'""",
                (now, now, capacity[0], int(capacity[2])),
            )
            connection.execute(
                """INSERT INTO work_lease_events(
                       event_id, lease_key, fencing_epoch, lease_id, owner_id,
                       event_kind, recorded_at, detail
                   ) VALUES (?, ?, ?, NULL, NULL, 'recovery_cleared', ?, ?)""",
                (
                    uuid.uuid4().hex, capacity[0], int(capacity[2]), now,
                    f"{actor}: {explanation}",
                ),
            )
        connection.execute(
            """UPDATE scan_schedule_occurrences
                  SET state = 'cancelled', completed_at = ?, status_reason = ?
                WHERE occurrence_id = ? AND state = 'needs_attention'""",
            (
                now,
                f"Reviewed and closed by {actor}; ambiguous contact was not resumed",
                occurrence_id,
            ),
        )
        connection.execute(
            """INSERT INTO scan_schedule_recovery_reviews(
                   review_id, occurrence_id, reviewed_by, reviewed_at, reason,
                   confirmed_former_contact_stopped
               ) VALUES (?, ?, ?, ?, ?, 1)""",
            (uuid.uuid4().hex, occurrence_id, actor, now, explanation),
        )
        schedule_row = connection.execute(
            "SELECT definition_json FROM scan_schedules WHERE schedule_id = ?",
            (occurrence[0],),
        ).fetchone()
        schedule = json.loads(schedule_row[0])
        schedule.update({
            "enabled": False,
            "active_batch_id": None,
            "batch_status": "reviewed_closed",
            "last_occurrence_status": "cancelled",
            "last_occurrence_completed_at": now,
            "last_dispatch_note": (
                "Interrupted occurrence reviewed and closed. Future occurrences remain paused."
            ),
            "updated_at": now,
            "control_revision": int(schedule.get("control_revision") or 0) + 1,
        })
        connection.execute(
            "UPDATE scan_schedules SET definition_json = ? WHERE schedule_id = ?",
            (json.dumps(schedule, sort_keys=True), occurrence[0]),
        )
    return {
        "occurrence_id": occurrence_id,
        "schedule_id": occurrence[0],
        "state": "cancelled",
        "reviewed_by": actor,
        "reviewed_at": now,
    }
