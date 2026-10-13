from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
import uuid

from app.build_info import APP_VERSION, BUILD_COMMIT, BUILD_ID
from app.database import connect_database


SCHEMA_CONTRACT_VERSION = 5
WRITABLE_SCHEMA_VERSION = 5
READABLE_SCHEMA_VERSIONS = (1, 2, 3, 4, 5)
DATA_LAYOUT_CONTRACT = "nct-data-layout-v1"
LEGACY_MIGRATION_ID = "nct-foundation-data-contract-v1"
WORK_COORDINATION_MIGRATION_ID = "nct-work-coordination-v2"
SCHEDULED_WORK_MIGRATION_ID = "nct-scheduled-occurrences-v3"
DEVICE_CONTACT_MIGRATION_ID = "nct-device-contact-fencing-v4"
MIGRATION_ID = "nct-mission-environment-v5"
MIGRATION_PLAN = (
    LEGACY_MIGRATION_ID,
    WORK_COORDINATION_MIGRATION_ID,
    SCHEDULED_WORK_MIGRATION_ID,
    DEVICE_CONTACT_MIGRATION_ID,
    MIGRATION_ID,
)


class SchemaCompatibilityError(RuntimeError):
    pass


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def migration_plan_digest() -> str:
    return _digest({"migration_ids": list(MIGRATION_PLAN)})


def image_schema_contract() -> dict[str, object]:
    """Return the compatibility statement owned by this exact application image."""
    body: dict[str, object] = {
        "schema_contract_version": SCHEMA_CONTRACT_VERSION,
        "application_version": APP_VERSION,
        "build_id": BUILD_ID,
        "build_commit": BUILD_COMMIT,
        "readable_schema_versions": list(READABLE_SCHEMA_VERSIONS),
        "writable_schema_version": WRITABLE_SCHEMA_VERSION,
        "data_layout_contract": DATA_LAYOUT_CONTRACT,
        "migration_ids": list(MIGRATION_PLAN),
        "migration_plan_digest": migration_plan_digest(),
        "direct_rollback_rule": (
            "The current data schema must be both readable and writable by the old image; "
            "the data-layout contract and completed migration-plan digest must match exactly."
        ),
    }
    return {**body, "contract_digest": _digest(body)}


def schema_fingerprint(connection: sqlite3.Connection) -> str:
    rows = connection.execute(
        """SELECT type, name, tbl_name, COALESCE(sql, '')
             FROM sqlite_master
            WHERE name NOT LIKE 'sqlite_%'
            ORDER BY type, name, tbl_name, sql"""
    ).fetchall()
    return _digest([list(row) for row in rows])


def _ensure_storage(connection: sqlite3.Connection) -> None:
    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS nct_schema_state (
            singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
            schema_contract_version INTEGER NOT NULL,
            schema_version INTEGER NOT NULL,
            data_layout_contract TEXT NOT NULL,
            migration_plan_digest TEXT NOT NULL,
            schema_fingerprint TEXT,
            originating_build_id TEXT NOT NULL,
            originating_build_commit TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS nct_schema_migrations (
            migration_id TEXT PRIMARY KEY,
            target_schema_version INTEGER NOT NULL,
            originating_build_id TEXT NOT NULL,
            originating_build_commit TEXT NOT NULL,
            status TEXT NOT NULL CHECK(status IN ('started', 'completed', 'failed')),
            attempts INTEGER NOT NULL CHECK(attempts >= 1),
            first_started_at TEXT NOT NULL,
            last_started_at TEXT NOT NULL,
            completed_at TEXT,
            before_schema_fingerprint TEXT NOT NULL,
            after_schema_fingerprint TEXT,
            error_summary TEXT
        );
        """
    )


@dataclass(frozen=True)
class MigrationAttempt:
    migration_id: str
    target_schema_version: int
    attempt: int


def begin_schema_migration(db_path: Path) -> MigrationAttempt | None:
    """Start or resume the image-owned migration before other schema writers run."""
    now = _utc_now()
    with connect_database(db_path) as connection:
        _ensure_storage(connection)
        state = connection.execute(
            """SELECT schema_contract_version, schema_version, data_layout_contract,
                      migration_plan_digest
                 FROM nct_schema_state WHERE singleton = 1"""
        ).fetchone()
        if state is not None:
            contract_version, schema_version, layout, plan_digest = state
            if int(contract_version) > SCHEMA_CONTRACT_VERSION:
                raise SchemaCompatibilityError(
                    "The saved schema contract is newer than this image supports."
                )
            if int(schema_version) not in READABLE_SCHEMA_VERSIONS and int(schema_version) != 0:
                raise SchemaCompatibilityError(
                    "The saved data schema is not readable by this image."
                )
            if layout != DATA_LAYOUT_CONTRACT:
                raise SchemaCompatibilityError(
                    "The saved evidence layout is not compatible with this image."
                )
            if int(schema_version) == 0:
                pending = connection.execute(
                    """SELECT migration_id, status FROM nct_schema_migrations
                         WHERE status IN ('started', 'failed')
                         ORDER BY last_started_at DESC LIMIT 1"""
                ).fetchone()
                if pending is None:
                    raise SchemaCompatibilityError(
                        "The bootstrap schema state has no resumable migration."
                    )
            elif int(schema_version) == WRITABLE_SCHEMA_VERSION:
                if plan_digest != migration_plan_digest():
                    raise SchemaCompatibilityError(
                        "The saved migration plan does not match this image."
                    )
                live_fingerprint = schema_fingerprint(connection)
                recorded = connection.execute(
                    "SELECT schema_fingerprint FROM nct_schema_state WHERE singleton = 1"
                ).fetchone()[0]
                ledger = connection.execute(
                    """SELECT migration_id, target_schema_version, status,
                              after_schema_fingerprint
                         FROM nct_schema_migrations ORDER BY migration_id"""
                ).fetchall()
                if not recorded or recorded != live_fingerprint:
                    raise SchemaCompatibilityError(
                        "The saved schema fingerprint does not match the live database."
                    )
                by_id = {row[0]: row for row in ledger}
                unknown = [row for row in ledger if row[0] not in MIGRATION_PLAN]
                unfinished = [row for row in ledger if row[2] == "started"]
                expected = {
                    migration_id: (index, "completed")
                    for index, migration_id in enumerate(MIGRATION_PLAN, start=1)
                }
                ledger_valid = len(by_id) == len(MIGRATION_PLAN)
                for migration_id, (target, status) in expected.items():
                    row = by_id.get(migration_id)
                    ledger_valid = ledger_valid and row is not None and (
                        row[1] == target
                        and row[2] == status
                        and bool(row[3])
                    )
                current = by_id.get(MIGRATION_ID)
                if current is None or current[3] != recorded:
                    ledger_valid = False
                if not ledger_valid or unknown or unfinished:
                    raise SchemaCompatibilityError(
                        "The saved migration ledger is incomplete or inconsistent."
                    )
                return None
            elif int(schema_version) in {1, 2, 3, 4}:
                live_fingerprint = schema_fingerprint(connection)
                recorded = connection.execute(
                    "SELECT schema_fingerprint FROM nct_schema_state WHERE singleton = 1"
                ).fetchone()[0]
                pending_current = connection.execute(
                    """SELECT status, before_schema_fingerprint,
                              after_schema_fingerprint
                         FROM nct_schema_migrations WHERE migration_id = ?""",
                    (MIGRATION_ID,),
                ).fetchone()
                if not recorded or recorded != live_fingerprint:
                    resumable_failure = (
                        pending_current is not None
                        and pending_current[0] == "failed"
                        and pending_current[1] == recorded
                        and pending_current[2] == live_fingerprint
                    )
                    if not resumable_failure:
                        raise SchemaCompatibilityError(
                            "The saved schema fingerprint does not match the live database."
                        )
                prior_ids = MIGRATION_PLAN[:int(schema_version)]
                prior_rows = connection.execute(
                    """SELECT migration_id, target_schema_version, status,
                              after_schema_fingerprint
                         FROM nct_schema_migrations"""
                ).fetchall()
                allowed_ids = set(MIGRATION_PLAN)
                if any(row[0] not in allowed_ids for row in prior_rows):
                    raise SchemaCompatibilityError(
                        "The saved migration ledger is incomplete or inconsistent."
                    )
                prior_by_id = {row[0]: row for row in prior_rows}
                for target, migration_id in enumerate(prior_ids, start=1):
                    row = prior_by_id.get(migration_id)
                    if (
                        row is None
                        or row[1] != target
                        or row[2] != "completed"
                        or not row[3]
                        or (target == int(schema_version) and row[3] != recorded)
                    ):
                        raise SchemaCompatibilityError(
                            "The saved migration ledger is incomplete or inconsistent."
                        )
                for target, migration_id in enumerate(
                    MIGRATION_PLAN[int(schema_version):-1],
                    start=int(schema_version) + 1,
                ):
                    row = prior_by_id.get(migration_id)
                    if row is not None and row != (
                        migration_id, target, "completed", recorded
                    ):
                        raise SchemaCompatibilityError(
                            "The saved migration ledger is incomplete or inconsistent."
                        )
            current_version = int(schema_version)
        else:
            current_version = 0

        before = schema_fingerprint(connection)
        if current_version == 0:
            connection.execute(
                """INSERT INTO nct_schema_migrations(
                       migration_id, target_schema_version, originating_build_id,
                       originating_build_commit, status, attempts, first_started_at,
                       last_started_at, completed_at, before_schema_fingerprint,
                       after_schema_fingerprint, error_summary
                   ) VALUES (?, 1, ?, ?, 'completed', 1, ?, ?, ?, ?, ?, NULL)
                   ON CONFLICT(migration_id) DO UPDATE SET
                       target_schema_version = 1,
                       originating_build_id = excluded.originating_build_id,
                       originating_build_commit = excluded.originating_build_commit,
                       status = 'completed', attempts = MAX(attempts, 1),
                       last_started_at = excluded.last_started_at,
                       completed_at = excluded.completed_at,
                       before_schema_fingerprint = excluded.before_schema_fingerprint,
                       after_schema_fingerprint = excluded.after_schema_fingerprint,
                       error_summary = NULL""",
                (
                    LEGACY_MIGRATION_ID, BUILD_ID, BUILD_COMMIT,
                    now, now, now, before, before,
                ),
            )
        if current_version in {0, 1}:
            connection.execute(
                """INSERT INTO nct_schema_migrations(
                       migration_id, target_schema_version, originating_build_id,
                       originating_build_commit, status, attempts, first_started_at,
                       last_started_at, completed_at, before_schema_fingerprint,
                       after_schema_fingerprint, error_summary
                   ) VALUES (?, 2, ?, ?, 'completed', 1, ?, ?, ?, ?, ?, NULL)
                   ON CONFLICT(migration_id) DO UPDATE SET
                       target_schema_version = 2,
                       originating_build_id = excluded.originating_build_id,
                       originating_build_commit = excluded.originating_build_commit,
                       status = 'completed', attempts = MAX(attempts, 1),
                       last_started_at = excluded.last_started_at,
                       completed_at = excluded.completed_at,
                       before_schema_fingerprint = excluded.before_schema_fingerprint,
                       after_schema_fingerprint = excluded.after_schema_fingerprint,
                       error_summary = NULL""",
                (
                    WORK_COORDINATION_MIGRATION_ID, BUILD_ID, BUILD_COMMIT,
                    now, now, now, before, before,
                ),
            )
        if current_version in {0, 1, 2}:
            connection.execute(
                """INSERT INTO nct_schema_migrations(
                       migration_id, target_schema_version, originating_build_id,
                       originating_build_commit, status, attempts, first_started_at,
                       last_started_at, completed_at, before_schema_fingerprint,
                       after_schema_fingerprint, error_summary
                   ) VALUES (?, 3, ?, ?, 'completed', 1, ?, ?, ?, ?, ?, NULL)
                   ON CONFLICT(migration_id) DO UPDATE SET
                       target_schema_version = 3,
                       originating_build_id = excluded.originating_build_id,
                       originating_build_commit = excluded.originating_build_commit,
                       status = 'completed', attempts = MAX(attempts, 1),
                       last_started_at = excluded.last_started_at,
                       completed_at = excluded.completed_at,
                       before_schema_fingerprint = excluded.before_schema_fingerprint,
                       after_schema_fingerprint = excluded.after_schema_fingerprint,
                       error_summary = NULL""",
                (
                    SCHEDULED_WORK_MIGRATION_ID, BUILD_ID, BUILD_COMMIT,
                    now, now, now, before, before,
                ),
            )
        if current_version in {0, 1, 2, 3}:
            connection.execute(
                """INSERT INTO nct_schema_migrations(
                       migration_id, target_schema_version, originating_build_id,
                       originating_build_commit, status, attempts, first_started_at,
                       last_started_at, completed_at, before_schema_fingerprint,
                       after_schema_fingerprint, error_summary
                   ) VALUES (?, 4, ?, ?, 'completed', 1, ?, ?, ?, ?, ?, NULL)
                   ON CONFLICT(migration_id) DO UPDATE SET
                       target_schema_version = 4,
                       originating_build_id = excluded.originating_build_id,
                       originating_build_commit = excluded.originating_build_commit,
                       status = 'completed', attempts = MAX(attempts, 1),
                       last_started_at = excluded.last_started_at,
                       completed_at = excluded.completed_at,
                       before_schema_fingerprint = excluded.before_schema_fingerprint,
                       after_schema_fingerprint = excluded.after_schema_fingerprint,
                       error_summary = NULL""",
                (
                    DEVICE_CONTACT_MIGRATION_ID, BUILD_ID, BUILD_COMMIT,
                    now, now, now, before, before,
                ),
            )
        previous = connection.execute(
            "SELECT attempts, first_started_at FROM nct_schema_migrations WHERE migration_id = ?",
            (MIGRATION_ID,),
        ).fetchone()
        attempts = int(previous[0]) + 1 if previous else 1
        first_started_at = previous[1] if previous else now
        connection.execute(
            """INSERT INTO nct_schema_migrations(
                   migration_id, target_schema_version, originating_build_id,
                   originating_build_commit, status, attempts, first_started_at,
                   last_started_at, completed_at, before_schema_fingerprint,
                   after_schema_fingerprint, error_summary
               ) VALUES (?, ?, ?, ?, 'started', ?, ?, ?, NULL, ?, NULL, NULL)
               ON CONFLICT(migration_id) DO UPDATE SET
                   target_schema_version = excluded.target_schema_version,
                   originating_build_id = excluded.originating_build_id,
                   originating_build_commit = excluded.originating_build_commit,
                   status = 'started', attempts = excluded.attempts,
                   last_started_at = excluded.last_started_at, completed_at = NULL,
                   after_schema_fingerprint = NULL, error_summary = NULL""",
            (
                MIGRATION_ID,
                WRITABLE_SCHEMA_VERSION,
                BUILD_ID,
                BUILD_COMMIT,
                attempts,
                first_started_at,
                now,
                before,
            ),
        )
        connection.execute(
            """INSERT INTO nct_schema_state(
                   singleton, schema_contract_version, schema_version,
                   data_layout_contract, migration_plan_digest, schema_fingerprint,
                   originating_build_id, originating_build_commit, updated_at
               ) VALUES (1, ?, ?, ?, ?, NULL, ?, ?, ?)
               ON CONFLICT(singleton) DO UPDATE SET
                   schema_contract_version = excluded.schema_contract_version,
                   data_layout_contract = excluded.data_layout_contract,
                   migration_plan_digest = excluded.migration_plan_digest,
                   originating_build_id = excluded.originating_build_id,
                   originating_build_commit = excluded.originating_build_commit,
                   updated_at = excluded.updated_at""",
            (
                SCHEMA_CONTRACT_VERSION,
                current_version,
                DATA_LAYOUT_CONTRACT,
                migration_plan_digest(),
                BUILD_ID,
                BUILD_COMMIT,
                now,
            ),
        )
        connection.commit()
    return MigrationAttempt(MIGRATION_ID, WRITABLE_SCHEMA_VERSION, attempts)


def complete_schema_migration(db_path: Path, attempt: MigrationAttempt | None) -> None:
    if attempt is None:
        return
    now = _utc_now()
    with connect_database(db_path) as connection:
        after = schema_fingerprint(connection)
        updated = connection.execute(
            """UPDATE nct_schema_migrations
                  SET status = 'completed', completed_at = ?,
                      after_schema_fingerprint = ?, error_summary = NULL
                WHERE migration_id = ? AND status = 'started' AND attempts = ?""",
            (now, after, attempt.migration_id, attempt.attempt),
        ).rowcount
        if updated != 1:
            raise SchemaCompatibilityError("The active schema migration ledger changed.")
        connection.execute(
            """UPDATE nct_schema_state
                  SET schema_contract_version = ?, schema_version = ?,
                      data_layout_contract = ?, migration_plan_digest = ?,
                      schema_fingerprint = ?, originating_build_id = ?,
                      originating_build_commit = ?, updated_at = ?
                WHERE singleton = 1""",
            (
                SCHEMA_CONTRACT_VERSION,
                attempt.target_schema_version,
                DATA_LAYOUT_CONTRACT,
                migration_plan_digest(),
                after,
                BUILD_ID,
                BUILD_COMMIT,
                now,
            ),
        )
        connection.commit()


def fail_schema_migration(
    db_path: Path, attempt: MigrationAttempt | None, error: BaseException
) -> None:
    if attempt is None or not db_path.exists():
        return
    summary = f"{type(error).__name__}: {error}"[:500]
    try:
        with connect_database(db_path) as connection:
            interrupted_fingerprint = schema_fingerprint(connection)
            connection.execute(
                """UPDATE nct_schema_migrations
                      SET status = 'failed', after_schema_fingerprint = ?,
                          error_summary = ?
                    WHERE migration_id = ? AND status = 'started' AND attempts = ?""",
                (
                    interrupted_fingerprint,
                    summary,
                    attempt.migration_id,
                    attempt.attempt,
                ),
            )
            connection.commit()
    except sqlite3.Error:
        # Preserve the original startup error. A still-started row is intentionally
        # treated as interrupted and is safe to resume through the same idempotent plan.
        pass


def schema_state(db_path: Path) -> dict[str, object]:
    with connect_database(db_path, read_only=True) as connection:
        row = connection.execute(
            """SELECT schema_contract_version, schema_version, data_layout_contract,
                      migration_plan_digest, schema_fingerprint,
                      originating_build_id, originating_build_commit, updated_at
                 FROM nct_schema_state WHERE singleton = 1"""
        ).fetchone()
        if row is None:
            raise SchemaCompatibilityError("The data has no NCT schema contract.")
        ledger = connection.execute(
            """SELECT migration_id, target_schema_version, originating_build_id,
                      originating_build_commit, status, attempts, first_started_at,
                      last_started_at, completed_at, before_schema_fingerprint,
                      after_schema_fingerprint, error_summary
                 FROM nct_schema_migrations
                ORDER BY CASE migration_id
                    WHEN 'nct-foundation-data-contract-v1' THEN 1
                    WHEN 'nct-work-coordination-v2' THEN 2
                    WHEN 'nct-scheduled-occurrences-v3' THEN 3
                    WHEN 'nct-device-contact-fencing-v4' THEN 4
                    WHEN 'nct-mission-environment-v5' THEN 5
                    ELSE 99 END,
                    first_started_at, migration_id"""
        ).fetchall()
        live_fingerprint = schema_fingerprint(connection)
    keys = (
        "migration_id", "target_schema_version", "originating_build_id",
        "originating_build_commit", "status", "attempts", "first_started_at",
        "last_started_at", "completed_at", "before_schema_fingerprint",
        "after_schema_fingerprint", "error_summary",
    )
    return {
        "schema_contract_version": int(row[0]),
        "schema_version": int(row[1]),
        "data_layout_contract": row[2],
        "migration_plan_digest": row[3],
        "recorded_schema_fingerprint": row[4],
        "live_schema_fingerprint": live_fingerprint,
        "schema_fingerprint_matches": row[4] == live_fingerprint,
        "originating_build_id": row[5],
        "originating_build_commit": row[6],
        "updated_at": row[7],
        "migration_ledger": [dict(zip(keys, values)) for values in ledger],
    }
