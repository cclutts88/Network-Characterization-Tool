from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
from itertools import combinations
import json
from pathlib import Path
import re
import sqlite3
import tempfile
import uuid

from app.build_info import APP_VERSION, BUILD_COMMIT, BUILD_ID
from app.database import connect_database


SCHEMA_CONTRACT_VERSION = 6
WRITABLE_SCHEMA_VERSION = 6
READABLE_SCHEMA_VERSIONS = (1, 2, 3, 4, 5, 6)
DATA_LAYOUT_CONTRACT = "nct-data-layout-v1"
LEGACY_MIGRATION_ID = "nct-foundation-data-contract-v1"
WORK_COORDINATION_MIGRATION_ID = "nct-work-coordination-v2"
SCHEDULED_WORK_MIGRATION_ID = "nct-scheduled-occurrences-v3"
DEVICE_CONTACT_MIGRATION_ID = "nct-device-contact-fencing-v4"
MISSION_ENVIRONMENT_MIGRATION_ID = "nct-mission-environment-v5"
VLAN_EVIDENCE_MIGRATION_ID = "nct-scoped-vlan-evidence-v6"
MIGRATION_ID = VLAN_EVIDENCE_MIGRATION_ID
MIGRATION_PLAN = (
    LEGACY_MIGRATION_ID,
    WORK_COORDINATION_MIGRATION_ID,
    SCHEDULED_WORK_MIGRATION_ID,
    DEVICE_CONTACT_MIGRATION_ID,
    MISSION_ENVIRONMENT_MIGRATION_ID,
    MIGRATION_ID,
)

# Exact version-4 Range images that may have created or subsequently opened the
# phase2 schema accepted by the phase3 replacement package.
SUPPORTED_V4_RANGE_BUILDS = (
    (
        "0.16.0-range-test-20261013-phase2-r3",
        "a4256d6f7fdd1bc02e465fbe57f9d738515a2960",
    ),
    (
        "0.16.0-range-test-20261013-phase2-r4",
        "99d8e03b826c05a719d541923a66cf3f5b597224",
    ),
    (
        "0.16.0-range-test-20261013-phase2-r5",
        "46fbf1d93dfe7bb53f89db931d423a91b3fba5ab",
    ),
)

_LEGACY_V4_LATE_SCHEMA_GROUPS = (
    frozenset({"searchsploit_query_cache", "searchsploit_query_cache_updated"}),
    frozenset({"artifact_backfill"}),
    frozenset({"artifact_compaction_journal"}),
)
_LEGACY_V4_LATE_SCHEMA_ROWS = {
    "searchsploit_query_cache": (
        "table",
        "searchsploit_query_cache",
        "searchsploit_query_cache",
        """CREATE TABLE searchsploit_query_cache (
               provider_key TEXT NOT NULL,
               query TEXT NOT NULL,
               candidates_json TEXT NOT NULL,
               updated_at TEXT NOT NULL,
               PRIMARY KEY (provider_key, query)
           )""",
    ),
    "searchsploit_query_cache_updated": (
        "index",
        "searchsploit_query_cache_updated",
        "searchsploit_query_cache",
        "CREATE INDEX searchsploit_query_cache_updated ON searchsploit_query_cache(updated_at)",
    ),
    "artifact_backfill": (
        "table",
        "artifact_backfill",
        "artifact_backfill",
        """CREATE TABLE artifact_backfill (
               source_key TEXT PRIMARY KEY,
               fingerprint TEXT NOT NULL,
               sha256 TEXT NOT NULL
           )""",
    ),
    "artifact_compaction_journal": (
        "table",
        "artifact_compaction_journal",
        "artifact_compaction_journal",
        """CREATE TABLE artifact_compaction_journal (
               compaction_id TEXT NOT NULL,
               item_id TEXT PRIMARY KEY,
               source_path TEXT NOT NULL,
               canonical_path TEXT NOT NULL,
               recovery_path TEXT NOT NULL,
               sha256 TEXT NOT NULL,
               size_bytes INTEGER NOT NULL,
               source_fingerprint_json TEXT NOT NULL,
               canonical_fingerprint_json TEXT NOT NULL,
               state TEXT NOT NULL,
               detail TEXT,
               updated_at TEXT NOT NULL
           )""",
    ),
}


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


def migration_plan_digest(
    migration_ids: tuple[str, ...] = MIGRATION_PLAN,
) -> str:
    return _digest({"migration_ids": list(migration_ids)})


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


def _schema_rows(connection: sqlite3.Connection) -> list[tuple]:
    rows = connection.execute(
        """SELECT type, name, tbl_name, COALESCE(sql, '')
             FROM sqlite_master
            WHERE name NOT LIKE 'sqlite_%'
            ORDER BY type, name, tbl_name, sql"""
    ).fetchall()
    return [tuple(row) for row in rows]


def schema_fingerprint(
    connection: sqlite3.Connection,
    *,
    excluded_names: frozenset[str] = frozenset(),
) -> str:
    rows = [row for row in _schema_rows(connection) if row[1] not in excluded_names]
    return _digest([list(row) for row in rows])


def _normalized_sql(value: str) -> str:
    normalized = " ".join(str(value).split())
    normalized = re.sub(r"\s*([(),])\s*", r"\1", normalized)
    return normalized.casefold()


def _matches_exact_v6_vlan_schema(
    connection: sqlite3.Connection, *, base_fingerprint: str | None,
) -> bool:
    """Recognize only the reviewed v6 VLAN objects above an exact sealed base."""
    from app.device_vlan_observations import (
        DEVICE_VLAN_SCHEMA_OBJECTS,
        create_device_vlan_schema,
    )

    if base_fingerprint is not None and schema_fingerprint(
        connection, excluded_names=DEVICE_VLAN_SCHEMA_OBJECTS
    ) != base_fingerprint:
        return False
    actual = {
        row[1]: row for row in _schema_rows(connection)
        if row[1] in DEVICE_VLAN_SCHEMA_OBJECTS
    }
    if set(actual) != set(DEVICE_VLAN_SCHEMA_OBJECTS):
        return False
    with tempfile.TemporaryDirectory(prefix="nct-v6-schema-") as directory:
        expected_path = Path(directory) / "expected.db"
        with connect_database(expected_path) as expected_db:
            create_device_vlan_schema(expected_db)
            expected = {
                row[1]: row for row in _schema_rows(expected_db)
                if row[1] in DEVICE_VLAN_SCHEMA_OBJECTS
            }
    if set(expected) != set(DEVICE_VLAN_SCHEMA_OBJECTS):
        raise RuntimeError("The image-owned v6 VLAN schema definition is incomplete")
    return all(
        actual[name][:3] == expected[name][:3]
        and _normalized_sql(actual[name][3]) == _normalized_sql(expected[name][3])
        for name in DEVICE_VLAN_SCHEMA_OBJECTS
    )


def _matches_exact_legacy_v4_late_schema(
    connection: sqlite3.Connection,
    recorded_fingerprint: str,
) -> bool:
    """Recognize only complete phase2 schema groups created after v4 was sealed."""
    by_name = {row[1]: row for row in _schema_rows(connection)}
    complete_groups: list[frozenset[str]] = []
    for group in _LEGACY_V4_LATE_SCHEMA_GROUPS:
        present = group.intersection(by_name)
        if present and present != group:
            return False
        if not present:
            continue
        for name in group:
            actual = by_name[name]
            expected = _LEGACY_V4_LATE_SCHEMA_ROWS[name]
            if actual[:3] != expected[:3]:
                return False
            if _normalized_sql(actual[3]) != _normalized_sql(expected[3]):
                return False
        complete_groups.append(group)

    for group_count in range(1, len(complete_groups) + 1):
        for selected in combinations(complete_groups, group_count):
            excluded = frozenset().union(*selected)
            if schema_fingerprint(
                connection, excluded_names=excluded
            ) == recorded_fingerprint:
                return True
    return False


def schema_upgrade_preflight(
    db_path: Path,
    *,
    expected_build_id: str,
    expected_build_commit: str,
) -> dict[str, object]:
    """Read-only proof that a saved v4 database is safe for this image to upgrade."""
    if not db_path.is_file():
        raise SchemaCompatibilityError("The saved NCT database was not found.")
    wal_path = db_path.with_name(f"{db_path.name}-wal")
    if wal_path.exists() and wal_path.stat().st_size:
        raise SchemaCompatibilityError(
            "The stopped database still has uncheckpointed WAL data."
        )
    connection = connect_database(db_path, read_only=True, immutable=True)
    try:
        integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
        foreign_key_errors = [list(row) for row in connection.execute("PRAGMA foreign_key_check")]
        if integrity != "ok" or foreign_key_errors:
            raise SchemaCompatibilityError(
                "The saved database failed integrity or foreign-key validation."
            )
        state = connection.execute(
            """SELECT schema_contract_version, schema_version, data_layout_contract,
                      migration_plan_digest, schema_fingerprint,
                      originating_build_id, originating_build_commit
                 FROM nct_schema_state WHERE singleton = 1"""
        ).fetchone()
        if state is None:
            raise SchemaCompatibilityError("The saved schema state is missing.")
        (
            contract_version,
            schema_version,
            layout,
            plan_digest,
            recorded,
            build_id,
            build_commit,
        ) = state
        if int(contract_version) != 4 or int(schema_version) != 4:
            raise SchemaCompatibilityError(
                "This replacement package requires the verified phase2 version 4 schema."
            )
        if layout != DATA_LAYOUT_CONTRACT or not recorded:
            raise SchemaCompatibilityError(
                "The saved evidence layout or schema fingerprint is not compatible."
            )
        expected_v4_plan_digest = migration_plan_digest(MIGRATION_PLAN[:4])
        if plan_digest != expected_v4_plan_digest:
            raise SchemaCompatibilityError(
                "The saved version 4 migration plan does not match the supported lineage."
            )
        running_origin = (expected_build_id, expected_build_commit)
        schema_origin = (build_id, build_commit)
        if running_origin not in SUPPORTED_V4_RANGE_BUILDS:
            raise SchemaCompatibilityError(
                "The retained running build is not a supported version 4 Range source."
            )
        if schema_origin not in SUPPORTED_V4_RANGE_BUILDS:
            raise SchemaCompatibilityError(
                "The saved schema origin is not a supported version 4 Range source."
            )
        live = schema_fingerprint(connection)
        compatibility = "recorded-fingerprint-match"
        if live != recorded:
            if not _matches_exact_legacy_v4_late_schema(connection, recorded):
                raise SchemaCompatibilityError(
                    "The saved schema differs from version 4 in an unrecognized way."
                )
            compatibility = "exact-known-phase2-late-schema"

        ledger = connection.execute(
            """SELECT migration_id, target_schema_version, status,
                      after_schema_fingerprint, originating_build_id,
                      originating_build_commit
                 FROM nct_schema_migrations ORDER BY target_schema_version, migration_id"""
        ).fetchall()
        expected_ids = MIGRATION_PLAN[:4]
        if len(ledger) != len(expected_ids):
            raise SchemaCompatibilityError(
                "The saved version 4 migration ledger is incomplete or contains extra entries."
            )
        by_id = {row[0]: row for row in ledger}
        for target, migration_id in enumerate(expected_ids, start=1):
            row = by_id.get(migration_id)
            if (
                row is None
                or int(row[1]) != target
                or row[2] != "completed"
                or not row[3]
                or (target == 4 and row[3] != recorded)
                or (
                    target == 4
                    and (row[4] != build_id or row[5] != build_commit)
                )
            ):
                raise SchemaCompatibilityError(
                    "The saved version 4 migration ledger is incomplete or inconsistent."
                )

        known_late_names = set(_LEGACY_V4_LATE_SCHEMA_ROWS)
        present_late_names = sorted(
            row[1] for row in _schema_rows(connection) if row[1] in known_late_names
        )
        return {
            "status": "pass",
            "compatibility": compatibility,
            "schema_contract_version": int(contract_version),
            "schema_version": int(schema_version),
            "data_layout_contract": layout,
            "migration_plan_digest": plan_digest,
            "recorded_schema_fingerprint": recorded,
            "live_schema_fingerprint": live,
            "originating_build_id": build_id,
            "originating_build_commit": build_commit,
            "retained_running_build_id": expected_build_id,
            "retained_running_build_commit": expected_build_commit,
            "known_late_schema_objects": present_late_names,
            "migration_ids": [row[0] for row in ledger],
            "integrity": integrity,
            "foreign_key_errors": foreign_key_errors,
        }
    except sqlite3.Error as exc:
        raise SchemaCompatibilityError(
            f"The saved database could not be audited: {exc}"
        ) from exc
    finally:
        connection.close()


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
            elif int(schema_version) == 5:
                if int(contract_version) != 5:
                    raise SchemaCompatibilityError(
                        "The saved version 5 schema contract is inconsistent."
                    )
                if plan_digest != migration_plan_digest(MIGRATION_PLAN[:5]):
                    raise SchemaCompatibilityError(
                        "The saved version 5 migration plan does not match this image."
                    )
                live_fingerprint = schema_fingerprint(connection)
                recorded = connection.execute(
                    "SELECT schema_fingerprint FROM nct_schema_state WHERE singleton = 1"
                ).fetchone()[0]
                pending_current = connection.execute(
                    """SELECT target_schema_version, status, attempts,
                              before_schema_fingerprint, after_schema_fingerprint,
                              completed_at, error_summary
                         FROM nct_schema_migrations WHERE migration_id = ?""",
                    (MIGRATION_ID,),
                ).fetchone()
                prior_ids = MIGRATION_PLAN[:5]
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
                        or (target == 5 and row[3] != recorded)
                    ):
                        raise SchemaCompatibilityError(
                            "The saved migration ledger is incomplete or inconsistent."
                        )
                if len(prior_by_id) != 5 + (1 if pending_current is not None else 0):
                    raise SchemaCompatibilityError(
                        "The saved migration ledger is incomplete or inconsistent."
                    )
                if pending_current is None:
                    if not recorded or live_fingerprint != recorded:
                        raise SchemaCompatibilityError(
                            "The saved schema fingerprint does not match the live database."
                        )
                else:
                    (
                        target, status, attempts, before_fingerprint,
                        after_fingerprint, completed_at, error_summary,
                    ) = pending_current
                    status_shape_valid = (
                        status == "started"
                        and after_fingerprint is None
                        and completed_at is None
                        and error_summary is None
                    ) or (
                        status == "failed"
                        and after_fingerprint == live_fingerprint
                        and completed_at is None
                        and bool(str(error_summary or "").strip())
                    )
                    if (
                        int(target) != 6
                        or status not in {"started", "failed"}
                        or not status_shape_valid
                        or int(attempts) < 1
                        or before_fingerprint != recorded
                    ):
                        raise SchemaCompatibilityError(
                            "The saved migration ledger is incomplete or inconsistent."
                        )
                    exact_before = live_fingerprint == recorded
                    exact_after = _matches_exact_v6_vlan_schema(
                        connection, base_fingerprint=recorded,
                    )
                    if not exact_before and not exact_after:
                        raise SchemaCompatibilityError(
                            "The saved schema fingerprint does not match an exact resumable migration."
                        )
            elif int(schema_version) in {1, 2, 3, 4}:
                raise SchemaCompatibilityError(
                    "This image requires older saved schemas to be upgraded to version 5 first."
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
        if current_version in {0, 1, 2, 3, 4}:
            connection.execute(
                """INSERT INTO nct_schema_migrations(
                       migration_id, target_schema_version, originating_build_id,
                       originating_build_commit, status, attempts, first_started_at,
                       last_started_at, completed_at, before_schema_fingerprint,
                       after_schema_fingerprint, error_summary
                   ) VALUES (?, 5, ?, ?, 'completed', 1, ?, ?, ?, ?, ?, NULL)
                   ON CONFLICT(migration_id) DO UPDATE SET
                       target_schema_version = 5,
                       originating_build_id = excluded.originating_build_id,
                       originating_build_commit = excluded.originating_build_commit,
                       status = 'completed', attempts = MAX(attempts, 1),
                       last_started_at = excluded.last_started_at,
                       completed_at = excluded.completed_at,
                       before_schema_fingerprint = excluded.before_schema_fingerprint,
                       after_schema_fingerprint = excluded.after_schema_fingerprint,
                       error_summary = NULL""",
                (
                    MISSION_ENVIRONMENT_MIGRATION_ID, BUILD_ID, BUILD_COMMIT,
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
                5 if current_version == 5 else SCHEMA_CONTRACT_VERSION,
                current_version,
                DATA_LAYOUT_CONTRACT,
                (
                    migration_plan_digest(MIGRATION_PLAN[:5])
                    if current_version == 5 else migration_plan_digest()
                ),
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
        active = connection.execute(
            """SELECT before_schema_fingerprint FROM nct_schema_migrations
               WHERE migration_id = ? AND status = 'started' AND attempts = ?""",
            (attempt.migration_id, attempt.attempt),
        ).fetchone()
        state = connection.execute(
            "SELECT schema_version FROM nct_schema_state WHERE singleton = 1"
        ).fetchone()
        if active is None or state is None:
            raise SchemaCompatibilityError("The active schema migration ledger changed.")
        base_fingerprint = active[0] if int(state[0]) == 5 else None
        if not _matches_exact_v6_vlan_schema(
            connection, base_fingerprint=base_fingerprint,
        ):
            raise SchemaCompatibilityError(
                "The exact version 6 VLAN schema was not applied cleanly."
            )
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
                    WHEN 'nct-scoped-vlan-evidence-v6' THEN 6
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
