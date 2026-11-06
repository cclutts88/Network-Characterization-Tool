"""Append-only retirement authority for retained evidence encounters.

Retirement suppresses one exact encounter from ordinary analysis without deleting
its original bytes or audit receipts. Content hashes are deliberately not valid
retirement identities because multiple independent encounters may share bytes.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sqlite3
from typing import Callable, Mapping, Sequence, TypeVar
import uuid

from app.database import (
    connect_database,
    execute_sql_script_statements,
    initialize_once_per_database,
)


EVIDENCE_RETIREMENT_SCHEMA_OBJECTS = frozenset({
    "evidence_retirement_lineage",
    "evidence_retirement_events",
    "evidence_retirement_identities",
    "evidence_retirement_event_encounter",
    "evidence_retirement_identity_lookup",
    "evidence_retirement_lineage_insert_guard",
    "evidence_retirement_lineage_no_update",
    "evidence_retirement_lineage_no_delete",
    "evidence_retirement_events_insert_guard",
    "evidence_retirement_events_no_update",
    "evidence_retirement_events_no_delete",
    "evidence_retirement_identity_conflict_guard",
    "evidence_retirement_identity_insert_guard",
    "evidence_retirement_identities_no_update",
    "evidence_retirement_identities_no_delete",
})

_FORBIDDEN_CONTENT_IDENTITY_NAMES = frozenset({
    "sha", "sha256", "content_hash", "content_sha256", "artifact_sha256",
})
_SQL_IDENTITY_EXPRESSION = re.compile(
    r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)?"
)


class EvidenceRetirementError(ValueError):
    pass


class EvidenceAlreadyRetired(EvidenceRetirementError):
    pass


class EvidenceRetirementBlocked(EvidenceRetirementError):
    pass


class RetiredEvidenceDependency(EvidenceRetirementError):
    pass


T = TypeVar("T")


@dataclass(frozen=True)
class EvidenceDependency:
    source_family: str
    identity_namespace: str
    identity_value: str


@dataclass(frozen=True)
class EvidenceRetirementAdapter:
    """Source-owned resolution used while the retirement write lock is held."""

    resolve_identities: Callable[[sqlite3.Connection, str], Mapping[str, str]]
    active_work_detail: Callable[[sqlite3.Connection, str], str | None]


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _canonical(value: object) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False,
    )


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _canonical_text(value: object, name: str, *, maximum: int = 500) -> str:
    text = str(value or "")
    if not text or text != text.strip() or len(text) > maximum:
        raise EvidenceRetirementError(f"{name} must be canonical non-empty text")
    return text


def _retirement_impact(
    source_family: str,
    encounter_id: str,
    *,
    authority_revision: int,
    identity_count: int,
    identity_snapshot_sha256: str,
) -> list[str]:
    return [
        (
            f"This exact {source_family} encounter {encounter_id} will leave ordinary "
            "selectors and future analysis."
        ),
        (
            f"The decision is based on authority revision {authority_revision} and "
            f"{identity_count} protected exact identities "
            f"({identity_snapshot_sha256[:12]})."
        ),
        "Any active same-content sibling remains independently available.",
        "Original source bytes and the immutable retirement receipt are retained.",
        "This action does not contact the network and does not physically delete files.",
    ]


def _identity_snapshot(
    source_family: str, encounter_id: str, identities: Mapping[str, str],
) -> tuple[dict[str, str], str, str]:
    normalized: dict[str, str] = {}
    for raw_namespace, raw_value in identities.items():
        namespace = _canonical_text(raw_namespace, "identity namespace", maximum=100)
        value = _canonical_text(raw_value, "identity value", maximum=500)
        if namespace.casefold() in _FORBIDDEN_CONTENT_IDENTITY_NAMES:
            raise EvidenceRetirementError(
                "content hashes cannot identify a retired evidence encounter"
            )
        if namespace in normalized:
            raise EvidenceRetirementError("identity namespaces must be unique")
        normalized[namespace] = value
    if normalized.get("encounter_id") != encounter_id:
        raise EvidenceRetirementError(
            "the source resolver must return its namespaced encounter identity"
        )
    snapshot = {
        "source_family": source_family,
        "encounter_id": encounter_id,
        "identities": dict(sorted(normalized.items())),
    }
    encoded = _canonical(snapshot)
    return normalized, encoded, hashlib.sha256(encoded.encode("utf-8")).hexdigest()


EVIDENCE_RETIREMENT_SCHEMA_SQL = """
            CREATE TABLE IF NOT EXISTS evidence_retirement_lineage (
                singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                lineage_id TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS evidence_retirement_events (
                revision INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT NOT NULL UNIQUE,
                lineage_id TEXT NOT NULL,
                source_family TEXT NOT NULL,
                encounter_id TEXT NOT NULL,
                identity_snapshot_json TEXT NOT NULL,
                identity_snapshot_sha256 TEXT NOT NULL,
                previous_event_digest TEXT NOT NULL,
                event_digest TEXT NOT NULL UNIQUE,
                identity_count INTEGER NOT NULL CHECK(identity_count > 0),
                sealed INTEGER NOT NULL CHECK(sealed IN (0, 1)),
                actor TEXT NOT NULL,
                reason TEXT NOT NULL,
                retired_at TEXT NOT NULL,
                UNIQUE(source_family, encounter_id),
                FOREIGN KEY(lineage_id)
                    REFERENCES evidence_retirement_lineage(lineage_id)
            );
            CREATE INDEX IF NOT EXISTS evidence_retirement_event_encounter
                ON evidence_retirement_events(source_family, encounter_id, revision);
            CREATE TABLE IF NOT EXISTS evidence_retirement_identities (
                revision INTEGER NOT NULL
                    REFERENCES evidence_retirement_events(revision),
                source_family TEXT NOT NULL,
                encounter_id TEXT NOT NULL,
                identity_namespace TEXT NOT NULL,
                identity_value TEXT NOT NULL,
                PRIMARY KEY(revision, identity_namespace),
                UNIQUE(source_family, identity_namespace, identity_value)
            );
            CREATE INDEX IF NOT EXISTS evidence_retirement_identity_lookup
                ON evidence_retirement_identities(
                    source_family, identity_namespace, identity_value, revision
                );
            CREATE TRIGGER IF NOT EXISTS evidence_retirement_lineage_insert_guard
                BEFORE INSERT ON evidence_retirement_lineage
                WHEN EXISTS (
                    SELECT 1 FROM evidence_retirement_lineage
                     WHERE singleton = NEW.singleton
                        OR lineage_id = NEW.lineage_id
                )
                BEGIN
                    SELECT RAISE(ABORT, 'retirement lineage conflicts are immutable');
                END;
            CREATE TRIGGER IF NOT EXISTS evidence_retirement_lineage_no_update
                BEFORE UPDATE ON evidence_retirement_lineage
                BEGIN SELECT RAISE(ABORT, 'retirement lineage is immutable'); END;
            CREATE TRIGGER IF NOT EXISTS evidence_retirement_lineage_no_delete
                BEFORE DELETE ON evidence_retirement_lineage
                BEGIN SELECT RAISE(ABORT, 'retirement lineage is immutable'); END;
            CREATE TRIGGER IF NOT EXISTS evidence_retirement_events_insert_guard
                BEFORE INSERT ON evidence_retirement_events
                WHEN NEW.sealed != 0 OR EXISTS (
                    SELECT 1 FROM evidence_retirement_events
                     WHERE revision = NEW.revision
                        OR event_id = NEW.event_id
                        OR event_digest = NEW.event_digest
                        OR (
                            source_family = NEW.source_family
                            AND encounter_id = NEW.encounter_id
                        )
                )
                BEGIN
                    SELECT RAISE(
                        ABORT,
                        'retirement event conflicts and pre-sealed inserts are forbidden'
                    );
                END;
            CREATE TRIGGER IF NOT EXISTS evidence_retirement_events_no_update
                BEFORE UPDATE ON evidence_retirement_events
                WHEN NOT (
                    OLD.sealed = 0 AND NEW.sealed = 1
                    AND NEW.revision IS OLD.revision
                    AND NEW.event_id IS OLD.event_id
                    AND NEW.lineage_id IS OLD.lineage_id
                    AND NEW.source_family IS OLD.source_family
                    AND NEW.encounter_id IS OLD.encounter_id
                    AND NEW.identity_snapshot_json IS OLD.identity_snapshot_json
                    AND NEW.identity_snapshot_sha256 IS OLD.identity_snapshot_sha256
                    AND NEW.previous_event_digest IS OLD.previous_event_digest
                    AND NEW.event_digest IS OLD.event_digest
                    AND NEW.identity_count IS OLD.identity_count
                    AND NEW.actor IS OLD.actor
                    AND NEW.reason IS OLD.reason
                    AND NEW.retired_at IS OLD.retired_at
                    AND NEW.identity_count = (
                        SELECT COUNT(*) FROM evidence_retirement_identities
                         WHERE revision = OLD.revision
                    )
                    AND NEW.identity_count = (
                        SELECT COUNT(*)
                          FROM json_each(OLD.identity_snapshot_json, '$.identities')
                    )
                    AND NOT EXISTS (
                        SELECT 1
                          FROM json_each(OLD.identity_snapshot_json, '$.identities') AS item
                         WHERE NOT EXISTS (
                             SELECT 1 FROM evidence_retirement_identities AS identity
                              WHERE identity.revision = OLD.revision
                                AND identity.source_family = OLD.source_family
                                AND identity.encounter_id = OLD.encounter_id
                                AND identity.identity_namespace = item.key
                                AND identity.identity_value = item.value
                         )
                    )
                )
                BEGIN SELECT RAISE(ABORT, 'retirement events are immutable'); END;
            CREATE TRIGGER IF NOT EXISTS evidence_retirement_events_no_delete
                BEFORE DELETE ON evidence_retirement_events
                BEGIN SELECT RAISE(ABORT, 'retirement events are immutable'); END;
            CREATE TRIGGER IF NOT EXISTS evidence_retirement_identity_conflict_guard
                BEFORE INSERT ON evidence_retirement_identities
                WHEN EXISTS (
                    SELECT 1 FROM evidence_retirement_identities
                     WHERE (
                         revision = NEW.revision
                         AND identity_namespace = NEW.identity_namespace
                     ) OR (
                         source_family = NEW.source_family
                         AND identity_namespace = NEW.identity_namespace
                         AND identity_value = NEW.identity_value
                     )
                )
                BEGIN
                    SELECT RAISE(ABORT, 'retirement identity conflicts are immutable');
                END;
            CREATE TRIGGER IF NOT EXISTS evidence_retirement_identity_insert_guard
                BEFORE INSERT ON evidence_retirement_identities
                WHEN NOT EXISTS (
                    SELECT 1
                      FROM evidence_retirement_events AS event
                      JOIN json_each(
                          event.identity_snapshot_json, '$.identities'
                      ) AS item
                        ON item.key = NEW.identity_namespace
                       AND item.value = NEW.identity_value
                     WHERE event.revision = NEW.revision
                       AND event.source_family = NEW.source_family
                       AND event.encounter_id = NEW.encounter_id
                       AND event.sealed = 0
                )
                BEGIN
                    SELECT RAISE(
                        ABORT,
                        'retirement identity must match an unsealed event snapshot'
                    );
                END;
            CREATE TRIGGER IF NOT EXISTS evidence_retirement_identities_no_update
                BEFORE UPDATE ON evidence_retirement_identities
                BEGIN SELECT RAISE(ABORT, 'retirement identities are immutable'); END;
            CREATE TRIGGER IF NOT EXISTS evidence_retirement_identities_no_delete
                BEFORE DELETE ON evidence_retirement_identities
                BEGIN SELECT RAISE(ABORT, 'retirement identities are immutable'); END;
"""


@initialize_once_per_database
def init_evidence_retirement_storage(db_path: Path) -> None:
    with connect_database(db_path) as db:
        db.execute("BEGIN IMMEDIATE")
        execute_sql_script_statements(db, EVIDENCE_RETIREMENT_SCHEMA_SQL)
        row = db.execute(
            "SELECT lineage_id FROM evidence_retirement_lineage WHERE singleton=1"
        ).fetchone()
        if row is None:
            db.execute(
                "INSERT INTO evidence_retirement_lineage VALUES (1,?,?)",
                (uuid.uuid4().hex, _now()),
            )
        db.commit()


def retirement_cache_token_on_connection(connection: sqlite3.Connection) -> str:
    """Return the retirement lineage head from the caller's read snapshot."""
    require_retirement_authority(connection)
    lineage = connection.execute(
        "SELECT lineage_id FROM evidence_retirement_lineage WHERE singleton=1"
    ).fetchone()
    head = connection.execute(
        "SELECT revision,event_digest FROM evidence_retirement_events "
        "WHERE sealed=1 ORDER BY revision DESC LIMIT 1"
    ).fetchone()
    return f"{lineage[0]}:{head[0] if head else 0}:{head[1] if head else 'root'}"


def retirement_cache_token(db_path: Path) -> str:
    """Return a branch-safe token for selectors and derived-result caches."""
    with connect_database(db_path, read_only=True) as db:
        db.execute("BEGIN")
        return retirement_cache_token_on_connection(db)


def retire_evidence(
    db_path: Path,
    *,
    source_family: str,
    encounter_id: str,
    actor: str,
    reason: str,
    adapter: EvidenceRetirementAdapter,
    expected_authority_revision: int | None = None,
    expected_identity_snapshot_sha256: str | None = None,
    expected_impact_sha256: str | None = None,
) -> dict[str, object]:
    """Retire one source encounter atomically without deleting retained evidence."""
    source_family = _canonical_text(source_family, "source family", maximum=100)
    encounter_id = _canonical_text(encounter_id, "encounter id", maximum=500)
    actor = _canonical_text(actor, "actor", maximum=200)
    reason = _canonical_text(reason, "reason")
    retired_at = _now()
    with connect_database(db_path) as db:
        db.execute("BEGIN IMMEDIATE")
        existing = db.execute(
            "SELECT revision FROM evidence_retirement_events "
            "WHERE source_family=? AND encounter_id=?",
            (source_family, encounter_id),
        ).fetchone()
        if existing is not None:
            raise EvidenceAlreadyRetired(
                f"evidence encounter is already retired at revision {existing[0]}"
            )
        blocked = adapter.active_work_detail(db, encounter_id)
        if blocked:
            raise EvidenceRetirementBlocked(str(blocked))
        identities, snapshot_json, snapshot_sha256 = _identity_snapshot(
            source_family, encounter_id,
            adapter.resolve_identities(db, encounter_id),
        )
        lineage = db.execute(
            "SELECT lineage_id FROM evidence_retirement_lineage WHERE singleton=1"
        ).fetchone()
        if lineage is None:
            raise EvidenceRetirementError("retirement lineage is missing")
        head = db.execute(
            "SELECT revision,event_digest FROM evidence_retirement_events "
            "WHERE sealed=1 ORDER BY revision DESC LIMIT 1"
        ).fetchone()
        authority_revision = int(head[0]) if head else 0
        if (
            expected_authority_revision is not None
            and int(expected_authority_revision) != authority_revision
        ):
            raise EvidenceRetirementBlocked(
                "Retirement authority changed after review; review the source again"
            )
        if (
            expected_identity_snapshot_sha256 is not None
            and expected_identity_snapshot_sha256 != snapshot_sha256
        ):
            raise EvidenceRetirementBlocked(
                "Exact source identity changed after review; review the source again"
            )
        impact = _retirement_impact(
            source_family,
            encounter_id,
            authority_revision=authority_revision,
            identity_count=len(identities),
            identity_snapshot_sha256=snapshot_sha256,
        )
        if (
            expected_impact_sha256 is not None
            and expected_impact_sha256 != _digest(impact)
        ):
            raise EvidenceRetirementBlocked(
                "Retirement impact changed after review; review the source again"
            )
        previous_digest = head[1] if head else "root"
        event_id = uuid.uuid4().hex
        body = {
            "event_id": event_id,
            "lineage_id": lineage[0],
            "source_family": source_family,
            "encounter_id": encounter_id,
            "identity_snapshot_sha256": snapshot_sha256,
            "previous_event_digest": previous_digest,
            "identity_count": len(identities),
            "actor": actor,
            "reason": reason,
            "retired_at": retired_at,
        }
        event_digest = _digest(body)
        cursor = db.execute(
            """INSERT INTO evidence_retirement_events(
                   event_id,lineage_id,source_family,encounter_id,
                   identity_snapshot_json,identity_snapshot_sha256,
                   previous_event_digest,event_digest,identity_count,sealed,
                   actor,reason,retired_at
               ) VALUES (?,?,?,?,?,?,?,?,?,0,?,?,?)""",
            (
                event_id, lineage[0], source_family, encounter_id,
                snapshot_json, snapshot_sha256, previous_digest, event_digest,
                len(identities), actor, reason, retired_at,
            ),
        )
        revision = int(cursor.lastrowid)
        db.executemany(
            """INSERT INTO evidence_retirement_identities(
                   revision,source_family,encounter_id,
                   identity_namespace,identity_value
               ) VALUES (?,?,?,?,?)""",
            [
                (revision, source_family, encounter_id, namespace, value)
                for namespace, value in sorted(identities.items())
            ],
        )
        db.execute(
            "UPDATE evidence_retirement_events SET sealed=1 WHERE revision=?",
            (revision,),
        )
        db.commit()
    return {
        **body,
        "revision": revision,
        "event_digest": event_digest,
        "identity_snapshot": json.loads(snapshot_json),
    }


def preview_evidence_retirement(
    db_path: Path,
    *,
    source_family: str,
    encounter_id: str,
    adapter: EvidenceRetirementAdapter,
    actor: str,
) -> dict[str, object]:
    """Review one exact encounter without changing its source or audit history.

    The final retirement repeats every check under the write lock.  This preview is
    therefore operator guidance, not an authorization token or a stale promise that
    an in-progress source will still be eligible when confirmation is submitted.
    """
    source_family = _canonical_text(source_family, "source family", maximum=100)
    encounter_id = _canonical_text(encounter_id, "encounter id", maximum=500)
    actor = _canonical_text(actor, "actor", maximum=200)
    with connect_database(db_path, read_only=True) as db:
        db.execute("BEGIN")
        require_retirement_authority(db)
        record = retirement_record(
            db, source_family=source_family, encounter_id=encounter_id,
        )
        if record is not None:
            raise EvidenceAlreadyRetired(
                f"evidence encounter is already retired at revision {record['revision']}"
            )
        blocked = adapter.active_work_detail(db, encounter_id)
        if blocked:
            raise EvidenceRetirementBlocked(str(blocked))
        identities, _snapshot, snapshot_sha256 = _identity_snapshot(
            source_family,
            encounter_id,
            adapter.resolve_identities(db, encounter_id),
        )
        head = db.execute(
            "SELECT revision FROM evidence_retirement_events "
            "WHERE sealed=1 ORDER BY revision DESC LIMIT 1"
        ).fetchone()
        authority_revision = int(head[0]) if head else 0
    impact = _retirement_impact(
        source_family,
        encounter_id,
        authority_revision=authority_revision,
        identity_count=len(identities),
        identity_snapshot_sha256=snapshot_sha256,
    )
    confirmation = (
        f"RETIRE {source_family} {encounter_id} AT {authority_revision} "
        f"{snapshot_sha256[:12]}"
    )
    return {
        "source_family": source_family,
        "encounter_id": encounter_id,
        "actor": actor,
        "authority_revision": authority_revision,
        "identity_count": len(identities),
        "identity_snapshot_sha256": snapshot_sha256,
        "confirmation": confirmation,
        "impact": impact,
    }


def list_retirement_records(
    db_path: Path, *, limit: int = 100, offset: int = 0,
) -> dict[str, object]:
    """Return the append-only operator audit without exposing identity snapshots."""
    if not 1 <= int(limit) <= 500 or int(offset) < 0:
        raise EvidenceRetirementError("Invalid retirement audit page range")
    with connect_database(db_path, read_only=True) as db:
        db.row_factory = sqlite3.Row
        db.execute("BEGIN")
        require_retirement_authority(db)
        total = int(db.execute(
            "SELECT COUNT(*) FROM evidence_retirement_events WHERE sealed=1"
        ).fetchone()[0])
        rows = [dict(row) for row in db.execute(
            """SELECT revision,event_id,source_family,encounter_id,actor,reason,
                      retired_at,event_digest,identity_count
                   FROM evidence_retirement_events
                  WHERE sealed=1
                  ORDER BY revision DESC
                  LIMIT ? OFFSET ?""",
            (int(limit), int(offset)),
        )]
    return {
        "items": rows,
        "total": total,
        "limit": int(limit),
        "offset": int(offset),
        "has_more": int(offset) + len(rows) < total,
    }


def is_evidence_retired(
    connection: sqlite3.Connection, *, source_family: str, encounter_id: str,
) -> bool:
    return connection.execute(
        "SELECT 1 FROM evidence_retirement_events "
        "WHERE source_family=? AND encounter_id=? AND sealed=1",
        (source_family, encounter_id),
    ).fetchone() is not None


def retirement_record(
    connection: sqlite3.Connection, *, source_family: str, encounter_id: str,
) -> dict[str, object] | None:
    row = connection.execute(
        """SELECT revision,event_id,actor,reason,retired_at,event_digest
             FROM evidence_retirement_events
            WHERE source_family=? AND encounter_id=? AND sealed=1""",
        (source_family, encounter_id),
    ).fetchone()
    if row is None:
        return None
    return {
        "revision": int(row[0]),
        "event_id": str(row[1]),
        "actor": str(row[2]),
        "reason": str(row[3]),
        "retired_at": str(row[4]),
        "event_digest": str(row[5]),
    }


def require_retirement_authority(connection: sqlite3.Connection) -> None:
    """Fail closed unless the lineage and event ledger are both readable."""
    try:
        lineage = connection.execute(
            "SELECT lineage_id FROM evidence_retirement_lineage WHERE singleton=1"
        ).fetchone()
        connection.execute(
            "SELECT revision FROM evidence_retirement_events WHERE sealed=1 LIMIT 1"
        ).fetchone()
    except sqlite3.OperationalError as exc:
        if "no such table" in str(exc).casefold():
            raise EvidenceRetirementError(
                "retirement authority is unavailable"
            ) from exc
        raise
    if lineage is None:
        raise EvidenceRetirementError("retirement lineage is missing")


def retirement_authority_token(connection: sqlite3.Connection) -> dict[str, object]:
    """Return the exact sealed authority head for one database snapshot."""
    require_retirement_authority(connection)
    lineage = connection.execute(
        "SELECT lineage_id FROM evidence_retirement_lineage WHERE singleton=1"
    ).fetchone()
    head = connection.execute(
        """SELECT revision,event_digest FROM evidence_retirement_events
            WHERE sealed=1 ORDER BY revision DESC LIMIT 1"""
    ).fetchone()
    return {
        "lineage_id": str(lineage[0]),
        "revision": int(head[0]) if head else 0,
        "event_digest": str(head[1]) if head else "root",
    }


def require_retirement_authority_token(
    connection: sqlite3.Connection, expected: Mapping[str, object],
) -> None:
    actual = retirement_authority_token(connection)
    normalized = {
        "lineage_id": str(expected.get("lineage_id") or ""),
        "revision": int(expected.get("revision") or 0),
        "event_digest": str(expected.get("event_digest") or ""),
    }
    if actual != normalized:
        raise RetiredEvidenceDependency(
            "retirement authority changed while the derived result was built"
        )


def require_active_encounter(
    connection: sqlite3.Connection, *, source_family: str, encounter_id: str,
) -> None:
    require_retirement_authority(connection)
    record = retirement_record(
        connection, source_family=source_family, encounter_id=encounter_id,
    )
    if record is not None:
        raise RetiredEvidenceDependency(
            f"Evidence encounter was retired at revision {record['revision']}"
        )


def require_artifact_observation_authority(
    connection: sqlite3.Connection,
) -> None:
    """Fail closed when encounter registration cannot support shared-content reads."""
    try:
        connection.execute(
            "SELECT observation_id FROM artifact_observations LIMIT 1"
        ).fetchone()
    except sqlite3.OperationalError as exc:
        if "no such table" in str(exc).casefold():
            raise EvidenceRetirementError(
                "artifact observation authority is unavailable"
            ) from exc
        raise


def retired_encounter_ids(
    connection: sqlite3.Connection, *, source_family: str,
) -> frozenset[str]:
    """Return sealed retired encounter identities from one authoritative snapshot."""
    require_retirement_authority(connection)
    return frozenset(
        str(row[0])
        for row in connection.execute(
            "SELECT encounter_id FROM evidence_retirement_events "
            "WHERE source_family=? AND sealed=1 ORDER BY encounter_id",
            (source_family,),
        ).fetchall()
    )


def require_active_registered_content(
    connection: sqlite3.Connection, *, source_family: str,
    source_kind: str, sha256: str,
) -> tuple[str, ...]:
    """Allow legacy content or content retained by at least one active encounter.

    The returned observation identities are active exact encounters.  An empty
    tuple means the content predates encounter registration and is therefore a
    legacy record, not proof that a registered encounter remains active.
    """
    require_retirement_authority(connection)
    require_artifact_observation_authority(connection)
    rows = connection.execute(
        """SELECT observation.observation_id
             FROM artifact_observations observation
            WHERE observation.source_kind=? AND observation.sha256=?
              AND NOT EXISTS (
                    SELECT 1 FROM evidence_retirement_events retired
                     WHERE retired.source_family=?
                       AND retired.encounter_id=observation.observation_id
                       AND retired.sealed=1
              )
            ORDER BY observation.observed_at DESC,observation.observation_id""",
        (source_kind, sha256, source_family),
    ).fetchall()
    if rows:
        return tuple(str(row[0]) for row in rows)
    registered = connection.execute(
        """SELECT 1 FROM artifact_observations
            WHERE source_kind=? AND sha256=? LIMIT 1""",
        (source_kind, sha256),
    ).fetchone()
    if registered is not None:
        raise RetiredEvidenceDependency(
            "Every registered encounter for this retained content was retired"
        )
    return ()


def active_encounter_sql(
    source_family: str, encounter_expression: str,
) -> tuple[str, tuple[str]]:
    """Return a bounded NOT EXISTS clause for a trusted table/column expression."""
    if not _SQL_IDENTITY_EXPRESSION.fullmatch(encounter_expression):
        raise EvidenceRetirementError("retirement SQL identity expression is invalid")
    return (
        "NOT EXISTS ("
        "SELECT 1 FROM evidence_retirement_events retired "
        "WHERE retired.source_family=? AND retired.encounter_id="
        f"{encounter_expression} AND retired.sealed=1)",
        (source_family,),
    )


def retired_dependency(
    connection: sqlite3.Connection, dependency: EvidenceDependency,
) -> tuple[int, str] | None:
    row = connection.execute(
        """SELECT identity.revision,identity.encounter_id
             FROM evidence_retirement_identities AS identity
             JOIN evidence_retirement_events AS event
               ON event.revision=identity.revision AND event.sealed=1
            WHERE identity.source_family=?
              AND identity.identity_namespace=?
              AND identity.identity_value=?""",
        (
            dependency.source_family,
            dependency.identity_namespace,
            dependency.identity_value,
        ),
    ).fetchone()
    return (int(row[0]), str(row[1])) if row else None


def require_active_dependencies(
    connection: sqlite3.Connection,
    dependencies: Sequence[EvidenceDependency],
) -> None:
    for dependency in dependencies:
        retired = retired_dependency(connection, dependency)
        if retired is not None:
            raise RetiredEvidenceDependency(
                f"evidence dependency was retired at revision {retired[0]}"
            )


def publish_with_active_dependencies(
    db_path: Path,
    dependencies: Sequence[EvidenceDependency],
    publish: Callable[[sqlite3.Connection], T],
) -> T:
    """Publish a result only while every exact source dependency is active."""
    with connect_database(db_path) as db:
        db.execute("BEGIN IMMEDIATE")
        require_active_dependencies(db, dependencies)
        result = publish(db)
        require_active_dependencies(db, dependencies)
        db.commit()
        return result
