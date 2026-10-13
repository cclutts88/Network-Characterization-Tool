"""Explicit Mission Environment declarations and per-scope coverage context.

These records describe administrator-reviewed operating context.  They never
infer or grant authorization and they do not start, block, or schedule network
contact.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import re
import sqlite3
import uuid

from pydantic import BaseModel, ConfigDict, Field

from app.database import connect_database, initialize_once_per_database
from app.network_scopes import init_network_scope_storage


TOOL_DEFINITIONS = (
    ("nmap", "Nmap"),
    ("arkime", "Arkime"),
    ("kibana", "Kibana / Elastic"),
    ("device_config", "Device configuration"),
)
TOOL_KEYS = {key for key, _label in TOOL_DEFINITIONS}
AVAILABILITY_VALUES = {"available", "unavailable", "unknown"}
COVERAGE_VALUES = {"available", "partial", "unavailable", "unknown"}
AUTHORIZATION_VALUES = {"authorized", "prohibited", "unknown"}
DEVICE_EVIDENCE_VALUES = {
    "full_configuration", "partial_configuration", "command_output_only",
    "analyst_known_manual", "unavailable", "unknown",
}
BLIND_SPOT_VALUES = {
    "no_passive_coverage", "missing_configuration", "unknown_nat",
    "partial_route_knowledge", "telemetry_gap", "stale_evidence",
    "unsupported_parser_field_mapping",
}
DERIVED_PROHIBITED_FLAG = "active_scan_prohibited"


class MissionEnvironmentConflict(ValueError):
    pass


class MissionEnvironmentProhibited(MissionEnvironmentConflict):
    """Raised before work is admitted when a reviewed scope prohibits Nmap."""


class ReviewedMissionScope(BaseModel):
    """The exact Mission Environment scope version an analyst reviewed."""

    model_config = ConfigDict(extra="forbid")

    scope_id: str = Field(min_length=1, max_length=100)
    version: int = Field(ge=0)


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _text(value: object, field: str, maximum: int, *, required: bool = False) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be text")
    cleaned = value.strip()
    if required and not cleaned:
        raise ValueError(f"{field} cannot be blank")
    if len(cleaned) > maximum:
        raise ValueError(f"{field} exceeds {maximum} characters")
    return cleaned


_SECRET_PATTERN = re.compile(
    r"(?ix)"
    r"(?:password|passwd|api[_ -]?key|access[_ -]?token|refresh[_ -]?token|"
    r"client[_ -]?secret|auth[_ -]?token|secret|token)\s*[:=]\s*\S+|"
    r"\bauthorization\s*:\s*(?:basic|bearer|digest|token)\s+\S+|"
    r"\bbearer\s+[A-Za-z0-9._~+/=-]{8,}|"
    r"\b[a-z][a-z0-9+.-]*://[^/\s:@]+:[^/\s@]+@|"
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----|"
    r"\bsk-[A-Za-z0-9_-]{12,}|"
    r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"
)


def _non_secret_text(value: object, field: str, maximum: int) -> str:
    cleaned = _text(value, field, maximum)
    if _SECRET_PATTERN.search(cleaned):
        raise ValueError(
            f"{field} must describe access without storing passwords, tokens, or keys"
        )
    return cleaned


def _enum(value: object, field: str, allowed: set[str]) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise ValueError(f"{field} is not a supported value")
    return value


def _flags(values: object) -> list[str]:
    if not isinstance(values, list) or any(not isinstance(item, str) for item in values):
        raise ValueError("blind_spots must be a list")
    if len(values) > len(BLIND_SPOT_VALUES):
        raise ValueError("blind_spots contains too many values")
    unknown = set(values) - BLIND_SPOT_VALUES
    if unknown:
        raise ValueError("blind_spots contains an unsupported value")
    return sorted(set(values))


@initialize_once_per_database
def init_mission_environment_storage(db_path: Path) -> None:
    init_network_scope_storage(db_path)
    with connect_database(db_path) as db:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS mission_environment_tools (
                tool_key TEXT PRIMARY KEY CHECK(tool_key IN (
                    'nmap', 'arkime', 'kibana', 'device_config'
                )),
                availability TEXT NOT NULL CHECK(availability IN (
                    'available', 'unavailable', 'unknown'
                )),
                version_text TEXT NOT NULL,
                access_method TEXT NOT NULL,
                notes TEXT NOT NULL,
                version INTEGER NOT NULL CHECK(version >= 1),
                created_at TEXT NOT NULL,
                created_by TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                updated_by TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS mission_scope_contexts (
                scope_id TEXT PRIMARY KEY REFERENCES network_scopes(scope_id),
                nmap_coverage TEXT NOT NULL CHECK(nmap_coverage IN (
                    'available', 'partial', 'unavailable', 'unknown'
                )),
                arkime_coverage TEXT NOT NULL CHECK(arkime_coverage IN (
                    'available', 'partial', 'unavailable', 'unknown'
                )),
                kibana_coverage TEXT NOT NULL CHECK(kibana_coverage IN (
                    'available', 'partial', 'unavailable', 'unknown'
                )),
                config_coverage TEXT NOT NULL CHECK(config_coverage IN (
                    'available', 'partial', 'unavailable', 'unknown'
                )),
                nmap_authorization TEXT NOT NULL CHECK(nmap_authorization IN (
                    'authorized', 'prohibited', 'unknown'
                )),
                device_evidence TEXT NOT NULL CHECK(device_evidence IN (
                    'full_configuration', 'partial_configuration',
                    'command_output_only', 'analyst_known_manual',
                    'unavailable', 'unknown'
                )),
                blind_spots_json TEXT NOT NULL,
                notes TEXT NOT NULL,
                version INTEGER NOT NULL CHECK(version >= 1),
                created_at TEXT NOT NULL,
                created_by TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                updated_by TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS mission_environment_audit (
                audit_id TEXT PRIMARY KEY,
                record_kind TEXT NOT NULL CHECK(record_kind IN ('tool', 'scope')),
                record_key TEXT NOT NULL,
                sequence INTEGER NOT NULL CHECK(sequence >= 1),
                actor TEXT NOT NULL,
                reason TEXT NOT NULL,
                previous_version INTEGER NOT NULL CHECK(previous_version >= 0),
                new_version INTEGER NOT NULL CHECK(new_version >= 1),
                before_json TEXT NOT NULL,
                after_json TEXT NOT NULL,
                recorded_at TEXT NOT NULL,
                UNIQUE(record_kind, record_key, sequence)
            );
            CREATE INDEX IF NOT EXISTS mission_environment_audit_record
                ON mission_environment_audit(record_kind, record_key, sequence);
            CREATE TRIGGER IF NOT EXISTS mission_environment_tool_key_immutable
                BEFORE UPDATE OF tool_key ON mission_environment_tools
                BEGIN SELECT RAISE(ABORT, 'mission tool identity is immutable'); END;
            CREATE TRIGGER IF NOT EXISTS mission_scope_id_immutable
                BEFORE UPDATE OF scope_id ON mission_scope_contexts
                BEGIN SELECT RAISE(ABORT, 'mission scope identity is immutable'); END;
            CREATE TRIGGER IF NOT EXISTS mission_environment_audit_no_update
                BEFORE UPDATE ON mission_environment_audit
                BEGIN SELECT RAISE(ABORT, 'mission environment audit is immutable'); END;
            CREATE TRIGGER IF NOT EXISTS mission_environment_audit_no_delete
                BEFORE DELETE ON mission_environment_audit
                BEGIN SELECT RAISE(ABORT, 'mission environment audit is immutable'); END;
            """
        )


def _default_tool(tool_key: str, label: str) -> dict:
    return {
        "tool_key": tool_key, "label": label, "availability": "unknown",
        "version_text": "", "access_method": "", "notes": "", "version": 0,
        "configured": False, "created_at": None, "created_by": None,
        "updated_at": None, "updated_by": None,
    }


def _tool_snapshot(row: sqlite3.Row | None, tool_key: str, label: str) -> dict:
    if row is None:
        return _default_tool(tool_key, label)
    return {
        "tool_key": row["tool_key"], "label": label,
        "availability": row["availability"], "version_text": row["version_text"],
        "access_method": row["access_method"], "notes": row["notes"],
        "version": int(row["version"]), "configured": True,
        "created_at": row["created_at"], "created_by": row["created_by"],
        "updated_at": row["updated_at"], "updated_by": row["updated_by"],
    }


def _default_scope(scope: sqlite3.Row) -> dict:
    return {
        "scope_id": scope["scope_id"], "scope_label": scope["label"],
        "scope_active": bool(scope["active"]), "nmap_coverage": "unknown",
        "arkime_coverage": "unknown", "kibana_coverage": "unknown",
        "config_coverage": "unknown", "nmap_authorization": "unknown",
        "device_evidence": "unknown", "blind_spots": [], "notes": "",
        "version": 0, "configured": False, "created_at": None,
        "created_by": None, "updated_at": None, "updated_by": None,
    }


def _scope_snapshot(row: sqlite3.Row | None, scope: sqlite3.Row) -> dict:
    if row is None:
        return _default_scope(scope)
    blind_spots = json.loads(row["blind_spots_json"])
    if row["nmap_authorization"] == "prohibited":
        blind_spots = sorted({*blind_spots, DERIVED_PROHIBITED_FLAG})
    return {
        "scope_id": scope["scope_id"], "scope_label": scope["label"],
        "scope_active": bool(scope["active"]),
        "nmap_coverage": row["nmap_coverage"],
        "arkime_coverage": row["arkime_coverage"],
        "kibana_coverage": row["kibana_coverage"],
        "config_coverage": row["config_coverage"],
        "nmap_authorization": row["nmap_authorization"],
        "device_evidence": row["device_evidence"], "blind_spots": blind_spots,
        "notes": row["notes"], "version": int(row["version"]),
        "configured": True, "created_at": row["created_at"],
        "created_by": row["created_by"], "updated_at": row["updated_at"],
        "updated_by": row["updated_by"],
    }


def _mission_tool_rows(db: sqlite3.Connection) -> dict[str, sqlite3.Row]:
    db.row_factory = sqlite3.Row
    return {
        row["tool_key"]: row
        for row in db.execute("SELECT * FROM mission_environment_tools").fetchall()
    }


def resolve_collection_mission_review(
    db: sqlite3.Connection,
    *,
    saved_network_ids: list[str],
    manual_targets: list[str],
    reviewed_scopes: list[dict],
    enforce_prohibited: bool = True,
) -> dict:
    """Recheck reviewed Mission declarations while the caller holds a write lock.

    Network context comes only from the selected Saved Network association leaves.
    Manual targets and unassociated Saved Networks remain explicitly unknown even if
    their addresses happen to overlap a declared scope.
    """
    db.row_factory = sqlite3.Row
    unique_ids = list(dict.fromkeys(str(value) for value in saved_network_ids))
    if len(unique_ids) > 100:
        raise MissionEnvironmentConflict("Choose 100 or fewer Saved Networks")
    if len(reviewed_scopes) > 100:
        raise MissionEnvironmentConflict("Mission Environment review is too large")
    submitted: dict[str, int] = {}
    for item in reviewed_scopes:
        scope_id = str(item.get("scope_id") or "")
        version = item.get("version")
        if not scope_id or isinstance(version, bool) or not isinstance(version, int) or version < 0:
            raise MissionEnvironmentConflict("Mission Environment review is invalid")
        if scope_id in submitted:
            raise MissionEnvironmentConflict("Mission Environment review contains a duplicate scope")
        submitted[scope_id] = version

    scope_ids: set[str] = set()
    unassociated: list[str] = []
    for saved_network_id in unique_ids:
        network = db.execute(
            "SELECT active FROM saved_networks WHERE saved_network_id = ?",
            (saved_network_id,),
        ).fetchone()
        if network is None or not bool(network[0]):
            raise MissionEnvironmentConflict(
                "A selected Saved Network was removed or changed; review the scan again"
            )
        association = db.execute(
            """
            SELECT current.scope_id
            FROM saved_network_scope_associations current
            WHERE current.saved_network_id = ?
              AND NOT EXISTS (
                  SELECT 1 FROM saved_network_scope_associations successor
                  WHERE successor.predecessor_id = current.association_id
              )
            """,
            (saved_network_id,),
        ).fetchone()
        if association is None or association[0] is None:
            unassociated.append(saved_network_id)
        else:
            scope_ids.add(str(association[0]))

    current_versions: dict[str, int] = {}
    snapshots: list[dict] = []
    for scope_id in sorted(scope_ids):
        scope = db.execute(
            "SELECT * FROM network_scopes WHERE scope_id = ?", (scope_id,)
        ).fetchone()
        if scope is None or not bool(scope["active"]):
            raise MissionEnvironmentConflict(
                "A selected Network Scope was archived; review the scan again"
            )
        row = db.execute(
            "SELECT * FROM mission_scope_contexts WHERE scope_id = ?", (scope_id,)
        ).fetchone()
        snapshot = _scope_snapshot(row, scope)
        current_versions[scope_id] = int(snapshot["version"])
        snapshots.append(snapshot)
    if submitted != current_versions:
        raise MissionEnvironmentConflict(
            "Mission Environment changed after review; review the scan again"
        )

    tools = _mission_tool_rows(db)
    tool_snapshots = [
        _tool_snapshot(tools.get(key), key, label)
        for key, label in TOOL_DEFINITIONS
    ]
    available_tools = {
        item["tool_key"]: item
        for item in tool_snapshots
        if item["availability"] == "available"
    }
    pivots = []
    for snapshot in snapshots:
        for tool_key in ("arkime", "kibana"):
            coverage = snapshot[f"{tool_key}_coverage"]
            tool = available_tools.get(tool_key)
            if tool is None or coverage not in {"available", "partial"}:
                continue
            pivots.append({
                "scope_id": snapshot["scope_id"],
                "scope_label": snapshot["scope_label"],
                "tool_key": tool_key,
                "tool_label": tool["label"],
                "coverage": coverage,
                "access_method": tool["access_method"],
                "tool_version": tool["version"],
            })

    prohibited = [
        item for item in snapshots if item["nmap_authorization"] == "prohibited"
    ]
    unknown = bool(manual_targets or unassociated) or any(
        item["nmap_authorization"] == "unknown" for item in snapshots
    )
    result = {
        "decision": "prohibited" if prohibited else "unknown" if unknown else "reviewed",
        "certified_at": _utc_now(),
        "scopes": snapshots,
        "tools": tool_snapshots,
        "passive_pivots": pivots,
        "manual_targets_unknown": bool(manual_targets),
        "unassociated_saved_network_ids": unassociated,
        "authorization_notice": (
            "Mission Environment is an administrator-reviewed declaration. Existing "
            "operator authorization and No-Strike controls remain authoritative."
        ),
    }
    if prohibited and enforce_prohibited:
        labels = ", ".join(item["scope_label"] for item in prohibited)
        raise MissionEnvironmentProhibited(
            f"Nmap is prohibited for the reviewed Network Scope: {labels}"
        )
    return result


def _audit(db: sqlite3.Connection, *, kind: str, key: str, actor: str,
           reason: str, before: dict, after: dict) -> None:
    sequence = db.execute(
        "SELECT COALESCE(MAX(sequence), 0) + 1 FROM mission_environment_audit "
        "WHERE record_kind = ? AND record_key = ?", (kind, key),
    ).fetchone()[0]
    db.execute(
        """INSERT INTO mission_environment_audit (
               audit_id, record_kind, record_key, sequence, actor, reason,
               previous_version, new_version, before_json, after_json, recorded_at
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (uuid.uuid4().hex, kind, key, sequence, actor, reason,
         before["version"], after["version"], json.dumps(before, sort_keys=True),
         json.dumps(after, sort_keys=True), _utc_now()),
    )


def get_mission_environment(db_path: Path, *, limit: int = 50, offset: int = 0,
                            include_archived: bool = False) -> dict:
    """Read a bounded snapshot without initializing or repairing schema."""
    limit = max(1, min(int(limit), 100))
    offset = max(0, int(offset))
    if not db_path.is_file():
        return {"tools": [_default_tool(*item) for item in TOOL_DEFINITIONS],
                "scopes": [], "scope_total": 0, "limit": limit, "offset": offset}
    with connect_database(db_path, read_only=True) as db:
        db.row_factory = sqlite3.Row
        tables = {row[0] for row in db.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'").fetchall()}
        if "network_scopes" not in tables:
            return {"tools": [_default_tool(*item) for item in TOOL_DEFINITIONS],
                    "scopes": [], "scope_total": 0, "limit": limit, "offset": offset}
        tool_rows = {}
        if "mission_environment_tools" in tables:
            tool_rows = {row["tool_key"]: row for row in db.execute(
                "SELECT * FROM mission_environment_tools").fetchall()}
        where = "" if include_archived else " WHERE active = 1"
        total = int(db.execute("SELECT COUNT(*) FROM network_scopes" + where).fetchone()[0])
        scopes = db.execute(
            "SELECT * FROM network_scopes" + where
            + " ORDER BY active DESC, label_key, scope_id LIMIT ? OFFSET ?",
            (limit, offset),
        ).fetchall()
        contexts = {}
        if scopes and "mission_scope_contexts" in tables:
            placeholders = ",".join("?" for _ in scopes)
            contexts = {row["scope_id"]: row for row in db.execute(
                f"SELECT * FROM mission_scope_contexts WHERE scope_id IN ({placeholders})",
                tuple(row["scope_id"] for row in scopes),
            ).fetchall()}
    return {
        "tools": [_tool_snapshot(tool_rows.get(key), key, label)
                  for key, label in TOOL_DEFINITIONS],
        "scopes": [_scope_snapshot(contexts.get(scope["scope_id"]), scope)
                   for scope in scopes],
        "scope_total": total, "limit": limit, "offset": offset,
    }


def update_mission_tool(db_path: Path, tool_key: str, *, expected_version: int,
                        availability: str, version_text: str, access_method: str,
                        notes: str, actor: str, reason: str) -> dict:
    init_mission_environment_storage(db_path)
    if tool_key not in TOOL_KEYS:
        raise KeyError("Mission tool not found")
    label = dict(TOOL_DEFINITIONS)[tool_key]
    availability = _enum(availability, "availability", AVAILABILITY_VALUES)
    version_text = _text(version_text, "version_text", 120)
    access_method = _non_secret_text(access_method, "access_method", 500)
    notes = _non_secret_text(notes, "notes", 1000)
    actor = _text(actor, "actor", 100, required=True)
    reason = _text(reason, "reason", 500, required=True)
    if not isinstance(expected_version, int) or isinstance(expected_version, bool) or expected_version < 0:
        raise ValueError("expected_version must be zero or greater")
    with connect_database(db_path) as db:
        db.row_factory = sqlite3.Row
        db.execute("BEGIN IMMEDIATE")
        row = db.execute(
            "SELECT * FROM mission_environment_tools WHERE tool_key = ?", (tool_key,),
        ).fetchone()
        before = _tool_snapshot(row, tool_key, label)
        if before["version"] != expected_version:
            raise MissionEnvironmentConflict("Mission tool changed in another session")
        timestamp = _utc_now()
        if row is None:
            db.execute(
                """INSERT INTO mission_environment_tools (
                       tool_key, availability, version_text, access_method, notes,
                       version, created_at, created_by, updated_at, updated_by
                   ) VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?, ?)""",
                (tool_key, availability, version_text, access_method, notes,
                 timestamp, actor, timestamp, actor),
            )
        else:
            changed = db.execute(
                """UPDATE mission_environment_tools
                      SET availability = ?, version_text = ?, access_method = ?, notes = ?,
                          version = version + 1, updated_at = ?, updated_by = ?
                    WHERE tool_key = ? AND version = ?""",
                (availability, version_text, access_method, notes, timestamp, actor,
                 tool_key, expected_version),
            ).rowcount
            if changed != 1:
                raise MissionEnvironmentConflict("Mission tool changed in another session")
        after_row = db.execute(
            "SELECT * FROM mission_environment_tools WHERE tool_key = ?", (tool_key,),
        ).fetchone()
        after = _tool_snapshot(after_row, tool_key, label)
        _audit(db, kind="tool", key=tool_key, actor=actor, reason=reason,
               before=before, after=after)
    return after


def update_scope_context(db_path: Path, scope_id: str, *, expected_version: int,
                         nmap_coverage: str, arkime_coverage: str,
                         kibana_coverage: str, config_coverage: str,
                         nmap_authorization: str, device_evidence: str,
                         blind_spots: list[str], notes: str, actor: str,
                         reason: str) -> dict:
    init_mission_environment_storage(db_path)
    values = {
        "nmap_coverage": _enum(nmap_coverage, "nmap_coverage", COVERAGE_VALUES),
        "arkime_coverage": _enum(arkime_coverage, "arkime_coverage", COVERAGE_VALUES),
        "kibana_coverage": _enum(kibana_coverage, "kibana_coverage", COVERAGE_VALUES),
        "config_coverage": _enum(config_coverage, "config_coverage", COVERAGE_VALUES),
        "nmap_authorization": _enum(
            nmap_authorization, "nmap_authorization", AUTHORIZATION_VALUES
        ),
        "device_evidence": _enum(
            device_evidence, "device_evidence", DEVICE_EVIDENCE_VALUES
        ),
    }
    flags = _flags(blind_spots)
    notes = _non_secret_text(notes, "notes", 1000)
    actor = _text(actor, "actor", 100, required=True)
    reason = _text(reason, "reason", 500, required=True)
    if not isinstance(expected_version, int) or isinstance(expected_version, bool) or expected_version < 0:
        raise ValueError("expected_version must be zero or greater")
    with connect_database(db_path) as db:
        db.row_factory = sqlite3.Row
        db.execute("BEGIN IMMEDIATE")
        scope = db.execute(
            "SELECT * FROM network_scopes WHERE scope_id = ?", (scope_id,),
        ).fetchone()
        if scope is None:
            raise KeyError("Network scope not found")
        if not bool(scope["active"]):
            raise ValueError("Archived network scopes cannot be changed")
        row = db.execute(
            "SELECT * FROM mission_scope_contexts WHERE scope_id = ?", (scope_id,),
        ).fetchone()
        before = _scope_snapshot(row, scope)
        if before["version"] != expected_version:
            raise MissionEnvironmentConflict("Mission scope context changed in another session")
        timestamp = _utc_now()
        params = (
            values["nmap_coverage"], values["arkime_coverage"],
            values["kibana_coverage"], values["config_coverage"],
            values["nmap_authorization"], values["device_evidence"],
            json.dumps(flags), notes,
        )
        if row is None:
            db.execute(
                """INSERT INTO mission_scope_contexts (
                       scope_id, nmap_coverage, arkime_coverage, kibana_coverage,
                       config_coverage, nmap_authorization, device_evidence,
                       blind_spots_json, notes, version, created_at, created_by,
                       updated_at, updated_by
                   ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?)""",
                (scope_id, *params, timestamp, actor, timestamp, actor),
            )
        else:
            changed = db.execute(
                """UPDATE mission_scope_contexts
                      SET nmap_coverage = ?, arkime_coverage = ?, kibana_coverage = ?,
                          config_coverage = ?, nmap_authorization = ?, device_evidence = ?,
                          blind_spots_json = ?, notes = ?, version = version + 1,
                          updated_at = ?, updated_by = ?
                    WHERE scope_id = ? AND version = ?""",
                (*params, timestamp, actor, scope_id, expected_version),
            ).rowcount
            if changed != 1:
                raise MissionEnvironmentConflict(
                    "Mission scope context changed in another session"
                )
        after_row = db.execute(
            "SELECT * FROM mission_scope_contexts WHERE scope_id = ?", (scope_id,),
        ).fetchone()
        after = _scope_snapshot(after_row, scope)
        _audit(db, kind="scope", key=scope_id, actor=actor, reason=reason,
               before=before, after=after)
    return after


def list_mission_history(db_path: Path, *, kind: str, key: str,
                         limit: int = 50, offset: int = 0) -> dict:
    if kind not in {"tool", "scope"}:
        raise ValueError("Unsupported history kind")
    limit = max(1, min(int(limit), 100))
    offset = max(0, int(offset))
    if not db_path.is_file():
        return {"items": [], "total": 0, "limit": limit, "offset": offset}
    with connect_database(db_path, read_only=True) as db:
        db.row_factory = sqlite3.Row
        table = db.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' "
            "AND name = 'mission_environment_audit'"
        ).fetchone()
        if table is None:
            return {"items": [], "total": 0, "limit": limit, "offset": offset}
        total = int(db.execute(
            "SELECT COUNT(*) FROM mission_environment_audit "
            "WHERE record_kind = ? AND record_key = ?", (kind, key),
        ).fetchone()[0])
        rows = db.execute(
            """SELECT * FROM mission_environment_audit
                WHERE record_kind = ? AND record_key = ?
                ORDER BY sequence DESC LIMIT ? OFFSET ?""",
            (kind, key, limit, offset),
        ).fetchall()
    return {
        "items": [{**dict(row), "before": json.loads(row["before_json"]),
                   "after": json.loads(row["after_json"])} for row in rows],
        "total": total, "limit": limit, "offset": offset,
    }
