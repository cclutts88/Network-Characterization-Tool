"""Bounded manual intake for Arkime Sessions API JSON exports.

This module retains exact export bytes and publishes immutable per-session receipts.
It intentionally does not ingest PCAP, contact Arkime, infer capture coverage, merge
observations, or feed canonical current-state selectors.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import sqlite3
import stat
import uuid

from app.artifacts import (
    artifact_root_for,
    canonical_artifact_path,
    init_artifact_storage,
    register_artifact_bytes,
)
from app.database import connect_database, initialize_once_per_database
from app.evidence_maintenance import guarded_evidence_mutation
from app.network_scopes import init_network_scope_storage


ARKIME_PARSER_VERSION = "arkime-sessions-json:1"
ARKIME_SOURCE_KIND = "arkime_sessions_json"
MAX_ARKIME_JSON_BYTES = 10 * 1024 * 1024
MAX_ARKIME_SESSIONS = 10_000
MAX_PAGE = 100
SUPPORTED_BOUNDING = {"first", "last", "both", "either"}
DECLARATIONS = {"complete", "partial", "unknown"}


class ArkimeEvidenceError(ValueError):
    pass


class ArkimeEvidenceConflict(ArkimeEvidenceError):
    pass


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _immutable_triggers(table: str) -> str:
    return f"""
        CREATE TRIGGER IF NOT EXISTS {table}_no_update
        BEFORE UPDATE ON {table}
        BEGIN SELECT RAISE(ABORT, '{table} is immutable'); END;
        CREATE TRIGGER IF NOT EXISTS {table}_no_delete
        BEFORE DELETE ON {table}
        BEGIN SELECT RAISE(ABORT, '{table} is immutable'); END;
    """


@initialize_once_per_database
def init_arkime_evidence_storage(db_path: Path) -> None:
    init_network_scope_storage(db_path)
    init_artifact_storage(db_path)
    with connect_database(db_path) as db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS arkime_imports (
                import_id TEXT PRIMARY KEY,
                observation_id TEXT NOT NULL UNIQUE
                    REFERENCES artifact_observations(observation_id),
                scope_id TEXT NOT NULL REFERENCES network_scopes(scope_id),
                scope_label TEXT NOT NULL,
                scope_version INTEGER NOT NULL CHECK(scope_version >= 1),
                operator_sensor TEXT NOT NULL,
                query_start TEXT NOT NULL,
                query_end TEXT NOT NULL,
                bounding_mode TEXT NOT NULL CHECK(
                    bounding_mode IN ('first', 'last', 'both', 'either')
                ),
                query_expression TEXT NOT NULL DEFAULT '',
                operator_export_assessment TEXT NOT NULL CHECK(
                    operator_export_assessment IN ('complete', 'partial', 'unknown')
                ),
                capture_coverage TEXT NOT NULL CHECK(
                    capture_coverage IN ('complete', 'partial', 'unknown')
                ),
                calculated_export_completeness TEXT NOT NULL CHECK(
                    calculated_export_completeness IN ('complete', 'partial', 'unknown')
                ),
                returned_count INTEGER NOT NULL CHECK(returned_count >= 0),
                records_filtered INTEGER CHECK(records_filtered >= 0),
                records_total INTEGER CHECK(records_total >= 0),
                timestamp_unit TEXT NOT NULL CHECK(
                    timestamp_unit IN ('seconds', 'milliseconds', 'iso8601', 'none')
                ),
                parser_version TEXT NOT NULL,
                imported_at TEXT NOT NULL,
                actor TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS arkime_imports_scope_time
                ON arkime_imports(scope_id, imported_at DESC, import_id DESC);
            CREATE TABLE IF NOT EXISTS arkime_session_receipts (
                receipt_id TEXT PRIMARY KEY,
                import_id TEXT NOT NULL REFERENCES arkime_imports(import_id),
                source_ordinal INTEGER NOT NULL CHECK(source_ordinal >= 0),
                session_id TEXT,
                source_node TEXT,
                source_ip TEXT NOT NULL,
                source_port INTEGER CHECK(source_port BETWEEN 0 AND 65535),
                destination_ip TEXT NOT NULL,
                destination_port INTEGER CHECK(destination_port BETWEEN 0 AND 65535),
                transport TEXT,
                applications_json TEXT NOT NULL DEFAULT '[]',
                first_packet TEXT NOT NULL,
                last_packet TEXT NOT NULL,
                packet_count INTEGER CHECK(packet_count >= 0),
                byte_count INTEGER CHECK(byte_count >= 0),
                vlan_json TEXT NOT NULL DEFAULT '[]',
                context_json TEXT NOT NULL DEFAULT '{}',
                UNIQUE(import_id, source_ordinal)
            );
            CREATE INDEX IF NOT EXISTS arkime_session_receipts_import
                ON arkime_session_receipts(import_id, source_ordinal);
            CREATE INDEX IF NOT EXISTS arkime_session_receipts_source
                ON arkime_session_receipts(source_ip, destination_ip);
        """ + _immutable_triggers("arkime_imports")
            + _immutable_triggers("arkime_session_receipts"))


def _text(value, field: str, maximum: int, *, allow_blank: bool = False) -> str:
    if not isinstance(value, str):
        raise ArkimeEvidenceError(f"{field} must be text")
    result = value.strip()
    if not result and not allow_blank:
        raise ArkimeEvidenceError(f"{field} cannot be blank")
    if len(result) > maximum:
        raise ArkimeEvidenceError(f"{field} exceeds {maximum} characters")
    return result


def _declaration(value: str, field: str) -> str:
    value = _text(value, field, 20).lower()
    if value not in DECLARATIONS:
        raise ArkimeEvidenceError(f"{field} must be complete, partial, or unknown")
    return value


def _canonical_time(value: str, field: str) -> tuple[str, datetime]:
    if not isinstance(value, str):
        raise ArkimeEvidenceError(f"{field} must be an ISO-8601 timestamp with a timezone")
    candidate = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError as exc:
        raise ArkimeEvidenceError(
            f"{field} must be an ISO-8601 timestamp with a timezone"
        ) from exc
    if parsed.tzinfo is None:
        raise ArkimeEvidenceError(f"{field} must include a timezone")
    parsed = parsed.astimezone(timezone.utc)
    return parsed.isoformat(timespec="milliseconds"), parsed


def _reject_constant(value: str):
    raise ArkimeEvidenceError(f"Non-finite JSON number {value} is not supported")


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ArkimeEvidenceError(f"Duplicate JSON key {key!r} is not supported")
        result[key] = value
    return result


def _load_json(content: bytes) -> dict:
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ArkimeEvidenceError("Arkime Sessions JSON must be UTF-8 text") from exc
    depth = 0
    in_string = False
    escaped = False
    for character in text:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            if depth > 100:
                raise ArkimeEvidenceError(
                    "Arkime Sessions JSON is nested too deeply to process safely"
                )
        elif character in "]}":
            depth -= 1
    try:
        value = json.loads(
            text, object_pairs_hook=_unique_object, parse_constant=_reject_constant,
        )
    except json.JSONDecodeError as exc:
        raise ArkimeEvidenceError(
            f"Arkime Sessions JSON is invalid near line {exc.lineno}, column {exc.colno}"
        ) from exc
    except RecursionError as exc:
        raise ArkimeEvidenceError(
            "Arkime Sessions JSON is nested too deeply to process safely"
        ) from exc
    if not isinstance(value, dict) or not isinstance(value.get("data"), list):
        raise ArkimeEvidenceError(
            "Unsupported Arkime export shape. Use the Sessions JSON API export with a data array."
        )
    return value


_MISSING = object()


def _path_value(row: dict, dotted: str):
    direct = row.get(dotted, _MISSING)
    parts = dotted.split(".")
    nested = row
    for part in parts:
        if not isinstance(nested, dict) or part not in nested:
            nested = _MISSING
            break
        nested = nested[part]
    if direct is not _MISSING and nested is not _MISSING and direct != nested:
        raise ArkimeEvidenceError(f"Conflicting flat and nested values for {dotted}")
    return direct if direct is not _MISSING else nested


def _alias(row: dict, names: tuple[str, ...], label: str, *, required: bool = False):
    values = []
    for name in names:
        value = _path_value(row, name)
        if value is not _MISSING and value is not None:
            values.append((name, value))
    if not values:
        if required:
            raise ArkimeEvidenceError(f"Session is missing {label}")
        return None
    first = values[0][1]
    if any(value != first for _, value in values[1:]):
        joined = ", ".join(name for name, _ in values)
        raise ArkimeEvidenceError(f"Conflicting aliases for {label}: {joined}")
    return first


def _integer(value, label: str, *, minimum: int = 0, maximum: int | None = None):
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise ArkimeEvidenceError(f"{label} must be an integer")
    if value < minimum or (maximum is not None and value > maximum):
        end = f" through {maximum}" if maximum is not None else " or greater"
        raise ArkimeEvidenceError(f"{label} must be {minimum}{end}")
    return value


def _ip(value, label: str) -> str:
    if not isinstance(value, str):
        raise ArkimeEvidenceError(f"{label} must be an IP address")
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError as exc:
        raise ArkimeEvidenceError(f"{label} is not a valid IP address") from exc


def _packet_time(value, label: str) -> tuple[str, datetime, str]:
    if isinstance(value, bool):
        raise ArkimeEvidenceError(f"{label} must be a numeric epoch or ISO-8601 timestamp")
    if isinstance(value, int):
        unit = "milliseconds" if abs(value) >= 100_000_000_000 else "seconds"
        seconds = value / 1000 if unit == "milliseconds" else value
        try:
            parsed = datetime.fromtimestamp(seconds, timezone.utc)
        except (OverflowError, OSError, ValueError) as exc:
            raise ArkimeEvidenceError(f"{label} is outside the supported timestamp range") from exc
        return parsed.isoformat(timespec="milliseconds"), parsed, unit
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ArkimeEvidenceError(f"{label} must be finite")
        raise ArkimeEvidenceError(f"{label} must use an integer epoch value")
    if isinstance(value, str):
        canonical, parsed = _canonical_time(value, label)
        return canonical, parsed, "iso8601"
    raise ArkimeEvidenceError(f"{label} must be a numeric epoch or ISO-8601 timestamp")


def _transport(value) -> str | None:
    if value is None:
        return None
    if isinstance(value, bool):
        raise ArkimeEvidenceError("ipProtocol cannot be boolean")
    if isinstance(value, int):
        if not 0 <= value <= 255:
            raise ArkimeEvidenceError("ipProtocol must be between 0 and 255")
        return {1: "icmp", 6: "tcp", 17: "udp", 58: "icmpv6", 132: "sctp"}.get(
            value, f"ip-{value}"
        )
    if isinstance(value, str):
        cleaned = value.strip().lower()
        if not cleaned:
            return None
        aliases = {"6": "tcp", "17": "udp", "132": "sctp", "1": "icmp", "58": "icmpv6"}
        if cleaned.isdecimal():
            number = int(cleaned)
            if not 0 <= number <= 255:
                raise ArkimeEvidenceError("ipProtocol must be between 0 and 255")
            return aliases.get(cleaned, f"ip-{number}")
        if len(cleaned) > 32 or re.fullmatch(r"[a-z][a-z0-9._-]*", cleaned) is None:
            raise ArkimeEvidenceError("ipProtocol text is not a supported protocol identifier")
        return cleaned
    raise ArkimeEvidenceError("ipProtocol must be an integer or text")


def _transport_alias(row: dict) -> str | None:
    values = []
    for name in ("ipProtocol", "network.transport"):
        value = _path_value(row, name)
        if value is not _MISSING and value is not None:
            values.append((name, _transport(value)))
    if not values:
        return None
    first = values[0][1]
    if any(value != first for _, value in values[1:]):
        joined = ", ".join(name for name, _ in values)
        raise ArkimeEvidenceError(f"Conflicting aliases for transport: {joined}")
    return first


def _identifier(value, label: str, maximum: int) -> str | None:
    if value is None:
        return None
    result = _text(value, label, maximum)
    if any(ord(character) < 32 or ord(character) == 127 for character in result):
        raise ArkimeEvidenceError(f"{label} contains unsupported control characters")
    return result


def _scalars(value, label: str) -> list:
    if value is None:
        return []
    values = value if isinstance(value, list) else [value]
    if any(isinstance(item, (dict, list)) or isinstance(item, bool) for item in values):
        raise ArkimeEvidenceError(f"{label} must contain only text or integer values")
    if any(not isinstance(item, (str, int)) for item in values):
        raise ArkimeEvidenceError(f"{label} must contain only text or integer values")
    return values


def _count(root: dict, key: str) -> int | None:
    if key not in root or root[key] is None:
        return None
    return _integer(root[key], key)


def _bounding_match(mode: str, first: datetime, last: datetime,
                    start: datetime, end: datetime) -> bool:
    if mode == "first":
        return start <= first <= end
    if mode == "last":
        return start <= last <= end
    if mode == "both":
        return start <= first <= last <= end
    return first <= end and last >= start


def parse_arkime_sessions_json(
    content: bytes, *, query_start: str, query_end: str, bounding_mode: str,
) -> dict:
    if not content:
        raise ArkimeEvidenceError("The uploaded Arkime export is empty")
    if len(content) > MAX_ARKIME_JSON_BYTES:
        raise ArkimeEvidenceError("The Arkime JSON file exceeds the 10 MiB intake limit")
    mode = _text(bounding_mode, "bounding_mode", 20).lower()
    if mode == "database":
        raise ArkimeEvidenceError(
            "Database-time Arkime exports are not supported; use first, last, both, or overlap bounding"
        )
    if mode == "overlap":
        mode = "either"
    if mode not in SUPPORTED_BOUNDING:
        raise ArkimeEvidenceError("bounding_mode must be first, last, both, or either")
    start_text, start = _canonical_time(query_start, "query_start")
    end_text, end = _canonical_time(query_end, "query_end")
    if start >= end:
        raise ArkimeEvidenceError("query_end must be later than query_start")
    root = _load_json(content)
    rows = root["data"]
    if len(rows) > MAX_ARKIME_SESSIONS:
        raise ArkimeEvidenceError("The Arkime export exceeds the 10,000-session intake limit")
    records_filtered = _count(root, "recordsFiltered")
    records_total = _count(root, "recordsTotal")
    if records_filtered is not None and records_filtered < len(rows):
        raise ArkimeEvidenceError("recordsFiltered is smaller than the returned data array")
    if records_total is not None and records_total < len(rows):
        raise ArkimeEvidenceError("recordsTotal is smaller than the returned data array")
    if (
        records_total is not None and records_filtered is not None
        and records_total < records_filtered
    ):
        raise ArkimeEvidenceError("recordsTotal is smaller than recordsFiltered")
    calculated = (
        "unknown" if records_filtered is None
        else "complete" if records_filtered == len(rows)
        else "partial"
    )
    sessions = []
    units = set()
    for ordinal, row in enumerate(rows):
        if not isinstance(row, dict):
            raise ArkimeEvidenceError(f"Session row {ordinal + 1} must be a JSON object")
        source_ip = _ip(_alias(row, ("source.ip", "srcIp"), "source IP", required=True), "source IP")
        destination_ip = _ip(
            _alias(row, ("destination.ip", "dstIp"), "destination IP", required=True),
            "destination IP",
        )
        source_port = _integer(
            _alias(row, ("source.port", "srcPort"), "source port"),
            "source port", maximum=65535,
        )
        destination_port = _integer(
            _alias(row, ("destination.port", "dstPort"), "destination port"),
            "destination port", maximum=65535,
        )
        first_text, first, first_unit = _packet_time(
            _alias(row, ("firstPacket",), "firstPacket", required=True), "firstPacket"
        )
        last_text, last, last_unit = _packet_time(
            _alias(row, ("lastPacket",), "lastPacket", required=True), "lastPacket"
        )
        units.update((first_unit, last_unit))
        if first > last:
            raise ArkimeEvidenceError(f"Session row {ordinal + 1} ends before it starts")
        if not _bounding_match(mode, first, last, start, end):
            raise ArkimeEvidenceError(
                f"Session row {ordinal + 1} does not match the declared {mode} query window"
            )
        session_id = _identifier(
            _alias(row, ("id", "_id"), "session ID"), "session ID", 500
        )
        source_node = _identifier(
            _alias(row, ("node",), "source node"), "source node", 200
        )
        applications = _scalars(_alias(row, ("protocol",), "applications"), "protocol")
        vlans = _scalars(_alias(row, ("vlan", "vlanId"), "VLAN context"), "VLAN context")
        packet_count = _integer(
            _alias(row, ("network.packets", "totPackets"), "packet count"), "packet count"
        )
        byte_count = _integer(
            _alias(row, ("network.bytes", "totBytes"), "byte count"), "byte count"
        )
        transport = _transport_alias(row)
        context = {}
        root_id = _alias(row, ("rootId",), "root session ID")
        if root_id is not None:
            context["rootId"] = _identifier(root_id, "root session ID", 500)
        for key in ("srcPackets", "dstPackets", "srcBytes", "dstBytes", "totDataBytes"):
            value = _alias(row, (key,), key)
            if value is not None:
                context[key] = _integer(value, key)
        sessions.append({
            "source_ordinal": ordinal,
            "session_id": session_id,
            "source_node": source_node,
            "source_ip": source_ip,
            "source_port": source_port,
            "destination_ip": destination_ip,
            "destination_port": destination_port,
            "transport": transport,
            "applications": applications,
            "first_packet": first_text,
            "last_packet": last_text,
            "packet_count": packet_count,
            "byte_count": byte_count,
            "vlans": vlans,
            "context": context,
        })
    if len(units) > 1:
        raise ArkimeEvidenceError("All Arkime packet timestamps must use one consistent unit")
    return {
        "query_start": start_text,
        "query_end": end_text,
        "bounding_mode": mode,
        "records_filtered": records_filtered,
        "records_total": records_total,
        "calculated_export_completeness": calculated,
        "timestamp_unit": next(iter(units), "none"),
        "sessions": sessions,
    }


def _revision(total: int, newest: sqlite3.Row | None) -> str:
    if newest is None:
        value = "0"
    else:
        value = (
            f"{total}:{newest['import_id']}:{newest['observation_id']}:"
            f"{newest['imported_at']}"
        )
    return hashlib.sha256(value.encode()).hexdigest()


def _scope_snapshot(db: sqlite3.Connection, scope_id: str) -> dict:
    db.row_factory = sqlite3.Row
    row = db.execute(
        "SELECT scope_id, label, version, active FROM network_scopes WHERE scope_id = ?",
        (scope_id,),
    ).fetchone()
    if row is None:
        raise KeyError("Network Scope not found")
    if not row["active"]:
        raise ArkimeEvidenceConflict("The selected Network Scope was archived")
    return dict(row)


@guarded_evidence_mutation(lambda db_path, *args, **kwargs: db_path)
def import_arkime_sessions_json(
    db_path: Path, *, content: bytes, original_filename: str, media_type: str,
    scope_id: str, operator_sensor: str, query_start: str, query_end: str,
    bounding_mode: str, operator_export_assessment: str,
    capture_coverage: str, query_expression: str, actor: str,
) -> dict:
    init_arkime_evidence_storage(db_path)
    scope_id = _text(scope_id, "scope_id", 200)
    sensor = _text(operator_sensor, "operator_sensor", 200)
    operator_assessment = _declaration(
        operator_export_assessment, "operator_export_assessment"
    )
    capture = _declaration(capture_coverage, "capture_coverage")
    expression = _text(query_expression, "query_expression", 2000, allow_blank=True)
    filename = _text(original_filename, "original_filename", 500)
    actor = _text(actor, "actor", 100)
    parsed = parse_arkime_sessions_json(
        content, query_start=query_start, query_end=query_end, bounding_mode=bounding_mode,
    )
    if (
        parsed["calculated_export_completeness"] == "partial"
        and operator_assessment == "complete"
    ):
        raise ArkimeEvidenceError(
            "Arkime reports more matching sessions than this file contains; the export cannot be declared complete"
        )
    import_id = f"arkime_{uuid.uuid4().hex}"
    imported_at = utc_now()
    root = artifact_root_for(db_path)
    with connect_database(db_path) as db:
        db.execute("BEGIN IMMEDIATE")
        scope = _scope_snapshot(db, scope_id)
        artifact = register_artifact_bytes(
            db_path=db_path,
            content=content,
            source_kind=ARKIME_SOURCE_KIND,
            source_ref=import_id,
            original_filename=filename,
            media_type=media_type or "application/json",
            actor=actor,
            observed_at=imported_at,
            observation_key=f"{ARKIME_SOURCE_KIND}:{import_id}",
            metadata={
                "import_tier": "tier_d_sessions_json",
                "scope_id": scope_id,
                "operator_sensor": sensor,
                "query_start": parsed["query_start"],
                "query_end": parsed["query_end"],
                "bounding_mode": parsed["bounding_mode"],
                "returned_count": len(parsed["sessions"]),
            },
            connection=db,
        )
        db.execute(
            """INSERT INTO arkime_imports (
                   import_id, observation_id, scope_id, scope_label, scope_version,
                   operator_sensor, query_start, query_end, bounding_mode,
                   query_expression, operator_export_assessment, capture_coverage,
                   calculated_export_completeness, returned_count, records_filtered,
                   records_total, timestamp_unit, parser_version, imported_at, actor
               ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                import_id, artifact["observation_id"], scope_id, scope["label"],
                int(scope["version"]), sensor, parsed["query_start"], parsed["query_end"],
                parsed["bounding_mode"], expression, operator_assessment, capture,
                parsed["calculated_export_completeness"], len(parsed["sessions"]),
                parsed["records_filtered"], parsed["records_total"],
                parsed["timestamp_unit"], ARKIME_PARSER_VERSION, imported_at, actor,
            ),
        )
        for session in parsed["sessions"]:
            receipt_id = hashlib.sha256(
                f"{import_id}:{session['source_ordinal']}".encode()
            ).hexdigest()
            db.execute(
                """INSERT INTO arkime_session_receipts (
                       receipt_id, import_id, source_ordinal, session_id, source_node,
                       source_ip, source_port, destination_ip, destination_port,
                       transport, applications_json, first_packet, last_packet,
                       packet_count, byte_count, vlan_json, context_json
                   ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    receipt_id, import_id, session["source_ordinal"], session["session_id"],
                    session["source_node"], session["source_ip"], session["source_port"],
                    session["destination_ip"], session["destination_port"],
                    session["transport"], json.dumps(session["applications"], sort_keys=True),
                    session["first_packet"], session["last_packet"],
                    session["packet_count"], session["byte_count"],
                    json.dumps(session["vlans"], sort_keys=True),
                    json.dumps(session["context"], sort_keys=True),
                ),
            )
    return {
        "import_id": import_id,
        "observation_id": artifact["observation_id"],
        "sha256": artifact["sha256"],
        "artifact_duplicate": artifact["duplicate"],
        "original_preserved": canonical_artifact_path(root, artifact["sha256"]).is_file(),
        "scope": {"scope_id": scope_id, "label": scope["label"], "version": scope["version"]},
        "operator_sensor": sensor,
        "query_start": parsed["query_start"],
        "query_end": parsed["query_end"],
        "bounding_mode": parsed["bounding_mode"],
        "operator_export_assessment": operator_assessment,
        "capture_coverage": capture,
        "calculated_export_completeness": parsed["calculated_export_completeness"],
        "returned_count": len(parsed["sessions"]),
        "records_filtered": parsed["records_filtered"],
        "records_total": parsed["records_total"],
        "timestamp_unit": parsed["timestamp_unit"],
        "parser_version": ARKIME_PARSER_VERSION,
        "imported_at": imported_at,
        "actor": actor,
        "raw_url": f"/api/arkime/imports/{import_id}/raw",
    }


def _import_dict(row: sqlite3.Row) -> dict:
    return {
        "import_id": row["import_id"],
        "observation_id": row["observation_id"],
        "scope": {
            "scope_id": row["scope_id"], "label": row["scope_label"],
            "version": int(row["scope_version"]),
        },
        "operator_sensor": row["operator_sensor"],
        "query_start": row["query_start"], "query_end": row["query_end"],
        "bounding_mode": row["bounding_mode"],
        "query_expression": row["query_expression"],
        "operator_export_assessment": row["operator_export_assessment"],
        "capture_coverage": row["capture_coverage"],
        "calculated_export_completeness": row["calculated_export_completeness"],
        "returned_count": int(row["returned_count"]),
        "records_filtered": row["records_filtered"],
        "records_total": row["records_total"],
        "timestamp_unit": row["timestamp_unit"],
        "parser_version": row["parser_version"],
        "imported_at": row["imported_at"], "actor": row["actor"],
        "raw_url": f"/api/arkime/imports/{row['import_id']}/raw",
    }


def list_arkime_imports(
    db_path: Path, *, scope_id: str | None = None, limit: int = 25,
    offset: int = 0, revision: str | None = None,
) -> dict:
    if type(limit) is not int or not 1 <= limit <= MAX_PAGE:
        raise ArkimeEvidenceError(f"limit must be between 1 and {MAX_PAGE}")
    if type(offset) is not int or offset < 0:
        raise ArkimeEvidenceError("offset must be zero or greater")
    where = " WHERE scope_id = ?" if scope_id else ""
    parameters = (scope_id,) if scope_id else ()
    with connect_database(db_path, read_only=True) as db:
        db.row_factory = sqlite3.Row
        db.execute("BEGIN")
        total = int(db.execute(
            "SELECT COUNT(*) FROM arkime_imports" + where, parameters,
        ).fetchone()[0])
        newest = db.execute(
            "SELECT import_id, observation_id, imported_at FROM arkime_imports" + where
            + " ORDER BY imported_at DESC, import_id DESC LIMIT 1", parameters,
        ).fetchone()
        source_revision = _revision(total, newest)
        if revision is not None and revision != source_revision:
            raise ArkimeEvidenceConflict("Arkime import history changed while paging")
        rows = db.execute(
            "SELECT * FROM arkime_imports" + where
            + " ORDER BY imported_at DESC, import_id DESC LIMIT ? OFFSET ?",
            (*parameters, limit, offset),
        ).fetchall()
    return {
        "items": [_import_dict(row) for row in rows],
        "source_revision": source_revision,
        "pagination": {
            "limit": limit, "offset": offset, "total": total,
            "has_more": offset + len(rows) < total,
        },
        "read_only": True,
    }


def get_arkime_import(
    db_path: Path, import_id: str, *, limit: int = 50, offset: int = 0,
) -> dict:
    if type(limit) is not int or not 1 <= limit <= MAX_PAGE:
        raise ArkimeEvidenceError(f"limit must be between 1 and {MAX_PAGE}")
    if type(offset) is not int or offset < 0:
        raise ArkimeEvidenceError("offset must be zero or greater")
    with connect_database(db_path, read_only=True) as db:
        db.row_factory = sqlite3.Row
        db.execute("BEGIN")
        record = db.execute(
            "SELECT * FROM arkime_imports WHERE import_id = ?", (import_id,)
        ).fetchone()
        if record is None:
            raise KeyError("Arkime import not found")
        total = int(db.execute(
            "SELECT COUNT(*) FROM arkime_session_receipts WHERE import_id = ?",
            (import_id,),
        ).fetchone()[0])
        rows = db.execute(
            """SELECT * FROM arkime_session_receipts WHERE import_id = ?
               ORDER BY source_ordinal LIMIT ? OFFSET ?""",
            (import_id, limit, offset),
        ).fetchall()
    sessions = []
    for row in rows:
        sessions.append({
            "receipt_id": row["receipt_id"],
            "source_ordinal": int(row["source_ordinal"]),
            "session_id": row["session_id"], "source_node": row["source_node"],
            "source_ip": row["source_ip"], "source_port": row["source_port"],
            "destination_ip": row["destination_ip"],
            "destination_port": row["destination_port"],
            "transport": row["transport"],
            "applications": json.loads(row["applications_json"]),
            "first_packet": row["first_packet"], "last_packet": row["last_packet"],
            "packet_count": row["packet_count"], "byte_count": row["byte_count"],
            "vlans": json.loads(row["vlan_json"]),
            "context": json.loads(row["context_json"]),
        })
    return {
        **_import_dict(record),
        "sessions": sessions,
        "pagination": {
            "limit": limit, "offset": offset, "total": total,
            "has_more": offset + len(rows) < total,
        },
        "read_only": True,
    }


def arkime_raw_source(db_path: Path, import_id: str) -> dict:
    with connect_database(db_path, read_only=True) as db:
        db.row_factory = sqlite3.Row
        row = db.execute(
            """SELECT ai.observation_id, ao.source_kind, ao.source_ref,
                      ao.observed_at, ao.original_filename, ao.actor,
                      ao.metadata_json, ar.sha256, ar.size_bytes,
                      ar.media_type, ar.canonical_path
                 FROM arkime_imports ai
                 JOIN artifact_observations ao
                   ON ao.observation_id = ai.observation_id
                 JOIN artifact_registry ar ON ar.sha256 = ao.sha256
                WHERE ai.import_id = ?""",
            (import_id,),
        ).fetchone()
    if row is None:
        raise KeyError("Arkime import not found")
    if row["source_kind"] != ARKIME_SOURCE_KIND:
        raise ArkimeEvidenceConflict("The retained Arkime source record is unavailable")
    return {
        "observation_id": row["observation_id"],
        "source_kind": row["source_kind"],
        "source_ref": row["source_ref"],
        "observed_at": row["observed_at"],
        "original_filename": row["original_filename"],
        "actor": row["actor"],
        "metadata": json.loads(row["metadata_json"]),
        "sha256": row["sha256"],
        "size_bytes": int(row["size_bytes"]),
        "media_type": row["media_type"],
        "canonical_path": row["canonical_path"],
    }


def read_verified_arkime_source(db_path: Path, import_id: str) -> tuple[dict, bytes]:
    """Read one canonical Arkime source without following storage symlinks."""
    source = arkime_raw_source(db_path, import_id)
    digest = source["sha256"]
    expected = canonical_artifact_path(artifact_root_for(db_path), digest).absolute()
    stored = Path(source["canonical_path"]).absolute()
    if stored != expected:
        raise ArkimeEvidenceConflict("The retained Arkime source path is not canonical")

    base = db_path.parent.absolute()
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    directory_flags = flags | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    file_flags = flags | getattr(os, "O_NOFOLLOW", 0)
    descriptors: list[int] = []
    try:
        current = os.open(base, directory_flags)
        descriptors.append(current)
        for component in ("artifacts", "sha256", digest[:2]):
            current = os.open(component, directory_flags, dir_fd=current)
            descriptors.append(current)
        file_descriptor = os.open(digest, file_flags, dir_fd=current)
        descriptors.append(file_descriptor)
        info = os.fstat(file_descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise ArkimeEvidenceConflict("The retained Arkime source is not a regular file")
        expected_size = int(source["size_bytes"])
        if info.st_size != expected_size or expected_size > MAX_ARKIME_JSON_BYTES:
            raise ArkimeEvidenceConflict("The retained Arkime source size no longer matches its receipt")
        chunks: list[bytes] = []
        remaining = expected_size + 1
        while remaining:
            chunk = os.read(file_descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        content = b"".join(chunks)
        after = os.fstat(file_descriptor)
        if (
            len(content) != expected_size
            or after.st_size != info.st_size
            or after.st_ino != info.st_ino
            or hashlib.sha256(content).hexdigest() != digest
        ):
            raise ArkimeEvidenceConflict("The retained Arkime source no longer matches its SHA-256 receipt")
        return source, content
    except ArkimeEvidenceError:
        raise
    except OSError as exc:
        raise ArkimeEvidenceConflict("The retained Arkime source is unavailable or unsafe") from exc
    finally:
        for descriptor in reversed(descriptors):
            try:
                os.close(descriptor)
            except OSError:
                pass
