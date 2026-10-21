"""Bounded Tier A communication-summary intake for passive Arkime evidence.

The supported source is an NCT-defined CSV contract. It retains exact bytes and
immutable grouped-count receipts. It does not contact Arkime, infer packet capture
coverage, merge overlapping summaries, create current hosts or services, or claim
that a reported destination port is an open listener.
"""
from __future__ import annotations

from contextlib import nullcontext
import csv
from datetime import datetime, timezone
import hashlib
import io
import ipaddress
import json
import os
from pathlib import Path
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


ARKIME_SUMMARY_PARSER_VERSION = "nct-arkime-summary-csv:1"
ARKIME_SUMMARY_SOURCE_KIND = "arkime_summary_csv"
MAX_ARKIME_SUMMARY_BYTES = 10 * 1024 * 1024
MAX_ARKIME_SUMMARY_ROWS = 10_000
MAX_PAGE = 100
SUMMARY_HEADERS = (
    "source_ip",
    "destination_ip",
    "destination_port",
    "transport",
    "detected_protocol",
    "vlan",
    "session_count",
    "packet_count",
    "byte_count",
)
SUMMARY_BASES = {"all_matching_groups", "top_n", "unknown"}
BOUNDING_MODES = {"first", "last", "both", "either"}
DECLARATIONS = {"complete", "partial", "unknown"}
TRANSPORTS = {"tcp", "udp", "sctp", "icmp", "icmpv6"}
SQLITE_INTEGER_MAX = 9_223_372_036_854_775_807


class ArkimeSummaryError(ValueError):
    pass


class ArkimeSummaryConflict(ArkimeSummaryError):
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
def init_arkime_summary_storage(db_path: Path) -> None:
    init_network_scope_storage(db_path)
    init_artifact_storage(db_path)
    with connect_database(db_path) as db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS arkime_summary_imports (
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
                summary_basis TEXT NOT NULL CHECK(
                    summary_basis IN ('all_matching_groups', 'top_n', 'unknown')
                ),
                top_n_limit INTEGER CHECK(top_n_limit BETWEEN 1 AND 100000),
                operator_export_assessment TEXT NOT NULL CHECK(
                    operator_export_assessment IN ('complete', 'partial', 'unknown')
                ),
                capture_coverage TEXT NOT NULL CHECK(
                    capture_coverage IN ('complete', 'partial', 'unknown')
                ),
                recorded_export_completeness TEXT NOT NULL CHECK(
                    recorded_export_completeness IN ('complete', 'partial', 'unknown')
                ),
                returned_count INTEGER NOT NULL CHECK(returned_count >= 0),
                parser_version TEXT NOT NULL,
                imported_at TEXT NOT NULL,
                actor TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS arkime_summary_imports_scope_time
                ON arkime_summary_imports(scope_id, imported_at DESC, import_id DESC);
            CREATE TABLE IF NOT EXISTS arkime_summary_receipts (
                receipt_id TEXT PRIMARY KEY,
                import_id TEXT NOT NULL REFERENCES arkime_summary_imports(import_id),
                source_ordinal INTEGER NOT NULL CHECK(source_ordinal >= 0),
                source_line INTEGER NOT NULL CHECK(source_line >= 2),
                source_ip TEXT,
                destination_ip TEXT NOT NULL,
                destination_port INTEGER CHECK(
                    destination_port BETWEEN 1 AND 65535
                ),
                transport TEXT,
                detected_protocol TEXT,
                vlan INTEGER CHECK(vlan BETWEEN 0 AND 4095),
                session_count INTEGER CHECK(session_count >= 0),
                packet_count INTEGER CHECK(packet_count >= 0),
                byte_count INTEGER CHECK(byte_count >= 0),
                UNIQUE(import_id, source_ordinal)
            );
            CREATE INDEX IF NOT EXISTS arkime_summary_receipts_import
                ON arkime_summary_receipts(import_id, source_ordinal);
            CREATE INDEX IF NOT EXISTS arkime_summary_receipts_destination
                ON arkime_summary_receipts(destination_ip, destination_port, transport);
        """ + _immutable_triggers("arkime_summary_imports")
            + _immutable_triggers("arkime_summary_receipts"))


def _text(value, field: str, maximum: int, *, allow_blank: bool = False) -> str:
    if not isinstance(value, str):
        raise ArkimeSummaryError(f"{field} must be text")
    result = value.strip()
    if not result and not allow_blank:
        raise ArkimeSummaryError(f"{field} cannot be blank")
    if len(result) > maximum:
        raise ArkimeSummaryError(f"{field} exceeds {maximum} characters")
    return result


def _declaration(value: str, field: str) -> str:
    result = _text(value, field, 20).lower()
    if result not in DECLARATIONS:
        raise ArkimeSummaryError(f"{field} must be complete, partial, or unknown")
    return result


def _canonical_time(value: str, field: str) -> tuple[str, datetime]:
    if not isinstance(value, str):
        raise ArkimeSummaryError(f"{field} must be an ISO-8601 timestamp with a timezone")
    candidate = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError as exc:
        raise ArkimeSummaryError(
            f"{field} must be an ISO-8601 timestamp with a timezone"
        ) from exc
    if parsed.tzinfo is None:
        raise ArkimeSummaryError(f"{field} must include a timezone")
    parsed = parsed.astimezone(timezone.utc)
    return parsed.isoformat(timespec="milliseconds"), parsed


def _ip(value: str, field: str, *, optional: bool = False) -> str | None:
    value = value.strip()
    if optional and not value:
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise ArkimeSummaryError(f"{field} is not a valid IP address") from exc


def _integer(
    value: str, field: str, *, minimum: int = 0,
    maximum: int = SQLITE_INTEGER_MAX, optional: bool = True,
) -> int | None:
    value = value.strip()
    if optional and not value:
        return None
    if not value or not value.isdecimal():
        raise ArkimeSummaryError(f"{field} must be a whole number")
    result = int(value)
    if not minimum <= result <= maximum:
        raise ArkimeSummaryError(
            f"{field} must be between {minimum} and {maximum}"
        )
    return result


def _summary_basis(value: str, top_n_limit: int | None) -> tuple[str, int | None]:
    basis = _text(value, "summary_basis", 40).lower()
    if basis not in SUMMARY_BASES:
        raise ArkimeSummaryError(
            "summary_basis must be all_matching_groups, top_n, or unknown"
        )
    if basis == "top_n":
        if type(top_n_limit) is not int or not 1 <= top_n_limit <= 100_000:
            raise ArkimeSummaryError("top_n_limit must be between 1 and 100000")
        return basis, top_n_limit
    if top_n_limit is not None:
        raise ArkimeSummaryError("top_n_limit is allowed only for a top_n summary")
    return basis, None


def parse_arkime_summary_csv(content: bytes) -> dict:
    if len(content) > MAX_ARKIME_SUMMARY_BYTES:
        raise ArkimeSummaryError("The summary CSV exceeds the 10 MiB intake limit")
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ArkimeSummaryError("The summary CSV must be UTF-8 text") from exc
    if "\x00" in text:
        raise ArkimeSummaryError("The summary CSV contains a null byte")
    try:
        reader = csv.reader(io.StringIO(text, newline=""), strict=True)
        header = next(reader, None)
        if header is None:
            raise ArkimeSummaryError("The summary CSV is empty")
        normalized_header = tuple(item.strip().lower() for item in header)
        if len(set(normalized_header)) != len(normalized_header):
            raise ArkimeSummaryError("The summary CSV has a duplicate header")
        if normalized_header != SUMMARY_HEADERS:
            raise ArkimeSummaryError(
                "The summary CSV header must be exactly: " + ",".join(SUMMARY_HEADERS)
            )
        rows = []
        grouping_keys: set[tuple] = set()
        for ordinal, values in enumerate(reader):
            source_line = reader.line_num
            if not values or all(not value.strip() for value in values):
                raise ArkimeSummaryError(f"Summary row {source_line} is blank")
            if len(values) != len(SUMMARY_HEADERS):
                raise ArkimeSummaryError(
                    f"Summary row {source_line} has {len(values)} fields; "
                    f"expected {len(SUMMARY_HEADERS)}"
                )
            if any(len(value) > 500 for value in values):
                raise ArkimeSummaryError(
                    f"Summary row {source_line} contains a field over 500 characters"
                )
            record = dict(zip(SUMMARY_HEADERS, values, strict=True))
            source_ip = _ip(
                record["source_ip"], f"Summary row {source_line} source_ip",
                optional=True,
            )
            destination_ip = _ip(
                record["destination_ip"],
                f"Summary row {source_line} destination_ip",
            )
            destination_port = _integer(
                record["destination_port"],
                f"Summary row {source_line} destination_port",
                minimum=1, maximum=65535,
            )
            transport = record["transport"].strip().lower() or None
            if transport is not None and transport not in TRANSPORTS:
                raise ArkimeSummaryError(
                    f"Summary row {source_line} transport must be TCP, UDP, SCTP, "
                    "ICMP, ICMPv6, or blank"
                )
            detected_protocol = record["detected_protocol"].strip() or None
            vlan = _integer(
                record["vlan"], f"Summary row {source_line} vlan",
                minimum=0, maximum=4095,
            )
            session_count = _integer(
                record["session_count"],
                f"Summary row {source_line} session_count",
            )
            packet_count = _integer(
                record["packet_count"],
                f"Summary row {source_line} packet_count",
            )
            byte_count = _integer(
                record["byte_count"], f"Summary row {source_line} byte_count",
            )
            if session_count is packet_count is byte_count is None:
                raise ArkimeSummaryError(
                    f"Summary row {source_line} must contain at least one count"
                )
            grouping_key = (
                source_ip, destination_ip, destination_port, transport,
                detected_protocol, vlan,
            )
            if grouping_key in grouping_keys:
                raise ArkimeSummaryError(
                    f"Summary row {source_line} repeats an earlier grouping key"
                )
            grouping_keys.add(grouping_key)
            rows.append({
                "source_ordinal": ordinal,
                "source_line": source_line,
                "source_ip": source_ip,
                "destination_ip": destination_ip,
                "destination_port": destination_port,
                "transport": transport,
                "detected_protocol": detected_protocol,
                "vlan": vlan,
                "session_count": session_count,
                "packet_count": packet_count,
                "byte_count": byte_count,
            })
            if len(rows) > MAX_ARKIME_SUMMARY_ROWS:
                raise ArkimeSummaryError(
                    "The summary CSV exceeds the 10,000-row intake limit"
                )
    except csv.Error as exc:
        raise ArkimeSummaryError(f"The summary CSV is invalid: {exc}") from exc
    return {"rows": rows, "format": ARKIME_SUMMARY_PARSER_VERSION}


def _scope_snapshot(db: sqlite3.Connection, scope_id: str) -> dict:
    db.row_factory = sqlite3.Row
    row = db.execute(
        "SELECT scope_id, label, version, active FROM network_scopes WHERE scope_id = ?",
        (scope_id,),
    ).fetchone()
    if row is None:
        raise KeyError("Network Scope not found")
    if not row["active"]:
        raise ArkimeSummaryConflict("The selected Network Scope was archived")
    return dict(row)


def _recorded_completeness(basis: str, assessment: str) -> str:
    if basis == "top_n" or assessment == "partial":
        return "partial"
    if basis == "all_matching_groups" and assessment == "complete":
        return "complete"
    return "unknown"


@guarded_evidence_mutation(lambda db_path, *args, **kwargs: db_path)
def import_arkime_summary_csv(
    db_path: Path, *, content: bytes, original_filename: str, media_type: str,
    scope_id: str, operator_sensor: str, query_start: str, query_end: str,
    bounding_mode: str, query_expression: str, summary_basis: str,
    top_n_limit: int | None, operator_export_assessment: str,
    capture_coverage: str, actor: str,
    connection: sqlite3.Connection | None = None,
) -> dict:
    if connection is None:
        init_arkime_summary_storage(db_path)
    scope_id = _text(scope_id, "scope_id", 200)
    sensor = _text(operator_sensor, "operator_sensor", 200)
    filename = _text(original_filename, "original_filename", 500)
    actor = _text(actor, "actor", 100)
    expression = _text(query_expression, "query_expression", 2000, allow_blank=True)
    bounding = _text(bounding_mode, "bounding_mode", 20).lower()
    if bounding not in BOUNDING_MODES:
        raise ArkimeSummaryError("bounding_mode must be first, last, both, or either")
    start, start_value = _canonical_time(query_start, "query_start")
    end, end_value = _canonical_time(query_end, "query_end")
    if end_value <= start_value:
        raise ArkimeSummaryError("query_end must be after query_start")
    basis, top_n = _summary_basis(summary_basis, top_n_limit)
    assessment = _declaration(
        operator_export_assessment, "operator_export_assessment"
    )
    capture = _declaration(capture_coverage, "capture_coverage")
    if basis in {"top_n", "unknown"} and assessment == "complete":
        raise ArkimeSummaryError(
            "A top-N or unknown-basis summary cannot be declared complete"
        )
    parsed = parse_arkime_summary_csv(content)
    if top_n is not None and len(parsed["rows"]) > top_n:
        raise ArkimeSummaryError("The summary contains more rows than its top-N limit")
    recorded = _recorded_completeness(basis, assessment)
    import_id = f"arkime_summary_{uuid.uuid4().hex}"
    imported_at = utc_now()
    root = artifact_root_for(db_path)
    database_context = (
        nullcontext(connection) if connection is not None else connect_database(db_path)
    )
    with database_context as db:
        if connection is None:
            db.execute("BEGIN IMMEDIATE")
        scope = _scope_snapshot(db, scope_id)
        artifact = register_artifact_bytes(
            db_path=db_path,
            content=content,
            source_kind=ARKIME_SUMMARY_SOURCE_KIND,
            source_ref=import_id,
            original_filename=filename,
            media_type=media_type or "text/csv",
            actor=actor,
            observed_at=imported_at,
            observation_key=f"{ARKIME_SUMMARY_SOURCE_KIND}:{import_id}",
            metadata={
                "import_tier": "tier_a_communication_summary",
                "format": ARKIME_SUMMARY_PARSER_VERSION,
                "scope_id": scope_id,
                "operator_sensor": sensor,
                "query_start": start,
                "query_end": end,
                "bounding_mode": bounding,
                "summary_basis": basis,
                "top_n_limit": top_n,
                "returned_count": len(parsed["rows"]),
            },
            connection=db,
        )
        db.execute(
            """INSERT INTO arkime_summary_imports (
                   import_id, observation_id, scope_id, scope_label, scope_version,
                   operator_sensor, query_start, query_end, bounding_mode,
                   query_expression, summary_basis, top_n_limit,
                   operator_export_assessment, capture_coverage,
                   recorded_export_completeness, returned_count, parser_version,
                   imported_at, actor
               ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                import_id, artifact["observation_id"], scope_id, scope["label"],
                int(scope["version"]), sensor, start, end, bounding, expression,
                basis, top_n, assessment, capture, recorded,
                len(parsed["rows"]), ARKIME_SUMMARY_PARSER_VERSION,
                imported_at, actor,
            ),
        )
        for row in parsed["rows"]:
            receipt_id = hashlib.sha256(
                f"{import_id}:{row['source_ordinal']}".encode()
            ).hexdigest()
            db.execute(
                """INSERT INTO arkime_summary_receipts (
                       receipt_id, import_id, source_ordinal, source_line, source_ip,
                       destination_ip, destination_port, transport, detected_protocol,
                       vlan, session_count, packet_count, byte_count
                   ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    receipt_id, import_id, row["source_ordinal"], row["source_line"],
                    row["source_ip"], row["destination_ip"],
                    row["destination_port"], row["transport"],
                    row["detected_protocol"], row["vlan"], row["session_count"],
                    row["packet_count"], row["byte_count"],
                ),
            )
    return {
        "import_id": import_id,
        "observation_id": artifact["observation_id"],
        "sha256": artifact["sha256"],
        "artifact_duplicate": artifact["duplicate"],
        "original_preserved": canonical_artifact_path(
            root, artifact["sha256"]
        ).is_file(),
        "scope": {
            "scope_id": scope_id, "label": scope["label"],
            "version": scope["version"],
        },
        "operator_sensor": sensor,
        "query_start": start,
        "query_end": end,
        "bounding_mode": bounding,
        "query_expression": expression,
        "summary_basis": basis,
        "top_n_limit": top_n,
        "operator_export_assessment": assessment,
        "capture_coverage": capture,
        "recorded_export_completeness": recorded,
        "returned_count": len(parsed["rows"]),
        "parser_version": ARKIME_SUMMARY_PARSER_VERSION,
        "imported_at": imported_at,
        "actor": actor,
        "raw_url": f"/api/arkime/summary-imports/{import_id}/raw",
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
        "query_start": row["query_start"],
        "query_end": row["query_end"],
        "bounding_mode": row["bounding_mode"],
        "query_expression": row["query_expression"],
        "summary_basis": row["summary_basis"],
        "top_n_limit": row["top_n_limit"],
        "operator_export_assessment": row["operator_export_assessment"],
        "capture_coverage": row["capture_coverage"],
        "recorded_export_completeness": row["recorded_export_completeness"],
        "returned_count": int(row["returned_count"]),
        "parser_version": row["parser_version"],
        "imported_at": row["imported_at"],
        "actor": row["actor"],
        "raw_url": f"/api/arkime/summary-imports/{row['import_id']}/raw",
    }


def _revision(total: int, newest: sqlite3.Row | None) -> str:
    value = "0" if newest is None else (
        f"{total}:{newest['import_id']}:{newest['observation_id']}:"
        f"{newest['imported_at']}"
    )
    return hashlib.sha256(value.encode()).hexdigest()


def list_arkime_summary_imports(
    db_path: Path, *, scope_id: str | None = None, limit: int = 25,
    offset: int = 0, revision: str | None = None,
) -> dict:
    if type(limit) is not int or not 1 <= limit <= MAX_PAGE:
        raise ArkimeSummaryError(f"limit must be between 1 and {MAX_PAGE}")
    if type(offset) is not int or offset < 0:
        raise ArkimeSummaryError("offset must be zero or greater")
    where = " WHERE scope_id = ?" if scope_id else ""
    parameters = (scope_id,) if scope_id else ()
    with connect_database(db_path, read_only=True) as db:
        db.row_factory = sqlite3.Row
        db.execute("BEGIN")
        total = int(db.execute(
            "SELECT COUNT(*) FROM arkime_summary_imports" + where, parameters,
        ).fetchone()[0])
        newest = db.execute(
            "SELECT import_id, observation_id, imported_at "
            "FROM arkime_summary_imports" + where
            + " ORDER BY imported_at DESC, import_id DESC LIMIT 1",
            parameters,
        ).fetchone()
        source_revision = _revision(total, newest)
        if revision is not None and revision != source_revision:
            raise ArkimeSummaryConflict(
                "Arkime summary history changed while paging"
            )
        rows = db.execute(
            "SELECT * FROM arkime_summary_imports" + where
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


def get_arkime_summary_import(
    db_path: Path, import_id: str, *, limit: int = 50, offset: int = 0,
) -> dict:
    if type(limit) is not int or not 1 <= limit <= MAX_PAGE:
        raise ArkimeSummaryError(f"limit must be between 1 and {MAX_PAGE}")
    if type(offset) is not int or offset < 0:
        raise ArkimeSummaryError("offset must be zero or greater")
    with connect_database(db_path, read_only=True) as db:
        db.row_factory = sqlite3.Row
        db.execute("BEGIN")
        record = db.execute(
            "SELECT * FROM arkime_summary_imports WHERE import_id = ?",
            (import_id,),
        ).fetchone()
        if record is None:
            raise KeyError("Arkime summary import not found")
        total = int(db.execute(
            "SELECT COUNT(*) FROM arkime_summary_receipts WHERE import_id = ?",
            (import_id,),
        ).fetchone()[0])
        rows = db.execute(
            """SELECT * FROM arkime_summary_receipts WHERE import_id = ?
               ORDER BY source_ordinal LIMIT ? OFFSET ?""",
            (import_id, limit, offset),
        ).fetchall()
    receipts = []
    for row in rows:
        receipts.append({
            "receipt_id": row["receipt_id"],
            "source_ordinal": int(row["source_ordinal"]),
            "source_line": int(row["source_line"]),
            "source_ip": row["source_ip"],
            "destination_ip": row["destination_ip"],
            "destination_port": row["destination_port"],
            "transport": row["transport"],
            "detected_protocol": row["detected_protocol"],
            "vlan": row["vlan"],
            # JSON numbers above 2^53 are rounded by browsers. Counts are returned
            # as decimal text so the API and UI preserve every accepted SQLite
            # integer exactly. Null remains distinct from the value zero.
            "session_count": (
                None if row["session_count"] is None else str(row["session_count"])
            ),
            "packet_count": (
                None if row["packet_count"] is None else str(row["packet_count"])
            ),
            "byte_count": (
                None if row["byte_count"] is None else str(row["byte_count"])
            ),
        })
    return {
        **_import_dict(record),
        "receipts": receipts,
        "pagination": {
            "limit": limit, "offset": offset, "total": total,
            "has_more": offset + len(rows) < total,
        },
        "read_only": True,
    }


def arkime_summary_raw_source(db_path: Path, import_id: str) -> dict:
    with connect_database(db_path, read_only=True) as db:
        db.row_factory = sqlite3.Row
        row = db.execute(
            """SELECT summary.observation_id, observed.source_kind,
                      observed.source_ref, observed.observed_at,
                      observed.original_filename, observed.actor,
                      observed.metadata_json, artifact.sha256,
                      artifact.size_bytes, artifact.media_type,
                      artifact.canonical_path
                 FROM arkime_summary_imports summary
                 JOIN artifact_observations observed
                   ON observed.observation_id = summary.observation_id
                 JOIN artifact_registry artifact
                   ON artifact.sha256 = observed.sha256
                WHERE summary.import_id = ?""",
            (import_id,),
        ).fetchone()
    if row is None:
        raise KeyError("Arkime summary import not found")
    if row["source_kind"] != ARKIME_SUMMARY_SOURCE_KIND:
        raise ArkimeSummaryConflict(
            "The retained Arkime summary source record is unavailable"
        )
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


def read_verified_arkime_summary_source(
    db_path: Path, import_id: str,
) -> tuple[dict, bytes]:
    source = arkime_summary_raw_source(db_path, import_id)
    digest = source["sha256"]
    expected = canonical_artifact_path(artifact_root_for(db_path), digest).absolute()
    stored = Path(source["canonical_path"]).absolute()
    if stored != expected:
        raise ArkimeSummaryConflict(
            "The retained Arkime summary source path is not canonical"
        )
    base = db_path.parent.absolute()
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    directory_flags = flags | getattr(os, "O_DIRECTORY", 0) | getattr(
        os, "O_NOFOLLOW", 0
    )
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
            raise ArkimeSummaryConflict(
                "The retained Arkime summary source is not a regular file"
            )
        expected_size = int(source["size_bytes"])
        if info.st_size != expected_size or expected_size > MAX_ARKIME_SUMMARY_BYTES:
            raise ArkimeSummaryConflict(
                "The retained Arkime summary source size no longer matches its receipt"
            )
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
            raise ArkimeSummaryConflict(
                "The retained Arkime summary source no longer matches its SHA-256 receipt"
            )
        return source, content
    except ArkimeSummaryError:
        raise
    except OSError as exc:
        raise ArkimeSummaryConflict(
            "The retained Arkime summary source is unavailable or unsafe"
        ) from exc
    finally:
        for descriptor in reversed(descriptors):
            try:
                os.close(descriptor)
            except OSError:
                pass
