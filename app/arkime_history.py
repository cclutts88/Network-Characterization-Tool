"""Immutable communication history for one exact automatic Arkime API stream."""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
import uuid

from app.arkime_connector import init_arkime_connector_storage
from app.derived_contracts import (
    ARKIME_STREAM_HISTORY_FAMILY,
    ARKIME_STREAM_HISTORY_PARAMETERS,
    ARKIME_STREAM_HISTORY_SCHEMA_VERSION,
    ARKIME_STREAM_HISTORY_VERSION,
)
from app.derived_results import (
    init_derived_result_storage, prepare_derived_result, publish_derived_result,
)
from app.database import connect_database, initialize_once_per_database


MAX_PAGE = 100
MAX_HISTORY_SOURCES = 1_000
MAX_HISTORY_RECEIPTS = 1_000_000
MAX_PATH_FILTER = 200


class ArkimeHistoryError(ValueError):
    pass


class ArkimeHistoryConflict(ArkimeHistoryError):
    pass


def _json(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _hash(value) -> str:
    return hashlib.sha256(_json(value).encode()).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _page(value: int, name: str, *, minimum: int, maximum: int | None = None) -> int:
    if type(value) is not int or value < minimum or (maximum is not None and value > maximum):
        suffix = f" and {maximum}" if maximum is not None else ""
        raise ArkimeHistoryError(f"{name} must be between {minimum}{suffix}")
    return value


def _immutable(table: str) -> str:
    return f"""
        CREATE TRIGGER IF NOT EXISTS {table}_no_update BEFORE UPDATE ON {table}
        BEGIN SELECT RAISE(ABORT, '{table} is immutable'); END;
        CREATE TRIGGER IF NOT EXISTS {table}_no_delete BEFORE DELETE ON {table}
        BEGIN SELECT RAISE(ABORT, '{table} is immutable'); END;
    """


@initialize_once_per_database
def init_arkime_history_storage(db_path: Path) -> None:
    init_arkime_connector_storage(db_path)
    init_derived_result_storage(db_path)
    with connect_database(db_path) as db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS arkime_history_build_attempts (
                attempt_id TEXT PRIMARY KEY,
                anchor_run_id TEXT NOT NULL REFERENCES arkime_pull_runs(run_id),
                requested_by TEXT NOT NULL,
                requested_at TEXT NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('complete','failed')),
                result_id TEXT REFERENCES derived_results(result_id),
                stream_identity TEXT,
                source_manifest_sha256 TEXT,
                detail TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS arkime_history_attempts_anchor
                ON arkime_history_build_attempts(anchor_run_id, requested_at DESC);
            CREATE TABLE IF NOT EXISTS arkime_history_generations (
                result_id TEXT PRIMARY KEY REFERENCES derived_results(result_id),
                stream_identity TEXT NOT NULL,
                dataset_identity TEXT NOT NULL,
                profile_id TEXT NOT NULL,
                profile_version INTEGER NOT NULL,
                profile_name TEXT NOT NULL,
                scope_id TEXT NOT NULL,
                scope_label TEXT NOT NULL,
                scope_version INTEGER NOT NULL,
                operator_sensor TEXT NOT NULL,
                query_expression TEXT NOT NULL,
                bounding_mode TEXT NOT NULL,
                connector_id TEXT NOT NULL,
                connector_contract TEXT NOT NULL,
                parser_version TEXT NOT NULL,
                source_manifest_sha256 TEXT NOT NULL,
                history_start TEXT,
                history_end TEXT,
                included_source_count INTEGER NOT NULL,
                excluded_source_count INTEGER NOT NULL,
                excluded_record_count INTEGER NOT NULL,
                duplicate_encounter_count INTEGER NOT NULL,
                retained_record_count INTEGER NOT NULL,
                path_count INTEGER NOT NULL,
                generated_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS arkime_history_generations_stream
                ON arkime_history_generations(stream_identity, generated_at DESC);
            CREATE TABLE IF NOT EXISTS arkime_history_sources (
                result_id TEXT NOT NULL REFERENCES arkime_history_generations(result_id),
                run_id TEXT NOT NULL,
                import_id TEXT,
                observation_id TEXT,
                query_start TEXT NOT NULL,
                query_end TEXT NOT NULL,
                capture_coverage TEXT,
                disposition TEXT NOT NULL CHECK(disposition IN ('included','excluded')),
                reason TEXT,
                PRIMARY KEY(result_id, run_id)
            );
            CREATE TABLE IF NOT EXISTS arkime_history_record_exclusions (
                result_id TEXT NOT NULL REFERENCES arkime_history_generations(result_id),
                receipt_id TEXT NOT NULL,
                run_id TEXT NOT NULL,
                import_id TEXT NOT NULL,
                source_ordinal INTEGER NOT NULL,
                reason TEXT NOT NULL,
                PRIMARY KEY(result_id, receipt_id)
            );
            CREATE TABLE IF NOT EXISTS arkime_history_records (
                result_id TEXT NOT NULL REFERENCES arkime_history_generations(result_id),
                record_key TEXT NOT NULL,
                source_node TEXT NOT NULL,
                session_id TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                source_port INTEGER,
                destination_ip TEXT NOT NULL,
                destination_port INTEGER,
                transport TEXT,
                applications_json TEXT NOT NULL,
                first_packet TEXT NOT NULL,
                last_packet TEXT NOT NULL,
                packet_count_text TEXT,
                byte_count_text TEXT,
                vlan_json TEXT NOT NULL,
                context_json TEXT NOT NULL,
                semantic_sha256 TEXT NOT NULL,
                PRIMARY KEY(result_id, record_key)
            );
            CREATE TABLE IF NOT EXISTS arkime_history_memberships (
                result_id TEXT NOT NULL,
                record_key TEXT NOT NULL,
                receipt_id TEXT NOT NULL,
                run_id TEXT NOT NULL,
                import_id TEXT NOT NULL,
                observation_id TEXT NOT NULL,
                source_ordinal INTEGER NOT NULL,
                query_start TEXT NOT NULL,
                query_end TEXT NOT NULL,
                capture_coverage TEXT NOT NULL,
                PRIMARY KEY(result_id, record_key, receipt_id),
                FOREIGN KEY(result_id, record_key)
                    REFERENCES arkime_history_records(result_id, record_key)
            );
            CREATE TABLE IF NOT EXISTS arkime_history_paths (
                result_id TEXT NOT NULL REFERENCES arkime_history_generations(result_id),
                path_key TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                destination_ip TEXT NOT NULL,
                destination_port INTEGER,
                transport TEXT,
                first_packet TEXT NOT NULL,
                last_packet TEXT NOT NULL,
                applications_json TEXT NOT NULL,
                retained_record_count INTEGER NOT NULL,
                known_packet_total_text TEXT,
                packet_records_unknown INTEGER NOT NULL,
                known_byte_total_text TEXT,
                byte_records_unknown INTEGER NOT NULL,
                source_window_count INTEGER NOT NULL,
                PRIMARY KEY(result_id, path_key)
            );
            CREATE TABLE IF NOT EXISTS arkime_history_path_records (
                result_id TEXT NOT NULL,
                path_key TEXT NOT NULL,
                record_key TEXT NOT NULL,
                PRIMARY KEY(result_id, path_key, record_key),
                FOREIGN KEY(result_id, path_key)
                    REFERENCES arkime_history_paths(result_id, path_key),
                FOREIGN KEY(result_id, record_key)
                    REFERENCES arkime_history_records(result_id, record_key)
            );
        """ + _immutable("arkime_history_build_attempts")
            + _immutable("arkime_history_generations")
            + _immutable("arkime_history_sources")
            + _immutable("arkime_history_record_exclusions")
            + _immutable("arkime_history_records")
            + _immutable("arkime_history_memberships")
            + _immutable("arkime_history_paths")
            + _immutable("arkime_history_path_records"))


STREAM_FIELDS = (
    "dataset_identity", "profile_id", "profile_version", "scope_id", "scope_label",
    "scope_version", "operator_sensor", "query_expression", "bounding_mode",
    "connector_id", "connector_contract", "parser_version",
)


def _stream(row: sqlite3.Row) -> dict:
    return {field: row[field] for field in STREAM_FIELDS}


def _stream_identity(stream: dict) -> str:
    return hashlib.sha256(_json(stream).encode()).hexdigest()


def _guard_stream_authority(db: sqlite3.Connection, stream: dict) -> None:
    scope = db.execute(
        "SELECT label,version,active FROM network_scopes WHERE scope_id=?",
        (stream["scope_id"],),
    ).fetchone()
    if (
        scope is None or not scope[2] or scope[0] != stream["scope_label"]
        or int(scope[1]) != int(stream["scope_version"])
    ):
        raise ArkimeHistoryConflict(
            "The frozen Network Scope authority changed; no history generation was published"
        )
    profile = db.execute("""SELECT scope_id,scope_label,scope_version,operator_sensor,
        query_expression,bounding_mode FROM arkime_pull_profile_versions
        WHERE profile_id=? AND version=?""", (
            stream["profile_id"], stream["profile_version"],
        )).fetchone()
    expected = (
        stream["scope_id"], stream["scope_label"], stream["scope_version"],
        stream["operator_sensor"], stream["query_expression"], stream["bounding_mode"],
    )
    if profile is None or tuple(profile) != expected:
        raise ArkimeHistoryConflict(
            "The frozen Arkime profile authority is unavailable or changed"
        )


def _candidate_rows(db: sqlite3.Connection, stream: dict) -> list[sqlite3.Row]:
    db.row_factory = sqlite3.Row
    where = " AND ".join(f"r.{field}=?" for field in STREAM_FIELDS)
    return db.execute(f"""
        SELECT r.*, ai.observation_id, ai.calculated_export_completeness,
               ai.operator_export_assessment, ai.capture_coverage,
               ai.returned_count, ai.imported_at, ai.actor AS import_actor,
               ai.scope_id AS import_scope_id, ai.scope_label AS import_scope_label,
               ai.scope_version AS import_scope_version,
               ai.operator_sensor AS import_operator_sensor,
               ai.query_expression AS import_query_expression,
               ai.bounding_mode AS import_bounding_mode,
               ai.query_start AS import_query_start, ai.query_end AS import_query_end,
               ai.parser_version AS import_parser_version,
               ao.metadata_json, ao.sha256 AS observation_sha256,
               v.name AS profile_name, v.scope_id AS version_scope_id,
               v.scope_label AS version_scope_label, v.scope_version AS version_scope_version,
               v.operator_sensor AS version_operator_sensor,
               v.query_expression AS version_query_expression,
               v.bounding_mode AS version_bounding_mode
          FROM arkime_pull_runs r
          LEFT JOIN arkime_imports ai ON ai.import_id=r.import_id
          LEFT JOIN artifact_observations ao ON ao.observation_id=ai.observation_id
          LEFT JOIN arkime_pull_profile_versions v
            ON v.profile_id=r.profile_id AND v.version=r.profile_version
         WHERE {where}
         ORDER BY r.queued_at, r.run_id
         LIMIT ?
    """, (*tuple(stream[field] for field in STREAM_FIELDS), MAX_HISTORY_SOURCES + 1)).fetchall()


def _source_reason(row: sqlite3.Row) -> str | None:
    if row["state"] != "complete":
        return f"Pull state is {row['state']}; only complete retained API results are eligible"
    if not row["import_id"] or not row["observation_id"]:
        return "The completed pull has no retained import and observation"
    if row["calculated_export_completeness"] != "complete":
        return "The retained API result is not calculated complete"
    if row["operator_export_assessment"] != "complete":
        return "The retained API result is not operator-assessed complete"
    import_checks = (
        (row["import_scope_id"], row["scope_id"]),
        (row["import_scope_label"], row["scope_label"]),
        (row["import_scope_version"], row["scope_version"]),
        (row["import_operator_sensor"], row["operator_sensor"]),
        (row["import_query_expression"], row["query_expression"]),
        (row["import_bounding_mode"], row["bounding_mode"]),
        (row["import_parser_version"], row["parser_version"]),
    )
    if any(left != right for left, right in import_checks):
        return "The retained import disagrees with its frozen pull authority"
    try:
        run_start = datetime.fromisoformat(row["query_start"].replace("Z", "+00:00"))
        run_end = datetime.fromisoformat(row["query_end"].replace("Z", "+00:00"))
        import_start = datetime.fromisoformat(row["import_query_start"].replace("Z", "+00:00"))
        import_end = datetime.fromisoformat(row["import_query_end"].replace("Z", "+00:00"))
    except (AttributeError, ValueError):
        return "The retained import or pull has unreadable query times"
    if run_start != import_start or run_end != import_end:
        return "The retained import disagrees with its frozen pull query interval"
    profile_checks = (
        (row["version_scope_id"], row["scope_id"]),
        (row["version_scope_label"], row["scope_label"]),
        (row["version_scope_version"], row["scope_version"]),
        (row["version_operator_sensor"], row["operator_sensor"]),
        (row["version_query_expression"], row["query_expression"]),
        (row["version_bounding_mode"], row["bounding_mode"]),
    )
    if any(left != right for left, right in profile_checks):
        return "The pull no longer matches its immutable profile version"
    try:
        metadata = json.loads(row["metadata_json"])
    except (TypeError, json.JSONDecodeError):
        return "The retained observation metadata is unreadable"
    expected = {
        "import_tier": "tier_e_sessions_api",
        "pull_run_id": row["run_id"],
        "connector_id": row["connector_id"],
        "dataset_identity": row["dataset_identity"],
        "connector_contract": row["connector_contract"],
        "parser_version": row["parser_version"],
        "scope_id": row["scope_id"],
        "operator_sensor": row["operator_sensor"],
        "query_start": row["import_query_start"],
        "query_end": row["import_query_end"],
        "bounding_mode": row["bounding_mode"],
        "returned_count": row["returned_count"],
    }
    if any(metadata.get(key) != value for key, value in expected.items()):
        return "The retained observation does not carry the frozen API stream identity"
    try:
        request_parameters = json.loads(row["request_parameters_json"])
    except (TypeError, json.JSONDecodeError):
        return "The frozen pull request parameters are unreadable"
    if metadata.get("request_parameters") != request_parameters:
        return "The retained observation request parameters disagree with the pull"
    return None


def _receipt_rows(
    db: sqlite3.Connection, import_id: str, *, limit: int,
) -> list[sqlite3.Row]:
    db.row_factory = sqlite3.Row
    return db.execute(
        """SELECT * FROM arkime_session_receipts WHERE import_id=?
           ORDER BY source_ordinal LIMIT ?""",
        (import_id, limit),
    ).fetchall()


def _semantic(row: sqlite3.Row) -> dict:
    try:
        applications = sorted(set(json.loads(row["applications_json"])))
        vlans = sorted(set(json.loads(row["vlan_json"])), key=lambda value: str(value))
        context = json.loads(row["context_json"])
    except (TypeError, json.JSONDecodeError) as exc:
        raise ArkimeHistoryConflict("A retained Arkime receipt contains unreadable JSON") from exc
    return {
        "source_ip": row["source_ip"], "source_port": row["source_port"],
        "destination_ip": row["destination_ip"],
        "destination_port": row["destination_port"], "transport": row["transport"],
        "applications": applications, "first_packet": row["first_packet"],
        "last_packet": row["last_packet"], "packet_count": row["packet_count"],
        "byte_count": row["byte_count"], "vlans": vlans, "context": context,
    }


def _snapshot(db: sqlite3.Connection, stream: dict) -> dict:
    sources = []
    records: dict[str, dict] = {}
    memberships = []
    exclusions = []
    conflicts = []
    manifest_sources = []
    candidates = _candidate_rows(db, stream)
    if len(candidates) > MAX_HISTORY_SOURCES:
        raise ArkimeHistoryConflict(
            f"This stream has more than {MAX_HISTORY_SOURCES:,} retained pulls; narrow the "
            "saved pull definition before calculating history"
        )
    receipt_total = 0
    for row in candidates:
        reason = _source_reason(row)
        source = {
            "run_id": row["run_id"], "import_id": row["import_id"],
            "observation_id": row["observation_id"], "query_start": row["query_start"],
            "query_end": row["query_end"], "capture_coverage": row["capture_coverage"],
            "disposition": "excluded" if reason else "included", "reason": reason,
        }
        sources.append(source)
        receipt_manifest = []
        if not reason:
            remaining = MAX_HISTORY_RECEIPTS - receipt_total
            receipts = _receipt_rows(db, row["import_id"], limit=remaining + 1)
            receipt_total += len(receipts)
            if receipt_total > MAX_HISTORY_RECEIPTS:
                raise ArkimeHistoryConflict(
                    f"This calculation exceeds the {MAX_HISTORY_RECEIPTS:,}-receipt safety "
                    "limit; use a narrower saved pull definition"
                )
            for receipt in receipts:
                semantic = _semantic(receipt)
                semantic_sha = _hash(semantic)
                receipt_manifest.append({
                    "receipt_id": receipt["receipt_id"],
                    "source_ordinal": int(receipt["source_ordinal"]),
                    "source_node": receipt["source_node"],
                    "session_id": receipt["session_id"],
                    "semantic_sha256": semantic_sha,
                })
                if not receipt["source_node"] or not receipt["session_id"]:
                    exclusions.append({
                        "receipt_id": receipt["receipt_id"], "run_id": row["run_id"],
                        "import_id": row["import_id"],
                        "source_ordinal": int(receipt["source_ordinal"]),
                        "reason": "Missing Arkime source node or session ID",
                    })
                    continue
                record_key = hashlib.sha256(
                    f"{stream['dataset_identity']}\0{receipt['source_node']}\0{receipt['session_id']}".encode()
                ).hexdigest()
                retained = records.get(record_key)
                if retained is not None and retained["semantic_sha256"] != semantic_sha:
                    conflicts.append({
                        "record_key": record_key,
                        "source_node": receipt["source_node"],
                        "session_id": receipt["session_id"],
                        "receipt_ids": sorted({retained["first_receipt_id"], receipt["receipt_id"]}),
                    })
                    continue
                if retained is None:
                    records[record_key] = {
                        "record_key": record_key, "source_node": receipt["source_node"],
                        "session_id": receipt["session_id"], "semantic_sha256": semantic_sha,
                        "first_receipt_id": receipt["receipt_id"], **semantic,
                    }
                memberships.append({
                    "record_key": record_key, "receipt_id": receipt["receipt_id"],
                    "run_id": row["run_id"], "import_id": row["import_id"],
                    "observation_id": row["observation_id"],
                    "source_ordinal": int(receipt["source_ordinal"]),
                    "query_start": row["query_start"], "query_end": row["query_end"],
                    "capture_coverage": row["capture_coverage"],
                })
        manifest_sources.append({
            "run_id": row["run_id"], "state": row["state"],
            "import_id": row["import_id"], "observation_id": row["observation_id"],
            "observation_sha256": row["observation_sha256"],
            "query_start": row["query_start"], "query_end": row["query_end"],
            "capture_coverage": row["capture_coverage"], "reason": reason,
            "receipts": receipt_manifest,
        })
    manifest = {"stream": stream, "sources": manifest_sources}
    return {
        "sources": sources, "records": records, "memberships": memberships,
        "exclusions": exclusions, "conflicts": conflicts, "manifest": manifest,
        "manifest_sha256": _hash(manifest),
    }


def _paths(records: dict[str, dict], memberships: list[dict]) -> list[dict]:
    windows: dict[str, set[str]] = defaultdict(set)
    for member in memberships:
        windows[member["record_key"]].add(member["import_id"])
    grouped: dict[str, dict] = {}
    for record in records.values():
        basis = {
            "source_ip": record["source_ip"], "destination_ip": record["destination_ip"],
            "destination_port": record["destination_port"], "transport": record["transport"],
        }
        key = _hash(basis)
        item = grouped.setdefault(key, {
            "path_key": key, **basis, "first_packet": record["first_packet"],
            "last_packet": record["last_packet"], "applications": set(), "record_keys": [],
            "known_packet_total": 0, "packet_records_unknown": 0,
            "known_byte_total": 0, "byte_records_unknown": 0, "source_windows": set(),
        })
        item["first_packet"] = min(item["first_packet"], record["first_packet"])
        item["last_packet"] = max(item["last_packet"], record["last_packet"])
        item["applications"].update(record["applications"])
        item["record_keys"].append(record["record_key"])
        item["source_windows"].update(windows[record["record_key"]])
        if record["packet_count"] is None:
            item["packet_records_unknown"] += 1
        else:
            item["known_packet_total"] += int(record["packet_count"])
        if record["byte_count"] is None:
            item["byte_records_unknown"] += 1
        else:
            item["known_byte_total"] += int(record["byte_count"])
    result = []
    for item in grouped.values():
        item["applications"] = sorted(item["applications"])
        item["record_keys"] = sorted(item["record_keys"])
        item["source_window_count"] = len(item.pop("source_windows"))
        item["retained_record_count"] = len(item["record_keys"])
        result.append(item)
    return sorted(result, key=lambda item: (
        item["source_ip"], item["destination_ip"],
        item["transport"] or "", item["destination_port"] if item["destination_port"] is not None else -1,
    ))


def _record_attempt(
    db_path: Path, *, attempt_id: str, anchor_run_id: str, actor: str, status: str,
    detail: str, result_id: str | None = None, stream_identity: str | None = None,
    manifest_sha: str | None = None,
) -> None:
    with connect_database(db_path) as db:
        db.execute("""INSERT INTO arkime_history_build_attempts
            (attempt_id,anchor_run_id,requested_by,requested_at,status,result_id,
             stream_identity,source_manifest_sha256,detail)
            VALUES (?,?,?,?,?,?,?,?,?)""", (
                attempt_id, anchor_run_id, actor, _now(), status, result_id,
                stream_identity, manifest_sha, detail,
            ))


def build_arkime_history(db_path: Path, anchor_run_id: str, *, actor: str) -> dict:
    init_arkime_history_storage(db_path)
    attempt_id = f"arkime_history_attempt_{uuid.uuid4().hex}"
    stream = None
    stream_id = None
    snapshot = None
    try:
        with connect_database(db_path, read_only=True) as db:
            db.row_factory = sqlite3.Row
            anchor = db.execute("SELECT * FROM arkime_pull_runs WHERE run_id=?", (anchor_run_id,)).fetchone()
            if anchor is None:
                raise KeyError("Arkime pull run not found")
            stream = _stream(anchor)
            stream_id = _stream_identity(stream)
            if stream["dataset_identity"] in {"unverified", "legacy-unverified"}:
                raise ArkimeHistoryConflict(
                    "This pull has no frozen Arkime dataset identity; collect a new pull after configuring NCT_ARKIME_DATASET_ID"
                )
            _guard_stream_authority(db, stream)
            snapshot = _snapshot(db, stream)
        if not any(item["disposition"] == "included" for item in snapshot["sources"]):
            reasons = sorted({item["reason"] for item in snapshot["sources"] if item["reason"]})
            detail = f" Reasons: {'; '.join(reasons)}" if reasons else ""
            raise ArkimeHistoryConflict(
                "No complete retained automatic API pulls are eligible for this stream" + detail
            )
        if snapshot["conflicts"]:
            refs = sorted({ref for item in snapshot["conflicts"] for ref in item["receipt_ids"]})
            raise ArkimeHistoryConflict(
                "Conflicting copies share an Arkime node and session ID; no generation was published. "
                f"Receipt references: {', '.join(refs[:20])}"
            )
        records = snapshot["records"]
        paths = _paths(records, snapshot["memberships"])
        included = [item for item in snapshot["sources"] if item["disposition"] == "included"]
        history_start = min((item["query_start"] for item in included), default=None)
        history_end = max((item["query_end"] for item in included), default=None)
        duplicate_count = len(snapshot["memberships"]) - len(records)
        profile_name = next(
            row["profile_name"] for row in _candidate_rows_for_path(db_path, stream)
            if row["profile_name"]
        )
        payload = {
            "stream_identity": stream_id, "source_manifest_sha256": snapshot["manifest_sha256"],
            "history_start": history_start, "history_end": history_end,
            "included_source_count": len(included),
            "excluded_source_count": len(snapshot["sources"]) - len(included),
            "excluded_record_count": len(snapshot["exclusions"]),
            "duplicate_encounter_count": duplicate_count,
            "retained_record_count": len(records), "path_count": len(paths),
            "boundary": "Deduplicated retained Arkime records; not unique connections, deduplicated packets, live traffic, continuous capture, absence, or whole-network truth.",
        }
        prepared = prepare_derived_result(
            family=ARKIME_STREAM_HISTORY_FAMILY,
            analysis_version=ARKIME_STREAM_HISTORY_VERSION,
            payload_schema_version=ARKIME_STREAM_HISTORY_SCHEMA_VERSION,
            parameters=dict(ARKIME_STREAM_HISTORY_PARAMETERS),
            inputs=[{
                "role": "stream_manifest", "kind": "canonical_json_sha256",
                "identity": snapshot["manifest_sha256"],
                "metadata": {"stream_identity": stream_id, "source_count": len(snapshot["sources"])},
            }], payload=payload,
        )

        def guard(db: sqlite3.Connection) -> None:
            _guard_stream_authority(db, stream)
            current = _snapshot(db, stream)
            if current["manifest_sha256"] != snapshot["manifest_sha256"]:
                raise ArkimeHistoryConflict(
                    "The retained automatic stream changed during calculation; calculate a new generation"
                )

        def finalize(db: sqlite3.Connection, created: bool) -> None:
            derived_row = db.execute(
                "SELECT generated_at FROM derived_results WHERE result_id=?",
                (prepared.identity.result_id,),
            ).fetchone()
            if derived_row is None:
                raise ArkimeHistoryConflict("Stored Arkime history parent result is unavailable")
            values = (
                prepared.identity.result_id, stream_id, stream["dataset_identity"],
                stream["profile_id"], stream["profile_version"], profile_name,
                stream["scope_id"], stream["scope_label"], stream["scope_version"],
                stream["operator_sensor"], stream["query_expression"], stream["bounding_mode"],
                stream["connector_id"], stream["connector_contract"], stream["parser_version"],
                snapshot["manifest_sha256"], history_start, history_end, len(included),
                len(snapshot["sources"]) - len(included), len(snapshot["exclusions"]),
                duplicate_count, len(records), len(paths), derived_row[0],
            )
            db.execute("""INSERT OR IGNORE INTO arkime_history_generations VALUES
                (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", values)
            retained = db.execute(
                "SELECT * FROM arkime_history_generations WHERE result_id=?",
                (prepared.identity.result_id,),
            ).fetchone()
            if retained is None or tuple(retained) != values:
                raise ArkimeHistoryConflict("Stored Arkime history generation metadata conflicts")
            _insert_children(db, prepared.identity.result_id, snapshot, records, paths)

        published = publish_derived_result(
            db_path, prepared, transaction_guard=guard, transaction_finalize=finalize,
        )
        _record_attempt(
            db_path, attempt_id=attempt_id, anchor_run_id=anchor_run_id, actor=actor,
            status="complete", detail="Immutable retained history generation published",
            result_id=published["result_id"], stream_identity=stream_id,
            manifest_sha=snapshot["manifest_sha256"],
        )
        return get_arkime_history(db_path, published["result_id"])
    except Exception as exc:
        try:
            _record_attempt(
                db_path, attempt_id=attempt_id, anchor_run_id=anchor_run_id, actor=actor,
                status="failed", detail=str(exc)[:1000], stream_identity=stream_id,
                manifest_sha=snapshot["manifest_sha256"] if snapshot else None,
            )
        except Exception:
            pass
        raise


def _candidate_rows_for_path(db_path: Path, stream: dict) -> list[sqlite3.Row]:
    with connect_database(db_path, read_only=True) as db:
        return _candidate_rows(db, stream)


def _insert_children(
    db: sqlite3.Connection, result_id: str, snapshot: dict,
    records: dict[str, dict], paths: list[dict],
) -> None:
    def exact(table: str, columns: tuple[str, ...], values: tuple, keys: int) -> None:
        names = ",".join(columns)
        placeholders = ",".join("?" for _ in values)
        db.execute(f"INSERT OR IGNORE INTO {table} ({names}) VALUES ({placeholders})", values)
        where = " AND ".join(f"{name}=?" for name in columns[:keys])
        retained = db.execute(
            f"SELECT {names} FROM {table} WHERE {where}", values[:keys],
        ).fetchone()
        if retained is None or tuple(retained) != values:
            raise ArkimeHistoryConflict(f"Stored {table} rows conflict with this generation")

    for source in snapshot["sources"]:
        values = (result_id, source["run_id"], source["import_id"], source["observation_id"],
                  source["query_start"], source["query_end"], source["capture_coverage"],
                  source["disposition"], source["reason"])
        exact("arkime_history_sources", (
            "result_id","run_id","import_id","observation_id","query_start","query_end",
            "capture_coverage","disposition","reason",
        ), values, 2)
    for exclusion in snapshot["exclusions"]:
        values = (
            result_id, exclusion["receipt_id"], exclusion["run_id"], exclusion["import_id"],
            exclusion["source_ordinal"], exclusion["reason"],
        )
        exact("arkime_history_record_exclusions", (
            "result_id","receipt_id","run_id","import_id","source_ordinal","reason",
        ), values, 2)
    for record in records.values():
        values = (
                result_id, record["record_key"], record["source_node"], record["session_id"],
                record["source_ip"], record["source_port"], record["destination_ip"],
                record["destination_port"], record["transport"], _json(record["applications"]),
                record["first_packet"], record["last_packet"],
                str(record["packet_count"]) if record["packet_count"] is not None else None,
                str(record["byte_count"]) if record["byte_count"] is not None else None,
                _json(record["vlans"]), _json(record["context"]), record["semantic_sha256"],
            )
        exact("arkime_history_records", (
            "result_id","record_key","source_node","session_id","source_ip","source_port",
            "destination_ip","destination_port","transport","applications_json","first_packet",
            "last_packet","packet_count_text","byte_count_text","vlan_json","context_json",
            "semantic_sha256",
        ), values, 2)
    for member in snapshot["memberships"]:
        values = (
                result_id, member["record_key"], member["receipt_id"], member["run_id"],
                member["import_id"], member["observation_id"], member["source_ordinal"],
                member["query_start"], member["query_end"], member["capture_coverage"],
            )
        exact("arkime_history_memberships", (
            "result_id","record_key","receipt_id","run_id","import_id","observation_id",
            "source_ordinal","query_start","query_end","capture_coverage",
        ), values, 3)
    for path in paths:
        values = (
                result_id, path["path_key"], path["source_ip"], path["destination_ip"],
                path["destination_port"], path["transport"], path["first_packet"],
                path["last_packet"], _json(path["applications"]), path["retained_record_count"],
                str(path["known_packet_total"]), path["packet_records_unknown"],
                str(path["known_byte_total"]), path["byte_records_unknown"],
                path["source_window_count"],
            )
        exact("arkime_history_paths", (
            "result_id","path_key","source_ip","destination_ip","destination_port","transport",
            "first_packet","last_packet","applications_json","retained_record_count",
            "known_packet_total_text","packet_records_unknown","known_byte_total_text",
            "byte_records_unknown","source_window_count",
        ), values, 2)
        for record_key in path["record_keys"]:
            exact("arkime_history_path_records", ("result_id","path_key","record_key"),
                  (result_id, path["path_key"], record_key), 3)
    expected = {
        "sources": len(snapshot["sources"]), "exclusions": len(snapshot["exclusions"]),
        "records": len(records), "memberships": len(snapshot["memberships"]), "paths": len(paths),
        "path_records": sum(len(path["record_keys"]) for path in paths),
    }
    actual = {
        "sources": db.execute("SELECT COUNT(*) FROM arkime_history_sources WHERE result_id=?", (result_id,)).fetchone()[0],
        "exclusions": db.execute("SELECT COUNT(*) FROM arkime_history_record_exclusions WHERE result_id=?", (result_id,)).fetchone()[0],
        "records": db.execute("SELECT COUNT(*) FROM arkime_history_records WHERE result_id=?", (result_id,)).fetchone()[0],
        "memberships": db.execute("SELECT COUNT(*) FROM arkime_history_memberships WHERE result_id=?", (result_id,)).fetchone()[0],
        "paths": db.execute("SELECT COUNT(*) FROM arkime_history_paths WHERE result_id=?", (result_id,)).fetchone()[0],
        "path_records": db.execute("SELECT COUNT(*) FROM arkime_history_path_records WHERE result_id=?", (result_id,)).fetchone()[0],
    }
    if actual != expected:
        raise ArkimeHistoryConflict("Stored Arkime history child rows conflict with the generation")


def list_arkime_history_streams(
    db_path: Path, *, limit: int = 100, offset: int = 0,
) -> dict:
    limit = _page(limit, "limit", minimum=1, maximum=MAX_PAGE)
    offset = _page(offset, "offset", minimum=0)
    partitions = ",".join(f"r.{field}" for field in STREAM_FIELDS)
    with connect_database(db_path, read_only=True) as db:
        db.row_factory = sqlite3.Row
        total = db.execute(f"""SELECT COUNT(*) FROM (
            SELECT 1 FROM arkime_pull_runs r GROUP BY {partitions}
        )""").fetchone()[0]
        rows = db.execute(f"""WITH ranked AS (
            SELECT r.*, v.name AS profile_name,
                   ROW_NUMBER() OVER (
                       PARTITION BY {partitions}
                       ORDER BY r.queued_at DESC, r.run_id DESC
                   ) AS stream_rank,
                   COUNT(*) OVER (PARTITION BY {partitions}) AS pull_count,
                   SUM(CASE WHEN r.state='complete' THEN 1 ELSE 0 END)
                       OVER (PARTITION BY {partitions}) AS complete_pull_count
              FROM arkime_pull_runs r
              JOIN arkime_pull_profile_versions v
                ON v.profile_id=r.profile_id AND v.version=r.profile_version
        )
        SELECT * FROM ranked WHERE stream_rank=1
         ORDER BY queued_at DESC, run_id DESC LIMIT ? OFFSET ?""", (limit, offset)).fetchall()
    streams = []
    for row in rows:
        stream = _stream(row)
        identity = _stream_identity(stream)
        streams.append({
            "stream_identity": identity, **stream, "profile_name": row["profile_name"],
            "anchor_run_id": row["run_id"], "pull_count": int(row["pull_count"]),
            "complete_pull_count": int(row["complete_pull_count"]),
            "history_ready": stream["dataset_identity"] not in {"unverified", "legacy-unverified"},
        })
    return {
        "items": streams,
        "pagination": {"limit": limit, "offset": offset, "total": total,
                       "has_more": offset + len(streams) < total},
        "read_only": True,
    }


def list_arkime_histories(
    db_path: Path, *, limit: int = 25, offset: int = 0,
    stream_identity: str | None = None,
) -> dict:
    limit = _page(limit, "limit", minimum=1, maximum=MAX_PAGE)
    offset = _page(offset, "offset", minimum=0)
    if stream_identity is not None and (
        len(stream_identity) != 64
        or any(character not in "0123456789abcdef" for character in stream_identity.lower())
    ):
        raise ArkimeHistoryError("stream_identity must be a SHA-256 value")
    where = " WHERE stream_identity=?" if stream_identity else ""
    parameters = (stream_identity,) if stream_identity else ()
    with connect_database(db_path, read_only=True) as db:
        db.row_factory = sqlite3.Row
        total = db.execute(
            f"SELECT COUNT(*) FROM arkime_history_generations{where}", parameters,
        ).fetchone()[0]
        rows = db.execute(f"""SELECT * FROM arkime_history_generations{where}
            ORDER BY generated_at DESC, result_id DESC LIMIT ? OFFSET ?""",
            (*parameters, limit, offset)).fetchall()
    return {
        "items": [_generation_dict(row) for row in rows],
        "pagination": {"limit": limit, "offset": offset, "total": total,
                       "has_more": offset + len(rows) < total}, "read_only": True,
    }


def _generation_dict(row: sqlite3.Row) -> dict:
    return {
        key: row[key] for key in row.keys()
    } | {
        "scope": {"scope_id": row["scope_id"], "label": row["scope_label"],
                  "version": int(row["scope_version"])},
        "detail_url": f"/api/arkime/history/{row['result_id']}",
    }


def get_arkime_history(
    db_path: Path, result_id: str, *, limit: int = 50, offset: int = 0,
    path_filter: str | None = None,
) -> dict:
    limit = _page(limit, "limit", minimum=1, maximum=MAX_PAGE)
    offset = _page(offset, "offset", minimum=0)
    normalized_filter = (path_filter or "").strip()
    if len(normalized_filter) > MAX_PATH_FILTER:
        raise ArkimeHistoryError(
            f"path_filter must be no longer than {MAX_PATH_FILTER} characters"
        )
    escaped_filter = (
        normalized_filter.lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    )
    where = "result_id=?"
    parameters: list[object] = [result_id]
    if escaped_filter:
        where += """ AND (
            lower(COALESCE(source_ip,'')) LIKE ? ESCAPE '\\'
            OR lower(COALESCE(destination_ip,'')) LIKE ? ESCAPE '\\'
            OR CAST(destination_port AS TEXT) LIKE ? ESCAPE '\\'
            OR lower(COALESCE(transport,'')) LIKE ? ESCAPE '\\'
            OR lower(applications_json) LIKE ? ESCAPE '\\'
        )"""
        needle = f"%{escaped_filter}%"
        parameters.extend([needle] * 5)
    with connect_database(db_path, read_only=True) as db:
        db.row_factory = sqlite3.Row
        row = db.execute("SELECT * FROM arkime_history_generations WHERE result_id=?", (result_id,)).fetchone()
        if row is None:
            raise KeyError("Arkime communication history not found")
        unfiltered_total = db.execute(
            "SELECT COUNT(*) FROM arkime_history_paths WHERE result_id=?", (result_id,),
        ).fetchone()[0]
        total = db.execute(
            f"SELECT COUNT(*) FROM arkime_history_paths WHERE {where}", parameters,
        ).fetchone()[0]
        paths = db.execute(f"""SELECT * FROM arkime_history_paths WHERE {where}
            ORDER BY source_ip,destination_ip,transport,destination_port,path_key
            LIMIT ? OFFSET ?""", (*parameters, limit, offset)).fetchall()
        sources = db.execute("""SELECT * FROM arkime_history_sources WHERE result_id=?
            ORDER BY query_start,query_end,run_id""", (result_id,)).fetchall()
        attempt = db.execute("""SELECT status,detail,requested_at FROM arkime_history_build_attempts
            WHERE stream_identity=? ORDER BY requested_at DESC,attempt_id DESC LIMIT 1""",
            (row["stream_identity"],)).fetchone()
    included_windows = sorted(
        (item for item in sources if item["disposition"] == "included"),
        key=lambda item: (item["query_start"], item["query_end"], item["run_id"]),
    )
    retained_window_gaps = []
    latest_end = None
    for item in included_windows:
        start = datetime.fromisoformat(item["query_start"].replace("Z", "+00:00"))
        end = datetime.fromisoformat(item["query_end"].replace("Z", "+00:00"))
        if latest_end is not None and start > latest_end:
            retained_window_gaps.append({
                "gap_start": latest_end.isoformat(), "gap_end": start.isoformat(),
                "gap_seconds": int((start - latest_end).total_seconds()),
            })
        latest_end = end if latest_end is None or end > latest_end else latest_end
    return {
        **_generation_dict(row),
        "paths": [_path_dict(item) for item in paths],
        "sources": [dict(item) | {"raw_url": f"/api/arkime/imports/{item['import_id']}/raw" if item["import_id"] else None} for item in sources],
        "record_exclusions_url": f"/api/arkime/history/{result_id}/record-exclusions",
        "latest_build_attempt": dict(attempt) if attempt else None,
        "path_filter": normalized_filter,
        "unfiltered_path_total": unfiltered_total,
        "retained_window_gaps": retained_window_gaps,
        "pagination": {"limit": limit, "offset": offset, "total": total,
                       "has_more": offset + len(paths) < total},
        "boundary_note": "Complete means the complete API result was retained. Capture declarations stay separate and may be Complete, Partial, or Unknown. This does not prove continuous capture, absence, live state, an open service, or whole-network visibility.",
        "deduplication_note": "The same Arkime dataset, source node and session ID is counted once only when every retained field agrees. Different IDs remain separate.",
        "read_only": True,
    }


def get_arkime_history_record_exclusions(
    db_path: Path, result_id: str, *, limit: int = 50, offset: int = 0,
) -> dict:
    limit = _page(limit, "limit", minimum=1, maximum=MAX_PAGE)
    offset = _page(offset, "offset", minimum=0)
    with connect_database(db_path, read_only=True) as db:
        db.row_factory = sqlite3.Row
        exists = db.execute(
            "SELECT 1 FROM arkime_history_generations WHERE result_id=?", (result_id,),
        ).fetchone()
        if exists is None:
            raise KeyError("Arkime communication history not found")
        total = db.execute(
            "SELECT COUNT(*) FROM arkime_history_record_exclusions WHERE result_id=?",
            (result_id,),
        ).fetchone()[0]
        rows = db.execute("""SELECT * FROM arkime_history_record_exclusions
            WHERE result_id=? ORDER BY import_id,source_ordinal,receipt_id
            LIMIT ? OFFSET ?""", (result_id, limit, offset)).fetchall()
    return {
        "items": [dict(row) for row in rows],
        "pagination": {"limit": limit, "offset": offset, "total": total,
                       "has_more": offset + len(rows) < total},
        "read_only": True,
    }


def _path_dict(row: sqlite3.Row) -> dict:
    return {
        "path_key": row["path_key"], "source_ip": row["source_ip"],
        "destination_ip": row["destination_ip"], "destination_port": row["destination_port"],
        "transport": row["transport"], "first_packet": row["first_packet"],
        "last_packet": row["last_packet"], "applications": json.loads(row["applications_json"]),
        "retained_record_count": int(row["retained_record_count"]),
        "known_packet_total": row["known_packet_total_text"],
        "packet_records_unknown": int(row["packet_records_unknown"]),
        "known_byte_total": row["known_byte_total_text"],
        "byte_records_unknown": int(row["byte_records_unknown"]),
        "source_window_count": int(row["source_window_count"]),
    }


def get_arkime_history_path_evidence(
    db_path: Path, result_id: str, path_key: str, *, limit: int = 50, offset: int = 0,
) -> dict:
    limit = _page(limit, "limit", minimum=1, maximum=MAX_PAGE)
    offset = _page(offset, "offset", minimum=0)
    with connect_database(db_path, read_only=True) as db:
        db.row_factory = sqlite3.Row
        exists = db.execute("SELECT 1 FROM arkime_history_paths WHERE result_id=? AND path_key=?", (result_id, path_key)).fetchone()
        if exists is None:
            raise KeyError("Arkime communication path not found")
        total = db.execute("""SELECT COUNT(*) FROM arkime_history_memberships m
            JOIN arkime_history_path_records p ON p.result_id=m.result_id AND p.record_key=m.record_key
            WHERE m.result_id=? AND p.path_key=?""", (result_id, path_key)).fetchone()[0]
        rows = db.execute("""SELECT m.*, r.source_node,r.session_id,r.first_packet,r.last_packet
            FROM arkime_history_memberships m
            JOIN arkime_history_path_records p ON p.result_id=m.result_id AND p.record_key=m.record_key
            JOIN arkime_history_records r ON r.result_id=m.result_id AND r.record_key=m.record_key
            WHERE m.result_id=? AND p.path_key=?
            ORDER BY m.query_start,m.import_id,m.source_ordinal LIMIT ? OFFSET ?""",
            (result_id, path_key, limit, offset)).fetchall()
    return {
        "items": [dict(row) | {"raw_url": f"/api/arkime/imports/{row['import_id']}/raw"} for row in rows],
        "pagination": {"limit": limit, "offset": offset, "total": total,
                       "has_more": offset + len(rows) < total}, "read_only": True,
    }
