"""Immutable scoped interface/address receipts from verified device evidence."""
from __future__ import annotations

import hashlib
import ipaddress
import json
from pathlib import Path
import re
import sqlite3
import uuid

from app.database import connect_database, initialize_once_per_database
from app.device_collection_authority import (
    COLLECTED_DEVICE_SELECTION_CONTRACT,
    MANUAL_UPLOAD_SELECTION_CONTRACT,
    init_device_collection_authority_storage,
)
from app.device_limits import MAX_RETAINED_COLLECTION_BYTES
from app.derived_results import init_derived_result_storage
from app.network_scopes import init_network_scope_storage, utc_now


DEVICE_INTERFACE_EXTRACTOR = "device-interface-addresses:1"
DEVICE_INTERFACE_JOB_TYPE = "device_interface_observations"
DEVICE_INTERFACE_TARGET_FAMILY = "scoped_device_interface_observations"
DEVICE_INTERFACE_SCHEMA_VERSION = 1


class DeviceObservationConflict(ValueError):
    pass


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _digest(*parts: object) -> str:
    return hashlib.sha256(_canonical_json(list(parts)).encode()).hexdigest()


def _text(value: object, field: str, maximum: int = 500) -> str:
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise ValueError(f"{field} must be nonblank trimmed text")
    if len(value) > maximum:
        raise ValueError(f"{field} exceeds {maximum} characters")
    return value


@initialize_once_per_database
def init_device_observation_storage(db_path: Path) -> None:
    init_network_scope_storage(db_path)
    init_device_collection_authority_storage(db_path)
    init_derived_result_storage(db_path)
    with connect_database(db_path) as db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS device_scope_assignments (
                assignment_id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL,
                authority_revision INTEGER NOT NULL CHECK(authority_revision >= 1),
                scope_id TEXT NOT NULL REFERENCES network_scopes(scope_id),
                revision INTEGER NOT NULL CHECK(revision >= 1),
                event_kind TEXT NOT NULL CHECK(event_kind IN ('assigned', 'corrected')),
                supersedes_assignment_id TEXT UNIQUE
                    REFERENCES device_scope_assignments(assignment_id),
                actor TEXT NOT NULL CHECK(length(actor) BETWEEN 1 AND 100 AND actor = trim(actor)),
                reason TEXT NOT NULL CHECK(length(reason) BETWEEN 1 AND 500 AND reason = trim(reason)),
                assigned_at TEXT NOT NULL,
                UNIQUE(run_id, authority_revision, revision)
            );
            CREATE UNIQUE INDEX IF NOT EXISTS device_scope_assignment_root
                ON device_scope_assignments(run_id, authority_revision)
                WHERE supersedes_assignment_id IS NULL;
            CREATE INDEX IF NOT EXISTS device_scope_assignment_run
                ON device_scope_assignments(run_id, authority_revision, revision);
            CREATE TABLE IF NOT EXISTS device_interface_assessments (
                assessment_id TEXT PRIMARY KEY,
                assignment_id TEXT NOT NULL UNIQUE
                    REFERENCES device_scope_assignments(assignment_id),
                run_id TEXT NOT NULL,
                authority_revision INTEGER NOT NULL,
                scope_id TEXT NOT NULL REFERENCES network_scopes(scope_id),
                configuration_observation_id TEXT NOT NULL
                    REFERENCES artifact_observations(observation_id),
                configuration_sha256 TEXT NOT NULL,
                configuration_size_bytes INTEGER NOT NULL CHECK(configuration_size_bytes >= 0),
                configuration_filename TEXT NOT NULL,
                summary_result_id TEXT NOT NULL REFERENCES derived_results(result_id),
                extractor_version TEXT NOT NULL,
                coverage_json TEXT NOT NULL,
                recorded_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS device_interface_receipts (
                receipt_id TEXT PRIMARY KEY,
                assessment_id TEXT NOT NULL REFERENCES device_interface_assessments(assessment_id),
                interface_name TEXT NOT NULL,
                address TEXT NOT NULL,
                prefix_length INTEGER NOT NULL,
                address_family TEXT NOT NULL CHECK(address_family IN ('ipv4', 'ipv6')),
                routing_context TEXT,
                routing_context_status TEXT NOT NULL CHECK(
                    routing_context_status IN ('known', 'default', 'unresolved')
                ),
                source_line_number INTEGER NOT NULL CHECK(source_line_number >= 1),
                source_line TEXT NOT NULL,
                source_syntax TEXT NOT NULL,
                facts_json TEXT NOT NULL,
                UNIQUE(assessment_id, source_line_number, interface_name, address, prefix_length)
            );
            CREATE INDEX IF NOT EXISTS device_interface_receipts_assessment
                ON device_interface_receipts(assessment_id, source_line_number, receipt_id);
            CREATE TRIGGER IF NOT EXISTS device_scope_assignments_no_update
                BEFORE UPDATE ON device_scope_assignments
                BEGIN SELECT RAISE(ABORT, 'device scope assignments are immutable'); END;
            CREATE TRIGGER IF NOT EXISTS device_scope_assignments_no_delete
                BEFORE DELETE ON device_scope_assignments
                BEGIN SELECT RAISE(ABORT, 'device scope assignments are immutable'); END;
            CREATE TRIGGER IF NOT EXISTS device_scope_assignments_active_scope
                BEFORE INSERT ON device_scope_assignments
                WHEN NOT EXISTS (
                    SELECT 1 FROM network_scopes
                    WHERE scope_id = NEW.scope_id AND active = 1
                )
                BEGIN SELECT RAISE(ABORT, 'device assignment scope is missing or archived'); END;
            CREATE TRIGGER IF NOT EXISTS device_scope_assignments_valid_root
                BEFORE INSERT ON device_scope_assignments
                WHEN NEW.supersedes_assignment_id IS NULL
                  AND (NEW.revision != 1 OR NEW.event_kind != 'assigned')
                BEGIN SELECT RAISE(ABORT, 'invalid device assignment root'); END;
            CREATE TRIGGER IF NOT EXISTS device_scope_assignments_valid_successor
                BEFORE INSERT ON device_scope_assignments
                WHEN NEW.supersedes_assignment_id IS NOT NULL AND (
                    NEW.event_kind != 'corrected'
                    OR NOT EXISTS (
                        SELECT 1 FROM device_scope_assignments previous
                        WHERE previous.assignment_id = NEW.supersedes_assignment_id
                          AND previous.run_id = NEW.run_id
                          AND previous.authority_revision = NEW.authority_revision
                          AND previous.revision + 1 = NEW.revision
                          AND previous.scope_id != NEW.scope_id
                    )
                    OR EXISTS (
                        SELECT 1 FROM device_scope_assignments successor
                        WHERE successor.supersedes_assignment_id = NEW.supersedes_assignment_id
                    )
                )
                BEGIN SELECT RAISE(ABORT, 'invalid device assignment successor'); END;
            CREATE TRIGGER IF NOT EXISTS device_interface_assessments_no_update
                BEFORE UPDATE ON device_interface_assessments
                BEGIN SELECT RAISE(ABORT, 'device interface assessments are immutable'); END;
            CREATE TRIGGER IF NOT EXISTS device_interface_assessments_no_delete
                BEFORE DELETE ON device_interface_assessments
                BEGIN SELECT RAISE(ABORT, 'device interface assessments are immutable'); END;
            CREATE TRIGGER IF NOT EXISTS device_interface_receipts_no_update
                BEFORE UPDATE ON device_interface_receipts
                BEGIN SELECT RAISE(ABORT, 'device interface receipts are immutable'); END;
            CREATE TRIGGER IF NOT EXISTS device_interface_receipts_no_delete
                BEFORE DELETE ON device_interface_receipts
                BEGIN SELECT RAISE(ABORT, 'device interface receipts are immutable'); END;
        """)


def _authority_contract(db: sqlite3.Connection, run_id: str) -> tuple[str, dict]:
    from app.pipeline_intake import (
        COLLECTED_DEVICE_INTENT,
        MANUAL_DEVICE_INTENT,
        _device_authority_contract,
    )

    row = db.execute(
        "SELECT selection_contract FROM device_collection_authority WHERE run_id = ?",
        (run_id,),
    ).fetchone()
    if row is None:
        raise KeyError("Device collection authority was not found")
    intent_kind = {
        MANUAL_UPLOAD_SELECTION_CONTRACT: MANUAL_DEVICE_INTENT,
        COLLECTED_DEVICE_SELECTION_CONTRACT: COLLECTED_DEVICE_INTENT,
    }.get(row[0])
    if intent_kind is None:
        raise ValueError("Device collection uses an unsupported authority contract")
    contract, _context = _device_authority_contract(db, run_id, intent_kind=intent_kind)
    return intent_kind, contract


def _assignment_row(row: sqlite3.Row | None) -> dict | None:
    if row is None:
        return None
    return {
        "assignment_id": row["assignment_id"],
        "run_id": row["run_id"],
        "authority_revision": int(row["authority_revision"]),
        "scope_id": row["scope_id"],
        "revision": int(row["revision"]),
        "event_kind": row["event_kind"],
        "supersedes_assignment_id": row["supersedes_assignment_id"],
        "actor": row["actor"],
        "reason": row["reason"],
        "assigned_at": row["assigned_at"],
    }


def _current_assignment(db: sqlite3.Connection, run_id: str) -> sqlite3.Row | None:
    db.row_factory = sqlite3.Row
    return db.execute(
        """SELECT assignment.* FROM device_scope_assignments assignment
           WHERE assignment.run_id = ?
             AND NOT EXISTS (
                 SELECT 1 FROM device_scope_assignments successor
                 WHERE successor.supersedes_assignment_id = assignment.assignment_id
             )
           ORDER BY assignment.authority_revision DESC, assignment.revision DESC
           LIMIT 1""",
        (run_id,),
    ).fetchone()


def _completed_summary_result(db: sqlite3.Connection, run_id: str) -> str:
    from app.pipeline_intake import DEVICE_SUMMARY_JOB_TYPE

    available = db.execute(
        """SELECT COUNT(*) FROM sqlite_master WHERE type = 'table'
           AND name IN ('pipeline_jobs', 'pipeline_job_attempts')"""
    ).fetchone()[0]
    if int(available) != 2:
        raise DeviceObservationConflict(
            "Reusable device analysis must complete before assigning a Network Scope"
        )
    row = db.execute(
        """SELECT attempt.output_id
           FROM pipeline_jobs job
           JOIN pipeline_job_attempts attempt ON attempt.job_id = job.job_id
           WHERE job.job_type = ? AND job.source_run_id = ?
             AND attempt.state = 'completed'
             AND attempt.output_kind = 'derived_result'
             AND attempt.output_id IS NOT NULL
           ORDER BY attempt.attempt_number DESC LIMIT 1""",
        (DEVICE_SUMMARY_JOB_TYPE, run_id),
    ).fetchone()
    if row is None:
        raise DeviceObservationConflict(
            "Reusable device analysis must complete before assigning a Network Scope"
        )
    return row[0]


def assignment_contract_on_connection(
    db: sqlite3.Connection, assignment_id: str,
) -> dict:
    db.row_factory = sqlite3.Row
    row = db.execute(
        "SELECT * FROM device_scope_assignments WHERE assignment_id = ?",
        (assignment_id,),
    ).fetchone()
    if row is None:
        raise KeyError("Device scope assignment was not found")
    current = _current_assignment(db, row["run_id"])
    if current is None or current["assignment_id"] != assignment_id:
        raise DeviceObservationConflict("Device scope assignment is no longer current")
    intent_kind, authority = _authority_contract(db, row["run_id"])
    if int(authority["authority_revision"]) != int(row["authority_revision"]):
        raise DeviceObservationConflict("Device collection authority changed")
    scope = db.execute(
        "SELECT label, active FROM network_scopes WHERE scope_id = ?", (row["scope_id"],)
    ).fetchone()
    if scope is None or not bool(scope[1]):
        raise DeviceObservationConflict("Assigned Network Scope is missing or archived")
    return {
        "assignment": _assignment_row(row),
        "scope_label": scope[0],
        "intent_kind": intent_kind,
        "authority": authority,
        "extractor_version": DEVICE_INTERFACE_EXTRACTOR,
        "target_family": DEVICE_INTERFACE_TARGET_FAMILY,
        "target_payload_schema_version": DEVICE_INTERFACE_SCHEMA_VERSION,
    }


def assign_device_scope(
    db_path: Path, *, run_id: str, scope_id: str, actor: str, reason: str,
    whole_collection_confirmed: bool,
) -> dict:
    run_id = _text(run_id, "run_id", 200)
    scope_id = _text(scope_id, "scope_id", 200)
    actor = _text(actor, "actor", 100)
    reason = _text(reason, "reason")
    if whole_collection_confirmed is not True:
        raise ValueError("Whole-collection Network Scope confirmation is required")
    init_device_observation_storage(db_path)
    from app.pipeline_intake import init_pipeline_intake_storage, record_device_observation_intent

    init_pipeline_intake_storage(db_path)
    with connect_database(db_path) as db:
        db.execute("BEGIN IMMEDIATE")
        _intent_kind, authority = _authority_contract(db, run_id)
        _completed_summary_result(db, run_id)
        if _current_assignment(db, run_id) is not None:
            raise DeviceObservationConflict("Device collection is already assigned")
        scope = db.execute(
            "SELECT active FROM network_scopes WHERE scope_id = ?", (scope_id,)
        ).fetchone()
        if scope is None:
            raise ValueError("Network Scope does not exist")
        if not bool(scope[0]):
            raise ValueError("Network Scope is archived")
        assignment_id = f"device_assignment_{uuid.uuid4().hex}"
        db.execute(
            """INSERT INTO device_scope_assignments (
                   assignment_id, run_id, authority_revision, scope_id, revision,
                   event_kind, supersedes_assignment_id, actor, reason, assigned_at
               ) VALUES (?, ?, ?, ?, 1, 'assigned', NULL, ?, ?, ?)""",
            (assignment_id, run_id, int(authority["authority_revision"]), scope_id,
             actor, reason, utc_now()),
        )
        record_device_observation_intent(db, assignment_id)
        return assignment_contract_on_connection(db, assignment_id)["assignment"]


def correct_device_scope(
    db_path: Path, *, expected_assignment_id: str, destination_scope_id: str,
    actor: str, reason: str, whole_collection_confirmed: bool,
) -> dict:
    expected_assignment_id = _text(expected_assignment_id, "expected_assignment_id", 200)
    destination_scope_id = _text(destination_scope_id, "destination_scope_id", 200)
    actor = _text(actor, "actor", 100)
    reason = _text(reason, "reason")
    if whole_collection_confirmed is not True:
        raise ValueError("Whole-collection Network Scope confirmation is required")
    init_device_observation_storage(db_path)
    from app.pipeline_intake import init_pipeline_intake_storage, record_device_observation_intent

    init_pipeline_intake_storage(db_path)
    with connect_database(db_path) as db:
        db.execute("BEGIN IMMEDIATE")
        db.row_factory = sqlite3.Row
        previous = db.execute(
            "SELECT * FROM device_scope_assignments WHERE assignment_id = ?",
            (expected_assignment_id,),
        ).fetchone()
        if previous is None:
            raise DeviceObservationConflict("Expected device scope assignment does not exist")
        current = _current_assignment(db, previous["run_id"])
        if current is None or current["assignment_id"] != expected_assignment_id:
            raise DeviceObservationConflict("Device scope assignment changed in another session")
        if previous["scope_id"] == destination_scope_id:
            raise ValueError("Correction must select a different Network Scope")
        _intent_kind, authority = _authority_contract(db, previous["run_id"])
        _completed_summary_result(db, previous["run_id"])
        if int(authority["authority_revision"]) != int(previous["authority_revision"]):
            raise DeviceObservationConflict("Device collection authority changed")
        scope = db.execute(
            "SELECT active FROM network_scopes WHERE scope_id = ?", (destination_scope_id,)
        ).fetchone()
        if scope is None or not bool(scope[0]):
            raise ValueError("Destination Network Scope is missing or archived")
        assignment_id = f"device_assignment_{uuid.uuid4().hex}"
        try:
            db.execute(
                """INSERT INTO device_scope_assignments (
                       assignment_id, run_id, authority_revision, scope_id, revision,
                       event_kind, supersedes_assignment_id, actor, reason, assigned_at
                   ) VALUES (?, ?, ?, ?, ?, 'corrected', ?, ?, ?, ?)""",
                (assignment_id, previous["run_id"], int(previous["authority_revision"]),
                 destination_scope_id, int(previous["revision"]) + 1,
                 expected_assignment_id, actor, reason, utc_now()),
            )
        except sqlite3.IntegrityError as exc:
            raise DeviceObservationConflict(
                "Device scope assignment changed in another session"
            ) from exc
        record_device_observation_intent(db, assignment_id)
        return assignment_contract_on_connection(db, assignment_id)["assignment"]


def _safe_bytes(path: Path, *, root: Path, label: str, maximum: int) -> bytes:
    root = root.resolve()
    candidate = path.resolve(strict=False)
    if root.is_symlink() or path.is_symlink() or candidate.parent != root:
        raise ValueError(f"{label} has an unsafe path")
    if not path.is_file():
        raise ValueError(f"{label} is unavailable")
    before = path.stat()
    if before.st_size > maximum:
        raise ValueError(f"{label} exceeds the supported extraction limit")
    content = path.read_bytes()
    after = path.stat()
    if (before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
        after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns
    ):
        raise ValueError(f"{label} changed during verification")
    return content


def _configuration_input(contract: dict) -> dict:
    items = [
        item for item in contract["authority_inputs"]
        if item["role"] in {"configuration", "configuration_and_raw_output"}
           and item["source_kind"] == "artifact_file"
    ]
    if len(items) != 1:
        raise ValueError("Device authority does not select one configuration artifact")
    return items[0]


def capture_device_interface_source(
    db_path: Path, run_id: str, data_dir: Path,
) -> dict:
    from app.pipeline_intake import MANUAL_DEVICE_INTENT

    init_device_observation_storage(db_path)
    with connect_database(db_path, read_only=True) as db:
        intent_kind, contract = _authority_contract(db, run_id)
        selected = _configuration_input(contract)
        row = db.execute(
            """SELECT observation.sha256, observation.source_kind,
                      observation.source_ref, artifact.size_bytes,
                      artifact.canonical_path
               FROM artifact_observations observation
               JOIN artifact_registry artifact ON artifact.sha256 = observation.sha256
               WHERE observation.observation_id = ?""",
            (selected["observation_id"],),
        ).fetchone()
    expected_kind = (
        "device_config_upload"
        if intent_kind == MANUAL_DEVICE_INTENT else "device_collection"
    )
    if row is None or tuple(row[:4]) != (
        selected["sha256"], expected_kind, run_id, int(selected["size_bytes"]),
    ):
        raise ValueError("Selected configuration observation no longer matches authority")
    run_root = Path(data_dir).resolve() / "device-configs" / run_id
    if run_root.parent.parent != Path(data_dir).resolve() or run_root.is_symlink():
        raise ValueError("Device collection path is unsafe")
    local_path = run_root / selected["filename"]
    local = _safe_bytes(
        local_path, root=run_root, label="Run-local device configuration",
        maximum=MAX_RETAINED_COLLECTION_BYTES,
    )
    canonical_path = Path(row[4])
    canonical = _safe_bytes(
        canonical_path, root=canonical_path.parent,
        label="Canonical device configuration", maximum=MAX_RETAINED_COLLECTION_BYTES,
    )
    if (
        len(local) != int(row[3]) or local != canonical
        or hashlib.sha256(local).hexdigest() != row[0]
    ):
        raise ValueError("Selected device configuration failed exact-content verification")
    return {
        "run_id": run_id,
        "intent_kind": intent_kind,
        "authority": contract,
        "observation_id": selected["observation_id"],
        "sha256": selected["sha256"],
        "size_bytes": int(selected["size_bytes"]),
        "filename": selected["filename"],
        "content": local,
    }


_IP_TOKEN = re.compile(r"(?<![0-9A-Fa-f:.])(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9A-Fa-f]*:[0-9A-Fa-f:]+)(?:/\d{1,3})?")


def _network_address(address: str, mask: str | None = None) -> tuple[str, int, str]:
    value = address.strip("'\"")
    if mask:
        value = f"{value}/{mask.strip("'\"")}"
    interface = ipaddress.ip_interface(value)
    return str(interface.ip), int(interface.network.prefixlen), (
        "ipv4" if interface.version == 4 else "ipv6"
    )


def _unquote_token(value: str) -> str:
    return value.strip("'\"")


def extract_device_interface_addresses(text: str) -> dict:
    """Extract explicit supported interface-address statements without inferring absence."""
    lines = text.splitlines()
    receipts: list[dict] = []
    recognized_lines: set[int] = set()
    context_by_interface: dict[str, list[tuple[str, int, str]]] = {}
    context_issues: list[dict] = []

    def remember_context(interface_name: str, context: str, line_number: int, raw: str) -> None:
        interface_name = _unquote_token(interface_name)
        context_by_interface.setdefault(interface_name, []).append(
            (_unquote_token(context), line_number, raw)
        )
        recognized_lines.add(line_number)

    def resolved_context(interface_name: str) -> tuple[str | None, str]:
        candidates = context_by_interface.get(interface_name, [])
        values = {item[0] for item in candidates}
        if len(values) == 1:
            return next(iter(values)), "known"
        if len(values) > 1:
            context_issues.extend(
                {"line_number": item[1], "source_line": item[2]} for item in candidates
            )
            return None, "unresolved"
        return None, "default"

    for line_number, raw in enumerate(lines, 1):
        stripped = raw.strip()
        match = re.match(r"set routing-instances (\S+) interface (\S+)$", stripped)
        if match:
            remember_context(match.group(2), match.group(1), line_number, raw)
        match = re.match(r"set vrf name (\S+) interface (\S+)$", stripped)
        if match:
            remember_context(match.group(2), match.group(1), line_number, raw)
        match = re.match(
            r"set interfaces \S+ (\S+) vrf ['\"]?([^'\"\s]+)['\"]?\s*$",
            stripped,
        )
        if match:
            remember_context(match.group(1), match.group(2), line_number, raw)

    def add(*, line_number: int, raw: str, interface_name: str, address: str,
            mask: str | None, syntax: str, context: str | None,
            context_status: str, attributes: dict | None = None) -> None:
        if mask is None and "/" not in address.strip("'\""):
            return
        try:
            normalized, prefix, family = _network_address(address, mask)
        except ValueError:
            return
        receipts.append({
            "interface_name": interface_name,
            "address": normalized,
            "prefix_length": prefix,
            "address_family": family,
            "routing_context": context,
            "routing_context_status": context_status,
            "source_line_number": line_number,
            "source_line": raw,
            "source_syntax": syntax,
            "facts": attributes or {},
        })
        recognized_lines.add(line_number)

    # Cisco-style interface blocks. Routing context may appear after an address, so
    # determine it for the whole block before recording address lines.
    index = 0
    while index < len(lines):
        header = re.match(r"^interface\s+(\S+)\s*$", lines[index].strip())
        if not header:
            index += 1
            continue
        name = header.group(1)
        end = index + 1
        while end < len(lines):
            candidate = lines[end]
            if re.match(r"^interface\s+\S+\s*$", candidate.strip()):
                break
            if candidate.strip() not in {"", "!"} and candidate == candidate.lstrip():
                break
            end += 1
        block = lines[index + 1:end]
        contexts: list[tuple[str, int, str]] = []
        unresolved_context = False
        for block_line_number, raw in enumerate(block, index + 2):
            match = re.match(r"^(?:ip\s+)?vrf\s+forwarding\s+(\S+)$", raw.strip())
            if match:
                contexts.append((match.group(1), block_line_number, raw))
                recognized_lines.add(block_line_number)
            elif "vrf" in raw.lower() or "routing-instance" in raw.lower():
                unresolved_context = True
        context_values = {item[0] for item in contexts}
        context = next(iter(context_values)) if len(context_values) == 1 else None
        if len(context_values) > 1:
            unresolved_context = True
            context_issues.extend(
                {"line_number": item[1], "source_line": item[2]} for item in contexts
            )
        for offset, raw in enumerate(block, index + 2):
            stripped = raw.strip()
            match = re.match(
                r"^ip address (\d{1,3}(?:\.\d{1,3}){3})(?:\s+(\d{1,3}(?:\.\d{1,3}){3})|/(\d{1,2}))(?:\s+(secondary))?\s*$",
                stripped,
            )
            if match:
                add(line_number=offset, raw=raw, interface_name=name,
                    address=(f"{match.group(1)}/{match.group(3)}" if match.group(3) else match.group(1)),
                    mask=match.group(2), syntax="cisco_interface",
                    context=context, context_status=(
                        "known" if context else "unresolved" if unresolved_context else "default"
                    ),
                    attributes={"secondary": bool(match.group(4))})
                continue
            match = re.match(r"^ipv6 address (\S+/\d{1,3})\s*$", stripped)
            if match:
                add(line_number=offset, raw=raw, interface_name=name,
                    address=match.group(1), mask=None, syntax="cisco_interface",
                    context=context, context_status=(
                        "known" if context else "unresolved" if unresolved_context else "default"
                    ))
        index = end

    for line_number, raw in enumerate(lines, 1):
        stripped = raw.strip()
        match = re.match(
            r"^set interfaces (\S+) unit (\S+) family (inet6?|inet) address (\S+)(?:\s+.*)?$",
            stripped,
        )
        if match:
            name = f"{_unquote_token(match.group(1))}.{_unquote_token(match.group(2))}"
            context, context_status = resolved_context(name)
            add(line_number=line_number, raw=raw, interface_name=name,
                address=match.group(4), mask=None, syntax="juniper_set",
                context=context, context_status=context_status)
            continue
        match = re.match(
            r"^set interfaces \S+ (\S+) address ['\"]?([^'\"\s]+)['\"]?\s*$",
            stripped,
        )
        if match:
            name = _unquote_token(match.group(1))
            context, context_status = resolved_context(name)
            add(line_number=line_number, raw=raw, interface_name=name,
                address=match.group(2), mask=None, syntax="vyos_set",
                context=context, context_status=context_status)

    unsupported = []
    unsupported_context = list(context_issues)
    for line_number, raw in enumerate(lines, 1):
        if line_number in recognized_lines:
            continue
        stripped = raw.strip()
        if "address" in raw.lower() and _IP_TOKEN.search(raw):
            unsupported.append({"line_number": line_number, "source_line": raw})
        # Combined SSH output can contain informational text such as Cisco's
        # "Bindings from all pools not associated with VRF:".  Treat only lines
        # shaped like configuration syntax as unresolved routing-context evidence.
        routing_context_syntax = re.match(
            r"^(?:(?:ip\s+)?vrf\b|routing-instances?\b|routing-instance\b|"
            r"set\s+(?:routing-instances?\b|vrf\b|interfaces\b.*\bvrf\b))",
            stripped,
            flags=re.IGNORECASE,
        )
        if line_number not in recognized_lines and routing_context_syntax:
            unsupported_context.append({"line_number": line_number, "source_line": raw})
    unsupported_context = list({
        (item["line_number"], item["source_line"]): item
        for item in unsupported_context
    }.values())
    unsupported_context.sort(key=lambda item: item["line_number"])
    receipts.sort(key=lambda item: (
        item["source_line_number"], item["interface_name"], item["address"],
        item["prefix_length"],
    ))
    return {
        "receipts": receipts,
        "coverage": {
            "contract": DEVICE_INTERFACE_EXTRACTOR,
            "source_line_count": len(lines),
            "reported_address_count": len(receipts),
            "unsupported_address_line_count": len(unsupported),
            "unsupported_address_line_samples": unsupported[:50],
            "sample_truncated": len(unsupported) > 50,
            "unsupported_context_line_count": len(unsupported_context),
            "unsupported_context_line_samples": unsupported_context[:50],
            "context_sample_truncated": len(unsupported_context) > 50,
            "absence_supported": False,
            "source_time_known": False,
            "source_time_detail": (
                "Configuration evidence does not establish when a reported address became active."
            ),
        },
    }


def publish_device_interface_assessment(
    db_path: Path, *, assignment_id: str, summary_result_id: str,
    snapshot: dict, extracted: dict,
    transaction_guard=None, transaction_finalize=None,
) -> dict:
    init_device_observation_storage(db_path)
    context_keys = set()
    for item in extracted["receipts"]:
        status = item["routing_context_status"]
        if status == "unresolved":
            raise DeviceObservationConflict(
                "The configuration has unresolved routing context; keep it unassigned"
            )
        context_keys.add((status, item["routing_context"] if status == "known" else None))
    if len(context_keys) > 1:
        raise DeviceObservationConflict(
            "The configuration reports more than one routing context; whole-collection "
            "scope assignment is not safe"
        )
    if int(extracted["coverage"].get("unsupported_context_line_count", 0)) > 0:
        raise DeviceObservationConflict(
            "The configuration contains routing context syntax that is unresolved; "
            "keep it unassigned"
        )
    with connect_database(db_path) as db:
        db.execute("BEGIN IMMEDIATE")
        contract = assignment_contract_on_connection(db, assignment_id)
        assignment = contract["assignment"]
        if contract["authority"] != snapshot["authority"]:
            raise DeviceObservationConflict("Device evidence authority changed while processing")
        if (
            snapshot["observation_id"] != _configuration_input(contract["authority"])["observation_id"]
            or snapshot["sha256"] != _configuration_input(contract["authority"])["sha256"]
        ):
            raise DeviceObservationConflict("Selected configuration changed while processing")
        linked = db.execute(
            """SELECT result.family, result.analysis_version, link.observation_id
               FROM derived_results result
               JOIN derived_result_observation_links link ON link.result_id = result.result_id
               WHERE result.result_id = ? AND link.input_role = 'configuration'""",
            (summary_result_id,),
        ).fetchall()
        if not linked or snapshot["observation_id"] not in {row[2] for row in linked}:
            raise DeviceObservationConflict(
                "Completed reusable summary is not linked to this configuration"
            )
        if transaction_guard is not None:
            transaction_guard(db)
        coverage_json = _canonical_json(extracted["coverage"])
        assessment_id = "device_assessment_" + _digest(
            assignment_id, summary_result_id, DEVICE_INTERFACE_EXTRACTOR,
            snapshot["observation_id"], snapshot["sha256"],
        )
        prepared_receipts = []
        for item in extracted["receipts"]:
            receipt_id = "device_receipt_" + _digest(
                assessment_id, item["source_line_number"], item["interface_name"],
                item["address"], item["prefix_length"], item["source_line"],
            )
            prepared_receipts.append((
                receipt_id, assessment_id, item["interface_name"], item["address"],
                item["prefix_length"], item["address_family"],
                item["routing_context"], item["routing_context_status"],
                item["source_line_number"], item["source_line"],
                item["source_syntax"], _canonical_json(item["facts"]),
            ))
        prepared_receipts.sort(key=lambda row: (row[8], row[0]))
        prior = db.execute(
            """SELECT run_id, authority_revision, scope_id,
                      configuration_observation_id, configuration_sha256,
                      configuration_size_bytes, configuration_filename,
                      summary_result_id, extractor_version, coverage_json
               FROM device_interface_assessments WHERE assessment_id = ?""",
            (assessment_id,),
        ).fetchone()
        expected = (
            snapshot["run_id"], assignment["authority_revision"], assignment["scope_id"],
            snapshot["observation_id"], snapshot["sha256"], snapshot["size_bytes"],
            snapshot["filename"], summary_result_id, DEVICE_INTERFACE_EXTRACTOR,
            coverage_json,
        )
        created = prior is None
        if prior is not None and tuple(prior) != expected:
            raise DeviceObservationConflict("Device interface assessment replay changed")
        if prior is not None:
            retained_receipts = db.execute(
                """SELECT receipt_id, assessment_id, interface_name, address,
                          prefix_length, address_family, routing_context,
                          routing_context_status, source_line_number, source_line,
                          source_syntax, facts_json
                   FROM device_interface_receipts WHERE assessment_id = ?
                   ORDER BY source_line_number, receipt_id""",
                (assessment_id,),
            ).fetchall()
            if [tuple(row) for row in retained_receipts] != prepared_receipts:
                raise DeviceObservationConflict(
                    "Device interface assessment receipt replay changed"
                )
        if created:
            db.execute(
                """INSERT INTO device_interface_assessments (
                       assessment_id, assignment_id, run_id, authority_revision, scope_id,
                       configuration_observation_id, configuration_sha256,
                       configuration_size_bytes, configuration_filename,
                       summary_result_id, extractor_version, coverage_json, recorded_at
                   ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (assessment_id, assignment_id, *expected, utc_now()),
            )
            for receipt in prepared_receipts:
                db.execute(
                    """INSERT INTO device_interface_receipts (
                           receipt_id, assessment_id, interface_name, address,
                           prefix_length, address_family, routing_context,
                           routing_context_status, source_line_number, source_line,
                           source_syntax, facts_json
                       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    receipt,
                )
        if transaction_finalize is not None:
            transaction_finalize(db, created, assessment_id)
    return {
        "assessment_id": assessment_id,
        "created": created,
        "receipt_count": len(extracted["receipts"]),
        "coverage": extracted["coverage"],
    }


def get_device_observation_status(db_path: Path, run_id: str) -> dict:
    if not Path(db_path).is_file():
        return {"state": "unassigned", "assignment": None, "assessment": None}
    with connect_database(db_path, read_only=True) as db:
        available = db.execute(
            """SELECT COUNT(*) FROM sqlite_master WHERE type = 'table'
               AND name IN ('device_scope_assignments', 'device_interface_assessments',
                            'pipeline_jobs', 'pipeline_job_attempts')"""
        ).fetchone()[0]
        if int(available) != 4:
            return {"state": "needs_scope", "assignment": None, "assessment": None}
        db.row_factory = sqlite3.Row
        assignment_row = _current_assignment(db, run_id)
        if assignment_row is None:
            return {"state": "needs_scope", "assignment": None, "assessment": None}
        assignment = _assignment_row(assignment_row)
        scope = db.execute(
            "SELECT label, active FROM network_scopes WHERE scope_id = ?",
            (assignment["scope_id"],),
        ).fetchone()
        assessment = db.execute(
            """SELECT assessment_id, recorded_at, coverage_json,
                      configuration_sha256, configuration_filename
               FROM device_interface_assessments WHERE assignment_id = ?""",
            (assignment["assignment_id"],),
        ).fetchone()
        job = db.execute(
            """SELECT attempt.state, attempt.error, job.job_id
               FROM pipeline_jobs job
               LEFT JOIN pipeline_job_attempts attempt ON attempt.job_id = job.job_id
               WHERE job.job_type = ? AND job.source_ref = ?
               ORDER BY attempt.attempt_number DESC LIMIT 1""",
            (DEVICE_INTERFACE_JOB_TYPE, assignment["assignment_id"]),
        ).fetchone()
        if assessment is not None:
            state = "completed"
        elif job is not None:
            state = job[0]
        else:
            state = "waiting"
        return {
            "state": state,
            "error": job[1] if job else None,
            "job_id": job[2] if job else None,
            "assignment": {
                **assignment,
                "scope_label": scope[0] if scope else "Unknown scope",
                "scope_active": bool(scope[1]) if scope else False,
            },
            "assessment": None if assessment is None else {
                "assessment_id": assessment[0], "recorded_at": assessment[1],
                "coverage": json.loads(assessment[2]),
                "configuration_sha256": assessment[3],
                "configuration_filename": assessment[4],
            },
        }


def collection_has_device_scope_assignment(db_path: Path, run_id: str) -> bool:
    if not Path(db_path).is_file():
        return False
    with connect_database(db_path, read_only=True) as db:
        table = db.execute(
            """SELECT 1 FROM sqlite_master
               WHERE type = 'table' AND name = 'device_scope_assignments'"""
        ).fetchone()
        if table is None:
            return False
        return db.execute(
            "SELECT 1 FROM device_scope_assignments WHERE run_id = ? LIMIT 1",
            (run_id,),
        ).fetchone() is not None


def get_device_interface_receipts(
    db_path: Path, run_id: str, *, limit: int = 100, offset: int = 0,
) -> dict:
    if not 1 <= limit <= 250 or offset < 0:
        raise ValueError("Invalid device receipt page")
    status = get_device_observation_status(db_path, run_id)
    assessment = status.get("assessment")
    if assessment is None:
        raise KeyError("Normalized device observations are not available")
    with connect_database(db_path, read_only=True) as db:
        db.row_factory = sqlite3.Row
        total = db.execute(
            "SELECT COUNT(*) FROM device_interface_receipts WHERE assessment_id = ?",
            (assessment["assessment_id"],),
        ).fetchone()[0]
        rows = db.execute(
            """SELECT * FROM device_interface_receipts
               WHERE assessment_id = ?
               ORDER BY source_line_number, receipt_id LIMIT ? OFFSET ?""",
            (assessment["assessment_id"], limit, offset),
        ).fetchall()
    return {
        "run_id": run_id,
        "meaning": "This retained configuration reported these interface addresses.",
        "claims": {
            "live_status": False, "physical_device_identity": False,
            "address_active_time": False, "absence_or_disappearance": False,
        },
        "assignment": status["assignment"],
        "assessment": assessment,
        "source": {
            "filename": assessment["configuration_filename"],
            "sha256": assessment["configuration_sha256"],
            "source_url": (
                f"/api/device-configs/{run_id}/files/"
                f"{assessment['configuration_filename']}"
            ),
        },
        "receipts": [{
            "receipt_id": row["receipt_id"],
            "interface_name": row["interface_name"],
            "address": row["address"],
            "prefix_length": int(row["prefix_length"]),
            "address_family": row["address_family"],
            "routing_context": row["routing_context"],
            "routing_context_status": row["routing_context_status"],
            "source_line_number": int(row["source_line_number"]),
            "source_line": row["source_line"],
            "source_syntax": row["source_syntax"],
            "facts": json.loads(row["facts_json"]),
        } for row in rows],
        "pagination": {
            "limit": limit, "offset": offset, "total": int(total),
            "has_more": offset + len(rows) < total,
        },
    }
