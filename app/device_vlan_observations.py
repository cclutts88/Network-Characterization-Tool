"""Immutable storage contract for scoped VLAN evidence.

This module owns only the versioned schema at the first migration gate. Extraction,
publication, and read APIs are added after the schema boundary independently clears.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import sqlite3
import time

from app.database import connect_database, initialize_once_per_database
from app.device_collection_authority import init_device_collection_authority_storage
from app.device_observations import init_device_observation_storage
from app.derived_results import init_derived_result_storage
from app.network_scopes import init_network_scope_storage


DEVICE_VLAN_EXTRACTOR = "device-vlan-observations:1"
DEVICE_VLAN_JOB_TYPE = "device_vlan_observations"
DEVICE_VLAN_TARGET_FAMILY = "scoped_device_vlan_observations"
DEVICE_VLAN_SCHEMA_VERSION = 1
DEVICE_VLAN_POLICY_VERSION = 1
MAX_VLAN_SOURCE_LINES = 250_000
MAX_VLAN_SOURCE_LINE_BYTES = 4_096
MAX_VLAN_RECEIPTS = 20_000
MAX_VLAN_JSON_BYTES = 1_048_576
MAX_VLAN_PROCESSING_SECONDS = 10.0
MAX_VLAN_API_PAGE = 100

DEVICE_VLAN_EVIDENCE_LABELS = {
    "configured": "Configured in retained source",
    "observed": "Reported in retained command output",
}
DEVICE_VLAN_CLAIMS = {
    "live_status": False,
    "absence_or_disappearance": False,
    "cross_device_vlan_identity": False,
    "physical_device_identity": False,
}
DEVICE_VLAN_STATUS_MEANING = (
    "This status describes processing of retained device evidence. It does not report "
    "live VLAN state or prove that a VLAN is absent."
)

DEVICE_VLAN_SCHEMA_OBJECTS = frozenset({
    "device_vlan_assessments",
    "device_vlan_assessments_scope",
    "device_vlan_assessments_version",
    "device_vlan_receipts",
    "device_vlan_receipts_assessment",
    "device_vlan_assessments_no_update",
    "device_vlan_assessments_no_delete",
    "device_vlan_receipts_no_update",
    "device_vlan_receipts_no_delete",
    "device_vlan_admission_intents",
    "device_vlan_admission_intents_state",
    "device_vlan_admission_intents_identity_immutable",
    "device_vlan_admission_intents_state_guard",
    "device_vlan_admission_intents_no_delete",
})


def create_device_vlan_schema(db: sqlite3.Connection) -> None:
    """Create the v6 VLAN schema on the caller's transaction."""
    statements = (
        """CREATE TABLE IF NOT EXISTS device_vlan_assessments (
            assessment_id TEXT PRIMARY KEY,
            assignment_id TEXT NOT NULL
                REFERENCES device_scope_assignments(assignment_id),
            run_id TEXT NOT NULL,
            authority_revision INTEGER NOT NULL CHECK(authority_revision >= 1),
            assignment_revision INTEGER NOT NULL CHECK(assignment_revision >= 1),
            scope_id TEXT NOT NULL REFERENCES network_scopes(scope_id),
            configuration_observation_id TEXT NOT NULL
                REFERENCES artifact_observations(observation_id),
            configuration_sha256 TEXT NOT NULL CHECK(length(configuration_sha256) = 64),
            configuration_size_bytes INTEGER NOT NULL CHECK(configuration_size_bytes >= 0),
            configuration_filename TEXT NOT NULL,
            summary_result_id TEXT NOT NULL REFERENCES derived_results(result_id),
            extractor_version TEXT NOT NULL,
            collection_contract TEXT NOT NULL,
            source_contract_json TEXT NOT NULL,
            coverage_json TEXT NOT NULL,
            recorded_at TEXT NOT NULL,
            UNIQUE(assignment_id, extractor_version, collection_contract)
        )""",
        """CREATE INDEX IF NOT EXISTS device_vlan_assessments_scope
            ON device_vlan_assessments(scope_id, recorded_at, assessment_id)""",
        """CREATE INDEX IF NOT EXISTS device_vlan_assessments_version
            ON device_vlan_assessments(
                assignment_id, extractor_version, collection_contract,
                recorded_at DESC, assessment_id DESC
            )""",
        """CREATE TABLE IF NOT EXISTS device_vlan_receipts (
            receipt_id TEXT PRIMARY KEY,
            assessment_id TEXT NOT NULL REFERENCES device_vlan_assessments(assessment_id),
            source_observation_id TEXT NOT NULL
                REFERENCES artifact_observations(observation_id),
            source_role TEXT NOT NULL CHECK(
                source_role IN ('configuration', 'raw_output', 'configuration_and_raw_output')
            ),
            source_filename TEXT NOT NULL,
            device_context TEXT NOT NULL,
            bridge_context TEXT,
            vlan_id INTEGER NOT NULL CHECK(vlan_id BETWEEN 0 AND 4095),
            vlan_name TEXT,
            interface_name TEXT,
            membership_relation TEXT NOT NULL CHECK(
                membership_relation IN (
                    'declaration', 'declared_member', 'access', 'native', 'allowed',
                    'tagged', 'untagged', 'pvid'
                )
            ),
            evidence_state TEXT NOT NULL CHECK(
                evidence_state IN ('configured', 'observed')
            ),
            source_line_number INTEGER NOT NULL CHECK(source_line_number >= 1),
            source_line TEXT NOT NULL,
            related_line_number INTEGER CHECK(related_line_number IS NULL OR related_line_number >= 1),
            related_source_line TEXT,
            source_command TEXT,
            source_section TEXT,
            source_syntax TEXT NOT NULL,
            facts_json TEXT NOT NULL,
            UNIQUE(
                assessment_id, source_observation_id, source_line_number,
                membership_relation, vlan_id, device_context,
                interface_name, bridge_context
            )
        )""",
        """CREATE INDEX IF NOT EXISTS device_vlan_receipts_assessment
            ON device_vlan_receipts(
                assessment_id, vlan_id, source_line_number, receipt_id
            )""",
        """CREATE TRIGGER IF NOT EXISTS device_vlan_assessments_no_update
            BEFORE UPDATE ON device_vlan_assessments
            BEGIN SELECT RAISE(ABORT, 'device VLAN assessments are immutable'); END""",
        """CREATE TRIGGER IF NOT EXISTS device_vlan_assessments_no_delete
            BEFORE DELETE ON device_vlan_assessments
            BEGIN SELECT RAISE(ABORT, 'device VLAN assessments are immutable'); END""",
        """CREATE TRIGGER IF NOT EXISTS device_vlan_receipts_no_update
            BEFORE UPDATE ON device_vlan_receipts
            BEGIN SELECT RAISE(ABORT, 'device VLAN receipts are immutable'); END""",
        """CREATE TRIGGER IF NOT EXISTS device_vlan_receipts_no_delete
            BEFORE DELETE ON device_vlan_receipts
            BEGIN SELECT RAISE(ABORT, 'device VLAN receipts are immutable'); END""",
        """CREATE TABLE IF NOT EXISTS device_vlan_admission_intents (
            intent_id TEXT PRIMARY KEY,
            assignment_id TEXT NOT NULL UNIQUE
                REFERENCES device_scope_assignments(assignment_id),
            policy_version INTEGER NOT NULL CHECK(policy_version >= 1),
            source_observation_id TEXT NOT NULL
                REFERENCES artifact_observations(observation_id),
            scope_id TEXT NOT NULL REFERENCES network_scopes(scope_id),
            actor TEXT NOT NULL,
            request_token TEXT NOT NULL UNIQUE,
            contract_json TEXT NOT NULL,
            state TEXT NOT NULL CHECK(state IN ('pending', 'admitted', 'blocked')),
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            admitted_job_id TEXT UNIQUE REFERENCES pipeline_jobs(job_id),
            activity_state TEXT NOT NULL CHECK(
                activity_state IN ('waiting', 'retrying', 'paused', 'complete', 'blocked')
            ),
            last_error TEXT,
            CHECK(
                (state = 'pending' AND admitted_job_id IS NULL
                    AND activity_state IN ('waiting', 'retrying', 'paused'))
                OR (state = 'admitted' AND admitted_job_id IS NOT NULL
                    AND activity_state = 'complete' AND last_error IS NULL)
                OR (state = 'blocked' AND admitted_job_id IS NULL
                    AND activity_state = 'blocked'
                    AND length(trim(last_error)) >= 1)
            )
        )""",
        """CREATE INDEX IF NOT EXISTS device_vlan_admission_intents_state
            ON device_vlan_admission_intents(state, created_at, intent_id)""",
        """CREATE TRIGGER IF NOT EXISTS device_vlan_admission_intents_identity_immutable
            BEFORE UPDATE ON device_vlan_admission_intents
            WHEN OLD.assignment_id != NEW.assignment_id
              OR OLD.policy_version != NEW.policy_version
              OR OLD.source_observation_id != NEW.source_observation_id
              OR OLD.scope_id != NEW.scope_id
              OR OLD.actor != NEW.actor
              OR OLD.request_token != NEW.request_token
              OR OLD.contract_json != NEW.contract_json
              OR OLD.created_at != NEW.created_at
              OR (OLD.admitted_job_id IS NOT NULL
                  AND IFNULL(NEW.admitted_job_id, '') != OLD.admitted_job_id)
            BEGIN SELECT RAISE(ABORT, 'device VLAN admission identity is immutable'); END""",
        """CREATE TRIGGER IF NOT EXISTS device_vlan_admission_intents_state_guard
            BEFORE UPDATE ON device_vlan_admission_intents
            WHEN OLD.state != NEW.state
             AND NOT (OLD.state = 'pending' AND NEW.state IN ('admitted', 'blocked'))
            BEGIN SELECT RAISE(ABORT, 'invalid device VLAN admission transition'); END""",
        """CREATE TRIGGER IF NOT EXISTS device_vlan_admission_intents_no_delete
            BEFORE DELETE ON device_vlan_admission_intents
            BEGIN SELECT RAISE(ABORT, 'device VLAN admission intents are retained'); END""",
    )
    for statement in statements:
        db.execute(statement)


@initialize_once_per_database
def init_device_vlan_observation_storage(db_path: Path) -> None:
    init_network_scope_storage(db_path)
    init_device_collection_authority_storage(db_path)
    init_device_observation_storage(db_path)
    init_derived_result_storage(db_path)
    from app.pipeline_intake import init_pipeline_intake_storage

    init_pipeline_intake_storage(db_path)
    with connect_database(db_path) as db:
        create_device_vlan_schema(db)


def current_device_vlan_assessment_on_connection(
    db: sqlite3.Connection, *, assignment_id: str, collection_contract: str,
) -> dict | None:
    """Return only the assessment produced by the image's supported extractor contract."""
    db.row_factory = sqlite3.Row
    row = db.execute(
        """SELECT * FROM device_vlan_assessments
           WHERE assignment_id = ? AND extractor_version = ?
             AND collection_contract = ?
           ORDER BY recorded_at DESC, assessment_id DESC LIMIT 1""",
        (assignment_id, DEVICE_VLAN_EXTRACTOR, collection_contract),
    ).fetchone()
    return dict(row) if row is not None else None


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _digest(*parts: object) -> str:
    return hashlib.sha256(_canonical_json(parts).encode()).hexdigest()


def _vlan_id(value: object) -> int | None:
    try:
        number = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    return number if 0 <= number <= 4095 else None


def _expand_vlan_spec(value: str) -> tuple[list[int], bool]:
    """Expand only explicit numeric IDs and ranges; never interpret symbolic shortcuts."""
    result: set[int] = set()
    for token in re.split(r"\s*,\s*|\s+", value.strip(" []")):
        if not token:
            continue
        if re.fullmatch(r"\d{1,4}", token):
            number = _vlan_id(token)
            if number is None:
                return [], False
            result.add(number)
            continue
        match = re.fullmatch(r"(\d{1,4})-(\d{1,4})", token)
        if not match:
            return [], False
        start, end = int(match.group(1)), int(match.group(2))
        if start > end or _vlan_id(start) is None or _vlan_id(end) is None:
            return [], False
        if end - start + 1 > 4096:
            return [], False
        result.update(range(start, end + 1))
    return sorted(result), True


def extract_device_vlan_observations(
    content: bytes, *, device_context: str,
) -> dict:
    """Extract explicit VLAN statements from already-retained bytes without inference."""
    started = time.monotonic()
    decoded = content.decode("utf-8", errors="replace")
    decoding_loss = "\ufffd" in decoded
    all_lines = decoded.splitlines()
    line_limit_reached = len(all_lines) > MAX_VLAN_SOURCE_LINES
    lines = all_lines[:MAX_VLAN_SOURCE_LINES]
    command_by_line: dict[int, str | None] = {}
    current_command: str | None = None
    command_sections: list[str] = []
    unavailable_commands: list[str] = []
    for line_number, raw in enumerate(lines, 1):
        marker = re.match(r"^=====\s*(.+?)\s*=====\s*$", raw.strip())
        if marker:
            current_command = marker.group(1).strip()[:300]
            command_sections.append(current_command)
            command_by_line[line_number] = current_command
            continue
        command_by_line[line_number] = current_command
        lower = raw.lower()
        if current_command and any(token in lower for token in (
            "[nct] command unavailable", "% invalid input", "unknown command",
            "command not found", "not supported", "invalid command",
        )) and current_command not in unavailable_commands:
            unavailable_commands.append(current_command)

    receipts: list[dict] = []
    unsupported: list[dict] = []
    unsupported_line_count = 0
    recognized_lines: set[int] = set()
    declaration_by_name: dict[str, tuple[int, str, int]] = {}
    receipt_limit_reached = False
    overlong_line_count = 0
    overlong_line_numbers: set[int] = set()

    def note_unsupported(line_number: int, reason: str, raw: str) -> None:
        nonlocal unsupported_line_count
        unsupported_line_count += 1
        recognized_lines.add(line_number)
        if len(unsupported) < 50:
            unsupported.append({
                "line_number": line_number,
                "reason": reason,
                "source_line": raw[:500],
            })

    def check_time(line_number: int) -> None:
        if line_number % 256 == 0 and time.monotonic() - started > MAX_VLAN_PROCESSING_SECONDS:
            raise ValueError("Device VLAN extraction exceeded its processing-time limit")

    def bounded_line(raw: str, line_number: int) -> str | None:
        nonlocal overlong_line_count
        if len(raw.encode("utf-8", errors="replace")) > MAX_VLAN_SOURCE_LINE_BYTES:
            if line_number not in overlong_line_numbers:
                overlong_line_numbers.add(line_number)
                overlong_line_count += 1
                note_unsupported(line_number, "source_line_too_long", raw)
            return None
        return raw

    def add(
        *, line_number: int, raw: str, vlan_id: int, relation: str,
        syntax: str, evidence_state: str, vlan_name: str | None = None,
        interface_name: str | None = None, bridge_context: str | None = None,
        related_line_number: int | None = None,
        related_source_line: str | None = None, facts: dict | None = None,
    ) -> None:
        nonlocal receipt_limit_reached
        if len(receipts) >= MAX_VLAN_RECEIPTS:
            receipt_limit_reached = True
            return
        receipts.append({
            "device_context": str(device_context)[:300],
            "bridge_context": str(bridge_context)[:200] if bridge_context else None,
            "vlan_id": vlan_id,
            "vlan_name": str(vlan_name)[:200] if vlan_name else None,
            "interface_name": str(interface_name)[:200] if interface_name else None,
            "membership_relation": relation,
            "evidence_state": evidence_state,
            "source_line_number": line_number,
            "source_line": raw,
            "related_line_number": related_line_number,
            "related_source_line": related_source_line,
            "source_command": command_by_line.get(line_number),
            "source_section": command_by_line.get(line_number),
            "source_syntax": syntax,
            "facts": facts or {},
        })
        recognized_lines.add(line_number)

    # Pass one records declarations so later membership lines can resolve an exact name.
    current_show_vlan: tuple[int, str, str] | None = None
    for index, raw in enumerate(lines):
        line_number = index + 1
        check_time(line_number)
        raw = bounded_line(raw, line_number)
        if raw is None:
            continue
        stripped = raw.strip()
        cisco = re.fullmatch(r"vlan\s+(\d{1,4})", stripped, re.I)
        if cisco:
            number = _vlan_id(cisco.group(1))
            if number is None:
                continue
            name = None
            related_number = None
            related_line = None
            for later_index in range(index + 1, min(len(lines), index + 30)):
                later = bounded_line(lines[later_index], later_index + 1)
                if later is None:
                    continue
                if later.strip() in {"", "!"}:
                    continue
                if later == later.lstrip():
                    break
                named = re.fullmatch(r"\s*name\s+(.+?)\s*", later, re.I)
                if named:
                    name = named.group(1).strip()[:200]
                    related_number = later_index + 1
                    related_line = later
                    recognized_lines.add(related_number)
                    break
            add(
                line_number=line_number, raw=raw, vlan_id=number,
                vlan_name=name, relation="declaration", syntax="cisco_vlan_config",
                evidence_state="configured", related_line_number=related_number,
                related_source_line=related_line,
            )
            if name:
                declaration_by_name[name.casefold()] = (number, raw, line_number)
            continue
        juniper = re.fullmatch(
            r"set\s+vlans\s+(\S+)\s+vlan-id\s+(\d{1,4})", stripped, re.I,
        )
        if juniper:
            number = _vlan_id(juniper.group(2))
            if number is None:
                continue
            name = juniper.group(1).strip("'\"")[:200]
            declaration_by_name[name.casefold()] = (number, raw, line_number)
            add(
                line_number=line_number, raw=raw, vlan_id=number,
                vlan_name=name, relation="declaration", syntax="juniper_set_vlan",
                evidence_state="configured",
            )
            continue
        table = re.fullmatch(
            r"(\d{1,4})\s+(.+?)\s+(active|act/unsup|suspended)\s*(.*)",
            stripped, re.I,
        )
        command = (command_by_line.get(line_number) or "").lower()
        if table and ("show vlan" in command or command == ""):
            number = _vlan_id(table.group(1))
            if number is None:
                continue
            name = table.group(2).strip()[:200]
            declaration_by_name[name.casefold()] = (number, raw, line_number)
            reported_state = table.group(3).lower()
            current_show_vlan = (number, name, reported_state)
            add(
                line_number=line_number, raw=raw, vlan_id=number,
                vlan_name=name, relation="declaration", syntax="cisco_show_vlan",
                evidence_state="observed", facts={"reported_state": reported_state},
            )
            for interface in re.split(r"\s*,\s*|\s+", table.group(4).strip()):
                if interface:
                    add(
                        line_number=line_number, raw=raw, vlan_id=number,
                        vlan_name=name, interface_name=interface,
                        relation="declared_member", syntax="cisco_show_vlan",
                        evidence_state="observed",
                        facts={"reported_state": reported_state},
                    )
            continue
        continuation = re.fullmatch(
            r"\s+([A-Za-z][A-Za-z0-9_.:/-]*(?:\s*,\s*"
            r"[A-Za-z][A-Za-z0-9_.:/-]*)*,?)\s*",
            raw,
        )
        if current_show_vlan and ("show vlan" in command or command == "") and continuation:
            number, name, reported_state = current_show_vlan
            interfaces = [
                item.strip() for item in continuation.group(1).rstrip(",").split(",")
                if item.strip()
            ]
            for interface in interfaces:
                add(
                    line_number=line_number, raw=raw, vlan_id=number,
                    vlan_name=name, interface_name=interface,
                    relation="declared_member", syntax="cisco_show_vlan_continuation",
                    evidence_state="observed", facts={"reported_state": reported_state},
                )
            recognized_lines.add(line_number)
            continue
        if stripped:
            current_show_vlan = None

    current_interface: tuple[str, int, str] | None = None
    current_bridge_interface: str | None = None
    for line_number, original in enumerate(lines, 1):
        check_time(line_number)
        raw = bounded_line(original, line_number)
        if raw is None:
            continue
        stripped = raw.strip()
        header = re.fullmatch(r"interface\s+(\S+)", stripped, re.I)
        if header and raw == raw.lstrip():
            current_interface = (header.group(1), line_number, raw)
            continue
        if current_interface and raw == raw.lstrip() and stripped not in {"", "!"}:
            current_interface = None
        if current_interface:
            mode = re.fullmatch(
                r"switchport\s+mode\s+(?:access|trunk|hybrid)", stripped, re.I,
            )
            if mode:
                recognized_lines.add(line_number)
                continue
            access = re.fullmatch(r"switchport\s+access\s+vlan\s+(\d{1,4})", stripped, re.I)
            native = re.fullmatch(
                r"switchport\s+trunk\s+native\s+vlan\s+(\d{1,4})", stripped, re.I,
            )
            allowed = re.fullmatch(
                r"switchport\s+trunk\s+allowed\s+vlan(?:\s+add)?\s+(.+)", stripped, re.I,
            )
            relation = "access" if access else "native" if native else None
            if relation:
                number = _vlan_id((access or native).group(1))
                if number is not None:
                    add(
                        line_number=line_number, raw=raw, vlan_id=number,
                        interface_name=current_interface[0], relation=relation,
                        syntax="cisco_switchport_config", evidence_state="configured",
                        related_line_number=current_interface[1],
                        related_source_line=current_interface[2],
                    )
                continue
            if allowed:
                numbers, supported = _expand_vlan_spec(allowed.group(1))
                if supported:
                    for number in numbers:
                        add(
                            line_number=line_number, raw=raw, vlan_id=number,
                            interface_name=current_interface[0], relation="allowed",
                            syntax="cisco_switchport_config", evidence_state="configured",
                            related_line_number=current_interface[1],
                            related_source_line=current_interface[2],
                        )
                    recognized_lines.add(line_number)
                else:
                    note_unsupported(line_number, "unsupported_vlan_list", raw)
                continue

        juniper_member = re.fullmatch(
            r"set\s+interfaces\s+(\S+)(?:\s+unit\s+(\S+))?.*?"
            r"family\s+ethernet-switching\s+vlan\s+members\s+(.+)",
            stripped, re.I,
        )
        if juniper_member:
            interface = juniper_member.group(1)
            if juniper_member.group(2) is not None:
                interface = f"{interface}.{juniper_member.group(2)}"
            members = re.split(r"[\s,]+", juniper_member.group(3).strip(" []'\""))
            supported = True
            for member in [item for item in members if item]:
                number = _vlan_id(member)
                name = None
                related = None
                if number is None:
                    related = declaration_by_name.get(member.casefold())
                    if related is None:
                        supported = False
                        continue
                    number, related_line, related_number = related
                    name = member
                else:
                    related_line = None
                    related_number = None
                add(
                    line_number=line_number, raw=raw, vlan_id=number,
                    vlan_name=name, interface_name=interface,
                    relation="declared_member", syntax="juniper_set_member",
                    evidence_state="configured", related_line_number=related_number,
                    related_source_line=related_line,
                )
            if supported:
                recognized_lines.add(line_number)
            else:
                note_unsupported(line_number, "unresolved_vlan_name", raw)
            continue
        juniper_native = re.fullmatch(
            r"set\s+interfaces\s+(\S+)(?:\s+unit\s+(\S+))?.*?native-vlan-id\s+(\d{1,4})",
            stripped, re.I,
        )
        if juniper_native:
            number = _vlan_id(juniper_native.group(3))
            if number is not None:
                interface = juniper_native.group(1)
                if juniper_native.group(2) is not None:
                    interface = f"{interface}.{juniper_native.group(2)}"
                add(
                    line_number=line_number, raw=raw, vlan_id=number,
                    interface_name=interface, relation="native",
                    syntax="juniper_set_native", evidence_state="configured",
                )
            continue

        command = (command_by_line.get(line_number) or "").lower()
        if "bridge vlan show" in command:
            bridge = re.fullmatch(
                r"([A-Za-z][A-Za-z0-9_.:/-]*)\s+(\d{1,4}(?:-\d{1,4})?)(.*)",
                stripped,
            )
            bridge_continuation = re.fullmatch(
                r"(\d{1,4}(?:-\d{1,4})?)(.*)", stripped,
            ) if raw[:1].isspace() and current_bridge_interface else None
            if bridge:
                interface_name = bridge.group(1)
                current_bridge_interface = interface_name
                vlan_spec = bridge.group(2)
                flags = bridge.group(3).lower()
            elif bridge_continuation:
                interface_name = current_bridge_interface
                vlan_spec = bridge_continuation.group(1)
                flags = bridge_continuation.group(2).lower()
            else:
                if re.fullmatch(r"port\s+vlan[- ]id", stripped, re.I):
                    recognized_lines.add(line_number)
                elif stripped:
                    current_bridge_interface = None
                continue
            numbers, supported = _expand_vlan_spec(vlan_spec)
            if not supported:
                note_unsupported(line_number, "unsupported_vlan_list", raw)
                continue
            syntax = (
                "linux_bridge_vlan" if bridge else "linux_bridge_vlan_continuation"
            )
            for number in numbers:
                if "pvid" in flags:
                    add(
                        line_number=line_number, raw=raw, vlan_id=number,
                        interface_name=interface_name, relation="pvid",
                        syntax=syntax, evidence_state="observed",
                        facts={"flags": flags.split()},
                    )
                relation = "untagged" if "untagged" in flags else "tagged"
                add(
                    line_number=line_number, raw=raw, vlan_id=number,
                    interface_name=interface_name, relation=relation,
                    syntax=syntax, evidence_state="observed",
                    facts={"flags": flags.split()},
                )
            recognized_lines.add(line_number)
            continue

    vlan_signal = re.compile(
        r"(?:\bvlan\b|switchport\b|ethernet-switching\b|native-vlan-id\b)", re.I,
    )
    for line_number, raw in enumerate(lines, 1):
        if (
            line_number in recognized_lines
            or re.match(r"^=====\s*.+?\s*=====\s*$", raw.strip())
            or not vlan_signal.search(raw)
        ):
            continue
        note_unsupported(line_number, "unsupported_vlan_syntax", raw)

    receipts.sort(key=lambda item: (
        item["source_line_number"], item["vlan_id"],
        item["membership_relation"], item.get("interface_name") or "",
    ))
    incomplete = any((
        decoding_loss,
        line_limit_reached,
        overlong_line_count,
        receipt_limit_reached,
    ))
    explicitly_unsupported = bool(unavailable_commands or unsupported_line_count)
    if receipts:
        collection_state = "partial" if incomplete or explicitly_unsupported else "supported"
    elif incomplete:
        collection_state = "unknown"
    elif explicitly_unsupported:
        collection_state = "unsupported"
    else:
        collection_state = "unknown"
    collection_labels = {
        "supported": "Supported VLAN evidence retained",
        "partial": "Partial VLAN evidence retained",
        "unsupported": "Retained source uses unsupported or unavailable VLAN output",
        "unknown": "No supported VLAN evidence found; VLAN presence is unknown",
    }
    coverage = {
        "contract": DEVICE_VLAN_EXTRACTOR,
        "source_byte_count": len(content),
        "source_line_count": len(all_lines),
        "processed_line_count": len(lines),
        "reported_receipt_count": len(receipts),
        "supported_syntaxes": sorted({item["source_syntax"] for item in receipts}),
        "command_sections": sorted(set(command_sections)),
        "unavailable_commands": sorted(unavailable_commands),
        "decoding_loss": decoding_loss,
        "line_limit_reached": line_limit_reached,
        "overlong_line_count": overlong_line_count,
        "receipt_limit_reached": receipt_limit_reached,
        "unsupported_line_count": unsupported_line_count,
        "unsupported_line_samples": unsupported,
        "unsupported_sample_truncated": unsupported_line_count > len(unsupported),
        "collection_state": collection_state,
        "collection_state_label": collection_labels[collection_state],
        "not_collected_supported": False,
        "absence_supported": False,
        "live_state_supported": False,
        "cross_device_identity_supported": False,
    }
    if len(_canonical_json(coverage).encode()) > MAX_VLAN_JSON_BYTES:
        raise ValueError("Device VLAN coverage exceeds its retained JSON limit")
    return {"receipts": receipts, "coverage": coverage}


def publish_device_vlan_assessment(
    db_path: Path, *, assignment_id: str, summary_result_id: str,
    snapshot: dict, extracted: dict, frozen_contract: dict,
    transaction_guard=None, transaction_finalize=None,
) -> dict:
    """Atomically publish one exact scoped VLAN assessment and its source receipts."""
    from app.artifacts import utc_now
    from app.device_observations import (
        DeviceObservationConflict,
        _completed_summary_result,
        _configuration_input,
        assignment_contract_on_connection,
    )

    init_device_vlan_observation_storage(db_path)
    coverage_json = _canonical_json(extracted["coverage"])
    source_contract_json = _canonical_json(frozen_contract)
    if max(len(coverage_json.encode()), len(source_contract_json.encode())) > MAX_VLAN_JSON_BYTES:
        raise DeviceObservationConflict("Device VLAN retained contract exceeds its JSON limit")
    collection_contract = frozen_contract["collection_contract"]
    with connect_database(db_path) as db:
        db.execute("BEGIN IMMEDIATE")
        current_contract = assignment_contract_on_connection(db, assignment_id)
        if current_contract != frozen_contract["assignment_contract"]:
            raise DeviceObservationConflict("Device VLAN assignment or authority changed")
        assignment = current_contract["assignment"]
        if _completed_summary_result(db, assignment["run_id"]) != summary_result_id:
            raise DeviceObservationConflict("Completed reusable device summary changed")
        selected = _configuration_input(current_contract["authority"])
        if (
            selected["observation_id"] != snapshot["observation_id"]
            or selected["sha256"] != snapshot["sha256"]
            or int(selected["size_bytes"]) != int(snapshot["size_bytes"])
        ):
            raise DeviceObservationConflict("Selected VLAN configuration changed")
        linked = db.execute(
            """SELECT 1 FROM derived_results result
               JOIN derived_result_observation_links link ON link.result_id = result.result_id
               WHERE result.result_id = ? AND link.input_role = 'configuration'
                 AND link.observation_id = ?""",
            (summary_result_id, snapshot["observation_id"]),
        ).fetchone()
        if linked is None:
            raise DeviceObservationConflict(
                "Completed reusable summary is not linked to this configuration"
            )
        if transaction_guard is not None:
            transaction_guard(db)
        assessment_id = "device_vlan_assessment_" + _digest(
            assignment_id, summary_result_id, DEVICE_VLAN_EXTRACTOR,
            collection_contract, snapshot["observation_id"], snapshot["sha256"],
        )
        source_role = selected["role"]
        prepared = []
        for item in extracted["receipts"]:
            receipt_id = "device_vlan_receipt_" + _digest(
                assessment_id, item["source_line_number"], item["vlan_id"],
                item["membership_relation"], item.get("interface_name"),
                item.get("bridge_context"), item["source_line"], item.get("related_source_line"),
            )
            facts_json = _canonical_json(item["facts"])
            if len(facts_json.encode()) > MAX_VLAN_JSON_BYTES:
                raise DeviceObservationConflict("Device VLAN receipt facts exceed their JSON limit")
            prepared.append((
                receipt_id, assessment_id, snapshot["observation_id"], source_role,
                snapshot["filename"], item["device_context"], item["bridge_context"],
                int(item["vlan_id"]), item["vlan_name"], item["interface_name"],
                item["membership_relation"], item["evidence_state"],
                int(item["source_line_number"]), item["source_line"],
                item["related_line_number"], item["related_source_line"],
                item["source_command"], item["source_section"], item["source_syntax"],
                facts_json,
            ))
        prepared.sort(key=lambda row: (row[12], row[7], row[10], row[0]))
        expected = (
            assignment["run_id"], int(assignment["authority_revision"]),
            int(assignment["revision"]), assignment["scope_id"],
            snapshot["observation_id"], snapshot["sha256"], int(snapshot["size_bytes"]),
            snapshot["filename"], summary_result_id, DEVICE_VLAN_EXTRACTOR,
            collection_contract, source_contract_json, coverage_json,
        )
        prior = db.execute(
            """SELECT run_id, authority_revision, assignment_revision, scope_id,
                      configuration_observation_id, configuration_sha256,
                      configuration_size_bytes, configuration_filename,
                      summary_result_id, extractor_version, collection_contract,
                      source_contract_json, coverage_json
               FROM device_vlan_assessments WHERE assessment_id = ?""",
            (assessment_id,),
        ).fetchone()
        created = prior is None
        if prior is not None and tuple(prior) != expected:
            raise DeviceObservationConflict("Device VLAN assessment replay changed")
        if prior is not None:
            retained = db.execute(
                """SELECT receipt_id, assessment_id, source_observation_id, source_role,
                          source_filename, device_context, bridge_context, vlan_id,
                          vlan_name, interface_name, membership_relation, evidence_state,
                          source_line_number, source_line, related_line_number,
                          related_source_line, source_command, source_section,
                          source_syntax, facts_json
                   FROM device_vlan_receipts WHERE assessment_id = ?
                   ORDER BY source_line_number, vlan_id, membership_relation, receipt_id""",
                (assessment_id,),
            ).fetchall()
            if [tuple(row) for row in retained] != prepared:
                raise DeviceObservationConflict("Device VLAN receipt replay changed")
        if created:
            db.execute(
                """INSERT INTO device_vlan_assessments(
                       assessment_id, assignment_id, run_id, authority_revision,
                       assignment_revision, scope_id, configuration_observation_id,
                       configuration_sha256, configuration_size_bytes,
                       configuration_filename, summary_result_id, extractor_version,
                       collection_contract, source_contract_json, coverage_json, recorded_at
                   ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (assessment_id, assignment_id, *expected, utc_now()),
            )
            for receipt in prepared:
                db.execute(
                    """INSERT INTO device_vlan_receipts(
                           receipt_id, assessment_id, source_observation_id, source_role,
                           source_filename, device_context, bridge_context, vlan_id,
                           vlan_name, interface_name, membership_relation, evidence_state,
                           source_line_number, source_line, related_line_number,
                           related_source_line, source_command, source_section,
                           source_syntax, facts_json
                       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    receipt,
                )
        if transaction_finalize is not None:
            transaction_finalize(db, created, assessment_id)
    return {
        "assessment_id": assessment_id,
        "created": created,
        "receipt_count": len(prepared),
        "coverage": extracted["coverage"],
    }


def get_device_vlan_observation_status(db_path: Path, run_id: str) -> dict:
    """Read current VLAN processing state without creating or repairing storage."""
    envelope = {
        "meaning": DEVICE_VLAN_STATUS_MEANING,
        "claims": dict(DEVICE_VLAN_CLAIMS),
        "evidence_state_labels": dict(DEVICE_VLAN_EVIDENCE_LABELS),
    }
    if not Path(db_path).is_file():
        return envelope | {
            "state": "needs_scope", "assignment": None, "assessment": None,
        }
    from app.device_observations import assignment_contract_on_connection

    with connect_database(db_path, read_only=True) as db:
        available = db.execute(
            """SELECT COUNT(*) FROM sqlite_master WHERE type = 'table'
               AND name IN ('device_scope_assignments', 'device_vlan_assessments',
                            'device_vlan_admission_intents', 'pipeline_jobs',
                            'pipeline_job_attempts')"""
        ).fetchone()[0]
        if int(available) != 5:
            return envelope | {
                "state": "unavailable", "assignment": None, "assessment": None,
            }
        db.row_factory = sqlite3.Row
        assignment = db.execute(
            """SELECT current.* FROM device_scope_assignments current
               WHERE current.run_id = ? AND NOT EXISTS (
                   SELECT 1 FROM device_scope_assignments successor
                    WHERE successor.supersedes_assignment_id = current.assignment_id
               )
               ORDER BY current.authority_revision DESC, current.revision DESC LIMIT 1""",
            (run_id,),
        ).fetchone()
        if assignment is None:
            return envelope | {
                "state": "needs_scope", "assignment": None, "assessment": None,
            }
        try:
            contract = assignment_contract_on_connection(db, assignment["assignment_id"])
        except (KeyError, ValueError) as exc:
            return envelope | {
                "state": "blocked",
                "error": str(exc),
                "assignment": {key: assignment[key] for key in assignment.keys()},
                "assessment": None,
            }
        collection_contract = contract["authority"]["selection_contract"]
        assessment = current_device_vlan_assessment_on_connection(
            db, assignment_id=assignment["assignment_id"],
            collection_contract=collection_contract,
        )
        attempt = db.execute(
            """SELECT attempt.state, attempt.error, job.job_id
                 FROM pipeline_jobs job
                 LEFT JOIN pipeline_job_attempts attempt ON attempt.job_id = job.job_id
                WHERE job.job_type = ? AND job.source_ref = ?
                ORDER BY attempt.attempt_number DESC LIMIT 1""",
            (DEVICE_VLAN_JOB_TYPE, assignment["assignment_id"]),
        ).fetchone()
        intent = db.execute(
            """SELECT state, activity_state, last_error, admitted_job_id
                 FROM device_vlan_admission_intents WHERE assignment_id = ?""",
            (assignment["assignment_id"],),
        ).fetchone()
        if assessment is not None:
            state = "completed"
        elif attempt is not None and attempt[0] is not None:
            state = attempt[0]
        elif intent is not None and intent[0] == "blocked":
            state = "blocked"
        else:
            state = "waiting"
        return envelope | {
            "state": state,
            "error": (
                attempt[1] if attempt is not None and attempt[1]
                else intent[2] if intent is not None else None
            ),
            "job_id": attempt[2] if attempt is not None else None,
            "assignment": contract["assignment"] | {
                "scope_label": contract["scope_label"],
                "collection_contract": collection_contract,
            },
            "assessment": None if assessment is None else {
                "assessment_id": assessment["assessment_id"],
                "recorded_at": assessment["recorded_at"],
                "extractor_version": assessment["extractor_version"],
                "collection_contract": assessment["collection_contract"],
                "configuration_sha256": assessment["configuration_sha256"],
                "configuration_filename": assessment["configuration_filename"],
                "coverage": json.loads(assessment["coverage_json"]),
            },
        }


def get_device_vlan_receipts(
    db_path: Path, run_id: str, *, limit: int = 50, offset: int = 0,
) -> dict:
    """Return one bounded read-only page from the current exact VLAN assessment."""
    if not 1 <= limit <= MAX_VLAN_API_PAGE or offset < 0:
        raise ValueError("Invalid device VLAN receipt page")
    status = get_device_vlan_observation_status(db_path, run_id)
    assessment = status.get("assessment")
    if assessment is None:
        raise KeyError("Scoped device VLAN observations are not available")
    with connect_database(db_path, read_only=True) as db:
        db.row_factory = sqlite3.Row
        total = db.execute(
            "SELECT COUNT(*) FROM device_vlan_receipts WHERE assessment_id = ?",
            (assessment["assessment_id"],),
        ).fetchone()[0]
        rows = db.execute(
            """SELECT * FROM device_vlan_receipts WHERE assessment_id = ?
               ORDER BY vlan_id, source_line_number, membership_relation, receipt_id
               LIMIT ? OFFSET ?""",
            (assessment["assessment_id"], limit, offset),
        ).fetchall()
    result = {
        "run_id": run_id,
        "meaning": (
            "This retained device source explicitly reported these VLAN facts. "
            "They are not a live VLAN status or proof that any other VLAN is absent."
        ),
        "claims": dict(DEVICE_VLAN_CLAIMS),
        "evidence_state_labels": dict(DEVICE_VLAN_EVIDENCE_LABELS),
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
            "device_context": row["device_context"],
            "bridge_context": row["bridge_context"],
            "vlan_id": int(row["vlan_id"]),
            "vlan_name": row["vlan_name"],
            "interface_name": row["interface_name"],
            "membership_relation": row["membership_relation"],
            "evidence_state": row["evidence_state"],
            "evidence_state_label": DEVICE_VLAN_EVIDENCE_LABELS[row["evidence_state"]],
            "source_line_number": int(row["source_line_number"]),
            "source_line": row["source_line"],
            "related_line_number": row["related_line_number"],
            "related_source_line": row["related_source_line"],
            "source_command": row["source_command"],
            "source_section": row["source_section"],
            "source_syntax": row["source_syntax"],
            "facts": json.loads(row["facts_json"]),
        } for row in rows],
        "pagination": {
            "limit": limit,
            "offset": offset,
            "total": int(total),
            "has_more": offset + len(rows) < int(total),
        },
    }
    if len(_canonical_json(result).encode()) > MAX_VLAN_JSON_BYTES:
        raise ValueError("Device VLAN receipt page exceeds its response limit")
    return result


def record_device_vlan_observation_intent(
    db: sqlite3.Connection, assignment_id: str,
) -> dict:
    """Freeze a separate VLAN job request beside the interface-observation request."""
    import hashlib
    import json

    from app.device_observations import (
        _completed_summary_result,
        assignment_contract_on_connection,
    )
    from app.pipeline_intake import (
        COLLECTED_DEVICE_SOURCE,
        DEVICE_INGESTION_POLICY_VERSION,
        MANUAL_DEVICE_INTENT,
        MANUAL_DEVICE_SOURCE,
        source_policy_version,
    )

    assignment_contract = assignment_contract_on_connection(db, assignment_id)
    assignment = assignment_contract["assignment"]
    summary_result_id = _completed_summary_result(db, assignment["run_id"])
    source_kind = (
        MANUAL_DEVICE_SOURCE
        if assignment_contract["intent_kind"] == MANUAL_DEVICE_INTENT
        else COLLECTED_DEVICE_SOURCE
    )
    policy = source_policy_version(db, source_kind, assignment["run_id"])
    if policy != DEVICE_INGESTION_POLICY_VERSION:
        raise ValueError("Device VLAN intake policy version is not supported")
    configuration = next((
        item for item in assignment_contract["authority"]["authority_inputs"]
        if item["role"] in {"configuration", "configuration_and_raw_output"}
        and item["source_kind"] == "artifact_file"
    ), None)
    if configuration is None:
        raise ValueError("Device authority has no selected configuration artifact")
    job_definition = {
        "assignment_contract": assignment_contract,
        "summary_result_id": summary_result_id,
        "vlan_extractor_version": DEVICE_VLAN_EXTRACTOR,
    }
    contract = {
        "assignment_id": assignment_id,
        "run_id": assignment["run_id"],
        "authority_revision": int(assignment["authority_revision"]),
        "assignment_revision": int(assignment["revision"]),
        "scope_id": assignment["scope_id"],
        "assignment_contract": assignment_contract,
        "summary_result_id": summary_result_id,
        "collection_contract": assignment_contract["authority"]["selection_contract"],
        "source_coverage": assignment_contract["authority"]["authority_inputs"],
        "source_observation_id": configuration["observation_id"],
        "source_sha256": configuration["sha256"],
        "source_size_bytes": int(configuration["size_bytes"]),
        "source_status": "assigned",
        "source_kind": "device_configuration",
        "source_ref": assignment_id,
        "target_job_type": DEVICE_VLAN_JOB_TYPE,
        "target_family": DEVICE_VLAN_TARGET_FAMILY,
        "target_analysis_version": DEVICE_VLAN_EXTRACTOR,
        "target_payload_schema_version": DEVICE_VLAN_SCHEMA_VERSION,
        "target_parameters": {},
        "target_result_id": summary_result_id,
        "job_definition": job_definition,
    }
    contract_json = json.dumps(
        contract, sort_keys=True, separators=(",", ":"), allow_nan=False,
    )
    digest = hashlib.sha256(f"device-vlan:{assignment_id}".encode()).hexdigest()
    intent_id = f"device_vlan_intent_{digest}"
    request_token = f"auto-{intent_id}"
    values = (
        intent_id, assignment_id, DEVICE_VLAN_POLICY_VERSION,
        configuration["observation_id"], assignment["scope_id"],
        assignment["actor"], request_token, contract_json,
        assignment["assigned_at"], assignment["assigned_at"],
    )
    inserted = db.execute(
        """INSERT OR IGNORE INTO device_vlan_admission_intents(
               intent_id, assignment_id, policy_version, source_observation_id,
               scope_id, actor, request_token, contract_json, state,
               created_at, updated_at, activity_state
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, 'waiting')""",
        values,
    ).rowcount
    row = db.execute(
        """SELECT intent_id, assignment_id, policy_version, source_observation_id,
                  scope_id, actor, request_token, contract_json, state,
                  created_at, updated_at, admitted_job_id, activity_state, last_error
           FROM device_vlan_admission_intents WHERE assignment_id = ?""",
        (assignment_id,),
    ).fetchone()
    if row is None:
        raise ValueError("Device VLAN admission intent is unavailable")
    retained = tuple(row)
    expected_identity = values[:8] + values[8:10]
    retained_identity = retained[:8] + retained[9:11]
    if not inserted and retained_identity != expected_identity:
        raise ValueError("Device VLAN admission intent replay does not match")
    keys = (
        "intent_id", "assignment_id", "policy_version", "source_observation_id",
        "scope_id", "actor", "request_token", "contract_json", "state",
        "created_at", "updated_at", "admitted_job_id", "activity_state", "last_error",
    )
    result = dict(zip(keys, retained))
    result["contract"] = json.loads(result.pop("contract_json"))
    return result


def admit_device_vlan_observation_intent(
    db: sqlite3.Connection, *, assignment_id: str, job_id: str, admitted_at: str,
) -> dict:
    """Bind one durable VLAN intent to its separately keyed pipeline job."""
    if not db.in_transaction:
        db.execute("BEGIN IMMEDIATE")
    row = db.execute(
        """SELECT state, admitted_job_id, contract_json
             FROM device_vlan_admission_intents
           WHERE assignment_id = ?""",
        (assignment_id,),
    ).fetchone()
    if row is None:
        raise ValueError("Device VLAN admission intent is unavailable")
    if row[0] == "admitted":
        if row[1] != job_id:
            raise ValueError("Device VLAN admission intent already names another job")
    elif row[0] == "pending":
        import json

        from app.device_observations import (
            _completed_summary_result,
            assignment_contract_on_connection,
        )

        contract = json.loads(row[2])
        try:
            current_contract = assignment_contract_on_connection(db, assignment_id)
        except (KeyError, ValueError) as exc:
            raise ValueError("Device VLAN scope assignment is no longer current") from exc
        if current_contract != contract["assignment_contract"]:
            raise ValueError("Device VLAN assignment or authority contract changed")
        if _completed_summary_result(db, contract["run_id"]) != contract["summary_result_id"]:
            raise ValueError("Completed reusable device summary changed before VLAN admission")
        job = db.execute(
            """SELECT job_type, source_run_id, source_observation_id, source_status,
                      source_sha256, source_size_bytes, target_family,
                      target_analysis_version, target_payload_schema_version,
                      target_parameters_json, target_result_id, source_kind, source_ref,
                      definition_json
                 FROM pipeline_jobs WHERE job_id = ?""",
            (job_id,),
        ).fetchone()
        expected = (
            contract["target_job_type"], contract["run_id"],
            contract["source_observation_id"], contract["source_status"],
            contract["source_sha256"], int(contract["source_size_bytes"]),
            contract["target_family"], contract["target_analysis_version"],
            int(contract["target_payload_schema_version"]),
            json.dumps(contract["target_parameters"], sort_keys=True, separators=(",", ":")),
            contract["target_result_id"], contract["source_kind"], contract["source_ref"],
            json.dumps(contract["job_definition"], sort_keys=True, separators=(",", ":")),
        )
        if job is None or tuple(job) != expected:
            raise ValueError("Pipeline job does not match the frozen device VLAN contract")
        _before_device_vlan_admission_bind(db)
        updated = db.execute(
            """UPDATE device_vlan_admission_intents
                  SET state = 'admitted', admitted_job_id = ?, updated_at = ?,
                      activity_state = 'complete', last_error = NULL
                WHERE assignment_id = ? AND state = 'pending'""",
            (job_id, admitted_at, assignment_id),
        ).rowcount
        if updated != 1:
            raise ValueError("Device VLAN admission intent changed concurrently")
    else:
        raise ValueError("Blocked device VLAN admission cannot be admitted")
    retained = db.execute(
        """SELECT intent_id, assignment_id, state, admitted_job_id, activity_state
           FROM device_vlan_admission_intents WHERE assignment_id = ?""",
        (assignment_id,),
    ).fetchone()
    return dict(zip(
        ("intent_id", "assignment_id", "state", "admitted_job_id", "activity_state"),
        retained,
    ))


def _before_device_vlan_admission_bind(db: sqlite3.Connection) -> None:
    """Test hook for proving the write lock spans validation and durable binding."""
