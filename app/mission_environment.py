"""Explicit Mission Environment declarations and per-scope coverage context.

These records describe administrator-reviewed operating context.  They never
infer or grant authorization and they do not start, block, or schedule network
contact.
"""
from __future__ import annotations

from datetime import datetime, timezone
import ipaddress
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
OBSERVATION_QUERY_LIMIT = 10_000
OBSERVED_NETWORK_LIMIT = 1_000
SPECIAL_ROLE_DECLARATION_LIMIT = 1_000
SPECIAL_ROLE_BATCH_LIMIT = 50
SPECIAL_ROLE_CATALOG_MATCH_LIMIT = 25
SPECIAL_ROLE_SUPPORTING_SOURCE_LIMIT = 25
SPECIAL_ROLE_KEY_PREFIX = "mission_special_role:"
SPECIAL_ROLE_ASSESSMENT_VERSION = "special-device-role-assessment:3"
SPECIAL_ROLE_DEFINITIONS = (
    ("directory_controller", "Directory service / domain controller", {
        ("tcp", 53), ("udp", 53), ("tcp", 88), ("udp", 88),
        ("tcp", 135), ("tcp", 139), ("tcp", 389), ("udp", 389),
        ("tcp", 445), ("tcp", 464), ("udp", 464), ("tcp", 636),
        ("tcp", 3268), ("tcp", 3269),
    }),
    ("dns_server", "DNS server", {("tcp", 53), ("udp", 53)}),
    # UDP/68 identifies a DHCP client. A declared DHCP server is assessed only
    # against the server-side UDP/67 signal so clients are not mislabeled.
    ("dhcp_server", "DHCP server", {("udp", 67)}),
    ("default_gateway", "Default gateway", set()),
    ("ntp_server", "Time server (NTP)", {("udp", 123)}),
    ("web_proxy", "Web proxy", {
        ("tcp", 3128), ("tcp", 8000), ("tcp", 8080), ("tcp", 8888),
    }),
    ("web_application_server", "Web or application server", {
        ("tcp", 80), ("tcp", 443), ("tcp", 8080), ("tcp", 8443),
    }),
    ("file_server", "File server", {
        ("tcp", 445), ("tcp", 2049), ("udp", 2049),
    }),
    ("mail_server", "Mail server", {
        ("tcp", 25), ("tcp", 110), ("tcp", 143), ("tcp", 465),
        ("tcp", 587), ("tcp", 993), ("tcp", 995),
    }),
    ("database_server", "Database server", {
        ("tcp", 1433), ("tcp", 1521), ("tcp", 3306),
        ("tcp", 5432), ("tcp", 27017),
    }),
    ("vpn_gateway", "VPN gateway", {
        ("udp", 500), ("udp", 4500), ("tcp", 1194),
        ("udp", 1194), ("tcp", 1723),
    }),
    ("pki_server", "PKI or certificate authority", set()),
    ("log_server", "Logging or SIEM server", {
        ("tcp", 514), ("udp", 514), ("tcp", 6514),
    }),
    ("network_management_server", "Network management server", set()),
    ("virtualization_manager", "Virtualization manager", set()),
    ("backup_server", "Backup server", set()),
    ("other", "Other mission-specific role", set()),
)
SPECIAL_ROLE_DESCRIPTIONS = {
    "directory_controller": "Provides directory, authentication, and domain services.",
    "dns_server": "Resolves names for systems in the mission environment.",
    "dhcp_server": "Assigns network settings to clients through server-side DHCP.",
    "default_gateway": "Routes traffic out of a local network or security zone.",
    "ntp_server": "Provides the time source used to align system and evidence timestamps.",
    "web_proxy": "Relays web traffic between clients and other networks.",
    "web_application_server": "Hosts a website, portal, API, or mission application.",
    "file_server": "Provides shared files through SMB or NFS services.",
    "mail_server": "Sends, receives, or stores email for the environment.",
    "database_server": "Stores structured application or mission data.",
    "vpn_gateway": "Terminates encrypted remote-access or site-to-site tunnels.",
    "pki_server": "Issues or manages certificates; ports vary by product and design.",
    "log_server": "Receives centralized logs or security-event records.",
    "network_management_server": "Monitors or manages network equipment. Generic SNMP agent ports do not reliably identify the management server.",
    "virtualization_manager": "Manages virtual machines or hypervisor infrastructure; ports vary by platform.",
    "backup_server": "Coordinates or stores backups; ports vary by backup product.",
    "other": "Records a mission-specific function that is not in the common catalog.",
}
SPECIAL_ROLE_KEYS = {key for key, _label, _ports in SPECIAL_ROLE_DEFINITIONS}
SPECIAL_ROLE_LABELS = {key: label for key, label, _ports in SPECIAL_ROLE_DEFINITIONS}
SPECIAL_ROLE_PROTOCOL_PORTS = {
    key: set(protocol_ports) for key, _label, protocol_ports in SPECIAL_ROLE_DEFINITIONS
}


def _special_role_definition_snapshots() -> list[dict]:
    snapshots = []
    for key, label, protocol_ports in SPECIAL_ROLE_DEFINITIONS:
        snapshots.append({
            "role_key": key,
            "label": label,
            "description": SPECIAL_ROLE_DESCRIPTIONS[key],
            "typical_ports": sorted(
                (f"{port}/{protocol}" for protocol, port in protocol_ports),
                key=lambda value: (int(value.split("/", 1)[0]), value),
            ),
            "assessment_support": (
                "retained_configuration" if key == "default_gateway"
                else "retained_port_and_traffic_signals" if protocol_ports
                else "declaration_only"
            ),
        })
    return snapshots


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
            CREATE TABLE IF NOT EXISTS app_settings (
                key TEXT PRIMARY KEY,
                value_json TEXT NOT NULL,
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
        "scope_active": bool(scope["active"]),
        "network_scope_version": int(scope["version"]),
        "nmap_coverage": "unknown",
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
        "network_scope_version": int(scope["version"]),
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


def _safe_address(value: object):
    try:
        return ipaddress.ip_address(str(value))
    except ValueError:
        return None


def _safe_network(value: object):
    try:
        return ipaddress.ip_network(str(value), strict=False)
    except ValueError:
        return None


def _observed_environment_rows(
    db: sqlite3.Connection,
    *,
    scopes: list[sqlite3.Row],
    tables: set[str],
) -> tuple[list[dict], dict]:
    """Summarize retained metadata without contacting or reprocessing a source."""
    if not scopes:
        return [], {"truncated": False, "source_row_limit": OBSERVATION_QUERY_LIMIT}
    scope_by_id = {str(row["scope_id"]): row for row in scopes}
    scope_ids = tuple(scope_by_id)
    placeholders = ",".join("?" for _ in scope_ids)
    rows: dict[tuple[str, str], dict] = {}

    def ensure(scope_id, network, *, name, basis):
        key = (scope_id, str(network))
        item = rows.get(key)
        if item is None:
            item = {
                "scope_id": scope_id,
                "scope_label": scope_by_id[scope_id]["label"],
                "network": str(network),
                "network_name": name,
                "identification_basis": basis,
                "nmap_addresses": set(),
                "device_addresses": set(),
                "device_runs": set(),
                "device_labels": set(),
                "arkime_addresses": set(),
                "arkime_imports": set(),
                "latest_nmap_at": None,
                "latest_device_at": None,
                "latest_arkime_at": None,
            }
            rows[key] = item
        elif basis == "saved_network":
            item["network_name"] = name
            item["identification_basis"] = basis
        return item

    def containing(scope_id, address):
        candidates = []
        for (candidate_scope, cidr), item in rows.items():
            if candidate_scope != scope_id:
                continue
            network = _safe_network(cidr)
            if network is not None and address.version == network.version and address in network:
                candidates.append((network.prefixlen, item))
        return max(candidates, default=(None, None), key=lambda value: value[0])[1]

    truncated = False
    if {"saved_networks", "saved_network_scope_associations"} <= tables:
        query = f"""
            SELECT a.scope_id, sn.name, sn.cidr
              FROM saved_network_scope_associations a
              JOIN saved_networks sn ON sn.saved_network_id = a.saved_network_id
             WHERE a.scope_id IN ({placeholders}) AND sn.active = 1
               AND NOT EXISTS (
                   SELECT 1 FROM saved_network_scope_associations successor
                    WHERE successor.predecessor_id = a.association_id
               )
             ORDER BY a.scope_id, sn.cidr, sn.name
             LIMIT ?
        """
        saved_rows = db.execute(
            query, (*scope_ids, OBSERVED_NETWORK_LIMIT + 1)
        ).fetchall()
        if len(saved_rows) > OBSERVED_NETWORK_LIMIT:
            truncated = True
            saved_rows = saved_rows[:OBSERVED_NETWORK_LIMIT]
        for row in saved_rows:
            network = _safe_network(row["cidr"])
            if network is not None:
                ensure(str(row["scope_id"]), network,
                       name=str(row["name"]), basis="saved_network")

    nmap_rows = []
    pending_nmap = []
    unmapped_nmap = 0
    unmapped_arkime = 0
    if "endpoint_entities" in tables:
        timestamp = "NULL AS observed_at"
        joins = ""
        current_assignment_where = ""
        if {"endpoint_receipts", "entity_assessments"} <= tables:
            timestamp = "MAX(COALESCE(ea.assessed_at, ea.recorded_at)) AS observed_at"
            joins = (
                " LEFT JOIN endpoint_receipts er ON er.host_id = e.entity_id"
                " LEFT JOIN entity_assessments ea ON ea.assessment_id = er.assessment_id"
            )
            if {
                "assessment_scope_assignment_links", "artifact_scope_assignments"
            } <= tables:
                joins += (
                    " JOIN assessment_scope_assignment_links asal"
                    " ON asal.assessment_id = ea.assessment_id"
                    " JOIN artifact_scope_assignments asa"
                    " ON asa.assignment_id = asal.assignment_id"
                )
                current_assignment_where = (
                    " AND NOT EXISTS (SELECT 1 FROM artifact_scope_assignments successor"
                    " WHERE successor.supersedes_assignment_id = asa.assignment_id)"
                )
        nmap_rows = db.execute(
            f"SELECT e.scope_id, e.address, {timestamp} FROM endpoint_entities e"
            f"{joins} WHERE e.scope_id IN ({placeholders})"
            f"{current_assignment_where}"
            " GROUP BY e.scope_id, e.address ORDER BY e.scope_id, e.address LIMIT ?",
            (*scope_ids, OBSERVATION_QUERY_LIMIT + 1),
        ).fetchall()
        if len(nmap_rows) > OBSERVATION_QUERY_LIMIT:
            truncated = True
            nmap_rows = nmap_rows[:OBSERVATION_QUERY_LIMIT]
        for row in nmap_rows:
            scope_id, address = str(row["scope_id"]), _safe_address(row["address"])
            if address is None:
                continue
            item = containing(scope_id, address)
            if item is None:
                pending_nmap.append((scope_id, address, row["observed_at"]))
                continue
            item["nmap_addresses"].add(str(address))
            observed_at = row["observed_at"]
            if observed_at and (not item["latest_nmap_at"] or observed_at > item["latest_nmap_at"]):
                item["latest_nmap_at"] = observed_at

    device_rows = []
    if {"device_interface_assessments", "device_interface_receipts"} <= tables:
        device_identity = (
            "COALESCE(NULLIF(dc.device_name, ''), NULLIF(dc.device_address, ''), a.run_id)"
            if "device_collections" in tables else "a.run_id"
        )
        device_address = (
            "COALESCE(NULLIF(dc.device_address, ''), r.address)"
            if "device_collections" in tables else "r.address"
        )
        device_join = (
            " LEFT JOIN device_collections dc ON dc.run_id = a.run_id"
            if "device_collections" in tables else ""
        )
        current_assignment_join = (
            " JOIN device_scope_assignments dsa ON dsa.assignment_id = a.assignment_id"
            if "device_scope_assignments" in tables else ""
        )
        current_assignment_where = (
            " AND NOT EXISTS (SELECT 1 FROM device_scope_assignments successor"
            " WHERE successor.supersedes_assignment_id = dsa.assignment_id)"
            if "device_scope_assignments" in tables else ""
        )
        device_rows = db.execute(
            f"""SELECT a.scope_id, a.run_id, a.recorded_at, r.address,
                       r.prefix_length, r.address_family,
                       {device_identity} AS device_label,
                       {device_address} AS device_address
                  FROM device_interface_assessments a
                  JOIN device_interface_receipts r ON r.assessment_id = a.assessment_id
                  {current_assignment_join}
                  {device_join}
                 WHERE a.scope_id IN ({placeholders})
                  {current_assignment_where}
                 ORDER BY a.scope_id, a.recorded_at DESC, r.address LIMIT ?""",
            (*scope_ids, OBSERVATION_QUERY_LIMIT + 1),
        ).fetchall()
        if len(device_rows) > OBSERVATION_QUERY_LIMIT:
            truncated = True
            device_rows = device_rows[:OBSERVATION_QUERY_LIMIT]
        for row in device_rows:
            scope_id, address = str(row["scope_id"]), _safe_address(row["address"])
            if address is None:
                continue
            try:
                network = ipaddress.ip_network(
                    f"{address}/{int(row['prefix_length'])}", strict=False
                )
            except (TypeError, ValueError):
                continue
            item = rows.get((scope_id, str(network))) or containing(scope_id, address)
            if item is None:
                item = ensure(scope_id, network, name="Device-identified network",
                              basis="device_identified")
            item["device_addresses"].add(str(address))
            item["device_runs"].add(str(row["run_id"]))
            item["device_labels"].add(str(row["device_label"]))
            item.setdefault("device_sources", {})[str(row["run_id"])] = {
                "run_id": str(row["run_id"]),
                "label": str(row["device_label"]),
                "address": str(row["device_address"] or row["address"]),
                "source_url": f"/device-config?run={row['run_id']}#deviceHistory",
            }
            recorded_at = row["recorded_at"]
            if recorded_at and (not item["latest_device_at"] or recorded_at > item["latest_device_at"]):
                item["latest_device_at"] = recorded_at

    for scope_id, address, observed_at in pending_nmap:
        item = containing(scope_id, address)
        if item is None:
            unmapped_nmap += 1
            continue
        item["nmap_addresses"].add(str(address))
        if observed_at and (not item["latest_nmap_at"] or observed_at > item["latest_nmap_at"]):
            item["latest_nmap_at"] = observed_at

    arkime_rows = []
    for imports, receipts in (
        ("arkime_imports", "arkime_session_receipts"),
        ("arkime_summary_imports", "arkime_summary_receipts"),
    ):
        if {imports, receipts} <= tables:
            arkime_rows.extend(db.execute(
                f"""SELECT i.scope_id, i.import_id, i.imported_at,
                            r.source_ip, r.destination_ip
                       FROM {imports} i JOIN {receipts} r ON r.import_id = i.import_id
                      WHERE i.scope_id IN ({placeholders})
                      ORDER BY i.scope_id, i.imported_at DESC LIMIT ?""",
                (*scope_ids, OBSERVATION_QUERY_LIMIT + 1),
            ).fetchall())
    if len(arkime_rows) > OBSERVATION_QUERY_LIMIT:
        truncated = True
        arkime_rows = arkime_rows[:OBSERVATION_QUERY_LIMIT]
    for row in arkime_rows:
        scope_id = str(row["scope_id"])
        for field in ("source_ip", "destination_ip"):
            address = _safe_address(row[field])
            if address is None:
                continue
            item = containing(scope_id, address)
            if item is None:
                unmapped_arkime += 1
                continue
            item["arkime_addresses"].add(str(address))
            item["arkime_imports"].add(str(row["import_id"]))
            imported_at = row["imported_at"]
            if imported_at and (not item["latest_arkime_at"] or imported_at > item["latest_arkime_at"]):
                item["latest_arkime_at"] = imported_at

    result = []
    for item in rows.values():
        nmap_addresses = item.pop("nmap_addresses")
        device_address_values = item.pop("device_addresses")
        arkime_addresses = item.pop("arkime_addresses")
        nmap = len(nmap_addresses)
        device_addresses = len(device_address_values)
        device_runs = len(item.pop("device_runs"))
        device_labels = sorted(item.pop("device_labels"), key=str.casefold)
        device_sources = sorted(
            item.pop("device_sources", {}).values(),
            key=lambda value: (value["label"].casefold(), value["address"], value["run_id"]),
        )
        device_identities = {
            (source["label"].casefold(), source["address"])
            if source["address"] else ("run", source["run_id"])
            for source in device_sources
        }
        arkime = len(arkime_addresses)
        arkime_imports = len(item.pop("arkime_imports"))
        if nmap and arkime:
            visibility = "Active and passive evidence retained"
        elif nmap:
            visibility = "Nmap evidence retained; no matching Arkime address observed"
        elif arkime:
            visibility = "Arkime evidence retained; no active Nmap assessment retained"
        elif device_runs:
            visibility = "Device-declared network; no host or passive observation retained"
        else:
            visibility = "Defined network; no retained visibility"
        blind_spots = []
        if not nmap:
            blind_spots.append("No retained Nmap host observation")
        if not arkime:
            blind_spots.append("No retained Arkime address observation")
        else:
            blind_spots.append(
                "Arkime observations show partial visibility, not full subnet coverage"
            )
        if not device_runs:
            blind_spots.append("No retained device interface evidence")
        item.update({
            "nmap_address_count": nmap,
            "device_address_count": device_addresses,
            "device_collection_count": device_runs,
            "network_device_count": len(device_identities),
            "network_devices": device_labels[:25],
            "network_device_sources": device_sources[:25],
            "network_devices_truncated": len(device_labels) > 25,
            "arkime_address_count": arkime,
            "arkime_import_count": arkime_imports,
            "reported_address_count": len(
                nmap_addresses | device_address_values | arkime_addresses
            ),
            # Compatibility field retained for older clients; this is an address
            # count and must never be described as physical host identity.
            "observed_host_count": len(
                nmap_addresses | device_address_values | arkime_addresses
            ),
            "visibility": visibility,
            "blind_spots": blind_spots,
        })
        result.append(item)

    def row_key(item):
        network = _safe_network(item["network"])
        return (
            str(item["scope_label"]).casefold(),
            network.version if network else 99,
            int(network.network_address) if network else 0,
            -(network.prefixlen if network else 0),
        )

    result.sort(key=row_key)
    if len(result) > OBSERVED_NETWORK_LIMIT:
        truncated = True
        result = result[:OBSERVED_NETWORK_LIMIT]
    return result, {
        "truncated": truncated,
        "source_row_limit": OBSERVATION_QUERY_LIMIT,
        "network_row_limit": OBSERVED_NETWORK_LIMIT,
        "read_only": True,
        "authorization_effect": "none",
        "unmapped_nmap_address_count": unmapped_nmap,
        "unmapped_arkime_address_count": unmapped_arkime,
    }


def _latest_special_role_records(db: sqlite3.Connection) -> list[dict]:
    """Read append-only role declarations without changing their operator meaning."""
    if db.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='app_settings'"
    ).fetchone() is None:
        return []
    latest: dict[str, dict] = {}
    identity_length = len(SPECIAL_ROLE_KEY_PREFIX) + 32
    rows = db.execute(
        """SELECT current.key, current.value_json
             FROM app_settings current
            WHERE current.key LIKE ?
              AND NOT EXISTS (
                  SELECT 1 FROM app_settings successor
                   WHERE successor.key LIKE substr(current.key, 1, ?) || ':%'
                     AND successor.key > current.key
              )
            ORDER BY current.key LIMIT ?""",
        (
            f"{SPECIAL_ROLE_KEY_PREFIX}%", identity_length,
            SPECIAL_ROLE_DECLARATION_LIMIT,
        ),
    ).fetchall()
    for row in rows:
        try:
            value = json.loads(row["value_json"])
        except (TypeError, json.JSONDecodeError):
            continue
        if not isinstance(value, dict):
            continue
        role_id = str(value.get("role_id") or "")
        version = value.get("version")
        if not role_id or isinstance(version, bool) or not isinstance(version, int):
            continue
        current = latest.get(role_id)
        if current is None or version > int(current.get("version") or 0):
            latest[role_id] = value
    return list(latest.values())


def list_active_special_device_roles(db_path: Path) -> list[dict]:
    """Return bounded, scope-labelled operator declarations without assessing evidence."""
    if not db_path.is_file():
        return []
    with connect_database(db_path, read_only=True) as db:
        db.row_factory = sqlite3.Row
        tables = {
            str(row[0]) for row in db.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        if not {"app_settings", "network_scopes"} <= tables:
            return []
        scopes = {
            str(row["scope_id"]): str(row["label"])
            for row in db.execute(
                "SELECT scope_id, label FROM network_scopes WHERE active = 1"
            ).fetchall()
        }
        results = []
        for record in _latest_special_role_records(db):
            scope_id = str(record.get("scope_id") or "")
            if not record.get("active", True) or scope_id not in scopes:
                continue
            role_key = str(record.get("role_key") or "")
            if role_key not in SPECIAL_ROLE_KEYS:
                continue
            results.append({
                **record,
                "scope_label": scopes[scope_id],
                "role_label": (
                    str(record.get("custom_role") or "Other local role")
                    if role_key == "other" else SPECIAL_ROLE_LABELS[role_key]
                ),
            })
    return sorted(results, key=lambda item: (
        item["scope_label"].casefold(), item["role_label"].casefold(), item["address"]
    ))


def _special_role_evidence(
    db: sqlite3.Connection, *, scope_ids: set[str], tables: set[str]
) -> tuple[dict[tuple[str, str], dict], list[dict], bool]:
    """Build bounded retained signals. These signals never prove a live role."""
    evidence: dict[tuple[str, str], dict] = {}
    truncated = False

    def columns(table: str) -> set[str]:
        return {str(row[1]) for row in db.execute(f"PRAGMA table_info({table})").fetchall()}

    def item(scope_id: str, address: str) -> dict:
        return evidence.setdefault((scope_id, address), {
            "open_services": {}, "traffic_ports": {}, "config_sources": {},
            "latest_evidence_at": None,
        })

    def latest(target: dict, value: object) -> None:
        timestamp = str(value or "")
        if timestamp and (not target["latest_evidence_at"] or timestamp > target["latest_evidence_at"]):
            target["latest_evidence_at"] = timestamp

    if scope_ids:
        placeholders = ",".join("?" for _ in scope_ids)
        args = tuple(sorted(scope_ids))
        if {"endpoint_entities", "service_entities", "service_receipts", "entity_assessments"} <= tables:
            assignment_joins = ""
            current_assignment_where = ""
            assignment_select = "NULL AS assignment_id,"
            if {
                "assessment_scope_assignment_links", "artifact_scope_assignments"
            } <= tables:
                assignment_joins = (
                    " JOIN assessment_scope_assignment_links asal"
                    " ON asal.assessment_id = a.assessment_id"
                    " JOIN artifact_scope_assignments asa"
                    " ON asa.assignment_id = asal.assignment_id"
                )
                current_assignment_where = (
                    " AND NOT EXISTS (SELECT 1 FROM artifact_scope_assignments successor"
                    " WHERE successor.supersedes_assignment_id = asa.assignment_id)"
                )
                assignment_select = "asal.assignment_id AS assignment_id,"
            rows = db.execute(
                f"""SELECT e.scope_id, e.address, s.protocol, s.port,
                            r.facts_json, a.assessed_at, a.recorded_at,
                            a.artifact_observation_id, a.assessment_id,
                            s.entity_id AS service_id, {assignment_select}
                            e.entity_id AS endpoint_id
                       FROM endpoint_entities e
                       JOIN service_entities s ON s.host_id = e.entity_id
                       JOIN service_receipts r ON r.service_id = s.entity_id
                       JOIN entity_assessments a ON a.assessment_id = r.assessment_id
                       {assignment_joins}
                      WHERE e.scope_id IN ({placeholders})
                       {current_assignment_where}
                      ORDER BY a.recorded_at DESC LIMIT ?""",
                (*args, OBSERVATION_QUERY_LIMIT + 1),
            ).fetchall()
            if len(rows) > OBSERVATION_QUERY_LIMIT:
                truncated = True
                rows = rows[:OBSERVATION_QUERY_LIMIT]
            for row in rows:
                try:
                    facts = json.loads(row["facts_json"])
                except (TypeError, json.JSONDecodeError):
                    continue
                if str(facts.get("state") or "").lower() != "open":
                    continue
                target = item(str(row["scope_id"]), str(row["address"]))
                key = (str(row["protocol"]).casefold(), int(row["port"]))
                signal = target["open_services"].setdefault(key, {
                    "protocol": key[0], "port": key[1],
                    "service": str(facts.get("service") or facts.get("name") or ""),
                    "product": str(facts.get("product") or ""),
                    "source": "Nmap retained service receipt",
                    "source_url": "/analysis#networkChangesPanel",
                    "observed_at": row["assessed_at"] or row["recorded_at"],
                    "observations": [],
                })
                assessment_id = str(row["assessment_id"])
                assignment_id = str(row["assignment_id"] or "")
                endpoint_id = str(row["endpoint_id"])
                source_url = (
                    "/api/foundation-evidence/scopes/"
                    f"{row['scope_id']}/endpoints/{endpoint_id}/assignments/"
                    f"{assignment_id}/assessments/{assessment_id}/services"
                    if assignment_id else "/analysis#networkChangesPanel"
                )
                observation = {
                    "assessment_id": assessment_id,
                    "service_id": str(row["service_id"]),
                    "artifact_observation_id": str(row["artifact_observation_id"] or ""),
                    "assignment_id": assignment_id or None,
                    "source_url": source_url,
                    "observed_at": row["assessed_at"] or row["recorded_at"],
                }
                if observation not in signal["observations"]:
                    signal["observations"].append(observation)
                signal["source_url"] = source_url
                latest(target, row["assessed_at"] or row["recorded_at"])

        arkime_columns = columns("arkime_session_receipts") if "arkime_session_receipts" in tables else set()
        if (
            {"arkime_imports", "arkime_session_receipts"} <= tables
            and {
                "source_ip", "source_port", "destination_ip", "destination_port",
                "transport", "applications_json", "first_packet", "last_packet",
            } <= arkime_columns
        ):
            receipt_select = "r.receipt_id," if "receipt_id" in arkime_columns else "NULL AS receipt_id,"
            session_select = "r.session_id," if "session_id" in arkime_columns else "NULL AS session_id,"
            rows = db.execute(
                f"""SELECT i.scope_id, i.import_id, i.imported_at,
                            {receipt_select} {session_select}
                            r.source_ip, r.source_port, r.destination_ip,
                            r.destination_port, r.transport, r.applications_json,
                            r.first_packet, r.last_packet
                       FROM arkime_imports i
                       JOIN arkime_session_receipts r ON r.import_id = i.import_id
                      WHERE i.scope_id IN ({placeholders})
                      ORDER BY i.imported_at DESC LIMIT ?""",
                (*args, OBSERVATION_QUERY_LIMIT + 1),
            ).fetchall()
            if len(rows) > OBSERVATION_QUERY_LIMIT:
                truncated = True
                rows = rows[:OBSERVATION_QUERY_LIMIT]
            for row in rows:
                for side, address_field, port_field in (
                    ("destination", "destination_ip", "destination_port"),
                    ("source", "source_ip", "source_port"),
                ):
                    address, port = str(row[address_field] or ""), row[port_field]
                    if not address or port is None:
                        continue
                    target = item(str(row["scope_id"]), address)
                    key = (str(row["transport"] or "unknown").casefold(), int(port), side)
                    signal = target["traffic_ports"].setdefault(key, {
                        "transport": key[0], "port": key[1], "side": side,
                        "session_count": 0, "observation_count": 0,
                        "duplicate_observation_count": 0,
                        "applications": set(), "observations": [],
                        "source": "Arkime retained session receipts",
                        "source_url": f"/arkime?analyze={row['import_id']}#arkimeTrafficAnalysis",
                        "first_packet": row["first_packet"],
                        "last_packet": row["last_packet"],
                    })
                    # Preserve every retained receipt in this role-assessment view.
                    # A session identifier is not complete identity by itself: two
                    # sensors can report the same identifier and retained records can
                    # conflict. Verified exact-stream deduplication belongs to Arkime
                    # Communication History, where dataset and source-node identity
                    # are available together with the session identifier.
                    session_id = str(row["session_id"] or "").strip()
                    signal["observation_count"] += 1
                    signal["session_count"] += 1
                    observation = {
                        "import_id": str(row["import_id"]),
                        "receipt_id": str(row["receipt_id"] or "") or None,
                        "session_id": session_id or None,
                        "source_url": f"/arkime?analyze={row['import_id']}#arkimeTrafficAnalysis",
                        "first_packet": row["first_packet"],
                        "last_packet": row["last_packet"],
                        "duplicate_of_retained_session": False,
                    }
                    signal["observations"].append(observation)
                    try:
                        signal["applications"].update(json.loads(row["applications_json"] or "[]"))
                    except (TypeError, json.JSONDecodeError):
                        pass
                    if str(row["first_packet"] or "") < str(signal["first_packet"] or ""):
                        signal["first_packet"] = row["first_packet"]
                    if str(row["last_packet"] or "") > str(signal["last_packet"] or ""):
                        signal["last_packet"] = row["last_packet"]
                    latest(target, row["last_packet"] or row["imported_at"])

        if {"device_interface_assessments", "device_interface_receipts"} <= tables:
            joins = ""
            collection_columns = columns("device_collections") if "device_collections" in tables else set()
            if "device_collections" in tables:
                joins += " LEFT JOIN device_collections dc ON dc.run_id = a.run_id"
                label = "COALESCE(NULLIF(dc.device_name,''), NULLIF(dc.device_address,''), a.run_id)"
                device_type = (
                    "COALESCE(NULLIF(dc.device_type,''), '')"
                    if "device_type" in collection_columns else "''"
                )
            else:
                label, device_type = "a.run_id", "''"
            assessment_columns = columns("device_interface_assessments")
            if "device_scope_assignments" in tables and "assignment_id" in assessment_columns:
                joins += " JOIN device_scope_assignments dsa ON dsa.assignment_id = a.assignment_id"
                current = (
                    " AND NOT EXISTS (SELECT 1 FROM device_scope_assignments successor"
                    " WHERE successor.supersedes_assignment_id = dsa.assignment_id)"
                )
            else:
                current = ""
            rows = db.execute(
                f"""SELECT a.scope_id, a.run_id, a.recorded_at, r.address,
                            {label} AS device_label, {device_type} AS device_type
                       FROM device_interface_assessments a
                       JOIN device_interface_receipts r ON r.assessment_id = a.assessment_id
                       {joins}
                      WHERE a.scope_id IN ({placeholders}) {current}
                      ORDER BY a.recorded_at DESC LIMIT ?""",
                (*args, OBSERVATION_QUERY_LIMIT + 1),
            ).fetchall()
            if len(rows) > OBSERVATION_QUERY_LIMIT:
                truncated = True
                rows = rows[:OBSERVATION_QUERY_LIMIT]
            for row in rows:
                target = item(str(row["scope_id"]), str(row["address"]))
                target["config_sources"].setdefault(str(row["run_id"]), {
                    "run_id": str(row["run_id"]),
                    "label": str(row["device_label"]),
                    "device_type": str(row["device_type"]),
                    "recorded_at": row["recorded_at"],
                    "source_url": f"/device-config?run={row['run_id']}#deviceHistory",
                })
                latest(target, row["recorded_at"])

    candidates = [
        {"scope_id": scope_id, "address": address}
        for scope_id, address in sorted(evidence)
    ][:1000]
    if len(evidence) > 1000:
        truncated = True
    return evidence, candidates, truncated


def _assess_special_role(declaration: dict, evidence: dict) -> dict:
    role_key = str(declaration["role_key"])
    declared_ports = list(declaration.get("declared_ports") or [])
    declared_services = [
        str(value).casefold() for value in declaration.get("declared_services") or []
    ]
    declared_port_pairs = {
        (value.rsplit("/", 1)[1], int(value.rsplit("/", 1)[0]))
        for value in declared_ports
    }
    expected = SPECIAL_ROLE_PROTOCOL_PORTS.get(role_key, set()) | declared_port_pairs
    services = list(evidence.get("open_services", {}).values())
    traffic = list(evidence.get("traffic_ports", {}).values())
    configs = list(evidence.get("config_sources", {}).values())
    service_protocol_ports = {
        (str(item.get("protocol") or "").casefold(), int(item["port"]))
        for item in services
    }
    traffic_protocol_ports = {
        (str(item.get("transport") or "").casefold(), int(item["port"]))
        for item in traffic
    }
    service_match_pairs = expected & service_protocol_ports
    traffic_match_pairs = expected & traffic_protocol_ports
    service_matches = sorted(f"{port}/{protocol}" for protocol, port in service_match_pairs)
    traffic_matches = sorted({
        f"{item['port']}/{str(item.get('transport') or '').casefold()} ({item['side']})"
        for item in traffic
        if (str(item.get("transport") or "").casefold(), int(item["port"])) in expected
    })
    declared_service_matches = sorted({
        declared
        for declared in declared_services
        if any(
            declared in " ".join((
                str(item.get("service") or ""), str(item.get("product") or "")
            )).casefold()
            for item in services
        )
    })
    declared_port_service_matches = sorted({
        f"{port}/{protocol}" for protocol, port in declared_port_pairs
        if (protocol, port) in {
            (str(item.get("protocol") or "").casefold(), int(item["port"]))
            for item in services
        }
    })
    declared_port_traffic_matches = sorted({
        f"{port}/{protocol}" for protocol, port in declared_port_pairs
        if (protocol, port) in {
            (str(item.get("transport") or "").casefold(), int(item["port"]))
            for item in traffic
        }
    })
    status = "not_assessed"
    explanation = "No assessment rule exists for this custom role."
    if role_key == "other":
        if not declared_ports and not declared_services:
            explanation = "No known ports or service names were supplied for evidence comparison."
        elif (
            (declared_port_service_matches or declared_service_matches)
            and declared_port_traffic_matches
        ):
            status = "evidence_consistent"
            explanation = "Retained service evidence and passive traffic are consistent with the operator-supplied identifier details."
        elif (
            declared_port_service_matches or declared_port_traffic_matches
            or declared_service_matches
        ):
            status = "some_supporting_evidence"
            explanation = "Some retained evidence matches the operator-supplied ports or service names; this supports review but does not prove the declared function."
        else:
            status = "insufficient_evidence"
            explanation = "No retained evidence matches the operator-supplied ports or service names; missing evidence does not disprove the declaration."
    elif role_key == "default_gateway":
        routing_configs = [
            item for item in configs
            if str(item.get("device_type") or "").casefold()
            in {"router", "firewall", "router+firewall"}
            or "router" in str(item.get("device_type") or "").casefold()
            or "firewall" in str(item.get("device_type") or "").casefold()
        ]
        if routing_configs:
            status = "some_supporting_evidence"
            explanation = "Retained configuration identifies this address on a router or firewall; that supports review but does not prove it is the default gateway."
        elif configs:
            status = "insufficient_evidence"
            explanation = "Configuration evidence identifies the address, but does not establish a default-gateway role."
        else:
            status = "insufficient_evidence"
            explanation = "No retained configuration evidence currently supports a gateway assessment."
    elif role_key == "directory_controller":
        directory_ports = {88, 389, 445, 636, 3268, 3269}
        strong = len(service_match_pairs) >= 2 and bool({
            port for _protocol, port in service_match_pairs
        } & directory_ports)
        if strong and traffic_matches:
            status = "evidence_consistent"
            explanation = "Several retained directory-related services and matching passive traffic are consistent with the declaration."
        elif service_matches or traffic_matches:
            status = "some_supporting_evidence"
            explanation = "Some directory-related ports or traffic were retained, but the evidence is not sufficient to establish a domain-controller role."
        else:
            status = "insufficient_evidence"
            explanation = "No retained directory-specific signal is available; absence of evidence does not disprove the declaration."
    elif not expected:
        status = "not_assessed"
        explanation = "This role has no reliable generic port rule. Review the declaration and any operator-supplied ports or services directly."
    elif service_matches and traffic_matches:
        status = "evidence_consistent"
        explanation = "A retained service receipt and passive traffic on a role-related port are consistent with the declaration."
    elif service_matches or traffic_matches:
        status = "some_supporting_evidence"
        explanation = "One retained evidence type has a role-related signal; this supports review but does not prove the device function."
    else:
        status = "insufficient_evidence"
        explanation = "No role-related port or traffic signal is retained; missing evidence does not disprove the declaration."
    return {
        "status": status,
        "status_label": {
            "evidence_consistent": "Evidence consistent with declaration",
            "some_supporting_evidence": "Some supporting evidence",
            "insufficient_evidence": "Not enough retained evidence",
            "not_assessed": "Not assessed",
        }[status],
        "explanation": explanation,
        "service_matches": service_matches,
        "traffic_matches": traffic_matches,
        "declared_port_service_matches": declared_port_service_matches,
        "declared_port_traffic_matches": declared_port_traffic_matches,
        "declared_service_matches": declared_service_matches,
        "open_services": services[:25],
        "traffic_signals": [
            {
                **dict(item),
                "applications": sorted(item["applications"], key=str.casefold),
            }
            for item in sorted(
                traffic,
                key=lambda value: (
                    int(value.get("port") or 0), str(value.get("transport") or ""),
                    str(value.get("side") or ""),
                ),
            )[:25]
        ],
        "configuration_sources": configs[:25],
        "latest_evidence_at": evidence.get("latest_evidence_at"),
        "assessment_version": SPECIAL_ROLE_ASSESSMENT_VERSION,
        "declaration_version": int(declaration["version"]),
        "limitations": [
            "Retained evidence is not a live network test.",
            "Ports and traffic patterns support review but do not prove a device role.",
            "Missing or partial evidence cannot disprove the declared role.",
        ],
    }


def _special_role_supporting_sources(
    role_key: str, assessment: dict, evidence: dict,
) -> tuple[list[dict], int]:
    """Return only the retained receipts that produced this role-match result."""
    service_matches = set(assessment.get("service_matches") or []) | set(
        assessment.get("declared_port_service_matches") or []
    )
    traffic_matches = set(assessment.get("traffic_matches") or [])
    declared_traffic_matches = set(
        assessment.get("declared_port_traffic_matches") or []
    )
    declared_services = {
        str(value).casefold()
        for value in assessment.get("declared_service_matches") or []
    }
    sources: list[dict] = []

    for service in evidence.get("open_services", {}).values():
        protocol = str(service.get("protocol") or "").casefold()
        port = int(service.get("port") or 0)
        token = f"{port}/{protocol}"
        fingerprint = " ".join((
            str(service.get("service") or ""),
            str(service.get("product") or ""),
        )).casefold()
        if token not in service_matches and not any(
            value in fingerprint for value in declared_services
        ):
            continue
        for observation in service.get("observations") or []:
            sources.append({
                "source_kind": "Nmap",
                "label": f"Retained {token} service receipt",
                "source_url": str(
                    observation.get("source_url")
                    or service.get("source_url")
                    or "/analysis#networkChangesPanel"
                ),
                "observed_at": observation.get("observed_at"),
                "assessment_id": observation.get("assessment_id"),
                "artifact_observation_id": observation.get("artifact_observation_id"),
                "assignment_id": observation.get("assignment_id"),
                "service_id": observation.get("service_id"),
            })

    for signal in evidence.get("traffic_ports", {}).values():
        protocol = str(signal.get("transport") or "").casefold()
        port = int(signal.get("port") or 0)
        side = str(signal.get("side") or "")
        token = f"{port}/{protocol}"
        full_token = f"{token} ({side})"
        if full_token not in traffic_matches and token not in declared_traffic_matches:
            continue
        for observation in signal.get("observations") or []:
            sources.append({
                "source_kind": "Arkime",
                "label": f"Retained {full_token} session receipt",
                "source_url": str(
                    observation.get("source_url")
                    or signal.get("source_url")
                    or "/arkime#arkimeTrafficAnalysis"
                ),
                "observed_at": (
                    observation.get("last_packet")
                    or observation.get("first_packet")
                ),
                "import_id": observation.get("import_id"),
                "receipt_id": observation.get("receipt_id"),
                "session_id": observation.get("session_id"),
            })

    if role_key == "default_gateway":
        for source in evidence.get("config_sources", {}).values():
            sources.append({
                "source_kind": "Device configuration",
                "label": f"Retained configuration from {source.get('label') or source.get('run_id')}",
                "source_url": str(
                    source.get("source_url") or "/device-config#deviceHistory"
                ),
                "observed_at": source.get("recorded_at"),
                "run_id": source.get("run_id"),
            })

    unique: dict[tuple, dict] = {}
    for source in sources:
        key = (
            source.get("source_kind"), source.get("source_url"),
            source.get("assessment_id"), source.get("receipt_id"),
            source.get("run_id"), source.get("observed_at"),
        )
        unique.setdefault(key, source)
    ordered = sorted(
        unique.values(),
        key=lambda item: (
            str(item.get("observed_at") or ""),
            str(item.get("source_kind") or ""),
            str(item.get("source_url") or ""),
        ),
        reverse=True,
    )
    return ordered[:SPECIAL_ROLE_SUPPORTING_SOURCE_LIMIT], len(ordered)


def _special_roles_snapshot(
    db: sqlite3.Connection, *, scopes: list[sqlite3.Row], tables: set[str]
) -> tuple[list[dict], list[dict], list[dict], dict]:
    scope_by_id = {str(scope["scope_id"]): scope for scope in scopes}
    retained, address_candidates, truncated = _special_role_evidence(
        db, scope_ids=set(scope_by_id), tables=tables,
    )
    declarations = [
        item for item in _latest_special_role_records(db)
        if item.get("active", True) and str(item.get("scope_id") or "") in scope_by_id
    ]
    results = []
    for declaration in declarations:
        key = (str(declaration["scope_id"]), str(declaration["address"]))
        assessment = _assess_special_role(declaration, retained.get(key, {}))
        results.append({
            **declaration,
            "scope_label": str(scope_by_id[key[0]]["label"]),
            "role_label": (
                declaration.get("custom_role")
                if declaration["role_key"] == "other"
                else SPECIAL_ROLE_LABELS[declaration["role_key"]]
            ),
            "assessment": assessment,
        })

    # Recognition stays separate from an operator declaration.  Candidates are
    # limited to other addresses in the exact same scope whose retained
    # evidence supports the same role rules.  They are investigation leads;
    # this never creates or changes a role record.
    groups: dict[tuple[str, str, str], list[dict]] = {}
    for item in results:
        group_key = (
            str(item["scope_id"]), str(item["role_key"]),
            str(item.get("custom_role") or "").casefold(),
        )
        groups.setdefault(group_key, []).append(item)
    for (scope_id, _role_key, _custom_role), items in groups.items():
        declared_addresses = {str(item["address"]) for item in items}
        representative = items[0]
        candidates = []
        for (candidate_scope, address), candidate_evidence in retained.items():
            if candidate_scope != scope_id or address in declared_addresses:
                continue
            assessment = _assess_special_role(representative, candidate_evidence)
            if assessment["status"] not in {
                "evidence_consistent", "some_supporting_evidence",
            }:
                continue
            supporting_sources, supporting_source_count = _special_role_supporting_sources(
                str(representative["role_key"]), assessment, candidate_evidence,
            )
            candidates.append({
                "scope_id": scope_id,
                "scope_label": str(scope_by_id[scope_id]["label"]),
                "address": address,
                "status": assessment["status"],
                "status_label": assessment["status_label"],
                "explanation": assessment["explanation"],
                "service_matches": assessment["service_matches"],
                "traffic_matches": assessment["traffic_matches"],
                "open_services": assessment["open_services"],
                "traffic_signals": assessment["traffic_signals"],
                "latest_evidence_at": assessment["latest_evidence_at"],
                "supporting_sources": supporting_sources,
                "supporting_source_count": supporting_source_count,
                "supporting_sources_truncated": (
                    supporting_source_count > len(supporting_sources)
                ),
                "source_url": (
                    supporting_sources[0]["source_url"] if supporting_sources
                    else "/analysis#networkOverview"
                ),
                "recognition_only": True,
                "role_assignment_effect": "none",
            })
        candidates.sort(key=lambda item: (
            0 if item["status"] == "evidence_consistent" else 1,
            ipaddress.ip_address(item["address"]).version,
            int(ipaddress.ip_address(item["address"])),
        ))
        for item in items:
            item["possible_matches"] = candidates[:100]
            item["possible_matches_truncated"] = len(candidates) > 100

    declared_by_role: dict[tuple[str, str], set[str]] = {}
    for item in results:
        declared_by_role.setdefault(
            (str(item["scope_id"]), str(item["role_key"])), set()
        ).add(str(item["address"]))
    catalog = []
    for scope_id, scope in scope_by_id.items():
        for definition in _special_role_definition_snapshots():
            role_key = str(definition["role_key"])
            declared_addresses = declared_by_role.get((scope_id, role_key), set())
            matches = []
            if definition["assessment_support"] != "declaration_only":
                draft = {
                    "role_key": role_key,
                    "declared_ports": [],
                    "declared_services": [],
                    "version": 0,
                }
                for (candidate_scope, address), candidate_evidence in retained.items():
                    if candidate_scope != scope_id or address in declared_addresses:
                        continue
                    assessment = _assess_special_role(draft, candidate_evidence)
                    if assessment["status"] not in {
                        "evidence_consistent", "some_supporting_evidence",
                    }:
                        continue
                    supporting_sources, supporting_source_count = _special_role_supporting_sources(
                        role_key, assessment, candidate_evidence,
                    )
                    matches.append({
                        "scope_id": scope_id,
                        "scope_label": str(scope["label"]),
                        "address": address,
                        "status": assessment["status"],
                        "status_label": assessment["status_label"],
                        "explanation": assessment["explanation"],
                        "service_matches": assessment["service_matches"],
                        "traffic_matches": assessment["traffic_matches"],
                        "latest_evidence_at": assessment["latest_evidence_at"],
                        "supporting_sources": supporting_sources,
                        "supporting_source_count": supporting_source_count,
                        "supporting_sources_truncated": (
                            supporting_source_count > len(supporting_sources)
                        ),
                        "source_url": (
                            supporting_sources[0]["source_url"] if supporting_sources
                            else "/analysis#networkOverview"
                        ),
                        "recognition_only": True,
                        "role_assignment_effect": "none",
                    })
            matches.sort(key=lambda item: (
                0 if item["status"] == "evidence_consistent" else 1,
                ipaddress.ip_address(item["address"]).version,
                int(ipaddress.ip_address(item["address"])),
            ))
            catalog.append({
                **definition,
                "scope_id": scope_id,
                "scope_label": str(scope["label"]),
                "declared_address_count": len(declared_addresses),
                "possible_match_count": len(matches),
                "possible_matches": matches[:SPECIAL_ROLE_CATALOG_MATCH_LIMIT],
                "possible_matches_truncated": (
                    len(matches) > SPECIAL_ROLE_CATALOG_MATCH_LIMIT
                ),
            })
    results.sort(key=lambda item: (
        item["scope_label"].casefold(), item["role_label"].casefold(), item["address"]
    ))
    return results, address_candidates, catalog, {
        "read_only_assessment": True,
        "authorization_effect": "none",
        "assessment_version": SPECIAL_ROLE_ASSESSMENT_VERSION,
        "recommendation_effect": "none",
        "catalog_match_limit": SPECIAL_ROLE_CATALOG_MATCH_LIMIT,
        "truncated": truncated,
    }


def _validate_special_device_role_fields(
    *, scope_id: str, address: str, role_key: str, custom_role: str,
    device_label: str, actor: str, reason: str,
    declared_ports: list[str] | None = None,
    declared_services: list[str] | None = None,
) -> dict:
    scope_id = _text(scope_id, "scope_id", 200, required=True)
    try:
        address = str(ipaddress.ip_address(address.strip()))
    except (AttributeError, ValueError) as exc:
        raise ValueError("address must be one IPv4 or IPv6 address") from exc
    role_key = _enum(role_key, "role_key", SPECIAL_ROLE_KEYS)
    custom_role = _text(custom_role, "custom_role", 120)
    if role_key == "other" and not custom_role:
        raise ValueError("Enter the Specific Special Identifier")
    if role_key != "other":
        custom_role = ""
    port_values = []
    for raw in declared_ports or []:
        value = _text(raw, "declared_port", 16, required=True).casefold()
        match = re.fullmatch(r"([0-9]{1,5})/(tcp|udp|sctp)", value)
        if match is None or not 1 <= int(match.group(1)) <= 65535:
            raise ValueError("Known ports must use port/protocol, such as 443/tcp")
        canonical = f"{int(match.group(1))}/{match.group(2)}"
        if canonical not in port_values:
            port_values.append(canonical)
    if len(port_values) > 50:
        raise ValueError("Enter 50 or fewer known ports")
    service_values = []
    for raw in declared_services or []:
        value = _text(raw, "declared_service", 80, required=True)
        if value.casefold() not in {item.casefold() for item in service_values}:
            service_values.append(value)
    if len(service_values) > 50:
        raise ValueError("Enter 50 or fewer known service names")
    return {
        "scope_id": scope_id,
        "address": address,
        "role_key": role_key,
        "custom_role": custom_role,
        "device_label": _text(device_label, "device_label", 120),
        "declared_ports": port_values,
        "declared_services": service_values,
        "actor": _text(actor, "actor", 100, required=True),
        "reason": _text(reason, "reason", 500, required=True),
    }


def _validate_role_id(role_id: str) -> str:
    value = _text(role_id, "role_id", 32, required=True)
    if re.fullmatch(r"[0-9a-f]{32}", value) is None:
        raise ValueError("role_id is invalid")
    return value


def _insert_special_device_role_version(
    db: sqlite3.Connection, *, role_id: str, expected_version: int,
    fields: dict, active: bool = True,
) -> dict:
    current = next(
        (item for item in _latest_special_role_records(db) if item["role_id"] == role_id),
        None,
    )
    current_version = int(current.get("version") or 0) if current else 0
    if current_version != expected_version:
        raise MissionEnvironmentConflict("Special device role changed in another session")
    timestamp = _utc_now()
    record = {
        "role_id": role_id, "version": current_version + 1,
        "scope_id": fields["scope_id"], "address": fields["address"],
        "role_key": fields["role_key"], "custom_role": fields["custom_role"],
        "device_label": fields["device_label"], "active": active,
        "declared_ports": fields["declared_ports"],
        "declared_services": fields["declared_services"],
        "actor": fields["actor"], "reason": fields["reason"],
        "recorded_at": timestamp, "supersedes_version": current_version or None,
    }
    db.execute(
        "INSERT INTO app_settings(key, value_json, updated_at, updated_by) VALUES (?, ?, ?, ?)",
        (
            f"{SPECIAL_ROLE_KEY_PREFIX}{role_id}:{record['version']:012d}",
            json.dumps(record, sort_keys=True), timestamp, fields["actor"],
        ),
    )
    return record


def save_special_device_role(
    db_path: Path, *, role_id: str | None, expected_version: int, scope_id: str,
    address: str, role_key: str, custom_role: str, device_label: str,
    actor: str, reason: str,
    declared_ports: list[str] | None = None,
    declared_services: list[str] | None = None,
) -> dict:
    init_mission_environment_storage(db_path)
    fields = _validate_special_device_role_fields(
        scope_id=scope_id, address=address, role_key=role_key,
        custom_role=custom_role, device_label=device_label, actor=actor, reason=reason,
        declared_ports=declared_ports, declared_services=declared_services,
    )
    if isinstance(expected_version, bool) or not isinstance(expected_version, int) or expected_version < 0:
        raise ValueError("expected_version must be zero or greater")
    role_id = _validate_role_id(role_id) if role_id else uuid.uuid4().hex
    with connect_database(db_path) as db:
        db.row_factory = sqlite3.Row
        db.execute("BEGIN IMMEDIATE")
        scope = db.execute(
            "SELECT active FROM network_scopes WHERE scope_id = ?", (fields["scope_id"],)
        ).fetchone()
        if scope is None:
            raise KeyError("Network Scope not found")
        if not bool(scope["active"]):
            raise ValueError("Archived Network Scopes cannot receive role declarations")
        return _insert_special_device_role_version(
            db, role_id=role_id, expected_version=expected_version, fields=fields,
        )


def create_special_device_roles(
    db_path: Path, *, scope_id: str, addresses: list[str], role_key: str,
    custom_role: str, device_label: str, actor: str, reason: str,
    declared_ports: list[str] | None = None,
    declared_services: list[str] | None = None,
) -> list[dict]:
    """Create one independently traceable declaration per submitted address atomically."""
    init_mission_environment_storage(db_path)
    if not isinstance(addresses, list) or not addresses:
        raise ValueError("Enter at least one IPv4 or IPv6 address")
    if len(addresses) > SPECIAL_ROLE_BATCH_LIMIT:
        raise ValueError(f"Enter {SPECIAL_ROLE_BATCH_LIMIT} or fewer addresses at a time")
    validated = [
        _validate_special_device_role_fields(
            scope_id=scope_id, address=address, role_key=role_key,
            custom_role=custom_role, device_label=device_label, actor=actor, reason=reason,
            declared_ports=declared_ports, declared_services=declared_services,
        )
        for address in addresses
    ]
    if len({item["address"] for item in validated}) != len(validated):
        raise ValueError("Remove duplicate addresses from this role entry")
    with connect_database(db_path) as db:
        db.row_factory = sqlite3.Row
        db.execute("BEGIN IMMEDIATE")
        scope = db.execute(
            "SELECT active FROM network_scopes WHERE scope_id = ?", (validated[0]["scope_id"],)
        ).fetchone()
        if scope is None:
            raise KeyError("Network Scope not found")
        if not bool(scope["active"]):
            raise ValueError("Archived Network Scopes cannot receive role declarations")
        current = _latest_special_role_records(db)
        if len(current) + len(validated) > SPECIAL_ROLE_DECLARATION_LIMIT:
            raise ValueError(
                f"Special Device Roles supports at most {SPECIAL_ROLE_DECLARATION_LIMIT} active or retained role identities"
            )
        active_signatures = {
            (item.get("scope_id"), item.get("address"), item.get("role_key"), item.get("custom_role"))
            for item in current if item.get("active", True)
        }
        submitted = {
            (item["scope_id"], item["address"], item["role_key"], item["custom_role"])
            for item in validated
        }
        if active_signatures & submitted:
            raise MissionEnvironmentConflict(
                "One of these addresses already has this active role in the selected scope"
            )
        return [
            _insert_special_device_role_version(
                db, role_id=uuid.uuid4().hex, expected_version=0, fields=item,
            )
            for item in validated
        ]


def retire_special_device_role(
    db_path: Path, *, role_id: str, expected_version: int, actor: str, reason: str,
) -> dict:
    init_mission_environment_storage(db_path)
    role_id = _validate_role_id(role_id)
    actor = _text(actor, "actor", 100, required=True)
    reason = _text(reason, "reason", 500, required=True)
    with connect_database(db_path) as db:
        db.row_factory = sqlite3.Row
        db.execute("BEGIN IMMEDIATE")
        current = next(
            (item for item in _latest_special_role_records(db) if item["role_id"] == role_id),
            None,
        )
        if current is None:
            raise KeyError("Special device role not found")
        if int(current["version"]) != expected_version:
            raise MissionEnvironmentConflict("Special device role changed in another session")
        timestamp = _utc_now()
        record = {
            **current, "version": expected_version + 1, "active": False,
            "actor": actor, "reason": reason, "recorded_at": timestamp,
            "supersedes_version": expected_version,
        }
        db.execute(
            "INSERT INTO app_settings(key, value_json, updated_at, updated_by) VALUES (?, ?, ?, ?)",
            (
                f"{SPECIAL_ROLE_KEY_PREFIX}{role_id}:{record['version']:012d}",
                json.dumps(record, sort_keys=True), timestamp, actor,
            ),
        )
    return record


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
                "scopes": [], "scope_total": 0, "limit": limit, "offset": offset,
                "observed_networks": [], "observed_network_metadata": {"read_only": True},
                "special_role_definitions": _special_role_definition_snapshots(),
                "special_device_roles": [], "special_role_address_candidates": [],
                "special_role_catalog": [],
                "special_role_metadata": {"read_only_assessment": True}}
    with connect_database(db_path, read_only=True) as db:
        db.row_factory = sqlite3.Row
        # Keep scopes, declarations, and their retained evidence on one SQLite
        # snapshot even while another process records new evidence or corrections.
        db.execute("BEGIN")
        tables = {row[0] for row in db.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'").fetchall()}
        if "network_scopes" not in tables:
            return {"tools": [_default_tool(*item) for item in TOOL_DEFINITIONS],
                    "scopes": [], "scope_total": 0, "limit": limit, "offset": offset,
                    "observed_networks": [], "observed_network_metadata": {"read_only": True},
                    "special_role_definitions": _special_role_definition_snapshots(),
                    "special_device_roles": [], "special_role_address_candidates": [],
                    "special_role_catalog": [],
                    "special_role_metadata": {"read_only_assessment": True}}
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
        observed_networks, observed_metadata = _observed_environment_rows(
            db, scopes=list(scopes), tables=tables,
        )
        special_roles, role_candidates, role_catalog, role_metadata = _special_roles_snapshot(
            db, scopes=list(scopes), tables=tables,
        )
    return {
        "tools": [_tool_snapshot(tool_rows.get(key), key, label)
                  for key, label in TOOL_DEFINITIONS],
        "scopes": [_scope_snapshot(contexts.get(scope["scope_id"]), scope)
                   for scope in scopes],
        "scope_total": total, "limit": limit, "offset": offset,
        "observed_networks": observed_networks,
        "observed_network_metadata": observed_metadata,
        "special_role_definitions": _special_role_definition_snapshots(),
        "special_device_roles": special_roles,
        "special_role_address_candidates": role_candidates,
        "special_role_catalog": role_catalog,
        "special_role_metadata": role_metadata,
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
