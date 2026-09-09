from __future__ import annotations

import ipaddress
import hmac
import json
import os
import re
import shlex
import signal
import secrets
import socket
import sqlite3
import subprocess
import shutil
import threading
import time
import uuid
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Literal

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import FileResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.scan_profiles import (
    BUILTIN_PROFILES,
    build_nmap_flags,
    normalize_scan_options,
    scan_coverage,
    scan_display_name,
)

DATA_DIR = Path(os.environ.get("ANALYZER_DATA_DIR", "/data"))
DB_PATH = DATA_DIR / "analyzer.db"
RUNS_DIR_NAME = "scan-runs"
MAX_EXPANDED_ADDRESSES = 65536
MAX_ACTIVE_RUNS = 1
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
# A few early proof-of-concept imports were persisted with a truncated digest.
# Keep the normal SHA-256 validation strict for new artifacts, but allow the
# existing hex identifiers to be reopened and compared safely by exact DB key.
IMPORT_KEY_RE = re.compile(r"^[0-9a-f]{32,64}$")
RUN_ID_RE = re.compile(r"^[0-9a-f]{32}$")
INTERFACE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$")
LEGACY_PROFILE_IDS = {
    "standard": "builtin-standard",
    "comprehensive": "builtin-comprehensive",
}
ARTIFACT_FILES = {
    "manifest": ("manifest.json", "application/json"),
    "xml": ("scan.xml", "application/xml"),
    "stdout": ("stdout.txt", "text/plain"),
    "stderr": ("stderr.txt", "text/plain"),
    "pcap": ("capture.pcap", "application/vnd.tcpdump.pcap"),
    "capture_stderr": ("capture-stderr.txt", "text/plain"),
    "fping_alive": ("fping-alive.txt", "text/plain"),
    "fping_stderr": ("fping-stderr.txt", "text/plain"),
}

router = APIRouter(prefix="/api", tags=["poc"])


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


class ScanOptions(BaseModel):
    model_config = ConfigDict(extra="forbid")

    protocol: Literal["tcp", "udp", "tcp_udp"] = "tcp"
    tcp_scope: Literal["top_1000", "common", "ics", "custom", "all"] = "top_1000"
    tcp_ports: str = Field(default="", max_length=1000)
    udp_scope: Literal["top_100", "common", "ics", "custom", "all"] = "top_100"
    udp_ports: str = Field(default="", max_length=1000)
    service_detection: bool = True
    os_detection: bool = True
    timing: Literal["conservative", "normal", "fast"] = "fast"
    discovery_mode: Literal["nmap", "fping"] = "nmap"
    traceroute: bool = False

    def normalized(self) -> dict:
        return normalize_scan_options(self.model_dump())


class ScanProfileCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=100)
    description: str = Field(default="", max_length=500)
    created_by: str = Field(min_length=1, max_length=100)
    settings: ScanOptions

    @field_validator("name", "description", "created_by")
    @classmethod
    def clean_profile_text(cls, value: str) -> str:
        return value.strip()


class ScanProfileVersionCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    description: str = Field(default="", max_length=500)
    created_by: str = Field(min_length=1, max_length=100)
    settings: ScanOptions


class ScanProfileClone(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=100)
    description: str = Field(default="", max_length=500)
    created_by: str = Field(min_length=1, max_length=100)
    source_version: int | None = Field(default=None, ge=1)


class ScanScheduleCreate(BaseModel):
    """A version-pinned recurring or one-time scan schedule."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=100)
    created_by: str = Field(min_length=1, max_length=100)
    profile_id: str = Field(min_length=1, max_length=128)
    profile_version: int = Field(ge=1)
    targets: list[str] = Field(min_length=1)
    no_strike: list[str] = Field(default_factory=list)
    interface: str = Field(min_length=1, max_length=64)
    cadence: Literal[
        "once", "interval", "custom_hours", "hourly", "daily", "weekly"
    ] = "once"
    first_run_at: datetime
    cadence_hours: int = Field(default=2, ge=1, le=8760)
    # Retained so schedules created by earlier builds remain readable.
    interval_minutes: int = Field(default=60, ge=5, le=10080)
    reason: str = Field(default="Scheduled authorized characterization", min_length=1, max_length=500)
    originating_host: str = Field(default="scheduler", min_length=1, max_length=255)
    timeout_seconds: int = Field(default=900, ge=10, le=3600)
    chunk_size: int = Field(default=256, ge=1, le=4096)
    chunk_delay_seconds: int = Field(default=30, ge=0, le=3600)
    fallback_policy: Literal["require_approval", "stop_without_nmap"] = "require_approval"
    enabled: bool = False

    @field_validator("name", "created_by", "reason", "originating_host")
    @classmethod
    def clean_schedule_text(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("This field cannot be blank")
        return cleaned


class ScheduleStateChange(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool


class ScheduleProfileChange(BaseModel):
    model_config = ConfigDict(extra="forbid")

    profile_id: str = Field(min_length=1, max_length=128)
    profile_version: int = Field(ge=1)
    changed_by: str = Field(min_length=1, max_length=100)

    @field_validator("changed_by")
    @classmethod
    def clean_changed_by(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("The analyst changing the schedule is required")
        return cleaned


class ScanRunPlan(BaseModel):
    model_config = ConfigDict(extra="forbid")

    operator: str = Field(min_length=1, max_length=100)
    name: str = Field(default="Scan", min_length=1, max_length=100)
    reason: str = Field(min_length=1, max_length=500)
    originating_host: str = Field(min_length=1, max_length=255)
    interface: str = Field(min_length=1, max_length=64)
    profile: str = Field(default="standard", min_length=1, max_length=100)
    profile_id: str | None = Field(default=None, max_length=128)
    profile_version: int | None = Field(default=None, ge=1)
    scan_options: ScanOptions | None = None
    created_by: str | None = Field(default=None, max_length=100)
    scheduled: bool = False
    scheduled_by: str | None = Field(default=None, max_length=100)
    executed_by: str | None = Field(default=None, max_length=100)
    fallback_policy: Literal["require_approval", "stop_without_nmap"] = "require_approval"
    schedule_id: str | None = Field(default=None, max_length=32)
    schedule_batch_id: str | None = Field(default=None, max_length=32)
    chunk_number: int | None = Field(default=None, ge=1)
    chunk_count: int | None = Field(default=None, ge=1)
    chunk_delay_seconds: int | None = Field(default=None, ge=0, le=3600)
    targets: list[str] = Field(min_length=1)
    no_strike: list[str] = Field(default_factory=list)

    @field_validator("operator", "name", "reason", "originating_host", "interface", "profile")
    @classmethod
    def clean_required_text(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("This field cannot be blank")
        return value

    @field_validator("profile_id", "created_by", "scheduled_by", "executed_by")
    @classmethod
    def clean_optional_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = value.strip()
        return cleaned or None

    @field_validator("interface")
    @classmethod
    def validate_interface(cls, value: str) -> str:
        if not INTERFACE_RE.fullmatch(value):
            raise ValueError("Interface must be a simple local interface name")
        return value


class ScanRunRequest(ScanRunPlan):
    capture: Literal[True] = True
    timeout_seconds: int = Field(default=900, ge=10, le=3600)


class DeleteConfirmation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    confirmation: str = Field(min_length=1, max_length=64)


class NoStrikeUpdate(BaseModel):
    """Add entries to the persistent global no-strike safety list."""

    model_config = ConfigDict(extra="forbid")

    entries: list[str] = Field(min_length=1)
    changed_by: str = Field(min_length=1, max_length=100)

    @field_validator("changed_by")
    @classmethod
    def clean_no_strike_operator(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("The operator changing the no-strike list is required")
        return cleaned


class NoStrikeRemoval(NoStrikeUpdate):
    confirmation: str = Field(min_length=1, max_length=64)


class FallbackDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: Literal["approve", "decline"]
    decided_by: str = Field(min_length=1, max_length=100)
    authorization_note: str = Field(min_length=1, max_length=500)

    @field_validator("decided_by", "authorization_note")
    @classmethod
    def clean_fallback_text(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("This field cannot be blank")
        return cleaned


@dataclass
class RunControl:
    cancel_event: threading.Event = field(default_factory=threading.Event)
    discovery_process: object | None = None
    nmap_process: object | None = None
    capture_process: object | None = None
    fallback_decision_event: threading.Event = field(default_factory=threading.Event)
    fallback_decision: Literal["approve", "decline"] | None = None
    fallback_decided_by: str | None = None
    fallback_authorization_note: str | None = None


ACTIVE_RUNS: dict[str, RunControl] = {}
ACTIVE_RUNS_LOCK = threading.Lock()
ACTIVE_SCHEDULE_BATCHES: set[str] = set()
ACTIVE_SCHEDULE_BATCHES_LOCK = threading.Lock()
DELETE_CHALLENGES: dict[str, tuple[str, float]] = {}
DELETE_CHALLENGES_LOCK = threading.Lock()


def available_interfaces() -> set[str]:
    return {name for _, name in socket.if_nameindex() if name != "lo"}


def validate_runtime_interface(interface: str, interfaces: set[str] | None = None) -> None:
    allowed = available_interfaces() if interfaces is None else interfaces
    if interface not in allowed:
        raise ValueError(
            f"Interface {interface!r} is not available; choose one of: "
            + ", ".join(sorted(allowed))
        )


def normalize_ipv4_networks(entries: list[str], label: str) -> list[str]:
    networks: list[ipaddress.IPv4Network] = []
    for raw in entries:
        token = raw.strip()
        if not token:
            continue
        try:
            network = ipaddress.ip_network(token, strict=False)
        except ValueError as exc:
            raise ValueError(f"Invalid {label} entry: {token}") from exc
        if network.version != 4:
            raise ValueError(f"IPv6 is not supported in this POC: {token}")
        networks.append(network)
    if label == "target" and not networks:
        raise ValueError("At least one target is required")
    collapsed = list(ipaddress.collapse_addresses(networks))
    if sum(network.num_addresses for network in collapsed) > MAX_EXPANDED_ADDRESSES:
        raise ValueError(
            f"{label.title()} scope exceeds the {MAX_EXPANDED_ADDRESSES}-address safety limit"
        )
    return [str(network) for network in collapsed]


def get_global_no_strike(db_path: Path = DB_PATH) -> dict:
    """Return the protected no-strike list that applies to every scan path."""
    init_poc_storage(db_path)
    with sqlite3.connect(db_path) as db:
        row = db.execute(
            "SELECT value_json, updated_at, updated_by FROM app_settings WHERE key = ?",
            ("global_no_strike",),
        ).fetchone()
    if not row:
        return {"entries": [], "updated_at": None, "updated_by": None}
    return {
        "entries": json.loads(row[0]),
        "updated_at": row[1],
        "updated_by": row[2],
    }


def _store_global_no_strike(
    entries: list[str], changed_by: str, db_path: Path = DB_PATH
) -> dict:
    normalized = normalize_ipv4_networks(entries, "no-strike") if entries else []
    updated_at = utc_now()
    init_poc_storage(db_path)
    with sqlite3.connect(db_path) as db:
        db.execute(
            """
            INSERT INTO app_settings (key, value_json, updated_at, updated_by)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET
                value_json = excluded.value_json,
                updated_at = excluded.updated_at,
                updated_by = excluded.updated_by
            """,
            ("global_no_strike", json.dumps(normalized), updated_at, changed_by),
        )
    return {
        "entries": normalized,
        "updated_at": updated_at,
        "updated_by": changed_by,
    }


def add_global_no_strike(
    request: NoStrikeUpdate, db_path: Path = DB_PATH
) -> dict:
    current = get_global_no_strike(db_path)["entries"]
    return _store_global_no_strike(
        [*current, *request.entries], request.changed_by, db_path
    )


def effective_no_strike(
    additional: list[str] | None = None, db_path: Path = DB_PATH
) -> tuple[list[str], list[str]]:
    """Merge persistent exclusions with optional run-specific exclusions."""
    global_entries = get_global_no_strike(db_path)["entries"]
    combined = [*global_entries, *(additional or [])]
    return (
        normalize_ipv4_networks(combined, "no-strike") if combined else [],
        global_entries,
    )


def remove_global_no_strike(
    request: NoStrikeRemoval, db_path: Path = DB_PATH
) -> dict:
    requested = normalize_ipv4_networks(request.entries, "no-strike")
    current = get_global_no_strike(db_path)["entries"]
    missing = [entry for entry in requested if entry not in current]
    if missing:
        raise KeyError("No-strike entry not found: " + ", ".join(missing))
    identifier = ",".join(requested)
    if not consume_delete_challenge(
        "global-no-strike", identifier, request.confirmation
    ):
        raise PermissionError("The confirmation string is invalid or expired")
    remaining = [entry for entry in current if entry not in set(requested)]
    result = _store_global_no_strike(remaining, request.changed_by, db_path)
    result["removed"] = requested
    return result


def build_nmap_argv(
    profile: str,
    interface: str,
    *,
    include_no_strike: bool,
    scan_options: dict | None = None,
    target_file: str = "targets.txt",
) -> list[str]:
    if scan_options is None:
        profile_id = LEGACY_PROFILE_IDS.get(profile, profile)
        builtin = next(
            (item for item in BUILTIN_PROFILES if item["profile_id"] == profile_id),
            None,
        )
        if builtin is None:
            raise ValueError(f"Unknown scan profile: {profile}")
        scan_options = builtin["settings"]
    argv = ["nmap", *build_nmap_flags(scan_options), "-e", interface, "-iL", target_file]
    if include_no_strike:
        argv.extend(["--excludefile", "no-strike.txt"])
    argv.extend(["-oX", "scan.xml"])
    return argv


def build_fping_argv(interface: str) -> list[str]:
    """Build the optional fast discovery command from a pre-certified address list."""
    return ["fping", "-a", "-I", interface, "-f", "discovery-targets.txt"]


def expanded_discovery_targets(targets: list[str], no_strike: list[str]) -> list[str]:
    """Expand a bounded target scope while preserving no-strike exclusions."""
    excluded = [ipaddress.ip_network(item, strict=False) for item in no_strike]
    addresses: list[str] = []
    for raw in targets:
        network = ipaddress.ip_network(raw, strict=False)
        for address in network:
            if not any(address in blocked for blocked in excluded):
                addresses.append(str(address))
    return addresses


def apply_fping_fallback(manifest: dict) -> None:
    """Retarget Nmap when ICMP-only discovery cannot see approved hosts."""
    manifest["command_argv"] = build_nmap_argv(
        manifest["profile"],
        manifest["interface"],
        include_no_strike=bool(manifest.get("no_strike")),
        scan_options=manifest["profile_settings"],
        target_file="targets.txt",
    )
    manifest["exact_command"] = shlex.join(manifest["command_argv"])
    manifest["discovery_fallback_used"] = True


def build_tcpdump_argv(interface: str) -> list[str]:
    return [
        "tcpdump", "-i", interface, "-p", "-nn", "-U", "-s", "0",
        "-w", "capture.pcap",
    ]


def build_scan_run_manifest(
    plan: ScanRunPlan,
    *,
    capture: bool = False,
    timeout_seconds: int | None = None,
    status: str = "planned",
    db_path: Path = DB_PATH,
) -> dict:
    targets = normalize_ipv4_networks(plan.targets, "target")
    no_strike, global_no_strike = effective_no_strike(plan.no_strike, db_path)
    profile_record = resolve_scan_profile(plan, db_path)
    settings = profile_record["settings"]
    use_fping = settings.get("discovery_mode") == "fping"
    nmap_argv = build_nmap_argv(
        profile_record["name"],
        plan.interface,
        include_no_strike=bool(no_strike),
        scan_options=settings,
        target_file="fping-alive.txt" if use_fping else "targets.txt",
    )
    discovery_argv = build_fping_argv(plan.interface) if use_fping else None
    capture_argv = build_tcpdump_argv(plan.interface) if capture else None
    created_at = utc_now()
    creator = plan.created_by or plan.operator
    if plan.scheduled and not plan.scheduled_by:
        raise ValueError("Scheduled scans must retain the scheduler identity")
    display_name = scan_display_name(plan.name, scheduled=plan.scheduled)
    coverage = {
        **scan_coverage(settings),
        "targets": targets,
        "no_strike": no_strike,
        "global_no_strike": global_no_strike,
        "additional_no_strike": normalize_ipv4_networks(plan.no_strike, "no-strike") if plan.no_strike else [],
        "interface": plan.interface,
        "profile_id": profile_record["profile_id"],
        "profile_name": profile_record["name"],
        "profile_version": profile_record["version"],
    }
    return {
        "schema_version": 3,
        "run_id": uuid.uuid4().hex,
        "name": plan.name,
        "display_name": display_name,
        "created_at": created_at,
        "status": status,
        "operator": plan.operator,
        "created_by": creator,
        "scheduled": plan.scheduled,
        "scheduled_by": plan.scheduled_by,
        "executed_by": plan.executed_by or ("scheduler" if plan.scheduled else plan.operator),
        "execution_method": "scheduled" if plan.scheduled else "manual",
        "fallback_policy": plan.fallback_policy,
        "schedule_id": plan.schedule_id,
        "schedule_batch_id": plan.schedule_batch_id,
        "chunk_number": plan.chunk_number,
        "chunk_count": plan.chunk_count,
        "chunk_delay_seconds": plan.chunk_delay_seconds,
        "reason": plan.reason,
        "originating_host": plan.originating_host,
        "interface": plan.interface,
        "profile": profile_record["name"],
        "profile_id": profile_record["profile_id"],
        "profile_version": profile_record["version"],
        "profile_settings": settings,
        "targets": targets,
        "no_strike": no_strike,
        "coverage": coverage,
        "capture_requested": capture,
        "discovery_mode": settings.get("discovery_mode", "nmap"),
        "discovery_command_argv": discovery_argv,
        "exact_discovery_command": shlex.join(discovery_argv) if discovery_argv else None,
        "timeout_seconds": timeout_seconds,
        "command_argv": nmap_argv,
        "exact_command": shlex.join(nmap_argv),
        "capture_command_argv": capture_argv,
        "exact_capture_command": shlex.join(capture_argv) if capture_argv else None,
        "artifacts": [],
    }


def init_poc_storage(db_path: Path = DB_PATH) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(db_path) as db:
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_runs (
                run_id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                status TEXT NOT NULL,
                operator_name TEXT NOT NULL,
                reason TEXT NOT NULL,
                originating_host TEXT NOT NULL,
                interface_name TEXT NOT NULL,
                profile TEXT NOT NULL,
                manifest_json TEXT NOT NULL
            )
            """
        )
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_profiles (
                profile_id TEXT NOT NULL,
                version INTEGER NOT NULL,
                name TEXT NOT NULL,
                description TEXT NOT NULL,
                built_in INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                created_by TEXT NOT NULL,
                source_profile_id TEXT,
                source_profile_version INTEGER,
                settings_json TEXT NOT NULL,
                PRIMARY KEY (profile_id, version)
            )
            """
        )
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_schedules (
                schedule_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                created_at TEXT NOT NULL,
                created_by TEXT NOT NULL,
                profile_id TEXT NOT NULL,
                profile_version INTEGER NOT NULL,
                definition_json TEXT NOT NULL,
                FOREIGN KEY (profile_id, profile_version)
                    REFERENCES scan_profiles(profile_id, version)
            )
            """
        )
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS app_settings (
                key TEXT PRIMARY KEY,
                value_json TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                updated_by TEXT NOT NULL
            )
            """
        )
        for profile in BUILTIN_PROFILES:
            db.execute(
                """
                INSERT OR IGNORE INTO scan_profiles (
                    profile_id, version, name, description, built_in,
                    created_at, created_by, source_profile_id,
                    source_profile_version, settings_json
                ) VALUES (?, 1, ?, ?, 1, ?, 'system', NULL, NULL, ?)
                """,
                (
                    profile["profile_id"],
                    profile["name"],
                    profile["description"],
                    utc_now(),
                    json.dumps(normalize_scan_options(profile["settings"]), sort_keys=True),
                ),
            )


def _profile_record(row: tuple | None) -> dict | None:
    if row is None:
        return None
    return {
        "profile_id": row[0],
        "version": row[1],
        "name": row[2],
        "description": row[3],
        "built_in": bool(row[4]),
        "created_at": row[5],
        "created_by": row[6],
        "source_profile_id": row[7],
        "source_profile_version": row[8],
        "settings": normalize_scan_options(json.loads(row[9])),
    }


def get_scan_profile(
    profile_id: str,
    version: int | None = None,
    db_path: Path = DB_PATH,
) -> dict | None:
    init_poc_storage(db_path)
    with sqlite3.connect(db_path) as db:
        if version is None:
            row = db.execute(
                """
                SELECT profile_id, version, name, description, built_in,
                       created_at, created_by, source_profile_id,
                       source_profile_version, settings_json
                FROM scan_profiles WHERE profile_id = ?
                ORDER BY version DESC LIMIT 1
                """,
                (profile_id,),
            ).fetchone()
        else:
            row = db.execute(
                """
                SELECT profile_id, version, name, description, built_in,
                       created_at, created_by, source_profile_id,
                       source_profile_version, settings_json
                FROM scan_profiles WHERE profile_id = ? AND version = ?
                """,
                (profile_id, version),
            ).fetchone()
    return _profile_record(row)


def list_scan_profiles(db_path: Path = DB_PATH, *, all_versions: bool = False) -> list[dict]:
    init_poc_storage(db_path)
    where = "" if all_versions else "WHERE p.version = (SELECT MAX(v.version) FROM scan_profiles v WHERE v.profile_id = p.profile_id)"
    with sqlite3.connect(db_path) as db:
        rows = db.execute(
            f"""
            SELECT p.profile_id, p.version, p.name, p.description, p.built_in,
                   p.created_at, p.created_by, p.source_profile_id,
                   p.source_profile_version, p.settings_json
            FROM scan_profiles p {where}
            ORDER BY p.built_in DESC, lower(p.name), p.version DESC
            """
        ).fetchall()
    return [_profile_record(row) for row in rows]


def create_scan_profile(request: ScanProfileCreate, db_path: Path = DB_PATH) -> dict:
    init_poc_storage(db_path)
    profile_id = uuid.uuid4().hex
    created_at = utc_now()
    settings = request.settings.normalized()
    with sqlite3.connect(db_path) as db:
        db.execute(
            """
            INSERT INTO scan_profiles (
                profile_id, version, name, description, built_in,
                created_at, created_by, source_profile_id,
                source_profile_version, settings_json
            ) VALUES (?, 1, ?, ?, 0, ?, ?, NULL, NULL, ?)
            """,
            (
                profile_id, request.name.strip(), request.description.strip(),
                created_at, request.created_by.strip(),
                json.dumps(settings, sort_keys=True),
            ),
        )
    return get_scan_profile(profile_id, 1, db_path)


def create_scan_profile_version(
    profile_id: str,
    request: ScanProfileVersionCreate,
    db_path: Path = DB_PATH,
) -> dict:
    current = get_scan_profile(profile_id, db_path=db_path)
    if current is None:
        raise KeyError("Scan profile not found")
    if current["built_in"]:
        raise ValueError("Built-in profiles are protected; clone one before editing it")
    version = int(current["version"]) + 1
    with sqlite3.connect(db_path) as db:
        db.execute(
            """
            INSERT INTO scan_profiles (
                profile_id, version, name, description, built_in,
                created_at, created_by, source_profile_id,
                source_profile_version, settings_json
            ) VALUES (?, ?, ?, ?, 0, ?, ?, ?, ?, ?)
            """,
            (
                profile_id, version, current["name"], request.description.strip(),
                utc_now(), request.created_by.strip(), profile_id,
                current["version"],
                json.dumps(request.settings.normalized(), sort_keys=True),
            ),
        )
    return get_scan_profile(profile_id, version, db_path)


def clone_scan_profile(
    profile_id: str,
    request: ScanProfileClone,
    db_path: Path = DB_PATH,
) -> dict:
    source = get_scan_profile(profile_id, request.source_version, db_path)
    if source is None:
        raise KeyError("Source scan profile version not found")
    clone_request = ScanProfileCreate(
        name=request.name,
        description=request.description or f"Cloned from {source['name']} v{source['version']}",
        created_by=request.created_by,
        settings=ScanOptions(**source["settings"]),
    )
    clone = create_scan_profile(clone_request, db_path)
    with sqlite3.connect(db_path) as db:
        db.execute(
            """
            UPDATE scan_profiles
            SET source_profile_id = ?, source_profile_version = ?
            WHERE profile_id = ? AND version = 1
            """,
            (source["profile_id"], source["version"], clone["profile_id"]),
        )
    return get_scan_profile(clone["profile_id"], 1, db_path)


def resolve_scan_profile(plan: ScanRunPlan, db_path: Path = DB_PATH) -> dict:
    if plan.profile_id:
        record = get_scan_profile(plan.profile_id, plan.profile_version, db_path)
        if record is None:
            raise ValueError("The selected saved profile version does not exist")
        return record
    if plan.scan_options is not None:
        return {
            "profile_id": "inline-custom",
            "version": 1,
            "name": plan.profile if plan.profile not in LEGACY_PROFILE_IDS else "Custom",
            "description": "Run-specific settings",
            "built_in": False,
            "settings": plan.scan_options.normalized(),
        }
    legacy_id = LEGACY_PROFILE_IDS.get(plan.profile, plan.profile)
    record = get_scan_profile(legacy_id, 1, db_path)
    if record is None:
        raise ValueError(f"Unknown scan profile: {plan.profile}")
    return record


def _as_utc(value: datetime | str) -> datetime:
    moment = datetime.fromisoformat(value) if isinstance(value, str) else value
    if moment.tzinfo is None or moment.utcoffset() is None:
        raise ValueError("Scheduled times must include a timezone")
    return moment.astimezone(timezone.utc).replace(microsecond=0)


def next_schedule_time(schedule: dict, after: datetime) -> datetime | None:
    """Advance a schedule after dispatch, preserving its original cadence."""
    if schedule["cadence"] == "once":
        return None
    current = _as_utc(schedule["next_run_at"])
    delta = {
        "interval": timedelta(minutes=int(schedule.get("interval_minutes") or 60)),
        "custom_hours": timedelta(hours=int(schedule.get("cadence_hours") or 2)),
        "hourly": timedelta(hours=1),
        "daily": timedelta(days=1),
        "weekly": timedelta(weeks=1),
    }[schedule["cadence"]]
    while current <= after:
        current += delta
    return current


def get_scan_schedule(schedule_id: str, db_path: Path = DB_PATH) -> dict | None:
    if not RUN_ID_RE.fullmatch(schedule_id):
        return None
    init_poc_storage(db_path)
    with sqlite3.connect(db_path) as db:
        row = db.execute(
            "SELECT definition_json FROM scan_schedules WHERE schedule_id = ?",
            (schedule_id,),
        ).fetchone()
    return json.loads(row[0]) if row else None


def _store_scan_schedule(schedule: dict, db_path: Path = DB_PATH) -> dict:
    schedule["updated_at"] = utc_now()
    with sqlite3.connect(db_path) as db:
        db.execute(
            """
            UPDATE scan_schedules
            SET name = ?, profile_id = ?, profile_version = ?, definition_json = ?
            WHERE schedule_id = ?
            """,
            (
                schedule["name"], schedule["profile_id"], schedule["profile_version"],
                json.dumps(schedule, sort_keys=True), schedule["schedule_id"],
            ),
        )
    return schedule


def create_scan_schedule(request: ScanScheduleCreate, db_path: Path = DB_PATH) -> dict:
    """Create an executable schedule pinned to one immutable profile version."""
    init_poc_storage(db_path)
    profile = get_scan_profile(request.profile_id, request.profile_version, db_path)
    if profile is None:
        raise ValueError("A schedule must reference an existing profile version")
    if not INTERFACE_RE.fullmatch(request.interface):
        raise ValueError("Interface must be a simple local interface name")
    first_run = _as_utc(request.first_run_at)
    definition = {
        "schema_version": 2,
        "schedule_id": uuid.uuid4().hex,
        "name": request.name,
        "created_at": utc_now(),
        "updated_at": utc_now(),
        "created_by": request.created_by,
        "profile_id": profile["profile_id"],
        "profile_version": profile["version"],
        "profile_name": profile["name"],
        "profile_snapshot": profile["settings"],
        "targets": normalize_ipv4_networks(request.targets, "target"),
        "no_strike": normalize_ipv4_networks(request.no_strike, "no-strike") if request.no_strike else [],
        "interface": request.interface,
        "cadence": request.cadence,
        "first_run_at": first_run.isoformat(),
        "next_run_at": first_run.isoformat(),
        "cadence_hours": request.cadence_hours,
        "interval_minutes": request.interval_minutes,
        "reason": request.reason,
        "originating_host": request.originating_host,
        "timeout_seconds": request.timeout_seconds,
        "chunk_size": request.chunk_size,
        "chunk_delay_seconds": request.chunk_delay_seconds,
        "fallback_policy": request.fallback_policy,
        "enabled": bool(request.enabled),
        "run_count": 0,
        "last_run_id": None,
        "last_run_at": None,
        "last_run_status": None,
        "last_changed_by": request.created_by,
        "conflict_count": 0,
        "conflict_flagged": False,
        "last_conflict_at": None,
        "last_conflict_key": None,
        "batch_status": None,
        "active_batch_id": None,
        "active_chunk_number": None,
        "active_chunk_count": None,
        "implementation_status": "active_scheduler",
    }
    with sqlite3.connect(db_path) as db:
        db.execute(
            """
            INSERT INTO scan_schedules (
                schedule_id, name, created_at, created_by,
                profile_id, profile_version, definition_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                definition["schedule_id"], definition["name"], definition["created_at"],
                definition["created_by"], definition["profile_id"],
                definition["profile_version"], json.dumps(definition, sort_keys=True),
            ),
        )
    return definition


def list_scan_schedules(db_path: Path = DB_PATH) -> list[dict]:
    init_poc_storage(db_path)
    with sqlite3.connect(db_path) as db:
        rows = db.execute(
            "SELECT definition_json FROM scan_schedules ORDER BY created_at DESC"
        ).fetchall()
    schedules = [json.loads(row[0]) for row in rows]
    for schedule in schedules:
        if schedule.get("last_run_id"):
            run = get_scan_run_plan(schedule["last_run_id"], db_path)
            schedule["last_run_status"] = run.get("status") if run else "not_found"
    return schedules


def set_scan_schedule_enabled(
    schedule_id: str, enabled: bool, db_path: Path = DB_PATH
) -> dict:
    schedule = get_scan_schedule(schedule_id, db_path)
    if schedule is None:
        raise KeyError("Scan schedule not found")
    schedule["enabled"] = bool(enabled)
    schedule["last_changed_by"] = schedule.get("last_changed_by") or schedule["created_by"]
    if enabled:
        if not schedule.get("next_run_at"):
            schedule["next_run_at"] = utc_now()
        elif _as_utc(schedule["next_run_at"]) < datetime.now(timezone.utc):
            if schedule["cadence"] == "once":
                schedule["next_run_at"] = utc_now()
            else:
                schedule["next_run_at"] = next_schedule_time(
                    schedule, datetime.now(timezone.utc)
                ).isoformat()
    return _store_scan_schedule(schedule, db_path)


def change_scan_schedule_profile(
    schedule_id: str, request: ScheduleProfileChange, db_path: Path = DB_PATH
) -> dict:
    schedule = get_scan_schedule(schedule_id, db_path)
    if schedule is None:
        raise KeyError("Scan schedule not found")
    with ACTIVE_SCHEDULE_BATCHES_LOCK:
        if schedule_id in ACTIVE_SCHEDULE_BATCHES:
            raise RuntimeError(
                "Pause and wait for the active scheduled batch to finish before changing its profile"
            )
    profile = get_scan_profile(request.profile_id, request.profile_version, db_path)
    if profile is None:
        raise ValueError("The selected saved profile version does not exist")
    schedule.update(
        {
            "profile_id": profile["profile_id"],
            "profile_version": profile["version"],
            "profile_name": profile["name"],
            "profile_snapshot": profile["settings"],
            "fallback_policy": (
                schedule.get("fallback_policy", "require_approval")
                if profile["settings"].get("discovery_mode") == "fping"
                else "require_approval"
            ),
            "last_changed_by": request.changed_by,
            "profile_changed_at": utc_now(),
        }
    )
    return _store_scan_schedule(schedule, db_path)


def insert_scan_run_manifest(manifest: dict, db_path: Path = DB_PATH) -> None:
    init_poc_storage(db_path)
    with sqlite3.connect(db_path) as db:
        db.execute(
            """
            INSERT INTO scan_runs (
                run_id, created_at, status, operator_name, reason,
                originating_host, interface_name, profile, manifest_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                manifest["run_id"], manifest["created_at"], manifest["status"],
                manifest["operator"], manifest["reason"],
                manifest["originating_host"], manifest["interface"],
                manifest["profile"], json.dumps(manifest, sort_keys=True),
            ),
        )


def update_scan_run_manifest(manifest: dict, db_path: Path = DB_PATH) -> None:
    with sqlite3.connect(db_path) as db:
        db.execute(
            """
            UPDATE scan_runs SET status = ?, manifest_json = ? WHERE run_id = ?
            """,
            (
                manifest["status"],
                json.dumps(manifest, sort_keys=True),
                manifest["run_id"],
            ),
        )


def save_scan_run_plan(plan: ScanRunPlan, db_path: Path = DB_PATH) -> dict:
    manifest = build_scan_run_manifest(plan, db_path=db_path)
    insert_scan_run_manifest(manifest, db_path)
    return manifest


def prepare_scan_run(
    request: ScanRunRequest,
    db_path: Path = DB_PATH,
    interfaces: set[str] | None = None,
) -> dict:
    validate_runtime_interface(request.interface, interfaces)
    manifest = build_scan_run_manifest(
        request,
        capture=request.capture,
        timeout_seconds=request.timeout_seconds,
        status="queued",
        db_path=db_path,
    )
    insert_scan_run_manifest(manifest, db_path)
    return manifest


def list_scan_run_plans(db_path: Path = DB_PATH, limit: int = 50) -> list[dict]:
    init_poc_storage(db_path)
    with sqlite3.connect(db_path) as db:
        rows = db.execute(
            "SELECT manifest_json FROM scan_runs ORDER BY created_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [with_host_count(json.loads(row[0])) for row in rows]


def get_scan_run_plan(run_id: str, db_path: Path = DB_PATH) -> dict | None:
    if not RUN_ID_RE.fullmatch(run_id):
        return None
    init_poc_storage(db_path)
    with sqlite3.connect(db_path) as db:
        row = db.execute(
            "SELECT manifest_json FROM scan_runs WHERE run_id = ?", (run_id,)
        ).fetchone()
    return with_host_count(json.loads(row[0])) if row else None


def nmap_host_count(xml_path: Path) -> int | None:
    """Return the number of hosts Nmap identified as up, if XML is available."""
    if not xml_path.is_file():
        return None
    try:
        root = ET.parse(xml_path).getroot()
    except (ET.ParseError, OSError):
        return None
    return sum(
        1
        for host in root.findall("host")
        if (host.find("status") is None or host.find("status").get("state") == "up")
    )


def with_host_count(manifest: dict, data_dir: Path = DATA_DIR) -> dict:
    if manifest.get("host_count") is None:
        manifest["host_count"] = nmap_host_count(
            run_directory(manifest["run_id"], data_dir) / "scan.xml"
        )
    return manifest


def run_directory(run_id: str, data_dir: Path = DATA_DIR) -> Path:
    if not RUN_ID_RE.fullmatch(run_id):
        raise ValueError("Invalid scan run identifier")
    root = (data_dir / RUNS_DIR_NAME).resolve()
    candidate = (root / run_id).resolve()
    if candidate.parent != root:
        raise ValueError("Invalid scan run path")
    return candidate


def _delete_challenge_key(scope: str, identifier: str | None = None) -> str:
    return f"{scope}:{identifier or '*'}"


def issue_delete_challenge(scope: str, identifier: str | None = None) -> dict:
    """Issue a short-lived confirmation token for a destructive scan-data action."""
    challenge = secrets.token_hex(4).upper()
    key = _delete_challenge_key(scope, identifier)
    with DELETE_CHALLENGES_LOCK:
        DELETE_CHALLENGES[key] = (challenge, time.time() + 300)
    return {"scope": scope, "identifier": identifier, "challenge": challenge, "expires_in_seconds": 300}


def consume_delete_challenge(scope: str, identifier: str | None, confirmation: str) -> bool:
    key = _delete_challenge_key(scope, identifier)
    with DELETE_CHALLENGES_LOCK:
        saved = DELETE_CHALLENGES.get(key)
        if not saved:
            return False
        if saved[1] < time.time():
            DELETE_CHALLENGES.pop(key, None)
            return False
        # Do not burn the challenge on a typo.  The analyst gets one chance
        # to correct the value before the token is consumed by a valid match.
        if not hmac.compare_digest(saved[0], confirmation.strip().upper()):
            return False
        DELETE_CHALLENGES.pop(key, None)
        return True


def delete_scan_profile(
    profile_id: str, confirmation: str, db_path: Path = DB_PATH
) -> dict:
    profile = get_scan_profile(profile_id, db_path=db_path)
    if profile is None:
        raise KeyError("Scan profile not found")
    if profile["built_in"]:
        raise PermissionError("Built-in profiles are protected and cannot be deleted")
    with sqlite3.connect(db_path) as db:
        pinned = db.execute(
            "SELECT COUNT(*) FROM scan_schedules WHERE profile_id = ?", (profile_id,)
        ).fetchone()[0]
    if pinned:
        raise RuntimeError(
            "This profile is pinned to a saved schedule. Change or delete that schedule first."
        )
    if not consume_delete_challenge("profile", profile_id, confirmation):
        raise PermissionError("The confirmation string is invalid or expired")
    with sqlite3.connect(db_path) as db:
        removed = db.execute(
            "DELETE FROM scan_profiles WHERE profile_id = ?", (profile_id,)
        ).rowcount
    return {"deleted": True, "profile_id": profile_id, "versions_removed": removed}


def delete_scan_schedule(
    schedule_id: str, confirmation: str, db_path: Path = DB_PATH
) -> dict:
    if get_scan_schedule(schedule_id, db_path) is None:
        raise KeyError("Scan schedule not found")
    with ACTIVE_SCHEDULE_BATCHES_LOCK:
        if schedule_id in ACTIVE_SCHEDULE_BATCHES:
            raise RuntimeError(
                "An active scheduled batch must finish or stop before its schedule can be deleted"
            )
    if not consume_delete_challenge("schedule", schedule_id, confirmation):
        raise PermissionError("The confirmation string is invalid or expired")
    with sqlite3.connect(db_path) as db:
        db.execute("DELETE FROM scan_schedules WHERE schedule_id = ?", (schedule_id,))
    return {"deleted": True, "schedule_id": schedule_id}


def scan_data_root(data_dir: Path = DATA_DIR) -> Path:
    root = (data_dir / RUNS_DIR_NAME).resolve()
    if root.parent != data_dir.resolve():
        raise ValueError("Invalid scan data root")
    return root


def delete_scan_data(run_id: str, confirmation: str, db_path: Path = DB_PATH,
                     data_dir: Path = DATA_DIR) -> dict:
    if get_scan_run_plan(run_id, db_path) is None:
        raise KeyError("Scan run not found")
    with ACTIVE_RUNS_LOCK:
        if run_id in ACTIVE_RUNS:
            raise RuntimeError("Active scans must be cancelled before they can be deleted")
    if not consume_delete_challenge("scan", run_id, confirmation):
        raise PermissionError("The confirmation string is invalid or expired")
    run_dir = run_directory(run_id, data_dir)
    if run_dir.exists():
        shutil.rmtree(run_dir)
    db = sqlite3.connect(db_path)
    try:
        db.execute("DELETE FROM scan_runs WHERE run_id = ?", (run_id,))
        db.commit()
    finally:
        db.close()
    return {"deleted": True, "run_id": run_id}


def delete_all_scan_data(confirmation: str, db_path: Path = DB_PATH,
                         data_dir: Path = DATA_DIR) -> dict:
    with ACTIVE_RUNS_LOCK:
        if ACTIVE_RUNS:
            raise RuntimeError("Active scans must be cancelled before all scan data can be deleted")
    if not consume_delete_challenge("all", None, confirmation):
        raise PermissionError("The confirmation string is invalid or expired")
    root = scan_data_root(data_dir)
    removed_runs = 0
    if root.exists():
        for child in root.iterdir():
            if child.is_dir() and RUN_ID_RE.fullmatch(child.name):
                shutil.rmtree(child)
                removed_runs += 1
    removed_imports = 0
    imports_root = (data_dir / "imports").resolve()
    if imports_root.parent == data_dir.resolve() and imports_root.exists():
        for child in imports_root.iterdir():
            if child.is_file():
                child.unlink()
                removed_imports += 1
    db = sqlite3.connect(db_path)
    try:
        db.execute("DELETE FROM scan_runs")
        try:
            db.execute("DELETE FROM imports")
        except sqlite3.OperationalError:
            pass
        db.commit()
    finally:
        db.close()
    return {"deleted": True, "removed_runs": removed_runs, "removed_imports": removed_imports}


def _stored_file_record(path: Path, url: str | None = None) -> dict:
    value = {"name": path.name, "size_bytes": path.stat().st_size,
             "modified_at": datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).isoformat()}
    if url:
        value["download_url"] = url
    return value


def list_stored_files(data_dir: Path = DATA_DIR, db_path: Path = DB_PATH,
                      limit: int = 300) -> dict:
    """Return a logical, download-oriented view of saved scan/config locations."""
    locations: list[dict] = [
        {"id": "folder:scan-runs", "category": "scan", "label": "Automated scan results", "folder": RUNS_DIR_NAME, "files": []},
        {"id": "folder:device-configs", "category": "device", "label": "Network-device configurations", "folder": "device-configs", "files": []},
        {"id": "folder:imports", "category": "import", "label": "Imported Nmap results", "folder": "imports", "files": []},
    ]
    by_id = {item["id"]: item for item in locations}
    scan_root = scan_data_root(data_dir)
    if scan_root.exists():
        for run_dir in sorted((item for item in scan_root.iterdir() if item.is_dir() and RUN_ID_RE.fullmatch(item.name)), key=lambda item: item.stat().st_mtime, reverse=True):
            try:
                manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                manifest = {"run_id": run_dir.name}
            location = {"id": f"scan:{run_dir.name}", "category": "scan", "label": f"Scan {run_dir.name[:8]}", "folder": f"{RUNS_DIR_NAME}/{run_dir.name}", "status": manifest.get("status"), "created_at": manifest.get("created_at"), "files": []}
            for child in sorted(run_dir.iterdir(), key=lambda item: item.name):
                if not child.is_file() or child.name not in {value[0] for value in ARTIFACT_FILES.values()}:
                    continue
                artifact_name = next((key for key, value in ARTIFACT_FILES.items() if value[0] == child.name), None)
                location["files"].append(_stored_file_record(child, f"/api/scan-runs/{run_dir.name}/artifacts/{artifact_name}" if artifact_name else None))
            locations.append(location)
    config_root = (data_dir / "device-configs").resolve()
    if config_root.exists():
        for run_dir in sorted((item for item in config_root.iterdir() if item.is_dir() and RUN_ID_RE.fullmatch(item.name)), key=lambda item: item.stat().st_mtime, reverse=True):
            try:
                manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                manifest = {"run_id": run_dir.name}
            location = {"id": f"device:{run_dir.name}", "category": "device", "label": f"{manifest.get('vendor', 'Device')} {manifest.get('device_address', run_dir.name[:8])}", "folder": f"device-configs/{run_dir.name}", "status": manifest.get("status"), "created_at": manifest.get("created_at"), "files": []}
            for child in sorted(run_dir.iterdir(), key=lambda item: item.name):
                if child.is_file() and (child.name == "manifest.json" or child.name.startswith("uploaded-") or child.name in {"stdout.txt", "stderr.txt", "accountability.pcap", "capture-stderr.txt"}):
                    location["files"].append(_stored_file_record(child, f"/api/device-configs/{run_dir.name}/files/{child.name}"))
            locations.append(location)
    db = sqlite3.connect(db_path)
    try:
        rows = db.execute("SELECT sha256, filename, imported_at FROM imports ORDER BY imported_at DESC LIMIT ?", (limit,)).fetchall()
    except sqlite3.Error:
        rows = []
    finally:
        db.close()
    for sha256, filename, imported_at in rows:
        locations.append({"id": f"import:{sha256}", "category": "import", "label": filename, "folder": "imports", "created_at": imported_at, "files": [{"name": filename, "download_url": f"/api/imports/{sha256}"}]})
    return {"locations": locations[:limit], "roots": locations[:3]}


def write_manifest_file(manifest: dict, data_dir: Path = DATA_DIR) -> None:
    path = run_directory(manifest["run_id"], data_dir) / "manifest.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def terminate_process(process: object | None, grace_seconds: float = 3.0) -> None:
    if process is None or process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except (AttributeError, OSError, ProcessLookupError):
        try:
            process.terminate()
        except OSError:
            pass
    try:
        process.wait(timeout=grace_seconds)
        return
    except (subprocess.TimeoutExpired, OSError):
        pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (AttributeError, OSError, ProcessLookupError):
        try:
            process.kill()
        except OSError:
            pass
    try:
        process.wait(timeout=1)
    except (subprocess.TimeoutExpired, OSError):
        pass


def collect_artifacts(manifest: dict, data_dir: Path = DATA_DIR) -> None:
    run_dir = run_directory(manifest["run_id"], data_dir)
    artifacts = []
    for name, (filename, media_type) in ARTIFACT_FILES.items():
        if name == "manifest":
            continue
        path = run_dir / filename
        if path.is_file():
            artifacts.append(
                {
                    "name": name,
                    "filename": filename,
                    "media_type": media_type,
                    "size_bytes": path.stat().st_size,
                    "download_url": f"/api/scan-runs/{manifest['run_id']}/artifacts/{name}",
                }
            )
    artifacts.append(
        {
            "name": "manifest",
            "filename": "manifest.json",
            "media_type": "application/json",
            "download_url": f"/api/scan-runs/{manifest['run_id']}/artifacts/manifest",
        }
    )
    manifest["artifacts"] = artifacts
    write_manifest_file(manifest, data_dir)


def artifact_path(
    manifest: dict,
    artifact_name: str,
    data_dir: Path = DATA_DIR,
) -> tuple[Path, str]:
    if artifact_name not in ARTIFACT_FILES:
        raise ValueError("Unknown artifact")
    available = {item["name"] for item in manifest.get("artifacts", [])}
    if artifact_name not in available:
        raise FileNotFoundError("Artifact is not available")
    filename, media_type = ARTIFACT_FILES[artifact_name]
    path = (run_directory(manifest["run_id"], data_dir) / filename).resolve()
    if path.parent != run_directory(manifest["run_id"], data_dir).resolve() or not path.is_file():
        raise FileNotFoundError("Artifact is not available")
    return path, media_type


def execute_scan_run(
    run_id: str,
    control: RunControl,
    *,
    db_path: Path = DB_PATH,
    data_dir: Path = DATA_DIR,
    popen_factory: Callable = subprocess.Popen,
    sleep_fn: Callable[[float], None] = time.sleep,
) -> None:
    manifest = get_scan_run_plan(run_id, db_path)
    if manifest is None:
        return
    run_dir = run_directory(run_id, data_dir)
    run_dir.mkdir(parents=True, exist_ok=False)
    (run_dir / "targets.txt").write_text("\n".join(manifest["targets"]) + "\n", encoding="utf-8")
    if manifest.get("discovery_mode") == "fping":
        discovery_targets = expanded_discovery_targets(
            manifest["targets"], manifest.get("no_strike") or []
        )
        (run_dir / "discovery-targets.txt").write_text(
            "\n".join(discovery_targets) + ("\n" if discovery_targets else ""),
            encoding="utf-8",
        )
    if manifest["no_strike"]:
        (run_dir / "no-strike.txt").write_text(
            "\n".join(manifest["no_strike"]) + "\n", encoding="utf-8"
        )
    manifest["started_at"] = utc_now()
    manifest["status"] = "running"
    update_scan_run_manifest(manifest, db_path)
    write_manifest_file(manifest, data_dir)
    deadline = time.monotonic() + int(manifest["timeout_seconds"])
    exit_code = None

    try:
        capture_error_path = run_dir / "capture-stderr.txt"
        with (
            (run_dir / "stdout.txt").open("wb") as stdout_handle,
            (run_dir / "stderr.txt").open("wb") as stderr_handle,
            capture_error_path.open("wb") as capture_error_handle,
        ):
            if manifest["capture_requested"]:
                control.capture_process = popen_factory(
                    manifest["capture_command_argv"],
                    cwd=run_dir,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=capture_error_handle,
                    start_new_session=True,
                )
                sleep_fn(0.25)
                capture_exit = control.capture_process.poll()
                if capture_exit is not None:
                    raise RuntimeError(f"tcpdump exited before the scan with status {capture_exit}")

            run_nmap = True
            if manifest.get("discovery_mode") == "fping":
                with (
                    (run_dir / "fping-alive.txt").open("wb") as alive_handle,
                    (run_dir / "fping-stderr.txt").open("wb") as fping_error_handle,
                ):
                    control.discovery_process = popen_factory(
                        manifest["discovery_command_argv"],
                        cwd=run_dir,
                        stdin=subprocess.DEVNULL,
                        stdout=alive_handle,
                        stderr=fping_error_handle,
                        start_new_session=True,
                    )
                    while True:
                        discovery_exit = control.discovery_process.poll()
                        if discovery_exit is not None:
                            if discovery_exit not in {0, 1}:
                                raise RuntimeError(f"fping failed with status {discovery_exit}")
                            break
                        if control.cancel_event.is_set():
                            manifest["status"] = "cancelled"
                            terminate_process(control.discovery_process)
                            run_nmap = False
                            break
                        if time.monotonic() >= deadline:
                            manifest["status"] = "timed_out"
                            terminate_process(control.discovery_process)
                            run_nmap = False
                            break
                        sleep_fn(0.2)
                alive_hosts = [
                    line.strip()
                    for line in (run_dir / "fping-alive.txt").read_text(
                        encoding="utf-8", errors="replace"
                    ).splitlines()
                    if line.strip()
                ]
                manifest["discovery_host_count"] = len(alive_hosts)
                if run_nmap and not alive_hosts:
                    terminate_process(control.capture_process)
                    control.capture_process = None
                    fallback_argv = build_nmap_argv(
                        manifest["profile"],
                        manifest["interface"],
                        include_no_strike=bool(manifest.get("no_strike")),
                        scan_options=manifest["profile_settings"],
                        target_file="targets.txt",
                    )
                    manifest["fallback_command_argv"] = fallback_argv
                    manifest["exact_fallback_command"] = shlex.join(fallback_argv)
                    if manifest.get("fallback_policy") == "stop_without_nmap":
                        manifest["status"] = "completed_without_nmap"
                        manifest["fallback_approval_required"] = False
                        manifest["fallback_decision"] = "policy_stop"
                        manifest["fallback_decided_at"] = utc_now()
                        manifest["discovery_note"] = (
                            "FPING found no responsive hosts. The pinned scheduled-scan "
                            "policy finished without starting the full Nmap fallback."
                        )
                        exit_code = 0
                        run_nmap = False
                        update_scan_run_manifest(manifest, db_path)
                        write_manifest_file(manifest, data_dir)
                    else:
                        manifest["status"] = "awaiting_fallback_approval"
                        manifest["fallback_approval_required"] = True
                        manifest["discovery_note"] = (
                            "FPING found no responsive hosts. Full Nmap fallback is paused "
                            "pending explicit operator or mission-partner approval."
                        )
                        collect_artifacts(manifest, data_dir)
                        update_scan_run_manifest(manifest, db_path)
                        write_manifest_file(manifest, data_dir)
                        while not control.fallback_decision_event.is_set():
                            if control.cancel_event.is_set():
                                manifest["status"] = "cancelled"
                                run_nmap = False
                                break
                            sleep_fn(0.2)
                        if run_nmap:
                            manifest["fallback_decision"] = control.fallback_decision
                            manifest["fallback_decided_by"] = control.fallback_decided_by
                            manifest["fallback_authorization_note"] = (
                                control.fallback_authorization_note
                            )
                            manifest["fallback_decided_at"] = utc_now()
                            if control.fallback_decision == "approve":
                                apply_fping_fallback(manifest)
                                manifest["status"] = "running"
                                manifest["discovery_note"] = (
                                    "FPING found no responsive hosts. Full Nmap fallback "
                                    f"approved by {control.fallback_decided_by}: "
                                    f"{control.fallback_authorization_note}"
                                )
                                deadline = time.monotonic() + int(manifest["timeout_seconds"])
                                if manifest["capture_requested"]:
                                    control.capture_process = popen_factory(
                                        manifest["capture_command_argv"],
                                        cwd=run_dir,
                                        stdin=subprocess.DEVNULL,
                                        stdout=subprocess.DEVNULL,
                                        stderr=capture_error_handle,
                                        start_new_session=True,
                                    )
                                    sleep_fn(0.25)
                                    capture_exit = control.capture_process.poll()
                                    if capture_exit is not None:
                                        raise RuntimeError(
                                            "tcpdump exited before the approved fallback "
                                            f"with status {capture_exit}"
                                        )
                            else:
                                manifest["status"] = "completed_without_nmap"
                                manifest["discovery_note"] = (
                                    "FPING found no responsive hosts. "
                                    f"{control.fallback_decided_by} chose to finish without "
                                    f"Nmap fallback: {control.fallback_authorization_note}"
                                )
                                exit_code = 0
                                run_nmap = False
                            update_scan_run_manifest(manifest, db_path)
                            write_manifest_file(manifest, data_dir)

            if run_nmap:
                control.nmap_process = popen_factory(
                    manifest["command_argv"],
                    cwd=run_dir,
                    stdin=subprocess.DEVNULL,
                    stdout=stdout_handle,
                    stderr=stderr_handle,
                    start_new_session=True,
                )
                while True:
                    exit_code = control.nmap_process.poll()
                    if exit_code is not None:
                        manifest["status"] = "completed" if exit_code == 0 else "failed"
                        break
                    if control.cancel_event.is_set():
                        manifest["status"] = "cancelled"
                        terminate_process(control.nmap_process)
                        exit_code = control.nmap_process.poll()
                        break
                    if time.monotonic() >= deadline:
                        manifest["status"] = "timed_out"
                        terminate_process(control.nmap_process)
                        exit_code = control.nmap_process.poll()
                        break
                    sleep_fn(0.2)
    except Exception as exc:
        manifest["status"] = "failed"
        manifest["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        terminate_process(control.discovery_process)
        terminate_process(control.nmap_process)
        terminate_process(control.capture_process)
        manifest["completed_at"] = utc_now()
        manifest["exit_code"] = exit_code
        manifest["success"] = manifest["status"] in {
            "completed", "completed_without_nmap"
        }
        manifest["host_count"] = nmap_host_count(run_dir / "scan.xml")
        collect_artifacts(manifest, data_dir)
        update_scan_run_manifest(manifest, db_path)
        with ACTIVE_RUNS_LOCK:
            ACTIVE_RUNS.pop(run_id, None)


def launch_scan_run(
    request: ScanRunRequest,
    *,
    db_path: Path = DB_PATH,
    data_dir: Path = DATA_DIR,
    interfaces: set[str] | None = None,
) -> dict:
    """Queue one scan through the same capacity gate used by manual and scheduled runs."""
    with ACTIVE_RUNS_LOCK:
        if len(ACTIVE_RUNS) >= MAX_ACTIVE_RUNS:
            raise RuntimeError("Another scan is already running")
        manifest = prepare_scan_run(request, db_path, interfaces)
        control = RunControl()
        ACTIVE_RUNS[manifest["run_id"]] = control
    try:
        worker = threading.Thread(
            target=execute_scan_run,
            args=(manifest["run_id"], control),
            kwargs={"db_path": db_path, "data_dir": data_dir},
            daemon=True,
            name=f"scan-{manifest['run_id'][:8]}",
        )
        worker.start()
    except Exception:
        with ACTIVE_RUNS_LOCK:
            ACTIVE_RUNS.pop(manifest["run_id"], None)
        manifest["status"] = "failed"
        manifest["error"] = "The scan worker could not be started"
        update_scan_run_manifest(manifest, db_path)
        raise
    return manifest


def schedule_target_chunks(
    schedule: dict, db_path: Path = DB_PATH
) -> list[list[str]]:
    no_strike, _ = effective_no_strike(schedule.get("no_strike") or [], db_path)
    addresses = expanded_discovery_targets(
        schedule["targets"], no_strike
    )
    size = int(schedule.get("chunk_size") or 256)
    return [addresses[index:index + size] for index in range(0, len(addresses), size)]


def _scheduled_request(
    schedule: dict,
    targets: list[str],
    *,
    batch_id: str,
    chunk_number: int,
    chunk_count: int,
    db_path: Path = DB_PATH,
) -> ScanRunRequest:
    no_strike, _ = effective_no_strike(schedule.get("no_strike") or [], db_path)
    return ScanRunRequest(
        operator=schedule["created_by"],
        created_by=schedule["created_by"],
        scheduled=True,
        scheduled_by=schedule["created_by"],
        executed_by="scheduler",
        name=f"{schedule['name']} Chunk {chunk_number} of {chunk_count}",
        reason=schedule["reason"],
        originating_host=schedule["originating_host"],
        interface=schedule["interface"],
        profile=schedule["profile_name"],
        profile_id=schedule["profile_id"],
        profile_version=schedule["profile_version"],
        targets=targets,
        no_strike=no_strike,
        capture=True,
        timeout_seconds=int(schedule.get("timeout_seconds") or 900),
        fallback_policy=schedule.get("fallback_policy", "require_approval"),
        schedule_id=schedule["schedule_id"],
        schedule_batch_id=batch_id,
        chunk_number=chunk_number,
        chunk_count=chunk_count,
        chunk_delay_seconds=int(schedule.get("chunk_delay_seconds") or 0),
    )


def execute_schedule_batch(
    schedule_id: str,
    batch_id: str,
    *,
    advance_schedule: bool,
    db_path: Path = DB_PATH,
    data_dir: Path = DATA_DIR,
    sleep_fn: Callable[[float], None] = time.sleep,
) -> None:
    successful_states = {"completed", "completed_without_nmap"}
    terminal_states = successful_states | {"failed", "cancelled", "timed_out"}
    try:
        schedule = get_scan_schedule(schedule_id, db_path)
        if schedule is None:
            return
        chunks = schedule_target_chunks(schedule, db_path)
        if not chunks:
            schedule["batch_status"] = "stopped_no_targets"
            schedule["enabled"] = False
            schedule["last_dispatch_note"] = "No addresses remained after no-strike filtering"
            _store_scan_schedule(schedule, db_path)
            return
        total = len(chunks)
        schedule.update(
            {
                "batch_status": "running",
                "active_batch_id": batch_id,
                "active_chunk_number": 0,
                "active_chunk_count": total,
                "last_dispatch_note": f"Preparing {total} sequential chunk(s)",
            }
        )
        _store_scan_schedule(schedule, db_path)
        for index, targets in enumerate(chunks, start=1):
            while True:
                try:
                    run = launch_scan_run(
                        _scheduled_request(
                            schedule,
                            targets,
                            batch_id=batch_id,
                            chunk_number=index,
                            chunk_count=total,
                            db_path=db_path,
                        ),
                        db_path=db_path,
                        data_dir=data_dir,
                    )
                    break
                except RuntimeError:
                    record_schedule_conflict(
                        schedule,
                        f"batch:{batch_id}",
                        db_path,
                    )
                    sleep_fn(2)
            schedule["last_run_id"] = run["run_id"]
            schedule["last_run_at"] = utc_now()
            schedule["last_run_status"] = run["status"]
            schedule["run_count"] = int(schedule.get("run_count") or 0) + 1
            schedule["active_chunk_number"] = index
            schedule["last_dispatch_note"] = f"Chunk {index} of {total} queued"
            _store_scan_schedule(schedule, db_path)
            while True:
                current = get_scan_run_plan(run["run_id"], db_path)
                if current and current.get("status") in terminal_states:
                    break
                sleep_fn(1)
            schedule = get_scan_schedule(schedule_id, db_path) or schedule
            schedule["last_run_status"] = current["status"]
            schedule["last_dispatch_note"] = f"Chunk {index} of {total} {current['status']}"
            _store_scan_schedule(schedule, db_path)
            if current["status"] not in successful_states:
                schedule["batch_status"] = f"stopped_{current['status']}"
                schedule["enabled"] = False
                schedule["active_batch_id"] = None
                _store_scan_schedule(schedule, db_path)
                return
            if advance_schedule and not schedule.get("enabled"):
                schedule["batch_status"] = "paused_after_current_chunk"
                schedule["active_batch_id"] = None
                schedule["last_dispatch_note"] = "Paused before the next chunk"
                _store_scan_schedule(schedule, db_path)
                return
            if index < total:
                delay = int(schedule.get("chunk_delay_seconds") or 0)
                schedule["next_chunk_at"] = (
                    datetime.now(timezone.utc) + timedelta(seconds=delay)
                ).replace(microsecond=0).isoformat()
                schedule["last_dispatch_note"] = (
                    f"Chunk {index} of {total} completed; waiting {delay} seconds"
                )
                _store_scan_schedule(schedule, db_path)
                if delay:
                    sleep_fn(delay)
        schedule = get_scan_schedule(schedule_id, db_path) or schedule
        schedule["batch_status"] = "completed"
        schedule["active_batch_id"] = None
        schedule["active_chunk_number"] = total
        schedule["next_chunk_at"] = None
        schedule["occurrence_count"] = int(schedule.get("occurrence_count") or 0) + 1
        schedule["last_dispatch_note"] = f"All {total} chunks completed"
        if advance_schedule:
            following = next_schedule_time(schedule, datetime.now(timezone.utc))
            schedule["next_run_at"] = following.isoformat() if following else None
            if following is None:
                schedule["enabled"] = False
        _store_scan_schedule(schedule, db_path)
    except Exception as exc:
        schedule = get_scan_schedule(schedule_id, db_path)
        if schedule is not None:
            schedule["batch_status"] = "failed_to_dispatch"
            schedule["enabled"] = False
            schedule["active_batch_id"] = None
            schedule["last_dispatch_note"] = f"{type(exc).__name__}: {exc}"
            _store_scan_schedule(schedule, db_path)
    finally:
        with ACTIVE_SCHEDULE_BATCHES_LOCK:
            ACTIVE_SCHEDULE_BATCHES.discard(schedule_id)


def queue_scan_schedule_batch(
    schedule_id: str,
    *,
    advance_schedule: bool,
    db_path: Path = DB_PATH,
    data_dir: Path = DATA_DIR,
) -> dict:
    schedule = get_scan_schedule(schedule_id, db_path)
    if schedule is None:
        raise KeyError("Scan schedule not found")
    chunks = schedule_target_chunks(schedule, db_path)
    if not chunks:
        raise ValueError("No addresses remain after no-strike filtering")
    with ACTIVE_SCHEDULE_BATCHES_LOCK:
        if ACTIVE_SCHEDULE_BATCHES:
            raise RuntimeError("Another scheduled batch is already active")
        ACTIVE_SCHEDULE_BATCHES.add(schedule_id)
    batch_id = uuid.uuid4().hex
    schedule["batch_status"] = "queued"
    schedule["active_batch_id"] = batch_id
    schedule["active_chunk_number"] = 0
    schedule["active_chunk_count"] = len(chunks)
    schedule["last_dispatch_note"] = f"Queued {len(chunks)} sequential chunk(s)"
    _store_scan_schedule(schedule, db_path)
    try:
        worker = threading.Thread(
            target=execute_schedule_batch,
            args=(schedule_id, batch_id),
            kwargs={
                "advance_schedule": advance_schedule,
                "db_path": db_path,
                "data_dir": data_dir,
            },
            daemon=True,
            name=f"schedule-{schedule_id[:8]}",
        )
        worker.start()
    except Exception:
        with ACTIVE_SCHEDULE_BATCHES_LOCK:
            ACTIVE_SCHEDULE_BATCHES.discard(schedule_id)
        raise
    return {
        "schedule_id": schedule_id,
        "batch_id": batch_id,
        "status": "queued",
        "chunk_count": len(chunks),
        "chunk_size": int(schedule.get("chunk_size") or 256),
        "chunk_delay_seconds": int(schedule.get("chunk_delay_seconds") or 0),
    }


def run_scan_schedule_now(schedule_id: str, db_path: Path = DB_PATH) -> dict:
    return queue_scan_schedule_batch(
        schedule_id, advance_schedule=False, db_path=db_path
    )


def record_schedule_conflict(
    schedule: dict,
    conflict_key: str,
    db_path: Path = DB_PATH,
) -> dict:
    """Record one distinct delayed occurrence without counting scheduler retries."""
    if schedule.get("last_conflict_key") != conflict_key:
        schedule["conflict_count"] = int(schedule.get("conflict_count") or 0) + 1
        schedule["last_conflict_key"] = conflict_key
        schedule["last_conflict_at"] = utc_now()
        schedule["conflict_flagged"] = schedule["conflict_count"] > 3
    schedule["last_dispatch_note"] = "Waiting for the analyzer scanner"
    return _store_scan_schedule(schedule, db_path)


def dispatch_due_schedules(
    now: datetime | None = None, db_path: Path = DB_PATH
) -> list[dict]:
    """Queue at most one due batch; its chunks run sequentially on the analyzer."""
    moment = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    dispatched = []
    with ACTIVE_SCHEDULE_BATCHES_LOCK:
        active_schedule_ids = set(ACTIVE_SCHEDULE_BATCHES)
    due = [
        schedule for schedule in list_scan_schedules(db_path)
        if schedule.get("enabled") and schedule.get("next_run_at")
        and schedule["schedule_id"] not in active_schedule_ids
        and _as_utc(schedule["next_run_at"]) <= moment
    ]
    due.sort(key=lambda item: item["next_run_at"])
    for schedule in due[:1]:
        try:
            batch = queue_scan_schedule_batch(
                schedule["schedule_id"], advance_schedule=True, db_path=db_path
            )
        except RuntimeError:
            record_schedule_conflict(
                schedule,
                f"scheduled:{schedule['next_run_at']}",
                db_path,
            )
            break
        dispatched.append(batch)
    return dispatched


def schedule_worker(stop_event: threading.Event, interval_seconds: float = 15.0) -> None:
    while not stop_event.is_set():
        try:
            dispatch_due_schedules()
        except Exception:
            # One malformed or unavailable schedule must not stop future checks.
            pass
        stop_event.wait(interval_seconds)


def list_import_history(db_path: Path = DB_PATH, limit: int = 50) -> list[dict]:
    with sqlite3.connect(db_path) as db:
        columns = {row[1] for row in db.execute("PRAGMA table_info(imports)").fetchall()}
        metadata_expression = "metadata_json" if "metadata_json" in columns else "'{}'"
        rows = db.execute(
            f"""
            SELECT sha256, filename, imported_at, analysis_json, {metadata_expression}
            FROM imports ORDER BY imported_at DESC LIMIT ?
            """,
            (limit,),
        ).fetchall()
    history = []
    for sha256, filename, imported_at, analysis_json, metadata_json in rows:
        analysis = json.loads(analysis_json)
        metadata = json.loads(metadata_json or "{}")
        history.append(
            {
                "sha256": sha256,
                "filename": filename,
                "display_name": metadata.get("display_name") or filename,
                "imported_at": imported_at,
                "metadata": metadata,
                "summary": {
                    "host_count": len(analysis.get("hosts", [])),
                    "up_count": analysis.get("up_count", 0),
                    "mac_count": analysis.get("mac_count", 0),
                    "os_group_count": len(analysis.get("os_groups", [])),
                    "coverage": analysis.get("coverage", {}),
                    "warnings": analysis.get("warnings", []),
                },
            }
        )
    return history


def get_import_history_item(sha256: str, db_path: Path = DB_PATH) -> dict | None:
    if not IMPORT_KEY_RE.fullmatch(sha256):
        return None
    with sqlite3.connect(db_path) as db:
        columns = {item[1] for item in db.execute("PRAGMA table_info(imports)").fetchall()}
        metadata_expression = "metadata_json" if "metadata_json" in columns else "'{}'"
        row = db.execute(
            f"""
            SELECT filename, imported_at, analysis_json, {metadata_expression}
            FROM imports WHERE sha256 = ?
            """,
            (sha256,),
        ).fetchone()
    if not row:
        return None
    return {
        "sha256": sha256,
        "filename": row[0],
        "display_name": (json.loads(row[3] or "{}").get("display_name") or row[0]),
        "imported_at": row[1],
        "metadata": json.loads(row[3] or "{}"),
        "analysis": json.loads(row[2]),
    }


def _comparison_port_key(port: dict) -> tuple[str, str]:
    return (str(port.get("protocol") or ""), str(port.get("port") or ""))


def _comparison_service(port: dict) -> dict:
    return {
        "protocol": port.get("protocol"),
        "port": port.get("port"),
        "service": port.get("service"),
        "product": port.get("product"),
        "version": port.get("version"),
    }


def compare_import_results(first_sha256: str, second_sha256: str,
                           db_path: Path = DB_PATH) -> dict:
    """Compare two retained Nmap analyses without reparsing their XML files."""
    first = get_import_history_item(first_sha256, db_path)
    second = get_import_history_item(second_sha256, db_path)
    if first is None or second is None:
        raise KeyError("One or both Nmap imports were not found")

    def valid_ip(value: object) -> str:
        """Return a canonical IP address for stable host matching."""
        try:
            return str(ipaddress.ip_address(str(value).strip()))
        except (ValueError, TypeError):
            return ""

    def host_map(item: dict) -> dict[str, dict]:
        result: dict[str, dict] = {}
        for host in item.get("analysis", {}).get("hosts", []) or []:
            key = valid_ip(host.get("ip")) or str(host.get("hostname") or host.get("name") or "").strip().lower()
            if key:
                result[key] = host
        return result

    before, after = host_map(first), host_map(second)
    added_keys = sorted(set(after) - set(before))
    removed_keys = sorted(set(before) - set(after))
    changed = []
    for key in sorted(set(before) & set(after)):
        old_ports = {_comparison_port_key(port): port for port in before[key].get("ports", []) or []}
        new_ports = {_comparison_port_key(port): port for port in after[key].get("ports", []) or []}
        added_ports = [_comparison_service(new_ports[item]) for item in sorted(set(new_ports) - set(old_ports))]
        removed_ports = [_comparison_service(old_ports[item]) for item in sorted(set(old_ports) - set(new_ports))]
        service_changes = []
        for port_key in sorted(set(old_ports) & set(new_ports)):
            old_service, new_service = _comparison_service(old_ports[port_key]), _comparison_service(new_ports[port_key])
            if old_service != new_service:
                service_changes.append({"port": new_service["port"], "protocol": new_service["protocol"], "before": old_service, "after": new_service})
        old_identity = {field: before[key].get(field) for field in ("hostname", "name", "state", "os", "os_group")}
        new_identity = {field: after[key].get(field) for field in ("hostname", "name", "state", "os", "os_group")}
        identity_changes = {field: {"before": old_identity[field], "after": new_identity[field]} for field in old_identity if old_identity[field] != new_identity[field]}
        if added_ports or removed_ports or service_changes or identity_changes:
            changed.append({"key": key, "ip": after[key].get("ip") or before[key].get("ip"), "added_ports": added_ports, "removed_ports": removed_ports, "service_changes": service_changes, "identity_changes": identity_changes})

    def public_host(host: dict, key: str) -> dict:
        return {"key": key, "ip": host.get("ip"), "hostname": host.get("hostname") or host.get("name"), "ports": [_comparison_service(port) for port in host.get("ports", []) or []]}

    return {
        "before": {"sha256": first["sha256"], "filename": first["filename"], "imported_at": first["imported_at"]},
        "after": {"sha256": second["sha256"], "filename": second["filename"], "imported_at": second["imported_at"]},
        "summary": {"hosts_added": len(added_keys), "hosts_removed": len(removed_keys), "hosts_changed": len(changed), "before_hosts": len(before), "after_hosts": len(after)},
        "hosts_added": [public_host(after[key], key) for key in added_keys],
        "hosts_removed": [public_host(before[key], key) for key in removed_keys],
        "hosts_changed": changed,
    }


@router.get("/scan-profiles")
def scan_profile_history(all_versions: bool = False) -> list[dict]:
    return list_scan_profiles(all_versions=all_versions)


@router.get("/safety/no-strike")
def global_no_strike_list() -> dict:
    return get_global_no_strike()


@router.post("/safety/no-strike", status_code=201)
def add_to_global_no_strike(request: NoStrikeUpdate) -> dict:
    try:
        return add_global_no_strike(request)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post("/safety/no-strike/remove-challenge")
def global_no_strike_remove_challenge(entries: list[str]) -> dict:
    try:
        requested = normalize_ipv4_networks(entries, "no-strike")
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    current = get_global_no_strike()["entries"]
    if any(entry not in current for entry in requested):
        raise HTTPException(status_code=404, detail="No-strike entry not found")
    return issue_delete_challenge("global-no-strike", ",".join(requested))


@router.post("/safety/no-strike/remove")
def remove_from_global_no_strike(request: NoStrikeRemoval) -> dict:
    try:
        return remove_global_no_strike(request)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/scan-profiles/{profile_id}/versions/{version}")
def scan_profile_detail(profile_id: str, version: int) -> dict:
    profile = get_scan_profile(profile_id, version)
    if profile is None:
        raise HTTPException(status_code=404, detail="Scan profile version not found")
    return profile


@router.post("/scan-profiles", status_code=201)
def save_scan_profile(request: ScanProfileCreate) -> dict:
    try:
        return create_scan_profile(request)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post("/scan-profiles/{profile_id}/versions", status_code=201)
def save_scan_profile_version(profile_id: str, request: ScanProfileVersionCreate) -> dict:
    try:
        return create_scan_profile_version(profile_id, request)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post("/scan-profiles/{profile_id}/clone", status_code=201)
def clone_saved_scan_profile(profile_id: str, request: ScanProfileClone) -> dict:
    try:
        return clone_scan_profile(profile_id, request)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post("/scan-profiles/{profile_id}/delete-challenge")
def scan_profile_delete_challenge(profile_id: str) -> dict:
    profile = get_scan_profile(profile_id)
    if profile is None:
        raise HTTPException(status_code=404, detail="Scan profile not found")
    if profile["built_in"]:
        raise HTTPException(status_code=403, detail="Built-in profiles cannot be deleted")
    return issue_delete_challenge("profile", profile_id)


@router.post("/scan-profiles/{profile_id}/delete")
def delete_saved_scan_profile(profile_id: str, confirmation: DeleteConfirmation) -> dict:
    try:
        return delete_scan_profile(profile_id, confirmation.confirmation)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Scan profile not found") from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


@router.get("/scan-schedules")
def scan_schedule_history() -> list[dict]:
    return list_scan_schedules()


@router.post("/scan-schedules", status_code=201)
def save_scan_schedule(request: ScanScheduleCreate) -> dict:
    try:
        return create_scan_schedule(request)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post("/scan-schedules/{schedule_id}/state")
def change_scan_schedule_state(schedule_id: str, request: ScheduleStateChange) -> dict:
    try:
        return set_scan_schedule_enabled(schedule_id, request.enabled)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Scan schedule not found") from exc


@router.post("/scan-schedules/{schedule_id}/profile")
def repin_scan_schedule_profile(schedule_id: str, request: ScheduleProfileChange) -> dict:
    try:
        return change_scan_schedule_profile(schedule_id, request)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Scan schedule not found") from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/scan-schedules/{schedule_id}/run", status_code=202)
def run_saved_scan_schedule(schedule_id: str) -> dict:
    try:
        return run_scan_schedule_now(schedule_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Scan schedule not found") from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post("/scan-schedules/{schedule_id}/delete-challenge")
def scan_schedule_delete_challenge(schedule_id: str) -> dict:
    if get_scan_schedule(schedule_id) is None:
        raise HTTPException(status_code=404, detail="Scan schedule not found")
    return issue_delete_challenge("schedule", schedule_id)


@router.post("/scan-schedules/{schedule_id}/delete")
def delete_saved_scan_schedule(schedule_id: str, confirmation: DeleteConfirmation) -> dict:
    try:
        return delete_scan_schedule(schedule_id, confirmation.confirmation)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Scan schedule not found") from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/scan-runs/plans", status_code=201)
def create_scan_run_plan(plan: ScanRunPlan) -> dict:
    try:
        return save_scan_run_plan(plan)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post("/scan-runs", status_code=202)
def start_scan_run(request: ScanRunRequest) -> dict:
    try:
        return launch_scan_run(request)
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post("/scan-runs/{run_id}/fallback-decision", status_code=202)
def decide_scan_fallback(run_id: str, request: FallbackDecision) -> dict:
    manifest = get_scan_run_plan(run_id)
    if manifest is None:
        raise HTTPException(status_code=404, detail="Scan run not found")
    with ACTIVE_RUNS_LOCK:
        control = ACTIVE_RUNS.get(run_id)
        if control is None or manifest["status"] != "awaiting_fallback_approval":
            raise HTTPException(status_code=409, detail="Fallback approval is not pending")
        if control.fallback_decision is not None:
            raise HTTPException(status_code=409, detail="Fallback decision already recorded")
        control.fallback_decision = request.decision
        control.fallback_decided_by = request.decided_by
        control.fallback_authorization_note = request.authorization_note
        control.fallback_decision_event.set()
    return {"run_id": run_id, "decision": request.decision, "status": "decision_recorded"}


@router.post("/scan-runs/{run_id}/cancel", status_code=202)
def cancel_scan_run(run_id: str) -> dict:
    manifest = get_scan_run_plan(run_id)
    if manifest is None:
        raise HTTPException(status_code=404, detail="Scan run not found")
    with ACTIVE_RUNS_LOCK:
        control = ACTIVE_RUNS.get(run_id)
    if control is None or manifest["status"] not in {"queued", "running", "awaiting_fallback_approval"}:
        raise HTTPException(status_code=409, detail="Scan run is not active")
    control.cancel_event.set()
    return {"run_id": run_id, "status": "cancellation_requested"}


@router.post("/scan-runs/delete-challenge")
def scan_delete_challenge(run_id: str | None = None) -> dict:
    if run_id is not None and get_scan_run_plan(run_id) is None:
        raise HTTPException(status_code=404, detail="Scan run not found")
    return issue_delete_challenge("scan" if run_id else "all", run_id)


@router.post("/scan-runs/{run_id}/delete")
def delete_scan_run(run_id: str, confirmation: DeleteConfirmation) -> dict:
    try:
        return delete_scan_data(run_id, confirmation.confirmation)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Scan run not found") from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


@router.post("/scan-runs/delete-all")
def delete_all_scan_runs(confirmation: DeleteConfirmation) -> dict:
    try:
        return delete_all_scan_data(confirmation.confirmation)
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


@router.get("/stored-files")
def stored_files(limit: int = Query(default=300, ge=1, le=500)) -> dict:
    return list_stored_files(limit=limit)


@router.get("/scan-runs/interfaces")
def scan_interfaces() -> dict:
    return {"interfaces": sorted(available_interfaces())}


@router.get("/scan-runs")
def scan_run_history(limit: int = Query(default=50, ge=1, le=200)) -> list[dict]:
    return list_scan_run_plans(limit=limit)


@router.get("/scan-runs/{run_id}")
def scan_run_detail(run_id: str) -> dict:
    manifest = get_scan_run_plan(run_id)
    if manifest is None:
        raise HTTPException(status_code=404, detail="Scan run not found")
    return manifest


@router.get("/scan-runs/{run_id}/artifacts")
def scan_run_artifacts(run_id: str) -> list[dict]:
    manifest = get_scan_run_plan(run_id)
    if manifest is None:
        raise HTTPException(status_code=404, detail="Scan run not found")
    return manifest.get("artifacts", [])


@router.get("/scan-runs/{run_id}/artifacts/{artifact_name}")
def download_scan_artifact(run_id: str, artifact_name: str) -> FileResponse:
    manifest = get_scan_run_plan(run_id)
    if manifest is None:
        raise HTTPException(status_code=404, detail="Scan run not found")
    try:
        path, media_type = artifact_path(manifest, artifact_name)
    except (ValueError, FileNotFoundError) as exc:
        raise HTTPException(status_code=404, detail="Artifact not found") from exc
    return FileResponse(
        path,
        media_type=media_type,
        filename=f"{run_id}-{path.name}",
    )


@router.get("/imports")
def import_history(limit: int = Query(default=50, ge=1, le=200)) -> list[dict]:
    return list_import_history(limit=limit)


@router.get("/imports/compare")
def import_compare(first: str, second: str) -> dict:
    try:
        return compare_import_results(first, second)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/imports/{sha256}")
def import_history_detail(sha256: str) -> dict:
    item = get_import_history_item(sha256)
    if item is None:
        raise HTTPException(status_code=404, detail="Import not found")
    return item
