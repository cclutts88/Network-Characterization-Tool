from __future__ import annotations

import calendar
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

from app.comparison import compare_analyses, coverage_warnings
from app.build_info import APP_VERSION, BUILD_COMMIT, BUILD_ID
from app.scan_profiles import (
    BUILTIN_PROFILES,
    build_nmap_flags,
    build_phase_nmap_flags,
    normalize_scan_options,
    scan_coverage,
    scan_display_name,
)
from app.scan_progress import latest_nmap_status, new_scan_progress, update_scan_progress
from app.saved_networks import (
    SavedNetworkArchive,
    SavedNetworkCreate,
    SavedNetworkUpdate,
    archive_saved_network,
    create_saved_network,
    get_saved_network,
    init_saved_network_storage,
    list_saved_networks,
    resolve_saved_network_targets,
    update_saved_network,
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
    "targets": ("targets.txt", "text/plain"),
    "discovery_targets": ("discovery-targets.txt", "text/plain"),
    "no_strike": ("no-strike.txt", "text/plain"),
    "xml": ("scan.xml", "application/xml"),
    "stdout": ("stdout.txt", "text/plain"),
    "stderr": ("stderr.txt", "text/plain"),
    "pcap": ("capture.pcap", "application/vnd.tcpdump.pcap"),
    "capture_stderr": ("capture-stderr.txt", "text/plain"),
    "fping_alive": ("fping-alive.txt", "text/plain"),
    "fping_stderr": ("fping-stderr.txt", "text/plain"),
    "discovery_xml": ("discovery.xml", "application/xml"),
    "discovery_stdout": ("discovery-stdout.txt", "text/plain"),
    "discovery_stderr": ("discovery-stderr.txt", "text/plain"),
    "discovery_alive": ("discovery-alive.txt", "text/plain"),
    "tcp_xml": ("tcp-scan.xml", "application/xml"),
    "tcp_stdout": ("tcp-stdout.txt", "text/plain"),
    "tcp_stderr": ("tcp-stderr.txt", "text/plain"),
    "udp_xml": ("udp-scan.xml", "application/xml"),
    "udp_stdout": ("udp-stdout.txt", "text/plain"),
    "udp_stderr": ("udp-stderr.txt", "text/plain"),
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
        "once", "interval", "custom_hours", "hourly", "daily", "weekly", "monthly"
    ] = "once"
    first_run_at: datetime
    cadence_hours: int = Field(default=2, ge=1, le=8760)
    # Retained so schedules created by earlier builds remain readable.
    interval_minutes: int = Field(default=60, ge=5, le=10080)
    reason: str = Field(default="Scheduled authorized characterization", min_length=1, max_length=500)
    originating_host: str = Field(default="scheduler", min_length=1, max_length=255)
    timeout_seconds: int = Field(default=2700, ge=10, le=3600)
    chunking_enabled: bool = False
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
    changed_by: str | None = Field(default=None, max_length=100)

    @field_validator("changed_by")
    @classmethod
    def clean_changed_by(cls, value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = value.strip()
        return cleaned or None


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
    batch_hosts_total: int | None = Field(default=None, ge=1)
    batch_hosts_completed_before: int = Field(default=0, ge=0)
    targets: list[str] = Field(default_factory=list)
    manual_targets: list[str] = Field(default_factory=list)
    saved_network_ids: list[str] = Field(default_factory=list)
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
    timeout_seconds: int = Field(default=2700, ge=10, le=3600)


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


class ScanSafetySummaryRequest(BaseModel):
    """Calculate the effective scan scope without starting a scan."""

    model_config = ConfigDict(extra="forbid")

    targets: list[str] = Field(min_length=1)
    no_strike: list[str] = Field(default_factory=list)


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
    """Return the excluded no-strike list that applies to every scan path."""
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


def scan_safety_summary(
    targets: list[str],
    additional: list[str] | None = None,
    db_path: Path = DB_PATH,
) -> dict:
    """Return additive address counts for a pre-launch safety review."""
    normalized_targets = normalize_ipv4_networks(targets, "target")
    normalized_additional = (
        normalize_ipv4_networks(additional, "no-strike") if additional else []
    )
    global_entries = get_global_no_strike(db_path)["entries"]

    target_addresses = {
        str(address)
        for network in (
            ipaddress.ip_network(entry, strict=False) for entry in normalized_targets
        )
        for address in network
    }
    global_addresses = {
        str(address)
        for network in (
            ipaddress.ip_network(entry, strict=False) for entry in global_entries
        )
        for address in network
        if str(address) in target_addresses
    }
    additional_addresses = {
        str(address)
        for network in (
            ipaddress.ip_network(entry, strict=False)
            for entry in normalized_additional
        )
        for address in network
        if str(address) in target_addresses
    }
    overlap_addresses = global_addresses & additional_addresses
    additional_unique = additional_addresses - global_addresses
    excluded_addresses = global_addresses | additional_addresses

    return {
        "targets": normalized_targets,
        "requested_address_count": len(target_addresses),
        "global_entry_count": len(global_entries),
        "global_excluded_address_count": len(global_addresses),
        "additional_entry_count": len(normalized_additional),
        "additional_excluded_address_count": len(additional_unique),
        "overlap_address_count": len(overlap_addresses),
        "excluded_address_count": len(excluded_addresses),
        "effective_address_count": len(target_addresses - excluded_addresses),
    }


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
    argv = [
        "nmap", *build_nmap_flags(scan_options), "--stats-every", "2s",
        "-e", interface, "-iL", target_file,
    ]
    if include_no_strike:
        argv.extend(["--excludefile", "no-strike.txt"])
    argv.extend(["-oX", "scan.xml"])
    return argv


def build_nmap_discovery_argv(interface: str, *, include_no_strike: bool) -> list[str]:
    argv = [
        "nmap", "-sn", "-n", "--reason", "--stats-every", "2s",
        "-e", interface, "-iL", "targets.txt",
    ]
    if include_no_strike:
        argv.extend(["--excludefile", "no-strike.txt"])
    argv.extend(["-oX", "discovery.xml"])
    return argv


def build_scan_phase_argv(
    interface: str,
    scan_options: dict,
    protocol: str,
    *,
    include_no_strike: bool,
    target_file: str,
    pre_discovered: bool,
) -> list[str]:
    argv = [
        "nmap",
        *build_phase_nmap_flags(
            scan_options, protocol, pre_discovered=pre_discovered
        ),
        "--stats-every", "2s", "-e", interface, "-iL", target_file,
    ]
    if include_no_strike:
        argv.extend(["--excludefile", "no-strike.txt"])
    argv.extend(["-oX", f"{protocol}-scan.xml"])
    return argv


def build_execution_phases(
    interface: str,
    scan_options: dict,
    *,
    include_no_strike: bool,
    target_file: str,
    pre_discovered: bool,
) -> list[dict]:
    selected = scan_options.get("protocol", "tcp")
    protocols = ["tcp", "udp"] if selected == "tcp_udp" else [selected]
    phases = []
    for protocol in protocols:
        command = build_scan_phase_argv(
            interface,
            scan_options,
            protocol,
            include_no_strike=include_no_strike,
            target_file=target_file,
            pre_discovered=pre_discovered,
        )
        execution = build_nmap_execution_argv(command)
        phases.append({
            "name": protocol,
            "protocol": protocol.upper(),
            "status": "pending",
            "command_argv": command,
            "exact_command": shlex.join(command),
            "execution_command_argv": execution,
            "exact_execution_command": shlex.join(execution),
            "xml_filename": f"{protocol}-scan.xml",
            "stdout_filename": f"{protocol}-stdout.txt",
            "stderr_filename": f"{protocol}-stderr.txt",
        })
    return phases


def build_nmap_execution_argv(
    nmap_argv: list[str], *, platform_name: str | None = None
) -> list[str]:
    """Give Nmap a terminal on Linux so --stats-every emits live progress."""
    platform_name = platform_name or os.name
    if platform_name != "posix":
        return list(nmap_argv)
    return [
        "script",
        "--quiet",
        "--return",
        "--flush",
        "--command",
        shlex.join(nmap_argv),
        "/dev/null",
    ]


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
    manifest["execution_command_argv"] = build_nmap_execution_argv(
        manifest["command_argv"]
    )
    manifest["exact_execution_command"] = shlex.join(
        manifest["execution_command_argv"]
    )
    manifest["execution_phases"] = build_execution_phases(
        manifest["interface"],
        manifest["profile_settings"],
        include_no_strike=bool(manifest.get("no_strike")),
        target_file="targets.txt",
        pre_discovered=False,
    )
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
    # New clients send resolved ``targets`` for legacy preview/package paths as
    # well as explicit Saved Network IDs.  When IDs are present, only the
    # explicit manual list belongs in the ad-hoc snapshot.
    manual_source = (
        plan.manual_targets
        if plan.manual_targets or plan.saved_network_ids
        else plan.targets
    )
    targets, saved_network_snapshots, manual_targets = resolve_saved_network_targets(
        plan.saved_network_ids,
        manual_source,
        db_path,
        max_addresses=MAX_EXPANDED_ADDRESSES,
    )
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
    execution_argv = build_nmap_execution_argv(nmap_argv)
    discovery_argv = (
        build_fping_argv(plan.interface)
        if use_fping
        else build_nmap_discovery_argv(
            plan.interface, include_no_strike=bool(no_strike)
        )
    )
    discovery_execution_argv = (
        discovery_argv
        if use_fping
        else build_nmap_execution_argv(discovery_argv)
    )
    execution_phases = build_execution_phases(
        plan.interface,
        settings,
        include_no_strike=bool(no_strike),
        target_file="fping-alive.txt" if use_fping else "discovery-alive.txt",
        pre_discovered=True,
    )
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
    scope_hosts_total = len(expanded_discovery_targets(targets, no_strike))
    progress = new_scan_progress(
        scope_hosts_total,
        phase=status,
        chunk_number=plan.chunk_number,
        chunk_count=plan.chunk_count,
        batch_hosts_total=plan.batch_hosts_total,
        batch_hosts_completed_before=plan.batch_hosts_completed_before,
        updated_at=created_at,
    )
    return {
        "schema_version": 5,
        "application_version": APP_VERSION,
        "build_id": BUILD_ID,
        "build_commit": BUILD_COMMIT,
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
        "batch_hosts_total": plan.batch_hosts_total,
        "batch_hosts_completed_before": plan.batch_hosts_completed_before,
        "reason": plan.reason,
        "originating_host": plan.originating_host,
        "interface": plan.interface,
        "profile": profile_record["name"],
        "profile_id": profile_record["profile_id"],
        "profile_version": profile_record["version"],
        "profile_settings": settings,
        "targets": targets,
        "manual_targets": manual_targets,
        "saved_network_ids": [
            item["saved_network_id"] for item in saved_network_snapshots
        ],
        "saved_networks": saved_network_snapshots,
        "target_selection": {
            "saved_networks": saved_network_snapshots,
            "manual_targets": manual_targets,
        },
        "no_strike": no_strike,
        "coverage": coverage,
        "capture_requested": capture,
        "discovery_mode": settings.get("discovery_mode", "nmap"),
        "discovery_command_argv": discovery_argv,
        "exact_discovery_command": shlex.join(discovery_argv) if discovery_argv else None,
        "discovery_execution_command_argv": discovery_execution_argv,
        "exact_discovery_execution_command": (
            shlex.join(discovery_execution_argv)
            if discovery_execution_argv else None
        ),
        "timeout_seconds": timeout_seconds,
        "command_argv": nmap_argv,
        "exact_command": shlex.join(nmap_argv),
        "execution_command_argv": execution_argv,
        "exact_execution_command": shlex.join(execution_argv),
        "execution_phases": execution_phases,
        "workflow": ["discovery", *[item["name"] for item in execution_phases], "merge", "analysis"],
        "capture_command_argv": capture_argv,
        "exact_capture_command": shlex.join(capture_argv) if capture_argv else None,
        "artifacts": [],
        "progress": progress,
    }


def init_poc_storage(db_path: Path = DB_PATH) -> None:
    init_saved_network_storage(db_path)
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


def _next_month(moment: datetime, anchor_day: int) -> datetime:
    year = moment.year + (1 if moment.month == 12 else 0)
    month = 1 if moment.month == 12 else moment.month + 1
    day = min(anchor_day, calendar.monthrange(year, month)[1])
    return moment.replace(year=year, month=month, day=day)


def next_schedule_time(schedule: dict, after: datetime) -> datetime | None:
    """Advance a schedule after dispatch, preserving its original cadence."""
    if schedule["cadence"] == "once":
        return None
    current = _as_utc(schedule["next_run_at"])
    if schedule["cadence"] == "monthly":
        anchor_day = _as_utc(schedule.get("first_run_at") or current).day
        while current <= after:
            current = _next_month(current, anchor_day)
        return current
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


def _append_schedule_history(
    schedule: dict,
    event: str,
    changed_by: str,
    details: str,
    *,
    changed_at: str | None = None,
) -> None:
    timestamp = changed_at or utc_now()
    history = list(schedule.get("modification_history") or [])
    history.append(
        {
            "event": event,
            "changed_at": timestamp,
            "changed_by": changed_by,
            "details": details,
        }
    )
    schedule["modification_history"] = history[-100:]
    schedule["last_changed_by"] = changed_by
    schedule["last_changed_at"] = timestamp


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
    legacy_chunk_request = (
        "chunk_size" in request.model_fields_set
        and "chunking_enabled" not in request.model_fields_set
    )
    chunking_enabled = request.chunking_enabled or legacy_chunk_request
    created_at = utc_now()
    definition = {
        "schema_version": 4,
        "schedule_id": uuid.uuid4().hex,
        "name": request.name,
        "created_at": created_at,
        "updated_at": created_at,
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
        "chunking_enabled": chunking_enabled,
        "chunk_size": request.chunk_size,
        "chunk_delay_seconds": (
            request.chunk_delay_seconds
            if chunking_enabled and request.chunk_size != 256
            else 0
        ),
        "fallback_policy": request.fallback_policy,
        "enabled": bool(request.enabled),
        "run_count": 0,
        "last_run_id": None,
        "last_run_at": None,
        "last_run_status": None,
        "last_changed_by": request.created_by,
        "last_changed_at": created_at,
        "modification_history": [
            {
                "event": "created",
                "changed_at": created_at,
                "changed_by": request.created_by,
                "details": (
                    f"Created {request.cadence} schedule pinned to "
                    f"{profile['name']} v{profile['version']}"
                ),
            }
        ],
        "conflict_count": 0,
        "conflict_flagged": False,
        "last_conflict_at": None,
        "last_conflict_key": None,
        "batch_status": None,
        "active_batch_id": None,
        "active_chunk_number": None,
        "active_chunk_count": None,
        "completed_chunk_count": 0,
        "resume_after_chunk": 0,
        "last_occurrence_started_at": None,
        "last_occurrence_completed_at": None,
        "last_occurrence_status": None,
        "last_occurrence_batch_id": None,
        "last_occurrence_run_ids": [],
        "recovery_count": 0,
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
    schedule_id: str,
    enabled: bool,
    changed_by: str | None = None,
    db_path: Path = DB_PATH,
) -> dict:
    schedule = get_scan_schedule(schedule_id, db_path)
    if schedule is None:
        raise KeyError("Scan schedule not found")
    previous = bool(schedule.get("enabled"))
    schedule["enabled"] = bool(enabled)
    actor = changed_by or schedule.get("last_changed_by") or schedule["created_by"]
    if enabled:
        completed_chunks = int(schedule.get("completed_chunk_count") or 0)
        total_chunks = int(schedule.get("active_chunk_count") or 0)
        resuming = (
            completed_chunks
            and total_chunks
            and completed_chunks < total_chunks
            and schedule.get("batch_status")
            in {
                "paused_after_current_chunk",
                "interrupted_paused",
                "failed_to_dispatch",
            }
        )
        if resuming:
            schedule["batch_status"] = "recovery_pending"
            schedule["resume_after_chunk"] = completed_chunks
            schedule["next_run_at"] = utc_now()
        elif not schedule.get("next_run_at"):
            schedule["next_run_at"] = utc_now()
        elif _as_utc(schedule["next_run_at"]) < datetime.now(timezone.utc):
            if schedule["cadence"] == "once":
                schedule["next_run_at"] = utc_now()
            else:
                schedule["next_run_at"] = next_schedule_time(
                    schedule, datetime.now(timezone.utc)
                ).isoformat()
    if previous != bool(enabled):
        _append_schedule_history(
            schedule,
            "enabled" if enabled else "paused",
            actor,
            "Enabled recurring execution" if enabled else "Paused recurring execution",
        )
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
    previous_profile = f"{schedule['profile_name']} v{schedule['profile_version']}"
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
            "profile_changed_at": utc_now(),
        }
    )
    _append_schedule_history(
        schedule,
        "profile_changed",
        request.changed_by,
        f"Changed pinned profile from {previous_profile} to {profile['name']} v{profile['version']}",
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


def group_scan_runs_by_saved_network(runs: list[dict]) -> list[dict]:
    """Group history by the Saved Network snapshots retained by each run."""
    groups: dict[str, dict] = {}
    for run in runs:
        target_selection = run.get("target_selection") or {}
        snapshots = run.get("saved_networks") or target_selection.get("saved_networks") or []
        unique_snapshots: list[dict] = []
        seen: set[str] = set()
        for snapshot in snapshots:
            if not isinstance(snapshot, dict):
                continue
            identity = str(
                snapshot.get("saved_network_id")
                or snapshot.get("cidr")
                or snapshot.get("name")
                or ""
            )
            if not identity or identity in seen:
                continue
            seen.add(identity)
            unique_snapshots.append(snapshot)

        if len(unique_snapshots) == 1:
            network = unique_snapshots[0]
            identity = str(
                network.get("saved_network_id")
                or network.get("cidr")
                or network.get("name")
            )
            group_id = f"saved:{identity}"
            group = groups.setdefault(
                group_id,
                {
                    "group_id": group_id,
                    "kind": "saved_network",
                    "name": network.get("name") or "Unnamed Saved Network",
                    "cidr": network.get("cidr") or "",
                    "description": network.get("description") or "",
                    "category": network.get("category") or "",
                    "tags": list(network.get("tags") or []),
                    "runs": [],
                },
            )
        elif len(unique_snapshots) > 1:
            group_id = "multiple-saved-networks"
            group = groups.setdefault(
                group_id,
                {
                    "group_id": group_id,
                    "kind": "multiple_saved_networks",
                    "name": "Multiple Saved Networks",
                    "cidr": "",
                    "description": "Scans spanning more than one Saved Network snapshot.",
                    "category": "",
                    "tags": [],
                    "runs": [],
                },
            )
        else:
            group_id = "ad-hoc-manual"
            group = groups.setdefault(
                group_id,
                {
                    "group_id": group_id,
                    "kind": "manual",
                    "name": "Ad Hoc / Manual Scans",
                    "cidr": "",
                    "description": "Scans created without a Saved Network snapshot.",
                    "category": "",
                    "tags": [],
                    "runs": [],
                },
            )
        group["runs"].append(run)

    for group in groups.values():
        group["runs"].sort(
            key=lambda item: item.get("created_at") or "", reverse=True
        )
        latest = group["runs"][0]
        group["scan_count"] = len(group["runs"])
        group["latest_scan_at"] = latest.get("completed_at") or latest.get("created_at")
        group["latest_scan_name"] = latest.get("display_name") or latest.get("name")
        group["latest_host_count"] = latest.get("host_count")

    kind_order = {
        "saved_network": 0,
        "multiple_saved_networks": 1,
        "manual": 2,
    }
    return sorted(
        groups.values(),
        key=lambda item: (
            kind_order.get(item["kind"], 99),
            str(item["name"]).casefold(),
            str(item.get("cidr") or ""),
        ),
    )


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


def nmap_up_addresses(xml_path: Path) -> list[str]:
    """Return unique IPv4 addresses marked up in an Nmap XML document."""
    if not xml_path.is_file():
        return []
    try:
        root = ET.parse(xml_path).getroot()
    except (ET.ParseError, OSError):
        return []
    addresses = []
    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue
        address = next(
            (
                item.get("addr")
                for item in host.findall("address")
                if item.get("addrtype") == "ipv4" and item.get("addr")
            ),
            None,
        )
        if address and address not in addresses:
            addresses.append(address)
    return addresses


def merge_nmap_xml(source_paths: list[Path], destination: Path) -> int:
    """Merge successful protocol XML into the canonical analysis artifact."""
    roots = []
    for path in source_paths:
        if not path.is_file():
            continue
        try:
            roots.append(ET.parse(path).getroot())
        except (ET.ParseError, OSError):
            continue
    if not roots:
        raise ValueError("No readable Nmap phase XML was available to merge")
    merged = ET.Element("nmaprun", dict(roots[0].attrib))
    for root in roots:
        for scaninfo in root.findall("scaninfo"):
            merged.append(ET.fromstring(ET.tostring(scaninfo, encoding="unicode")))
    hosts: dict[str, ET.Element] = {}
    for root in roots:
        for host in root.findall("host"):
            address = next(
                (
                    item.get("addr")
                    for item in host.findall("address")
                    if item.get("addrtype") == "ipv4" and item.get("addr")
                ),
                ET.tostring(host, encoding="unicode"),
            )
            if address not in hosts:
                copy = ET.fromstring(ET.tostring(host, encoding="unicode"))
                hosts[address] = copy
                merged.append(copy)
                continue
            existing = hosts[address]
            existing_ports = existing.find("ports")
            source_ports = host.find("ports")
            if source_ports is None:
                continue
            if existing_ports is None:
                existing_ports = ET.SubElement(existing, "ports")
            known = {
                (port.get("protocol"), port.get("portid"))
                for port in existing_ports.findall("port")
            }
            for port in source_ports.findall("port"):
                key = (port.get("protocol"), port.get("portid"))
                if key not in known:
                    existing_ports.append(
                        ET.fromstring(ET.tostring(port, encoding="unicode"))
                    )
                    known.add(key)
            for extraports in source_ports.findall("extraports"):
                existing_ports.append(
                    ET.fromstring(ET.tostring(extraports, encoding="unicode"))
                )
    finished = roots[-1].find("runstats/finished")
    hosts_up = sum(
        1
        for host in hosts.values()
        if host.find("status") is None or host.find("status").get("state") == "up"
    )
    runstats = ET.SubElement(merged, "runstats")
    ET.SubElement(runstats, "finished", dict(finished.attrib) if finished is not None else {})
    ET.SubElement(
        runstats,
        "hosts",
        {"up": str(hosts_up), "down": "0", "total": str(len(hosts))},
    )
    ET.ElementTree(merged).write(destination, encoding="utf-8", xml_declaration=True)
    return hosts_up


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


def persist_scan_progress(
    manifest: dict,
    *,
    db_path: Path = DB_PATH,
    data_dir: Path = DATA_DIR,
    **changes,
) -> bool:
    """Persist a progress change to both the database and retained manifest."""
    changed = update_scan_progress(
        manifest["progress"], updated_at=utc_now(), **changes
    )
    if changed:
        update_scan_run_manifest(manifest, db_path)
        write_manifest_file(manifest, data_dir)
    return changed


def refresh_nmap_progress(
    manifest: dict,
    output_path: Path,
    *,
    phase: str = "nmap",
    db_path: Path = DB_PATH,
    data_dir: Path = DATA_DIR,
) -> bool:
    """Read the newest Nmap terminal status without interfering with its output."""
    try:
        with output_path.open("rb") as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            handle.seek(max(0, size - 131072))
            status = latest_nmap_status(
                handle.read().decode("utf-8", errors="replace")
            )
    except OSError:
        return False
    if status is None:
        return False
    return persist_scan_progress(
        manifest,
        phase=phase,
        **status,
        db_path=db_path,
        data_dir=data_dir,
    )


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
    persist_scan_progress(manifest, phase="discovery", db_path=db_path, data_dir=data_dir)
    started = time.monotonic()
    deadline = started + int(manifest["timeout_seconds"])
    exit_code = None
    successful_xml: list[Path] = []

    def watch_process(
        argv: list[str],
        stdout_path: Path,
        stderr_path: Path,
        *,
        phase: str,
        process_attr: str,
        allowed_exit_codes: set[int],
        track_nmap: bool,
    ) -> tuple[str, int | None]:
        with stdout_path.open("wb") as stdout_handle, stderr_path.open("wb") as stderr_handle:
            process = popen_factory(
                argv,
                cwd=run_dir,
                stdin=subprocess.DEVNULL,
                stdout=stdout_handle,
                stderr=stderr_handle,
                start_new_session=True,
            )
            setattr(control, process_attr, process)
            last_progress_check = 0.0
            while True:
                code = process.poll()
                if code is not None:
                    if track_nmap:
                        refresh_nmap_progress(
                            manifest, stdout_path, phase=phase,
                            db_path=db_path, data_dir=data_dir,
                        )
                    return ("completed" if code in allowed_exit_codes else "failed", code)
                if control.cancel_event.is_set():
                    terminate_process(process)
                    return "cancelled", process.poll()
                if time.monotonic() >= deadline:
                    terminate_process(process)
                    return "timed_out", process.poll()
                now = time.monotonic()
                if now - last_progress_check >= 1:
                    if track_nmap:
                        refresh_nmap_progress(
                            manifest, stdout_path, phase=phase,
                            db_path=db_path, data_dir=data_dir,
                        )
                    persist_scan_progress(
                        manifest,
                        phase=phase,
                        elapsed_seconds=max(0, int(now - started)),
                        deadline_remaining_seconds=max(0, int(deadline - now)),
                        db_path=db_path,
                        data_dir=data_dir,
                    )
                    last_progress_check = now
                sleep_fn(0.2)

    try:
        capture_error_path = run_dir / "capture-stderr.txt"
        with capture_error_path.open("wb") as capture_error_handle:
            def start_capture(label: str = "the scan") -> None:
                if not manifest["capture_requested"]:
                    return
                control.capture_process = popen_factory(
                    manifest["capture_command_argv"], cwd=run_dir,
                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                    stderr=capture_error_handle, start_new_session=True,
                )
                sleep_fn(0.25)
                capture_exit = control.capture_process.poll()
                if capture_exit is not None:
                    raise RuntimeError(
                        f"tcpdump exited before {label} with status {capture_exit}"
                    )

            start_capture()
            run_phases = True
            alive_hosts: list[str] = []
            if manifest.get("discovery_mode") == "fping":
                discovery_status, discovery_exit = watch_process(
                    manifest["discovery_command_argv"],
                    run_dir / "fping-alive.txt",
                    run_dir / "fping-stderr.txt",
                    phase="discovery", process_attr="discovery_process",
                    allowed_exit_codes={0, 1}, track_nmap=False,
                )
                exit_code = discovery_exit
                if discovery_status != "completed":
                    manifest["status"] = discovery_status
                    run_phases = False
                alive_hosts = [
                    line.strip()
                    for line in (run_dir / "fping-alive.txt").read_text(
                        encoding="utf-8", errors="replace"
                    ).splitlines()
                    if line.strip()
                ]
                manifest["discovery_host_count"] = len(alive_hosts)
                if run_phases and not alive_hosts:
                    terminate_process(control.capture_process)
                    control.capture_process = None
                    fallback_argv = build_nmap_argv(
                        manifest["profile"], manifest["interface"],
                        include_no_strike=bool(manifest.get("no_strike")),
                        scan_options=manifest["profile_settings"],
                        target_file="targets.txt",
                    )
                    manifest["fallback_command_argv"] = fallback_argv
                    manifest["exact_fallback_command"] = shlex.join(fallback_argv)
                    if manifest.get("fallback_policy") == "stop_without_nmap":
                        manifest.update({
                            "status": "completed_without_nmap",
                            "fallback_approval_required": False,
                            "fallback_decision": "policy_stop",
                            "fallback_decided_at": utc_now(),
                            "discovery_note": (
                                "FPING found no responsive hosts. The pinned scheduled-scan "
                                "policy finished without starting the full Nmap fallback."
                            ),
                        })
                        exit_code, run_phases = 0, False
                    else:
                        manifest["status"] = "awaiting_fallback_approval"
                        manifest["fallback_approval_required"] = True
                        manifest["discovery_note"] = (
                            "FPING found no responsive hosts. Full Nmap fallback is paused "
                            "pending explicit operator or mission-partner approval."
                        )
                        collect_artifacts(manifest, data_dir)
                        persist_scan_progress(
                            manifest, phase="awaiting_approval",
                            db_path=db_path, data_dir=data_dir,
                        )
                        while not control.fallback_decision_event.is_set():
                            if control.cancel_event.is_set():
                                manifest["status"], run_phases = "cancelled", False
                                break
                            sleep_fn(0.2)
                        if run_phases:
                            manifest.update({
                                "fallback_decision": control.fallback_decision,
                                "fallback_decided_by": control.fallback_decided_by,
                                "fallback_authorization_note": control.fallback_authorization_note,
                                "fallback_decided_at": utc_now(),
                            })
                            if control.fallback_decision == "approve":
                                apply_fping_fallback(manifest)
                                manifest["status"] = "running"
                                manifest["discovery_note"] = (
                                    "FPING found no responsive hosts. Full Nmap fallback "
                                    f"approved by {control.fallback_decided_by}: "
                                    f"{control.fallback_authorization_note}"
                                )
                                started = time.monotonic()
                                deadline = started + int(manifest["timeout_seconds"])
                                start_capture("the approved fallback")
                            else:
                                manifest["status"] = "completed_without_nmap"
                                manifest["discovery_note"] = (
                                    "FPING found no responsive hosts. "
                                    f"{control.fallback_decided_by} chose to finish without "
                                    f"Nmap fallback: {control.fallback_authorization_note}"
                                )
                                exit_code, run_phases = 0, False
            else:
                discovery_status, discovery_exit = watch_process(
                    manifest["discovery_execution_command_argv"],
                    run_dir / "discovery-stdout.txt",
                    run_dir / "discovery-stderr.txt",
                    phase="discovery", process_attr="nmap_process",
                    allowed_exit_codes={0}, track_nmap=True,
                )
                exit_code = discovery_exit
                if discovery_status != "completed":
                    manifest["status"] = discovery_status
                    run_phases = False
                else:
                    alive_hosts = nmap_up_addresses(run_dir / "discovery.xml")
                    (run_dir / "discovery-alive.txt").write_text(
                        "\n".join(alive_hosts) + ("\n" if alive_hosts else ""),
                        encoding="utf-8",
                    )
                    manifest["discovery_host_count"] = len(alive_hosts)
                    if not alive_hosts:
                        shutil.copyfile(run_dir / "discovery.xml", run_dir / "scan.xml")
                        manifest["status"] = "completed"
                        manifest["discovery_note"] = (
                            "Nmap discovery completed, but no responsive hosts were found; "
                            "TCP and UDP port phases were skipped."
                        )
                        run_phases = False

            if run_phases:
                hosts_total = len(alive_hosts) or int(
                    manifest["progress"].get("scope_hosts_total") or 0
                )
                for phase in manifest.get("execution_phases") or []:
                    phase_name = phase["name"]
                    phase["status"] = "running"
                    phase["started_at"] = utc_now()
                    persist_scan_progress(
                        manifest, phase=phase_name, hosts_completed=0,
                        hosts_total=hosts_total, hosts_up=0,
                        db_path=db_path, data_dir=data_dir,
                    )
                    phase_status, phase_exit = watch_process(
                        phase["execution_command_argv"],
                        run_dir / phase["stdout_filename"],
                        run_dir / phase["stderr_filename"],
                        phase=phase_name, process_attr="nmap_process",
                        allowed_exit_codes={0}, track_nmap=True,
                    )
                    xml_path = run_dir / phase["xml_filename"]
                    if phase_status == "completed" and not xml_path.is_file():
                        phase_status = "failed"
                    exit_code = phase_exit
                    phase["status"] = phase_status
                    phase["exit_code"] = phase_exit
                    phase["completed_at"] = utc_now()
                    if phase_status == "completed" and xml_path.is_file():
                        successful_xml.append(xml_path)
                        continue
                    tcp_succeeded = any(
                        item.get("name") == "tcp" and item.get("status") == "completed"
                        for item in manifest.get("execution_phases") or []
                    )
                    if phase_name == "udp" and tcp_succeeded:
                        manifest["partial_results"] = True
                        manifest["execution_note"] = (
                            f"TCP results were preserved. The UDP phase {phase_status}"
                            + (f" with exit code {phase_exit}." if phase_exit is not None else ".")
                        )
                        manifest["status"] = "completed"
                        break
                    manifest["status"] = phase_status
                    break
                else:
                    manifest["status"] = "completed"

                if successful_xml:
                    persist_scan_progress(
                        manifest, phase="merge", db_path=db_path, data_dir=data_dir
                    )
                    merge_nmap_xml(successful_xml, run_dir / "scan.xml")
                    persist_scan_progress(
                        manifest, phase="analysis", db_path=db_path, data_dir=data_dir
                    )
                    successful_protocols = [
                        item["protocol"]
                        for item in manifest.get("execution_phases") or []
                        if item.get("status") == "completed"
                    ]
                    manifest["coverage"]["actual_protocols"] = successful_protocols
                    manifest["coverage"]["partial_results"] = bool(
                        manifest.get("partial_results")
                    )
                    if manifest.get("partial_results"):
                        manifest["coverage"]["requested_protocols"] = manifest[
                            "coverage"
                        ].get("protocols", [])
                        manifest["coverage"]["protocols"] = successful_protocols

            output_sources = [
                run_dir / "discovery-stdout.txt",
                run_dir / "tcp-stdout.txt",
                run_dir / "udp-stdout.txt",
            ]
            error_sources = [
                run_dir / "discovery-stderr.txt",
                run_dir / "fping-stderr.txt",
                run_dir / "tcp-stderr.txt",
                run_dir / "udp-stderr.txt",
            ]
            (run_dir / "stdout.txt").write_bytes(
                b"\n".join(path.read_bytes() for path in output_sources if path.is_file())
            )
            (run_dir / "stderr.txt").write_bytes(
                b"\n".join(path.read_bytes() for path in error_sources if path.is_file())
            )
    except Exception as exc:
        manifest["status"] = "failed"
        manifest["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        terminate_process(control.discovery_process)
        terminate_process(control.nmap_process)
        terminate_process(control.capture_process)
        manifest["completed_at"] = utc_now()
        manifest["exit_code"] = exit_code
        manifest["success"] = manifest["status"] in {"completed", "completed_without_nmap"}
        manifest["host_count"] = nmap_host_count(run_dir / "scan.xml")
        progress = manifest["progress"]
        if manifest["status"] == "completed":
            update_scan_progress(
                progress,
                phase="completed",
                hosts_completed=int(progress.get("hosts_total") or 0),
                hosts_up=manifest["host_count"] or 0,
                batch_hosts_completed=(
                    int(progress.get("batch_hosts_completed_before") or 0)
                    + int(progress.get("scope_hosts_total") or 0)
                ),
                updated_at=utc_now(),
            )
        elif manifest["status"] == "completed_without_nmap":
            update_scan_progress(
                progress,
                phase="completed_without_nmap",
                batch_hosts_completed=(
                    int(progress.get("batch_hosts_completed_before") or 0)
                    + int(progress.get("scope_hosts_total") or 0)
                ),
                updated_at=utc_now(),
            )
        else:
            update_scan_progress(
                progress, phase=manifest["status"], updated_at=utc_now()
            )
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
    chunking_enabled = bool(
        schedule.get("chunking_enabled", "chunk_size" in schedule)
    )
    if not chunking_enabled:
        return [addresses] if addresses else []
    size = int(schedule.get("chunk_size") or 256)
    return [addresses[index:index + size] for index in range(0, len(addresses), size)]


def _scheduled_request(
    schedule: dict,
    targets: list[str],
    *,
    batch_id: str,
    chunk_number: int,
    chunk_count: int,
    batch_hosts_total: int,
    batch_hosts_completed_before: int,
    db_path: Path = DB_PATH,
) -> ScanRunRequest:
    no_strike, _ = effective_no_strike(schedule.get("no_strike") or [], db_path)
    return ScanRunRequest(
        operator=schedule["created_by"],
        created_by=schedule["created_by"],
        scheduled=True,
        scheduled_by=schedule["created_by"],
        executed_by="scheduler",
        # Chunk identity belongs in structured metadata so every occurrence keeps
        # one readable Name_(S)_Date_Time label on the comparison page.
        name=schedule["name"],
        reason=schedule["reason"],
        originating_host=schedule["originating_host"],
        interface=schedule["interface"],
        profile=schedule["profile_name"],
        profile_id=schedule["profile_id"],
        profile_version=schedule["profile_version"],
        targets=targets,
        no_strike=no_strike,
        capture=True,
        timeout_seconds=int(schedule.get("timeout_seconds") or 2700),
        fallback_policy=schedule.get("fallback_policy", "require_approval"),
        schedule_id=schedule["schedule_id"],
        schedule_batch_id=batch_id,
        chunk_number=chunk_number,
        chunk_count=chunk_count,
        chunk_delay_seconds=int(schedule.get("chunk_delay_seconds") or 0),
        batch_hosts_total=batch_hosts_total,
        batch_hosts_completed_before=batch_hosts_completed_before,
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
        resume_after = min(
            max(int(schedule.get("resume_after_chunk") or 0), 0), total
        )
        batch_hosts_total = sum(len(chunk) for chunk in chunks)
        occurrence_run_ids = (
            list(schedule.get("last_occurrence_run_ids") or [])
            if resume_after
            else []
        )
        schedule.update(
            {
                "batch_status": "running",
                "active_batch_id": batch_id,
                "active_chunk_number": resume_after,
                "active_chunk_count": total,
                "completed_chunk_count": resume_after,
                "last_occurrence_started_at": (
                    schedule.get("last_occurrence_started_at")
                    if resume_after
                    else utc_now()
                ),
                "last_occurrence_completed_at": None,
                "last_occurrence_status": "running",
                "last_occurrence_batch_id": batch_id,
                "last_occurrence_run_ids": occurrence_run_ids,
                "last_dispatch_note": (
                    f"Resuming after {resume_after} completed chunk(s)"
                    if resume_after
                    else f"Preparing {total} sequential chunk(s)"
                ),
            }
        )
        _store_scan_schedule(schedule, db_path)
        for index, targets in enumerate(
            chunks[resume_after:], start=resume_after + 1
        ):
            while True:
                try:
                    run = launch_scan_run(
                        _scheduled_request(
                            schedule,
                            targets,
                            batch_id=batch_id,
                            chunk_number=index,
                            chunk_count=total,
                            batch_hosts_total=batch_hosts_total,
                            batch_hosts_completed_before=sum(
                                len(chunk) for chunk in chunks[: index - 1]
                            ),
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
            occurrence_run_ids.append(run["run_id"])
            schedule["last_occurrence_run_ids"] = occurrence_run_ids
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
            if current["status"] in successful_states:
                schedule["completed_chunk_count"] = index
            _store_scan_schedule(schedule, db_path)
            if current["status"] not in successful_states:
                schedule["batch_status"] = f"stopped_{current['status']}"
                schedule["enabled"] = False
                schedule["active_batch_id"] = None
                schedule["last_occurrence_status"] = current["status"]
                schedule["last_occurrence_completed_at"] = utc_now()
                _store_scan_schedule(schedule, db_path)
                return
            if advance_schedule and not schedule.get("enabled"):
                schedule["batch_status"] = "paused_after_current_chunk"
                schedule["active_batch_id"] = None
                schedule["last_occurrence_status"] = "paused"
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
        schedule["completed_chunk_count"] = total
        schedule["resume_after_chunk"] = 0
        schedule["next_chunk_at"] = None
        schedule["occurrence_count"] = int(schedule.get("occurrence_count") or 0) + 1
        schedule["last_occurrence_status"] = "completed"
        schedule["last_occurrence_completed_at"] = utc_now()
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
            schedule["last_occurrence_status"] = "failed_to_dispatch"
            schedule["last_occurrence_completed_at"] = utc_now()
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
    recovering = schedule.get("batch_status") == "recovery_pending"
    resume_after = (
        min(max(int(schedule.get("resume_after_chunk") or 0), 0), len(chunks))
        if recovering
        else 0
    )
    with ACTIVE_SCHEDULE_BATCHES_LOCK:
        if ACTIVE_SCHEDULE_BATCHES:
            raise RuntimeError("Another scheduled batch is already active")
        ACTIVE_SCHEDULE_BATCHES.add(schedule_id)
    batch_id = uuid.uuid4().hex
    schedule["batch_status"] = "queued"
    schedule["active_batch_id"] = batch_id
    schedule["active_chunk_number"] = resume_after
    schedule["active_chunk_count"] = len(chunks)
    schedule["completed_chunk_count"] = resume_after
    schedule["resume_after_chunk"] = resume_after
    schedule["last_dispatch_note"] = (
        f"Recovery queued at chunk {resume_after + 1} of {len(chunks)}"
        if recovering and resume_after < len(chunks)
        else f"Queued {len(chunks)} sequential chunk(s)"
    )
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
        "chunking_enabled": bool(
            schedule.get("chunking_enabled", "chunk_size" in schedule)
        ),
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


def recover_scheduler_state(
    db_path: Path = DB_PATH,
    data_dir: Path = DATA_DIR,
) -> dict:
    """Close orphaned runs and resume interrupted batches after completed chunks."""
    init_poc_storage(db_path)
    recovered_at = utc_now()
    with sqlite3.connect(db_path) as db:
        rows = db.execute("SELECT manifest_json FROM scan_runs").fetchall()
    manifests = [json.loads(row[0]) for row in rows]
    orphaned = []
    for manifest in manifests:
        if manifest.get("status") not in {
            "queued",
            "running",
            "awaiting_fallback_approval",
        }:
            continue
        manifest["status"] = "interrupted"
        manifest["success"] = False
        manifest["completed_at"] = recovered_at
        manifest["error"] = "The analyzer restarted before this scan finished"
        if isinstance(manifest.get("progress"), dict):
            update_scan_progress(
                manifest["progress"], phase="interrupted", updated_at=recovered_at
            )
        collect_artifacts(manifest, data_dir)
        update_scan_run_manifest(manifest, db_path)
        orphaned.append(manifest["run_id"])

    recovered_schedules = []
    for schedule in list_scan_schedules(db_path):
        active_batch_id = schedule.get("active_batch_id")
        if not active_batch_id and schedule.get("batch_status") not in {
            "queued",
            "running",
        }:
            continue
        batch_manifests = [
            manifest
            for manifest in manifests
            if manifest.get("schedule_batch_id") == active_batch_id
        ]
        completed_numbers = {
            int(manifest.get("chunk_number") or 0)
            for manifest in batch_manifests
            if manifest.get("status") in {"completed", "completed_without_nmap"}
        }
        contiguous_completed = 0
        while contiguous_completed + 1 in completed_numbers:
            contiguous_completed += 1
        stored_completed = int(schedule.get("completed_chunk_count") or 0)
        if "completed_chunk_count" not in schedule:
            stored_completed = max(
                0, int(schedule.get("active_chunk_number") or 0) - 1
            )
        completed = max(stored_completed, contiguous_completed)
        total = int(schedule.get("active_chunk_count") or 0)
        if total:
            completed = min(completed, total)
        schedule["active_batch_id"] = None
        schedule["active_chunk_number"] = completed
        schedule["completed_chunk_count"] = completed
        schedule["resume_after_chunk"] = completed
        schedule["next_chunk_at"] = None
        schedule["last_occurrence_status"] = "interrupted"
        schedule["last_occurrence_completed_at"] = recovered_at
        schedule["last_occurrence_run_ids"] = [
            manifest["run_id"]
            for manifest in sorted(
                batch_manifests,
                key=lambda item: int(item.get("chunk_number") or 0),
            )
        ]
        schedule["recovery_count"] = int(schedule.get("recovery_count") or 0) + 1
        if schedule.get("enabled"):
            schedule["batch_status"] = "recovery_pending"
            schedule["next_run_at"] = recovered_at
            schedule["last_dispatch_note"] = (
                f"Restart recovery will resume after {completed} completed chunk(s)"
            )
            details = (
                f"Recovered an interrupted batch; {completed} completed chunk(s) "
                "will not be repeated"
            )
        else:
            schedule["batch_status"] = "interrupted_paused"
            schedule["last_dispatch_note"] = (
                f"Interrupted after {completed} completed chunk(s); enable to resume"
            )
            details = "Recorded an interrupted batch while the schedule was paused"
        _append_schedule_history(
            schedule,
            "restart_recovery",
            "system",
            details,
            changed_at=recovered_at,
        )
        _store_scan_schedule(schedule, db_path)
        recovered_schedules.append(schedule["schedule_id"])
    return {
        "orphaned_run_ids": orphaned,
        "recovered_schedule_ids": recovered_schedules,
    }


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


def compare_import_results(first_sha256: str, second_sha256: str,
                           db_path: Path = DB_PATH) -> dict:
    """Compare two retained Nmap analyses without reparsing their XML files."""
    first = get_import_history_item(first_sha256, db_path)
    second = get_import_history_item(second_sha256, db_path)
    if first is None or second is None:
        raise KeyError("One or both Nmap imports were not found")

    before_evidence = {
        "label": first.get("display_name") or first["filename"],
        "sources": [{"label": "Original Nmap XML", "url": f"/api/imports/{first['sha256']}/raw"}],
    }
    after_evidence = {
        "label": second.get("display_name") or second["filename"],
        "sources": [{"label": "Original Nmap XML", "url": f"/api/imports/{second['sha256']}/raw"}],
    }
    result = compare_analyses(
        first.get("analysis", {}), second.get("analysis", {}),
        before_evidence=before_evidence, after_evidence=after_evidence,
    )
    warnings = coverage_warnings(
        first.get("analysis", {}).get("coverage", {}),
        second.get("analysis", {}).get("coverage", {}),
    )
    return {
        "before": {"sha256": first["sha256"], "filename": first["filename"], "display_name": first.get("display_name"), "imported_at": first["imported_at"]},
        "after": {"sha256": second["sha256"], "filename": second["filename"], "display_name": second.get("display_name"), "imported_at": second["imported_at"]},
        "coverage_compatible": not warnings,
        "coverage_warnings": warnings,
        **result,
    }


@router.get("/scan-profiles")
def scan_profile_history(all_versions: bool = False) -> list[dict]:
    return list_scan_profiles(all_versions=all_versions)


@router.get("/saved-networks")
def saved_network_history(include_archived: bool = False) -> list[dict]:
    return list_saved_networks(DB_PATH, include_archived=include_archived)


@router.get("/saved-networks/{saved_network_id}")
def saved_network_detail(saved_network_id: str) -> dict:
    record = get_saved_network(saved_network_id, DB_PATH)
    if record is None:
        raise HTTPException(status_code=404, detail="Saved Network not found")
    return record


@router.post("/saved-networks", status_code=201)
def save_saved_network(request: SavedNetworkCreate) -> dict:
    try:
        return create_saved_network(request, DB_PATH)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.put("/saved-networks/{saved_network_id}")
def edit_saved_network(saved_network_id: str, request: SavedNetworkUpdate) -> dict:
    try:
        return update_saved_network(saved_network_id, request, DB_PATH)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Saved Network not found") from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post("/saved-networks/{saved_network_id}/archive")
def archive_saved_network_record(
    saved_network_id: str, request: SavedNetworkArchive
) -> dict:
    try:
        return archive_saved_network(saved_network_id, request, DB_PATH)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Saved Network not found") from exc


@router.get("/safety/no-strike")
def global_no_strike_list() -> dict:
    return get_global_no_strike()


@router.post("/safety/scan-summary")
def preview_scan_safety(request: ScanSafetySummaryRequest) -> dict:
    try:
        return scan_safety_summary(request.targets, request.no_strike)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


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
        return set_scan_schedule_enabled(
            schedule_id, request.enabled, changed_by=request.changed_by
        )
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


@router.get("/scan-runs-grouped")
def grouped_scan_run_history(
    limit: int = Query(default=200, ge=1, le=200),
) -> list[dict]:
    return group_scan_runs_by_saved_network(list_scan_run_plans(limit=limit))


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
    from app.identity import enrich_analysis_macs
    from app.network_map import build_topology
    item["analysis"] = enrich_analysis_macs(
        item.get("analysis") or {},
        build_topology(),
        direct_source_label=item.get("filename") or "Imported Nmap XML",
        direct_source_url=f"/api/imports/{sha256}/raw",
    )
    from app.identity_overrides import apply_analysis_os_overrides
    item["analysis"] = apply_analysis_os_overrides(item["analysis"], DB_PATH)
    return item
