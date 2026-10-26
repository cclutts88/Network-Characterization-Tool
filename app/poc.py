from __future__ import annotations

import calendar
import hashlib
import ipaddress
import hmac
import json
import logging
import os
import re
import shlex
import signal
import secrets
import socket
import sqlite3
import subprocess
import shutil
import tempfile
import threading
import time
import uuid
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Literal

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.comparison import compare_analyses, coverage_warnings
from app.build_info import APP_VERSION, BUILD_COMMIT, BUILD_ID
from app.database import configure_database, connect_database
from app.evidence_maintenance import (
    EvidenceMaintenanceBlocked,
    evidence_mutations_blocked,
    guarded_evidence_mutation,
)
from app.artifacts import init_artifact_storage, register_finalized_files
from app.scan_profiles import (
    BUILTIN_PROFILE_VERSION,
    BUILTIN_PROFILES,
    build_nmap_flags,
    build_phase_nmap_flags,
    normalize_scan_options,
    requires_split_protocol_phases,
    scan_coverage,
    scan_display_name,
)
from app.scan_progress import latest_nmap_status, new_scan_progress, update_scan_progress
from app.live_scan_discoveries import UnsafeLiveScanPath, live_scan_discoveries
from app.nmap_presence import nmap_presence_counts
from app.saved_networks import (
    SavedNetworkArchive,
    SavedNetworkCreate,
    SavedNetworkUpdate,
    archive_saved_network,
    create_saved_network,
    get_saved_network,
    get_saved_network_on_connection,
    get_saved_network_with_warnings,
    init_saved_network_storage,
    insert_saved_network_record,
    list_saved_networks,
    resolve_saved_network_targets,
    saved_network_integrity_message,
    update_saved_network,
    update_saved_network_record,
)
from app.network_scopes import list_network_scopes
from app.collection_safety_setup import (
    bind_collection_scope_context_on_connection,
    CollectionSafetySetupIncomplete,
    require_collection_safety_ready,
    require_collection_safety_ready_on_connection,
)
from app.mission_environment import (
    MissionEnvironmentConflict,
    ReviewedMissionScope,
    init_mission_environment_storage,
    resolve_collection_mission_review,
)
from app.saved_network_scope_associations import (
    SavedNetworkScopeConflict,
    attach_scope_associations,
    change_saved_network_scope_association,
    current_saved_network_scope_association,
    current_scope_association_in_transaction,
    get_schedule_scope_context,
    init_scan_scope_context_storage,
    init_saved_network_scope_storage,
    insert_run_scope_context,
    insert_saved_network_scope_association,
    insert_schedule_scope_context,
    list_saved_network_scope_history,
    resolve_reviewed_scope_context,
    resolve_schedule_scope_context_in_transaction,
)
from app.request_identity import bind_signed_in_actor
from app.active_collection import active_collection_enabled, require_active_collection
from app.pipeline_intake import (
    AUTOMATED_NMAP_SOURCE,
    NMAP_INGESTION_POLICY_VERSION,
    init_pipeline_intake_storage,
    mark_pipeline_source,
    record_automated_nmap_intent,
)
from app.automated_nmap_foundation import get_automated_scan_foundation_status
from app.derived_jobs import scan_run_job_statuses, start_derived_job_worker
from app.scan_history_index import (
    init_scan_history_index_storage,
    ScanHistoryCatalogChanged,
    scan_history_catalog_page,
    scan_history_group_page_from_index,
    sync_scan_history_manifest,
)
from app.scan_collaboration import (
    append_scan_audit,
    append_scan_audit_on_connection,
    init_scan_collaboration_storage,
    scan_audit_history,
)
from app.scheduled_work import (
    abandon_chunk_after_worker_error,
    WorkLeaseConflict,
    bind_chunk_scan_run_on_connection,
    claim_next_chunk,
    close_reviewed_occurrence,
    content_digest,
    definition_identity,
    get_occurrence,
    init_scheduled_work_storage,
    list_schedule_occurrences,
    migrate_legacy_schedules,
    prepare_occurrence,
    publish_chunk_terminal,
    publish_chunk_terminal_on_connection,
    recover_schedule_occurrences,
    register_schedule_definition_on_connection,
    mark_chunk_contact_starting_on_connection,
)
from app.work_coordination import (
    WorkLease,
    WorkLeaseLost,
    WorkRecoveryRequired,
    acquire_work_lease_on_connection,
    assert_work_lease_on_connection,
    init_work_coordination_storage,
    release_work_lease_on_connection,
    renew_work_lease,
)
from app.scan_work_recovery import scan_contact_paused

DATA_DIR = Path(os.environ.get("ANALYZER_DATA_DIR", "/data"))
DB_PATH = DATA_DIR / "analyzer.db"
RUNS_DIR_NAME = "scan-runs"
MAX_EXPANDED_ADDRESSES = 65536
MAX_ACTIVE_RUNS = 1
SCAN_CAPACITY_LEASE_KEY = "scan-capacity:primary"
SCAN_PROGRESS_PUBLISH_INTERVAL_SECONDS = 5.0


def is_transient_sqlite_contention(exc: sqlite3.OperationalError) -> bool:
    """Return true only for SQLite busy/locked failures that are safe to retry."""
    code = getattr(exc, "sqlite_errorcode", None)
    if isinstance(code, int) and (code & 0xFF) in {
        sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED,
    }:
        return True
    message = str(exc).strip().lower()
    return "database is locked" in message or "database table is locked" in message


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

_POC_STORAGE_READY: dict[str, tuple[int, int]] = {}
_POC_STORAGE_LOCK = threading.RLock()


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
    discovery_mode: Literal["nmap", "fping"] = "fping"
    traceroute: bool = False

    def normalized(self) -> dict:
        return normalize_scan_options(self.model_dump())


class ScanProfileCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=100)
    description: str = Field(default="", max_length=500)
    created_by: str = Field(min_length=1, max_length=100)
    settings: ScanOptions
    request_token: str = Field(min_length=16, max_length=128)

    @field_validator("name", "description", "created_by")
    @classmethod
    def clean_profile_text(cls, value: str) -> str:
        return value.strip()


class ScanProfileVersionCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    description: str = Field(default="", max_length=500)
    created_by: str = Field(min_length=1, max_length=100)
    settings: ScanOptions
    expected_version: int = Field(ge=1)
    request_token: str = Field(min_length=16, max_length=128)


class ScanProfileClone(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=100)
    description: str = Field(default="", max_length=500)
    created_by: str = Field(min_length=1, max_length=100)
    source_version: int | None = Field(default=None, ge=1)
    request_token: str = Field(min_length=16, max_length=128)


class ReviewedScopeAssociation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    association_id: str = Field(min_length=1, max_length=100)
    revision: int = Field(ge=1)


class SavedNetworkScopeChange(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scope_id: str | None = Field(default=None, max_length=100)
    expected_association_id: str | None = Field(default=None, max_length=100)
    expected_revision: int | None = Field(default=None, ge=1)
    reason: str = Field(min_length=1, max_length=500)

    @field_validator("scope_id", "expected_association_id")
    @classmethod
    def clean_optional_identifier(cls, value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = value.strip()
        return cleaned or None

    @field_validator("reason")
    @classmethod
    def clean_scope_reason(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("A reason for the Network Scope change is required")
        return cleaned


class SavedNetworkContextSave(BaseModel):
    """One all-or-nothing Saved Network and future-scan context change."""

    model_config = ConfigDict(extra="forbid")

    saved_network_id: str | None = Field(default=None, max_length=100)
    name: str = Field(min_length=1, max_length=100)
    cidr: str = Field(min_length=1, max_length=64)
    description: str = Field(default="", max_length=500)
    category: str = Field(default="", max_length=100)
    tags: list[str] = Field(default_factory=list, max_length=30)
    expected_updated_at: str | None = Field(default=None, max_length=64)
    scope_id: str | None = Field(default=None, max_length=100)
    expected_association_id: str | None = Field(default=None, max_length=100)
    expected_revision: int | None = Field(default=None, ge=1)
    scope_reason: str = Field(default="", max_length=500)

    @field_validator(
        "saved_network_id", "expected_updated_at", "scope_id", "expected_association_id"
    )
    @classmethod
    def clean_context_identifier(cls, value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = value.strip()
        return cleaned or None

    @field_validator("name", "cidr")
    @classmethod
    def clean_context_required_text(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("Value cannot be blank")
        return cleaned

    @field_validator("description", "category", "scope_reason")
    @classmethod
    def clean_context_text(cls, value: str) -> str:
        return value.strip()

    @field_validator("tags")
    @classmethod
    def clean_context_tags(cls, value: list[str]) -> list[str]:
        cleaned: list[str] = []
        seen: set[str] = set()
        for item in value:
            tag = item.strip()
            key = tag.casefold()
            if tag and key not in seen:
                cleaned.append(tag)
                seen.add(key)
        return cleaned


class ScanScheduleCreate(BaseModel):
    """A version-pinned recurring or one-time scan schedule."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=100)
    created_by: str = Field(min_length=1, max_length=100)
    profile_id: str = Field(min_length=1, max_length=128)
    profile_version: int = Field(ge=1)
    targets: list[str] = Field(min_length=1)
    manual_targets: list[str] = Field(default_factory=list)
    saved_network_ids: list[str] = Field(default_factory=list)
    reviewed_scope_associations: list[ReviewedScopeAssociation] = Field(default_factory=list)
    reviewed_mission_scopes: list[ReviewedMissionScope] = Field(default_factory=list)
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


class ScheduleRunNow(BaseModel):
    model_config = ConfigDict(extra="forbid")

    request_id: str = Field(min_length=16, max_length=100)
    requested_by: str | None = Field(default=None, max_length=100)

    @field_validator("request_id", "requested_by")
    @classmethod
    def clean_run_now_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = value.strip()
        if not cleaned or "\x00" in cleaned:
            raise ValueError("This field cannot be blank")
        return cleaned


class ScheduleRecoveryReview(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reviewed_by: str | None = Field(default=None, max_length=100)
    reason: str = Field(min_length=8, max_length=500)
    confirmed_former_contact_stopped: bool

    @field_validator("reviewed_by", "reason")
    @classmethod
    def clean_recovery_review(cls, value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = value.strip()
        if not cleaned or "\x00" in cleaned:
            raise ValueError("This field cannot be blank")
        return cleaned


class ScanRunPlan(BaseModel):
    model_config = ConfigDict(extra="forbid")

    operator: str = Field(min_length=1, max_length=100)
    name: str = Field(default="Scan", min_length=1, max_length=100)
    reason: str = Field(
        default="NCT network characterization initiated through the operator workspace",
        max_length=500,
    )
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
    reviewed_scope_associations: list[ReviewedScopeAssociation] = Field(default_factory=list)
    reviewed_mission_scopes: list[ReviewedMissionScope] = Field(default_factory=list)
    no_strike: list[str] = Field(default_factory=list)

    @field_validator("operator", "name", "originating_host", "interface", "profile")
    @classmethod
    def clean_required_text(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("This field cannot be blank")
        return value

    @field_validator("reason")
    @classmethod
    def clean_optional_reason(cls, value: str) -> str:
        cleaned = value.strip()
        return cleaned or "NCT network characterization initiated through the operator workspace"

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


class ScanRunOwnerChange(BaseModel):
    model_config = ConfigDict(extra="forbid")

    owner: str = Field(min_length=1, max_length=100)
    expected_owner: str = Field(min_length=1, max_length=100)
    expected_assignment_revision: int = Field(ge=0)

    @field_validator("owner", "expected_owner")
    @classmethod
    def clean_owner(cls, value: str) -> str:
        cleaned = value.strip().lower()
        if not cleaned:
            raise ValueError("A queue owner is required")
        return cleaned


class ScanRunNetworkAttribution(BaseModel):
    """Attach retained scan evidence to active Saved Network snapshots."""

    model_config = ConfigDict(extra="forbid")

    saved_network_ids: list[str] = Field(default_factory=list, max_length=100)
    changed_by: str = Field(min_length=1, max_length=100)
    expected_metadata_revision: int = Field(ge=0)

    @field_validator("changed_by")
    @classmethod
    def clean_attribution_actor(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("The analyst changing scan attribution is required")
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
ACTIVE_RUN_THREADS: dict[str, threading.Thread] = {}
ACTIVE_RUNS_LOCK = threading.Lock()
ACTIVE_SCHEDULE_BATCHES: set[str] = set()
ACTIVE_SCHEDULE_THREADS: dict[str, threading.Thread] = {}
ACTIVE_SCHEDULE_BATCHES_LOCK = threading.Lock()
_SCAN_WORKER_SHUTDOWN = threading.Event()
_SCHEDULE_WORKER_SHUTDOWN = threading.Event()
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
    # Targets are expanded by the scanner, so bound them here.  No-Strike
    # entries remain symbolic CIDRs and may intentionally cover very large
    # ranges such as 0.0.0.0/0.
    if label == "target" and sum(network.num_addresses for network in collapsed) > MAX_EXPANDED_ADDRESSES:
        raise ValueError(
            f"{label.title()} scope exceeds the {MAX_EXPANDED_ADDRESSES}-address safety limit"
        )
    return [str(network) for network in collapsed]


def get_global_no_strike(db_path: Path = DB_PATH) -> dict:
    """Return the excluded no-strike list that applies to every scan path."""
    init_poc_storage(db_path)
    with connect_database(db_path) as db:
        row = db.execute(
            """
            SELECT revision, entries_json, changed_at, changed_by
            FROM global_no_strike_history
            ORDER BY revision DESC
            LIMIT 1
            """
        ).fetchone()
    if not row:
        return {
            "entries": [], "updated_at": None, "updated_by": None,
            "revision": 0,
        }
    return {
        "entries": json.loads(row[1]),
        "updated_at": row[2],
        "updated_by": row[3],
        "revision": int(row[0]),
    }


def _global_no_strike_state_in_transaction(db) -> dict:
    row = db.execute(
        """
        SELECT revision, entries_json, changed_at, changed_by
        FROM global_no_strike_history
        ORDER BY revision DESC
        LIMIT 1
        """
    ).fetchone()
    return {
        "entries": json.loads(row[1]) if row else [],
        "updated_at": row[2] if row else None,
        "updated_by": row[3] if row else None,
        "revision": int(row[0]) if row else 0,
    }


def _store_global_no_strike_in_transaction(
    db, entries: list[str], changed_by: str, *, action: str
) -> dict:
    normalized = normalize_ipv4_networks(entries, "no-strike") if entries else []
    updated_at = utc_now()
    revision = int(db.execute(
        "SELECT COALESCE(MAX(revision), 0) + 1 FROM global_no_strike_history"
    ).fetchone()[0])
    db.execute(
        """
        INSERT INTO global_no_strike_history (
            revision, entries_json, action, changed_at, changed_by
        ) VALUES (?, ?, ?, ?, ?)
        """,
        (revision, json.dumps(normalized), action, updated_at, changed_by),
    )
    # Keep the former settings row as an atomic compatibility mirror so an
    # immediate application rollback retains the same safety boundary. The
    # append-only history above remains authoritative for this version.
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
        "revision": revision,
    }


def add_global_no_strike(
    request: NoStrikeUpdate, db_path: Path = DB_PATH
) -> dict:
    requested = normalize_ipv4_networks(request.entries, "no-strike")
    init_poc_storage(db_path)
    with connect_database(db_path) as db:
        db.execute("BEGIN IMMEDIATE")
        current = _global_no_strike_state_in_transaction(db)["entries"]
        result = _store_global_no_strike_in_transaction(
            db, [*current, *requested], request.changed_by, action="add"
        )
        cancellation_records = _persist_active_run_cancellations_in_transaction(
            db,
            requested,
            revision=result["revision"],
            changed_by=request.changed_by,
        )
        _persist_active_device_cancellations_in_transaction(
            db,
            requested,
            revision=result["revision"],
            changed_by=request.changed_by,
        )
    # Signal workers only after the exclusion and every durable cancellation request
    # have committed together. A failed write rolls the whole safety change back.
    for run_id, _intersecting, _cause in cancellation_records:
        with ACTIVE_RUNS_LOCK:
            control = ACTIVE_RUNS.get(run_id)
        if control is not None:
            control.cancel_event.set()
    return result


def _persist_active_device_cancellations_in_transaction(
    db, entries: list[str], *, revision: int, changed_by: str
) -> list[str]:
    """Fence active SSH work when a new exclusion covers its bound IPv4 target."""
    if not db.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='device_contact_runs'"
    ).fetchone():
        return []
    exclusions = [ipaddress.ip_network(item, strict=False) for item in entries]
    cancelled: list[str] = []
    rows = db.execute(
        """SELECT run_id, request_json, state FROM device_contact_runs
             WHERE state IN ('waiting', 'preparing', 'contact_starting', 'contact_active')
               AND cancellation_requested = 0"""
    ).fetchall()
    for run_id, request_json, state in rows:
        try:
            address = ipaddress.ip_address(
                str(json.loads(request_json).get("device_address") or "")
            )
        except (ValueError, TypeError, json.JSONDecodeError):
            continue
        if address.version != 4 or not any(address in item for item in exclusions):
            continue
        requested_at = utc_now()
        reason = (
            f"Global No-Strike revision {revision} now excludes device target {address}"
        )
        db.execute(
            """INSERT INTO device_contact_controls(
                   control_id, run_id, control_kind, requested_at,
                   requested_by, reason
               ) VALUES (?, ?, 'cancel_requested', ?, ?, ?)""",
            (uuid.uuid4().hex, run_id, requested_at, changed_by[:100], reason),
        )
        if state == "waiting":
            db.execute(
                """UPDATE device_contact_runs
                      SET state='cancelled', cancellation_requested=1,
                          completed_at=?, updated_at=?, status_reason=?
                    WHERE run_id=? AND cancellation_requested=0""",
                (requested_at, requested_at, reason, run_id),
            )
        else:
            db.execute(
                """UPDATE device_contact_runs
                      SET cancellation_requested=1, updated_at=?, status_reason=?
                    WHERE run_id=? AND cancellation_requested=0""",
                (requested_at, reason, run_id),
            )
        cancelled.append(str(run_id))
    return cancelled


def _persist_active_run_cancellations_in_transaction(
    db, entries: list[str], *, revision: int, changed_by: str
) -> list[tuple[str, list[str], dict]]:
    """Atomically bind a new safety boundary to every affected active run."""
    exclusions = [ipaddress.ip_network(item, strict=False) for item in entries]
    cancellation_records = []
    rows = db.execute(
        """SELECT manifest_json FROM scan_runs
             WHERE json_extract(manifest_json, '$.status')
                   IN ('dispatching', 'running', 'awaiting_fallback_approval')
             ORDER BY created_at ASC, rowid ASC"""
    ).fetchall()
    for row in rows:
        manifest = json.loads(row[0])
        if manifest.get("status") not in {"dispatching", "running", "awaiting_fallback_approval"}:
            continue
        run_id = manifest["run_id"]
        targets = [
            ipaddress.ip_network(item, strict=False)
            for item in manifest.get("targets") or []
        ]
        intersecting = sorted({
            str(exclusion)
            for target in targets
            for exclusion in exclusions
            if target.overlaps(exclusion)
        })
        if not intersecting:
            continue
        requested_at = utc_now()
        cause = {
            "global_no_strike_revision": revision,
            "intersecting_exclusions": intersecting,
            "requested_at": requested_at,
            "requested_by": changed_by,
        }
        _request_scan_cancellation_in_transaction(
            db,
            run_id,
            requested_by=changed_by,
            cause="global_no_strike",
            detail=json.dumps(cause, sort_keys=True),
            requested_at=cause["requested_at"],
        )
        db.execute(
            """INSERT INTO scan_run_audit (
                   run_id, event, actor, changed_at, details
               ) VALUES (?, 'safety_cancellation_requested', ?, ?, ?)""",
            (
                run_id,
                changed_by,
                cause["requested_at"],
                f"Global No-Strike revision {revision} intersects this run: "
                + ", ".join(intersecting),
            ),
        )
        cancellation_records.append((run_id, intersecting, cause))
    return cancellation_records


def _request_scan_cancellation_in_transaction(
    db,
    run_id: str,
    *,
    requested_by: str,
    cause: str,
    detail: str = "",
    requested_at: str | None = None,
) -> bool:
    if not RUN_ID_RE.fullmatch(run_id):
        raise ValueError("Invalid scan run identifier")
    at = requested_at or utc_now()
    existing = db.execute(
        "SELECT cancellation_requested_at FROM scan_run_control WHERE run_id = ?",
        (run_id,),
    ).fetchone()
    if existing and existing[0]:
        return True
    db.execute(
        """INSERT INTO scan_run_control(
               run_id, cancellation_requested_at, cancellation_requested_by,
               cancellation_cause, cancellation_detail
           ) VALUES (?, ?, ?, ?, ?)
           ON CONFLICT(run_id) DO UPDATE SET
               cancellation_requested_at = excluded.cancellation_requested_at,
               cancellation_requested_by = excluded.cancellation_requested_by,
               cancellation_cause = excluded.cancellation_cause,
               cancellation_detail = excluded.cancellation_detail,
               cancellation_acknowledged_at = NULL""",
        (run_id, at, requested_by[:100], cause[:100], detail[:2000]),
    )
    return True


def request_scan_cancellation(
    run_id: str,
    *,
    requested_by: str,
    cause: str,
    detail: str = "",
    requested_at: str | None = None,
    db_path: Path = DB_PATH,
) -> bool:
    """Persist one idempotent cancellation request outside mutable scan progress."""
    init_poc_storage(db_path)
    if not RUN_ID_RE.fullmatch(run_id):
        raise ValueError("Invalid scan run identifier")
    at = requested_at or utc_now()
    with connect_database(db_path) as db:
        db.execute("BEGIN IMMEDIATE")
        return _request_scan_cancellation_in_transaction(
            db,
            run_id,
            requested_by=requested_by,
            cause=cause,
            detail=detail,
            requested_at=at,
        )


def scan_cancellation_requested(run_id: str, db_path: Path = DB_PATH) -> bool:
    """Read the durable cancellation signal used by workers in every process."""
    init_poc_storage(db_path)
    with connect_database(db_path, read_only=True) as db:
        row = db.execute(
            """SELECT cancellation_requested_at
                 FROM scan_run_control WHERE run_id = ?
                   AND cancellation_acknowledged_at IS NULL""",
            (run_id,),
        ).fetchone()
    return bool(row and row[0])


def effective_no_strike(
    additional: list[str] | None = None, db_path: Path = DB_PATH
) -> tuple[list[str], list[str]]:
    """Merge persistent exclusions with optional run-specific exclusions."""
    global_state = get_global_no_strike(db_path)
    global_entries = global_state["entries"]
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
    global_state = get_global_no_strike(db_path)
    global_entries = global_state["entries"]

    target_addresses = {
        str(address)
        for network in (
            ipaddress.ip_network(entry, strict=False) for entry in normalized_targets
        )
        for address in network
    }
    global_networks = [
        ipaddress.ip_network(entry, strict=False) for entry in global_entries
    ]
    additional_networks = [
        ipaddress.ip_network(entry, strict=False) for entry in normalized_additional
    ]
    global_addresses = {
        address for address in target_addresses
        if any(ipaddress.ip_address(address) in network for network in global_networks)
    }
    additional_addresses = {
        address for address in target_addresses
        if any(ipaddress.ip_address(address) in network for network in additional_networks)
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
        "global_no_strike_revision": global_state["revision"],
        "global_no_strike_as_of": global_state["updated_at"],
    }


def _plan_manual_targets(plan: ScanRunPlan | ScanRunRequest) -> list[str]:
    if plan.manual_targets or plan.saved_network_ids:
        return list(plan.manual_targets)
    return list(plan.targets)


def require_scan_plan_collection_setup(
    plan: ScanRunPlan | ScanRunRequest, db_path: Path = DB_PATH
) -> dict:
    """Require one exact reviewed setup for a scan that may contact targets."""
    init_poc_storage(db_path)
    with connect_database(db_path) as db:
        db.execute("BEGIN IMMEDIATE")
        context = resolve_reviewed_scope_context(
            db,
            saved_network_ids=list(plan.saved_network_ids),
            manual_targets=_plan_manual_targets(plan),
            reviewed_associations=[
                item.model_dump() for item in plan.reviewed_scope_associations
            ],
        )
        status, _context = bind_collection_scope_context_on_connection(
            db, context=context, saved_network_ids=list(plan.saved_network_ids),
        )
        return status


def remove_global_no_strike(
    request: NoStrikeRemoval, db_path: Path = DB_PATH
) -> dict:
    requested = normalize_ipv4_networks(request.entries, "no-strike")
    identifier = ",".join(requested)
    if not consume_delete_challenge(
        "global-no-strike", identifier, request.confirmation
    ):
        raise PermissionError("The confirmation string is invalid or expired")
    init_poc_storage(db_path)
    with connect_database(db_path) as db:
        db.execute("BEGIN IMMEDIATE")
        current = _global_no_strike_state_in_transaction(db)["entries"]
        missing = [entry for entry in requested if entry not in current]
        if missing:
            raise KeyError("No-strike entry not found: " + ", ".join(missing))
        remaining = [entry for entry in current if entry not in set(requested)]
        result = _store_global_no_strike_in_transaction(
            db, remaining, request.changed_by, action="remove"
        )
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


def compact_discovery_targets(targets: list[str], no_strike: list[str]) -> list[str]:
    """Keep scheduled scope as compact CIDRs while removing excluded ranges."""
    remaining = list(
        ipaddress.collapse_addresses(
            ipaddress.ip_network(item, strict=False) for item in targets
        )
    )
    exclusions = list(
        ipaddress.collapse_addresses(
            ipaddress.ip_network(item, strict=False) for item in no_strike
        )
    )
    for exclusion in exclusions:
        updated: list[ipaddress.IPv4Network] = []
        for target in remaining:
            if not target.overlaps(exclusion):
                updated.append(target)
            elif target.subnet_of(exclusion):
                continue
            elif exclusion.subnet_of(target):
                updated.extend(target.address_exclude(exclusion))
        remaining = list(ipaddress.collapse_addresses(updated))
    return [str(network) for network in remaining]


def target_address_count(targets: list[str]) -> int:
    """Count addresses represented by IP or CIDR target entries."""
    return sum(
        ipaddress.ip_network(item, strict=False).num_addresses for item in targets
    )


def apply_fping_fallback(manifest: dict) -> None:
    """Retarget Nmap when ICMP-only discovery cannot see approved hosts."""
    phases = build_execution_phases(
        manifest["interface"],
        manifest["profile_settings"],
        include_no_strike=True,
        target_file="targets.txt",
        pre_discovered=False,
    )
    manifest["fallback_execution_phases"] = phases
    if requires_split_protocol_phases(manifest["profile_settings"]):
        manifest["command_argv"] = list(phases[0]["command_argv"])
        manifest["command_note"] = (
            "Compatibility field shows the TCP phase; execution_phases contains "
            "the complete TCP and UDP workflow."
        )
    else:
        manifest["command_argv"] = build_nmap_argv(
            manifest["profile"],
            manifest["interface"],
            include_no_strike=True,
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
    manifest["execution_phases"] = phases
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
    reserved_run_id: str | None = None,
    work_claim: dict | None = None,
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
    additional_no_strike = (
        normalize_ipv4_networks(plan.no_strike, "no-strike") if plan.no_strike else []
    )
    global_state = get_global_no_strike(db_path)
    global_no_strike = global_state["entries"]
    no_strike = normalize_ipv4_networks(
        [*global_no_strike, *additional_no_strike], "no-strike"
    ) if global_no_strike or additional_no_strike else []
    profile_record = resolve_scan_profile(plan, db_path)
    settings = profile_record["settings"]
    use_fping = settings.get("discovery_mode") == "fping"
    execution_phases = build_execution_phases(
        plan.interface,
        settings,
        include_no_strike=True,
        target_file="fping-alive.txt" if use_fping else "discovery-alive.txt",
        pre_discovered=True,
    )
    command_note = None
    if requires_split_protocol_phases(settings):
        nmap_argv = list(execution_phases[0]["command_argv"])
        command_note = (
            "Compatibility field shows the TCP phase; execution_phases contains "
            "the complete TCP and UDP workflow."
        )
    else:
        nmap_argv = build_nmap_argv(
            profile_record["name"],
            plan.interface,
            include_no_strike=True,
            scan_options=settings,
            target_file="fping-alive.txt" if use_fping else "targets.txt",
        )
    execution_argv = build_nmap_execution_argv(nmap_argv)
    discovery_argv = (
        build_fping_argv(plan.interface)
        if use_fping
        else build_nmap_discovery_argv(
            plan.interface, include_no_strike=True
        )
    )
    discovery_execution_argv = (
        discovery_argv
        if use_fping
        else build_nmap_execution_argv(discovery_argv)
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
        "additional_no_strike": additional_no_strike,
        "global_no_strike_revision": global_state["revision"],
        "global_no_strike_as_of": global_state["updated_at"],
        "interface": plan.interface,
        "profile_id": profile_record["profile_id"],
        "profile_name": profile_record["name"],
        "profile_version": profile_record["version"],
    }
    scope_hosts_total = len(expanded_discovery_targets(targets, no_strike))
    if scope_hosts_total == 0:
        raise ValueError(
            "No addresses remain after global and scan-specific No-Strike exclusions"
        )
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
        "run_id": reserved_run_id or uuid.uuid4().hex,
        "name": plan.name,
        "display_name": display_name,
        "created_at": created_at,
        "status": status,
        "operator": plan.operator,
        "created_by": creator,
        "owner": creator,
        "requested_by": creator,
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
        "reviewed_scope_associations": [
            item.model_dump() for item in plan.reviewed_scope_associations
        ],
        "reviewed_mission_scopes": [
            item.model_dump() for item in plan.reviewed_mission_scopes
        ],
        "saved_networks": saved_network_snapshots,
        "target_selection": {
            "saved_networks": saved_network_snapshots,
            "manual_targets": manual_targets,
        },
        "queue_assignment_revision": 0,
        "metadata_revision": 0,
        "no_strike": no_strike,
        "no_strike_submission": {
            "global": global_no_strike,
            "additional": additional_no_strike,
            "effective": no_strike,
            "revision": global_state["revision"],
            "certified_at": created_at,
        },
        "no_strike_certifications": [],
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
        "command_note": command_note,
        "execution_phases": execution_phases,
        "workflow": ["discovery", *[item["name"] for item in execution_phases], "merge", "analysis"],
        "capture_command_argv": capture_argv,
        "exact_capture_command": shlex.join(capture_argv) if capture_argv else None,
        "artifacts": [],
        "progress": progress,
        "work_claim": work_claim,
    }


def init_poc_storage(db_path: Path = DB_PATH) -> None:
    storage_key = str(db_path.resolve())
    try:
        info = db_path.stat()
        storage_identity = (info.st_dev, info.st_ino)
    except FileNotFoundError:
        storage_identity = None
    if storage_identity is not None and _POC_STORAGE_READY.get(storage_key) == storage_identity:
        return
    with _POC_STORAGE_LOCK:
        try:
            info = db_path.stat()
            storage_identity = (info.st_dev, info.st_ino)
        except FileNotFoundError:
            storage_identity = None
        if storage_identity is not None and _POC_STORAGE_READY.get(storage_key) == storage_identity:
            return
        configure_database(db_path)
        init_artifact_storage(db_path)
        init_saved_network_storage(db_path)
        init_mission_environment_storage(db_path)
        init_scan_collaboration_storage(db_path)
        with connect_database(db_path) as db:
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
            db.execute(
                """
                CREATE TABLE IF NOT EXISTS scan_run_control (
                    run_id TEXT PRIMARY KEY,
                    cancellation_requested_at TEXT,
                    cancellation_requested_by TEXT,
                    cancellation_cause TEXT,
                    cancellation_detail TEXT,
                    cancellation_acknowledged_at TEXT,
                    CHECK (
                        cancellation_requested_at IS NULL
                        OR (
                            cancellation_requested_by IS NOT NULL
                            AND cancellation_cause IS NOT NULL
                        )
                    )
                )
                """
            )
            db.execute(
                """
                CREATE TABLE IF NOT EXISTS global_no_strike_history (
                    revision INTEGER PRIMARY KEY,
                    entries_json TEXT NOT NULL,
                    action TEXT NOT NULL,
                    changed_at TEXT NOT NULL,
                    changed_by TEXT NOT NULL
                )
                """
            )
            db.execute(
                """
                CREATE TRIGGER IF NOT EXISTS global_no_strike_history_no_update
                BEFORE UPDATE ON global_no_strike_history
                BEGIN
                    SELECT RAISE(ABORT, 'Global No-Strike history is append-only');
                END
                """
            )
            db.execute(
                """
                CREATE TRIGGER IF NOT EXISTS global_no_strike_history_no_delete
                BEFORE DELETE ON global_no_strike_history
                BEGIN
                    SELECT RAISE(ABORT, 'Global No-Strike history is append-only');
                END
                """
            )
            db.execute("DROP TRIGGER IF EXISTS global_no_strike_history_valid_insert")
            db.execute(
                """
                CREATE TRIGGER IF NOT EXISTS global_no_strike_history_valid_insert
                BEFORE INSERT ON global_no_strike_history
                WHEN NEW.revision != COALESCE(
                        (SELECT MAX(revision) + 1 FROM global_no_strike_history), 1
                    )
                    OR NEW.entries_json IS NOT nct_normalize_ipv4_network_list(NEW.entries_json)
                    OR NEW.action NOT IN ('add', 'remove', 'legacy_snapshot')
                    OR nct_is_canonical_utc(NEW.changed_at) != 1
                    OR NEW.changed_by != trim(NEW.changed_by)
                    OR trim(NEW.changed_by) = ''
                    OR length(NEW.changed_by) > 100
                BEGIN
                    SELECT RAISE(ABORT, 'Invalid Global No-Strike history revision');
                END
                """
            )
            existing_no_strike = db.execute(
                "SELECT value_json, updated_at, updated_by FROM app_settings WHERE key = ?",
                ("global_no_strike",),
            ).fetchone()
            history_count = int(db.execute(
                "SELECT COUNT(*) FROM global_no_strike_history"
            ).fetchone()[0])
            if existing_no_strike and history_count == 0:
                legacy_entries = normalize_ipv4_networks(
                    json.loads(existing_no_strike[0]), "no-strike"
                )
                legacy_actor = str(existing_no_strike[2]).strip()[:100] or "legacy-migration"
                db.execute(
                    """
                    INSERT INTO global_no_strike_history (
                        revision, entries_json, action, changed_at, changed_by
                    ) VALUES (1, ?, 'legacy_snapshot', ?, ?)
                    """,
                    (
                        json.dumps(legacy_entries),
                        utc_now(),
                        legacy_actor,
                    ),
                )
            latest_no_strike = db.execute(
                """
                SELECT revision, entries_json, changed_at, changed_by
                FROM global_no_strike_history
                ORDER BY revision DESC
                LIMIT 1
                """
            ).fetchone()
            if latest_no_strike:
                authoritative_entries = json.loads(latest_no_strike[1])
                mirror_entries = (
                    normalize_ipv4_networks(
                        json.loads(existing_no_strike[0]), "no-strike"
                    )
                    if existing_no_strike else []
                )
                reconciled_entries = normalize_ipv4_networks(
                    [*authoritative_entries, *mirror_entries], "no-strike"
                ) if authoritative_entries or mirror_entries else []
                if reconciled_entries != authoritative_entries:
                    reconciled_at = utc_now()
                    reconciled_by = "legacy-rollback-reconciliation"
                    next_revision = int(latest_no_strike[0]) + 1
                    db.execute(
                        """
                        INSERT INTO global_no_strike_history (
                            revision, entries_json, action, changed_at, changed_by
                        ) VALUES (?, ?, 'legacy_snapshot', ?, ?)
                        """,
                        (
                            next_revision,
                            json.dumps(reconciled_entries),
                            reconciled_at,
                            reconciled_by,
                        ),
                    )
                    latest_no_strike = (
                        next_revision,
                        json.dumps(reconciled_entries),
                        reconciled_at,
                        reconciled_by,
                    )
                db.execute(
                    """
                    INSERT INTO app_settings (key, value_json, updated_at, updated_by)
                    VALUES ('global_no_strike', ?, ?, ?)
                    ON CONFLICT(key) DO UPDATE SET
                        value_json = excluded.value_json,
                        updated_at = excluded.updated_at,
                        updated_by = excluded.updated_by
                    """,
                    (latest_no_strike[1], latest_no_strike[2], latest_no_strike[3]),
                )
            db.execute(
                "CREATE INDEX IF NOT EXISTS scan_runs_status_created "
                "ON scan_runs(status, created_at)"
            )
            db.execute(
                "CREATE INDEX IF NOT EXISTS scan_runs_created "
                "ON scan_runs(created_at DESC)"
            )
            db.execute(
                "CREATE INDEX IF NOT EXISTS scan_schedules_profile "
                "ON scan_schedules(profile_id, profile_version)"
            )
            for profile in BUILTIN_PROFILES:
                # Retain the original Nmap-discovery version for schedules already
                # pinned to it, then publish FPING-first behavior as the new latest
                # built-in version for new scans and schedules.
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
                        json.dumps(
                            normalize_scan_options(
                                {**profile["settings"], "discovery_mode": "nmap"}
                            ),
                            sort_keys=True,
                        ),
                    ),
                )
                db.execute(
                    """
                    INSERT OR IGNORE INTO scan_profiles (
                        profile_id, version, name, description, built_in,
                        created_at, created_by, source_profile_id,
                        source_profile_version, settings_json
                    ) VALUES (?, ?, ?, ?, 1, ?, 'system', ?, 1, ?)
                    """,
                    (
                        profile["profile_id"],
                        BUILTIN_PROFILE_VERSION,
                        profile["name"],
                        profile["description"],
                        utc_now(),
                        profile["profile_id"],
                        json.dumps(
                            normalize_scan_options(profile["settings"]), sort_keys=True
                        ),
                    ),
                )
        init_scheduled_work_storage(db_path)
        migrate_legacy_schedules(db_path)
        init_scan_history_index_storage(db_path)
        init_scan_scope_context_storage(db_path)
        info = db_path.stat()
        _POC_STORAGE_READY[storage_key] = (info.st_dev, info.st_ino)


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
    with connect_database(db_path) as db:
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
    with connect_database(db_path) as db:
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


_PROFILE_MUTATION_RECEIPT_PREFIX = "scan_profile_mutation:v1:"
_PROFILE_REQUEST_TOKEN_RE = re.compile(r"^[A-Za-z0-9._:-]{16,128}$")


def _profile_record_on_connection(
    db: sqlite3.Connection,
    profile_id: str,
    version: int | None = None,
) -> dict | None:
    if version is None:
        row = db.execute(
            """
            SELECT profile_id, version, name, description, built_in,
                   created_at, created_by, source_profile_id,
                   source_profile_version, settings_json
            FROM scan_profiles
            WHERE profile_id = ? ORDER BY version DESC LIMIT 1
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
    return _profile_record(row) if row else None


def _profile_mutation_identity(
    request_token: str,
    action: str,
    actor: str,
    normalized_request: dict,
) -> tuple[str, str, str]:
    token = request_token.strip()
    if not _PROFILE_REQUEST_TOKEN_RE.fullmatch(token):
        raise ValueError(
            "Profile request token must contain 16-128 letters, numbers, dots, colons, underscores, or hyphens"
        )
    request_json = json.dumps(normalized_request, sort_keys=True, separators=(",", ":"))
    request_sha256 = hashlib.sha256(request_json.encode("utf-8")).hexdigest()
    return token, request_json, request_sha256


def _profile_mutation_replay(
    db: sqlite3.Connection,
    *,
    request_token: str,
    action: str,
    actor: str,
    request_json: str,
    request_sha256: str,
) -> dict | None:
    row = db.execute(
        "SELECT value_json FROM app_settings WHERE key = ?",
        (f"{_PROFILE_MUTATION_RECEIPT_PREFIX}{request_token}",),
    ).fetchone()
    if row is None:
        return None
    receipt = json.loads(row[0])
    if (
        receipt.get("contract") != "nct-scan-profile-mutation:1"
        or receipt.get("action") != action
        or receipt.get("actor") != actor
        or receipt.get("request_json") != request_json
        or receipt.get("request_sha256") != request_sha256
    ):
        raise RuntimeError(
            "This profile request token was already used for different work; reload and try again"
        )
    result = dict(receipt["result"])
    if _profile_record_on_connection(
        db, str(result["profile_id"]), int(result["version"])
    ) is None:
        raise RuntimeError(
            "The profile created by this earlier request was later deleted; reload before trying again"
        )
    result["request_replayed"] = True
    return result


def _record_profile_mutation(
    db: sqlite3.Connection,
    *,
    request_token: str,
    action: str,
    actor: str,
    request_json: str,
    request_sha256: str,
    result: dict,
) -> None:
    receipt = {
        "contract": "nct-scan-profile-mutation:1",
        "action": action,
        "actor": actor,
        "request_json": request_json,
        "request_sha256": request_sha256,
        "result": result,
    }
    db.execute(
        """
        INSERT INTO app_settings (key, value_json, updated_at, updated_by)
        VALUES (?, ?, ?, ?)
        """,
        (
            f"{_PROFILE_MUTATION_RECEIPT_PREFIX}{request_token}",
            json.dumps(receipt, sort_keys=True),
            utc_now(),
            actor,
        ),
    )


def create_scan_profile(request: ScanProfileCreate, db_path: Path = DB_PATH) -> dict:
    init_poc_storage(db_path)
    actor = request.created_by.strip()
    settings = request.settings.normalized()
    normalized_request = {
        "name": request.name.strip(),
        "description": request.description.strip(),
        "settings": settings,
    }
    request_token, request_json, request_sha256 = _profile_mutation_identity(
        request.request_token, "create", actor, normalized_request
    )
    with connect_database(db_path) as db:
        db.execute("BEGIN IMMEDIATE")
        replay = _profile_mutation_replay(
            db,
            request_token=request_token,
            action="create",
            actor=actor,
            request_json=request_json,
            request_sha256=request_sha256,
        )
        if replay is not None:
            return replay
        profile_id = uuid.uuid4().hex
        db.execute(
            """
            INSERT INTO scan_profiles (
                profile_id, version, name, description, built_in,
                created_at, created_by, source_profile_id,
                source_profile_version, settings_json
            ) VALUES (?, 1, ?, ?, 0, ?, ?, NULL, NULL, ?)
            """,
            (
                profile_id,
                normalized_request["name"],
                normalized_request["description"],
                utc_now(),
                actor,
                json.dumps(settings, sort_keys=True),
            ),
        )
        result = _profile_record_on_connection(db, profile_id, 1)
        assert result is not None
        result.update(request_token=request_token, request_replayed=False)
        _record_profile_mutation(
            db,
            request_token=request_token,
            action="create",
            actor=actor,
            request_json=request_json,
            request_sha256=request_sha256,
            result=result,
        )
        return result


def create_scan_profile_version(
    profile_id: str,
    request: ScanProfileVersionCreate,
    db_path: Path = DB_PATH,
) -> dict:
    init_poc_storage(db_path)
    actor = request.created_by.strip()
    settings = request.settings.normalized()
    normalized_request = {
        "profile_id": profile_id,
        "expected_version": int(request.expected_version),
        "description": request.description.strip(),
        "settings": settings,
    }
    request_token, request_json, request_sha256 = _profile_mutation_identity(
        request.request_token, "version", actor, normalized_request
    )
    with connect_database(db_path) as db:
        db.execute("BEGIN IMMEDIATE")
        replay = _profile_mutation_replay(
            db,
            request_token=request_token,
            action="version",
            actor=actor,
            request_json=request_json,
            request_sha256=request_sha256,
        )
        if replay is not None:
            return replay
        current = _profile_record_on_connection(db, profile_id)
        if current is None:
            raise KeyError("Scan profile not found")
        if current["built_in"]:
            raise ValueError("Built-in profiles are protected; clone one before editing it")
        if int(current["version"]) != int(request.expected_version):
            raise RuntimeError(
                f"This profile changed from v{request.expected_version} to v{current['version']}; reload it before saving a new version"
            )
        version = int(current["version"]) + 1
        db.execute(
            """
            INSERT INTO scan_profiles (
                profile_id, version, name, description, built_in,
                created_at, created_by, source_profile_id,
                source_profile_version, settings_json
            ) VALUES (?, ?, ?, ?, 0, ?, ?, ?, ?, ?)
            """,
            (
                profile_id, version, current["name"], normalized_request["description"],
                utc_now(), actor, profile_id,
                current["version"],
                json.dumps(settings, sort_keys=True),
            ),
        )
        result = _profile_record_on_connection(db, profile_id, version)
        assert result is not None
        result.update(request_token=request_token, request_replayed=False)
        _record_profile_mutation(
            db,
            request_token=request_token,
            action="version",
            actor=actor,
            request_json=request_json,
            request_sha256=request_sha256,
            result=result,
        )
        return result


def clone_scan_profile(
    profile_id: str,
    request: ScanProfileClone,
    db_path: Path = DB_PATH,
) -> dict:
    init_poc_storage(db_path)
    actor = request.created_by.strip()
    normalized_request = {
        "source_profile_id": profile_id,
        "source_version": request.source_version,
        "name": request.name.strip(),
        "description": request.description.strip(),
    }
    request_token, request_json, request_sha256 = _profile_mutation_identity(
        request.request_token, "clone", actor, normalized_request
    )
    with connect_database(db_path) as db:
        db.execute("BEGIN IMMEDIATE")
        replay = _profile_mutation_replay(
            db,
            request_token=request_token,
            action="clone",
            actor=actor,
            request_json=request_json,
            request_sha256=request_sha256,
        )
        if replay is not None:
            return replay
        source = _profile_record_on_connection(db, profile_id, request.source_version)
        if source is None:
            raise KeyError("Source scan profile version not found")
        clone_id = uuid.uuid4().hex
        description = normalized_request["description"] or (
            f"Cloned from {source['name']} v{source['version']}"
        )
        db.execute(
            """
            INSERT INTO scan_profiles (
                profile_id, version, name, description, built_in,
                created_at, created_by, source_profile_id,
                source_profile_version, settings_json
            ) VALUES (?, 1, ?, ?, 0, ?, ?, ?, ?, ?)
            """,
            (
                clone_id,
                normalized_request["name"],
                description,
                utc_now(),
                actor,
                source["profile_id"],
                source["version"],
                json.dumps(source["settings"], sort_keys=True),
            ),
        )
        result = _profile_record_on_connection(db, clone_id, 1)
        assert result is not None
        result.update(request_token=request_token, request_replayed=False)
        _record_profile_mutation(
            db,
            request_token=request_token,
            action="clone",
            actor=actor,
            request_json=request_json,
            request_sha256=request_sha256,
            result=result,
        )
        return result


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


def _month_from_anchor(anchor: datetime, months: int, anchor_day: int) -> datetime:
    absolute = anchor.year * 12 + (anchor.month - 1) + max(0, int(months))
    year, month_index = divmod(absolute, 12)
    month = month_index + 1
    day = min(anchor_day, calendar.monthrange(year, month)[1])
    return anchor.replace(year=year, month=month, day=day)


def next_schedule_time(schedule: dict, after: datetime) -> datetime | None:
    """Advance a schedule after dispatch, preserving its original cadence."""
    if schedule["cadence"] == "once":
        return None
    current = _as_utc(schedule["next_run_at"])
    if schedule["cadence"] == "monthly":
        anchor = _as_utc(schedule.get("first_run_at") or current)
        anchor_day = anchor.day
        after = _as_utc(after)
        month_distance = max(
            0, (after.year - anchor.year) * 12 + after.month - anchor.month
        )
        current = _month_from_anchor(anchor, month_distance, anchor_day)
        if current <= after:
            current = _month_from_anchor(anchor, month_distance + 1, anchor_day)
        return current
    delta = {
        "interval": timedelta(minutes=int(schedule.get("interval_minutes") or 60)),
        "custom_hours": timedelta(hours=int(schedule.get("cadence_hours") or 2)),
        "hourly": timedelta(hours=1),
        "daily": timedelta(days=1),
        "weekly": timedelta(weeks=1),
    }[schedule["cadence"]]
    after = _as_utc(after)
    if current <= after:
        steps = int((after - current) // delta) + 1
        current += delta * steps
    return current


def get_scan_schedule(schedule_id: str, db_path: Path = DB_PATH) -> dict | None:
    if not RUN_ID_RE.fullmatch(schedule_id):
        return None
    init_poc_storage(db_path)
    with connect_database(db_path) as db:
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
    with connect_database(db_path) as db:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute(
            "SELECT definition_json FROM scan_schedules WHERE schedule_id = ?",
            (schedule["schedule_id"],),
        ).fetchone()
        if row is None:
            raise KeyError("Scan schedule not found")
        current = json.loads(row[0])
        current_control_revision = int(current.get("control_revision") or 0)
        supplied_control_revision = int(schedule.get("control_revision") or 0)
        if current_control_revision > supplied_control_revision:
            for key in (
                "enabled", "next_run_at", "control_revision",
                "modification_history", "last_changed_by", "last_changed_at",
            ):
                if key in current:
                    schedule[key] = current[key]
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
    if request.saved_network_ids or request.manual_targets:
        resolved_targets, saved_network_snapshots, manual_targets = (
            resolve_saved_network_targets(
                request.saved_network_ids,
                request.manual_targets,
                db_path,
                max_addresses=MAX_EXPANDED_ADDRESSES,
            )
        )
    else:
        resolved_targets = normalize_ipv4_networks(request.targets, "target")
        saved_network_snapshots = []
        manual_targets = []
    created_at = utc_now()
    definition = {
        "schema_version": 5,
        "definition_version": 1,
        "control_revision": 1,
        "schedule_id": uuid.uuid4().hex,
        "name": request.name,
        "created_at": created_at,
        "updated_at": created_at,
        "created_by": request.created_by,
        "profile_id": profile["profile_id"],
        "profile_version": profile["version"],
        "profile_name": profile["name"],
        "profile_snapshot": profile["settings"],
        "targets": resolved_targets,
        "manual_targets": manual_targets,
        "saved_network_ids": [
            item["saved_network_id"] for item in saved_network_snapshots
        ],
        "saved_networks": saved_network_snapshots,
        "reviewed_scope_associations": [
            item.model_dump() for item in request.reviewed_scope_associations
        ],
        "reviewed_mission_scopes": [
            item.model_dump() for item in request.reviewed_mission_scopes
        ],
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
        "active_target_chunks": None,
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
    definition["definition_digest"] = definition_identity(definition)[1]
    with connect_database(db_path) as db:
        db.execute("BEGIN IMMEDIATE")
        context = resolve_reviewed_scope_context(
            db,
            saved_network_ids=definition["saved_network_ids"],
            manual_targets=definition["manual_targets"],
            reviewed_associations=definition["reviewed_scope_associations"],
        )
        _setup, context = bind_collection_scope_context_on_connection(
            db,
            context=context,
            saved_network_ids=definition["saved_network_ids"],
        )
        definition["collection_safety_setup"] = _setup["review"]
        definition["network_scope_context"] = context
        definition["network_scope_status"] = (
            "pinned" if context is not None else "unscoped"
        )
        mission_review = resolve_collection_mission_review(
            db,
            saved_network_ids=definition["saved_network_ids"],
            manual_targets=definition["manual_targets"],
            reviewed_scopes=definition["reviewed_mission_scopes"],
            collection_scope_id=(context or {}).get("scope_id"),
            enforce_prohibited=bool(request.enabled),
        )
        definition["mission_environment_review"] = mission_review
        definition["mission_environment_status"] = mission_review["decision"]
        definition["definition_digest"] = definition_identity(definition)[1]
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
        register_schedule_definition_on_connection(
            db, definition, created_by=definition["created_by"]
        )
        insert_schedule_scope_context(db, definition["schedule_id"], context)
    return definition


def list_scan_schedules(db_path: Path = DB_PATH) -> list[dict]:
    init_poc_storage(db_path)
    with connect_database(db_path) as db:
        rows = db.execute(
            "SELECT definition_json FROM scan_schedules ORDER BY created_at DESC"
        ).fetchall()
    schedules = [json.loads(row[0]) for row in rows]
    for schedule in schedules:
        if schedule.get("last_run_id"):
            run = get_scan_run_plan(schedule["last_run_id"], db_path)
            schedule["last_run_status"] = run.get("status") if run else "not_found"
        occurrences = list_schedule_occurrences(
            db_path, schedule["schedule_id"], limit=5
        )
        schedule["occurrences"] = occurrences
        schedule["latest_occurrence"] = occurrences[0] if occurrences else None
    return schedules


def set_scan_schedule_enabled(
    schedule_id: str,
    enabled: bool,
    changed_by: str | None = None,
    db_path: Path = DB_PATH,
) -> dict:
    init_poc_storage(db_path)
    with connect_database(db_path) as db:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute(
            "SELECT definition_json FROM scan_schedules WHERE schedule_id = ?",
            (schedule_id,),
        ).fetchone()
        if row is None:
            raise KeyError("Scan schedule not found")
        schedule = json.loads(row[0])
        previous = bool(schedule.get("enabled"))
        if enabled:
            unresolved = db.execute(
                """SELECT 1 FROM scan_schedule_occurrences
                     WHERE schedule_id = ? AND state = 'needs_attention' LIMIT 1""",
                (schedule_id,),
            ).fetchone()
            if unresolved is not None:
                raise RuntimeError(
                    "Review and close the interrupted occurrence before enabling future occurrences"
                )
            context = resolve_schedule_scope_context_in_transaction(db, schedule_id)
            reviewed_context = resolve_reviewed_scope_context(
                db,
                saved_network_ids=list(schedule.get("saved_network_ids") or []),
                manual_targets=list(schedule.get("manual_targets") or []),
                reviewed_associations=list(
                    schedule.get("reviewed_scope_associations") or []
                ),
            )
            _setup, bound_context = bind_collection_scope_context_on_connection(
                db,
                context=context or reviewed_context,
                saved_network_ids=list(schedule.get("saved_network_ids") or []),
            )
            if context is None:
                insert_schedule_scope_context(db, schedule_id, bound_context)
            mission_review = resolve_collection_mission_review(
                db,
                saved_network_ids=list(schedule.get("saved_network_ids") or []),
                manual_targets=list(schedule.get("manual_targets") or []),
                reviewed_scopes=list(schedule.get("reviewed_mission_scopes") or []),
                collection_scope_id=(bound_context or {}).get("scope_id"),
            )
            schedule["mission_environment_review"] = mission_review
            schedule["mission_environment_status"] = mission_review["decision"]
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
                    "failed_to_dispatch",
                }
            )
            if resuming:
                schedule["batch_status"] = "recovery_pending"
                schedule["resume_after_chunk"] = completed_chunks
                schedule["next_run_at"] = utc_now()
            elif schedule.get("batch_status") == "recovery_review_required":
                schedule["batch_status"] = None
                schedule["active_batch_id"] = None
                schedule["active_chunk_number"] = None
                schedule["active_chunk_count"] = None
                schedule["completed_chunk_count"] = 0
                schedule["resume_after_chunk"] = 0
                schedule["active_target_chunks"] = None
                schedule["last_dispatch_note"] = (
                    "Review completed; the interrupted occurrence remains closed. "
                    "A new occurrence will use the current saved schedule."
                )
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
            schedule["control_revision"] = int(schedule.get("control_revision") or 0) + 1
            _append_schedule_history(
                schedule,
                "enabled" if enabled else "paused",
                actor,
                "Enabled recurring execution" if enabled else "Paused recurring execution",
            )
        schedule["updated_at"] = utc_now()
        db.execute(
            """
            UPDATE scan_schedules
            SET name = ?, profile_id = ?, profile_version = ?, definition_json = ?
            WHERE schedule_id = ?
            """,
            (
                schedule["name"], schedule["profile_id"],
                schedule["profile_version"], json.dumps(schedule, sort_keys=True),
                schedule_id,
            ),
        )
    return schedule


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
    if any(
        item["state"] in {"waiting", "preparing", "active", "needs_attention"}
        for item in list_schedule_occurrences(db_path, schedule_id, limit=100)
    ):
        raise RuntimeError(
            "Review or finish the current occurrence before changing this schedule's profile"
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
            "definition_version": int(schedule.get("definition_version") or 1) + 1,
        }
    )
    schedule["definition_digest"] = definition_identity(schedule)[1]
    _append_schedule_history(
        schedule,
        "profile_changed",
        request.changed_by,
        f"Changed pinned profile from {previous_profile} to {profile['name']} v{profile['version']}",
    )
    schedule["updated_at"] = utc_now()
    with connect_database(db_path) as db:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute(
            "SELECT definition_json FROM scan_schedules WHERE schedule_id = ?",
            (schedule_id,),
        ).fetchone()
        if row is None:
            raise KeyError("Scan schedule not found")
        current = json.loads(row[0])
        if int(current.get("definition_version") or 1) + 1 != schedule["definition_version"]:
            raise RuntimeError("The schedule changed while its profile was being updated")
        db.execute(
            """UPDATE scan_schedules
                  SET name = ?, profile_id = ?, profile_version = ?, definition_json = ?
                WHERE schedule_id = ?""",
            (
                schedule["name"], schedule["profile_id"], schedule["profile_version"],
                json.dumps(schedule, sort_keys=True), schedule_id,
            ),
        )
        register_schedule_definition_on_connection(
            db, schedule, created_by=request.changed_by
        )
    return schedule


def insert_scan_run_manifest(manifest: dict, db_path: Path = DB_PATH) -> None:
    init_poc_storage(db_path)
    with connect_database(db_path) as db:
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
        sync_scan_history_manifest(db, manifest)


def insert_reviewed_scan_run(
    manifest: dict,
    plan: ScanRunPlan,
    db_path: Path = DB_PATH,
    *,
    audit_event: str | None = None,
    scheduled_chunk_claim: tuple[str, int, WorkLease] | None = None,
) -> None:
    """Atomically recheck reviewed context, retain the run, and snapshot context."""
    init_poc_storage(db_path)
    init_pipeline_intake_storage(db_path)
    reviewed = [item.model_dump() for item in plan.reviewed_scope_associations]
    mission_reviewed = [item.model_dump() for item in plan.reviewed_mission_scopes]
    with connect_database(db_path) as db:
        db.execute("BEGIN IMMEDIATE")
        if plan.scheduled and plan.schedule_id:
            schedule_row = db.execute(
                "SELECT definition_json FROM scan_schedules WHERE schedule_id = ?",
                (plan.schedule_id,),
            ).fetchone()
            if schedule_row is None:
                raise MissionEnvironmentConflict("The saved schedule is no longer available")
            schedule = json.loads(schedule_row[0])
            if scheduled_chunk_claim is not None:
                occurrence_row = db.execute(
                    """SELECT schedule_id, definition_version, definition_digest
                         FROM scan_schedule_occurrences WHERE occurrence_id = ?""",
                    (scheduled_chunk_claim[0],),
                ).fetchone()
                if occurrence_row is None or tuple(occurrence_row) != (
                    plan.schedule_id, *definition_identity(schedule)[:2]
                ):
                    raise WorkLeaseConflict(
                        "The schedule definition no longer matches its frozen occurrence"
                    )
            resolve_reviewed_scope_context(
                db,
                saved_network_ids=list(schedule.get("saved_network_ids") or []),
                manual_targets=list(schedule.get("manual_targets") or []),
                reviewed_associations=list(
                    schedule.get("reviewed_scope_associations") or []
                ),
            )
            context = resolve_schedule_scope_context_in_transaction(
                db, plan.schedule_id
            )
            # Preserve the reviewed selection as provenance, not execution
            # targets. Feeding IDs back into the generic builder would expand
            # this chunk to the whole Saved Network. The final contact check
            # must use the same reviewed associations rather than an empty
            # selection that would silently replace inherited scope with None.
            for field in (
                "saved_network_ids", "saved_networks", "manual_targets",
                "reviewed_scope_associations", "reviewed_mission_scopes",
            ):
                manifest[field] = list(schedule.get(field) or [])
            mission_reviewed = list(schedule.get("reviewed_mission_scopes") or [])
            manifest["target_selection"] = {
                "saved_networks": manifest["saved_networks"],
                "manual_targets": manifest["manual_targets"],
            }
        else:
            context = resolve_reviewed_scope_context(
                db,
                saved_network_ids=manifest.get("saved_network_ids") or [],
                manual_targets=manifest.get("manual_targets") or [],
                reviewed_associations=reviewed,
            )
        _setup, context = bind_collection_scope_context_on_connection(
            db,
            context=context,
            saved_network_ids=list(manifest.get("saved_network_ids") or []),
        )
        mission_review = resolve_collection_mission_review(
            db,
            saved_network_ids=manifest.get("saved_network_ids") or [],
            manual_targets=manifest.get("manual_targets") or [],
            reviewed_scopes=mission_reviewed,
            collection_scope_id=(context or {}).get("scope_id"),
        )
        manifest["collection_safety_setup"] = _setup["review"]
        prior_context = manifest.get("network_scope_context")
        if (
            isinstance(context, dict)
            and isinstance(prior_context, dict)
            and all(
                context.get(key) == prior_context.get(key)
                for key in ("scope_id", "scope_label", "scope_version", "sources")
            )
            and prior_context.get("recorded_at")
        ):
            # Admission validates the reviewed scope decision;
            # it does not create a new decision when every reviewed input is
            # unchanged. Keep the original evidence-context time stable.
            context["recorded_at"] = prior_context["recorded_at"]
        manifest["network_scope_context"] = context
        manifest["network_scope_status"] = (
            "inherited" if context is not None else "unscoped"
        )
        manifest["mission_environment_review"] = mission_review
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
        if scheduled_chunk_claim is not None:
            occurrence_id, chunk_number, lease = scheduled_chunk_claim
            bind_chunk_scan_run_on_connection(
                db,
                occurrence_id=occurrence_id,
                chunk_number=chunk_number,
                scan_run_id=manifest["run_id"],
                lease=lease,
            )
        sync_scan_history_manifest(db, manifest)

        insert_run_scope_context(db, manifest["run_id"], context)
        mark_pipeline_source(
            db,
            source_kind=AUTOMATED_NMAP_SOURCE,
            source_id=manifest["run_id"],
            marked_by=(
                manifest.get("requested_by") or manifest.get("created_by")
                or manifest.get("operator") or "system"
            ),
            marked_at=manifest["created_at"],
            policy_version=NMAP_INGESTION_POLICY_VERSION,
        )
        if audit_event:
            db.execute(
                """
                INSERT INTO scan_run_audit (
                    run_id, event, actor, changed_at, details
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    manifest["run_id"], audit_event,
                    manifest.get("requested_by") or manifest.get("created_by")
                    or manifest["operator"],
                    manifest["created_at"],
                    "Submitted to the shared analyzer queue",
                ),
            )


def _assert_manifest_fences_on_connection(db, manifest: dict) -> None:
    execution_claim = manifest.get("execution_claim")
    if isinstance(execution_claim, dict):
        assert_work_lease_on_connection(db, execution_claim)
    scheduled_claim = manifest.get("work_claim")
    if isinstance(scheduled_claim, dict):
        assert_work_lease_on_connection(db, scheduled_claim)


def update_scan_run_manifest(manifest: dict, db_path: Path = DB_PATH) -> None:
    init_pipeline_intake_storage(db_path)
    with connect_database(db_path) as db:
        db.execute("BEGIN IMMEDIATE")
        _assert_manifest_fences_on_connection(db, manifest)
        execution_claim = manifest.get("execution_claim")
        if isinstance(execution_claim, dict):
            changed = db.execute(
                """UPDATE scan_runs SET status = ?, manifest_json = ?
                     WHERE run_id = ?
                       AND json_extract(manifest_json, '$.execution_claim.lease_id') = ?""",
                (
                    manifest["status"], json.dumps(manifest, sort_keys=True),
                    manifest["run_id"], str(execution_claim["lease_id"]),
                ),
            ).rowcount
            if changed != 1:
                raise WorkLeaseLost(
                    "This scan worker can no longer update the saved scan"
                )
        else:
            db.execute(
                """UPDATE scan_runs SET status = ?, manifest_json = ?
                     WHERE run_id = ?""",
                (
                    manifest["status"],
                    json.dumps(manifest, sort_keys=True),
                    manifest["run_id"],
                ),
            )
        sync_scan_history_manifest(db, manifest)
        registered_aggregate_count = int(db.execute(
            """SELECT COUNT(*) FROM artifact_observations
               WHERE source_kind = 'nmap_scan' AND source_ref = ?
                 AND original_filename = 'scan.xml'""",
            (manifest["run_id"],),
        ).fetchone()[0])
        artifact_registration_finished = isinstance(
            manifest.get("artifact_registry"), dict,
        )
        if (
            manifest["status"] == "completed"
            and (registered_aggregate_count > 0 or artifact_registration_finished)
        ):
            record_automated_nmap_intent(db, manifest["run_id"])


def update_scan_progress_manifest(manifest: dict, db_path: Path = DB_PATH) -> None:
    """Publish only the fenced run manifest; never rebuild Scan History here."""
    execution_claim = manifest.get("execution_claim")
    if not isinstance(execution_claim, dict):
        raise WorkLeaseLost("Scan progress requires the current execution fence")
    init_pipeline_intake_storage(db_path)
    with connect_database(db_path) as db:
        db.execute("BEGIN IMMEDIATE")
        _assert_manifest_fences_on_connection(db, manifest)
        changed = db.execute(
            """UPDATE scan_runs SET status = ?, manifest_json = ?
                 WHERE run_id = ?
                   AND json_extract(manifest_json, '$.execution_claim.lease_id') = ?""",
            (
                manifest["status"], json.dumps(manifest, sort_keys=True),
                manifest["run_id"], str(execution_claim["lease_id"]),
            ),
        ).rowcount
        if changed != 1:
            raise WorkLeaseLost(
                "This scan worker can no longer publish scan progress"
            )


def publish_scan_contact_starting(
    manifest: dict, *, db_path: Path = DB_PATH
) -> bool:
    """Publish scan running state and scheduled contact start atomically."""
    execution_claim = manifest.get("execution_claim")
    if not isinstance(execution_claim, dict):
        raise WorkLeaseConflict("The scan has no current execution fence")
    scheduled_claim = manifest.get("work_claim")
    with connect_database(db_path) as db:
        db.execute("BEGIN IMMEDIATE")
        _assert_manifest_fences_on_connection(db, manifest)
        cancellation = db.execute(
            """SELECT cancellation_requested_at, cancellation_requested_by,
                      cancellation_cause, cancellation_detail
                 FROM scan_run_control
                WHERE run_id = ? AND cancellation_requested_at IS NOT NULL
                  AND cancellation_acknowledged_at IS NULL""",
            (manifest["run_id"],),
        ).fetchone()
        if cancellation is not None:
            cancelled = _close_precontact_cancellation_on_connection(
                db, manifest, cancellation
            )
            manifest.clear()
            manifest.update(cancelled)
            return False
        prior_context = manifest.get("network_scope_context")
        prior_setup = manifest.get("collection_safety_setup")
        try:
            strict_collection_context = active_collection_enabled()
            if strict_collection_context and (
                not isinstance(prior_context, dict) or not isinstance(prior_setup, dict)
            ):
                raise CollectionSafetySetupIncomplete(
                    "The admitted scan has no frozen Mission Environment collection context"
                )
            reviewed_context = resolve_reviewed_scope_context(
                db,
                saved_network_ids=list(manifest.get("saved_network_ids") or []),
                manual_targets=list(manifest.get("manual_targets") or []),
                reviewed_associations=list(
                    manifest.get("reviewed_scope_associations") or []
                ),
            )
            setup, context = bind_collection_scope_context_on_connection(
                db,
                context=(
                    prior_context if isinstance(prior_context, dict)
                    else reviewed_context
                ),
                saved_network_ids=list(manifest.get("saved_network_ids") or []),
            )
            if (
                isinstance(prior_context, dict)
                and reviewed_context is not None
                and any(
                    reviewed_context.get(key) != prior_context.get(key)
                    for key in (
                        "scope_id", "scope_label", "scope_version", "sources",
                    )
                )
            ):
                raise CollectionSafetySetupIncomplete(
                    "The reviewed Saved Network context changed after scan admission"
                )
            current_setup = setup.get("review") or {}
            if isinstance(prior_setup, dict) and any(
                current_setup.get(key) != prior_setup.get(key)
                for key in (
                    "revision", "scope_id", "scope_version", "no_strike_revision",
                )
            ):
                raise CollectionSafetySetupIncomplete(
                    "Mission Environment scope or safety review changed after scan admission"
                )
            # The contact boundary may validate the frozen decision but must never
            # replace it with a newer active scope or setup review.
            if isinstance(prior_context, dict):
                context = dict(prior_context)
            mission_review = resolve_collection_mission_review(
                db,
                saved_network_ids=list(manifest.get("saved_network_ids") or []),
                manual_targets=list(manifest.get("manual_targets") or []),
                reviewed_scopes=list(manifest.get("reviewed_mission_scopes") or []),
                collection_scope_id=(context or {}).get("scope_id"),
            )
        except (
            CollectionSafetySetupIncomplete,
            MissionEnvironmentConflict,
            SavedNetworkScopeConflict,
        ) as exc:
            blocked = _close_precontact_mission_block_on_connection(
                db, manifest, str(exc)
            )
            manifest.clear()
            manifest.update(blocked)
            return False
        manifest["network_scope_context"] = context
        manifest["network_scope_status"] = (
            "inherited" if context is not None else "unscoped"
        )
        manifest["mission_environment_review"] = mission_review
        manifest["collection_safety_setup"] = (
            dict(prior_setup) if isinstance(prior_setup, dict) else setup["review"]
        )
        manifest["started_at"] = utc_now()
        manifest["status"] = "running"
        if isinstance(scheduled_claim, dict):
            mark_chunk_contact_starting_on_connection(
                db,
                occurrence_id=str(scheduled_claim["occurrence_id"]),
                chunk_number=int(scheduled_claim["chunk_number"]),
                lease=scheduled_claim,
            )
        changed = db.execute(
            """UPDATE scan_runs SET status = 'running', manifest_json = ?
                 WHERE run_id = ? AND status = 'dispatching'
                   AND json_extract(manifest_json, '$.execution_claim.lease_id') = ?""",
            (
                json.dumps(manifest, sort_keys=True),
                manifest["run_id"],
                str(execution_claim["lease_id"]),
            ),
        ).rowcount
        if changed != 1:
            raise WorkLeaseLost("This scan worker can no longer start network contact")
        sync_scan_history_manifest(db, manifest)
        db.execute(
            """INSERT INTO scan_run_audit(
                   run_id, event, actor, changed_at, details
               ) VALUES (?, 'started', ?, ?, ?)""",
            (
                manifest["run_id"],
                manifest.get("owner") or manifest.get("executed_by") or "system",
                manifest["started_at"],
                "Analyzer capacity assigned; scan execution started",
            ),
        )
    return True


def _close_precontact_mission_block_on_connection(
    db,
    manifest: dict,
    detail: str,
) -> dict:
    """Fail a claimed run closed when its reviewed mission context changed."""
    execution_claim = manifest.get("execution_claim")
    if not isinstance(execution_claim, dict):
        raise WorkLeaseConflict("The scan has no current execution fence")
    changed_at = utc_now()
    reason = (
        "Blocked before network contact because Mission Environment review is no "
        f"longer current: {detail}"
    )[:500]
    blocked = dict(manifest)
    blocked.update({
        "status": "blocked_mission_environment",
        "completed_at": changed_at,
        "success": False,
        "execution_note": reason,
    })
    blocked.pop("started_at", None)
    blocked.pop("execution_claim", None)
    if isinstance(blocked.get("progress"), dict):
        update_scan_progress(
            blocked["progress"],
            phase="blocked_mission_environment",
            updated_at=changed_at,
        )
    scheduled_claim = manifest.get("work_claim")
    if isinstance(scheduled_claim, dict):
        publish_chunk_terminal_on_connection(
            db,
            occurrence_id=str(scheduled_claim["occurrence_id"]),
            chunk_number=int(scheduled_claim["chunk_number"]),
            terminal_state="cancelled",
            reason=reason,
            lease=scheduled_claim,
            contact_started=False,
        )
    changed = db.execute(
        """UPDATE scan_runs SET status = 'blocked_mission_environment',
                                  manifest_json = ?
             WHERE run_id = ? AND status = 'dispatching'
               AND json_extract(manifest_json, '$.execution_claim.lease_id') = ?""",
        (
            json.dumps(blocked, sort_keys=True),
            blocked["run_id"],
            str(execution_claim["lease_id"]),
        ),
    ).rowcount
    if changed != 1:
        raise WorkLeaseLost("This scan worker can no longer block stale mission work")
    sync_scan_history_manifest(db, blocked)
    release_work_lease_on_connection(
        db,
        execution_claim,
        detail="Released after Mission Environment changed before contact",
    )
    db.execute(
        """INSERT INTO scan_run_audit(
               run_id, event, actor, changed_at, details
           ) VALUES (?, 'blocked_mission_environment', ?, ?, ?)""",
        (
            blocked["run_id"],
            blocked.get("owner") or blocked.get("executed_by") or "system",
            changed_at,
            reason,
        ),
    )
    return blocked


def _close_precontact_cancellation_on_connection(
    db,
    manifest: dict,
    cancellation,
) -> dict:
    """Close a dispatching run without contact while both current fences are held."""
    execution_claim = manifest.get("execution_claim")
    if not isinstance(execution_claim, dict):
        raise WorkLeaseConflict("The scan has no current execution fence")
    requested_at, requested_by, cause, detail = cancellation
    changed_at = utc_now()
    reason = (
        "Cancelled before network contact"
        + (f" by {requested_by}" if requested_by else "")
        + (f": {detail}" if detail else "")
    )[:500]
    cancelled = dict(manifest)
    cancelled.update({
        "status": "cancelled",
        "completed_at": changed_at,
        "success": False,
        "execution_note": reason,
        "cancellation_cause": cause,
        "cancellation_requested_at": requested_at,
    })
    cancelled.pop("started_at", None)
    cancelled.pop("execution_claim", None)
    if isinstance(cancelled.get("progress"), dict):
        update_scan_progress(
            cancelled["progress"], phase="cancelled", updated_at=changed_at
        )
    scheduled_claim = manifest.get("work_claim")
    if isinstance(scheduled_claim, dict):
        publish_chunk_terminal_on_connection(
            db,
            occurrence_id=str(scheduled_claim["occurrence_id"]),
            chunk_number=int(scheduled_claim["chunk_number"]),
            terminal_state="cancelled",
            reason=reason,
            lease=scheduled_claim,
            contact_started=False,
        )
    changed = db.execute(
        """UPDATE scan_runs SET status = 'cancelled', manifest_json = ?
             WHERE run_id = ? AND status = 'dispatching'
               AND json_extract(manifest_json, '$.execution_claim.lease_id') = ?""",
        (
            json.dumps(cancelled, sort_keys=True),
            cancelled["run_id"],
            str(execution_claim["lease_id"]),
        ),
    ).rowcount
    if changed != 1:
        raise WorkLeaseLost("This scan worker can no longer close the cancelled run")
    sync_scan_history_manifest(db, cancelled)
    release_work_lease_on_connection(
        db, execution_claim, detail="Cancelled before network contact"
    )
    db.execute(
        """UPDATE scan_run_control SET cancellation_acknowledged_at = ?
             WHERE run_id = ? AND cancellation_acknowledged_at IS NULL""",
        (changed_at, cancelled["run_id"]),
    )
    db.execute(
        """INSERT INTO scan_run_audit(
               run_id, event, actor, changed_at, details
           ) VALUES (?, 'cancelled', ?, ?, ?)""",
        (
            cancelled["run_id"], requested_by or "system", changed_at, reason,
        ),
    )
    return cancelled


def requeue_scan_after_precontact_failure(
    manifest: dict,
    *,
    reason: str,
    db_path: Path = DB_PATH,
    automatic_retry_limit: int = 1,
    retry_if_clear: bool = True,
) -> bool:
    """Release current fences and retain the same run for one bounded safe retry."""
    execution_claim = manifest.get("execution_claim")
    if not isinstance(execution_claim, dict):
        return False
    if manifest.get("started_at") or manifest.get("status") != "dispatching":
        return False
    failure_count = int(manifest.get("precontact_start_failure_count") or 0) + 1
    scheduled_claim = manifest.get("work_claim")
    with connect_database(db_path) as db:
        db.execute("BEGIN IMMEDIATE")
        _assert_manifest_fences_on_connection(db, manifest)
        cancellation = db.execute(
            """SELECT cancellation_requested_at, cancellation_requested_by,
                      cancellation_cause, cancellation_detail
                 FROM scan_run_control
                WHERE run_id = ? AND cancellation_requested_at IS NOT NULL
                  AND cancellation_acknowledged_at IS NULL""",
            (manifest["run_id"],),
        ).fetchone()
        if cancellation is not None:
            retained = _close_precontact_cancellation_on_connection(
                db, manifest, cancellation
            )
            manifest.clear()
            manifest.update(retained)
            return True
        if not retry_if_clear:
            return False
        if failure_count > max(0, int(automatic_retry_limit)):
            manifest["precontact_start_failure_count"] = failure_count
            return False
        retained = dict(manifest)
        retained["status"] = "queued"
        retained["precontact_start_failure_count"] = failure_count
        retained["last_precontact_start_error"] = str(reason)[:500]
        retained.pop("execution_claim", None)
        if isinstance(scheduled_claim, dict):
            row = db.execute(
                """SELECT state, contact_phase FROM scan_schedule_chunks
                     WHERE occurrence_id = ? AND chunk_number = ?""",
                (
                    str(scheduled_claim["occurrence_id"]),
                    int(scheduled_claim["chunk_number"]),
                ),
            ).fetchone()
            if row is None or row[0] != "preparing" or row[1] != "preparing":
                return False
            db.execute(
                """UPDATE scan_schedule_chunks
                      SET state = 'waiting', contact_phase = 'not_started',
                          status_reason = ?
                    WHERE occurrence_id = ? AND chunk_number = ?""",
                (
                    f"Local start failed before network contact; retry {failure_count} of {automatic_retry_limit}",
                    str(scheduled_claim["occurrence_id"]),
                    int(scheduled_claim["chunk_number"]),
                ),
            )
            db.execute(
                """UPDATE scan_schedule_occurrences
                      SET state = 'waiting', status_reason = ?
                    WHERE occurrence_id = ?""",
                (
                    "Local start failed before network contact; the same saved run is waiting for one safe retry",
                    str(scheduled_claim["occurrence_id"]),
                ),
            )
        changed = db.execute(
            """UPDATE scan_runs SET status = 'queued', manifest_json = ?
                 WHERE run_id = ? AND status = 'dispatching'
                   AND json_extract(manifest_json, '$.execution_claim.lease_id') = ?""",
            (
                json.dumps(retained, sort_keys=True),
                retained["run_id"],
                str(execution_claim["lease_id"]),
            ),
        ).rowcount
        if changed != 1:
            raise WorkLeaseLost("This scan worker can no longer retain a safe retry")
        sync_scan_history_manifest(db, retained)
        if isinstance(scheduled_claim, dict):
            release_work_lease_on_connection(
                db,
                scheduled_claim,
                detail="Released after local failure before network contact",
            )
        release_work_lease_on_connection(
            db,
            execution_claim,
            detail="Released after local failure before network contact",
        )
        db.execute(
            """INSERT INTO scan_run_audit(
                   run_id, event, actor, changed_at, details
               ) VALUES (?, 'precontact_retry_saved', ?, ?, ?)""",
            (
                retained["run_id"],
                retained.get("owner") or retained.get("executed_by") or "system",
                utc_now(),
                str(reason)[:500],
            ),
        )
    manifest.clear()
    manifest.update(retained)
    return True


def publish_scheduled_scan_terminal(
    manifest: dict,
    claim: dict,
    *,
    db_path: Path = DB_PATH,
) -> str:
    """Publish scheduled scan authority, chunk state, and fence release together."""
    status = str(manifest["status"])
    if status in {"completed", "completed_without_nmap"}:
        chunk_state = "complete"
    elif status == "cancelled":
        chunk_state = "cancelled"
    else:
        chunk_state = "needs_attention"
    reason = manifest.get("error") or manifest.get("execution_note") or (
        f"Scan ended {status}"
    )
    with connect_database(db_path) as db:
        db.execute("BEGIN IMMEDIATE")
        _assert_manifest_fences_on_connection(db, manifest)
        execution_claim = manifest.get("execution_claim")
        if not isinstance(execution_claim, dict):
            raise WorkLeaseConflict("The scheduled scan has no execution fence")
        changed = db.execute(
            """UPDATE scan_runs SET status = ?, manifest_json = ?
                WHERE run_id = ?
                  AND json_extract(manifest_json, '$.work_claim.lease_id') = ?
                  AND json_extract(manifest_json, '$.execution_claim.lease_id') = ?""",
            (
                status,
                json.dumps(manifest, sort_keys=True),
                manifest["run_id"],
                str(claim["lease_id"]),
                str(execution_claim["lease_id"]),
            ),
        ).rowcount
        if changed != 1:
            raise WorkLeaseConflict(
                "This scheduled scan can no longer publish its terminal evidence"
            )
        sync_scan_history_manifest(db, manifest)
        registered_aggregate_count = int(db.execute(
            """SELECT COUNT(*) FROM artifact_observations
               WHERE source_kind = 'nmap_scan' AND source_ref = ?
                 AND original_filename = 'scan.xml'""",
            (manifest["run_id"],),
        ).fetchone()[0])
        if status == "completed" and (
            registered_aggregate_count > 0
            or isinstance(manifest.get("artifact_registry"), dict)
        ):
            record_automated_nmap_intent(db, manifest["run_id"])
        occurrence_state = publish_chunk_terminal_on_connection(
            db,
            occurrence_id=str(claim["occurrence_id"]),
            chunk_number=int(claim["chunk_number"]),
            terminal_state=chunk_state,
            reason=str(reason),
            lease=claim,
        )
        release_work_lease_on_connection(
            db, execution_claim, detail=f"Scan ended {status}"
        )
        db.execute(
            """INSERT INTO scan_run_audit(
                   run_id, event, actor, changed_at, details
               ) VALUES (?, ?, ?, ?, ?)""",
            (
                manifest["run_id"], status,
                manifest.get("owner") or manifest.get("executed_by") or "system",
                manifest["completed_at"], str(reason)[:500],
            ),
        )
    return occurrence_state


def publish_scan_terminal(manifest: dict, *, db_path: Path = DB_PATH) -> None:
    """Publish an unscheduled terminal scan and release shared capacity atomically."""
    execution_claim = manifest.get("execution_claim")
    if not isinstance(execution_claim, dict):
        update_scan_run_manifest(manifest, db_path)
        return
    with connect_database(db_path) as db:
        db.execute("BEGIN IMMEDIATE")
        _assert_manifest_fences_on_connection(db, manifest)
        changed = db.execute(
            """UPDATE scan_runs SET status = ?, manifest_json = ?
                 WHERE run_id = ?
                   AND json_extract(manifest_json, '$.execution_claim.lease_id') = ?""",
            (
                manifest["status"], json.dumps(manifest, sort_keys=True),
                manifest["run_id"], str(execution_claim["lease_id"]),
            ),
        ).rowcount
        if changed != 1:
            raise WorkLeaseLost("This scan worker can no longer publish its result")
        sync_scan_history_manifest(db, manifest)
        registered_aggregate_count = int(db.execute(
            """SELECT COUNT(*) FROM artifact_observations
                 WHERE source_kind = 'nmap_scan' AND source_ref = ?
                   AND original_filename = 'scan.xml'""",
            (manifest["run_id"],),
        ).fetchone()[0])
        if manifest["status"] == "completed" and (
            registered_aggregate_count > 0
            or isinstance(manifest.get("artifact_registry"), dict)
        ):
            record_automated_nmap_intent(db, manifest["run_id"])
        release_work_lease_on_connection(
            db, execution_claim, detail=f"Scan ended {manifest['status']}"
        )


class NoScannableTargetsError(RuntimeError):
    pass


def _add_excludefile(argv: list[str] | None) -> list[str] | None:
    if not argv or "--excludefile" in argv:
        return argv
    return [*argv, "--excludefile", "no-strike.txt"]


def _ensure_manifest_excludefile_commands(manifest: dict) -> None:
    """Upgrade queued legacy commands so a later safety update is enforceable."""
    keys = ["command_argv", "fallback_command_argv"]
    if manifest.get("discovery_mode") != "fping":
        keys.append("discovery_command_argv")
    for key in keys:
        if isinstance(manifest.get(key), list) and manifest[key]:
            manifest[key] = _add_excludefile(manifest[key])
    if manifest.get("command_argv"):
        manifest["execution_command_argv"] = build_nmap_execution_argv(
            manifest["command_argv"]
        )
    if (
        manifest.get("discovery_mode") != "fping"
        and manifest.get("discovery_command_argv")
    ):
        manifest["discovery_execution_command_argv"] = build_nmap_execution_argv(
            manifest["discovery_command_argv"]
        )
    for phase in manifest.get("execution_phases") or []:
        if isinstance(phase.get("command_argv"), list) and phase["command_argv"]:
            phase["command_argv"] = _add_excludefile(phase["command_argv"])
            phase["execution_command_argv"] = build_nmap_execution_argv(
                phase["command_argv"]
            )
        if phase.get("command_argv"):
            phase["exact_command"] = shlex.join(phase["command_argv"])
        if phase.get("execution_command_argv"):
            phase["exact_execution_command"] = shlex.join(
                phase["execution_command_argv"]
            )
    for argv_key, exact_key in (
        ("command_argv", "exact_command"),
        ("execution_command_argv", "exact_execution_command"),
        ("discovery_command_argv", "exact_discovery_command"),
        ("discovery_execution_command_argv", "exact_discovery_execution_command"),
        ("fallback_command_argv", "exact_fallback_command"),
    ):
        if manifest.get(argv_key):
            manifest[exact_key] = shlex.join(manifest[argv_key])


def certify_scan_contact_phase(
    manifest: dict,
    phase: str,
    *,
    db_path: Path = DB_PATH,
    data_dir: Path = DATA_DIR,
) -> list[str]:
    """Re-certify the safety boundary immediately before active contact."""
    context = manifest.get("network_scope_context") or {}
    setup = require_collection_safety_ready(
        db_path, expected_scope_id=context.get("scope_id")
    )
    current_review = setup["review"]
    admitted_review = manifest.get("collection_safety_setup")
    if active_collection_enabled():
        if not isinstance(admitted_review, dict) or not context.get("scope_id"):
            raise CollectionSafetySetupIncomplete(
                "The admitted scan has no frozen Mission Environment collection context"
            )
        if any(
            current_review.get(key) != admitted_review.get(key)
            for key in (
                "revision", "scope_id", "scope_version", "no_strike_revision",
            )
        ) or any(
            context.get(key) != admitted_review.get(review_key)
            for key, review_key in (
                ("scope_id", "scope_id"),
                ("scope_version", "scope_version"),
            )
        ):
            raise CollectionSafetySetupIncomplete(
                "Mission Environment scope or safety review changed after scan admission"
            )
    elif not isinstance(admitted_review, dict):
        # Analysis-only legacy test and recovery paths have no active collection
        # boundary to freeze, but retain the current review for diagnostics.
        manifest["collection_safety_setup"] = current_review
    global_state = get_global_no_strike(db_path)
    coverage = manifest.setdefault("coverage", {})
    submission = manifest.get("no_strike_submission") or {}
    additional = coverage.get("additional_no_strike")
    if additional is None:
        additional = submission.get("additional")
    if additional is None:
        # Legacy queued runs did not separate source lists. Preserve their old
        # effective list as an additional boundary, then add the current global list.
        additional = manifest.get("no_strike") or []
    additional = normalize_ipv4_networks(additional, "no-strike") if additional else []
    effective = normalize_ipv4_networks(
        [*global_state["entries"], *additional], "no-strike"
    ) if global_state["entries"] or additional else []
    remaining = expanded_discovery_targets(manifest["targets"], effective)
    certified_at = utc_now()
    certification = {
        "phase": phase,
        "certified_at": certified_at,
        "global_revision": global_state["revision"],
        "global_as_of": global_state["updated_at"],
        "global": global_state["entries"],
        "additional": additional,
        "effective": effective,
        "remaining_address_count": len(remaining),
    }
    manifest["no_strike"] = effective
    manifest.setdefault("no_strike_certifications", []).append(certification)
    coverage.update({
        "no_strike": effective,
        "global_no_strike": global_state["entries"],
        "additional_no_strike": additional,
        "global_no_strike_revision": global_state["revision"],
        "global_no_strike_as_of": global_state["updated_at"],
        "no_strike_last_certified_at": certified_at,
        "no_strike_last_certified_phase": phase,
    })
    if isinstance(manifest.get("progress"), dict):
        manifest["progress"]["scope_hosts_total"] = len(remaining)
    _ensure_manifest_excludefile_commands(manifest)
    run_dir = run_directory(manifest["run_id"], data_dir)
    if run_dir.exists():
        (run_dir / "no-strike.txt").write_text(
            "\n".join(effective) + ("\n" if effective else ""), encoding="utf-8"
        )
        if manifest.get("discovery_mode") == "fping":
            (run_dir / "discovery-targets.txt").write_text(
                "\n".join(remaining) + ("\n" if remaining else ""), encoding="utf-8"
            )
    update_scan_run_manifest(manifest, db_path)
    if run_dir.exists():
        write_manifest_file(manifest, data_dir)
    append_scan_audit(
        db_path,
        run_id=manifest["run_id"],
        event="no_strike_certified",
        actor="system",
        details=(
            f"{phase}: global revision {global_state['revision']}; "
            f"{len(remaining)} address(es) remain"
        ),
        changed_at=certified_at,
    )
    if not remaining:
        raise NoScannableTargetsError(
            "No addresses remain after the latest global and scan-specific No-Strike exclusions"
        )
    return remaining


def _queued_run_ids(db_path: Path = DB_PATH) -> list[str]:
    init_poc_storage(db_path)
    with connect_database(db_path) as db:
        return [
            row[0]
            for row in db.execute(
                "SELECT run_id FROM scan_runs WHERE status = 'queued' ORDER BY rowid"
            ).fetchall()
        ]


def with_queue_state(
    manifest: dict,
    db_path: Path = DB_PATH,
    queued_ids: list[str] | None = None,
) -> dict:
    result = dict(manifest)
    queued_ids = _queued_run_ids(db_path) if queued_ids is None else queued_ids
    if result.get("status") == "queued" and result.get("run_id") in queued_ids:
        result["queue_position"] = queued_ids.index(result["run_id"]) + 1
    else:
        result["queue_position"] = None
    result["queue_waiting_count"] = len(queued_ids)
    result.setdefault("owner", result.get("created_by") or result.get("operator"))
    result.setdefault("requested_by", result.get("created_by") or result.get("operator"))
    with connect_database(db_path, read_only=True) as db:
        control = db.execute(
            """SELECT cancellation_requested_at, cancellation_requested_by,
                      cancellation_cause, cancellation_detail,
                      cancellation_acknowledged_at
                 FROM scan_run_control WHERE run_id = ?""",
            (result.get("run_id"),),
        ).fetchone()
    if control and control[0]:
        result.update(
            {
                "cancellation_requested_at": control[0],
                "cancellation_requested_by": control[1],
                "cancellation_cause": control[2],
                "cancellation_detail": control[3],
                "cancellation_acknowledged_at": control[4],
            }
        )
        if control[2] == "global_no_strike" and control[3]:
            try:
                result["safety_cancellation_requested"] = json.loads(control[3])
            except json.JSONDecodeError:
                result["safety_cancellation_requested"] = {
                    "detail": control[3]
                }
    return result


def save_scan_run_plan(plan: ScanRunPlan, db_path: Path = DB_PATH) -> dict:
    manifest = build_scan_run_manifest(plan, db_path=db_path)
    insert_reviewed_scan_run(manifest, plan, db_path)
    return manifest


def prepare_scan_run(
    request: ScanRunRequest,
    db_path: Path = DB_PATH,
    interfaces: set[str] | None = None,
    *,
    reserved_run_id: str | None = None,
    scheduled_chunk_claim: tuple[str, int, WorkLease] | None = None,
) -> dict:
    validate_runtime_interface(request.interface, interfaces)
    manifest = build_scan_run_manifest(
        request,
        capture=request.capture,
        timeout_seconds=request.timeout_seconds,
        status="queued",
        db_path=db_path,
        reserved_run_id=reserved_run_id,
        work_claim=(
            {
                **scheduled_chunk_claim[2].as_claim(),
                "occurrence_id": scheduled_chunk_claim[0],
                "chunk_number": int(scheduled_chunk_claim[1]),
            }
            if scheduled_chunk_claim is not None else None
        ),
    )
    insert_reviewed_scan_run(
        manifest,
        request,
        db_path,
        audit_event="queued",
        scheduled_chunk_claim=scheduled_chunk_claim,
    )
    return manifest


SCAN_HISTORY_METADATA_EXPRESSION = (
    "json_remove(manifest_json, '$.artifacts', '$.commands', '$.execution_steps', "
    "'$.stdout', '$.stderr', '$.profile_settings', '$.command', "
    "'$.exact_execution_command')"
)


def list_scan_run_plans(db_path: Path = DB_PATH, limit: int = 50, *, offset: int = 0, metadata_only: bool = False) -> list[dict]:
    init_poc_storage(db_path)
    with connect_database(db_path) as db:
        # Lightweight history never opens scan XML or enumerates artifacts.
        expression = SCAN_HISTORY_METADATA_EXPRESSION if metadata_only else "manifest_json"
        rows = db.execute(
            f"SELECT {expression} FROM scan_runs ORDER BY created_at DESC, rowid DESC LIMIT ? OFFSET ?",
            (limit, offset),
        ).fetchall()
    if metadata_only:
        return [json.loads(row[0]) for row in rows]
    queued_ids = _queued_run_ids(db_path)
    return [
        with_queue_state(with_host_count(json.loads(row[0])), db_path, queued_ids)
        for row in rows
    ]


def list_active_scan_run_plans(db_path: Path = DB_PATH) -> list[dict]:
    """Return all queued or executing runs without applying a history window first."""
    init_poc_storage(db_path)
    active_states = ("queued", "dispatching", "running", "awaiting_fallback_approval")
    placeholders = ",".join("?" for _ in active_states)
    with connect_database(db_path) as db:
        rows = db.execute(
            "SELECT manifest_json FROM scan_runs "
            f"WHERE json_extract(manifest_json, '$.status') IN ({placeholders}) "
            "ORDER BY created_at ASC, rowid ASC",
            active_states,
        ).fetchall()
    queued_ids = _queued_run_ids(db_path)
    return [
        with_queue_state(with_host_count(json.loads(row[0])), db_path, queued_ids)
        for row in rows
    ]


def list_all_scan_history_metadata(db_path: Path = DB_PATH) -> list[dict]:
    """Read one consistent metadata-only snapshot without opening evidence files."""
    if not Path(db_path).is_file():
        return []
    try:
        with connect_database(db_path, read_only=True) as db:
            db.execute("BEGIN")
            rows = db.execute(
                f"SELECT {SCAN_HISTORY_METADATA_EXPRESSION} FROM scan_runs "
                "ORDER BY created_at DESC, rowid DESC"
            ).fetchall()
    except sqlite3.OperationalError as exc:
        if "no such table" in str(exc).lower():
            return []
        raise
    return [json.loads(row[0]) for row in rows]


def list_scan_history_metadata_by_ids(
    run_ids: list[str], db_path: Path = DB_PATH
) -> list[dict]:
    if not run_ids:
        return []
    if len(run_ids) > 100 or any(not RUN_ID_RE.fullmatch(run_id) for run_id in run_ids):
        raise ValueError("At most 100 valid scan identifiers may be refreshed")
    if not Path(db_path).is_file():
        return []
    placeholders = ",".join("?" for _ in run_ids)
    try:
        with connect_database(db_path, read_only=True) as db:
            db.execute("BEGIN")
            rows = db.execute(
                f"SELECT run_id, {SCAN_HISTORY_METADATA_EXPRESSION} FROM scan_runs "
                f"WHERE run_id IN ({placeholders})",
                tuple(run_ids),
            ).fetchall()
    except sqlite3.OperationalError as exc:
        if "no such table" in str(exc).lower():
            return []
        raise
    records = {row[0]: json.loads(row[1]) for row in rows}
    return [records[run_id] for run_id in run_ids if run_id in records]


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
    with connect_database(db_path) as db:
        row = db.execute(
            "SELECT manifest_json FROM scan_runs WHERE run_id = ?", (run_id,)
        ).fetchone()
    return with_queue_state(with_host_count(json.loads(row[0])), db_path) if row else None


class ScanRunMetadataConflict(RuntimeError):
    """Historical metadata changed after the operator opened the record."""


HISTORICAL_METADATA_STATES = {
    "completed",
    "completed_without_nmap",
    "failed",
    "cancelled",
    "timed_out",
    "stopped_no_targets",
    "interrupted",
}


def _manifest_metadata_revision(manifest: dict) -> int:
    revision = manifest.get("metadata_revision", 0)
    if isinstance(revision, bool) or not isinstance(revision, int) or revision < 0:
        raise ScanRunMetadataConflict(
            "This scan has invalid historical-context revision data. An administrator must review it before changes can be recorded."
        )
    return revision


def attribute_scan_run_networks(
    run_id: str,
    request: ScanRunNetworkAttribution,
    db_path: Path = DB_PATH,
    *,
    actor: str | None = None,
    role: str | None = None,
) -> dict:
    """Atomically revise only terminal-scan attribution metadata and its audit."""
    init_poc_storage(db_path)
    signed_in_actor = str(actor or request.changed_by).strip()[:100]
    signed_in_role = str(role or "admin").strip().lower()
    changed_at = utc_now()
    with connect_database(db_path) as db:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute(
            "SELECT manifest_json FROM scan_runs WHERE run_id = ?", (run_id,)
        ).fetchone()
        if row is None:
            raise KeyError("Scan run not found")
        manifest = json.loads(row[0])
        owner = str(
            manifest.get("owner")
            or manifest.get("created_by")
            or manifest.get("operator")
            or ""
        ).strip()
        if signed_in_role not in {"analyst", "admin"} or (
            signed_in_role != "admin" and signed_in_actor != owner
        ):
            raise PermissionError(
                "Only the scan owner or an Administrator can record historical scan context."
            )
        if manifest.get("status") not in HISTORICAL_METADATA_STATES:
            raise ValueError(
                "Historical scan context can be changed only after the scan has stopped."
            )
        current_revision = _manifest_metadata_revision(manifest)
        if request.expected_metadata_revision != current_revision:
            raise ScanRunMetadataConflict(
                "Another analyst changed this scan's recorded context after you opened it. Your choice was not saved. Reload Scan History, reopen Review network context, and review the latest context and attribution history before trying again."
            )

        target_cidrs: set[str] = set()
        for value in manifest.get("targets") or []:
            try:
                target_cidrs.add(str(ipaddress.ip_network(value, strict=False)))
            except ValueError:
                continue
        snapshots: list[dict] = []
        selected_ids: list[str] = []
        for saved_network_id in dict.fromkeys(request.saved_network_ids):
            record = get_saved_network_on_connection(db, saved_network_id)
            if record is None or not record.get("active"):
                raise ValueError("Choose an active Saved Network")
            if record["cidr"] not in target_cidrs:
                raise ValueError(
                    f"{record['name']} ({record['cidr']}) is not an exact target of this scan"
                )
            selected_ids.append(record["saved_network_id"])
            snapshots.append(
                {
                    "saved_network_id": record["saved_network_id"],
                    "name": record["name"],
                    "cidr": record["cidr"],
                    "description": record["description"],
                    "category": record["category"],
                    "tags": list(record["tags"]),
                }
            )

        previous = {
            "metadata_revision": current_revision,
            "saved_network_ids": list(manifest.get("saved_network_ids") or []),
            "saved_networks": list(manifest.get("saved_networks") or []),
            "manual_targets": list(manifest.get("manual_targets") or []),
        }
        selected_cidrs = {item["cidr"] for item in snapshots}
        manual_targets = [
            value for value in sorted(target_cidrs) if value not in selected_cidrs
        ]
        manifest["saved_network_ids"] = selected_ids
        manifest["saved_networks"] = snapshots
        manifest["manual_targets"] = manual_targets
        target_selection = dict(manifest.get("target_selection") or {})
        target_selection["saved_networks"] = snapshots
        target_selection["manual_targets"] = manual_targets
        manifest["target_selection"] = target_selection
        manifest["network_attribution_changed_at"] = changed_at
        manifest["network_attribution_changed_by"] = signed_in_actor
        manifest["metadata_revision"] = current_revision + 1
        prior_history = manifest.get("network_attribution_history")
        if prior_history is not None and not isinstance(prior_history, list):
            raise ScanRunMetadataConflict(
                "This scan has invalid historical attribution data. An administrator must review it before changes can be recorded."
            )
        history = list(prior_history or [])
        history.append(
            {
                "metadata_revision": manifest["metadata_revision"],
                "changed_at": changed_at,
                "changed_by": signed_in_actor,
                "previous_saved_networks": [
                    {
                        "saved_network_id": item.get("saved_network_id"),
                        "name": item.get("name"),
                        "cidr": item.get("cidr"),
                    }
                    for item in previous["saved_networks"]
                    if isinstance(item, dict)
                ],
                "saved_networks": [
                    {
                        "saved_network_id": item["saved_network_id"],
                        "name": item["name"],
                        "cidr": item["cidr"],
                    }
                    for item in snapshots
                ],
                "previous": previous,
                "current": {
                    "saved_network_ids": list(selected_ids),
                    "saved_networks": list(snapshots),
                    "manual_targets": list(manual_targets),
                },
            }
        )
        manifest["network_attribution_history"] = history
        db.execute(
            "UPDATE scan_runs SET manifest_json = ? WHERE run_id = ?",
            (json.dumps(manifest, sort_keys=True), run_id),
        )
        sync_scan_history_manifest(db, manifest)
        details = (
            "Attributed retained scan to "
            + ", ".join(f"{item['name']} ({item['cidr']})" for item in snapshots)
            if snapshots
            else "Returned retained scan to manual/ad hoc history"
        )
        append_scan_audit_on_connection(
            db,
            run_id=run_id,
            event="network_attribution_changed",
            actor=signed_in_actor,
            details=(
                f"Historical context revision {manifest['metadata_revision']}. {details}"
            ),
            changed_at=changed_at,
        )
    return with_queue_state(with_host_count(manifest), db_path)


def nmap_host_presence_counts(xml_path: Path) -> dict[str, int] | None:
    """Return reported, confirmed, and assumed host counts from Nmap XML."""
    if not xml_path.is_file():
        return None
    try:
        root = ET.parse(xml_path).getroot()
    except (ET.ParseError, OSError):
        return None
    return nmap_presence_counts(root)


def nmap_host_count(xml_path: Path) -> int | None:
    """Return the number of targets with direct response evidence."""
    counts = nmap_host_presence_counts(xml_path)
    return counts["confirmed"] if counts is not None else None


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
    merged_attributes = dict(roots[0].attrib)
    merged_attributes["nct_source"] = "protocol-phase-merge"
    merged_attributes["nct_phase_count"] = str(len(roots))
    merged = ET.Element("nmaprun", merged_attributes)
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
    xml_path = run_directory(manifest["run_id"], data_dir) / "scan.xml"
    if (
        manifest.get("host_count") is None
        or "nmap_reported_host_count" not in manifest
        or "nmap_assumed_host_count" not in manifest
    ):
        counts = nmap_host_presence_counts(xml_path)
        if counts is not None:
            manifest["host_count"] = counts["confirmed"]
            manifest["nmap_reported_host_count"] = counts["reported_up"]
            manifest["nmap_assumed_host_count"] = counts["assumed"]
    return manifest


def run_directory(run_id: str, data_dir: Path = DATA_DIR) -> Path:
    if not RUN_ID_RE.fullmatch(run_id):
        raise ValueError("Invalid scan run identifier")
    root = (data_dir / RUNS_DIR_NAME).resolve()
    candidate = (root / run_id).resolve()
    if candidate.parent != root:
        raise ValueError("Invalid scan run path")
    return candidate


PRECONTACT_RUN_FILES = frozenset({
    "targets.txt", "discovery-targets.txt", "no-strike.txt", "manifest.json",
})
PRECONTACT_TEMP_PREFIX = ".nct-precontact-"


def _write_text_atomic(path: Path, value: str) -> None:
    """Replace one small retained metadata file without following an old hard link."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=PRECONTACT_TEMP_PREFIX,
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def prepare_scan_run_directory(manifest: dict, data_dir: Path = DATA_DIR) -> Path:
    """Create or safely reuse only this run's known pre-contact planning folder."""
    run_id = str(manifest["run_id"])
    root = scan_data_root(data_dir)
    root.mkdir(parents=True, exist_ok=True)
    raw_path = root / run_id
    if raw_path.is_symlink():
        raise RuntimeError("The saved pre-contact scan folder is a symbolic link")
    run_dir = run_directory(run_id, data_dir)
    if not run_dir.exists():
        run_dir.mkdir()
        return run_dir
    if not run_dir.is_dir():
        raise RuntimeError("The saved pre-contact scan path is not a directory")
    if manifest.get("status") != "dispatching" or manifest.get("started_at"):
        raise RuntimeError("An existing scan folder cannot be reused after contact started")
    for child in run_dir.iterdir():
        if child.is_symlink() or not child.is_file():
            raise RuntimeError(
                "The saved pre-contact scan folder contains an unsafe path"
            )
        if child.name.startswith(PRECONTACT_TEMP_PREFIX):
            child.unlink()
            continue
        if child.name not in PRECONTACT_RUN_FILES:
            raise RuntimeError(
                f"The saved pre-contact scan folder contains unexpected output: {child.name}"
            )
    retained_manifest = run_dir / "manifest.json"
    if retained_manifest.is_file():
        try:
            retained = json.loads(retained_manifest.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RuntimeError(
                "The saved pre-contact scan manifest cannot be verified"
            ) from exc
        if (
            retained.get("run_id") != run_id
            or retained.get("started_at")
            or retained.get("status") not in {"queued", "dispatching"}
        ):
            raise RuntimeError(
                "The saved pre-contact scan manifest does not match reusable work"
            )
    return run_dir


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


class ScanProfileDependencyError(RuntimeError):
    def __init__(self, review: dict):
        self.review = review
        blocker_names = ", ".join(
            f"{item['name']} (v{item['profile_version']}, "
            f"{'active' if item['enabled'] else 'paused'})"
            for item in review["blocking_schedules"]
        )
        super().__init__(
            "This custom profile cannot be deleted until its saved schedules are changed or deleted: "
            + blocker_names
        )


def _scan_profile_delete_review_on_connection(
    db: sqlite3.Connection, profile_id: str
) -> dict:
    profile = _profile_record_on_connection(db, profile_id)
    if profile is None:
        raise KeyError("Scan profile not found")
    version_count = int(
        db.execute(
            "SELECT COUNT(*) FROM scan_profiles WHERE profile_id = ?", (profile_id,)
        ).fetchone()[0]
    )
    blockers = []
    for row in db.execute(
        """
        SELECT schedule_id, name, profile_version, definition_json
        FROM scan_schedules WHERE profile_id = ?
        ORDER BY lower(name), schedule_id
        """,
        (profile_id,),
    ).fetchall():
        try:
            definition = json.loads(row[3])
        except (TypeError, json.JSONDecodeError):
            definition = {}
        blockers.append(
            {
                "schedule_id": row[0],
                "name": row[1],
                "profile_version": int(row[2]),
                "enabled": bool(definition.get("enabled", True)),
            }
        )
    return {
        "profile_id": profile_id,
        "profile_name": profile["name"],
        "latest_version": int(profile["version"]),
        "version_count": version_count,
        "built_in": bool(profile["built_in"]),
        "deletable": not profile["built_in"] and not blockers,
        "blocking_schedules": blockers,
        "retained_history_preserved": True,
    }


def scan_profile_delete_review(
    profile_id: str, db_path: Path = DB_PATH
) -> dict:
    init_poc_storage(db_path)
    with connect_database(db_path) as db:
        return _scan_profile_delete_review_on_connection(db, profile_id)


def delete_scan_profile(
    profile_id: str, confirmation: str, db_path: Path = DB_PATH
) -> dict:
    init_poc_storage(db_path)
    with connect_database(db_path) as db:
        db.execute("BEGIN IMMEDIATE")
        review = _scan_profile_delete_review_on_connection(db, profile_id)
        if review["built_in"]:
            raise PermissionError("Built-in profiles are protected and cannot be deleted")
        if review["blocking_schedules"]:
            raise ScanProfileDependencyError(review)
        if not consume_delete_challenge("profile", profile_id, confirmation):
            raise PermissionError("The confirmation string is invalid or expired")
        removed = db.execute(
            "DELETE FROM scan_profiles WHERE profile_id = ?", (profile_id,)
        ).rowcount
        return {
            "deleted": True,
            "profile_id": profile_id,
            "profile_name": review["profile_name"],
            "versions_removed": removed,
            "retained_history_preserved": True,
        }


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
    if list_schedule_occurrences(db_path, schedule_id, limit=1):
        raise RuntimeError(
            "This schedule has retained occurrence history and cannot be deleted. Pause future occurrences instead."
        )
    if not consume_delete_challenge("schedule", schedule_id, confirmation):
        raise PermissionError("The confirmation string is invalid or expired")
    with connect_database(db_path) as db:
        db.execute("DELETE FROM scan_schedules WHERE schedule_id = ?", (schedule_id,))
    return {"deleted": True, "schedule_id": schedule_id}


def scan_data_root(data_dir: Path = DATA_DIR) -> Path:
    root = (data_dir / RUNS_DIR_NAME).resolve()
    if root.parent != data_dir.resolve():
        raise ValueError("Invalid scan data root")
    return root


@guarded_evidence_mutation(
    lambda *args, **kwargs: kwargs.get("db_path", args[2] if len(args) > 2 else DB_PATH)
)
def delete_scan_data(run_id: str, confirmation: str, db_path: Path = DB_PATH,
                     data_dir: Path = DATA_DIR) -> dict:
    if get_scan_run_plan(run_id, db_path) is None:
        raise KeyError("Scan run not found")
    with ACTIVE_RUNS_LOCK:
        if run_id in ACTIVE_RUNS:
            raise RuntimeError("Active scans must be cancelled before they can be deleted")
    if not consume_delete_challenge("scan", run_id, confirmation):
        raise PermissionError("The confirmation string is invalid or expired")
    try:
        with connect_database(db_path) as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("DELETE FROM scan_run_control WHERE run_id = ?", (run_id,))
            db.execute("DELETE FROM scan_runs WHERE run_id = ?", (run_id,))
    except sqlite3.IntegrityError as exc:
        raise RuntimeError(
            "This scan is retained by scope or processed evidence records and cannot be deleted"
        ) from exc
    run_dir = run_directory(run_id, data_dir)
    if run_dir.exists():
        shutil.rmtree(run_dir)
    return {"deleted": True, "run_id": run_id}


@guarded_evidence_mutation(
    lambda *args, **kwargs: kwargs.get("db_path", args[1] if len(args) > 1 else DB_PATH)
)
def delete_all_scan_data(confirmation: str, db_path: Path = DB_PATH,
                         data_dir: Path = DATA_DIR) -> dict:
    with ACTIVE_RUNS_LOCK:
        if ACTIVE_RUNS:
            raise RuntimeError("Active scans must be cancelled before all scan data can be deleted")
    if not consume_delete_challenge("all", None, confirmation):
        raise PermissionError("The confirmation string is invalid or expired")
    try:
        with connect_database(db_path) as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("DELETE FROM scan_run_control")
            db.execute("DELETE FROM scan_runs")
            try:
                db.execute("DELETE FROM imports")
            except sqlite3.OperationalError:
                pass
    except sqlite3.IntegrityError as exc:
        raise RuntimeError(
            "Some scans are retained by scope or processed evidence records; no scan data was deleted"
        ) from exc
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
    db = connect_database(db_path)
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
    _write_text_atomic(path, json.dumps(manifest, indent=2, sort_keys=True) + "\n")


def persist_scan_progress(
    manifest: dict,
    *,
    db_path: Path = DB_PATH,
    data_dir: Path = DATA_DIR,
    **changes,
) -> bool:
    """Immediately publish visible progress without rebuilding Scan History."""
    changed = update_scan_progress(
        manifest["progress"], updated_at=utc_now(), **changes
    )
    if changed:
        update_scan_progress_manifest(manifest, db_path)
        write_manifest_file(manifest, data_dir)
    return changed


def read_nmap_progress(
    manifest: dict,
    output_path: Path,
    *,
    phase: str = "nmap",
) -> bool:
    """Update in-memory Nmap progress without publishing or touching history."""
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
    return update_scan_progress(
        manifest["progress"], phase=phase, updated_at=utc_now(), **status
    )


def refresh_nmap_progress(
    manifest: dict,
    output_path: Path,
    *,
    phase: str = "nmap",
    db_path: Path = DB_PATH,
    data_dir: Path = DATA_DIR,
) -> bool:
    """Read and immediately publish the newest Nmap terminal status."""
    changed = read_nmap_progress(manifest, output_path, phase=phase)
    if changed:
        update_scan_progress_manifest(manifest, db_path)
        write_manifest_file(manifest, data_dir)
    return changed


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


def collect_artifacts(
    manifest: dict, data_dir: Path = DATA_DIR, *, write_file: bool = True
) -> None:
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
    if write_file:
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


@guarded_evidence_mutation(lambda *args, **kwargs: kwargs.get("db_path", DB_PATH))
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
    if not isinstance(manifest.get("execution_claim"), dict):
        claimed = claim_next_queued_scan(db_path)
        if claimed is None or claimed.get("run_id") != run_id:
            return
        manifest = claimed
    execution_claim = manifest["execution_claim"]
    scheduled_claim = manifest.get("work_claim")
    last_fence_renewal = time.monotonic()

    def renew_execution_fences(*, force: bool = False) -> None:
        nonlocal execution_claim, scheduled_claim, last_fence_renewal
        now = time.monotonic()
        if not force and now - last_fence_renewal < 10:
            return
        execution_claim = renew_work_lease(
            db_path, execution_claim, lease_seconds=30
        ).as_claim()
        manifest["execution_claim"] = execution_claim
        if isinstance(scheduled_claim, dict):
            renewed = renew_work_lease(
                db_path, scheduled_claim, lease_seconds=30
            ).as_claim()
            scheduled_claim = {
                **renewed,
                "occurrence_id": scheduled_claim["occurrence_id"],
                "chunk_number": scheduled_claim["chunk_number"],
            }
            manifest["work_claim"] = scheduled_claim
        last_fence_renewal = now

    run_dir = prepare_scan_run_directory(manifest, data_dir)
    _write_text_atomic(
        run_dir / "targets.txt", "\n".join(manifest["targets"]) + "\n"
    )
    if manifest.get("discovery_mode") == "fping":
        discovery_targets = expanded_discovery_targets(
            manifest["targets"], manifest.get("no_strike") or []
        )
        _write_text_atomic(
            run_dir / "discovery-targets.txt",
            "\n".join(discovery_targets) + ("\n" if discovery_targets else ""),
        )
    _write_text_atomic(
        run_dir / "no-strike.txt",
        "\n".join(manifest.get("no_strike") or [])
        + ("\n" if manifest.get("no_strike") else ""),
    )
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
            renew_execution_fences(force=True)
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
            last_progress_publish = time.monotonic()
            progress_dirty = False
            while True:
                renew_execution_fences()
                code = process.poll()
                if code is not None:
                    if track_nmap:
                        read_nmap_progress(manifest, stdout_path, phase=phase)
                    return ("completed" if code in allowed_exit_codes else "failed", code)
                if control.cancel_event.is_set() or scan_cancellation_requested(
                    run_id, db_path
                ):
                    control.cancel_event.set()
                    terminate_process(process)
                    return "cancelled", process.poll()
                if time.monotonic() >= deadline:
                    terminate_process(process)
                    return "timed_out", process.poll()
                now = time.monotonic()
                if now - last_progress_check >= 1:
                    if track_nmap:
                        progress_dirty = (
                            read_nmap_progress(manifest, stdout_path, phase=phase)
                            or progress_dirty
                        )
                    progress_dirty = update_scan_progress(
                        manifest["progress"],
                        phase=phase,
                        elapsed_seconds=max(0, int(now - started)),
                        deadline_remaining_seconds=max(0, int(deadline - now)),
                        updated_at=utc_now(),
                    ) or progress_dirty
                    if (
                        progress_dirty
                        and now - last_progress_publish
                        >= SCAN_PROGRESS_PUBLISH_INTERVAL_SECONDS
                    ):
                        try:
                            update_scan_progress_manifest(manifest, db_path)
                            write_manifest_file(manifest, data_dir)
                        except sqlite3.OperationalError as exc:
                            if not is_transient_sqlite_contention(exc):
                                raise
                            # Retain the newest in-memory progress and retry on the next
                            # polling interval. Cancellation and ownership live in
                            # separate durable rows and are never inferred from progress.
                            pass
                        else:
                            progress_dirty = False
                            last_progress_publish = now
                    last_progress_check = now
                sleep_fn(0.2)

    # Everything above this point is retained local planning only.  Keep the
    # contact transition outside the execution try/finally so a local failure
    # before the atomic publication reaches the worker wrapper and can retain
    # the same run for its one bounded, fenced retry.
    try:
        certify_scan_contact_phase(
            manifest, "queue_start", db_path=db_path, data_dir=data_dir
        )
    except CollectionSafetySetupIncomplete:
        # Publication performs the durable, fenced transition to a visible
        # Mission Environment block while preserving the admitted review.
        if publish_scan_contact_starting(manifest, db_path=db_path):
            raise RuntimeError(
                "Mission Environment certification changed but contact was not blocked"
            )
        write_manifest_file(manifest, data_dir)
        with ACTIVE_RUNS_LOCK:
            ACTIVE_RUNS.pop(run_id, None)
        dispatch_next_queued_run(db_path=db_path, data_dir=data_dir)
        return
    except NoScannableTargetsError as exc:
        if requeue_scan_after_precontact_failure(
            manifest,
            reason=str(exc),
            db_path=db_path,
            retry_if_clear=False,
        ):
            write_manifest_file(manifest, data_dir)
        else:
            manifest["status"] = "stopped_no_targets"
            manifest["error"] = str(exc)
            manifest["completed_at"] = utc_now()
            manifest["success"] = False
            update_scan_progress(
                manifest["progress"],
                phase="stopped_no_targets",
                updated_at=manifest["completed_at"],
            )
            if isinstance(scheduled_claim, dict):
                with connect_database(db_path) as db:
                    db.execute("BEGIN IMMEDIATE")
                    _assert_manifest_fences_on_connection(db, manifest)
                    publish_chunk_terminal_on_connection(
                        db,
                        occurrence_id=str(scheduled_claim["occurrence_id"]),
                        chunk_number=int(scheduled_claim["chunk_number"]),
                        terminal_state="cancelled",
                        reason=str(exc),
                        lease=scheduled_claim,
                        contact_started=False,
                    )
                    execution_claim = manifest["execution_claim"]
                    changed = db.execute(
                        """UPDATE scan_runs SET status = ?, manifest_json = ?
                             WHERE run_id = ? AND status = 'dispatching'
                               AND json_extract(manifest_json, '$.execution_claim.lease_id') = ?""",
                        (
                            manifest["status"], json.dumps(manifest, sort_keys=True),
                            manifest["run_id"], str(execution_claim["lease_id"]),
                        ),
                    ).rowcount
                    if changed != 1:
                        raise WorkLeaseLost(
                            "This scan worker can no longer stop the excluded run"
                        )
                    sync_scan_history_manifest(db, manifest)
                    release_work_lease_on_connection(
                        db, execution_claim,
                        detail="Stopped before contact because no targets remain",
                    )
            else:
                publish_scan_terminal(manifest, db_path=db_path)
            write_manifest_file(manifest, data_dir)
        with ACTIVE_RUNS_LOCK:
            ACTIVE_RUNS.pop(run_id, None)
        dispatch_next_queued_run(db_path=db_path, data_dir=data_dir)
        return
    if not publish_scan_contact_starting(manifest, db_path=db_path):
        write_manifest_file(manifest, data_dir)
        with ACTIVE_RUNS_LOCK:
            ACTIVE_RUNS.pop(run_id, None)
        dispatch_next_queued_run(db_path=db_path, data_dir=data_dir)
        return

    try:
        persist_scan_progress(
            manifest, phase="discovery", db_path=db_path, data_dir=data_dir
        )
        capture_error_path = run_dir / "capture-stderr.txt"
        with capture_error_path.open("wb") as capture_error_handle:
            def start_capture(label: str = "the scan") -> None:
                if not manifest["capture_requested"]:
                    return
                renew_execution_fences(force=True)
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
                certify_scan_contact_phase(
                    manifest, "fping_discovery", db_path=db_path, data_dir=data_dir
                )
                fping_start_error = ""
                try:
                    discovery_status, discovery_exit = watch_process(
                        manifest["discovery_command_argv"],
                        run_dir / "fping-alive.txt",
                        run_dir / "fping-stderr.txt",
                        phase="discovery", process_attr="discovery_process",
                        allowed_exit_codes={0, 1}, track_nmap=False,
                    )
                except OSError as exc:
                    discovery_status, discovery_exit = "failed", None
                    fping_start_error = f"{type(exc).__name__}: {exc}"
                    (run_dir / "fping-stderr.txt").write_text(
                        fping_start_error + "\n", encoding="utf-8"
                    )
                exit_code = discovery_exit
                if discovery_status in {"cancelled", "timed_out"}:
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
                fping_failed = discovery_status == "failed"
                if fping_failed:
                    retained_error = (run_dir / "fping-stderr.txt").read_text(
                        encoding="utf-8", errors="replace"
                    ).strip()
                    manifest["discovery_error"] = (
                        retained_error[-1000:]
                        or fping_start_error
                        or "FPING ended unsuccessfully without error text."
                    )
                if run_phases and (fping_failed or not alive_hosts):
                    if fping_failed:
                        failure_status = (
                            f"exit status {discovery_exit}"
                            if discovery_exit is not None
                            else "a startup error"
                        )
                        fallback_reason = (
                            f"FPING failed with {failure_status}, so host discovery is incomplete. "
                            "No full-target Nmap fallback will start until an operator or mission "
                            "partner explicitly authorizes it."
                        )
                        fallback_trigger = "fping_failed"
                    else:
                        fallback_reason = (
                            "FPING completed but found no responsive hosts. No full-target Nmap "
                            "fallback will start until an operator or mission partner explicitly "
                            "authorizes it."
                        )
                        fallback_trigger = "no_responsive_hosts"
                    manifest["fallback_reason"] = fallback_reason
                    manifest["fallback_trigger"] = fallback_trigger
                    terminate_process(control.capture_process)
                    control.capture_process = None
                    fallback_phases = build_execution_phases(
                        manifest["interface"], manifest["profile_settings"],
                        include_no_strike=bool(manifest.get("no_strike")),
                        target_file="targets.txt",
                        pre_discovered=False,
                    )
                    manifest["fallback_execution_phases"] = fallback_phases
                    fallback_argv = list(fallback_phases[0]["command_argv"])
                    manifest["fallback_command_argv"] = fallback_argv
                    manifest["exact_fallback_command"] = shlex.join(fallback_argv)
                    manifest["fallback_command_note"] = (
                        "Review every protocol command below before approval."
                        if len(fallback_phases) > 1
                        else "Review the full-target command below before approval."
                    )
                    if manifest.get("fallback_policy") == "stop_without_nmap":
                        manifest.update({
                            "status": "completed_without_nmap",
                            "fallback_approval_required": False,
                            "fallback_decision": "policy_stop",
                            "fallback_decided_at": utc_now(),
                            "discovery_note": fallback_reason + (
                                " The pinned scheduled-scan policy finished without starting "
                                "the full Nmap fallback."
                            ),
                        })
                        exit_code, run_phases = 0, False
                    else:
                        manifest["status"] = "awaiting_fallback_approval"
                        manifest["fallback_approval_required"] = True
                        manifest["discovery_note"] = fallback_reason
                        collect_artifacts(manifest, data_dir)
                        persist_scan_progress(
                            manifest, phase="awaiting_approval",
                            db_path=db_path, data_dir=data_dir,
                        )
                        while not control.fallback_decision_event.is_set():
                            if control.cancel_event.is_set() or scan_cancellation_requested(
                                run_id, db_path
                            ):
                                control.cancel_event.set()
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
                                certify_scan_contact_phase(
                                    manifest,
                                    "approved_fallback",
                                    db_path=db_path,
                                    data_dir=data_dir,
                                )
                                apply_fping_fallback(manifest)
                                manifest["status"] = "running"
                                manifest["fallback_approval_required"] = False
                                manifest["discovery_note"] = fallback_reason + (
                                    f" Full Nmap fallback approved by {control.fallback_decided_by}: "
                                    f"{control.fallback_authorization_note}"
                                )
                                started = time.monotonic()
                                deadline = started + int(manifest["timeout_seconds"])
                                start_capture("the approved fallback")
                            else:
                                manifest["status"] = "completed_without_nmap"
                                manifest["fallback_approval_required"] = False
                                manifest["discovery_note"] = fallback_reason + (
                                    f" {control.fallback_decided_by} chose to finish without "
                                    f"Nmap fallback: {control.fallback_authorization_note}"
                                )
                                exit_code, run_phases = 0, False
            else:
                certify_scan_contact_phase(
                    manifest, "nmap_discovery", db_path=db_path, data_dir=data_dir
                )
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
                    certify_scan_contact_phase(
                        manifest,
                        f"{phase_name}_scan",
                        db_path=db_path,
                        data_dir=data_dir,
                    )
                    phase["status"] = "running"
                    phase["started_at"] = utc_now()
                    persist_scan_progress(
                        manifest, phase=phase_name, hosts_completed=0,
                        hosts_total=hosts_total, hosts_up=0,
                        reset_phase_metrics=True,
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
                        manifest, phase="merge", reset_phase_metrics=True,
                        db_path=db_path, data_dir=data_dir
                    )
                    merge_nmap_xml(successful_xml, run_dir / "scan.xml")
                    persist_scan_progress(
                        manifest, phase="analysis", reset_phase_metrics=True,
                        db_path=db_path, data_dir=data_dir
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
    except NoScannableTargetsError as exc:
        manifest["status"] = "stopped_no_targets"
        manifest["error"] = str(exc)
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
        presence_counts = nmap_host_presence_counts(run_dir / "scan.xml")
        manifest["host_count"] = (
            presence_counts["confirmed"] if presence_counts is not None else None
        )
        manifest["nmap_reported_host_count"] = (
            presence_counts["reported_up"] if presence_counts is not None else None
        )
        manifest["nmap_assumed_host_count"] = (
            presence_counts["assumed"] if presence_counts is not None else 0
        )
        if presence_counts and presence_counts["assumed"]:
            quality_note = (
                f"Nmap -Pn assumed {presence_counts['assumed']} target"
                f"{'s' if presence_counts['assumed'] != 1 else ''} up; "
                f"{presence_counts['confirmed']} returned direct response evidence. "
                "Assumed targets are not counted as confirmed live hosts."
            )
            manifest["execution_note"] = " ".join(
                value for value in (manifest.get("execution_note"), quality_note) if value
            )
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
        scheduled_claim = manifest.get("work_claim")
        register_finalized_files(
            db_path,
            run_dir,
            manifest,
            "nmap_scan",
            [item[0] for item in ARTIFACT_FILES.values()],
            transaction_guard=(
                (lambda db: _assert_manifest_fences_on_connection(db, manifest))
            ),
        )
        collect_artifacts(manifest, data_dir, write_file=False)
        if isinstance(scheduled_claim, dict):
            publish_scheduled_scan_terminal(
                manifest, scheduled_claim, db_path=db_path
            )
        else:
            publish_scan_terminal(manifest, db_path=db_path)
        write_manifest_file(manifest, data_dir)
        start_derived_job_worker(db_path, data_dir)
        if not isinstance(scheduled_claim, dict):
            append_scan_audit(
                db_path,
                run_id=run_id,
                event=manifest["status"],
                actor=manifest.get("owner") or manifest.get("executed_by") or "system",
                details=manifest.get("error") or manifest.get("execution_note") or "Scan execution finished",
                changed_at=manifest["completed_at"],
            )
        with ACTIVE_RUNS_LOCK:
            ACTIVE_RUNS.pop(run_id, None)
        dispatch_next_queued_run(db_path=db_path, data_dir=data_dir)


@guarded_evidence_mutation(lambda *args, **kwargs: kwargs.get("db_path", DB_PATH))
def launch_scan_run(
    request: ScanRunRequest,
    *,
    db_path: Path = DB_PATH,
    data_dir: Path = DATA_DIR,
    interfaces: set[str] | None = None,
    reserved_run_id: str | None = None,
    scheduled_chunk_claim: tuple[str, int, WorkLease] | None = None,
) -> dict:
    """Persist one scan in the shared FIFO queue and dispatch it when capacity is free."""
    manifest = prepare_scan_run(
        request,
        db_path,
        interfaces,
        reserved_run_id=reserved_run_id,
        scheduled_chunk_claim=scheduled_chunk_claim,
    )
    dispatch_next_queued_run(db_path=db_path, data_dir=data_dir)
    return get_scan_run_plan(manifest["run_id"], db_path) or with_queue_state(manifest, db_path)


def _scan_worker_entry(
    run_id: str,
    control: RunControl,
    *,
    db_path: Path,
    data_dir: Path,
) -> None:
    """Keep an unexpected worker error from wedging the shared queue."""
    try:
        execute_scan_run(run_id, control, db_path=db_path, data_dir=data_dir)
    except EvidenceMaintenanceBlocked:
        manifest = get_scan_run_plan(run_id, db_path)
        claim = (manifest or {}).get("work_claim")
        if manifest is not None and isinstance(claim, dict):
            manifest["status"] = "failed"
            manifest["success"] = False
            manifest["completed_at"] = utc_now()
            manifest["error"] = "Evidence maintenance blocked scheduled scan startup"
            publish_scheduled_scan_terminal(manifest, claim, db_path=db_path)
        with ACTIVE_RUNS_LOCK:
            ACTIVE_RUNS.pop(run_id, None)
        return
    except Exception as exc:
        manifest = get_scan_run_plan(run_id, db_path)
        if manifest is not None and requeue_scan_after_precontact_failure(
            manifest,
            reason=f"{type(exc).__name__}: {exc}",
            db_path=db_path,
        ):
            with ACTIVE_RUNS_LOCK:
                ACTIVE_RUNS.pop(run_id, None)
            dispatch_next_queued_run(db_path=db_path, data_dir=data_dir)
            return
        if manifest is not None and manifest.get("status") in {
            "dispatching",
            "queued",
            "running",
            "awaiting_fallback_approval",
        }:
            manifest["status"] = "failed"
            manifest["success"] = False
            manifest["completed_at"] = utc_now()
            manifest["error"] = f"{type(exc).__name__}: {exc}"
            if isinstance(manifest.get("progress"), dict):
                update_scan_progress(
                    manifest["progress"],
                    phase="failed",
                    updated_at=manifest["completed_at"],
                )
            claim = manifest.get("work_claim")
            if isinstance(claim, dict):
                publish_scheduled_scan_terminal(manifest, claim, db_path=db_path)
            else:
                publish_scan_terminal(manifest, db_path=db_path)
                append_scan_audit(
                    db_path,
                    run_id=run_id,
                    event="failed",
                    actor="system",
                    details=manifest["error"],
                    changed_at=manifest["completed_at"],
                )
        with ACTIVE_RUNS_LOCK:
            ACTIVE_RUNS.pop(run_id, None)
        dispatch_next_queued_run(db_path=db_path, data_dir=data_dir)
    finally:
        with ACTIVE_RUNS_LOCK:
            ACTIVE_RUN_THREADS.pop(run_id, None)


def claim_next_queued_scan(db_path: Path = DB_PATH) -> dict | None:
    """Atomically reserve shared scan capacity and one FIFO run across processes."""
    init_work_coordination_storage(db_path)
    owner_id = f"scan-worker:{uuid.uuid4().hex}"
    with connect_database(db_path) as db:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute(
            """SELECT manifest_json FROM scan_runs
                 WHERE status = 'queued' ORDER BY rowid LIMIT 1"""
        ).fetchone()
        if row is None:
            return None
        manifest = json.loads(row[0])
        scheduled_claim = manifest.get("work_claim")
        if isinstance(scheduled_claim, dict):
            try:
                assert_work_lease_on_connection(db, scheduled_claim)
            except WorkLeaseConflict:
                return None
            chunk = db.execute(
                """SELECT state, contact_phase, scan_run_id
                     FROM scan_schedule_chunks
                    WHERE occurrence_id = ? AND chunk_number = ?""",
                (
                    str(scheduled_claim.get("occurrence_id") or ""),
                    int(scheduled_claim.get("chunk_number") or 0),
                ),
            ).fetchone()
            if (
                chunk is None or chunk[0] != "preparing"
                or chunk[1] not in {"not_started", "preparing"}
                or chunk[2] != manifest["run_id"]
            ):
                return None
        try:
            execution = acquire_work_lease_on_connection(
                db,
                lease_key=SCAN_CAPACITY_LEASE_KEY,
                work_kind="scan_execution",
                work_id=manifest["run_id"],
                owner_id=owner_id,
                lease_seconds=30,
                expired_policy="recovery_required",
            )
        except WorkLeaseConflict:
            return None
        manifest["execution_claim"] = execution.as_claim()
        manifest["status"] = "dispatching"
        manifest["dispatching_at"] = utc_now()
        changed = db.execute(
            """UPDATE scan_runs SET status = 'dispatching', manifest_json = ?
                 WHERE run_id = ? AND status = 'queued'""",
            (json.dumps(manifest, sort_keys=True), manifest["run_id"]),
        ).rowcount
        if changed != 1:
            raise WorkLeaseConflict("The queued scan changed before dispatch")
        sync_scan_history_manifest(db, manifest)
        return manifest


def dispatch_next_queued_run(
    *, db_path: Path = DB_PATH, data_dir: Path = DATA_DIR
) -> dict | None:
    """Start the oldest queued run if the analyzer has free scan capacity."""
    if scan_contact_paused(data_dir):
        return None
    if evidence_mutations_blocked(db_path):
        return None
    with ACTIVE_RUNS_LOCK:
        if _SCAN_WORKER_SHUTDOWN.is_set():
            return None
        if len(ACTIVE_RUNS) >= MAX_ACTIVE_RUNS:
            return None
        manifest = claim_next_queued_scan(db_path)
        if manifest is None:
            return None
        control = RunControl()
        worker = _new_scan_worker_thread(
            manifest["run_id"], control, db_path=db_path, data_dir=data_dir,
        )
        ACTIVE_RUNS[manifest["run_id"]] = control
        ACTIVE_RUN_THREADS[manifest["run_id"]] = worker
        try:
            worker.start()
        except BaseException as exc:
            ACTIVE_RUNS.pop(manifest["run_id"], None)
            ACTIVE_RUN_THREADS.pop(manifest["run_id"], None)
            start_error = exc
        else:
            start_error = None
    if start_error is not None:
        manifest["status"] = "failed"
        manifest["error"] = "The scan worker could not be started"
        manifest["completed_at"] = utc_now()
        if isinstance(manifest.get("work_claim"), dict):
            publish_scheduled_scan_terminal(
                manifest, manifest["work_claim"], db_path=db_path
            )
        else:
            publish_scan_terminal(manifest, db_path=db_path)
        append_scan_audit(
            db_path,
            run_id=manifest["run_id"],
            event="failed",
            actor="system",
            details=manifest["error"],
            changed_at=manifest["completed_at"],
        )
        dispatch_next_queued_run(db_path=db_path, data_dir=data_dir)
        raise start_error
    return with_queue_state(manifest, db_path)


def _new_scan_worker_thread(
    run_id: str,
    control: RunControl,
    *,
    db_path: Path,
    data_dir: Path,
) -> threading.Thread:
    return threading.Thread(
        target=_scan_worker_entry,
        args=(run_id, control),
        kwargs={"db_path": db_path, "data_dir": data_dir},
        daemon=True,
        name=f"scan-{run_id[:8]}",
    )


def schedule_target_chunks(
    schedule: dict, db_path: Path = DB_PATH, *, global_no_strike: list[str] | None = None
) -> list[list[str]]:
    if global_no_strike is None:
        no_strike, _ = effective_no_strike(schedule.get("no_strike") or [], db_path)
    else:
        combined = [*global_no_strike, *(schedule.get("no_strike") or [])]
        no_strike = normalize_ipv4_networks(combined, "no-strike") if combined else []
    chunking_enabled = bool(
        schedule.get("chunking_enabled", "chunk_size" in schedule)
    )
    if not chunking_enabled:
        compact_targets = compact_discovery_targets(schedule["targets"], no_strike)
        return [compact_targets] if compact_targets else []
    addresses = expanded_discovery_targets(
        schedule["targets"], no_strike
    )
    size = int(schedule.get("chunk_size") or 256)
    return [addresses[index:index + size] for index in range(0, len(addresses), size)]


def _schedule_due_window(schedule: dict, moment: datetime) -> dict:
    """Coalesce every overdue cadence point into one latest occurrence."""
    first_due = _as_utc(schedule["next_run_at"])
    moment = _as_utc(moment)
    if first_due > moment:
        raise ValueError("This schedule is not due yet")
    cadence = schedule["cadence"]
    if cadence == "once":
        latest_due = first_due
        skipped = 0
        next_due = None
    elif cadence == "monthly":
        anchor = _as_utc(schedule.get("first_run_at") or first_due)
        distance = max(
            0, (moment.year - first_due.year) * 12 + moment.month - first_due.month
        )
        anchor_distance = (
            (first_due.year - anchor.year) * 12 + first_due.month - anchor.month
        )
        latest_due = _month_from_anchor(anchor, anchor_distance + distance, anchor.day)
        if latest_due > moment:
            distance -= 1
            latest_due = _month_from_anchor(
                anchor, anchor_distance + max(0, distance), anchor.day
            )
        skipped = max(0, distance)
        next_due = _month_from_anchor(
            anchor, anchor_distance + max(0, distance) + 1, anchor.day
        )
    else:
        delta = {
            "interval": timedelta(minutes=int(schedule.get("interval_minutes") or 60)),
            "custom_hours": timedelta(hours=int(schedule.get("cadence_hours") or 2)),
            "hourly": timedelta(hours=1),
            "daily": timedelta(days=1),
            "weekly": timedelta(weeks=1),
        }[cadence]
        skipped = int((moment - first_due) // delta)
        latest_due = first_due + delta * skipped
        next_due = latest_due + delta
    return {
        "first_missed_due_at": first_due.isoformat(),
        "latest_missed_due_at": latest_due.isoformat(),
        "skipped_due_count": skipped,
        "due_at": latest_due.isoformat(),
        "next_due_at": next_due.isoformat() if next_due else None,
    }


def prepare_schedule_occurrence(
    schedule_id: str,
    *,
    advance_schedule: bool,
    trigger_key: str,
    actor: str,
    now: datetime | None = None,
    db_path: Path = DB_PATH,
) -> dict:
    schedule = get_scan_schedule(schedule_id, db_path)
    if schedule is None:
        raise KeyError("Scan schedule not found")
    scope_context = get_schedule_scope_context(
        db_path, schedule_id, require_active=True
    )
    with connect_database(db_path) as mission_db:
        mission_db.execute("BEGIN")
        reviewed_context = resolve_reviewed_scope_context(
            mission_db,
            saved_network_ids=list(schedule.get("saved_network_ids") or []),
            manual_targets=list(schedule.get("manual_targets") or []),
            reviewed_associations=list(
                schedule.get("reviewed_scope_associations") or []
            ),
        )
        _setup, scope_context = bind_collection_scope_context_on_connection(
            mission_db,
            context=scope_context or reviewed_context,
            saved_network_ids=list(schedule.get("saved_network_ids") or []),
        )
        mission_review = resolve_collection_mission_review(
            mission_db,
            saved_network_ids=list(schedule.get("saved_network_ids") or []),
            manual_targets=list(schedule.get("manual_targets") or []),
            reviewed_scopes=list(schedule.get("reviewed_mission_scopes") or []),
            collection_scope_id=(scope_context or {}).get("scope_id"),
        )
    moment = _as_utc(now or datetime.now(timezone.utc))
    if advance_schedule:
        if not schedule.get("enabled"):
            raise RuntimeError("This schedule is paused")
        if not schedule.get("next_run_at"):
            raise RuntimeError("This schedule has no future due time")
        due = _schedule_due_window(schedule, moment)
        trigger_kind = "scheduled"
    else:
        due = {
            "first_missed_due_at": None,
            "latest_missed_due_at": None,
            "skipped_due_count": 0,
            "due_at": moment.isoformat(),
            "next_due_at": schedule.get("next_run_at"),
        }
        trigger_kind = "manual"
    global_no_strike = get_global_no_strike(db_path)
    chunks = schedule_target_chunks(
        schedule, db_path, global_no_strike=global_no_strike["entries"]
    )
    if not chunks:
        raise ValueError("No addresses remain after no-strike filtering")
    frozen = {
        "resolved_targets": list(schedule.get("targets") or []),
        "manual_targets": list(schedule.get("manual_targets") or []),
        "saved_networks": list(schedule.get("saved_networks") or []),
        "network_scope_context": scope_context,
        "collection_safety_setup": _setup["review"],
        "mission_environment_review": mission_review,
        "profile": {
            "profile_id": schedule["profile_id"],
            "profile_version": schedule["profile_version"],
            "profile_name": schedule.get("profile_name"),
            "settings": schedule.get("profile_snapshot") or {},
        },
        "schedule_no_strike": list(schedule.get("no_strike") or []),
        "global_no_strike": global_no_strike,
        "contact_policy": {
            "interface": schedule["interface"],
            "timeout_seconds": int(schedule.get("timeout_seconds") or 2700),
            "fallback_policy": schedule.get("fallback_policy", "require_approval"),
            "capture": True,
            "chunking_enabled": bool(schedule.get("chunking_enabled")),
            "chunk_size": int(schedule.get("chunk_size") or 256),
            "chunk_delay_seconds": int(schedule.get("chunk_delay_seconds") or 0),
        },
        "authorization": {
            "created_by": schedule["created_by"],
            "executed_by": actor,
            "reason": schedule["reason"],
            "originating_host": schedule["originating_host"],
        },
    }
    frozen_scope_digest = content_digest(scope_context)
    frozen_mission_digest = content_digest({
        key: value for key, value in mission_review.items() if key != "certified_at"
    })

    def recheck_external_inputs(connection) -> None:
        require_collection_safety_ready_on_connection(
            connection,
            expected_scope_id=(scope_context or {}).get("scope_id"),
        )
        live_global = _global_no_strike_state_in_transaction(connection)
        if int(live_global["revision"]) != int(global_no_strike["revision"]):
            raise RuntimeError(
                "The Global No-Strike list changed while this occurrence was prepared"
            )
        live_scope = resolve_schedule_scope_context_in_transaction(
            connection, schedule_id
        )
        if content_digest(live_scope) != frozen_scope_digest:
            raise RuntimeError(
                "The Network Scope context changed while this occurrence was prepared"
            )
        resolve_reviewed_scope_context(
            connection,
            saved_network_ids=list(schedule.get("saved_network_ids") or []),
            manual_targets=list(schedule.get("manual_targets") or []),
            reviewed_associations=list(
                schedule.get("reviewed_scope_associations") or []
            ),
        )
        live_mission = resolve_collection_mission_review(
            connection,
            saved_network_ids=list(schedule.get("saved_network_ids") or []),
            manual_targets=list(schedule.get("manual_targets") or []),
            reviewed_scopes=list(schedule.get("reviewed_mission_scopes") or []),
            collection_scope_id=(scope_context or {}).get("scope_id"),
        )
        if content_digest({
            key: value for key, value in live_mission.items() if key != "certified_at"
        }) != frozen_mission_digest:
            raise RuntimeError(
                "The Mission Environment changed while this occurrence was prepared"
            )

    occurrence = prepare_occurrence(
        db_path,
        schedule=schedule,
        due_at=due["due_at"],
        trigger_kind=trigger_kind,
        trigger_key=trigger_key,
        actor=actor,
        frozen_contract=frozen,
        chunks=chunks,
        next_due_at=due["next_due_at"],
        first_missed_due_at=due["first_missed_due_at"],
        latest_missed_due_at=due["latest_missed_due_at"],
        skipped_due_count=due["skipped_due_count"],
        transaction_guard=recheck_external_inputs,
    )
    return {
        "schedule_id": schedule_id,
        "occurrence_id": occurrence.occurrence_id,
        "batch_id": occurrence.occurrence_id,
        "status": occurrence.state,
        "created": occurrence.created,
        "chunk_count": occurrence.chunk_count,
        "chunking_enabled": bool(
            schedule.get("chunking_enabled", "chunk_size" in schedule)
        ),
        "chunk_size": int(schedule.get("chunk_size") or 256),
        "chunk_delay_seconds": int(schedule.get("chunk_delay_seconds") or 0),
        "skipped_due_count": int(due["skipped_due_count"]),
    }


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
        # The manifest builder adds the current global list exactly once and
        # retains this schedule-specific list as its separate source.
        no_strike=schedule.get("no_strike") or [],
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


def _execute_durable_schedule_occurrence(
    schedule_id: str,
    occurrence_id: str,
    *,
    db_path: Path,
    data_dir: Path,
    sleep_fn: Callable[[float], None],
) -> None:
    successful_states = {"completed", "completed_without_nmap"}
    terminal_states = successful_states | {
        "failed", "cancelled", "timed_out", "stopped_no_targets", "interrupted"
    }
    occurrence = get_occurrence(db_path, occurrence_id)
    schedule = get_scan_schedule(schedule_id, db_path)
    if occurrence is None or schedule is None:
        return
    chunks = [item["targets"] for item in occurrence["chunks"]]
    total = len(chunks)
    batch_hosts_total = sum(target_address_count(chunk) for chunk in chunks)
    owner_id = f"schedule:{schedule_id}:{uuid.uuid4().hex}"
    occurrence_run_ids = [
        item["scan_run_id"] for item in occurrence["chunks"] if item.get("scan_run_id")
    ]
    schedule.update({
        "batch_status": "preparing",
        "active_batch_id": occurrence_id,
        "active_chunk_count": total,
        "last_occurrence_started_at": occurrence.get("started_at") or utc_now(),
        "last_occurrence_status": "preparing",
        "last_occurrence_batch_id": occurrence_id,
        "last_occurrence_run_ids": occurrence_run_ids,
        "last_dispatch_note": f"Preparing chunk 1 of {total}",
    })
    _store_scan_schedule(schedule, db_path)
    while True:
        claimed = claim_next_chunk(
            db_path, occurrence_id, owner_id=owner_id, lease_seconds=30
        )
        if claimed is None:
            break
        chunk, lease = claimed
        index = int(chunk["chunk_number"])
        targets = list(chunk["targets"])
        existing_run_id = chunk.get("scan_run_id")
        try:
            if existing_run_id:
                run = get_scan_run_plan(existing_run_id, db_path)
                if run is None:
                    raise RuntimeError("The scan bound to this schedule chunk is missing")
            else:
                reserved_run_id = uuid.uuid4().hex
                run = launch_scan_run(
                    _scheduled_request(
                        schedule,
                        targets,
                        batch_id=occurrence_id,
                        chunk_number=index,
                        chunk_count=total,
                        batch_hosts_total=batch_hosts_total,
                        batch_hosts_completed_before=sum(
                            target_address_count(item) for item in chunks[: index - 1]
                        ),
                        db_path=db_path,
                    ),
                    db_path=db_path,
                    data_dir=data_dir,
                    reserved_run_id=reserved_run_id,
                    scheduled_chunk_claim=(occurrence_id, index, lease),
                )
        except Exception as exc:
            abandon_chunk_after_worker_error(
                db_path,
                occurrence_id=occurrence_id,
                chunk_number=index,
                lease=lease,
                reason=f"{type(exc).__name__}: {exc}",
            )
            raise
        # The scan worker now owns contact and renews both execution fences.
        schedule = get_scan_schedule(schedule_id, db_path) or schedule
        schedule["batch_status"] = "active"
        schedule["active_chunk_number"] = index
        schedule["last_run_id"] = run["run_id"]
        schedule["last_run_at"] = utc_now()
        schedule["last_run_status"] = run["status"]
        schedule["run_count"] = int(schedule.get("run_count") or 0) + (
            0 if run["run_id"] in occurrence_run_ids else 1
        )
        if run["run_id"] not in occurrence_run_ids:
            occurrence_run_ids.append(run["run_id"])
        schedule["last_occurrence_run_ids"] = occurrence_run_ids
        schedule["last_occurrence_status"] = "active"
        schedule["last_dispatch_note"] = f"Scanning chunk {index} of {total}"
        _store_scan_schedule(schedule, db_path)
        last_renewal = time.monotonic()
        while True:
            current = get_scan_run_plan(run["run_id"], db_path)
            if current and current.get("status") in terminal_states:
                break
            if time.monotonic() - last_renewal >= 10:
                lease = renew_work_lease(db_path, lease, lease_seconds=30)
                last_renewal = time.monotonic()
            sleep_fn(1)
        schedule = get_scan_schedule(schedule_id, db_path) or schedule
        schedule["last_run_status"] = current["status"]
        durable = get_occurrence(db_path, occurrence_id)
        durable_chunk = next(
            (
                item for item in (durable or {}).get("chunks", [])
                if item["chunk_number"] == index
            ),
            None,
        )
        if current["status"] in successful_states:
            if not durable_chunk or durable_chunk["state"] != "complete":
                publish_chunk_terminal(
                    db_path,
                    occurrence_id=occurrence_id,
                    chunk_number=index,
                    terminal_state="complete",
                    reason=f"Scan {current['status']}",
                    lease=lease,
                )
            schedule["completed_chunk_count"] = index
            schedule["last_dispatch_note"] = f"Chunk {index} of {total} complete"
            _store_scan_schedule(schedule, db_path)
        else:
            if not durable_chunk or durable_chunk["state"] not in {
                "needs_attention", "cancelled"
            }:
                publish_chunk_terminal(
                    db_path,
                    occurrence_id=occurrence_id,
                    chunk_number=index,
                    terminal_state=(
                        "cancelled" if current["status"] == "cancelled"
                        else "needs_attention"
                    ),
                    reason=(
                        f"Chunk {index} ended {current['status']}; later chunks will not start"
                    ),
                    lease=lease,
                )
            cancelled = current["status"] == "cancelled"
            schedule["batch_status"] = "cancelled" if cancelled else "needs_attention"
            schedule["enabled"] = False
            schedule["last_occurrence_status"] = "cancelled" if cancelled else "needs_attention"
            schedule["last_occurrence_completed_at"] = utc_now()
            schedule["last_dispatch_note"] = (
                f"Chunk {index} cancelled; later chunks will not start"
                if cancelled
                else f"Chunk {index} ended {current['status']} — review before new contact"
            )
            _store_scan_schedule(schedule, db_path)
            return
        if index < total:
            delay = int(schedule.get("chunk_delay_seconds") or 0)
            schedule["next_chunk_at"] = (
                datetime.now(timezone.utc) + timedelta(seconds=delay)
            ).replace(microsecond=0).isoformat()
            _store_scan_schedule(schedule, db_path)
            if delay:
                sleep_fn(delay)
    final = get_occurrence(db_path, occurrence_id)
    schedule = get_scan_schedule(schedule_id, db_path) or schedule
    if final and final["state"] == "complete":
        schedule["batch_status"] = "complete"
        schedule["active_batch_id"] = None
        schedule["active_chunk_number"] = total
        schedule["completed_chunk_count"] = total
        schedule["resume_after_chunk"] = 0
        schedule["active_target_chunks"] = None
        schedule["next_chunk_at"] = None
        schedule["occurrence_count"] = int(schedule.get("occurrence_count") or 0) + 1
        schedule["last_occurrence_status"] = "complete"
        schedule["last_occurrence_completed_at"] = final.get("completed_at") or utc_now()
        schedule["last_dispatch_note"] = f"All {total} chunks complete"
        _store_scan_schedule(schedule, db_path)


@guarded_evidence_mutation(lambda *args, **kwargs: kwargs.get("db_path", DB_PATH))
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
    terminal_states = successful_states | {
        "failed", "cancelled", "timed_out", "stopped_no_targets"
    }
    try:
        if get_occurrence(db_path, batch_id) is not None:
            _execute_durable_schedule_occurrence(
                schedule_id,
                batch_id,
                db_path=db_path,
                data_dir=data_dir,
                sleep_fn=sleep_fn,
            )
            return
        schedule = get_scan_schedule(schedule_id, db_path)
        if schedule is None:
            return
        get_schedule_scope_context(db_path, schedule_id, require_active=True)
        chunks = schedule.get("active_target_chunks") or schedule_target_chunks(
            schedule, db_path
        )
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
        batch_hosts_total = sum(target_address_count(chunk) for chunk in chunks)
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
                                target_address_count(chunk)
                                for chunk in chunks[: index - 1]
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
        schedule["active_target_chunks"] = None
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
    except WorkLeaseConflict:
        # Another application process may have claimed this exact durable chunk
        # after this process discovered it. The durable owner remains authoritative;
        # a losing coordinator must not disable or relabel the schedule.
        return
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
            ACTIVE_SCHEDULE_THREADS.pop(schedule_id, None)


@guarded_evidence_mutation(lambda *args, **kwargs: kwargs.get("db_path", DB_PATH))
def queue_scan_schedule_batch(
    schedule_id: str,
    *,
    advance_schedule: bool,
    trigger_key: str | None = None,
    actor: str = "scheduler",
    now: datetime | None = None,
    db_path: Path = DB_PATH,
    data_dir: Path = DATA_DIR,
) -> dict:
    schedule = get_scan_schedule(schedule_id, db_path)
    if schedule is None:
        raise KeyError("Scan schedule not found")
    key = trigger_key or (
        "cadence" if advance_schedule else uuid.uuid4().hex
    )
    prepared = prepare_schedule_occurrence(
        schedule_id,
        advance_schedule=advance_schedule,
        trigger_key=key,
        actor=actor,
        now=now,
        db_path=db_path,
    )
    batch_id = prepared["occurrence_id"]
    _start_prepared_schedule_occurrence(
        schedule_id,
        batch_id,
        db_path=db_path,
        data_dir=data_dir,
    )
    return prepared


def _start_prepared_schedule_occurrence(
    schedule_id: str,
    occurrence_id: str,
    *,
    db_path: Path,
    data_dir: Path,
) -> bool:
    with ACTIVE_SCHEDULE_BATCHES_LOCK:
        if _SCHEDULE_WORKER_SHUTDOWN.is_set():
            raise RuntimeError("The scan scheduler is shutting down")
        if schedule_id in ACTIVE_SCHEDULE_BATCHES:
            return False
        if ACTIVE_SCHEDULE_BATCHES:
            raise RuntimeError("Another scheduled batch is already active")
        worker = _new_schedule_batch_thread(
            schedule_id,
            occurrence_id,
            # Cadence advanced atomically when the occurrence was created.
            advance_schedule=False,
            db_path=db_path,
            data_dir=data_dir,
        )
        ACTIVE_SCHEDULE_BATCHES.add(schedule_id)
        ACTIVE_SCHEDULE_THREADS[schedule_id] = worker
        try:
            worker.start()
        except Exception:
            ACTIVE_SCHEDULE_BATCHES.discard(schedule_id)
            ACTIVE_SCHEDULE_THREADS.pop(schedule_id, None)
            raise
    return True


def _new_schedule_batch_thread(
    schedule_id: str,
    batch_id: str,
    *,
    advance_schedule: bool,
    db_path: Path,
    data_dir: Path,
) -> threading.Thread:
    return threading.Thread(
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


def run_scan_schedule_now(
    schedule_id: str,
    *,
    request_id: str,
    requested_by: str,
    db_path: Path = DB_PATH,
) -> dict:
    return queue_scan_schedule_batch(
        schedule_id,
        advance_schedule=False,
        trigger_key=request_id,
        actor=requested_by,
        db_path=db_path,
    )


def record_schedule_conflict(
    schedule: dict,
    conflict_key: str,
    db_path: Path = DB_PATH,
) -> dict:
    """Record one distinct delayed occurrence without counting scheduler retries."""
    schedule = get_scan_schedule(str(schedule["schedule_id"]), db_path) or schedule
    if schedule.get("last_conflict_key") != conflict_key:
        schedule["conflict_count"] = int(schedule.get("conflict_count") or 0) + 1
        schedule["last_conflict_key"] = conflict_key
        schedule["last_conflict_at"] = utc_now()
        schedule["conflict_flagged"] = schedule["conflict_count"] > 3
    schedule["last_dispatch_note"] = "Waiting for the analyzer scanner"
    return _store_scan_schedule(schedule, db_path)


def recover_scan_execution_fence(db_path: Path = DB_PATH) -> dict | None:
    """Recover the one shared scan slot after the former application owner ended."""
    with connect_database(db_path) as db:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute(
            """SELECT work_id, fencing_epoch, lease_id, owner_id, state
                 FROM work_leases WHERE lease_key = ?""",
            (SCAN_CAPACITY_LEASE_KEY,),
        ).fetchone()
        if row is None or row[4] != "active":
            return None
        run_id, epoch, lease_id, owner_id, _state = row
        run_row = db.execute(
            "SELECT manifest_json FROM scan_runs WHERE run_id = ?", (run_id,)
        ).fetchone()
        if run_row is None:
            safe_pre_contact = False
            manifest = None
        else:
            manifest = json.loads(run_row[0])
            work_claim = manifest.get("work_claim")
            chunk = None
            if isinstance(work_claim, dict):
                chunk = db.execute(
                    """SELECT state, contact_phase FROM scan_schedule_chunks
                         WHERE occurrence_id = ? AND chunk_number = ?""",
                    (
                        str(work_claim.get("occurrence_id") or ""),
                        int(work_claim.get("chunk_number") or 0),
                    ),
                ).fetchone()
            safe_pre_contact = bool(
                not manifest.get("started_at")
                and (
                    not isinstance(work_claim, dict)
                    or (chunk and chunk[0] == "waiting" and chunk[1] == "not_started")
                )
            )
        now = utc_now()
        if safe_pre_contact and manifest is not None:
            manifest["status"] = "queued"
            manifest.pop("execution_claim", None)
            db.execute(
                """UPDATE work_leases
                      SET lease_id = NULL, owner_id = NULL, state = 'released',
                          expires_at = NULL, released_at = ?, renewed_at = ?,
                          recovery_reason = NULL
                    WHERE lease_key = ? AND fencing_epoch = ? AND state = 'active'""",
                (now, now, SCAN_CAPACITY_LEASE_KEY, int(epoch)),
            )
            event_kind = "released"
            detail = "Former application ended before network contact; queued scan retained"
        else:
            detail = "Former scan owner may have made network contact; manual review is required"
            db.execute(
                """UPDATE work_leases
                      SET lease_id = NULL, owner_id = NULL,
                          state = 'recovery_required', expires_at = NULL,
                          released_at = ?, renewed_at = ?, recovery_reason = ?
                    WHERE lease_key = ? AND fencing_epoch = ? AND state = 'active'""",
                (now, now, detail, SCAN_CAPACITY_LEASE_KEY, int(epoch)),
            )
            event_kind = "recovery_required"
            if manifest is not None:
                manifest["status"] = "interrupted"
                manifest["success"] = False
                manifest["completed_at"] = now
                manifest["error"] = detail
        db.execute(
            """INSERT INTO work_lease_events(
                   event_id, lease_key, fencing_epoch, lease_id, owner_id,
                   event_kind, recorded_at, detail
               ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                uuid.uuid4().hex, SCAN_CAPACITY_LEASE_KEY, int(epoch), lease_id,
                owner_id, event_kind, now, detail,
            ),
        )
        if manifest is not None:
            db.execute(
                """UPDATE scan_runs SET status = ?, manifest_json = ? WHERE run_id = ?""",
                (manifest["status"], json.dumps(manifest, sort_keys=True), run_id),
            )
            sync_scan_history_manifest(db, manifest)
        return {
            "run_id": run_id,
            "safe_pre_contact": safe_pre_contact,
            "state": "queued" if safe_pre_contact else "interrupted",
        }


@guarded_evidence_mutation(lambda *args, **kwargs: kwargs.get("db_path", args[0] if args else DB_PATH))
def recover_scheduler_state(
    db_path: Path = DB_PATH,
    data_dir: Path = DATA_DIR,
) -> dict:
    """Close orphaned work, preserve manual queue entries, and recover scheduled batches."""
    init_poc_storage(db_path)
    recovered_at = utc_now()
    durable_needs_attention = recover_schedule_occurrences(
        db_path, owner_process_ended=True
    )
    execution_recovery = recover_scan_execution_fence(db_path)
    with connect_database(db_path) as db:
        rows = db.execute("SELECT manifest_json FROM scan_runs").fetchall()
    manifests = [json.loads(row[0]) for row in rows]
    orphaned = []
    preserved_queue = []
    for manifest in manifests:
        if manifest.get("status") not in {
            "queued",
            "dispatching",
            "running",
            "awaiting_fallback_approval",
        }:
            continue
        if (
            manifest.get("status") == "queued"
            and not manifest.get("started_at")
        ):
            claim = manifest.get("work_claim")
            preserve_scheduled = False
            if manifest.get("scheduled") and isinstance(claim, dict):
                occurrence = get_occurrence(
                    db_path, str(claim.get("occurrence_id") or "")
                )
                chunk = next(
                    (
                        item for item in (occurrence or {}).get("chunks", [])
                        if item["chunk_number"] == int(claim.get("chunk_number") or 0)
                    ),
                    None,
                )
                preserve_scheduled = bool(
                    chunk
                    and chunk["state"] == "waiting"
                    and chunk["contact_phase"] == "not_started"
                )
            if manifest.get("scheduled") and not preserve_scheduled:
                pass
            else:
                preserved_queue.append(manifest["run_id"])
                append_scan_audit(
                    db_path,
                    run_id=manifest["run_id"],
                    event="queue_recovered",
                    actor="system",
                    details=(
                        "Preserved unstarted scheduled chunk across analyzer restart"
                        if preserve_scheduled
                        else "Preserved unstarted manual request across analyzer restart"
                    ),
                    changed_at=recovered_at,
                )
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
        append_scan_audit(
            db_path,
            run_id=manifest["run_id"],
            event="interrupted",
            actor="system",
            details=manifest["error"],
            changed_at=recovered_at,
        )
        orphaned.append(manifest["run_id"])

    recovered_schedules = []
    for schedule in list_scan_schedules(db_path):
        active_batch_id = schedule.get("active_batch_id")
        durable_occurrence = (
            get_occurrence(db_path, active_batch_id) if active_batch_id else None
        )
        if durable_occurrence is not None:
            if durable_occurrence["state"] == "needs_attention":
                schedule["enabled"] = False
                schedule["batch_status"] = "needs_attention"
                schedule["last_occurrence_status"] = "needs_attention"
                schedule["last_dispatch_note"] = durable_occurrence.get(
                    "status_reason"
                ) or "Interrupted occurrence needs review and will not resume"
                _store_scan_schedule(schedule, db_path)
                recovered_schedules.append(schedule["schedule_id"])
            elif durable_occurrence["state"] == "waiting":
                schedule["batch_status"] = "waiting"
                schedule["last_occurrence_status"] = "waiting"
                schedule["last_dispatch_note"] = "Due now — waiting for scanner"
                _store_scan_schedule(schedule, db_path)
            continue
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
        schedule["enabled"] = False
        schedule["batch_status"] = "recovery_review_required"
        schedule["next_run_at"] = None
        schedule["last_dispatch_note"] = (
            f"Restart interrupted this occurrence after {completed} completed "
            "chunk(s). NCT will not resume network contact automatically. Review "
            "the retained runs, then start a new occurrence when authorized."
        )
        details = (
            "Paused an interrupted batch for operator review; network contact never "
            "transfers or resumes from restart recovery"
        )
        _append_schedule_history(
            schedule,
            "restart_recovery",
            "system",
            details,
            changed_at=recovered_at,
        )
        _store_scan_schedule(schedule, db_path)
        recovered_schedules.append(schedule["schedule_id"])
    dispatch_next_queued_run(db_path=db_path, data_dir=data_dir)
    return {
        "orphaned_run_ids": orphaned,
        "preserved_queue_run_ids": preserved_queue,
        "recovered_schedule_ids": recovered_schedules,
        "durable_needs_attention_occurrence_ids": durable_needs_attention,
        "scan_execution_recovery": execution_recovery,
    }


def dispatch_due_schedules(
    now: datetime | None = None,
    db_path: Path = DB_PATH,
    data_dir: Path | None = None,
) -> list[dict]:
    """Queue at most one due batch; its chunks run sequentially on the analyzer."""
    recovery_data_dir = (
        data_dir
        if data_dir is not None
        else DATA_DIR if db_path == DB_PATH else db_path.parent
    )
    if scan_contact_paused(recovery_data_dir):
        return []
    moment = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    dispatched = []
    with ACTIVE_SCHEDULE_BATCHES_LOCK:
        active_schedule_ids = set(ACTIVE_SCHEDULE_BATCHES)
    schedules = list_scan_schedules(db_path)
    waiting = [
        schedule for schedule in schedules
        if (schedule.get("latest_occurrence") or {}).get("state") == "waiting"
        and schedule["schedule_id"] not in active_schedule_ids
        and (schedule.get("enabled") or schedule.get("batch_status") not in {
            "blocked_network_scope", "blocked_mission_environment",
        })
    ]
    waiting.sort(
        key=lambda item: (item["latest_occurrence"]["created_at"], item["schedule_id"])
    )
    for selected in waiting:
        try:
            with connect_database(db_path) as db:
                db.execute("BEGIN IMMEDIATE")
                resolve_reviewed_scope_context(
                    db,
                    saved_network_ids=list(selected.get("saved_network_ids") or []),
                    manual_targets=list(selected.get("manual_targets") or []),
                    reviewed_associations=list(
                        selected.get("reviewed_scope_associations") or []
                    ),
                )
                resolve_collection_mission_review(
                    db,
                    saved_network_ids=list(selected.get("saved_network_ids") or []),
                    manual_targets=list(selected.get("manual_targets") or []),
                    reviewed_scopes=list(
                        selected.get("reviewed_mission_scopes") or []
                    ),
                    collection_scope_id=(
                        selected.get("network_scope_context") or {}
                    ).get("scope_id"),
                )
            started = _start_prepared_schedule_occurrence(
                selected["schedule_id"],
                selected["latest_occurrence"]["occurrence_id"],
                db_path=db_path,
                data_dir=recovery_data_dir,
            )
        except (MissionEnvironmentConflict, SavedNetworkScopeConflict) as exc:
            blocked = get_scan_schedule(selected["schedule_id"], db_path) or selected
            blocked["enabled"] = False
            blocked["batch_status"] = (
                "blocked_network_scope" if isinstance(exc, SavedNetworkScopeConflict)
                else "blocked_mission_environment"
            )
            blocked["last_occurrence_status"] = blocked["batch_status"]
            blocked["last_dispatch_note"] = str(exc)
            _store_scan_schedule(blocked, db_path)
            continue
        except RuntimeError:
            record_schedule_conflict(
                selected,
                f"occurrence:{selected['latest_occurrence']['occurrence_id']}",
                db_path,
            )
            continue
        if started:
            return [{
                "schedule_id": selected["schedule_id"],
                "occurrence_id": selected["latest_occurrence"]["occurrence_id"],
                "batch_id": selected["latest_occurrence"]["occurrence_id"],
                "status": "waiting",
                "created": False,
            }]
    due = [
        schedule for schedule in schedules
        if schedule.get("enabled") and schedule.get("next_run_at")
        and schedule["schedule_id"] not in active_schedule_ids
        and _as_utc(schedule["next_run_at"]) <= moment
    ]
    due.sort(key=lambda item: item["next_run_at"])
    for schedule in due:
        try:
            batch = queue_scan_schedule_batch(
                schedule["schedule_id"],
                advance_schedule=True,
                trigger_key="cadence",
                actor="scheduler",
                now=moment,
                db_path=db_path,
            )
        except (MissionEnvironmentConflict, SavedNetworkScopeConflict) as exc:
            schedule["enabled"] = False
            schedule["batch_status"] = (
                "blocked_network_scope" if isinstance(exc, SavedNetworkScopeConflict)
                else "blocked_mission_environment"
            )
            schedule["last_occurrence_status"] = schedule["batch_status"]
            schedule["last_dispatch_note"] = str(exc)
            _store_scan_schedule(schedule, db_path)
            continue
        except RuntimeError:
            record_schedule_conflict(
                schedule,
                f"scheduled:{schedule['next_run_at']}",
                db_path,
            )
            continue
        dispatched.append(batch)
        break
    return dispatched


def schedule_worker(stop_event: threading.Event, interval_seconds: float = 15.0) -> None:
    while not stop_event.is_set():
        try:
            dispatch_next_queued_run()
            dispatch_due_schedules()
        except Exception:
            # One malformed or unavailable schedule must not stop future checks.
            logging.getLogger(__name__).exception("Scan scheduler check failed")
        stop_event.wait(interval_seconds)


def resume_scan_workers() -> None:
    with ACTIVE_SCHEDULE_BATCHES_LOCK:
        _SCHEDULE_WORKER_SHUTDOWN.clear()
    with ACTIVE_RUNS_LOCK:
        _SCAN_WORKER_SHUTDOWN.clear()


def stop_scan_workers(timeout: float = 2.0) -> bool:
    """Request active scans to stop and prove their writer threads exited."""
    deadline = time.monotonic() + max(0.0, timeout)
    with ACTIVE_RUNS_LOCK:
        _SCAN_WORKER_SHUTDOWN.set()
        controls = list(ACTIVE_RUNS.values())
        threads = list(ACTIVE_RUN_THREADS.values())
    for control in controls:
        control.cancel_event.set()
    for thread in threads:
        thread.join(timeout=max(0.0, deadline - time.monotonic()))
    with ACTIVE_RUNS_LOCK:
        return not any(thread.is_alive() for thread in ACTIVE_RUN_THREADS.values())


def stop_schedule_batch_workers(timeout: float = 2.0) -> bool:
    """Wait briefly for scheduled batch writers; retain the guard if any remain."""
    deadline = time.monotonic() + max(0.0, timeout)
    with ACTIVE_SCHEDULE_BATCHES_LOCK:
        _SCHEDULE_WORKER_SHUTDOWN.set()
        threads = list(ACTIVE_SCHEDULE_THREADS.values())
    for thread in threads:
        thread.join(timeout=max(0.0, deadline - time.monotonic()))
    with ACTIVE_SCHEDULE_BATCHES_LOCK:
        return not any(
            thread.is_alive() for thread in ACTIVE_SCHEDULE_THREADS.values()
        )


def list_import_history(db_path: Path = DB_PATH, limit: int = 50) -> list[dict]:
    with connect_database(db_path) as db:
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
                    "reported_up_count": analysis.get(
                        "reported_up_count", analysis.get("up_count", 0)
                    ),
                    "assumed_up_count": analysis.get("assumed_up_count", 0),
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
    with connect_database(db_path) as db:
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


def save_saved_network_with_context(
    request: SavedNetworkContextSave,
    *,
    actor: str,
    db_path: Path = DB_PATH,
) -> dict:
    """Save the network and its future-scan context in one transaction."""
    init_poc_storage(db_path)
    normalized_from: str | None = None
    try:
        with connect_database(db_path) as db:
            db.execute("BEGIN IMMEDIATE")
            if request.saved_network_id is None:
                if (
                    request.expected_updated_at is not None
                    or request.expected_association_id is not None
                    or request.expected_revision is not None
                ):
                    raise SavedNetworkScopeConflict(
                        "A new Saved Network cannot reference earlier context"
                    )
                saved_network_id, normalized_from = insert_saved_network_record(
                    db,
                    SavedNetworkCreate(
                        name=request.name,
                        cidr=request.cidr,
                        description=request.description,
                        category=request.category,
                        tags=request.tags,
                        created_by=actor,
                    ),
                )
                current = None
            else:
                saved_network_id = request.saved_network_id
                current = current_scope_association_in_transaction(
                    db, saved_network_id
                )
                current_id = current["association_id"] if current else None
                current_revision = int(current["revision"]) if current else None
                if (
                    request.expected_association_id != current_id
                    or request.expected_revision != current_revision
                ):
                    raise SavedNetworkScopeConflict(
                        "Saved Network context changed in another session; reload and review it again"
                    )
                normalized_from = update_saved_network_record(
                    db,
                    saved_network_id,
                    SavedNetworkUpdate(
                        name=request.name,
                        cidr=request.cidr,
                        description=request.description,
                        category=request.category,
                        tags=request.tags,
                        expected_updated_at=request.expected_updated_at or "",
                        updated_by=actor,
                    ),
                )
            current_scope = current["scope_id"] if current else None
            if request.scope_id != current_scope:
                if not request.scope_reason:
                    raise ValueError(
                        "Enter why the Network Scope is being assigned, changed, or cleared"
                    )
                insert_saved_network_scope_association(
                    db,
                    saved_network_id,
                    scope_id=request.scope_id,
                    expected_association_id=(
                        current["association_id"] if current else None
                    ),
                    expected_revision=(int(current["revision"]) if current else None),
                    actor=actor,
                    reason=request.scope_reason,
                )
    except sqlite3.IntegrityError as exc:
        if "saved_networks" in str(exc).lower():
            raise ValueError(saved_network_integrity_message(exc)) from exc
        raise SavedNetworkScopeConflict(str(exc)) from exc
    record = get_saved_network_with_warnings(
        saved_network_id, db_path, normalized_from=normalized_from,
    )
    return attach_scope_associations(db_path, [record])[0]


@router.get("/saved-networks")
def saved_network_history(include_archived: bool = False) -> list[dict]:
    return attach_scope_associations(
        DB_PATH,
        list_saved_networks(DB_PATH, include_archived=include_archived),
    )


@router.get("/network-scope-options")
def active_network_scope_options() -> list[dict]:
    return [
        {
            "scope_id": item["scope_id"],
            "label": item["label"],
            "description": item["description"],
            "version": item["version"],
        }
        for item in list_network_scopes(DB_PATH)
    ]


@router.get("/saved-networks/{saved_network_id}")
def saved_network_detail(saved_network_id: str) -> dict:
    record = get_saved_network(saved_network_id, DB_PATH)
    if record is None:
        raise HTTPException(status_code=404, detail="Saved Network not found")
    return attach_scope_associations(DB_PATH, [record])[0]


@router.get("/saved-networks/{saved_network_id}/scope-history")
def saved_network_scope_history(saved_network_id: str) -> list[dict]:
    if get_saved_network(saved_network_id, DB_PATH) is None:
        raise HTTPException(status_code=404, detail="Saved Network not found")
    return list_saved_network_scope_history(DB_PATH, saved_network_id)


@router.post("/saved-networks/contextual-save")
def save_saved_network_and_context(
    payload: SavedNetworkContextSave, http_request: Request
) -> dict:
    analyst = getattr(http_request.state, "analyst", None)
    actor = (
        str(analyst.get("username"))
        if analyst and analyst.get("username")
        else "local-operator"
    )
    try:
        return save_saved_network_with_context(payload, actor=actor, db_path=DB_PATH)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc.args[0])) from exc
    except SavedNetworkScopeConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.put("/saved-networks/{saved_network_id}/network-scope")
def set_saved_network_scope(
    saved_network_id: str,
    payload: SavedNetworkScopeChange,
    http_request: Request,
) -> dict:
    analyst = getattr(http_request.state, "analyst", None)
    actor = (
        str(analyst.get("username"))
        if analyst and analyst.get("username")
        else "local-operator"
    )
    try:
        return change_saved_network_scope_association(
            DB_PATH,
            saved_network_id,
            scope_id=payload.scope_id,
            expected_association_id=payload.expected_association_id,
            expected_revision=payload.expected_revision,
            actor=actor,
            reason=payload.reason,
        )


    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc.args[0])) from exc
    except SavedNetworkScopeConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post("/saved-networks", status_code=201)
def save_saved_network(request: SavedNetworkCreate, http_request: Request) -> dict:
    try:
        request = bind_signed_in_actor(http_request, request, "created_by")
        return create_saved_network(request, DB_PATH)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.put("/saved-networks/{saved_network_id}")
def edit_saved_network(
    saved_network_id: str, request: SavedNetworkUpdate, http_request: Request
) -> dict:
    try:
        request = bind_signed_in_actor(http_request, request, "updated_by")
        return update_saved_network(saved_network_id, request, DB_PATH)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Saved Network not found") from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post("/saved-networks/{saved_network_id}/archive")
def archive_saved_network_record(
    saved_network_id: str, request: SavedNetworkArchive, http_request: Request
) -> dict:
    try:
        request = bind_signed_in_actor(http_request, request, "changed_by")
        return archive_saved_network(saved_network_id, request, DB_PATH)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Saved Network not found") from exc


@router.get("/safety/no-strike")
def global_no_strike_list() -> dict:
    return get_global_no_strike(DB_PATH)


@router.post("/safety/scan-summary")
def preview_scan_safety(request: ScanSafetySummaryRequest) -> dict:
    try:
        return scan_safety_summary(request.targets, request.no_strike, DB_PATH)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post("/safety/no-strike", status_code=201)
def add_to_global_no_strike(request: NoStrikeUpdate, http_request: Request) -> dict:
    try:
        analyst = getattr(http_request.state, "analyst", None)
        if analyst and analyst.get("role") not in {"analyst", "admin"}:
            raise HTTPException(status_code=403, detail="Analyst or administrator role required")
        actor = str(analyst.get("username")) if analyst else "local-operator"
        request = request.model_copy(update={"changed_by": actor})
        return add_global_no_strike(request, DB_PATH)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post("/safety/no-strike/remove-challenge")
def global_no_strike_remove_challenge(entries: list[str]) -> dict:
    try:
        requested = normalize_ipv4_networks(entries, "no-strike")
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    current = get_global_no_strike(DB_PATH)["entries"]
    if any(entry not in current for entry in requested):
        raise HTTPException(status_code=404, detail="No-strike entry not found")
    return issue_delete_challenge("global-no-strike", ",".join(requested))


@router.post("/safety/no-strike/remove")
def remove_from_global_no_strike(
    request: NoStrikeRemoval, http_request: Request
) -> dict:
    try:
        analyst = getattr(http_request.state, "analyst", None)
        if analyst and analyst.get("role") != "admin":
            raise HTTPException(
                status_code=403,
                detail="Administrator role required to remove a global No-Strike exclusion",
            )
        actor = str(analyst.get("username")) if analyst else "local-operator"
        request = request.model_copy(update={"changed_by": actor})
        return remove_global_no_strike(request, DB_PATH)
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
def save_scan_profile(request: ScanProfileCreate, http_request: Request) -> dict:
    try:
        request = bind_signed_in_actor(http_request, request, "created_by")
        return create_scan_profile(request)
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post("/scan-profiles/{profile_id}/versions", status_code=201)
def save_scan_profile_version(
    profile_id: str, request: ScanProfileVersionCreate, http_request: Request
) -> dict:
    try:
        request = bind_signed_in_actor(http_request, request, "created_by")
        return create_scan_profile_version(profile_id, request)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post("/scan-profiles/{profile_id}/clone", status_code=201)
def clone_saved_scan_profile(
    profile_id: str, request: ScanProfileClone, http_request: Request
) -> dict:
    try:
        request = bind_signed_in_actor(http_request, request, "created_by")
        return clone_scan_profile(profile_id, request)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post("/scan-profiles/{profile_id}/delete-challenge")
def scan_profile_delete_challenge(profile_id: str) -> dict:
    try:
        review = scan_profile_delete_review(profile_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Scan profile not found") from exc
    if review["built_in"]:
        raise HTTPException(status_code=403, detail="Built-in profiles cannot be deleted")
    if not review["deletable"]:
        return review
    return {**review, **issue_delete_challenge("profile", profile_id)}


@router.post("/scan-profiles/{profile_id}/delete")
def delete_saved_scan_profile(profile_id: str, confirmation: DeleteConfirmation) -> dict:
    try:
        return delete_scan_profile(profile_id, confirmation.confirmation)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Scan profile not found") from exc
    except ScanProfileDependencyError as exc:
        raise HTTPException(
            status_code=409,
            detail={"message": str(exc), **exc.review},
        ) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


@router.get("/scan-schedules")
def scan_schedule_history() -> list[dict]:
    return list_scan_schedules(DB_PATH)


@router.post("/scan-schedules", status_code=201)
def save_scan_schedule(request: ScanScheduleCreate, http_request: Request) -> dict:
    try:
        if request.enabled:
            require_active_collection()
        request = bind_signed_in_actor(http_request, request, "created_by")
        return create_scan_schedule(request, DB_PATH)
    except CollectionSafetySetupIncomplete as exc:
        raise HTTPException(status_code=409, detail=f"Mission Environment: {exc}") from exc
    except SavedNetworkScopeConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except MissionEnvironmentConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post("/scan-schedules/{schedule_id}/state")
def change_scan_schedule_state(
    schedule_id: str, request: ScheduleStateChange, http_request: Request
) -> dict:
    try:
        if request.enabled:
            require_active_collection()
        request = bind_signed_in_actor(http_request, request, "changed_by")
        return set_scan_schedule_enabled(
            schedule_id, request.enabled, changed_by=request.changed_by,
            db_path=DB_PATH,
        )
    except CollectionSafetySetupIncomplete as exc:
        raise HTTPException(status_code=409, detail=f"Mission Environment: {exc}") from exc
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Scan schedule not found") from exc
    except SavedNetworkScopeConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except MissionEnvironmentConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/scan-schedules/{schedule_id}/profile")
def repin_scan_schedule_profile(
    schedule_id: str, request: ScheduleProfileChange, http_request: Request
) -> dict:
    try:
        request = bind_signed_in_actor(http_request, request, "changed_by")
        return change_scan_schedule_profile(schedule_id, request)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Scan schedule not found") from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/scan-schedules/{schedule_id}/run", status_code=202)
def run_saved_scan_schedule(
    schedule_id: str, http_request: Request, request: ScheduleRunNow | None = None
) -> dict:
    require_active_collection()
    try:
        if request is None:
            raise ValueError("A unique request identifier is required")
        request = bind_signed_in_actor(http_request, request, "requested_by")
        return run_scan_schedule_now(
            schedule_id,
            request_id=request.request_id,
            requested_by=request.requested_by or "local-operator",
        )
    except CollectionSafetySetupIncomplete as exc:
        raise HTTPException(status_code=409, detail=f"Mission Environment: {exc}") from exc
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Scan schedule not found") from exc
    except SavedNetworkScopeConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except MissionEnvironmentConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post("/scan-schedule-occurrences/{occurrence_id}/close-review")
def close_interrupted_schedule_occurrence(
    occurrence_id: str,
    request: ScheduleRecoveryReview,
    http_request: Request,
) -> dict:
    try:
        request = bind_signed_in_actor(http_request, request, "reviewed_by")
        return close_reviewed_occurrence(
            DB_PATH,
            occurrence_id,
            reviewed_by=request.reviewed_by or "local-operator",
            reason=request.reason,
            confirmed_former_contact_stopped=request.confirmed_former_contact_stopped,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc.args[0])) from exc
    except WorkLeaseConflict as exc:
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
@guarded_evidence_mutation(lambda *args, **kwargs: DB_PATH)
def create_scan_run_plan(plan: ScanRunPlan, http_request: Request) -> dict:
    try:
        actor_fields = ["operator", "created_by", "executed_by"]
        if plan.scheduled:
            actor_fields.append("scheduled_by")
        plan = bind_signed_in_actor(http_request, plan, *actor_fields)
        return save_scan_run_plan(plan)
    except SavedNetworkScopeConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post("/scan-runs", status_code=202)
@guarded_evidence_mutation(lambda *args, **kwargs: DB_PATH)
def start_scan_run(request: ScanRunRequest, http_request: Request) -> dict:
    require_active_collection()
    try:
        actor_fields = ["operator", "created_by", "executed_by"]
        if request.scheduled:
            actor_fields.append("scheduled_by")
        request = bind_signed_in_actor(http_request, request, *actor_fields)
        require_scan_plan_collection_setup(request, DB_PATH)
        return launch_scan_run(request)
    except CollectionSafetySetupIncomplete as exc:
        raise HTTPException(
            status_code=409, detail=f"Mission Environment: {exc}"
        ) from exc
    except SavedNetworkScopeConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post("/scan-runs/{run_id}/fallback-decision", status_code=202)
def decide_scan_fallback(
    run_id: str, request: FallbackDecision, http_request: Request
) -> dict:
    manifest = get_scan_run_plan(run_id, DB_PATH)
    if manifest is None:
        raise HTTPException(status_code=404, detail="Scan run not found")
    actor, _ = _require_run_control(http_request, manifest)
    request = request.model_copy(update={"decided_by": actor})
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
    append_scan_audit(
        DB_PATH,
        run_id=run_id,
        event=f"fallback_{request.decision}",
        actor=request.decided_by,
        details=request.authorization_note,
    )
    return {"run_id": run_id, "decision": request.decision, "status": "decision_recorded"}


def _scan_actor(request: Request) -> tuple[str | None, str | None]:
    analyst = getattr(request.state, "analyst", None)
    if not analyst:
        return None, None
    return str(analyst.get("username") or ""), str(analyst.get("role") or "")


def _require_run_control(request: Request, manifest: dict) -> tuple[str, str]:
    actor, role = _scan_actor(request)
    if actor is None:
        return "local-operator", "admin"
    owner = str(manifest.get("owner") or manifest.get("created_by") or manifest.get("operator") or "")
    if role != "admin" and actor != owner:
        raise HTTPException(
            status_code=403,
            detail="Only the scan owner or an Administrator can control this run",
        )
    return actor, role or "analyst"


class ScanRunAssignmentConflict(RuntimeError):
    """The waiting scan changed after the assignment control was opened."""


def reassign_queued_scan_operator(
    run_id: str,
    change: ScanRunOwnerChange,
    db_path: Path = DB_PATH,
    *,
    actor: str | None,
    role: str | None,
) -> dict:
    """Atomically change responsibility for one waiting scan and audit it."""
    init_poc_storage(db_path)
    changed_at = utc_now()
    acting_username = actor or "local-operator"
    with connect_database(db_path) as db:
        db.execute("BEGIN IMMEDIATE")
        if actor is None:
            if change.owner != "local-operator":
                raise PermissionError(
                    "Assigned operator changes require a signed-in Administrator"
                )
        else:
            actor_row = db.execute(
                "SELECT role, disabled FROM analyst_users WHERE username = ?",
                (actor,),
            ).fetchone()
            if (
                actor_row is None
                or bool(actor_row[1])
                or str(actor_row[0]) != "admin"
                or role != "admin"
            ):
                raise PermissionError("An active Administrator account is required")
            target_row = db.execute(
                "SELECT role, disabled FROM analyst_users WHERE username = ?",
                (change.owner,),
            ).fetchone()
            if target_row is None or bool(target_row[1]):
                raise ValueError("Choose an active analyst account")
            if str(target_row[0]) == "viewer":
                raise ValueError("Viewer accounts cannot be assigned waiting scans")

        row = db.execute(
            "SELECT status, manifest_json FROM scan_runs WHERE run_id = ?",
            (run_id,),
        ).fetchone()
        if row is None:
            raise KeyError(run_id)
        manifest = json.loads(row[1])
        if str(row[0]) != "queued" or manifest.get("status") != "queued":
            raise ScanRunAssignmentConflict(
                "The scan is no longer waiting, so the assignment was not saved. Reload Active Scans and review its current state."
            )
        current_owner = str(
            manifest.get("owner")
            or manifest.get("created_by")
            or manifest.get("operator")
            or ""
        ).strip().lower()
        raw_revision = manifest.get("queue_assignment_revision", 0)
        if isinstance(raw_revision, bool) or not isinstance(raw_revision, int) or raw_revision < 0:
            raise ScanRunAssignmentConflict(
                "The saved assignment record is invalid. The assignment was not saved; reload Active Scans and review this waiting scan."
            )
        if (
            current_owner != change.expected_owner
            or raw_revision != change.expected_assignment_revision
        ):
            raise ScanRunAssignmentConflict(
                "This waiting scan changed after you opened it. The assignment was not saved. Reload Active Scans, reopen this scan, and review the current assigned operator before retrying."
            )

        manifest["owner"] = change.owner
        manifest["owner_changed_at"] = changed_at
        manifest["owner_changed_by"] = acting_username
        manifest["queue_assignment_revision"] = raw_revision + 1
        changed = db.execute(
            """UPDATE scan_runs SET manifest_json = ?
                 WHERE run_id = ? AND status = 'queued'""",
            (json.dumps(manifest, sort_keys=True), run_id),
        ).rowcount
        if changed != 1:
            raise ScanRunAssignmentConflict(
                "The scan left the waiting queue. The assignment was not saved. Reload Active Scans and review its current state."
            )
        append_scan_audit_on_connection(
            db,
            run_id=run_id,
            event="reassigned",
            actor=acting_username,
            details=(
                f"Assigned operator changed from {current_owner} to {change.owner}; "
                "original requestor, queue position, targets, settings, and authorization were unchanged"
            ),
            changed_at=changed_at,
        )
    return manifest


@router.post("/scan-runs/{run_id}/cancel", status_code=202)
def cancel_scan_run(run_id: str, request: Request) -> dict:
    manifest = get_scan_run_plan(run_id, DB_PATH)
    if manifest is None:
        raise HTTPException(status_code=404, detail="Scan run not found")
    actor, _ = _require_run_control(request, manifest)
    with ACTIVE_RUNS_LOCK:
        control = ACTIVE_RUNS.get(run_id)
    if manifest["status"] == "queued" and control is None:
        changed_at = utc_now()
        manifest.update(
            {
                "status": "cancelled",
                "completed_at": changed_at,
                "success": False,
                "execution_note": "Cancelled before analyzer capacity was assigned",
            }
        )
        if isinstance(manifest.get("progress"), dict):
            update_scan_progress(manifest["progress"], phase="cancelled", updated_at=changed_at)
        update_scan_run_manifest(manifest, DB_PATH)
        append_scan_audit(
            DB_PATH,
            run_id=run_id,
            event="cancelled",
            actor=actor,
            details=manifest["execution_note"],
            changed_at=changed_at,
        )
        dispatch_next_queued_run(db_path=DB_PATH, data_dir=DATA_DIR)
        return {"run_id": run_id, "status": "cancelled"}
    if manifest["status"] not in {"queued", "dispatching", "running", "awaiting_fallback_approval"}:
        raise HTTPException(status_code=409, detail="Scan run is not active")
    if scan_cancellation_requested(run_id, DB_PATH):
        return {"run_id": run_id, "status": "cancellation_requested"}
    requested_at = utc_now()
    request_scan_cancellation(
        run_id,
        requested_by=actor,
        cause="operator",
        detail="Cancellation requested for the active analyzer process",
        requested_at=requested_at,
        db_path=DB_PATH,
    )
    if control is not None:
        control.cancel_event.set()
    append_scan_audit(
        DB_PATH,
        run_id=run_id,
        event="cancellation_requested",
        actor=actor,
        details="Cancellation requested for the active analyzer process",
        changed_at=requested_at,
    )
    return {"run_id": run_id, "status": "cancellation_requested"}


@router.post("/scan-runs/{run_id}/owner")
def change_scan_run_owner(
    run_id: str, change: ScanRunOwnerChange, request: Request
) -> dict:
    actor, role = _scan_actor(request)
    try:
        manifest = reassign_queued_scan_operator(
            run_id, change, DB_PATH, actor=actor, role=role
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Scan run not found") from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ScanRunAssignmentConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return with_queue_state(manifest, DB_PATH)


@router.put("/scan-runs/{run_id}/network-attribution")
def change_scan_run_network_attribution(
    run_id: str, change: ScanRunNetworkAttribution, request: Request
) -> dict:
    actor, role = _scan_actor(request)
    actor = actor or "local-operator"
    role = role or "admin"
    change = change.model_copy(update={"changed_by": actor})
    try:
        return attribute_scan_run_networks(
            run_id, change, DB_PATH, actor=actor, role=role
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Scan run not found") from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ScanRunMetadataConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/scan-runs/queue/status")
def scan_queue_status(request: Request) -> dict:
    actor, role = _scan_actor(request)
    runs = list_active_scan_run_plans(db_path=DB_PATH)
    runs.sort(
        key=lambda item: (
            0 if item.get("status") in {"dispatching", "running", "awaiting_fallback_approval"} else 1,
            int(item.get("queue_position") or 0),
            item.get("created_at") or "",
        )
    )
    for item in runs:
        owner = item.get("owner") or item.get("created_by") or item.get("operator")
        item["can_cancel"] = actor is None or role == "admin" or actor == owner
        item["can_reassign"] = bool(role == "admin" and item.get("status") == "queued")
    return {
        "capacity": MAX_ACTIVE_RUNS,
        "active_count": sum(item.get("status") != "queued" for item in runs),
        "queued_count": sum(item.get("status") == "queued" for item in runs),
        "runs": runs,
    }


@router.get("/scan-runs/{run_id}/live-discoveries")
def scan_run_live_discoveries(run_id: str) -> dict:
    if not RUN_ID_RE.fullmatch(run_id):
        raise HTTPException(status_code=422, detail="Invalid scan run id")
    manifest = get_scan_run_plan(run_id, DB_PATH)
    if manifest is None:
        raise HTTPException(status_code=404, detail="Scan run not found")
    if manifest.get("status") not in {
        "dispatching", "running", "awaiting_fallback_approval"
    }:
        raise HTTPException(
            status_code=409,
            detail="Live discoveries are available only while this scan is active",
        )
    try:
        result = live_scan_discoveries(DATA_DIR / RUNS_DIR_NAME / run_id)
    except UnsafeLiveScanPath as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    result.update({
        "run_id": run_id,
        "status": manifest.get("status"),
        "phase": (manifest.get("progress") or {}).get("phase"),
    })
    return result


@router.get("/scan-runs/{run_id}/audit")
def scan_run_audit(run_id: str, limit: int = Query(default=200, ge=1, le=1000)) -> list[dict]:
    if get_scan_run_plan(run_id, DB_PATH) is None:
        raise HTTPException(status_code=404, detail="Scan run not found")
    return scan_audit_history(DB_PATH, run_id, limit)


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


SCAN_HISTORY_FIELDS = {
    "run_id", "status", "partial_results", "execution_note", "display_name",
    "name", "created_at", "completed_at", "profile", "profile_id",
    "profile_version", "profile_settings", "saved_network_ids",
    "saved_networks", "target_selection", "manual_targets", "targets",
    "host_count", "interface", "created_by", "operator", "scheduled_by",
    "executed_by", "execution_method", "coverage", "scheduled",
    "timeout_seconds", "progress", "discovery_mode", "fallback_decision",
    "nmap_reported_host_count", "nmap_assumed_host_count",
    "network_scope_context", "history_also_covers",
}


def _enrich_scan_history_runs(runs: list[dict]) -> list[dict]:
    run_ids = [run["run_id"] for run in runs]
    analysis_jobs = scan_run_job_statuses(DB_PATH, run_ids, DATA_DIR)
    return [
        {
            **{key: value for key, value in run.items() if key in SCAN_HISTORY_FIELDS},
            "foundation_status": get_automated_scan_foundation_status(
                DB_PATH, run["run_id"]
            ),
            "analysis_job_status": analysis_jobs.get(run["run_id"], {}),
        }
        for run in runs
    ]


@router.get("/scan-history-groups")
def scan_history_group_catalog(
    limit: int = Query(default=100, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    sort: Literal["alphabetical", "newest"] = Query(default="alphabetical"),
    snapshot: str | None = Query(default=None, min_length=64, max_length=64),
) -> dict:
    try:
        return scan_history_catalog_page(
            DB_PATH,
            limit=limit,
            offset=offset,
            sort=sort,
            snapshot=snapshot,
        )
    except ScanHistoryCatalogChanged as exc:
        raise HTTPException(
            status_code=409,
            detail={"code": "scan_history_catalog_changed", "message": str(exc)},
        ) from exc


@router.get("/scan-history-groups/{group_id}/runs")
def scan_history_group_runs(
    group_id: str,
    limit: int = Query(default=25, ge=1, le=100),
    cursor: str | None = Query(default=None, max_length=512),
) -> dict:
    try:
        page = scan_history_group_page_from_index(
            DB_PATH, group_id, limit=limit, cursor=cursor
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if page is None:
        raise HTTPException(status_code=404, detail="Scan history group not found")
    page["runs"] = _enrich_scan_history_runs(page["runs"])
    return page


@router.get("/scan-history-visible-runs")
def scan_history_visible_runs(
    run_id: list[str] = Query(default=[]),
) -> dict:
    try:
        runs = list_scan_history_metadata_by_ids(run_id, DB_PATH)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {"runs": _enrich_scan_history_runs(runs)}


@router.get("/scan-runs-grouped")
def grouped_scan_run_history(
    limit: int = Query(default=25, ge=1, le=200),
    offset: int = 0,
) -> list[dict]:
    if offset < 0:
        raise HTTPException(status_code=422, detail="History offset must not be negative")
    groups = group_scan_runs_by_saved_network(
        list_scan_run_plans(DB_PATH, limit=limit, offset=offset, metadata_only=True)
    )
    for group in groups:
        group["runs"] = _enrich_scan_history_runs(group.get("runs", []))
    return groups


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
    from app.host_identities import apply_analysis_host_identities
    item["analysis"] = apply_analysis_host_identities(item["analysis"], DB_PATH)
    return item
