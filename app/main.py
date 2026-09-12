from __future__ import annotations

from app.poc import (
    LEGACY_PROFILE_IDS,
    ScanOptions,
    effective_no_strike,
    get_import_history_item,
    get_scan_profile,
    get_scan_run_plan,
    init_poc_storage,
    list_scan_run_plans,
    recover_scheduler_state,
    router as poc_router,
    run_directory,
    schedule_worker,
)
from app.device_configs import router as device_config_router
from app.device_analysis import router as device_analysis_router
from app.device_analysis_ui import device_analysis_page
from app.device_ui import device_config_page
from app.hunting import (
    build_hunting_analysis,
    compare_hunting_results,
    correlate_hunting_identity,
    merge_hunting_analyses,
)
from app.hunting_ui import hunting_page
from app.ip_sort import ip_sort_key
from app.os_inference import infer_os_identity
from app.searchsploit import (
    MAX_ARCHIVE_BYTES,
    enrich_hunting_with_searchsploit,
    install_searchsploit_archive,
    rollback_searchsploit_database,
    searchsploit_status,
    update_searchsploit_from_internet,
)
from app.identity import enrich_analysis_macs
from app.identity_overrides import (
    apply_analysis_os_overrides,
    delete_os_override,
    inference_review_history,
    init_os_override_storage,
    list_os_overrides,
    os_override_history,
    set_inference_review,
    set_os_override,
)
from app.exports import HOST_SUMMARY_FIELDS, PORT_LEVEL_FIELDS, host_summary_rows, port_level_rows, rows_to_csv
from app.scan_profiles import build_nmap_flags, scan_coverage, scan_display_name
from app.comparison import (
    compare_analyses,
    coverage_warnings,
    describe_run_group,
    group_is_comparable,
    group_run_manifests,
    merge_analyses,
    representative_coverage,
    run_group_key,
    select_same_scope_baseline,
)
from app.analysis_ui import analysis_page
from app.ui import operator_page
from app.build_info import APP_VERSION, BUILD_COMMIT, BUILD_ID
from app.auth import (
    SESSION_COOKIE,
    auth_enabled,
    cookie_secure,
    create_session,
    create_user,
    end_session,
    init_auth_storage,
    list_users,
    session_hours,
    session_identity,
    verify_credentials,
)
from app.workspaces import (
    WorkspaceConflict,
    delete_layout,
    init_workspace_storage,
    list_layouts,
    publish_layout,
    save_layout,
)
import hashlib
import io
import ipaddress
import json
import math
import os
import re
import shlex
import sqlite3
import threading
import uuid
import zipfile
from collections import Counter, defaultdict
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Literal
from defusedxml import ElementTree as ET

from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, Response, StreamingResponse
from pydantic import BaseModel, Field, field_validator


DATA_DIR = Path(os.environ.get("ANALYZER_DATA_DIR", "/data"))
IMPORT_DIR = DATA_DIR / "imports"
PACKAGE_DIR = DATA_DIR / "packages"
DB_PATH = DATA_DIR / "analyzer.db"
MAX_EXPANDED_ADDRESSES = 65536

class TerrainSegment(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    targets: list[str] = Field(min_length=1)

    @field_validator("name")
    @classmethod
    def clean_name(cls, value: str) -> str:
        return value.strip()


class CampaignSpec(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    profile: str = Field(default="standard", min_length=1, max_length=100)
    profile_id: str | None = Field(default=None, max_length=128)
    profile_version: int | None = Field(default=None, ge=1)
    scan_options: ScanOptions | None = None
    created_by: str = Field(default="analyst", min_length=1, max_length=100)
    scheduled: bool = False
    scheduled_by: str | None = Field(default=None, max_length=100)
    terrain: list[TerrainSegment] = Field(min_length=1)
    no_strike_mode: Literal["entered", "none"]
    no_strike: list[str] = Field(default_factory=list)
    chunking_enabled: bool = False
    chunk_size: int = Field(default=256, ge=1, le=4096)

    @field_validator("name")
    @classmethod
    def clean_campaign_name(cls, value: str) -> str:
        return value.strip()


class OsOverrideRequest(BaseModel):
    ip: str | None = Field(default=None, max_length=64)
    mac: str | None = Field(default=None, max_length=32)
    os_name: str = Field(min_length=1, max_length=120)
    analyst: str = Field(min_length=1, max_length=100)
    reason: str = Field(min_length=1, max_length=500)
    scanner_os: str | None = Field(default=None, max_length=240)


class OsOverrideDeleteRequest(BaseModel):
    analyst: str = Field(min_length=1, max_length=100)
    reason: str = Field(min_length=1, max_length=500)


class OsInferenceReviewRequest(BaseModel):
    ip: str | None = Field(default=None, max_length=64)
    mac: str | None = Field(default=None, max_length=32)
    inference: dict
    status: Literal["confirmed", "dismissed", "investigate"]
    analyst: str = Field(min_length=1, max_length=100)
    reason: str = Field(min_length=1, max_length=500)


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class AnalystUserRequest(BaseModel):
    username: str = Field(min_length=2, max_length=64)
    display_name: str = Field(min_length=1, max_length=100)
    role: Literal["admin", "analyst", "viewer"]
    password: str = Field(min_length=12, max_length=256)


class WorkspaceLayoutRequest(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    snapshot: dict
    layout_id: str | None = Field(default=None, max_length=64)
    expected_version: int | None = Field(default=None, ge=1)


class WorkspacePublishRequest(BaseModel):
    shared: bool


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def safe_name(value: str, fallback: str = "item") -> str:
    value = re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip()).strip("-._")
    return value[:80] or fallback


def init_storage() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    IMPORT_DIR.mkdir(parents=True, exist_ok=True)
    PACKAGE_DIR.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(DB_PATH) as db:
        db.execute(
            """CREATE TABLE IF NOT EXISTS imports (
                sha256 TEXT PRIMARY KEY,
                filename TEXT NOT NULL,
                stored_path TEXT NOT NULL,
                imported_at TEXT NOT NULL,
                analysis_json TEXT NOT NULL
            )"""
        )
        columns = {
            row[1] for row in db.execute("PRAGMA table_info(imports)").fetchall()
        }
        if "metadata_json" not in columns:
            db.execute(
                "ALTER TABLE imports ADD COLUMN metadata_json TEXT NOT NULL DEFAULT '{}'"
            )
    init_os_override_storage(DB_PATH)


def parse_networks(entries: list[str], label: str) -> list[ipaddress.IPv4Network]:
    networks: list[ipaddress.IPv4Network] = []
    for raw in entries:
        for token in re.split(r"[\s,]+", raw.strip()):
            if not token:
                continue
            try:
                network = ipaddress.ip_network(token, strict=False)
            except ValueError as exc:
                raise ValueError(f"Invalid {label} entry: {token}") from exc
            if network.version != 4:
                raise ValueError(f"IPv6 is not supported in this release: {token}")
            networks.append(network)
    if not networks:
        raise ValueError(f"At least one {label} entry is required")
    return list(ipaddress.collapse_addresses(networks))


def addresses_for(networks: list[ipaddress.IPv4Network]) -> list[str]:
    # Nmap treats a CIDR as its complete address range. Range environments also
    # commonly assign addresses traditionally called network/broadcast, so keep
    # every address and make no-strike subtraction operate on the same universe.
    estimated = sum(network.num_addresses for network in networks)
    if estimated > MAX_EXPANDED_ADDRESSES:
        raise ValueError(
            f"This campaign expands to {estimated:,} usable addresses; the current safety limit is "
            f"{MAX_EXPANDED_ADDRESSES:,}. Split it into smaller campaigns."
        )
    result: list[str] = []
    for network in networks:
        result.extend(str(address) for address in network)
    return result


def resolve_campaign_profile(spec: CampaignSpec) -> dict:
    if spec.profile_id:
        profile = get_scan_profile(spec.profile_id, spec.profile_version)
        if profile is None:
            raise ValueError("The selected saved profile version does not exist")
        return profile
    if spec.scan_options is not None:
        return {
            "profile_id": "inline-custom",
            "version": 1,
            "name": spec.profile if spec.profile not in LEGACY_PROFILE_IDS else "Custom",
            "settings": spec.scan_options.normalized(),
        }
    profile_id = LEGACY_PROFILE_IDS.get(spec.profile, spec.profile)
    profile = get_scan_profile(profile_id, 1)
    if profile is None:
        raise ValueError(f"Unknown scan profile: {spec.profile}")
    return profile


def scan_flags(profile: str, scan_options: dict | None = None) -> list[str]:
    if scan_options is not None:
        return build_nmap_flags(scan_options)
    profile_id = LEGACY_PROFILE_IDS.get(profile, profile)
    saved = get_scan_profile(profile_id, 1)
    if saved is None:
        raise ValueError(f"Unknown scan profile: {profile}")
    return build_nmap_flags(saved["settings"])


def sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def validate_campaign(spec: CampaignSpec) -> tuple[list[str], list[tuple[str, list[str]]]]:
    if spec.no_strike_mode == "entered" and not spec.no_strike:
        raise ValueError("No-strike mode is 'entered', but the no-strike list is empty")
    if spec.no_strike_mode == "none" and spec.no_strike:
        raise ValueError("Choose 'entered' when supplying no-strike addresses")

    effective_entries, _ = effective_no_strike(spec.no_strike, DB_PATH)
    no_strike_addresses: list[str] = []
    if effective_entries:
        no_strike_addresses = addresses_for(
            parse_networks(effective_entries, "no-strike")
        )
    blocked = set(no_strike_addresses)

    seen_names: set[str] = set()
    segments: list[tuple[str, list[str]]] = []
    total = 0
    for segment in spec.terrain:
        segment_slug = safe_name(segment.name, "segment")
        if segment_slug.lower() in seen_names:
            raise ValueError(f"Terrain segment names must be unique: {segment.name}")
        seen_names.add(segment_slug.lower())
        target_addresses = addresses_for(parse_networks(segment.targets, "terrain"))
        allowed = [address for address in target_addresses if address not in blocked]
        if not allowed:
            raise ValueError(f"No scannable addresses remain in terrain segment: {segment.name}")
        total += len(allowed)
        if total > MAX_EXPANDED_ADDRESSES:
            raise ValueError(f"Campaign exceeds the {MAX_EXPANDED_ADDRESSES:,}-address safety limit")
        segments.append((segment_slug, allowed))
    return no_strike_addresses, segments


def campaign_chunking_enabled(spec: CampaignSpec) -> bool:
    """Honor explicit opt-in while preserving older API requests with chunk_size."""
    legacy_chunk_request = (
        "chunk_size" in spec.model_fields_set
        and "chunking_enabled" not in spec.model_fields_set
    )
    return spec.chunking_enabled or legacy_chunk_request


def build_scan_plan(spec: CampaignSpec) -> tuple[list[str], list[str], list[dict]]:
    no_strike, segments = validate_campaign(spec)
    profile = resolve_campaign_profile(spec)
    flags = build_nmap_flags(profile["settings"])
    use_fping = profile["settings"].get("discovery_mode") == "fping"
    chunks: list[dict] = []
    chunk_number = 0
    chunking_enabled = campaign_chunking_enabled(spec)
    for segment_name, addresses in segments:
        addresses_per_scan = spec.chunk_size if chunking_enabled else len(addresses)
        for start in range(0, len(addresses), addresses_per_scan):
            chunk_number += 1
            chunk_addresses = addresses[start:start + addresses_per_scan]
            stem = f"{chunk_number:03d}-{segment_name}"
            target_path = f"targets/{stem}.txt"
            output_path = f"results/{stem}.xml"
            alive_path = f"results/{stem}-fping-alive.txt"
            fping_log_path = f"results/{stem}-fping-stderr.txt"
            nmap_target_path = alive_path if use_fping else target_path
            common = (
                f"{' '.join(flags)} -iL {nmap_target_path} "
                f"--excludefile no-strike.txt -oX {output_path}"
            )
            linux_nmap = f"sudo nmap {common}"
            windows_nmap = f"nmap {common}"
            if use_fping:
                linux_command = (
                    f"fping -a -f {target_path} > {alive_path} 2> {fping_log_path} || [ $? -eq 1 ]; "
                    f"if [ -s {alive_path} ]; then {linux_nmap}; else echo 'No responsive hosts in {target_path}'; fi"
                )
                windows_command = (
                    f"fping -a -f {target_path} > {alive_path} 2> {fping_log_path} & "
                    f"for %%A in ({alive_path}) do if %%~zA GTR 0 {windows_nmap}"
                )
            else:
                linux_command = linux_nmap
                windows_command = windows_nmap
            chunks.append({
                "number": chunk_number,
                "terrain_segment": segment_name,
                "stem": stem,
                "target_file": target_path,
                "output_file": output_path,
                "addresses": chunk_addresses,
                "linux_command": linux_command,
                "windows_command": windows_command,
                "discovery_mode": "fping" if use_fping else "nmap",
                "fping_alive_file": alive_path if use_fping else None,
                "fping_log_file": fping_log_path if use_fping else None,
            })
    return no_strike, flags, chunks


def build_package(spec: CampaignSpec) -> tuple[str, bytes]:
    if spec.scheduled and not (spec.scheduled_by or "").strip():
        raise ValueError("Scheduled packages must retain the scheduler identity")
    no_strike, flags, scan_plan = build_scan_plan(spec)
    global_no_strike = effective_no_strike([], DB_PATH)[0]
    profile = resolve_campaign_profile(spec)
    moment = datetime.now(timezone.utc)
    created_at = moment.replace(microsecond=0).isoformat()
    display_name = scan_display_name(spec.name, scheduled=spec.scheduled, when=moment)
    files: dict[str, bytes] = {}
    chunks: list[dict] = []
    unix_lines = ["#!/usr/bin/env bash", "set -euo pipefail", "mkdir -p results"]
    windows_lines = ["@echo off", "if not exist results mkdir results"]

    no_strike_text = "\n".join(no_strike) + ("\n" if no_strike else "")
    files["no-strike.txt"] = no_strike_text.encode()

    for chunk in scan_plan:
        target_content = ("\n".join(chunk["addresses"]) + "\n").encode()
        files[chunk["target_file"]] = target_content
        unix_lines.append(chunk["linux_command"])
        windows_lines.append(chunk["windows_command"])
        chunks.append({
            "number": chunk["number"],
            "terrain_segment": chunk["terrain_segment"],
            "target_file": chunk["target_file"],
            "output_file": chunk["output_file"],
            "address_count": len(chunk["addresses"]),
            "target_sha256": sha256_bytes(target_content),
        })

    files["run-linux.sh"] = ("\n".join(unix_lines) + "\n").encode()
    files["run-windows.cmd"] = ("\r\n".join(windows_lines) + "\r\n").encode()
    files["results/.keep"] = b""

    manifest = {
        "schema_version": 2,
        "application_version": APP_VERSION,
        "build_id": BUILD_ID,
        "build_commit": BUILD_COMMIT,
        "campaign": spec.name,
        "display_name": display_name,
        "created_at": created_at,
        "created_by": spec.created_by,
        "scheduled": spec.scheduled,
        "scheduled_by": spec.scheduled_by,
        "executed_by": spec.created_by,
        "execution_method": "generated_package",
        "profile": profile["name"],
        "profile_id": profile["profile_id"],
        "profile_version": profile["version"],
        "profile_settings": profile["settings"],
        "nmap_flags": flags,
        "discovery_mode": profile["settings"].get("discovery_mode", "nmap"),
        "traceroute": bool(profile["settings"].get("traceroute", False)),
        "dns_resolution_disabled": True,
        "no_strike_mode": spec.no_strike_mode,
        "no_strike_count": len(no_strike),
        "global_no_strike": global_no_strike,
        "global_no_strike_count": len(global_no_strike),
        "no_strike_sha256": sha256_bytes(files["no-strike.txt"]),
        "chunking_enabled": campaign_chunking_enabled(spec),
        "chunk_size": spec.chunk_size,
        "chunks": chunks,
        "coverage": {
            **scan_coverage(profile["settings"]),
            "terrain": [segment.model_dump() for segment in spec.terrain],
            "address_count": sum(chunk["address_count"] for chunk in chunks),
            "no_strike_count": len(no_strike),
            "profile_id": profile["profile_id"],
            "profile_name": profile["name"],
            "profile_version": profile["version"],
        },
    }
    files["manifest.json"] = json.dumps(manifest, indent=2).encode() + b"\n"
    readme = f"""# {spec.name} Nmap scan package

Profile: {profile['name']} v{profile['version']}
Created: {manifest['created_at']}
Chunks: {len(chunks)}

## Certification

- DNS resolution is disabled (`-n`).
- Host discovery: `{profile['settings'].get('discovery_mode', 'nmap')}`.
- Nmap traceroute collection: `{'enabled' if profile['settings'].get('traceroute') else 'disabled'}`.
- Every target file has had the certified no-strike addresses removed.
- Every command also uses `--excludefile no-strike.txt` as a second safeguard.
- Chunks never mix terrain segments.
- This application generated these commands; it did not execute Nmap.

## Run

Linux: `chmod +x run-linux.sh && ./run-linux.sh`

Windows: run `run-windows.cmd` from a terminal with Nmap available. FPING-enabled
profiles also require an `fping` executable on the command path.

Return the completed XML files from `results/` to the analyzer.
"""
    files["README.md"] = readme.encode()

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for path, content in files.items():
            info = zipfile.ZipInfo(path)
            info.date_time = datetime.now().timetuple()[:6]
            info.external_attr = (0o755 if path == "run-linux.sh" else 0o644) << 16
            archive.writestr(info, content)
    return f"{display_name}.zip", buffer.getvalue()


def classify_os_group(
    os_name: str,
    os_vendor: str,
    os_family: str,
    device_type: str,
    ports: list[dict],
) -> tuple[str, str, str]:
    """Return a practical family/role group and the evidence used for the role."""
    text = " ".join((os_name, os_vendor, os_family, device_type)).lower()
    if any(word in text for word in ("router", "switch", "firewall", "access point", "printer", "network device")):
        return "Network", "Appliance", "Nmap device classification"
    if "windows" in text or "microsoft" in text:
        family = "Windows"
    elif "linux" in text:
        family = "Linux"
    elif any(word in text for word in ("freebsd", "openbsd", "netbsd", " bsd")):
        family = "BSD"
    elif any(word in text for word in ("mac os", "macos", "darwin", "apple")):
        family = "macOS"
    elif any(word in text for word in ("solaris", "aix", "unix")):
        family = "Unix"
    else:
        family = "Unknown"

    server_ports = {25, 53, 88, 110, 143, 389, 464, 465, 587, 636, 993, 995, 1433, 1521, 2049, 3268, 3269, 3306, 5432, 6379}
    server_services = {
        "domain", "smtp", "ldap", "ldaps", "kerberos", "mysql", "postgresql",
        "ms-sql-s", "oracle", "nfs", "imap", "imaps", "pop3", "pop3s",
    }
    service_text = " ".join(
        f"{port.get('service', '')} {port.get('product', '')}" for port in ports
    ).lower()
    port_ids = {port["port"] for port in ports}
    explicit_server = "server" in text
    infrastructure_service = bool(port_ids & server_ports) or any(
        service in server_services for service in (port.get("service", "").lower() for port in ports)
    )
    web_server = any(product in service_text for product in ("apache", "nginx", "iis", "tomcat"))
    unix_web_service = family in {"Linux", "BSD", "Unix"} and bool(
        port_ids & {80, 443, 8000, 8006, 8080, 8443}
    )
    platform_server = any(
        product in service_text for product in ("proxmox", "uvicorn", "gunicorn", "kubernetes")
    )
    if explicit_server:
        role, basis = "Server", "Nmap OS/device classification"
    elif infrastructure_service or web_server or unix_web_service or platform_server:
        role, basis = "Server", "Server-oriented open services"
    elif family in {"Windows", "Linux", "BSD", "macOS", "Unix"}:
        role, basis = "Workstation", "No server-oriented services detected"
    else:
        role, basis = "Unclassified", "Insufficient OS evidence"
    return family, role, basis


def nmap_xml_coverage(root: ET.Element) -> dict:
    arguments = root.get("args", "")
    try:
        argument_tokens = shlex.split(arguments)
    except ValueError:
        argument_tokens = arguments.split()
    scan_types = []
    protocols: list[str] = []
    for info in root.findall("scaninfo"):
        protocol = (info.get("protocol") or "").upper()
        if protocol and protocol not in protocols:
            protocols.append(protocol)
        scan_types.append(
            {
                "type": info.get("type", ""),
                "protocol": protocol,
                "services": info.get("services", ""),
                "service_count": int(info.get("numservices", "0") or 0),
            }
        )
    if not protocols:
        if "-sU" in argument_tokens:
            protocols.append("UDP")
        if any(flag in argument_tokens for flag in ("-sS", "-sT", "-sA")):
            protocols.append("TCP")
    options_with_values = {
        "-p", "--top-ports", "-e", "--exclude", "--excludefile", "-iL",
        "-oA", "-oG", "-oN", "-oS", "-oX", "--script", "--script-args",
        "--source-port", "-g", "--max-rate", "--min-rate", "--host-timeout",
    }
    target_arguments: list[str] = []
    skip_next = False
    for index, token in enumerate(argument_tokens):
        if index == 0 and token.lower().endswith("nmap"):
            continue
        if skip_next:
            skip_next = False
            continue
        if token in options_with_values:
            skip_next = True
            continue
        if token.startswith("-"):
            continue
        target_arguments.append(token)
    timing = next((token for token in argument_tokens if re.fullmatch(r"-T[0-5]", token)), None)
    return {
        "source": "nmap_xml",
        "protocols": protocols,
        "scan_types": scan_types,
        "command": arguments,
        "timing": timing,
        "dns_resolution_disabled": "-n" in argument_tokens,
        "traceroute": "--traceroute" in argument_tokens,
        "target_arguments": sorted(target_arguments),
    }


def parse_xml(content: bytes) -> dict:
    try:
        root = ET.fromstring(content)
    except ET.ParseError as exc:
        raise ValueError(f"Invalid XML: {exc}") from exc
    if root.tag != "nmaprun":
        raise ValueError("This file is XML, but its root element is not <nmaprun>")

    finished = root.find("./runstats/finished")
    hosts_stats = root.find("./runstats/hosts")
    warnings: list[str] = []
    if finished is None:
        warnings.append("The XML does not contain completed run statistics")

    hosts: list[dict] = []
    port_frequency: Counter[tuple[str, int]] = Counter()
    peer_groups: defaultdict[str, list[str]] = defaultdict(list)
    for host in root.findall("host"):
        state_node = host.find("status")
        state = state_node.get("state", "unknown") if state_node is not None else "unknown"
        state_reason = state_node.get("reason", "") if state_node is not None else ""
        state_reason_ttl = state_node.get("reason_ttl", "") if state_node is not None else ""
        ipv4 = ""
        mac = ""
        vendor = ""
        for address in host.findall("address"):
            if address.get("addrtype") == "ipv4":
                ipv4 = address.get("addr", "")
            elif address.get("addrtype") == "mac":
                mac = address.get("addr", "")
                vendor = address.get("vendor", "")

        hostnames = [
            node.get("name", "")
            for node in host.findall("./hostnames/hostname")
            if node.get("name")
        ]

        osmatch = host.find("./os/osmatch")
        os_name = osmatch.get("name", "") if osmatch is not None else ""
        osclass = host.find("./os/osmatch/osclass")
        device_type = osclass.get("type", "") if osclass is not None else ""
        os_vendor = osclass.get("vendor", "") if osclass is not None else ""
        os_family = osclass.get("osfamily", "") if osclass is not None else ""
        os_generation = osclass.get("osgen", "") if osclass is not None else ""
        ports: list[dict] = []
        observed_ports: list[dict] = []
        open_port_ids: list[int] = []
        for port in host.findall("./ports/port"):
            state_element = port.find("state")
            if state_element is None:
                continue
            port_id = int(port.get("portid", "0"))
            service = port.find("service")
            service_name = service.get("name", "unknown") if service is not None else "unknown"
            product = service.get("product", "") if service is not None else ""
            version = service.get("version", "") if service is not None else ""
            reason = state_element.get("reason", "")
            observation = {
                "port": port_id,
                "protocol": port.get("protocol", ""),
                "state": state_element.get("state", "unknown"),
                "service": service_name,
                "product": product,
                "version": version,
                "reason": reason,
            }
            observed_ports.append(observation)
            if observation["state"] != "open":
                continue
            ports.append(dict(observation))
            open_port_ids.append(port_id)
            port_frequency[(port.get("protocol", ""), port_id)] += 1

        signature = ",".join(
            f"{port['port']}/{port['protocol']}" for port in sorted(
                ports, key=lambda item: (item["port"], item["protocol"])
            )
        ) or "no-open-ports"
        if ipv4:
            peer_groups[signature].append(ipv4)
        family, role, classification_basis = classify_os_group(
            os_name, os_vendor, os_family, device_type, ports
        )
        trace_node = host.find("trace")
        trace = None
        if trace_node is not None:
            trace = {
                "port": trace_node.get("port", ""),
                "protocol": trace_node.get("proto", ""),
                "hops": [
                    {
                        "ttl": int(hop.get("ttl", "0") or 0),
                        "rtt": hop.get("rtt", ""),
                        "ip": hop.get("ipaddr", ""),
                        "hostname": hop.get("host", ""),
                    }
                    for hop in trace_node.findall("hop")
                    if hop.get("ipaddr")
                ],
            }
        host_record = {
            "ip": ipv4,
            "hostname": hostnames[0] if hostnames else "",
            "hostnames": hostnames,
            "state": state,
            "state_reason": state_reason,
            "state_reason_ttl": state_reason_ttl,
            "mac": mac,
            "vendor": vendor,
            "os": os_name,
            "device_type": device_type,
            "os_vendor": os_vendor,
            "os_family": os_family,
            "os_generation": os_generation,
            "os_group": f"{family} {role}" if role != "Unclassified" else "Unclassified",
            "classification_basis": classification_basis,
            "ports": ports,
            "observed_ports": observed_ports,
            "trace": trace,
        }
        host_record["os_inference"] = infer_os_identity(host_record)
        hosts.append(host_record)

    hosts.sort(key=lambda item: ip_sort_key(item.get("ip") or item.get("hostname")))
    up_hosts = [host for host in hosts if host["state"] == "up"]
    reported_total = int(hosts_stats.get("total", "0")) if hosts_stats is not None else len(hosts)
    discovery_reason_counts = Counter(
        host["state_reason"] for host in up_hosts if host.get("state_reason")
    )
    reset_discovered = sum(
        count
        for reason, count in discovery_reason_counts.items()
        if "reset" in reason.lower()
    )
    mac_count = sum(1 for host in hosts if host["mac"])
    nearly_every_target_up = (
        reported_total >= 64
        and len(up_hosts) >= math.ceil(reported_total * 0.95)
    )
    reset_dominated = (
        reset_discovered >= 16
        and reset_discovered >= math.ceil(max(1, len(up_hosts)) * 0.50)
    )
    if nearly_every_target_up and mac_count == 0 and reset_dominated:
        warnings.append(
            "Scan-quality warning: nearly every target was reported up, no MAC addresses "
            f"were observed, and {reset_discovered} hosts were marked up by TCP reset "
            "responses. A translated or proxying path such as Docker Desktop NAT may be "
            "creating false-positive host discovery. Prefer FPING pre-scan or a directly "
            "attached Linux analyzer."
        )
    grouped_hosts: defaultdict[str, list[dict]] = defaultdict(list)
    for host in up_hosts:
        grouped_hosts[host["os_group"]].append(host)

    os_groups: list[dict] = []
    for group_name, members in sorted(grouped_hosts.items()):
        port_members: defaultdict[tuple[str, int], list[dict]] = defaultdict(list)
        port_examples: dict[tuple[str, int], dict] = {}
        for host in members:
            seen_on_host: set[tuple[str, int]] = set()
            for port in host["ports"]:
                key = (port["protocol"], port["port"])
                port_examples.setdefault(key, port)
                if key not in seen_on_host:
                    port_members[key].append(host)
                    seen_on_host.add(key)

        outlier_limit = max(1, math.ceil(len(members) * 0.20))
        outlier_keys = {
            key for key, values in port_members.items()
            if len(members) >= 2 and len(values) <= outlier_limit
        }
        for host in members:
            for port in host["ports"]:
                key = (port["protocol"], port["port"])
                port["outlier"] = key in outlier_keys
                port["group_host_count"] = len(members)
                port["group_port_host_count"] = len(port_members[key])

        outlying_ports = []
        for key in sorted(outlier_keys, key=lambda value: (value[1], value[0])):
            example = port_examples[key]
            affected = port_members[key]
            outlying_ports.append({
                "port": key[1],
                "protocol": key[0],
                "service": example.get("service", "unknown"),
                "product": example.get("product", ""),
                "host_count": len(affected),
                "group_host_count": len(members),
                "prevalence_percent": round((len(affected) / len(members)) * 100, 1),
                "hosts": [host["ip"] for host in affected if host["ip"]],
            })
        os_groups.append({
            "name": group_name,
            "host_count": len(members),
            "outlier_limit": outlier_limit,
            "outlying_ports": outlying_ports,
        })

    rare_ports = [
        {"protocol": key[0], "port": key[1], "host_count": count}
        for key, count in sorted(port_frequency.items(), key=lambda item: (item[0][1], item[0][0]))
        if count <= max(1, len(up_hosts) // 10)
    ]
    return {
        "scanner": root.get("scanner", "nmap"),
        "nmap_version": root.get("version", ""),
        "started": root.get("startstr", ""),
        "finished": finished.get("timestr", "") if finished is not None else "",
        "reported_total": reported_total,
        "host_count": len(hosts),
        "up_count": len(up_hosts),
        "mac_count": mac_count,
        "discovery_reason_counts": dict(sorted(discovery_reason_counts.items())),
        "coverage": nmap_xml_coverage(root),
        "warnings": warnings,
        "hosts": hosts,
        "peer_groups": [
            {"open_ports": signature, "hosts": sorted(values, key=ip_sort_key)}
            for signature, values in sorted(peer_groups.items())
        ],
        "os_groups": os_groups,
        "rare_ports": rare_ports,
    }


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_storage()
    init_poc_storage()
    init_auth_storage(DB_PATH)
    init_workspace_storage(DB_PATH)
    recover_scheduler_state()
    scheduler_stop = threading.Event()
    scheduler_thread = threading.Thread(
        target=schedule_worker,
        args=(scheduler_stop,),
        daemon=True,
        name="scan-scheduler",
    )
    scheduler_thread.start()
    try:
        yield
    finally:
        scheduler_stop.set()
        scheduler_thread.join(timeout=2)


app = FastAPI(title="Nmap Terrain Analyzer", version=APP_VERSION, lifespan=lifespan)
app.include_router(poc_router)
app.include_router(device_config_router)
app.include_router(device_analysis_router)


@app.middleware("http")
async def local_authentication_guard(request: Request, call_next):
    request.state.analyst = None
    if not auth_enabled():
        return await call_next(request)
    public_paths = {"/health", "/login", "/api/auth/login"}
    if request.url.path in public_paths:
        return await call_next(request)
    analyst = session_identity(DB_PATH, request.cookies.get(SESSION_COOKIE))
    if analyst is None:
        if not request.url.path.startswith("/api/"):
            destination = request.url.path
            if request.url.query:
                destination += f"?{request.url.query}"
            return RedirectResponse(f"/login?next={destination}", status_code=303)
        return JSONResponse({"detail": "Authentication required"}, status_code=401)
    request.state.analyst = analyst
    if request.method not in {"GET", "HEAD", "OPTIONS"}:
        origin = request.headers.get("origin")
        if origin and origin.rstrip("/").split("://", 1)[-1] != request.headers.get("host"):
            return JSONResponse({"detail": "Cross-origin changes are not allowed"}, status_code=403)
        if analyst["role"] == "viewer" and request.url.path != "/api/auth/logout":
            return JSONResponse({"detail": "Viewer accounts cannot make changes"}, status_code=403)
    return await call_next(request)


@app.get("/health")
def health() -> dict:
    return {
        "status": "ok",
        "version": APP_VERSION,
        "build_id": BUILD_ID,
        "build_commit": BUILD_COMMIT,
    }


@app.get("/login", response_class=HTMLResponse)
def login_page() -> HTMLResponse:
    if not auth_enabled():
        return RedirectResponse("/", status_code=303)
    return HTMLResponse('''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>NCT · Sign in</title><style>:root{color-scheme:dark}*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:#07121a;color:#eaf4f8;font:16px system-ui}.card{width:min(420px,calc(100vw - 32px));padding:28px;border:1px solid #315367;border-radius:14px;background:#0d1c26;box-shadow:0 24px 70px #0009}h1{margin:0;text-align:center;letter-spacing:.25em}p{color:#a9c3cf}form{display:grid;gap:12px}label{font-weight:750}input,button{width:100%;padding:12px;border:1px solid #3c6072;border-radius:8px;background:#091722;color:inherit;font:inherit}button{margin-top:6px;background:#57d6bf;color:#06201d;font-weight:850;cursor:pointer}.bad{color:#ff9f9f}</style></head><body><main class="card"><h1>N C T</h1><p>Network Characterization Tool · Analyst sign in</p><form id="login"><label for="username">Username</label><input id="username" autocomplete="username" required><label for="password">Password</label><input id="password" type="password" autocomplete="current-password" required><div id="status" role="status"></div><button>Sign in</button></form></main><script>const form=document.getElementById('login'),status=document.getElementById('status');form.onsubmit=async event=>{event.preventDefault();status.textContent='Signing in…';status.className='';const response=await fetch('/api/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:username.value,password:password.value})}),data=await response.json();if(!response.ok){status.textContent=data.detail||'Sign in failed';status.className='bad';return}const next=new URLSearchParams(location.search).get('next')||'/';location.href=next.startsWith('/')&&!next.startsWith('//')?next:'/'};</script></body></html>''')


@app.post("/api/auth/login")
def login(request: LoginRequest) -> Response:
    if not auth_enabled():
        raise HTTPException(status_code=409, detail="Local authentication is disabled")
    analyst = verify_credentials(DB_PATH, request.username, request.password)
    if analyst is None:
        raise HTTPException(status_code=401, detail="Username or password is incorrect")
    token, expires_at = create_session(DB_PATH, analyst["username"])
    response = JSONResponse({"authenticated": True, "analyst": analyst, "expires_at": expires_at})
    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=session_hours() * 3600,
        httponly=True,
        secure=cookie_secure(),
        samesite="strict",
        path="/",
    )
    return response


@app.post("/api/auth/logout")
def logout(request: Request) -> Response:
    end_session(DB_PATH, request.cookies.get(SESSION_COOKIE))
    response = JSONResponse({"authenticated": False})
    response.delete_cookie(SESSION_COOKIE, path="/", samesite="strict")
    return response


@app.get("/api/auth/me")
def current_analyst(request: Request) -> dict:
    return {
        "authentication_enabled": auth_enabled(),
        "analyst": request.state.analyst,
    }


def require_admin(request: Request) -> dict:
    analyst = request.state.analyst
    if analyst is None or analyst.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Administrator role required")
    return analyst


@app.get("/api/auth/users")
def analyst_users(request: Request) -> list[dict]:
    require_admin(request)
    return list_users(DB_PATH)


@app.post("/api/auth/users")
def add_analyst_user(request: Request, user: AnalystUserRequest) -> dict:
    actor = require_admin(request)
    try:
        return create_user(DB_PATH, **user.model_dump(), created_by=actor["username"])
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.get("/api/workspaces/layouts")
def workspace_layouts(request: Request) -> dict:
    if not auth_enabled():
        return {"server_persistence": False, "layouts": []}
    analyst = request.state.analyst
    return {
        "server_persistence": True,
        "analyst": analyst,
        "layouts": list_layouts(DB_PATH, analyst["username"]),
    }


@app.post("/api/workspaces/layouts")
def store_workspace_layout(request: Request, layout: WorkspaceLayoutRequest) -> dict:
    if not auth_enabled() or request.state.analyst is None:
        raise HTTPException(status_code=409, detail="Server workspaces require authenticated mode")
    try:
        return save_layout(
            DB_PATH,
            owner=request.state.analyst["username"],
            **layout.model_dump(),
        )
    except WorkspaceConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Personal layout not found") from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.delete("/api/workspaces/layouts/{layout_id}")
def remove_workspace_layout(request: Request, layout_id: str, expected_version: int) -> dict:
    if not auth_enabled() or request.state.analyst is None:
        raise HTTPException(status_code=409, detail="Server workspaces require authenticated mode")
    try:
        return delete_layout(
            DB_PATH,
            owner=request.state.analyst["username"],
            layout_id=layout_id,
            expected_version=expected_version,
        )
    except WorkspaceConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Personal layout not found") from exc


@app.post("/api/workspaces/layouts/{layout_id}/publish")
def share_workspace_layout(
    request: Request, layout_id: str, publish: WorkspacePublishRequest
) -> dict:
    actor = require_admin(request)
    try:
        return publish_layout(
            DB_PATH,
            layout_id=layout_id,
            actor=actor["username"],
            shared=publish.shared,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Layout not found") from exc


@app.get("/api/os-overrides")
def get_os_overrides() -> list[dict]:
    return list_os_overrides(DB_PATH)


@app.get("/api/os-overrides/history")
def get_os_override_history(identity_key: str) -> list[dict]:
    return os_override_history(DB_PATH, identity_key)


@app.post("/api/os-overrides")
def save_os_override(http_request: Request, request: OsOverrideRequest) -> dict:
    try:
        values = request.model_dump()
        if http_request.state.analyst:
            values["analyst"] = http_request.state.analyst["username"]
        return set_os_override(DB_PATH, **values)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.delete("/api/os-overrides/{identity_key}")
def remove_os_override(
    http_request: Request, identity_key: str, request: OsOverrideDeleteRequest
) -> dict:
    try:
        analyst = (
            http_request.state.analyst["username"]
            if http_request.state.analyst else request.analyst
        )
        return delete_os_override(
            DB_PATH, identity_key, analyst=analyst, reason=request.reason
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="OS correction not found") from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.get("/api/os-inference-reviews/history")
def get_os_inference_review_history(identity_key: str) -> list[dict]:
    return inference_review_history(DB_PATH, identity_key)


@app.post("/api/os-inference-reviews")
def save_os_inference_review(
    http_request: Request, request: OsInferenceReviewRequest
) -> dict:
    try:
        values = request.model_dump()
        if http_request.state.analyst:
            values["analyst"] = http_request.state.analyst["username"]
        return set_inference_review(DB_PATH, **values)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.post("/api/packages")
def create_package(spec: CampaignSpec) -> StreamingResponse:
    try:
        filename, content = build_package(spec)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    digest = sha256_bytes(content)
    stored_name = f"{Path(filename).stem}-{digest[:12]}.zip"
    (PACKAGE_DIR / stored_name).write_bytes(content)
    return StreamingResponse(
        io.BytesIO(content),
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-Server-Package": f"/opt/nmap-analyzer/data/packages/{stored_name}",
        },
    )


@app.post("/api/preview")
def preview_commands(spec: CampaignSpec) -> dict:
    try:
        _, flags, chunks = build_scan_plan(spec)
        profile = resolve_campaign_profile(spec)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    commands = [chunk["linux_command"] for chunk in chunks]
    return {
        "profile": profile["name"],
        "profile_id": profile["profile_id"],
        "profile_version": profile["version"],
        "coverage": scan_coverage(profile["settings"]),
        "nmap_flags": flags,
        "command_count": len(commands),
        "commands": commands,
        "copy_text": "\n".join(commands),
    }


@app.post("/api/import")
async def import_xml(file: Annotated[UploadFile, File()]) -> dict:
    content = await file.read()
    if not content:
        raise HTTPException(status_code=422, detail="The uploaded file is empty")
    if len(content) > 100 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="The XML file exceeds the 100 MB import limit")
    try:
        analysis = parse_xml(content)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    digest = sha256_bytes(content)
    original_name = safe_name(file.filename or "scan.xml", "scan.xml")
    stored_name = f"{digest[:12]}-{original_name}"
    stored_path = IMPORT_DIR / stored_name
    duplicate = stored_path.exists()
    if not duplicate:
        stored_path.write_bytes(content)
    imported_at = utc_now()
    imported_moment = datetime.fromisoformat(imported_at)
    metadata = {
        "display_name": scan_display_name(Path(original_name).stem, when=imported_moment),
        "created_at": imported_at,
        "created_by": "imported file",
        "scheduled": False,
        "scheduled_by": None,
        "executed_by": None,
        "execution_method": "imported",
        "source_filename": original_name,
        "coverage": analysis.get("coverage", {}),
    }
    with sqlite3.connect(DB_PATH) as db:
        db.execute(
            """
            INSERT OR IGNORE INTO imports (
                sha256, filename, stored_path, imported_at, analysis_json, metadata_json
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                digest, original_name, str(stored_path), imported_at,
                json.dumps(analysis), json.dumps(metadata),
            ),
        )
        row = db.execute(
            "SELECT imported_at, metadata_json FROM imports WHERE sha256 = ?", (digest,)
        ).fetchone()
    if row:
        imported_at = row[0]
        metadata = json.loads(row[1] or "{}")
    from app.network_map import build_topology
    response_analysis = enrich_analysis_macs(
        analysis,
        build_topology(),
        direct_source_label=original_name,
        direct_source_url=f"/api/imports/{digest}/raw",
    )
    apply_analysis_os_overrides(response_analysis, DB_PATH)
    return {
        "sha256": digest,
        "duplicate": duplicate,
        "original_preserved": True,
        "imported_at": imported_at,
        "metadata": metadata,
        "analysis": response_analysis,
    }


@app.get("/api/scan-runs/{run_id}/analysis")
def analyze_scan_run(run_id: str) -> dict:
    manifest = get_scan_run_plan(run_id)
    if manifest is None:
        raise HTTPException(status_code=404, detail="Scan run not found")
    manifests = list_scan_run_plans(limit=5000)
    group_key = run_group_key(manifest)
    group = [item for item in manifests if run_group_key(item) == group_key]
    if not group:
        group = [manifest]
    if not all((run_directory(item["run_id"]) / "scan.xml").is_file() for item in group):
        raise HTTPException(status_code=409, detail="This scan does not have completed XML results yet")
    try:
        analysis = _run_group_analysis(group)
    except (OSError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    description = describe_run_group(group)
    from app.network_map import build_topology
    analysis = enrich_analysis_macs(
        analysis,
        build_topology(),
        direct_source_label=description.get("display_name") or "Automated Nmap scan",
        direct_source_url=f"/api/scan-runs/{run_id}/artifacts/xml",
    )
    apply_analysis_os_overrides(analysis, DB_PATH)
    return {
        "run_id": run_id,
        "display_name": manifest.get("display_name") or f"Scan {run_id[:8]}",
        "comparison_name": _comparison_name(group, description),
        "metadata": {**manifest, "group": description},
        "analysis": analysis,
    }


def _run_group_analysis(manifests: list[dict]) -> dict:
    analyses = []
    for manifest in manifests:
        xml_path = run_directory(manifest["run_id"]) / "scan.xml"
        if not xml_path.is_file():
            raise FileNotFoundError(manifest["run_id"])
        analyses.append(parse_xml(xml_path.read_bytes()))
    merged = merge_analyses(analyses)
    partial_notes = [
        str(manifest.get("execution_note") or "A scan phase did not complete.")
        for manifest in manifests
        if manifest.get("partial_results")
    ]
    if partial_notes:
        merged["warnings"] = list(dict.fromkeys([
            *(merged.get("warnings") or []),
            *[f"Partial scan evidence: {note}" for note in partial_notes],
        ]))
        merged.setdefault("coverage", {})["partial_results"] = True
    return merged


def _run_group_analysis_with_overrides(manifests: list[dict]) -> dict:
    """Apply current analyst identity only to presentation/correlation views."""
    return apply_analysis_os_overrides(_run_group_analysis(manifests), DB_PATH)


def _comparison_evidence(manifests: list[dict], description: dict | None = None) -> dict:
    description = description or describe_run_group(manifests)
    return {
        "label": description.get("display_name") or "Automated scan",
        "run_ids": description.get("run_ids") or [],
        "sources": [
            {
                "label": f"{item.get('display_name') or item['run_id']} XML",
                "url": f"/api/scan-runs/{item['run_id']}/artifacts/xml",
            }
            for item in manifests
        ],
    }


def _comparison_name(manifests: list[dict], description: dict | None = None) -> str:
    description = description or describe_run_group(manifests)
    first = manifests[0]
    mode = "Scheduled" if first.get("scheduled") or first.get("schedule_id") else "Manual"
    profile = first.get("profile") or first.get("profile_name") or "Run-specific"
    version = first.get("profile_version")
    profile_label = f"{profile} v{version}" if version else profile
    scope = ", ".join(description.get("scope", {}).get("targets") or []) or "scope unavailable"
    completed = description.get("completed_at") or description.get("created_at") or "time unavailable"
    return f"{description.get('display_name') or 'Scan'} · {mode} · {completed} · {scope} · {profile_label}"


def _hunting_group(selected_id: str) -> list[dict]:
    manifests = list_scan_run_plans(limit=5000)
    group = next(
        (
            items
            for items in group_run_manifests(manifests)
            if any(item.get("run_id") == selected_id for item in items)
        ),
        None,
    )
    if group is None:
        raise HTTPException(status_code=404, detail="Scan result was not found")
    if not all((run_directory(item["run_id"]) / "scan.xml").is_file() for item in group):
        raise HTTPException(
            status_code=409,
            detail="This scan does not retain completed XML for every chunk",
        )
    return group


def _hunting_scope_tokens(group: list[dict]) -> tuple[str, ...]:
    first = group[0]
    saved_ids = sorted({
        str(item)
        for manifest in group
        for item in (manifest.get("saved_network_ids") or [])
        if item
    })
    if saved_ids:
        return tuple(f"saved:{item}" for item in saved_ids)
    targets = sorted({
        str(item)
        for manifest in group
        for item in (
            (manifest.get("target_selection") or {}).get("manual_targets")
            or manifest.get("targets")
            or (manifest.get("coverage") or {}).get("targets")
            or []
        )
        if item
    })
    return tuple(f"target:{item}" for item in targets) or (
        f"run:{first.get('run_id')}",
    )


def _hunting_subnets(group: list[dict]) -> list[str]:
    values = []
    for manifest in group:
        values.extend(
            item.get("cidr")
            for item in (manifest.get("saved_networks") or [])
            if item.get("cidr")
        )
        values.extend(
            (manifest.get("target_selection") or {}).get("manual_targets")
            or manifest.get("targets")
            or (manifest.get("coverage") or {}).get("targets")
            or []
        )
    return list(dict.fromkeys(str(item) for item in values if item))


def _latest_hunting_groups() -> list[list[dict]]:
    manifests = list_scan_run_plans(limit=5000)
    for manifest in manifests:
        manifest["_comparison_xml_available"] = (
            run_directory(manifest["run_id"]) / "scan.xml"
        ).is_file()
    groups = [
        group for group in group_run_manifests(manifests)
        if group_is_comparable(group)
    ]
    groups.sort(
        key=lambda group: describe_run_group(group).get("completed_at")
        or describe_run_group(group).get("created_at") or "",
        reverse=True,
    )
    selected, covered = [], set()
    for group in groups:
        tokens = set(_hunting_scope_tokens(group))
        if tokens and tokens.issubset(covered):
            continue
        selected.append(group)
        covered.update(tokens)
    return selected


@app.get("/api/hunting/network")
def analyze_hunting_network() -> dict:
    from app.network_map import build_topology

    groups = _latest_hunting_groups()
    analyses, sources, scope_summaries = [], [], []
    for group in groups:
        description = describe_run_group(group)
        evidence = _comparison_evidence(group, description)
        source = {
            **description,
            "comparison_name": _comparison_name(group, description),
            "evidence": evidence,
        }
        analyses.append(build_hunting_analysis(
            _run_group_analysis_with_overrides(group),
            evidence=source,
            subnets=_hunting_subnets(group),
        ))
        sources.extend(evidence.get("sources") or [])
        scope_summaries.append({
            "display_name": description.get("display_name"),
            "completed_at": description.get("completed_at")
            or description.get("created_at"),
            "subnets": _hunting_subnets(group),
            "run_ids": description.get("run_ids") or [],
        })
    result = correlate_hunting_identity(merge_hunting_analyses(
        analyses,
        source={
            "display_name": "Latest network-wide evidence",
            "comparison_name": (
                f"Newest completed evidence from {len(groups)} network scope"
                f"{'s' if len(groups) != 1 else ''}"
            ),
            "scan_count": len(groups),
            "scope_summaries": scope_summaries,
            "evidence": {"label": "Latest network evidence", "sources": sources},
        },
    ), build_topology(), include_configuration_devices=True)
    result["status"] = "hunting_network_complete"
    return result


@app.get("/api/hunting/compare")
def compare_hunting_scans(before: str, after: str) -> dict:
    if before == after:
        raise HTTPException(status_code=422, detail="Choose two different scans")
    before_group, after_group = _hunting_group(before), _hunting_group(after)
    before_description = describe_run_group(before_group)
    after_description = describe_run_group(after_group)
    before_result = build_hunting_analysis(
        _run_group_analysis_with_overrides(before_group),
        evidence={
            **before_description,
            "comparison_name": _comparison_name(before_group, before_description),
            "evidence": _comparison_evidence(before_group, before_description),
        },
        subnets=_hunting_subnets(before_group),
    )
    after_result = build_hunting_analysis(
        _run_group_analysis_with_overrides(after_group),
        evidence={
            **after_description,
            "comparison_name": _comparison_name(after_group, after_description),
            "evidence": _comparison_evidence(after_group, after_description),
        },
        subnets=_hunting_subnets(after_group),
    )
    warnings = coverage_warnings(
        representative_coverage(before_group), representative_coverage(after_group)
    )
    return {
        **compare_hunting_results(before_result, after_result),
        "coverage_compatible": not warnings,
        "coverage_warnings": warnings,
    }


@app.get("/api/hunting/{run_id}")
def analyze_hunting_scan(run_id: str) -> dict:
    from app.network_map import build_topology

    group = _hunting_group(run_id)
    description = describe_run_group(group)
    return correlate_hunting_identity(build_hunting_analysis(
        _run_group_analysis_with_overrides(group),
        evidence={
            **description,
            "comparison_name": _comparison_name(group, description),
            "evidence": _comparison_evidence(group, description),
        },
        subnets=_hunting_subnets(group),
    ), build_topology())


@app.get("/api/searchsploit/status")
def get_searchsploit_status() -> dict:
    return searchsploit_status()


@app.post("/api/searchsploit/database/update-online")
def update_searchsploit_database_online() -> dict:
    try:
        return update_searchsploit_from_internet()
    except (OSError, ValueError) as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@app.post("/api/searchsploit/database/upload")
async def upload_searchsploit_database(file: UploadFile = File(...)) -> dict:
    incoming = DATA_DIR / "searchsploit" / ".incoming"
    incoming.mkdir(parents=True, exist_ok=True)
    archive_path = incoming / f"upload-{uuid.uuid4().hex}.archive"
    total = 0
    try:
        with archive_path.open("wb") as output:
            while chunk := await file.read(1024 * 1024):
                total += len(chunk)
                if total > MAX_ARCHIVE_BYTES:
                    raise HTTPException(
                        status_code=413,
                        detail="The update archive is larger than the 1.5 GB limit.",
                    )
                output.write(chunk)
        try:
            return install_searchsploit_archive(
                archive_path,
                source=f"uploaded:{Path(file.filename or 'offline-update').name}",
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
    finally:
        await file.close()
        archive_path.unlink(missing_ok=True)


@app.post("/api/searchsploit/database/rollback/{version_id}")
def rollback_searchsploit_database_version(version_id: str) -> dict:
    try:
        return rollback_searchsploit_database(version_id)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.post("/api/searchsploit/hunting/network")
def searchsploit_hunting_network() -> dict:
    return enrich_hunting_with_searchsploit(analyze_hunting_network())


@app.post("/api/searchsploit/hunting/{run_id}")
def searchsploit_hunting_scan(run_id: str) -> dict:
    return enrich_hunting_with_searchsploit(analyze_hunting_scan(run_id))


@app.get("/api/scan-comparisons/candidates")
def comparison_candidates() -> list[dict]:
    manifests = list_scan_run_plans(limit=5000)
    for manifest in manifests:
        manifest["_comparison_xml_available"] = (
            run_directory(manifest["run_id"]) / "scan.xml"
        ).is_file()
    candidates = []
    for group in group_run_manifests(manifests):
        if not group_is_comparable(group):
            continue
        description = describe_run_group(group)
        first = group[0]
        candidates.append({
            **description,
            "selection_run_id": description["run_ids"][-1],
            "comparison_name": _comparison_name(group, description),
            "scheduled": bool(first.get("scheduled") or first.get("schedule_id")),
            "profile": first.get("profile") or first.get("profile_name"),
            "profile_id": first.get("profile_id"),
            "profile_version": first.get("profile_version"),
            "coverage": representative_coverage(group),
            "evidence": _comparison_evidence(group, description),
        })
    return sorted(candidates, key=lambda item: item.get("completed_at") or item.get("created_at") or "", reverse=True)


@app.get("/api/scan-comparisons/compare")
def compare_selected_scan_groups(first: str, second: str) -> dict:
    manifests = list_scan_run_plans(limit=5000)
    for manifest in manifests:
        manifest["_comparison_xml_available"] = (
            run_directory(manifest["run_id"]) / "scan.xml"
        ).is_file()
    selected_groups = []
    for selected_id in (first, second):
        group = next(
            (items for items in group_run_manifests(manifests) if any(item.get("run_id") == selected_id for item in items)),
            None,
        )
        if group is None:
            raise HTTPException(status_code=404, detail="One or both automated scans were not found")
        if not group_is_comparable(group):
            raise HTTPException(status_code=409, detail="Both scans must be completed and retain XML for every chunk")
        selected_groups.append(group)
    if run_group_key(selected_groups[0][0]) == run_group_key(selected_groups[1][0]):
        raise HTTPException(status_code=422, detail="Choose two different scans")
    selected_groups.sort(key=lambda group: describe_run_group(group).get("completed_at") or describe_run_group(group).get("created_at") or "")
    before_group, after_group = selected_groups
    before_description, after_description = describe_run_group(before_group), describe_run_group(after_group)
    before_evidence = _comparison_evidence(before_group, before_description)
    after_evidence = _comparison_evidence(after_group, after_description)
    result = compare_analyses(
        _run_group_analysis(before_group),
        _run_group_analysis(after_group),
        before_evidence=before_evidence,
        after_evidence=after_evidence,
    )
    warnings = coverage_warnings(
        representative_coverage(before_group), representative_coverage(after_group)
    )
    return {
        "status": "comparison_complete",
        "before": {**before_description, "comparison_name": _comparison_name(before_group, before_description)},
        "after": {**after_description, "comparison_name": _comparison_name(after_group, after_description)},
        "coverage_compatible": not warnings,
        "coverage_warnings": warnings,
        **result,
    }


@app.get("/api/scan-runs/{run_id}/comparison")
def compare_scan_run_to_previous_scope(run_id: str) -> dict:
    manifests = list_scan_run_plans(limit=5000)
    for manifest in manifests:
        manifest["_comparison_xml_available"] = (
            run_directory(manifest["run_id"]) / "scan.xml"
        ).is_file()
    try:
        selected = select_same_scope_baseline(run_id, manifests)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Scan run not found") from exc

    status = selected["status"]
    if status != "baseline_found":
        messages = {
            "current_running": "This scan or one of its chunks is still running.",
            "current_incomplete": (
                "This scan batch is incomplete or does not have XML evidence for every chunk."
            ),
            "no_baseline": (
                "No earlier completed scan has the same effective target scope after exclusions."
            ),
        }
        return {
            "status": status,
            "message": messages[status],
            "current": selected["current"],
            "baseline": None,
        }

    before_manifests = selected.pop("baseline_manifests")
    after_manifests = selected.pop("current_manifests")
    try:
        before_analysis = _run_group_analysis(before_manifests)
        after_analysis = _run_group_analysis(after_manifests)
    except (OSError, ValueError, FileNotFoundError) as exc:
        raise HTTPException(
            status_code=409,
            detail="The selected comparison evidence is incomplete or unreadable",
        ) from exc
    before_evidence = _comparison_evidence(before_manifests, selected["baseline"])
    after_evidence = _comparison_evidence(after_manifests, selected["current"])
    result = compare_analyses(
        before_analysis,
        after_analysis,
        before_evidence=before_evidence,
        after_evidence=after_evidence,
    )
    warnings = coverage_warnings(
        representative_coverage(before_manifests),
        representative_coverage(after_manifests),
    )
    return {
        "status": "baseline_found",
        "message": "Compared with the latest completed scan of the same effective scope.",
        "current": selected["current"],
        "baseline": selected["baseline"],
        "coverage_compatible": not warnings,
        "coverage_warnings": warnings,
        **result,
    }


@app.get("/api/imports/{sha256}/raw")
def download_imported_xml(sha256: str) -> FileResponse:
    with sqlite3.connect(DB_PATH) as db:
        row = db.execute(
            "SELECT filename, stored_path FROM imports WHERE sha256 = ?", (sha256,)
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Import not found")
    path = Path(row[1]).resolve()
    import_root = IMPORT_DIR.resolve()
    if path.parent != import_root or not path.is_file():
        raise HTTPException(status_code=404, detail="Imported XML is not available")
    return FileResponse(path, media_type="application/xml", filename=row[0])


def csv_download(content: bytes, filename: str) -> StreamingResponse:
    return StreamingResponse(
        io.BytesIO(content),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def compact_export_filename(label: str, identifier: str, suffix: str) -> str:
    """Keep recognizable NCT exports comfortably below Windows path limits."""
    stem = safe_name(Path(label).stem, "results")[:36].rstrip("-._") or "results"
    short_id = safe_name(identifier, "export")[:8]
    return f"NCT-{stem}-{short_id}-{suffix}.csv"


@app.get("/api/imports/{sha256}/exports/hosts.csv")
def export_import_host_summary(sha256: str) -> StreamingResponse:
    item = get_import_history_item(sha256)
    if item is None:
        raise HTTPException(status_code=404, detail="Import not found")
    apply_analysis_os_overrides(item["analysis"], DB_PATH)
    return csv_download(
        rows_to_csv(host_summary_rows(item["analysis"]), HOST_SUMMARY_FIELDS),
        compact_export_filename(
            item.get("display_name") or item["filename"], sha256, "hosts"
        ),
    )


@app.get("/api/imports/{sha256}/exports/ports.csv")
def export_import_ports(sha256: str) -> StreamingResponse:
    item = get_import_history_item(sha256)
    if item is None:
        raise HTTPException(status_code=404, detail="Import not found")
    apply_analysis_os_overrides(item["analysis"], DB_PATH)
    return csv_download(
        rows_to_csv(port_level_rows(item["analysis"]), PORT_LEVEL_FIELDS),
        compact_export_filename(
            item.get("display_name") or item["filename"], sha256, "ports"
        ),
    )


HTML = r'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Nmap Terrain Analyzer</title>
<style>
:root{--bg:#091016;--panel:#111c25;--line:#263541;--text:#edf6fb;--muted:#93a8b5;--accent:#53d1b6;--accent2:#64a9ff;--bad:#ff837a;--warn:#ffc66d}*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at top right,#102c35 0,#091016 42%);color:var(--text);font:15px system-ui,sans-serif;min-height:100vh}.wrap{max-width:1080px;margin:auto;padding:38px 20px 70px}header{display:flex;justify-content:space-between;gap:20px;align-items:end;margin-bottom:26px}h1{margin:0;font-size:34px;letter-spacing:-1px}header p{color:var(--muted);margin:7px 0 0}.badge{border:1px solid #327a6d;color:var(--accent);padding:7px 10px;border-radius:99px;font-size:12px;white-space:nowrap}.tabs{display:flex;gap:8px;margin-bottom:14px}.tab{background:#13212b;color:var(--muted);border:1px solid var(--line);padding:10px 15px;border-radius:10px;cursor:pointer}.tab.active{color:#06130f;background:var(--accent);border-color:var(--accent)}.panel{display:none;background:rgba(17,28,37,.94);border:1px solid var(--line);border-radius:16px;padding:24px;box-shadow:0 22px 70px #0005}.panel.active{display:block}.grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}.full{grid-column:1/-1}label{display:block;color:#b9cbd5;font-weight:600;margin-bottom:7px}input,select,textarea{width:100%;background:#0b141b;border:1px solid #344754;color:var(--text);border-radius:9px;padding:11px 12px;font:inherit}textarea{min-height:100px;resize:vertical}.hint{color:var(--muted);font-size:12px;margin-top:6px}.segment{background:#0d171e;border:1px solid var(--line);border-radius:12px;padding:15px;margin-bottom:10px}.row{display:flex;gap:10px}.row>:first-child{flex:1}.remove{width:auto;background:#321b20;border-color:#63313b;color:#ffaaa3}.button{background:var(--accent);border:0;color:#06130f;font-weight:800;padding:12px 17px;border-radius:10px;cursor:pointer;width:auto}.secondary{background:#183144;color:#bfe0fa;border:1px solid #31546b}.actions{display:flex;gap:10px;align-items:center;margin-top:20px}.status{margin-top:18px;padding:13px;border-radius:10px;background:#0b141b;border:1px solid var(--line);color:var(--muted);display:none}.status.show{display:block}.status.error{border-color:#6c3336;color:#ffaaa3}.cards{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin:14px 0}.card{padding:13px;background:#0b141b;border-radius:10px}.card b{font-size:24px;display:block;color:var(--accent2)}table{width:100%;border-collapse:collapse;font-size:13px}th,td{text-align:left;padding:8px;border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--muted)}code{color:#9cd4ff}.filterbar{display:grid;grid-template-columns:2fr 1fr;gap:12px;margin:20px 0}.port-chip{display:block;padding:5px 7px;margin:0 0 4px;border-left:3px solid transparent;border-radius:5px}.port-chip.outlier{background:#4a3218;border-left-color:var(--warn);color:#ffe1ad}.outlier-tag{display:inline-block;margin-left:7px;padding:2px 5px;border-radius:99px;background:var(--warn);color:#291906;font-size:10px;font-weight:900;text-transform:uppercase}.group-label{display:inline-block;margin-top:5px;color:var(--accent2);font-weight:700}.os-inferred{color:#ffe1ad;font-weight:800;text-decoration:underline dotted;text-underline-offset:3px}.os-inferred .badge{margin-left:4px;padding:2px 6px;border-color:#9b762f;color:#ffe1ad}.os-inferred-evidence{display:block;margin-top:4px;color:#d4b77f;font-size:11px;font-weight:500}.outlier-group{margin:12px 0 18px;padding:15px;background:#0b141b;border:1px solid var(--line);border-radius:11px}.outlier-group h4{margin:0 0 8px}.empty{color:var(--muted);font-style:italic}.table-wrap{overflow-x:auto}@media(max-width:700px){.grid,.cards,.filterbar{grid-template-columns:1fr}header{display:block}.badge{display:inline-block;margin-top:12px}}

    #analysis-history-panel { margin-top:18px; padding:16px; border:1px solid #243b47; border-radius:12px; background:rgba(15,29,39,.95); }
    #analysis-history-panel h3 { margin:0 0 6px; }
    .analysis-history-actions { display:flex; flex-wrap:wrap; gap:8px; align-items:center; margin:10px 0; }
    .analysis-history-actions button { border:1px solid #3b6f91; background:#174665; color:#fff; border-radius:7px; padding:8px 11px; font-weight:700; cursor:pointer; }
    .analysis-history-actions button:hover { background:#1d587d; }
    .analysis-history-actions button:disabled { opacity:.55; cursor:not-allowed; }
    .analysis-history-table { width:100%; border-collapse:collapse; font-size:12px; }
    .analysis-history-table th,.analysis-history-table td { text-align:left; vertical-align:top; padding:7px 6px; border-bottom:1px solid #263f49; }
    .analysis-history-table th { color:#9eb0b8; text-transform:uppercase; letter-spacing:.04em; font-size:10px; }
    .analysis-history-table a,.analysis-history-table button { color:#8be1d0; background:none; border:0; cursor:pointer; font:inherit; text-decoration:underline; padding:0; }
    .analysis-history-results { margin-top:12px; padding:12px; border:1px solid #294753; border-radius:8px; background:#0b1b24; }
    .analysis-history-results:empty { display:none; }
    .analysis-history-results ul { margin:6px 0 0; padding-left:20px; }
    .analysis-history-results li { margin:4px 0; }
    .analysis-history-muted { color:#9eb0b8; }
    .analysis-history-good { color:#61d095; }
    .analysis-history-warning { color:#f4c95d; }
    .table-wrap { overflow:visible; }
    .table-wrap thead th,.analysis-history-table thead th { position:sticky; top:0; z-index:2; background:#0b141b; box-shadow:0 2px 0 #344754; }
</style></head><body><main class="wrap">
<header><div><h1>Nmap Terrain Analyzer</h1><p>Build on PythonTool · scan from Kali · return XML for terrain analysis.</p></div><span class="badge">Generator only · never executes Nmap</span></header>
<div class="tabs"><button class="tab active" data-target="generate">Build scan package</button><button class="tab" data-target="analyze">Analyze Nmap XML</button><a href='/operator' style='display:inline-block;margin-left:.5rem;padding:.55rem .9rem;border:1px solid #3b82f6;border-radius:.5rem;color:#bfdbfe;text-decoration:none'>Automated Scan</a><a href='/device-config' style='display:inline-block;margin-left:.5rem;padding:.55rem .9rem;border:1px solid #3b82f6;border-radius:.5rem;color:#bfdbfe;text-decoration:none'>Device Configurations</a><a href="/network-map" style="display:inline-block;margin-left:.5rem;padding:.55rem .9rem;border:1px solid #3b82f6;border-radius:.5rem;color:#bfdbfe;text-decoration:none">Network Map</a></div>
<section id="generate" class="panel active"><form id="campaignForm"><div class="grid">
<div><label>Campaign name</label><input id="campaign" required placeholder="Range exercise 04"></div>
<div><label>Scan profile</label><select id="profile"><option value="standard">Standard · top 1,000 ports</option><option value="comprehensive">Comprehensive · all ports</option></select></div>
<div class="full"><label>Terrain segments</label><div id="segments"></div><button type="button" class="button secondary" id="addSegment">+ Add segment</button><p class="hint">Use IPv4 addresses or CIDRs. Each chunk stays inside its named terrain segment.</p></div>
<div><label>No-strike certification</label><select id="noStrikeMode"><option value="entered">I entered the definitive no-strike list</option><option value="none">There are no no-strike addresses</option></select></div>
<div><label>Addresses per chunk</label><input id="chunkSize" type="number" value="256" min="1" max="4096"></div>
<div class="full" id="noStrikeBox"><label>Definitive no-strike list</label><textarea id="noStrike" placeholder="192.168.1.1&#10;192.168.1.50/32"></textarea><p class="hint">These addresses are removed from target files and also passed to Nmap as an exclusion file.</p></div>
<div class="full"><label>Nmap command preview</label><textarea id="commandPreview" readonly placeholder="Choose your parameters, then generate the command preview."></textarea><div class="actions"><button class="button secondary" type="button" id="previewCommands">Generate command preview</button><button class="button secondary" type="button" id="copyCommands" disabled>Copy all commands</button></div><p class="hint">Commands use files inside the downloaded ZIP. Extract the package on Kali and run them from that folder.</p></div>
</div><div class="actions"><button class="button" type="submit">Certify & download package</button><span class="hint">Both profiles always include <code>-n</code>.</span></div><div id="packageStatus" class="status"></div></form></section>
<section id="analyze" class="panel">
<section id="analysis-history-panel" aria-labelledby="analysis-history-title">
  <h3 id="analysis-history-title">Previous Nmap scans</h3>
  <p class="hint">Reopen a retained Nmap analysis or select exactly two scans to compare hosts, ports, and service changes.</p>
  <div class="analysis-history-actions"><button type="button" id="analysisHistoryRefresh">Refresh history</button><button type="button" id="analysisCompare" disabled>Compare selected scans</button><span id="analysisHistoryStatus" class="analysis-history-muted" role="status" aria-live="polite"></span></div>
  <div id="analysisHistory" class="analysis-history-muted">Loading previous scans…</div>
  <div id="analysisOpenResult" class="analysis-history-results"></div>
  <div id="analysisCompareResult" class="analysis-history-results"></div>
</section>
<form id="xmlForm"><label>Nmap XML result</label><input id="xmlFile" type="file" accept=".xml,text/xml,application/xml" required><p class="hint">The original file and SHA-256 hash are preserved. Import checks completed run statistics and duplicate files.</p><div class="actions"><button class="button" type="submit">Import & analyze</button></div><div id="xmlStatus" class="status"></div><div id="results"></div></form></section>
</main><script>
const q=s=>document.querySelector(s), qa=s=>[...document.querySelectorAll(s)];
qa('.tab').forEach(b=>b.onclick=()=>{qa('.tab,.panel').forEach(x=>x.classList.remove('active'));b.classList.add('active');q('#'+b.dataset.target).classList.add('active')});const requestedTab=location.hash.slice(1);if(requestedTab){const requestedButton=q('.tab[data-target='+requestedTab+']');if(requestedButton)requestedButton.click()}
function addSegment(name='',targets=''){const d=document.createElement('div');d.className='segment';d.innerHTML=`<div class="row"><div><label>Segment name</label><input class="segName" required placeholder="Management" value="${name}"></div><button type="button" class="remove">Remove</button></div><label>Targets</label><textarea class="segTargets" required placeholder="192.168.1.0/24">${targets}</textarea>`;d.querySelector('.remove').onclick=()=>d.remove();q('#segments').appendChild(d)}
q('#addSegment').onclick=()=>addSegment();addSegment('Management','192.168.1.0/24');
q('#noStrikeMode').onchange=()=>q('#noStrikeBox').style.display=q('#noStrikeMode').value==='entered'?'block':'none';
function lines(v){return v.split(/[\n,]+/).map(x=>x.trim()).filter(Boolean)}
function esc(v){return String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
function osIdentity(h){const inference=h.os_inference;if(!inference)return esc(h.os||'Unknown');const evidence=(inference.evidence||[]).join(' · '),title=`Inferred OS · ${inference.confidence||'unspecified'} confidence${evidence?' · '+evidence:''}`;return`<span class="os-inferred" title="${esc(title)}">${esc(inference.family)} <span class="badge">inferred</span><span class="os-inferred-evidence">${esc(inference.confidence||'unspecified')} confidence${evidence?' · '+esc(evidence):''}</span></span>`}
function show(el,msg,error=false){el.className='status show'+(error?' error':'');el.textContent=msg}
function csvCell(v){return '"'+String(v??'').replace(/"/g,'""')+'"'}
function renderAnalysis(a){
 const outlierTotal=(a.os_groups||[]).reduce((n,g)=>n+g.outlying_ports.length,0);
 const options=(a.os_groups||[]).map(g=>`<option value="${esc(g.name)}">${esc(g.name)} (${g.host_count})</option>`).join('');
 const groups=(a.os_groups||[]).map(g=>`<section class="outlier-group" data-outlier-group="${esc(g.name)}"><h4>${esc(g.name)} · ${g.host_count} host${g.host_count===1?'':'s'}</h4>${g.host_count<2?'<p class="empty">At least two hosts in this group are needed to identify outliers.</p>':g.outlying_ports.length?`<div class="table-wrap"><table><thead><tr><th>Outlying port</th><th>Service</th><th>Seen on</th><th>Affected hosts</th></tr></thead><tbody>${g.outlying_ports.map(p=>`<tr><td><strong>${esc(p.port)}/${esc(p.protocol)}</strong></td><td>${esc(p.service)}${p.product?' · '+esc(p.product):''}</td><td>${p.host_count} of ${p.group_host_count} (${p.prevalence_percent}%)</td><td>${p.hosts.map(esc).join('<br>')||'—'}</td></tr>`).join('')}</tbody></table></div>`:'<p class="empty">No ports are statistical outliers in this group.</p>'}</section>`).join('');
 const rows=a.hosts.map((h,index)=>{const search=[h.ip,h.mac,h.vendor,h.os,h.os_family,h.os_generation,h.device_type,h.os_group,h.os_inference?.family,...(h.os_inference?.evidence||[]),...h.ports.flatMap(p=>[p.port,p.protocol,p.service,p.product,p.version])].join(' ').toLowerCase();const ports=h.ports.map(p=>`<span class="port-chip${p.outlier?' outlier':''}" title="Seen on ${p.group_port_host_count||0} of ${p.group_host_count||0} ${esc(h.os_group)} hosts">${esc(p.port)}/${esc(p.protocol)} ${esc(p.service)}${p.product?' · '+esc(p.product):''}${p.outlier?'<span class="outlier-tag">Outlier</span>':''}</span>`).join('')||'None reported';return `<tr class="host-row" data-index="${index}" data-group="${esc(h.os_group)}" data-search="${esc(search)}"><td>${esc(h.ip||'—')}</td><td>${esc(h.state)}</td><td>${esc(h.mac||'—')}<br>${esc(h.vendor||'')}</td><td>${osIdentity(h)}<br><span class="group-label">${esc(h.os_group)}</span><br><span class="hint">${esc(h.classification_basis)}</span></td><td>${ports}</td></tr>`}).join('');
 q('#results').innerHTML=`<div class="cards"><div class="card"><b id="visibleHosts">${a.host_count}</b>matching hosts</div><div class="card"><b>${a.up_count}</b>hosts up</div><div class="card"><b>${outlierTotal}</b>OS-group outlying ports</div></div><div class="filterbar"><div><label>Search results</label><input id="hostSearch" type="search" placeholder="IP, OS, vendor, service, product, or port"></div><div><label>OS / role group</label><select id="osFilter"><option value="">All OS groups</option>${options}</select></div><div class="full"><button type="button" class="button secondary" id="exportCsv">Export visible hosts to CSV</button></div></div><h3>Outlying ports by OS type</h3><p class="hint">A port is highlighted when it appears on only one host in a small peer group, or on no more than 20% of a larger group. Groups need at least two hosts.</p><div id="outlierGroups">${groups||'<p class="empty">No OS groups were detected.</p>'}</div><h3>Host inventory</h3><div class="table-wrap"><table><thead><tr><th>IP</th><th>State</th><th>MAC / vendor</th><th>OS / peer group</th><th>Open services</th></tr></thead><tbody id="hostRows">${rows}</tbody></table></div>`;
 const apply=()=>{const term=q('#hostSearch').value.trim().toLowerCase(),group=q('#osFilter').value;let visible=0;qa('.host-row').forEach(row=>{const showRow=(!group||row.dataset.group===group)&&(!term||row.dataset.search.includes(term));row.style.display=showRow?'':'none';if(showRow)visible++});q('#visibleHosts').textContent=visible;qa('.outlier-group').forEach(card=>card.style.display=(!group||card.dataset.outlierGroup===group)?'':'none')};
 q('#hostSearch').oninput=apply;q('#osFilter').onchange=apply;
 q('#exportCsv').onclick=()=>{const visible=qa('.host-row').filter(row=>row.style.display!=='none').map(row=>a.hosts[+row.dataset.index]);const header=['IP','State','MAC','Vendor','Detected OS','Inferred OS','Inference confidence','Inference evidence','OS family','OS generation','OS role group','Classification basis','Outlying ports','Open services'];const records=visible.map(h=>[h.ip,h.state,h.mac,h.vendor,h.os,h.os_inference?.family,h.os_inference?.confidence,(h.os_inference?.evidence||[]).join('; '),h.os_family,h.os_generation,h.os_group,h.classification_basis,h.ports.filter(p=>p.outlier).map(p=>`${p.port}/${p.protocol} ${p.service} (${p.group_port_host_count} of ${p.group_host_count} peers)`).join('; '),h.ports.map(p=>`${p.port}/${p.protocol} ${p.service}${p.product?' '+p.product:''}${p.version?' '+p.version:''}`).join('; ')]);const csv=[header,...records].map(row=>row.map(csvCell).join(',')).join('\r\n')+'\r\n';const blob=new Blob([csv],{type:'text/csv;charset=utf-8'}),link=document.createElement('a');link.href=URL.createObjectURL(blob);link.download='nmap-terrain-results-'+new Date().toISOString().slice(0,10)+'.csv';link.click();URL.revokeObjectURL(link.href)};
}
function campaignBody(){return{name:q('#campaign').value,profile:q('#profile').value,chunk_size:+q('#chunkSize').value,no_strike_mode:q('#noStrikeMode').value,no_strike:lines(q('#noStrike').value),terrain:qa('.segment').map(d=>({name:d.querySelector('.segName').value,targets:lines(d.querySelector('.segTargets').value)}))}}
q('#previewCommands').onclick=async()=>{const out=q('#commandPreview'),copy=q('#copyCommands');out.value='Generating and validating commands…';copy.disabled=true;try{const r=await fetch('/api/preview',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(campaignBody())});const x=await r.json();if(!r.ok)throw new Error(x.detail||'Command preview failed');out.value=x.copy_text;copy.disabled=false}catch(err){out.value='Error: '+err.message}};
q('#copyCommands').onclick=async()=>{const out=q('#commandPreview');out.focus();out.select();try{if(navigator.clipboard&&window.isSecureContext){await navigator.clipboard.writeText(out.value)}else{document.execCommand('copy')}q('#copyCommands').textContent='Copied';setTimeout(()=>q('#copyCommands').textContent='Copy all commands',1400)}catch(err){q('#copyCommands').textContent='Select and copy manually'}};
q('#campaignForm').onsubmit=async e=>{e.preventDefault();const st=q('#packageStatus');show(st,'Building and certifying the package…');try{const r=await fetch('/api/packages',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(campaignBody())});if(!r.ok){const x=await r.json();throw new Error(x.detail||'Package generation failed')}const serverCopy=r.headers.get('x-server-package')||'';const blob=await r.blob();const a=document.createElement('a');a.href=URL.createObjectURL(blob);const cd=r.headers.get('content-disposition')||'';a.download=(cd.match(/filename="([^"]+)"/)||[])[1]||'nmap-package.zip';a.click();URL.revokeObjectURL(a.href);show(st,'Package certified and downloaded. A runnable copy is also saved on PythonTool at '+serverCopy+'.')}catch(err){show(st,err.message,true)}};
q('#xmlForm').onsubmit=async e=>{e.preventDefault();const st=q('#xmlStatus'),out=q('#results'),f=q('#xmlFile').files[0];show(st,'Preserving and analyzing the original XML…');out.innerHTML='';try{const fd=new FormData();fd.append('file',f);const r=await fetch('/api/import',{method:'POST',body:fd});const x=await r.json();if(!r.ok)throw new Error(x.detail||'Import failed');const a=x.analysis;show(st,(x.duplicate?'Duplicate recognized. ':'Original preserved. ')+`SHA-256: ${x.sha256}`);renderAnalysis(a)}catch(err){show(st,err.message,true)}};
</script><script>
const analysisHistoryEsc = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
let analysisHistoryItems = [];
function analysisHistorySetStatus(message, kind='') { const node=document.getElementById('analysisHistoryStatus'); if(node){node.textContent=message;node.className=kind ? `analysis-history-${kind}` : 'analysis-history-muted';} }
function analysisHistoryPortLabel(port) { return `${port.port ?? '—'}/${port.protocol ?? '—'}${port.service ? ` · ${port.service}` : ''}${port.product ? ` · ${port.product}` : ''}${port.version ? ` ${port.version}` : ''}`; }
function analysisHistoryHostLabel(host) { return host.hostname || host.name || host.ip || 'Unnamed host'; }
function renderAnalysisHistory() {
  const target=document.getElementById('analysisHistory');
  if(!analysisHistoryItems.length){target.innerHTML='<div class="analysis-history-muted">No imported Nmap scans have been retained.</div>';document.getElementById('analysisCompare').disabled=true;return;}
  target.innerHTML=`<table class="analysis-history-table"><thead><tr><th>Select</th><th>File</th><th>Imported</th><th>Hosts</th><th>Actions</th></tr></thead><tbody>${analysisHistoryItems.map(item=>`<tr><td><input type="checkbox" data-analysis-select="${analysisHistoryEsc(item.sha256)}" aria-label="Select ${analysisHistoryEsc(item.filename)} for comparison"></td><td>${analysisHistoryEsc(item.filename)}<br><span class="analysis-history-muted">${analysisHistoryEsc(item.sha256.slice(0,12))}…</span></td><td>${analysisHistoryEsc(item.imported_at)}</td><td>${Number(item.summary?.up_count ?? item.summary?.host_count ?? 0).toLocaleString()} up · ${Number(item.summary?.host_count ?? 0).toLocaleString()} parsed</td><td><button type="button" data-analysis-open="${analysisHistoryEsc(item.sha256)}">Open and analyze</button></td></tr>`).join('')}</tbody></table>`;
  document.querySelectorAll('[data-analysis-select]').forEach(box=>box.onchange=()=>{document.getElementById('analysisCompare').disabled=document.querySelectorAll('[data-analysis-select]:checked').length!==2;});
  document.querySelectorAll('[data-analysis-open]').forEach(button=>button.onclick=()=>openAnalysisHistory(button.dataset.analysisOpen));
}
async function loadAnalysisHistory(){analysisHistorySetStatus('Loading…');try{const response=await fetch('/api/imports?limit=100');const data=await response.json();if(!response.ok)throw new Error(data.detail||'History request failed');analysisHistoryItems=data||[];renderAnalysisHistory();analysisHistorySetStatus(`${analysisHistoryItems.length} retained scan${analysisHistoryItems.length===1?'':'s'}`,'good');}catch(error){document.getElementById('analysisHistory').innerHTML=`<div class="analysis-history-warning">${analysisHistoryEsc(error.message)}</div>`;analysisHistorySetStatus('Unavailable','warning');}}
async function openAnalysisHistory(sha256){const target=document.getElementById('analysisOpenResult');target.innerHTML='<span class="analysis-history-muted">Opening analysis…</span>';try{const response=await fetch(`/api/imports/${encodeURIComponent(sha256)}`);const item=await response.json();if(!response.ok)throw new Error(item.detail||'Analysis could not be opened');const analysis=item.analysis||{};const hosts=analysis.hosts||[];target.innerHTML=`<h3>${analysisHistoryEsc(item.filename)}</h3><div class="analysis-history-muted">Imported ${analysisHistoryEsc(item.imported_at)} · ${hosts.length} parsed host${hosts.length===1?'':'s'} · ${Number(analysis.up_count||0)} up</div><ul>${hosts.map(host=>`<li><strong>${analysisHistoryEsc(analysisHistoryHostLabel(host))}</strong>${host.ip&&host.ip!==analysisHistoryHostLabel(host)?` <code>${analysisHistoryEsc(host.ip)}</code>`:''}${(host.ports||[]).length?`<br><span class="analysis-history-muted">${host.ports.map(analysisHistoryPortLabel).map(analysisHistoryEsc).join(' · ')}</span>`:''}</li>`).join('')||'<li class="analysis-history-muted">No parsed hosts in this result.</li>'}</ul>`;target.scrollIntoView({behavior:'smooth',block:'nearest'});}catch(error){target.innerHTML=`<span class="analysis-history-warning">${analysisHistoryEsc(error.message)}</span>`;}}
async function compareAnalysisHistory(){const selected=[...document.querySelectorAll('[data-analysis-select]:checked')].map(box=>box.dataset.analysisSelect);if(selected.length!==2){analysisHistorySetStatus('Select exactly two scans.','warning');return;}const target=document.getElementById('analysisCompareResult');target.innerHTML='<span class="analysis-history-muted">Comparing selected scans…</span>';try{const response=await fetch(`/api/imports/compare?first=${encodeURIComponent(selected[0])}&second=${encodeURIComponent(selected[1])}`);const result=await response.json();if(!response.ok)throw new Error(result.detail||'Comparison failed');const summary=result.summary||{};const row=(title,items,render)=>items.length?`<h4>${title} (${items.length})</h4><ul>${items.map(render).join('')}</ul>`:'';target.innerHTML=`<h3>Scan comparison</h3><div class="analysis-history-muted">${analysisHistoryEsc(result.before.filename)} → ${analysisHistoryEsc(result.after.filename)}</div><p class="analysis-history-good">${summary.hosts_added||0} hosts added · ${summary.hosts_removed||0} removed · ${summary.hosts_changed||0} changed</p>${row('Hosts added',result.hosts_added||[],host=>`<li>${analysisHistoryEsc(analysisHistoryHostLabel(host))}${host.ip?` <code>${analysisHistoryEsc(host.ip)}</code>`:''}</li>`)}${row('Hosts removed',result.hosts_removed||[],host=>`<li>${analysisHistoryEsc(analysisHistoryHostLabel(host))}${host.ip?` <code>${analysisHistoryEsc(host.ip)}</code>`:''}</li>`)}${row('Hosts changed',result.hosts_changed||[],host=>`<li><strong>${analysisHistoryEsc(host.ip||host.key)}</strong>${host.added_ports?.length?` · added: ${host.added_ports.map(analysisHistoryPortLabel).map(analysisHistoryEsc).join(', ')}`:''}${host.removed_ports?.length?` · removed: ${host.removed_ports.map(analysisHistoryPortLabel).map(analysisHistoryEsc).join(', ')}`:''}${host.service_changes?.length?` · service changes: ${host.service_changes.length}`:''}${Object.keys(host.identity_changes||{}).length?` · identity changes: ${Object.keys(host.identity_changes).join(', ')}`:''}</li>`)}${!summary.hosts_added&&!summary.hosts_removed&&!summary.hosts_changed?'<p class="analysis-history-good">No host, port, service, or identity changes were detected.</p>':''}`;target.scrollIntoView({behavior:'smooth',block:'nearest'});}catch(error){target.innerHTML=`<span class="analysis-history-warning">${analysisHistoryEsc(error.message)}</span>`;}}
document.getElementById('analysisHistoryRefresh')?.addEventListener('click',loadAnalysisHistory);document.getElementById('analysisCompare')?.addEventListener('click',compareAnalysisHistory);loadAnalysisHistory();
</script></body></html>'''


@app.get("/", response_class=HTMLResponse)
def index() -> HTMLResponse:
    return device_config_page()

@app.get('/operator')
def operator():
    return operator_page()

@app.get('/scans')
def scans():
    return operator_page()

@app.get('/analysis')
def analysis():
    return analysis_page()

@app.get('/device-config')
def device_config():
    return device_config_page()

@app.get('/device-analysis')
def device_analysis():
    return device_analysis_page()

@app.get('/hunting')
def hunting():
    return hunting_page()

from app.network_map import router as network_map_router
from app.network_map_ui import network_map_page
app.include_router(network_map_router)

@app.get("/network-map")
def network_map():
    return network_map_page()
