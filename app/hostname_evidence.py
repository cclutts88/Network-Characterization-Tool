from __future__ import annotations

import ipaddress
import json
import re
from datetime import datetime, timezone
from pathlib import Path

from app.device_configs import CONFIG_DIR
from app.host_identities import list_host_identities
from app.hostname_imports import HOSTNAME_EVIDENCE_DIR, list_hostname_evidence
from app.ip_sort import ip_sort_key
from app.topology_neighbors import parse_topology_neighbors


SOURCES = ("nmap", "dhcp", "dns", "lldp", "cdp", "config", "operator")
_HOSTNAME = re.compile(r"^[A-Za-z0-9_](?:[A-Za-z0-9_.-]{0,251}[A-Za-z0-9_])?$", re.I)
_IPV4 = r"(?:\d{1,3}\.){3}\d{1,3}"
_MAC = r"(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}"


def _ip(value: object) -> str | None:
    try:
        parsed = ipaddress.ip_address(str(value or "").strip())
    except ValueError:
        return None
    return str(parsed) if parsed.version == 4 else None


def _hostname(value: object) -> str | None:
    candidate = str(value or "").strip().strip("'\"").rstrip(".")
    if not candidate or len(candidate) > 253 or not _HOSTNAME.fullmatch(candidate):
        return None
    if any(len(label) > 63 for label in candidate.split(".")):
        return None
    return candidate


def _lease_expiry(value: str) -> str | None:
    cleaned = value.strip()
    if cleaned.isdigit() and len(cleaned) >= 9:
        try:
            return datetime.fromtimestamp(int(cleaned), timezone.utc).isoformat()
        except (OSError, OverflowError, ValueError):
            return None
    for pattern in ("%Y/%m/%d %H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(cleaned, pattern).replace(tzinfo=timezone.utc).isoformat()
        except ValueError:
            continue
    return None


def _lease_remaining(expires_at: str | None) -> int | None:
    if not expires_at:
        return None
    try:
        expires = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
    except ValueError:
        return None
    return max(0, int((expires - datetime.now(timezone.utc)).total_seconds()))


def _command_sections(text: str) -> list[tuple[str, str]]:
    headings = list(re.finditer(r"(?m)^=====\s*(.+?)\s*=====\s*$", text))
    if not headings:
        return [("retained output", text)]
    sections: list[tuple[str, str]] = []
    for index, heading in enumerate(headings):
        start = heading.end()
        end = headings[index + 1].start() if index + 1 < len(headings) else len(text)
        sections.append((heading.group(1).strip(), text[start:end]))
    return sections


def parse_retained_hostname_evidence(
    text: str, *, device_ip: str | None = None
) -> list[dict]:
    """Extract attributable hostname candidates from already-retained device output."""
    records: list[dict] = []
    seen: set[tuple[str, str, str]] = set()

    def add(
        ip: object,
        name: object,
        source: str,
        evidence: str,
        lease_expires_at: str | None = None,
    ) -> None:
        address, hostname = _ip(ip), _hostname(name)
        if not address or not hostname:
            return
        key = (address, hostname.casefold(), source)
        if key in seen:
            return
        seen.add(key)
        records.append({
            "ip": address,
            "hostname": hostname,
            "source": source,
            "evidence": evidence.strip()[:1000],
            "lease_expires_at": lease_expires_at,
            "lease_time_left_seconds": _lease_remaining(lease_expires_at),
        })

    static_patterns = (
        re.compile(rf"(?im)^\s*ip\s+host\s+(\S+)(?:\s+\d+)?\s+({_IPV4})\s*$"),
        re.compile(rf"(?im)^\s*set\s+system\s+static-host-mapping(?:\s+host-name)?\s+(\S+)\s+inet\s+({_IPV4})\s*$"),
        re.compile(rf"(?im)^\s*host-record\s*=\s*([^,\s]+)\s*,\s*({_IPV4})\s*$"),
        re.compile(rf"(?im)^\s*address\s*=\s*/([^/\s]+)/({_IPV4})\s*$"),
    )
    for pattern in static_patterns:
        for match in pattern.finditer(text):
            add(match.group(2), match.group(1), "dns", match.group(0))

    for block in re.finditer(rf"(?is)\blease\s+({_IPV4})\s*\{{(.*?)\}}", text):
        body = block.group(2)
        name = re.search(r'(?im)^\s*(?:client-hostname|hostname)\s+"?([^";\s]+)', body)
        ends = re.search(r"(?im)^\s*ends\s+\d+\s+(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})", body)
        expiry = _lease_expiry(ends.group(1)) if ends else None
        if name:
            add(block.group(1), name.group(1), "dhcp", block.group(0), expiry)

    for line in text.splitlines():
        dnsmasq = re.match(rf"^\s*(\d{{9,}})\s+{_MAC}\s+({_IPV4})\s+(\S+)\s+\S+\s*$", line, re.I)
        if dnsmasq:
            add(
                dnsmasq.group(2), dnsmasq.group(3), "dhcp", line,
                _lease_expiry(dnsmasq.group(1)),
            )

    ignored_tail = {
        "active", "inactive", "automatic", "manual", "static", "dynamic",
        "none", "n/a", "unknown", "expired", "offered", "reserved",
    }
    for command, body in _command_sections(text):
        lower_command = command.casefold()
        if "show hosts" in lower_command:
            for line in body.splitlines():
                address = re.search(rf"\b({_IPV4})\b", line)
                name = re.match(r"^\s*([A-Za-z0-9_][A-Za-z0-9_.-]*)\s+", line)
                if address and name and name.group(1).casefold() not in {"host", "default"}:
                    add(address.group(1), name.group(1), "dns", line)
        if "dhcp" in lower_command or "lease" in lower_command:
            for line in body.splitlines():
                address = re.search(rf"\b({_IPV4})\b", line)
                if not address:
                    continue
                tokens = line.split()
                tail = tokens[-1].strip("'\"") if tokens else ""
                if (
                    _hostname(tail)
                    and tail.casefold() not in ignored_tail
                    and not _ip(tail)
                    and not re.fullmatch(_MAC, tail, re.I)
                ):
                    dates = re.findall(r"\d{4}[-/]\d{2}[-/]\d{2}\s+\d{2}:\d{2}:\d{2}", line)
                    expiry = _lease_expiry(dates[-1]) if dates else None
                    add(address.group(1), tail, "dhcp", line, expiry)

    if device_ip:
        local_names = []
        for pattern in (
            r"(?im)^\s*hostname\s+([^\s#;]+)",
            r"(?im)^\s*set\s+system\s+host-name\s+([^\s#;]+)",
            r"(?is)<hostname>\s*([^<\s]+)\s*</hostname>",
        ):
            local_names.extend(match.group(1) for match in re.finditer(pattern, text))
        for name in local_names:
            add(device_ip, name, "config", f"Device configuration hostname: {name}")
    return records


def _latest_device_outputs(config_dir: Path) -> list[tuple[dict, str, str | None]]:
    if not config_dir.exists():
        return []
    manifests: list[tuple[Path, dict]] = []
    for path in config_dir.glob("*/manifest.json"):
        try:
            manifests.append((path, json.loads(path.read_text(encoding="utf-8"))))
        except (OSError, ValueError):
            continue
    manifests.sort(
        key=lambda item: item[1].get("completed_at") or item[1].get("created_at") or "",
        reverse=True,
    )
    selected: list[tuple[dict, str, str | None]] = []
    seen_devices: set[str] = set()
    for manifest_path, manifest in manifests:
        device_key = str(manifest.get("device_address") or "").casefold()
        if not device_key or device_key in seen_devices:
            continue
        run_dir = manifest_path.parent
        candidates = [run_dir / "stdout.txt"]
        candidates.extend(path for path in run_dir.glob("uploaded-*") if path.is_file())
        source_path = next((path for path in candidates if path.is_file()), None)
        if source_path is None:
            continue
        try:
            text = source_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        seen_devices.add(device_key)
        selected.append((manifest, text, source_path.name))
    return selected


def build_hostname_workspace(
    db_path: Path,
    *,
    topology: dict | None = None,
    config_dir: Path | None = None,
    evidence_dir: Path | None = None,
) -> dict:
    """Build an IP-centered hostname review table without contacting the network."""
    if topology is None:
        from app.network_map import build_topology

        topology = build_topology()
    retained = {item["ip"]: item for item in list_host_identities(db_path)}
    rows: dict[str, dict] = {}

    def row_for(ip: str) -> dict:
        return rows.setdefault(ip, {
            "ip": ip,
            "candidates": {source: [] for source in SOURCES},
            "selected_hostname": None,
            "selected_source": None,
            "selection_persisted": False,
        })

    def add_candidate(
        ip: object,
        hostname: object,
        source: str,
        *,
        observed_at: str | None = None,
        evidence_label: str | None = None,
        evidence_url: str | None = None,
        accountability_url: str | None = None,
        lease_expires_at: str | None = None,
        lease_time_left_seconds: int | None = None,
    ) -> None:
        address, name = _ip(ip), _hostname(hostname)
        if not address or not name or source not in SOURCES:
            return
        bucket = row_for(address)["candidates"][source]
        existing = next(
            (item for item in bucket if item["hostname"].casefold() == name.casefold()),
            None,
        )
        candidate = {
            "hostname": name,
            "source": source,
            "observed_at": observed_at,
            "evidence_label": evidence_label,
            "evidence_url": evidence_url,
            "accountability_url": accountability_url,
            "lease_expires_at": lease_expires_at,
            "lease_time_left_seconds": lease_time_left_seconds,
        }
        if existing is None:
            bucket.append(candidate)
        elif (observed_at or "") > (existing.get("observed_at") or ""):
            existing.update(candidate)

    for node in topology.get("nodes") or []:
        addresses = []
        for value in [node.get("ip"), node.get("address"), *(node.get("addresses") or [])]:
            address = _ip(value)
            if address and address not in addresses:
                addresses.append(address)
        hostname = _hostname(node.get("hostname"))
        sources = node.get("sources") or []
        source_kinds = {str(item.get("kind") or "") for item in sources}
        latest_source = max(sources, key=lambda item: item.get("timestamp") or "", default={})
        for address in addresses:
            row_for(address)
            if hostname and source_kinds & {"nmap_import", "automated_nmap"}:
                add_candidate(
                    address, hostname, "nmap",
                    observed_at=latest_source.get("timestamp"),
                    evidence_label="Retained Nmap hostname",
                    evidence_url=latest_source.get("url"),
                )
            if hostname and source_kinds & {"device_configuration", "configuration_output"}:
                add_candidate(
                    address, hostname, "config",
                    observed_at=latest_source.get("timestamp"),
                    evidence_label="Retained device configuration",
                    evidence_url=latest_source.get("url"),
                )
        for observation in node.get("topology_observations") or []:
            protocol = str(observation.get("protocol") or "lldp").casefold()
            if protocol not in {"lldp", "cdp"}:
                protocol = "lldp"
            add_candidate(
                observation.get("management_ip") or node.get("ip"),
                observation.get("neighbor_name"),
                protocol,
                evidence_label=f"Retained {protocol.upper()} neighbor detail",
            )

    device_root = CONFIG_DIR if config_dir is None else config_dir
    for manifest, text, filename in _latest_device_outputs(device_root):
        device_ip = _ip(manifest.get("device_address"))
        run_id = manifest.get("run_id")
        evidence_url = (
            f"/api/device-configs/{run_id}/files/{filename}"
            if run_id and filename else None
        )
        observed_at = manifest.get("completed_at") or manifest.get("created_at")
        for evidence in parse_retained_hostname_evidence(text, device_ip=device_ip):
            add_candidate(
                evidence["ip"], evidence["hostname"], evidence["source"],
                observed_at=observed_at,
                evidence_label=f"{manifest.get('vendor', 'device')} retained output",
                evidence_url=evidence_url,
                lease_expires_at=evidence.get("lease_expires_at"),
                lease_time_left_seconds=evidence.get("lease_time_left_seconds"),
            )
        for neighbor in parse_topology_neighbors(text):
            source = str(neighbor.get("protocol") or "lldp").casefold()
            add_candidate(
                neighbor.get("management_ip"), neighbor.get("neighbor_name"), source,
                observed_at=observed_at,
                evidence_label=f"{source.upper()} neighbor detail",
                evidence_url=evidence_url,
            )

    imported_root = HOSTNAME_EVIDENCE_DIR if evidence_dir is None else evidence_dir
    for evidence in list_hostname_evidence(imported_root):
        expiry = evidence.get("lease_expires_at")
        add_candidate(
            evidence.get("ip"), evidence.get("hostname"), evidence.get("source", ""),
            observed_at=evidence.get("observed_at"),
            evidence_label=evidence.get("evidence_label"),
            evidence_url=evidence.get("evidence_url"),
            accountability_url=evidence.get("accountability_url"),
            lease_expires_at=expiry,
            lease_time_left_seconds=_lease_remaining(expiry),
        )

    for ip, identity in retained.items():
        add_candidate(
            ip, identity.get("hostname"), "operator",
            observed_at=identity.get("imported_at"),
            evidence_label=identity.get("source_filename"),
        )
        row = row_for(ip)
        row["selected_hostname"] = identity.get("hostname")
        row["selected_source"] = identity.get("selection_source") or "operator_import"
        row["selection_persisted"] = True

    default_priority = ("nmap", "config", "lldp", "cdp", "dns", "dhcp")
    for row in rows.values():
        for source in SOURCES:
            row["candidates"][source].sort(
                key=lambda item: (item.get("observed_at") or "", item["hostname"].casefold()),
                reverse=True,
            )
        if not row["selected_hostname"]:
            choice = next(
                (
                    row["candidates"][source][0]
                    for source in default_priority
                    if row["candidates"][source]
                ),
                None,
            )
            if choice:
                row["selected_hostname"] = choice["hostname"]
                row["selected_source"] = choice["source"]

    ordered = sorted(rows.values(), key=lambda item: ip_sort_key(item["ip"]))
    counts = {
        source: sum(bool(row["candidates"][source]) for row in ordered)
        for source in SOURCES
    }
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "network_contacted": False,
        "row_count": len(ordered),
        "selected_count": sum(bool(row["selection_persisted"]) for row in ordered),
        "source_counts": counts,
        "methods": [
            {"source": "nmap", "label": "Nmap", "mode": "retained", "detail": "Reuses hostnames already stored in completed Nmap scans."},
            {"source": "dhcp", "label": "DHCP", "mode": "device_pull", "detail": "Reuses retained lease output and shows time remaining when the source provides it."},
            {"source": "dns", "label": "DNS", "mode": "device_pull", "detail": "Reuses retained host tables and static DNS mappings; it does not issue new lookups."},
            {"source": "lldp", "label": "LLDP / CDP", "mode": "device_pull", "detail": "Reuses neighbor details already collected with router, firewall, and switch pulls."},
            {"source": "operator", "label": "Operator", "mode": "local", "detail": "Uses reviewed entries or CSV/TXT imports without contacting the network."},
        ],
        "rows": ordered,
    }
