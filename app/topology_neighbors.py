from __future__ import annotations

import ipaddress
import re

from app.mac_enrichment import normalize_mac


ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
TOPOLOGY_START_RE = re.compile(
    r"^(?:Device\s+ID\s*:|Local\s+(?:Intf|interface)\s*:|"
    r"Interface\s*:\s*[^,]+,\s*via\s*:\s*(?:LLDP|CDP)\b|Chassis\s+ID\s*:)",
    re.IGNORECASE,
)


def _clean(value: str | None, limit: int = 200) -> str | None:
    cleaned = re.sub(r"\s+", " ", str(value or "").strip(" \t\r\n,;"))
    return cleaned[:limit] or None


def _field(block: str, *patterns: str) -> str | None:
    for pattern in patterns:
        match = re.search(pattern, block, re.IGNORECASE | re.MULTILINE)
        if match:
            return _clean(match.group(1))
    return None


def _valid_ip(value: str | None) -> str | None:
    if not value:
        return None
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


def _neighbor_blocks(text: str) -> list[str]:
    blocks: list[list[str]] = []
    current: list[str] = []
    has_local = False
    has_chassis = False
    for raw_line in ANSI_RE.sub("", text).splitlines():
        line = raw_line.strip()
        start = TOPOLOGY_START_RE.match(line)
        if start:
            is_device = bool(re.match(r"^Device\s+ID\s*:", line, re.I))
            is_local = bool(re.match(r"^Local\s+(?:Intf|interface)\s*:", line, re.I))
            is_via = bool(re.match(r"^Interface\s*:\s*[^,]+,\s*via\s*:", line, re.I))
            is_chassis = bool(re.match(r"^Chassis\s+ID\s*:", line, re.I))
            should_flush = bool(current) and (
                is_device or is_via or (is_local and has_local) or (is_chassis and has_chassis)
            )
            if should_flush:
                blocks.append(current)
                current = []
                has_local = False
                has_chassis = False
            has_local = has_local or is_local or is_via
            has_chassis = has_chassis or is_chassis
        if current or start:
            current.append(raw_line)
    if current:
        blocks.append(current)
    return ["\n".join(lines).strip() for lines in blocks if lines]


def parse_topology_neighbors(text: str) -> list[dict]:
    """Normalize detailed Cisco CDP and common LLDP neighbor output."""
    observations: list[dict] = []
    seen: set[tuple[str, str, str, str, str]] = set()
    for block in _neighbor_blocks(text):
        lower = block.lower()
        protocol = "cdp" if (
            re.search(r"^\s*Device\s+ID\s*:", block, re.I | re.M)
            or "port id (outgoing port)" in lower
            or re.search(r",\s*via\s*:\s*cdp\b", block, re.I)
        ) else "lldp"
        local_interface = _field(
            block,
            r"^\s*Interface\s*:\s*([^,\n]+),\s*Port\s+ID\s*\(outgoing port\)",
            r"^\s*Local\s+(?:Intf|interface)\s*:\s*([^,\n]+)",
            r"^\s*Interface\s*:\s*([^,\n]+),\s*via\s*:\s*(?:LLDP|CDP)",
        )
        remote_port = _field(
            block,
            r"Port\s+ID\s*\(outgoing port\)\s*:\s*([^\n]+)",
            r"^\s*Port\s+(?:ID|id)\s*:\s*([^\n]+)",
            r"^\s*PortID\s*:\s*(?:\S+\s+)?([^\n]+)",
        )
        neighbor_name = _field(
            block,
            r"^\s*Device\s+ID\s*:\s*([^\n]+)",
            r"^\s*System\s+[Nn]ame\s*:\s*([^\n]+)",
            r"^\s*SysName\s*:\s*([^\n]+)",
        )
        chassis_id = _field(
            block,
            r"^\s*Chassis\s+(?:ID|id)\s*:\s*([^\n]+)",
            r"^\s*ChassisID\s*:\s*(?:\S+\s+)?([^\n]+)",
        )
        management_ip = _valid_ip(_field(
            block,
            r"^\s*IP\s+address\s*:\s*((?:\d{1,3}\.){3}\d{1,3})",
            r"^\s*Management\s+(?:address|Address)\s*:\s*((?:\d{1,3}\.){3}\d{1,3})",
            r"^\s*MgmtIP\s*:\s*((?:\d{1,3}\.){3}\d{1,3})",
            r"^\s*IP\s*:\s*((?:\d{1,3}\.){3}\d{1,3})",
        ))
        platform = _field(
            block,
            r"^\s*Platform\s*:\s*(.*?)(?:,\s*Capabilities\s*:|$)",
            r"^\s*System\s+[Dd]escription\s*:\s*([^\n]+)",
            r"^\s*SysDescr\s*:\s*([^\n]+)",
        )
        capabilities = _field(
            block,
            r"^\s*(?:System\s+)?Capabilities\s*:\s*([^\n]+)",
            r"^\s*Enabled\s+Capabilities\s*:\s*([^\n]+)",
            r"\bCapabilities\s*:\s*([^\n]+)",
        )
        chassis_mac = normalize_mac(chassis_id)
        if not (neighbor_name or management_ip or chassis_id):
            continue
        if not (local_interface or remote_port):
            continue
        key = (
            protocol, local_interface or "", remote_port or "",
            management_ip or "", chassis_id or neighbor_name or "",
        )
        if key in seen:
            continue
        seen.add(key)
        observations.append({
            "protocol": protocol,
            "local_interface": local_interface,
            "remote_port": remote_port,
            "neighbor_name": neighbor_name,
            "management_ip": management_ip,
            "chassis_id": chassis_id,
            "chassis_mac": chassis_mac,
            "platform": platform,
            "capabilities": capabilities,
            "confidence": "confirmed",
            "evidence": block[:2000],
        })
    return observations
