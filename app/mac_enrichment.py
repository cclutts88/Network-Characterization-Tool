from __future__ import annotations

import ipaddress
import os
import re
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path


MAC_TOKEN = r"(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}|(?:[0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4}"
MAC_RE = re.compile(rf"(?<![0-9A-Fa-f])({MAC_TOKEN})(?![0-9A-Fa-f])")
IPV4_RE = re.compile(r"(?<![\w.])((?:\d{1,3}\.){3}\d{1,3})(?![\w.])")
IPV4_TOKEN = r"(?:\d{1,3}\.){3}\d{1,3}"
INTERFACE_TOKEN = r"[A-Za-z0-9_.:/-]+"
UNRESOLVED_MARKERS = ("incomplete", "failed", "unresolved", "noarp", "<incomplete>")
DEFAULT_OUI_PATHS = (
    Path("/usr/share/nmap/nmap-mac-prefixes"),
    Path("/usr/local/share/nmap/nmap-mac-prefixes"),
)


def normalize_mac(value: object) -> str | None:
    compact = re.sub(r"[^0-9A-Fa-f]", "", str(value or ""))
    if len(compact) != 12:
        return None
    compact = compact.upper()
    if compact in {"000000000000", "FFFFFFFFFFFF"}:
        return None
    return ":".join(compact[index:index + 2] for index in range(0, 12, 2))


def is_unicast_mac(value: object) -> bool:
    mac = normalize_mac(value)
    return bool(mac and not (int(mac[:2], 16) & 1))


def valid_ip(value: object) -> str | None:
    try:
        parsed = ipaddress.ip_address(str(value))
    except ValueError:
        return None
    return str(parsed)


def _interface_from_neighbor_line(line: str) -> str | None:
    for pattern in (
        r"\bdev\s+([A-Za-z0-9_.:/-]+)",
        r"\bon\s+([A-Za-z0-9_.:/-]+)",
        r"\b(?:ARPA|SNAP)\s+([A-Za-z0-9_.:/-]+)\s*$",
    ):
        match = re.search(pattern, line, re.IGNORECASE)
        if match:
            return match.group(1).rstrip(",")
    tokens = line.split()
    if tokens and re.fullmatch(
        r"(?:eth|ens|enp|bond|br|vlan|ge-|xe-|em|fxp|vtnet|vmx|ix|igb|lagg|Gi|Fa|Te|Eth|Vl)[A-Za-z0-9_.:/-]*",
        tokens[-1],
        re.IGNORECASE,
    ):
        return tokens[-1].rstrip(",")
    return None


def parse_neighbor_text(text: str) -> list[dict]:
    """Parse common ARP/neighbor table formats and omit unresolved entries."""
    patterns = (
        # Linux ip-neighbor output.
        re.compile(
            rf"^(?P<ip>{IPV4_TOKEN})\s+dev\s+(?P<interface>{INTERFACE_TOKEN})\s+lladdr\s+(?P<mac>{MAC_TOKEN})(?:\s|$)",
            re.IGNORECASE,
        ),
        # FreeBSD/pfSense arp -an output.
        re.compile(
            rf"^\S*\s*\((?P<ip>{IPV4_TOKEN})\)\s+at\s+(?P<mac>{MAC_TOKEN})\s+on\s+(?P<interface>{INTERFACE_TOKEN})(?:\s|$)",
            re.IGNORECASE,
        ),
        # Cisco IOS ARP output.
        re.compile(
            rf"^(?:Internet|IPv4)\s+(?P<ip>{IPV4_TOKEN})\s+\S+\s+(?P<mac>{MAC_TOKEN})\s+(?:ARPA|SNAP)\s+(?P<interface>{INTERFACE_TOKEN})(?:\s|$)",
            re.IGNORECASE,
        ),
        # Linux/VyOS arp -n or show arp output.
        re.compile(
            rf"^(?P<ip>{IPV4_TOKEN})\s+(?:ether|lladdr)\s+(?P<mac>{MAC_TOKEN})(?:\s+\S+){{1,3}}\s+(?P<interface>{INTERFACE_TOKEN})\s*$",
            re.IGNORECASE,
        ),
        # Junos show arp no-resolve output.
        re.compile(
            rf"^(?P<mac>{MAC_TOKEN})\s+(?P<ip>{IPV4_TOKEN})\s+(?P<interface>{INTERFACE_TOKEN})(?:\s|$)",
            re.IGNORECASE,
        ),
        # Cisco ASA output: interface, address, MAC, age.
        re.compile(
            rf"^(?P<interface>{INTERFACE_TOKEN})\s+(?P<ip>{IPV4_TOKEN})\s+(?P<mac>{MAC_TOKEN})(?:\s|$)",
            re.IGNORECASE,
        ),
    )
    observations: list[dict] = []
    seen: set[tuple[str, str, str | None]] = set()
    for raw_line in text.splitlines():
        line = raw_line.strip()
        lower = line.lower()
        if not line or any(marker in lower for marker in UNRESOLVED_MARKERS):
            continue
        match = None
        for pattern in patterns:
            match = pattern.match(line)
            if match:
                break
        if not match:
            continue
        mac = normalize_mac(match.group("mac"))
        if not mac or not is_unicast_mac(mac):
            continue
        ip = valid_ip(match.group("ip"))
        if not ip:
            continue
        interface = match.groupdict().get("interface") or _interface_from_neighbor_line(line)
        key = (ip, mac, interface)
        if key in seen:
            continue
        seen.add(key)
        observations.append(
            {
                "ip": ip,
                "mac": mac,
                "interface": interface,
                "protocol": "arp",
                "confidence": "confirmed",
                "evidence": line[:500],
            }
        )
    return observations


def oui_search_paths() -> tuple[Path, ...]:
    configured = os.environ.get("NMAP_MAC_PREFIXES_PATH", "").strip()
    return ((Path(configured),) if configured else ()) + DEFAULT_OUI_PATHS


@lru_cache(maxsize=8)
def _load_oui_file(path_text: str) -> dict[str, str]:
    path = Path(path_text)
    prefixes: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return prefixes
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split(None, 1)
        prefix = re.sub(r"[^0-9A-Fa-f]", "", parts[0]).upper()
        if len(prefix) == 6 and len(parts) == 2 and parts[1].strip():
            prefixes[prefix] = parts[1].strip()
    return prefixes


def lookup_oui_vendor(mac: object, paths: tuple[Path, ...] | None = None) -> dict:
    normalized = normalize_mac(mac)
    if not normalized:
        return {"vendor": None, "source": None, "database": None}
    prefix = normalized.replace(":", "")[:6]
    for path in paths or oui_search_paths():
        vendor = _load_oui_file(str(path.resolve())).get(prefix)
        if vendor:
            return {
                "vendor": vendor,
                "source": "offline_nmap_oui",
                "database": str(path),
            }
    return {"vendor": None, "source": None, "database": None}


def oui_database_info(paths: tuple[Path, ...] | None = None) -> dict:
    for path in paths or oui_search_paths():
        if path.is_file():
            try:
                return {
                    "available": True,
                    "path": str(path),
                    "prefix_count": len(_load_oui_file(str(path.resolve()))),
                    "modified_at": datetime.fromtimestamp(
                        path.stat().st_mtime, timezone.utc
                    ).isoformat(timespec="seconds"),
                }
            except OSError:
                continue
    return {"available": False, "path": None, "prefix_count": 0, "modified_at": None}
