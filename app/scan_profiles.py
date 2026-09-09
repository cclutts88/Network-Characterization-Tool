from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Mapping


TCP_COMMON_PORTS = "20-23,25,53,80,110,111,135,139,143,389,443,445,587,636,993,995,1433,1521,2049,3306,3389,5432,5900,5985,5986,6379,8000,8080,8443"
UDP_COMMON_PORTS = "53,67,68,69,123,137,138,161,162,500,514,1900,4500,5353"
TCP_ICS_PORTS = "102,502,789,1911,1962,2404,4000,44818,4840,5094,9600,20000,20547,34962-34964"
UDP_ICS_PORTS = "2222,47808"

PROTOCOLS = {"tcp", "udp", "tcp_udp"}
TCP_SCOPES = {"top_1000", "common", "ics", "custom", "all"}
UDP_SCOPES = {"top_100", "common", "ics", "custom", "all"}
TIMINGS = {"conservative", "normal", "fast"}
DISCOVERY_MODES = {"nmap", "fping"}
PORT_EXPRESSION_RE = re.compile(r"^[0-9,\-\s]+$")


DEFAULT_SCAN_OPTIONS = {
    "protocol": "tcp",
    "tcp_scope": "top_1000",
    "tcp_ports": "",
    "udp_scope": "top_100",
    "udp_ports": "",
    "service_detection": True,
    "os_detection": True,
    "timing": "fast",
    "discovery_mode": "nmap",
    "traceroute": False,
}


BUILTIN_PROFILES = (
    {
        "profile_id": "builtin-standard",
        "name": "Standard Characterization",
        "description": "TCP SYN scan of Nmap's top 1,000 ports with service and OS detection.",
        "settings": dict(DEFAULT_SCAN_OPTIONS),
    },
    {
        "profile_id": "builtin-comprehensive",
        "name": "Comprehensive TCP",
        "description": "All TCP ports with service and OS detection.",
        "settings": {**DEFAULT_SCAN_OPTIONS, "tcp_scope": "all"},
    },
    {
        "profile_id": "builtin-quick-discovery",
        "name": "Quick Discovery",
        "description": "Common TCP ports without service or OS fingerprinting.",
        "settings": {
            **DEFAULT_SCAN_OPTIONS,
            "tcp_scope": "common",
            "service_detection": False,
            "os_detection": False,
            "timing": "normal",
        },
    },
    {
        "profile_id": "builtin-ics-safe",
        "name": "ICS Safe Discovery",
        "description": "Conservative TCP and UDP discovery across common industrial-control ports.",
        "settings": {
            **DEFAULT_SCAN_OPTIONS,
            "protocol": "tcp_udp",
            "tcp_scope": "ics",
            "udp_scope": "ics",
            "os_detection": False,
            "timing": "conservative",
        },
    },
)


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def friendly_name(value: str, fallback: str = "Scan") -> str:
    """Return a readable, filename-safe stem while preserving word boundaries."""
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", (value or "").strip())
    cleaned = re.sub(r"_+", "_", cleaned).strip("-._")
    return cleaned[:80] or fallback


def scan_display_name(
    name: str,
    *,
    scheduled: bool = False,
    when: datetime | None = None,
) -> str:
    moment = when or datetime.now(timezone.utc)
    marker = "_(S)" if scheduled else ""
    return f"{friendly_name(name)}{marker}_{moment.strftime('%Y-%m-%d_%H%M')}"


def normalize_port_expression(value: str, label: str) -> str:
    expression = re.sub(r"\s+", "", value or "")
    if not expression or not PORT_EXPRESSION_RE.fullmatch(expression):
        raise ValueError(f"{label} ports must be comma-separated ports or ranges")
    normalized: list[str] = []
    for token in expression.split(","):
        if not token:
            raise ValueError(f"{label} ports contain an empty entry")
        if "-" in token:
            parts = token.split("-")
            if len(parts) != 2 or not all(part.isdigit() for part in parts):
                raise ValueError(f"Invalid {label} port range: {token}")
            start, end = (int(part) for part in parts)
            if not (1 <= start <= end <= 65535):
                raise ValueError(f"Invalid {label} port range: {token}")
            normalized.append(f"{start}-{end}")
        else:
            if not token.isdigit() or not 1 <= int(token) <= 65535:
                raise ValueError(f"Invalid {label} port: {token}")
            normalized.append(str(int(token)))
    return ",".join(normalized)


def normalize_scan_options(value: Mapping[str, object] | None = None) -> dict:
    options = {**DEFAULT_SCAN_OPTIONS, **dict(value or {})}
    protocol = str(options["protocol"])
    tcp_scope = str(options["tcp_scope"])
    udp_scope = str(options["udp_scope"])
    timing = str(options["timing"])
    discovery_mode = str(options.get("discovery_mode", "nmap"))
    if protocol not in PROTOCOLS:
        raise ValueError("Protocol must be TCP, UDP, or TCP + UDP")
    if tcp_scope not in TCP_SCOPES:
        raise ValueError("Unknown TCP port scope")
    if udp_scope not in UDP_SCOPES:
        raise ValueError("Unknown UDP port scope")
    if timing not in TIMINGS:
        raise ValueError("Timing must be conservative, normal, or fast")
    if discovery_mode not in DISCOVERY_MODES:
        raise ValueError("Host discovery must use Nmap or FPING")

    normalized = {
        "protocol": protocol,
        "tcp_scope": tcp_scope,
        "tcp_ports": str(options.get("tcp_ports") or ""),
        "udp_scope": udp_scope,
        "udp_ports": str(options.get("udp_ports") or ""),
        "service_detection": bool(options.get("service_detection", True)),
        "os_detection": bool(options.get("os_detection", True)),
        "timing": timing,
        "discovery_mode": discovery_mode,
        "traceroute": bool(options.get("traceroute", False)),
    }
    if tcp_scope == "custom":
        normalized["tcp_ports"] = normalize_port_expression(normalized["tcp_ports"], "TCP")
    if udp_scope == "custom":
        normalized["udp_ports"] = normalize_port_expression(normalized["udp_ports"], "UDP")
    if protocol == "tcp_udp" and (tcp_scope.startswith("top_") or udp_scope.startswith("top_")):
        raise ValueError(
            "TCP + UDP requires independently defined Common, ICS, Custom, or All port scopes; "
            "Nmap top-port counts cannot be set independently in one combined command"
        )
    return normalized


def _ports_for_scope(scope: str, custom: str, protocol: str) -> tuple[str | None, int | None]:
    if scope.startswith("top_"):
        return None, int(scope.split("_", 1)[1])
    if scope == "all":
        return "1-65535", None
    if scope == "common":
        return (TCP_COMMON_PORTS if protocol == "tcp" else UDP_COMMON_PORTS), None
    if scope == "ics":
        return (TCP_ICS_PORTS if protocol == "tcp" else UDP_ICS_PORTS), None
    return normalize_port_expression(custom, protocol.upper()), None


def build_nmap_flags(value: Mapping[str, object] | None = None) -> list[str]:
    options = normalize_scan_options(value)
    protocol = options["protocol"]
    flags = ["-n"]
    if protocol in {"tcp", "tcp_udp"}:
        flags.append("-sS")
    if protocol in {"udp", "tcp_udp"}:
        flags.append("-sU")
    if options["discovery_mode"] == "fping":
        # FPING already certified these hosts as responsive. Avoid repeating
        # Nmap's host-discovery stage before the requested port scan.
        flags.append("-Pn")
    if options["service_detection"]:
        flags.append("-sV")
    if options["os_detection"]:
        flags.extend(["-O", "--osscan-limit"])
    flags.append("--reason")

    tcp_ports = tcp_top = udp_ports = udp_top = None
    if protocol in {"tcp", "tcp_udp"}:
        tcp_ports, tcp_top = _ports_for_scope(options["tcp_scope"], options["tcp_ports"], "tcp")
    if protocol in {"udp", "tcp_udp"}:
        udp_ports, udp_top = _ports_for_scope(options["udp_scope"], options["udp_ports"], "udp")

    if protocol == "tcp_udp":
        flags.extend(["-p", f"T:{tcp_ports},U:{udp_ports}"])
    elif tcp_top:
        flags.extend(["--top-ports", str(tcp_top)])
    elif udp_top:
        flags.extend(["--top-ports", str(udp_top)])
    else:
        flags.extend(["-p", str(tcp_ports or udp_ports)])

    flags.append({"conservative": "-T2", "normal": "-T3", "fast": "-T4"}[options["timing"]])
    if options["traceroute"]:
        flags.append("--traceroute")
    if "-n" not in flags:
        raise RuntimeError("All generated Nmap commands must include -n")
    return flags


def scan_coverage(value: Mapping[str, object] | None = None) -> dict:
    options = normalize_scan_options(value)
    protocols = {
        "tcp": ["TCP"],
        "udp": ["UDP"],
        "tcp_udp": ["TCP", "UDP"],
    }[options["protocol"]]
    return {
        "protocols": protocols,
        "tcp_scope": options["tcp_scope"] if "TCP" in protocols else None,
        "tcp_ports": options["tcp_ports"] if options["tcp_scope"] == "custom" and "TCP" in protocols else None,
        "udp_scope": options["udp_scope"] if "UDP" in protocols else None,
        "udp_ports": options["udp_ports"] if options["udp_scope"] == "custom" and "UDP" in protocols else None,
        "service_detection": options["service_detection"],
        "os_detection": options["os_detection"],
        "timing": options["timing"],
        "discovery_mode": options["discovery_mode"],
        "traceroute": options["traceroute"],
        "dns_resolution_disabled": True,
    }
