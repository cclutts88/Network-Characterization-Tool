"""Verified reusable Nmap topology-host calculation with legacy output parity."""
from __future__ import annotations

import ipaddress
from pathlib import Path
import xml.etree.ElementTree as ET

from app.derived_contracts import (
    NMAP_TOPOLOGY_FAMILY,
    NMAP_TOPOLOGY_PARAMETERS,
    NMAP_TOPOLOGY_PAYLOAD_SCHEMA_VERSION,
    NMAP_TOPOLOGY_VERSION,
)
from app.nmap_base_analysis import analyze_scan_run_nmap_result


def _valid_ip(value: object) -> str | None:
    try:
        return str(ipaddress.ip_address(str(value)))
    except ValueError:
        return None


def parse_nmap_topology_bytes(content: bytes) -> list[dict]:
    """Preserve the established Map/device-correlation XML interpretation."""
    try:
        root = ET.fromstring(content)
    except ET.ParseError:
        return []
    hosts = []
    for element in root.findall("host"):
        addresses = {
            item.get("addrtype"): item.get("addr")
            for item in element.findall("address")
        }
        ip = _valid_ip(addresses.get("ipv4"))
        if not ip:
            continue
        hostname_el = element.find("hostnames/hostname")
        status_el = element.find("status")
        os_el = element.find("os/osmatch")
        ports = []
        for port_el in element.findall("ports/port"):
            state_el = port_el.find("state")
            if state_el is not None and state_el.get("state") != "open":
                continue
            service_el = port_el.find("service")
            ports.append({
                "port": int(port_el.get("portid", "0")),
                "protocol": port_el.get("protocol"),
                "service": service_el.get("name") if service_el is not None else None,
                "product": service_el.get("product") if service_el is not None else None,
                "version": service_el.get("version") if service_el is not None else None,
            })
        trace_el = element.find("trace")
        hosts.append({
            "ip": ip,
            "hostname": hostname_el.get("name") if hostname_el is not None else None,
            "state": status_el.get("state") if status_el is not None else None,
            "mac": addresses.get("mac"),
            "vendor": next(
                (item.get("vendor") for item in element.findall("address") if item.get("vendor")),
                None,
            ),
            "os": os_el.get("name") if os_el is not None else None,
            "ports": ports,
            "trace": {
                "port": trace_el.get("port", ""),
                "protocol": trace_el.get("proto", ""),
                "hops": [
                    {
                        "ttl": int(hop.get("ttl", "0") or 0),
                        "rtt": hop.get("rtt", ""),
                        "ip": hop.get("ipaddr", ""),
                        "hostname": hop.get("host", ""),
                    }
                    for hop in trace_el.findall("hop")
                    if hop.get("ipaddr")
                ],
            } if trace_el is not None else None,
        })
    return hosts


def analyze_scan_run_nmap_topology(
    db_path: Path,
    run_id: str,
    run_local_path: Path,
    *,
    registration_expected: bool = False,
    analysis_version: str | None = None,
) -> dict:
    return analyze_scan_run_nmap_result(
        db_path,
        run_id,
        run_local_path,
        family=NMAP_TOPOLOGY_FAMILY,
        analysis_version=analysis_version or NMAP_TOPOLOGY_VERSION,
        payload_schema_version=NMAP_TOPOLOGY_PAYLOAD_SCHEMA_VERSION,
        parameters=dict(NMAP_TOPOLOGY_PARAMETERS),
        parser=parse_nmap_topology_bytes,
        registration_expected=registration_expected,
    )
