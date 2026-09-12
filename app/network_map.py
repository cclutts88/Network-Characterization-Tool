from __future__ import annotations

import html
import ipaddress
import json
import re
import sqlite3
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter

from app.device_configs import CONFIG_DIR
from app.mac_enrichment import (
    lookup_oui_vendor,
    normalize_mac,
    oui_database_info,
    parse_neighbor_text,
)
from app.poc import DATA_DIR, DB_PATH, RUNS_DIR_NAME
from app.ip_sort import ip_sort_key
from app.topology_neighbors import parse_topology_neighbors


router = APIRouter(prefix="/api/network-map", tags=["network-map"])

IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
CIDR_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}(?![\w.])")
VIA_RE = re.compile(r"\bvia\s+((?:\d{1,3}\.){3}\d{1,3})\b", re.IGNORECASE)
NEXT_HOP_RE = re.compile(r"\bnext-hop\s+['\"]?((?:\d{1,3}\.){3}\d{1,3})\b", re.IGNORECASE)
INTERFACE_RE = re.compile(r"\b(?:dev\s+)?([A-Za-z][A-Za-z0-9_.:/-]{0,31})\b")
DIRECT_MARKERS = ("directly connected", " connected", "direct/", "link#")
MAC_CANDIDATE_RE = re.compile(
    r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}(?![0-9A-Fa-f])"
    r"|(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4}(?![0-9A-Fa-f])"
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def valid_ip(value: object) -> str | None:
    try:
        parsed = ipaddress.ip_address(str(value))
    except ValueError:
        return None
    return str(parsed)


def valid_network(value: object) -> str | None:
    try:
        parsed = ipaddress.ip_network(str(value), strict=False)
    except ValueError:
        return None
    return str(parsed) if parsed.version == 4 else None


def valid_interface_address(value: object) -> str | None:
    try:
        parsed = ipaddress.ip_interface(str(value))
    except ValueError:
        return None
    return str(parsed) if parsed.version == 4 else None


def prefix_from_netmask(value: str) -> int | None:
    value = value.strip().lower()
    try:
        if value.startswith("0x"):
            bits = f"{int(value, 16):032b}"
            if "01" in bits:
                return None
            return bits.count("1")
        return ipaddress.IPv4Network(f"0.0.0.0/{value}").prefixlen
    except (ValueError, ipaddress.NetmaskValueError):
        return None


def source_record(kind: str, label: str, timestamp: str | None, url: str | None = None) -> dict:
    return {"kind": kind, "label": label, "timestamp": timestamp, "url": url}


def add_source(node: dict, source: dict) -> None:
    signature = (source.get("kind"), source.get("label"), source.get("timestamp"))
    existing = {
        (item.get("kind"), item.get("label"), item.get("timestamp"))
        for item in node["sources"]
    }
    if signature not in existing:
        node["sources"].append(source)


def ensure_ip_node(nodes: dict[str, dict], ip: str, **values: object) -> dict:
    node_id = f"ip:{ip}"
    node = nodes.setdefault(
        node_id,
        {
            "id": node_id,
            "kind": "host",
            "label": ip,
            "ip": ip,
            "addresses": [ip],
            "hostname": None,
            "role": None,
            "vendor": None,
            "mac": None,
            "os": None,
            "state": None,
            "services": [],
            "interfaces": [],
            "routes": [],
            "mac_observations": [],
            "scan_observations": [],
            "sources": [],
        },
    )
    if ip not in node.setdefault("addresses", []):
        node["addresses"].append(ip)
    for key in ("hostname", "role", "vendor", "mac", "os", "state"):
        if values.get(key) and not node.get(key):
            node[key] = values[key]
    if values.get("role") in {"router", "firewall"}:
        node["kind"] = "device"
    elif values.get("kind") == "gateway" and node["kind"] == "host":
        node["kind"] = "gateway"
    node["label"] = node.get("hostname") or node.get("role") or ip
    source = values.get("source")
    if isinstance(source, dict):
        add_source(node, source)
    for service in values.get("services") or []:
        signature = (service.get("port"), service.get("protocol"), service.get("service"))
        if signature not in {
            (item.get("port"), item.get("protocol"), item.get("service"))
            for item in node["services"]
        }:
            node["services"].append(service)
    return node


def add_mac_observation(node: dict, observation: dict, source: dict) -> bool:
    """Attach one normalized, attributable MAC observation to a topology node."""
    mac = normalize_mac(observation.get("mac"))
    if not mac:
        return False
    reported_vendor = (observation.get("vendor") or "").strip() or None
    lookup = lookup_oui_vendor(mac)
    vendor = reported_vendor or lookup["vendor"]
    vendor_source = "reported_by_source" if reported_vendor else lookup["source"]
    timestamp = observation.get("timestamp") or source.get("timestamp")
    item = {
        "ip": observation.get("ip") or node.get("ip"),
        "mac": mac,
        "vendor": vendor,
        "vendor_source": vendor_source,
        "protocol": observation.get("protocol") or "ethernet",
        "interface": observation.get("interface"),
        "segment": observation.get("segment"),
        "confidence": observation.get("confidence") or "observed",
        "first_observed": observation.get("first_observed") or timestamp,
        "last_observed": observation.get("last_observed") or timestamp,
        "packet_count": int(observation.get("packet_count") or 1),
        "source_kind": source.get("kind"),
        "source_label": source.get("label"),
        "source_url": source.get("url"),
        "evidence": observation.get("evidence"),
    }
    signature = (
        item["mac"], item["protocol"], item["interface"],
        item["source_kind"], item["source_label"],
    )
    existing = next(
        (
            value for value in node.setdefault("mac_observations", [])
            if (
                value.get("mac"), value.get("protocol"), value.get("interface"),
                value.get("source_kind"), value.get("source_label"),
            ) == signature
        ),
        None,
    )
    if existing:
        if item["first_observed"]:
            existing["first_observed"] = min(
                value for value in (existing.get("first_observed"), item["first_observed"])
                if value
            )
        if item["last_observed"]:
            existing["last_observed"] = max(
                value for value in (existing.get("last_observed"), item["last_observed"])
                if value
            )
        existing["packet_count"] = int(existing.get("packet_count") or 0) + item["packet_count"]
    else:
        node["mac_observations"].append(item)
    if not node.get("mac"):
        node["mac"] = mac
    if vendor and not node.get("vendor"):
        node["vendor"] = vendor
    node["mac_conflict"] = len(
        {value.get("mac") for value in node["mac_observations"] if value.get("mac")}
    ) > 1
    add_source(node, source)
    return True


def ensure_subnet_node(nodes: dict[str, dict], network: str, source: dict | None = None) -> dict:
    node_id = f"subnet:{network}"
    node = nodes.setdefault(
        node_id,
        {
            "id": node_id,
            "kind": "subnet",
            "label": network,
            "network": network,
            # A subnet can be present on more than one device (for example a
            # transit segment).  Keep all owners so the UI can place it near
            # the devices that actually advertise/own the interface.
            "owners": [],
            "sources": [],
        },
    )
    if source:
        add_source(node, source)
    return node


def add_subnet_owner(subnet: dict, owner_id: str | None) -> None:
    if owner_id and owner_id not in subnet.setdefault("owners", []):
        subnet["owners"].append(owner_id)


def apply_subnet_zone(subnet: dict, zone: str | None, source: dict | None = None) -> None:
    """Attach an operator-defined interface/zone label without hiding the CIDR."""
    clean = re.sub(r"\s+", " ", str(zone or "").strip(" \t\r\n'\""))[:80]
    if not clean or clean.lower() in {"none", "null", "interface"}:
        return
    zones = subnet.setdefault("zone_names", [])
    if clean not in zones:
        zones.append(clean)
    subnet["label"] = f"{' / '.join(zones)} · {subnet['network']}"
    if source:
        add_source(subnet, source)


def ensure_interface_node(nodes: dict[str, dict], device: dict, name: str,
                          address: str | None = None, source: dict | None = None,
                          mac: str | None = None) -> dict:
    safe = re.sub(r"[^A-Za-z0-9_.:-]+", "-", name or "interface")[:64]
    node_id = f"interface:{device['ip']}:{safe}"
    node = nodes.setdefault(
        node_id,
        {
            "id": node_id,
            "kind": "interface",
            "label": name or "interface",
            "interface": name or "interface",
            "address": address,
            "addresses": [address] if address else [],
            "device_id": device["id"],
            "device_ip": device["ip"],
            "mac": normalize_mac(mac),
            "mac_observations": [],
            "sources": [],
        },
    )
    if address and not node.get("address"):
        node["address"] = address
    if address and address not in node.setdefault("addresses", []):
        node["addresses"].append(address)
    normalized_mac = normalize_mac(mac)
    if normalized_mac and not node.get("mac"):
        node["mac"] = normalized_mac
    if source:
        add_source(node, source)
    return node


def ensure_topology_neighbor_node(
    nodes: dict[str, dict],
    observation: dict,
    source: dict,
    aliases: dict[str, str],
) -> dict:
    """Resolve an LLDP/CDP neighbor to an existing device or a discovered one."""
    management_ip = valid_ip(observation.get("management_ip"))
    chassis_mac = normalize_mac(observation.get("chassis_mac"))
    neighbor_name = str(observation.get("neighbor_name") or "").strip()
    node = None
    if management_ip and management_ip in aliases and aliases[management_ip] in nodes:
        node = nodes[aliases[management_ip]]
    if node is None and management_ip:
        node = ensure_ip_node(
            nodes, management_ip, hostname=neighbor_name or None, source=source
        )
        aliases[management_ip] = node["id"]
    if node is None and chassis_mac:
        node = next(
            (
                item for item in nodes.values()
                if normalize_mac(item.get("mac")) == chassis_mac
                and item.get("kind") in {"device", "gateway", "host"}
            ),
            None,
        )
    if node is None and neighbor_name:
        lowered = neighbor_name.lower()
        node = next(
            (
                item for item in nodes.values()
                if item.get("kind") in {"device", "gateway", "host"}
                and str(item.get("hostname") or item.get("label") or "").lower() == lowered
            ),
            None,
        )
    if node is None:
        identity = chassis_mac or neighbor_name or observation.get("chassis_id") or "unknown"
        safe_identity = re.sub(r"[^A-Za-z0-9_.:-]+", "-", str(identity))[:100]
        node_id = f"topology:{safe_identity}"
        node = nodes.setdefault(
            node_id,
            {
                "id": node_id,
                "kind": "device",
                "label": neighbor_name or str(identity),
                "ip": None,
                "addresses": [],
                "hostname": neighbor_name or None,
                "role": None,
                "vendor": None,
                "mac": chassis_mac,
                "os": None,
                "state": "observed",
                "services": [],
                "interfaces": [],
                "routes": [],
                "mac_observations": [],
                "scan_observations": [],
                "sources": [],
            },
        )
    if node.get("kind") != "gateway":
        node["kind"] = "device"
    capabilities = str(observation.get("capabilities") or "").lower()
    observed_role = (
        "switch" if any(value in capabilities for value in ("switch", "bridge"))
        else "router" if "router" in capabilities
        else "discovered neighbor"
    )
    node["role"] = node.get("role") or observed_role
    if neighbor_name and not node.get("hostname"):
        node["hostname"] = neighbor_name
    node["label"] = node.get("hostname") or node.get("label") or management_ip or "Network device"
    if observation.get("platform") and not node.get("platform"):
        node["platform"] = observation["platform"]
    if not node.get("vendor"):
        platform = str(observation.get("platform") or "").lower()
        node["vendor"] = next(
            (vendor for vendor in ("cisco", "juniper", "arista", "vyos") if vendor in platform),
            None,
        )
    details = {
        field: observation.get(field)
        for field in (
            "protocol", "local_interface", "remote_port", "neighbor_name",
            "management_ip", "chassis_id", "platform", "capabilities",
        )
        if observation.get(field)
    }
    if details not in node.setdefault("topology_observations", []):
        node["topology_observations"].append(details)
    add_source(node, source)
    if chassis_mac:
        add_mac_observation(
            node,
            {
                "ip": management_ip,
                "mac": chassis_mac,
                "protocol": observation.get("protocol") or "lldp",
                "confidence": "confirmed",
                "evidence": observation.get("evidence"),
            },
            source,
        )
    return node


def add_edge(edges: dict[tuple[str, str, str], dict], source: str, target: str, relation: str,
             label: str, confidence: str, evidence: str | None = None,
             interface_label: bool = False) -> None:
    key = (source, target, relation)
    if key not in edges:
        edges[key] = {
            "id": f"edge:{len(edges) + 1}",
            "source": source,
            "target": target,
            "relation": relation,
            "label": label,
            "confidence": confidence,
            "evidence": evidence,
            "interface_label": interface_label,
        }


def os_label(host: dict) -> str | None:
    group = host.get("os_group")
    if isinstance(group, str) and group.strip():
        return group.strip()
    group = group if isinstance(group, dict) else {}
    pieces = [
        group.get("vendor") or host.get("os_vendor"),
        group.get("family") or host.get("os_family"),
        group.get("generation") or host.get("os_generation"),
    ]
    label = " ".join(str(piece) for piece in pieces if piece)
    return label or host.get("os") or None


def add_analysis_hosts(
    nodes: dict[str, dict],
    analysis: dict,
    source: dict,
    edges: dict[tuple[str, str, str], dict] | None = None,
) -> int:
    added = 0
    for host in analysis.get("hosts") or []:
        ip = valid_ip(host.get("ip"))
        if not ip:
            continue
        services = []
        for port in host.get("ports") or []:
            services.append(
                {
                    "port": port.get("port"),
                    "protocol": port.get("protocol"),
                    "service": port.get("service"),
                    "product": port.get("product"),
                    "version": port.get("version"),
                }
            )
        destination = ensure_ip_node(
            nodes,
            ip,
            hostname=host.get("hostname") or host.get("name"),
            state=host.get("state"),
            mac=host.get("mac"),
            vendor=host.get("vendor"),
            os=os_label(host),
            services=services,
            source=source,
        )
        scan_observation = {
            "ip": ip,
            "source_kind": source.get("kind"),
            "source_label": source.get("label"),
            "timestamp": source.get("timestamp"),
            "source_url": source.get("url"),
        }
        if scan_observation not in destination.setdefault("scan_observations", []):
            destination["scan_observations"].append(scan_observation)
        if host.get("mac"):
            add_mac_observation(
                destination,
                {
                    "ip": ip,
                    "mac": host.get("mac"),
                    "vendor": host.get("vendor"),
                    "protocol": "nmap",
                    "confidence": "confirmed",
                    "evidence": "MAC address reported in Nmap XML",
                },
                source,
            )
        trace = host.get("trace") or {}
        hops = trace.get("hops") or []
        if hops:
            path = []
            previous_id = None
            for hop in hops:
                hop_ip = valid_ip(hop.get("ip"))
                if not hop_ip:
                    continue
                hop_node = (
                    destination
                    if hop_ip == ip
                    else ensure_ip_node(
                        nodes,
                        hop_ip,
                        hostname=hop.get("hostname"),
                        kind="gateway",
                        source=source,
                    )
                )
                path.append(
                    {
                        "ttl": hop.get("ttl"),
                        "rtt": hop.get("rtt"),
                        "ip": hop_ip,
                        "hostname": hop.get("hostname"),
                    }
                )
                if edges is not None and previous_id and previous_id != hop_node["id"]:
                    add_edge(
                        edges,
                        previous_id,
                        hop_node["id"],
                        "trace_hop",
                        f"TTL {hop.get('ttl') or '?'} · {hop.get('rtt') or '?'} ms",
                        "observed",
                        "Nmap traceroute",
                        True,
                    )
                previous_id = hop_node["id"]
            if path:
                destination.setdefault("paths", []).append(
                    {
                        "protocol": trace.get("protocol"),
                        "port": trace.get("port"),
                        "hops": path,
                        "source": source,
                    }
                )
                if edges is not None and previous_id and previous_id != destination["id"]:
                    add_edge(
                        edges,
                        previous_id,
                        destination["id"],
                        "trace_destination",
                        "Observed destination",
                        "observed",
                        "Nmap traceroute",
                        True,
                    )
        added += 1
    return added


def imported_hosts(nodes: dict[str, dict], edges: dict, warnings: list[str]) -> int:
    db = None
    try:
        db = sqlite3.connect(DB_PATH)
        rows = db.execute(
            "SELECT sha256, filename, imported_at, analysis_json FROM imports "
            "ORDER BY imported_at DESC LIMIT 200"
        ).fetchall()
    except sqlite3.Error:
        return 0
    finally:
        if db is not None:
            db.close()
    count = 0
    for sha256, filename, imported_at, analysis_json in rows:
        try:
            analysis = json.loads(analysis_json)
        except (TypeError, json.JSONDecodeError):
            warnings.append(f"Could not read analyzed import {filename}")
            continue
        source = source_record(
            "nmap_import", filename, imported_at, f"/api/imports/{sha256}"
        )
        count += add_analysis_hosts(nodes, analysis, source, edges)
    return count


def parse_nmap_xml(path: Path) -> list[dict]:
    try:
        root = ET.parse(path).getroot()
    except (ET.ParseError, OSError):
        return []
    hosts = []
    for element in root.findall("host"):
        addresses = {
            item.get("addrtype"): item.get("addr")
            for item in element.findall("address")
        }
        ip = valid_ip(addresses.get("ipv4"))
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
            ports.append(
                {
                    "port": int(port_el.get("portid", "0")),
                    "protocol": port_el.get("protocol"),
                    "service": service_el.get("name") if service_el is not None else None,
                    "product": service_el.get("product") if service_el is not None else None,
                    "version": service_el.get("version") if service_el is not None else None,
                }
            )
        hosts.append(
            {
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
                    "port": element.find("trace").get("port", ""),
                    "protocol": element.find("trace").get("proto", ""),
                    "hops": [
                        {
                            "ttl": int(hop.get("ttl", "0") or 0),
                            "rtt": hop.get("rtt", ""),
                            "ip": hop.get("ipaddr", ""),
                            "hostname": hop.get("host", ""),
                        }
                        for hop in element.findall("trace/hop")
                        if hop.get("ipaddr")
                    ],
                }
                if element.find("trace") is not None
                else None,
            }
        )
    return hosts


def automated_scan_hosts(nodes: dict[str, dict], edges: dict, warnings: list[str]) -> int:
    db = None
    try:
        db = sqlite3.connect(DB_PATH)
        rows = db.execute(
            "SELECT manifest_json FROM scan_runs ORDER BY created_at DESC LIMIT 200"
        ).fetchall()
    except sqlite3.Error:
        return 0
    finally:
        if db is not None:
            db.close()
    count = 0
    for (manifest_json,) in rows:
        try:
            manifest = json.loads(manifest_json)
        except (TypeError, json.JSONDecodeError):
            continue
        run_id = manifest.get("run_id")
        if not run_id:
            continue
        path = DATA_DIR / RUNS_DIR_NAME / run_id / "scan.xml"
        hosts = parse_nmap_xml(path)
        if not hosts:
            continue
        source = source_record(
            "automated_nmap",
            f"Automated scan {run_id[:8]}",
            manifest.get("completed_at") or manifest.get("created_at"),
            f"/api/scan-runs/{run_id}/artifacts/xml",
        )
        count += add_analysis_hosts(nodes, {"hosts": hosts}, source, edges)
    return count


def interface_name(line: str) -> str | None:
    stripped = line.strip()
    if not stripped:
        return None
    first = stripped.split()[0].rstrip(":,")
    # FreeBSD ifconfig emits a link-layer line such as ``ether <mac>``.
    # ``ether`` begins with ``eth`` but is not an interface name; do not let
    # it replace the preceding vtnet/igb/etc. header while parsing addresses.
    if first.lower() == "ether":
        return None
    if re.fullmatch(
        r"(?:eth|ens|enp|lo|bond|br|bridge|vlan|ge-|xe-|em|fxp|vtnet|vmx|ix|igb|lagg|tap|tun|wg|enc|pflog|pfsync|pppoe|gif|gre)[A-Za-z0-9_.:/-]*",
        first,
        re.I,
    ):
        return first
    direct = re.search(r"directly connected,\s*([A-Za-z0-9_.:/-]+)", line, re.I)
    return direct.group(1).rstrip(",") if direct else None


def parse_config_text(text: str) -> tuple[list[dict], list[dict]]:
    interfaces: list[dict] = []
    routes: list[dict] = []
    zone_by_interface: dict[str, str] = {}
    seen_interfaces: set[tuple[str | None, str]] = set()
    seen_routes: set[tuple[str, str | None, str | None, bool]] = set()
    interface_macs: dict[str, str] = {}
    interface_mac_evidence: dict[str, str] = {}
    current_iface: str | None = None

    def set_zone(name: str | None, value: str | None) -> None:
        if not name or not value:
            return
        clean = re.sub(r"\s+", " ", html.unescape(value).strip(" \t\r\n'\""))[:80]
        if clean and clean.lower() not in {"none", "null", "interface"}:
            zone_by_interface[name] = clean

    def add_interface(name: str | None, address: str | None) -> None:
        normalized = valid_interface_address(address) if address else None
        if not name or not normalized:
            return
        key = (name, normalized)
        if key not in seen_interfaces:
            interfaces.append({"name": name, "address": normalized})
            seen_interfaces.add(key)

    def set_interface_mac(name: str | None, value: str | None, evidence: str) -> None:
        normalized = normalize_mac(value)
        if name and normalized and name not in interface_macs:
            interface_macs[name] = normalized
            interface_mac_evidence[name] = evidence[:500]

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        ifconfig_header = re.match(r"^([A-Za-z][A-Za-z0-9_.:/-]*):\s+(?:flags|link|mtu)\b", line, re.I)
        ip_header = re.match(r"^\d+:\s+([^:@\s]+)(?:@[^:]+)?:", line)
        config_header = re.match(r"^interface\s+([A-Za-z0-9_.:/-]+)\b", line, re.I)
        cisco_oper_header = re.match(
            r"^([A-Za-z][A-Za-z0-9_.:/-]*(?:\s+\d+(?:/\d+)*)?)\s+is\s+"
            r"(?:administratively\s+)?(?:up|down|reset|deleted|disabled)\b",
            line,
            re.I,
        )
        juniper_physical_header = re.match(
            r"^Physical interface:\s*([^,\s]+)", line, re.I
        )
        vyos_set_address = re.search(
            r"\bset\s+interfaces\s+\S+\s+([A-Za-z0-9_.:/-]+)\s+address\s+['\"]?((?:\d{1,3}\.){3}\d{1,3}/\d{1,2})",
            line,
            re.I,
        )
        juniper_set = re.search(
            r"\binterfaces\s+([A-Za-z0-9_.:/-]+)\s+unit\s+(\d+).*?\baddress\s+['\"]?((?:\d{1,3}\.){3}\d{1,3}/\d{1,2})",
            line,
            re.I,
        )
        if ifconfig_header:
            current_iface = ifconfig_header.group(1)
        elif ip_header:
            current_iface = ip_header.group(1)
        elif juniper_physical_header:
            current_iface = juniper_physical_header.group(1)
        elif cisco_oper_header:
            current_iface = re.sub(r"\s+", "", cisco_oper_header.group(1))
        elif config_header:
            current_iface = config_header.group(1)
        elif vyos_set_address:
            current_iface = vyos_set_address.group(1)
            add_interface(current_iface, vyos_set_address.group(2))
        elif juniper_set:
            base = juniper_set.group(1)
            current_iface = f"{base}.{juniper_set.group(2)}"
            add_interface(current_iface, juniper_set.group(3))

        vyos_hw_id = re.search(
            r"\bset\s+interfaces\s+\S+\s+([A-Za-z0-9_.:/-]+)\s+hw-id\s+['\"]?([^'\"\s]+)",
            line,
            re.I,
        )
        if vyos_hw_id:
            current_iface = vyos_hw_id.group(1)
            set_interface_mac(vyos_hw_id.group(1), vyos_hw_id.group(2), line)
        mac_line = bool(
            re.search(
                r"\b(?:address\s+is|current\s+address|hardware\s+address|mac(?:\s+address)?|hw-id|ether|link/ether)\b",
                line,
                re.I,
            )
        )
        if current_iface and mac_line:
            mac_match = MAC_CANDIDATE_RE.search(line)
            if mac_match:
                set_interface_mac(current_iface, mac_match.group(0), line)

        vyos_description = re.search(
            r"\bset\s+interfaces\s+\S+\s+([A-Za-z0-9_.:/-]+)\s+description\s+['\"]?(.+?)['\"]?$",
            line,
            re.I,
        )
        juniper_zone = re.search(
            r"\bsecurity\s+zones\s+security-zone\s+['\"]?([^'\"\s]+)['\"]?\s+interfaces\s+['\"]?([A-Za-z0-9_.:/-]+)",
            line,
            re.I,
        )
        nameif = re.match(r"^nameif\s+(.+)$", line, re.I)
        description = re.match(r"^description\s+(.+)$", line, re.I)
        if vyos_description:
            set_zone(vyos_description.group(1), vyos_description.group(2))
        if juniper_zone:
            set_zone(juniper_zone.group(2), juniper_zone.group(1))
        if nameif and current_iface:
            set_zone(current_iface, nameif.group(1))
        elif description and current_iface:
            set_zone(current_iface, description.group(1))

        inet_match = re.search(
            r"\binet\s+((?:\d{1,3}\.){3}\d{1,3})(?:/(\d{1,2}))?\s+(?:netmask\s+([^\s]+))?",
            line,
            re.I,
        )
        if inet_match and current_iface:
            prefix = inet_match.group(2)
            if prefix is None and inet_match.group(3):
                parsed_prefix = prefix_from_netmask(inet_match.group(3))
                prefix = str(parsed_prefix) if parsed_prefix is not None else None
            if prefix is not None:
                add_interface(current_iface, f"{inet_match.group(1)}/{prefix}")

        cisco_address = re.search(
            r"\bip\s+address\s+((?:\d{1,3}\.){3}\d{1,3})\s+((?:\d{1,3}\.){3}\d{1,3})\b",
            line,
            re.I,
        )
        if cisco_address and current_iface:
            prefix = prefix_from_netmask(cisco_address.group(2))
            if prefix is not None:
                add_interface(current_iface, f"{cisco_address.group(1)}/{prefix}")

        route_parts = line.strip(" ;").split()
        lower_route_parts = [value.lower() for value in route_parts]
        explicit_route: tuple[str, str | None, str | None] | None = None
        if len(route_parts) >= 4 and lower_route_parts[:2] == ["ip", "route"]:
            destination = route_parts[2]
            remaining = route_parts[3:]
            network = valid_network(destination) if "/" in destination else None
            if network is None and remaining:
                prefix = prefix_from_netmask(remaining[0])
                if prefix is not None:
                    network = valid_network(f"{destination}/{prefix}")
                    remaining = remaining[1:]
            gateway = next((valid_ip(value) for value in remaining if valid_ip(value)), None)
            route_interface = next(
                (value for value in remaining if not valid_ip(value)), None
            )
            if network and gateway:
                explicit_route = (network, gateway, route_interface)
        elif len(route_parts) >= 5 and lower_route_parts[0] == "route":
            prefix = prefix_from_netmask(route_parts[3])
            gateway = valid_ip(route_parts[4])
            network = (
                valid_network(f"{route_parts[2]}/{prefix}")
                if prefix is not None
                else None
            )
            if network and gateway:
                explicit_route = (network, gateway, route_parts[1])
        if explicit_route:
            network, gateway, route_interface = explicit_route
            route_key = (network, gateway, route_interface, False)
            if route_key not in seen_routes:
                routes.append(
                    {
                        "network": network,
                        "via": gateway,
                        "interface": route_interface,
                        "direct": False,
                        "line": line[:500],
                    }
                )
                seen_routes.add(route_key)

        lower = f" {line.lower()}"
        cidrs = [valid_network(value) for value in CIDR_RE.findall(line)]
        cidrs = [value for value in cidrs if value]
        via_match = VIA_RE.search(line) or NEXT_HOP_RE.search(line)
        via = valid_ip(via_match.group(1)) if via_match else None
        direct = any(marker in lower for marker in DIRECT_MARKERS)
        iface = interface_name(line)
        if iface and not (via or any(marker in lower for marker in DIRECT_MARKERS)):
            current_iface = iface
        for network in cidrs:
            parsed = ipaddress.ip_network(network)
            route_key = (network, via, iface, direct)
            if (direct or via) and route_key not in seen_routes:
                routes.append(
                    {
                        "network": network,
                        "via": via,
                        "interface": iface,
                        "direct": direct,
                        "line": line[:500],
                    }
                )
                seen_routes.add(route_key)
            if iface and not (direct or via) and parsed.prefixlen > 0:
                address_match = next(
                    (value for value in CIDR_RE.findall(line) if valid_network(value) == network),
                    None,
                )
                add_interface(iface, address_match or network)
    interfaces_xml = re.search(r"<interfaces>(.*?)</interfaces>", text, re.I | re.S)
    if interfaces_xml:
        for match in re.finditer(r"<([A-Za-z][A-Za-z0-9_-]*)>(.*?)</\1>", interfaces_xml.group(1), re.I | re.S):
            block = match.group(2)
            iface_match = re.search(r"<if>([^<]+)</if>", block, re.I)
            label_match = re.search(r"<descr>([^<]+)</descr>", block, re.I)
            if iface_match:
                set_zone(iface_match.group(1), label_match.group(1) if label_match else match.group(1).upper())
    matched_mac_interfaces: set[str] = set()
    for interface in interfaces:
        name = interface.get("name") or ""
        base_name = name.rsplit(".", 1)[0] if "." in name else name
        mac_name = name if name in interface_macs else base_name
        if mac_name in interface_macs:
            interface["mac"] = interface_macs[mac_name]
            interface["mac_evidence"] = interface_mac_evidence[mac_name]
            matched_mac_interfaces.add(mac_name)
    for name, mac in interface_macs.items():
        if name not in matched_mac_interfaces:
            interfaces.append(
                {
                    "name": name,
                    "address": None,
                    "mac": mac,
                    "mac_evidence": interface_mac_evidence[name],
                }
            )
    for interface in interfaces:
        name = interface.get("name")
        zone = zone_by_interface.get(name or "")
        if not zone and name and "." in name:
            zone = zone_by_interface.get(name.rsplit(".", 1)[0])
        if zone:
            interface["zone"] = zone
    return interfaces, routes


def configuration_network_candidates(
    *,
    config_dir: Path | None = None,
    db_path: Path | None = None,
    limit: int = 100,
) -> list[dict]:
    """Return review-only IPv4 subnet candidates found in saved device configs."""
    from app.saved_networks import list_saved_networks

    config_dir = CONFIG_DIR if config_dir is None else config_dir
    db_path = DB_PATH if db_path is None else db_path
    saved_by_cidr = {
        item["cidr"]: item
        for item in list_saved_networks(db_path, include_archived=True)
    }
    candidates: dict[str, dict] = {}

    def add_candidate(network_value: str, source: dict) -> None:
        network = ipaddress.ip_network(network_value, strict=False)
        if (
            network.version != 4
            or network.prefixlen in {0, 32}
            or network.is_loopback
            or network.is_link_local
            or network.is_multicast
            or network.is_unspecified
        ):
            return
        cidr = str(network)
        if cidr in saved_by_cidr:
            return
        label = source.get("zone") or source.get("device_name") or source.get("interface")
        suggested_name = f"{label} · {cidr}" if label else cidr
        if len(suggested_name) > 100:
            suggested_name = f"{suggested_name[: max(0, 97 - len(cidr))].rstrip()} · {cidr}"
        record = candidates.setdefault(
            cidr,
            {
                "cidr": cidr,
                "suggested_name": suggested_name,
                "category": "Device configuration",
                "tags": ["config-derived"],
                "description": "",
                "sources": [],
            },
        )
        signature = (
            source.get("run_id"),
            source.get("interface"),
            source.get("kind"),
            source.get("evidence"),
        )
        if signature not in {
            (
                item.get("run_id"), item.get("interface"), item.get("kind"),
                item.get("evidence"),
            )
            for item in record["sources"]
        }:
            record["sources"].append(source)

    if not config_dir.exists():
        return []
    manifests = sorted(
        config_dir.glob("*/manifest.json"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )[:limit]
    for manifest_path in manifests:
        try:
            manifest = json.loads(manifest_path.read_text(errors="replace"))
        except (OSError, ValueError):
            continue
        if manifest.get("status") not in {"completed", "uploaded"}:
            continue
        run_dir = manifest_path.parent
        artifacts = sorted(path for path in run_dir.glob("uploaded-*") if path.is_file())
        if not artifacts:
            artifacts = sorted(path for path in run_dir.glob("*-config.txt") if path.is_file())
        if not artifacts and (run_dir / "stdout.txt").is_file():
            artifacts = [run_dir / "stdout.txt"]
        if not artifacts:
            continue
        try:
            text = "\n".join(path.read_text(errors="replace") for path in artifacts)
        except OSError:
            continue
        interfaces, routes = parse_config_text(text)
        device_name = manifest.get("device_name") or manifest.get("device_address")
        common = {
            "run_id": manifest.get("run_id") or run_dir.name,
            "device_name": device_name,
            "device_address": manifest.get("device_address"),
            "vendor": manifest.get("vendor"),
            "observed_at": manifest.get("completed_at") or manifest.get("created_at"),
        }
        for interface in interfaces:
            address = valid_interface_address(interface.get("address"))
            if not address:
                continue
            network = str(ipaddress.ip_interface(address).network)
            add_candidate(
                network,
                {
                    **common,
                    "kind": "interface",
                    "interface": interface.get("name"),
                    "zone": interface.get("zone"),
                    "evidence": address,
                },
            )
        for route in routes:
            network = valid_network(route.get("network"))
            if not network:
                continue
            add_candidate(
                network,
                {
                    **common,
                    "kind": "connected route" if route.get("direct") else "route",
                    "interface": route.get("interface"),
                    "zone": None,
                    "evidence": route.get("line"),
                },
            )

    for record in candidates.values():
        source_labels = []
        for source in record["sources"]:
            label = source.get("device_name") or source.get("device_address") or "device config"
            if source.get("zone"):
                label += f" zone {source['zone']}"
            elif source.get("interface"):
                label += f" interface {source['interface']}"
            if label not in source_labels:
                source_labels.append(label)
        record["description"] = (
            "Identified from " + ", ".join(source_labels[:4])
            + ". Review authorization before scanning."
        )[:500]
    return sorted(
        candidates.values(),
        key=lambda item: (
            int(ipaddress.ip_network(item["cidr"]).network_address),
            ipaddress.ip_network(item["cidr"]).prefixlen,
        ),
    )


def replace_edge_node(edges: dict[tuple[str, str, str], dict], old_id: str, new_id: str) -> None:
    if old_id == new_id:
        return
    rewritten: dict[tuple[str, str, str], dict] = {}
    for edge in edges.values():
        edge = dict(edge)
        if edge["source"] == old_id:
            edge["source"] = new_id
        if edge["target"] == old_id:
            edge["target"] = new_id
        if edge["source"] == edge["target"]:
            continue
        key = (edge["source"], edge["target"], edge["relation"])
        rewritten.setdefault(key, edge)
    edges.clear()
    edges.update(rewritten)


def merge_device_alias(nodes: dict[str, dict], edges: dict[tuple[str, str, str], dict],
                       device: dict, alias_ip: str, aliases: dict[str, str]) -> None:
    if alias_ip not in device.setdefault("addresses", []):
        device["addresses"].append(alias_ip)
    alias_id = f"ip:{alias_ip}"
    aliases[alias_ip] = device["id"]
    if alias_id == device["id"]:
        return
    alias = nodes.pop(alias_id, None)
    if not alias:
        return
    for source in alias.get("sources") or []:
        add_source(device, source)
    for service in alias.get("services") or []:
        signature = (service.get("port"), service.get("protocol"), service.get("service"))
        if signature not in {
            (item.get("port"), item.get("protocol"), item.get("service"))
            for item in device.get("services") or []
        }:
            device["services"].append(service)
    for field in ("hostname", "mac", "os"):
        if not device.get(field) and alias.get(field):
            device[field] = alias[field]
    for observation in alias.get("mac_observations") or []:
        observation_source = source_record(
            observation.get("source_kind") or "merged_observation",
            observation.get("source_label") or "Merged address evidence",
            observation.get("last_observed"),
            observation.get("source_url"),
        )
        add_mac_observation(device, observation, observation_source)
    for observation in alias.get("scan_observations") or []:
        if observation not in device.setdefault("scan_observations", []):
            device["scan_observations"].append(observation)
    replace_edge_node(edges, alias_id, device["id"])


def config_result_text(run_dir: Path, manifest: dict) -> tuple[str, str | None]:
    candidates = [run_dir / "stdout.txt"]
    candidates.extend(
        path for path in run_dir.glob("uploaded-*") if path.is_file()
    )
    for path in candidates:
        if not path.is_file() or path.stat().st_size > 2_000_000:
            continue
        try:
            return path.read_text(encoding="utf-8", errors="replace"), path.name
        except OSError:
            continue
    return "", None


def configuration_devices(nodes: dict[str, dict], edges: dict[tuple[str, str, str], dict],
                          warnings: list[str]) -> int:
    if not CONFIG_DIR.exists():
        return 0
    manifests: list[tuple[Path, dict]] = []
    for path in CONFIG_DIR.glob("*/manifest.json"):
        try:
            manifests.append((path, json.loads(path.read_text(encoding="utf-8"))))
        except (OSError, json.JSONDecodeError):
            continue
    manifests.sort(key=lambda item: item[1].get("completed_at") or item[1].get("created_at") or "", reverse=True)
    parsed_devices: set[str] = set()
    aliases: dict[str, str] = {}
    count = 0
    for path, manifest in manifests[:300]:
        operation = manifest.get("operation")
        legacy_pull = operation is None and manifest.get("vendor") and manifest.get("device_type")
        if operation not in {
            "configuration_pull", "interactive_configuration_pull", "manual_upload",
        } and not legacy_pull:
            continue
        ip = valid_ip(manifest.get("device_address"))
        if not ip:
            continue
        run_id = manifest.get("run_id") or path.parent.name
        source = source_record(
            "device_configuration",
            f"{manifest.get('vendor', 'device')} {manifest.get('device_type', '')} configuration",
            manifest.get("completed_at") or manifest.get("created_at"),
            f"/api/device-configs/{run_id}/files/manifest.json",
        )
        if ip in aliases and aliases[ip] in nodes:
            node = nodes[aliases[ip]]
            add_source(node, source)
        else:
            node = ensure_ip_node(
                nodes,
                ip,
                hostname=manifest.get("device_name"),
                role=manifest.get("device_type"),
                vendor=manifest.get("vendor"),
                state=manifest.get("status"),
                source=source,
            )
            aliases[ip] = node["id"]
        if manifest.get("device_name") and not node.get("hostname"):
            node["hostname"] = manifest["device_name"]
            node["label"] = manifest["device_name"]
        count += 1
        if node["id"] in parsed_devices:
            continue
        text, filename = config_result_text(path.parent, manifest)
        if not text:
            continue
        if manifest.get("status") == "failed" and node.get("state") in {None, "failed"}:
            node["state"] = "partial"
        parsed_devices.add(node["id"])
        interfaces, routes = parse_config_text(text)
        neighbors = parse_neighbor_text(text)
        topology_neighbors = parse_topology_neighbors(text)
        interfaces = [
            item
            for item in interfaces
            if not item.get("name", "").lower().startswith("lo")
            and not (
                valid_network(item.get("address"))
                and ipaddress.ip_network(valid_network(item.get("address"))).is_loopback
            )
        ]
        node["interfaces"] = interfaces
        node["routes"] = routes
        for interface in interfaces:
            address = valid_interface_address(interface.get("address"))
            if address:
                merge_device_alias(nodes, edges, node, str(ipaddress.ip_interface(address).ip), aliases)
        observed_macs_by_ip = {
            valid_ip(observation.get("ip")): observation.get("mac")
            for observation in node.get("mac_observations") or []
            if valid_ip(observation.get("ip")) and normalize_mac(observation.get("mac"))
        }
        for interface in interfaces:
            address = valid_interface_address(interface.get("address"))
            interface_ip = str(ipaddress.ip_interface(address).ip) if address else None
            if not interface.get("mac") and interface_ip in observed_macs_by_ip:
                interface["mac"] = normalize_mac(observed_macs_by_ip[interface_ip])
                interface["mac_evidence"] = "MAC address reported for this interface IP in saved scan evidence"
            if interface.get("mac"):
                lookup = lookup_oui_vendor(interface["mac"])
                interface["mac_vendor"] = lookup.get("vendor")
        interface_addresses = {
            item.get("name"): item.get("address")
            for item in interfaces
            if item.get("name")
        }
        interface_zones = {
            item.get("name"): item.get("zone")
            for item in interfaces
            if item.get("name") and item.get("zone")
        }
        interface_nodes: dict[str, dict] = {}
        for interface in interfaces:
            name = interface.get("name") or "interface"
            interface_node = ensure_interface_node(
                nodes, node, name, interface.get("address"), source,
                mac=interface.get("mac"),
            )
            if interface.get("zone"):
                interface_node["zone"] = interface["zone"]
            if interface.get("mac"):
                address = valid_interface_address(interface.get("address"))
                add_mac_observation(
                    interface_node,
                    {
                        "ip": str(ipaddress.ip_interface(address).ip) if address else None,
                        "mac": interface["mac"],
                        "interface": name,
                        "protocol": "device_configuration",
                        "confidence": "confirmed",
                        "evidence": interface.get("mac_evidence"),
                    },
                    source,
                )
            interface_nodes[name] = interface_node
            add_edge(
                edges,
                node["id"],
                interface_node["id"],
                "owns_interface",
                name,
                "confirmed",
                interface.get("address"),
            )
        evidence_url = f"/api/device-configs/{run_id}/files/{filename}" if filename else None
        if evidence_url:
            add_source(
                node,
                source_record("configuration_output", filename or "configuration output", source["timestamp"], evidence_url),
            )
        neighbor_source = source_record(
            "arp_neighbor_table",
            f"{manifest.get('vendor', 'device')} ARP/neighbor table",
            source["timestamp"],
            evidence_url,
        )
        for observation in neighbors:
            observation_ip = observation["ip"]
            if observation_ip in aliases and aliases[observation_ip] in nodes:
                neighbor = nodes[aliases[observation_ip]]
                add_source(neighbor, neighbor_source)
            else:
                neighbor = ensure_ip_node(nodes, observation_ip, source=neighbor_source)
            interface = observation.get("interface")
            segment = valid_network(interface_addresses.get(interface)) if interface else None
            if segment:
                observation["segment"] = segment
            origin = interface_nodes.get(interface) or node
            if neighbor["id"] == node["id"]:
                if origin["id"] != node["id"]:
                    add_mac_observation(origin, observation, neighbor_source)
                continue
            add_mac_observation(neighbor, observation, neighbor_source)
            add_edge(
                edges,
                origin["id"],
                neighbor["id"],
                "arp_neighbor",
                f"ARP neighbor{f' on {interface}' if interface else ''}",
                "confirmed",
                observation.get("evidence"),
                bool(interface),
            )
        topology_source = source_record(
            "lldp_cdp_neighbor",
            f"{manifest.get('vendor', 'device')} LLDP/CDP neighbor evidence",
            source["timestamp"],
            evidence_url,
        )
        for observation in topology_neighbors:
            local_interface = observation.get("local_interface")
            origin = interface_nodes.get(local_interface)
            if origin is None and local_interface:
                origin = ensure_interface_node(
                    nodes,
                    node,
                    local_interface,
                    interface_addresses.get(local_interface),
                    source,
                )
                interface_nodes[local_interface] = origin
                add_edge(
                    edges,
                    node["id"],
                    origin["id"],
                    "owns_interface",
                    local_interface,
                    "confirmed",
                    interface_addresses.get(local_interface),
                )
            neighbor = ensure_topology_neighbor_node(
                nodes, observation, topology_source, aliases
            )
            source_node = origin or node
            if source_node["id"] == neighbor["id"]:
                continue
            protocol = str(observation.get("protocol") or "lldp").upper()
            local_label = local_interface or node.get("label") or "local device"
            remote_label = (
                observation.get("remote_port")
                or observation.get("neighbor_name")
                or observation.get("management_ip")
                or "remote device"
            )
            add_edge(
                edges,
                source_node["id"],
                neighbor["id"],
                "topology_neighbor",
                f"{local_label} ↔ {remote_label} ({protocol})",
                "confirmed",
                observation.get("evidence"),
                True,
            )
        for route in routes:
            network = route["network"]
            parsed_network = ipaddress.ip_network(network)
            route_source = node
            if route.get("interface"):
                name = route["interface"]
                route_source = interface_nodes.get(name) or ensure_interface_node(
                    nodes, node, name, interface_addresses.get(name), source
                )
                interface_nodes[name] = route_source
                add_edge(
                    edges,
                    node["id"],
                    route_source["id"],
                    "owns_interface",
                    name,
                    "confirmed",
                    interface_addresses.get(name),
                )
            if (
                route["direct"]
                and network != "0.0.0.0/0"
                and parsed_network.prefixlen < 32
                and not parsed_network.is_loopback
            ):
                subnet = ensure_subnet_node(nodes, network, source)
                apply_subnet_zone(subnet, interface_zones.get(route.get("interface")), source)
                add_subnet_owner(subnet, route_source.get("device_id") or node["id"])
                add_edge(
                    edges,
                    route_source["id"],
                    subnet["id"],
                    "directly_connected",
                    route.get("interface") or "direct",
                    "confirmed",
                    route.get("line"),
                )
            if route.get("via"):
                if route["via"] in aliases and aliases[route["via"]] in nodes:
                    gateway = nodes[aliases[route["via"]]]
                    add_source(gateway, source)
                else:
                    gateway = ensure_ip_node(nodes, route["via"], kind="gateway", source=source)
                add_edge(
                    edges,
                    route_source["id"],
                    gateway["id"],
                    "next_hop",
                    f"{network} via {route['via']}",
                    "confirmed",
                    route.get("line"),
                )
        for interface in interfaces:
            address = interface.get("address")
            network = valid_network(address)
            if not network or network == "0.0.0.0/0":
                continue
            parsed_network = ipaddress.ip_network(network)
            if parsed_network.prefixlen >= 32 or parsed_network.is_loopback:
                continue
            subnet = ensure_subnet_node(nodes, network, source)
            name = interface.get("name") or "interface"
            apply_subnet_zone(subnet, interface.get("zone"), source)
            interface_node = interface_nodes.get(name) or ensure_interface_node(
                nodes, node, name, interface.get("address"), source
            )
            if interface.get("zone"):
                interface_node["zone"] = interface["zone"]
            interface_nodes[name] = interface_node
            add_subnet_owner(subnet, interface_node.get("device_id") or node["id"])
            add_edge(
                edges,
                interface_node["id"],
                subnet["id"],
                "directly_connected",
                interface.get("name") or "interface",
                "confirmed",
                address,
            )
    return count


def add_membership_edges(nodes: dict[str, dict], edges: dict[tuple[str, str, str], dict]) -> None:
    subnet_nodes = [node for node in nodes.values() if node["kind"] == "subnet"]
    networks = sorted(
        ((ipaddress.ip_network(node["network"]), node) for node in subnet_nodes),
        key=lambda item: item[0].prefixlen,
        reverse=True,
    )
    linked = {(edge["source"], edge["target"]) for edge in edges.values()}
    for node in list(nodes.values()):
        ip = valid_ip(node.get("ip"))
        if not ip:
            continue
        address = ipaddress.ip_address(ip)
        for network, subnet in networks:
            if address.version != network.version:
                continue
            if address not in network:
                continue
            if (node["id"], subnet["id"]) not in linked:
                add_edge(
                    edges,
                    node["id"],
                    subnet["id"],
                    "subnet_membership",
                    "address membership",
                    "inferred",
                    f"{ip} falls within {network}",
                )
            break


def annotate_subnet_scan_observations(nodes: dict[str, dict]) -> None:
    """Retain scanned router/firewall addresses in their owning subnet summary."""
    infrastructure_kinds = {"device", "gateway"}
    scanned_devices = [
        node for node in nodes.values()
        if node.get("kind") in infrastructure_kinds
        and node.get("scan_observations")
    ]
    for subnet in (node for node in nodes.values() if node.get("kind") == "subnet"):
        network = ipaddress.ip_network(subnet["network"])
        observations = []
        seen: set[tuple[str, str]] = set()
        for device in scanned_devices:
            for observation in device.get("scan_observations") or []:
                ip = valid_ip(observation.get("ip"))
                if not ip or ipaddress.ip_address(ip) not in network:
                    continue
                signature = (device["id"], ip)
                if signature in seen:
                    continue
                seen.add(signature)
                observations.append(
                    {
                        "node_id": device["id"],
                        "label": device.get("label") or ip,
                        "ip": ip,
                        "role": device.get("role") or device.get("kind"),
                        "source_kind": observation.get("source_kind"),
                        "source_label": observation.get("source_label"),
                        "timestamp": observation.get("timestamp"),
                        "source_url": observation.get("source_url"),
                    }
                )
        observations.sort(key=lambda item: (ip_sort_key(item["ip"]), item["label"].casefold()))
        subnet["infrastructure_observations"] = observations
        subnet["infrastructure_count"] = len(observations)


def build_topology() -> dict:
    nodes: dict[str, dict] = {}
    edges: dict[tuple[str, str, str], dict] = {}
    warnings: list[str] = []
    imported_count = imported_hosts(nodes, edges, warnings)
    automated_count = automated_scan_hosts(nodes, edges, warnings)
    config_count = configuration_devices(nodes, edges, warnings)
    add_membership_edges(nodes, edges)
    annotate_subnet_scan_observations(nodes)
    node_list = sorted(
        nodes.values(),
        key=lambda item: (
            {"device": 0, "gateway": 1, "interface": 2, "subnet": 3, "host": 4}.get(item["kind"], 5),
            ip_sort_key(item.get("ip") or item.get("network") or item.get("address") or item.get("label")),
            str(item.get("label") or "").casefold(),
        ),
    )
    for node in node_list:
        node["sources"].sort(key=lambda item: item.get("timestamp") or "", reverse=True)
        node["mac_observations"].sort(
            key=lambda item: item.get("last_observed") or "", reverse=True
        ) if node.get("mac_observations") else None
        node["services"].sort(key=lambda item: (item.get("port") or 0, item.get("protocol") or "")) if node.get("services") else None
    summary = {
        "devices": sum(1 for node in node_list if node["kind"] == "device"),
        "gateways": sum(1 for node in node_list if node["kind"] == "gateway"),
        "interfaces": sum(1 for node in node_list if node["kind"] == "interface"),
        "subnets": sum(1 for node in node_list if node["kind"] == "subnet"),
        "hosts": sum(1 for node in node_list if node["kind"] == "host"),
        "relationships": len(edges),
        "nmap_records_read": imported_count + automated_count,
        "configuration_records_read": config_count,
        "mac_observations": sum(len(node.get("mac_observations") or []) for node in node_list),
        "mac_identified_hosts": sum(1 for node in node_list if node.get("mac")),
        "mac_conflicts": sum(1 for node in node_list if node.get("mac_conflict")),
        "arp_neighbors": sum(
            1 for edge in edges.values() if edge.get("relation") == "arp_neighbor"
        ),
        "topology_neighbors": sum(
            1 for edge in edges.values() if edge.get("relation") == "topology_neighbor"
        ),
    }
    if not node_list:
        warnings.append("No saved Nmap or network-device records are available yet.")
    if summary["subnets"] == 0 and summary["hosts"]:
        warnings.append("Hosts are available, but no directly connected subnets were parsed from device configurations.")
    return {
        "generated_at": utc_now(),
        "summary": summary,
        "oui_database": oui_database_info(),
        "nodes": node_list,
        "edges": list(edges.values()),
        "warnings": warnings,
    }


@router.get("")
def topology() -> dict:
    return build_topology()
