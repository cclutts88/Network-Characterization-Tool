from __future__ import annotations

import ipaddress
import json
import re
import sqlite3
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter

from app.device_configs import CONFIG_DIR
from app.poc import DATA_DIR, DB_PATH, RUNS_DIR_NAME


router = APIRouter(prefix="/api/network-map", tags=["network-map"])

IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
CIDR_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}(?![\w.])")
VIA_RE = re.compile(r"\bvia\s+((?:\d{1,3}\.){3}\d{1,3})\b", re.IGNORECASE)
INTERFACE_RE = re.compile(r"\b(?:dev\s+)?([A-Za-z][A-Za-z0-9_.:/-]{0,31})\b")
DIRECT_MARKERS = ("directly connected", " connected", "direct/", "link#")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def valid_ip(value: object) -> str | None:
    try:
        parsed = ipaddress.ip_address(str(value))
    except ValueError:
        return None
    return str(parsed) if parsed.version == 4 else None


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


def ensure_interface_node(nodes: dict[str, dict], device: dict, name: str,
                          address: str | None = None, source: dict | None = None) -> dict:
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
            "sources": [],
        },
    )
    if address and not node.get("address"):
        node["address"] = address
    if address and address not in node.setdefault("addresses", []):
        node["addresses"].append(address)
    if source:
        add_source(node, source)
    return node


def add_edge(edges: dict[tuple[str, str, str], dict], source: str, target: str, relation: str,
             label: str, confidence: str, evidence: str | None = None) -> None:
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


def add_analysis_hosts(nodes: dict[str, dict], analysis: dict, source: dict) -> int:
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
        ensure_ip_node(
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
        added += 1
    return added


def imported_hosts(nodes: dict[str, dict], warnings: list[str]) -> int:
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
        count += add_analysis_hosts(nodes, analysis, source)
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
            }
        )
    return hosts


def automated_scan_hosts(nodes: dict[str, dict], warnings: list[str]) -> int:
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
        count += add_analysis_hosts(nodes, {"hosts": hosts}, source)
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
    seen_interfaces: set[tuple[str | None, str]] = set()
    seen_routes: set[tuple[str, str | None, str | None, bool]] = set()
    current_iface: str | None = None

    def add_interface(name: str | None, address: str | None) -> None:
        normalized = valid_interface_address(address) if address else None
        if not name or not normalized:
            return
        key = (name, normalized)
        if key not in seen_interfaces:
            interfaces.append({"name": name, "address": normalized})
            seen_interfaces.add(key)

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        ifconfig_header = re.match(r"^([A-Za-z][A-Za-z0-9_.:/-]*):\s+(?:flags|link|mtu)\b", line, re.I)
        ip_header = re.match(r"^\d+:\s+([^:@\s]+)(?:@[^:]+)?:", line)
        config_header = re.match(r"^interface\s+([A-Za-z0-9_.:/-]+)\b", line, re.I)
        juniper_set = re.search(
            r"\binterfaces\s+([A-Za-z0-9_.:/-]+)(?:\s+unit\s+(\d+))?.*?\baddress\s+['\"]?((?:\d{1,3}\.){3}\d{1,3}/\d{1,2})",
            line,
            re.I,
        )
        if ifconfig_header:
            current_iface = ifconfig_header.group(1)
        elif ip_header:
            current_iface = ip_header.group(1)
        elif config_header:
            current_iface = config_header.group(1)
        elif juniper_set:
            base = juniper_set.group(1)
            current_iface = f"{base}.{juniper_set.group(2)}" if juniper_set.group(2) else base
            add_interface(current_iface, juniper_set.group(3))

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

        lower = f" {line.lower()}"
        cidrs = [valid_network(value) for value in CIDR_RE.findall(line)]
        cidrs = [value for value in cidrs if value]
        via_match = VIA_RE.search(line)
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
    return interfaces, routes


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
        if operation not in {"configuration_pull", "manual_upload"} and not legacy_pull:
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
                role=manifest.get("device_type"),
                vendor=manifest.get("vendor"),
                state=manifest.get("status"),
                source=source,
            )
            aliases[ip] = node["id"]
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
        interface_addresses = {
            item.get("name"): item.get("address")
            for item in interfaces
            if item.get("name")
        }
        interface_nodes: dict[str, dict] = {}
        for interface in interfaces:
            name = interface.get("name") or "interface"
            interface_node = ensure_interface_node(
                nodes, node, name, interface.get("address"), source
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
            interface_node = interface_nodes.get(name) or ensure_interface_node(
                nodes, node, name, interface.get("address"), source
            )
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


def build_topology() -> dict:
    nodes: dict[str, dict] = {}
    edges: dict[tuple[str, str, str], dict] = {}
    warnings: list[str] = []
    imported_count = imported_hosts(nodes, warnings)
    automated_count = automated_scan_hosts(nodes, warnings)
    config_count = configuration_devices(nodes, edges, warnings)
    add_membership_edges(nodes, edges)
    node_list = sorted(
        nodes.values(),
        key=lambda item: ({"device": 0, "gateway": 1, "interface": 2, "subnet": 3, "host": 4}.get(item["kind"], 5), item["label"]),
    )
    for node in node_list:
        node["sources"].sort(key=lambda item: item.get("timestamp") or "", reverse=True)
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
    }
    if not node_list:
        warnings.append("No saved Nmap or network-device records are available yet.")
    if summary["subnets"] == 0 and summary["hosts"]:
        warnings.append("Hosts are available, but no directly connected subnets were parsed from device configurations.")
    return {
        "generated_at": utc_now(),
        "summary": summary,
        "nodes": node_list,
        "edges": list(edges.values()),
        "warnings": warnings,
    }


@router.get("")
def topology() -> dict:
    return build_topology()
