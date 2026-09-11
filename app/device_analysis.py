from __future__ import annotations

import ipaddress
import json
import re
import sqlite3
from collections import Counter, defaultdict
from pathlib import Path

from fastapi import APIRouter, HTTPException

from app.device_configs import CONFIG_DIR, device_collection_directory, device_collection_summary
from app.network_map import parse_nmap_xml
from app.poc import DATA_DIR, DB_PATH, RUNS_DIR_NAME
from app.saved_networks import list_saved_networks


router = APIRouter(prefix="/api/device-analysis", tags=["device-analysis"])


def _route_protocol(route: dict) -> str:
    if route.get("direct"):
        return "connected"
    line = str(route.get("line") or "")
    lower = line.lower()
    patterns = (
        ("bgp", r"(?:^|\s)(?:b|bgp)(?:\s|\*)"),
        ("ospf", r"(?:^|\s)(?:o|ospf)(?:\s|\*)"),
        ("eigrp", r"(?:^|\s)(?:d|eigrp)(?:\s|\*)"),
        ("rip", r"(?:^|\s)(?:r|rip)(?:\s|\*)"),
        ("isis", r"(?:^|\s)(?:i|isis)(?:\s|\*)"),
    )
    for name, pattern in patterns:
        if re.search(pattern, lower):
            return name
    if (
        lower.startswith(("ip route ", "route "))
        or " protocols static " in f" {lower} "
        or re.match(r"^s(?:\*|\s)", lower)
    ):
        return "static"
    return "other"


def _interface_role(interface: dict) -> str:
    text = f"{interface.get('name', '')} {interface.get('zone', '')}".lower()
    for role, markers in (
        ("external", ("wan", "outside", "untrust", "external", "internet")),
        ("internal", ("lan", "inside", "trust", "user", "server")),
        ("dmz", ("dmz",)),
        ("management", ("mgmt", "management", "admin")),
        ("transit", ("transit", "uplink", "peer", "core")),
    ):
        if any(marker in text for marker in markers):
            return role
    return "unclassified"


def _interface_network(interface: dict) -> ipaddress.IPv4Network | None:
    try:
        parsed = ipaddress.ip_interface(str(interface.get("address") or ""))
    except ValueError:
        return None
    return parsed.network if parsed.version == 4 else None


def _evidence_networks(items: list[dict]) -> list[tuple[ipaddress.IPv4Network, dict]]:
    """Return IPv4 hosts/networks explicitly present in retained evidence lines."""
    found: list[tuple[ipaddress.IPv4Network, dict]] = []
    for item in items:
        evidence = str(item.get("evidence") or "")
        for token in re.findall(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?", evidence):
            try:
                network = ipaddress.ip_network(token, strict=False)
            except ValueError:
                continue
            if network.version == 4:
                found.append((network, item))
    return found


def _saved_network_correlations(
    interfaces: list[dict], routes: list[dict], policy_items: list[dict], db_path: Path
) -> list[dict]:
    matches = []
    for saved in list_saved_networks(db_path):
        try:
            saved_network = ipaddress.ip_network(saved["cidr"], strict=False)
        except ValueError:
            continue
        interface_names = sorted({
            str(item.get("name") or "interface")
            for item in interfaces
            if (network := _interface_network(item)) is not None
            and network.overlaps(saved_network)
        })
        route_networks = []
        for item in routes:
            try:
                route_network = ipaddress.ip_network(str(item.get("network") or ""), strict=False)
            except ValueError:
                continue
            if route_network.overlaps(saved_network):
                route_networks.append(str(route_network))
        route_networks = sorted(set(route_networks))
        policy_evidence = [
            item
            for network, item in _evidence_networks(policy_items)
            if network.overlaps(saved_network)
        ][:25]
        if interface_names or route_networks or policy_evidence:
            provenance = []
            if interface_names:
                provenance.append("parsed interface addressing")
            if route_networks:
                provenance.append("parsed routing table")
            if policy_evidence:
                provenance.append("parsed policy, NAT, or object evidence")
            matches.append({
                "saved_network_id": saved["saved_network_id"],
                "name": saved["name"],
                "cidr": saved["cidr"],
                "interface_names": interface_names,
                "route_networks": route_networks,
                "policy_evidence": policy_evidence,
                "confidence": "high" if interface_names else "medium",
                "provenance": provenance,
            })
    return matches


def _nmap_correlations(
    interfaces: list[dict], policy_items: list[dict], *, db_path: Path, data_dir: Path
) -> list[dict]:
    networks = [network for item in interfaces if (network := _interface_network(item))]
    if not networks or not db_path.is_file():
        return []
    try:
        with sqlite3.connect(db_path) as db:
            rows = db.execute(
                "SELECT manifest_json FROM scan_runs ORDER BY created_at DESC LIMIT 200"
            ).fetchall()
    except sqlite3.Error:
        return []
    policy_networks = _evidence_networks(policy_items)
    observed: dict[str, dict] = {}
    for (manifest_json,) in rows:
        try:
            manifest = json.loads(manifest_json)
        except (TypeError, json.JSONDecodeError):
            continue
        if manifest.get("status") != "completed" or not manifest.get("run_id"):
            continue
        xml_path = data_dir / RUNS_DIR_NAME / manifest["run_id"] / "scan.xml"
        for host in parse_nmap_xml(xml_path):
            try:
                address = ipaddress.ip_address(host.get("ip") or "")
            except ValueError:
                continue
            matching = [str(network) for network in networks if address in network]
            if not matching:
                continue
            record = observed.setdefault(
                str(address),
                {
                    "ip": str(address),
                    "hostname": host.get("hostname"),
                    "ports": host.get("ports") or [],
                    "interface_networks": set(),
                    "policy_evidence": [],
                    "sources": [],
                },
            )
            record["interface_networks"].update(matching)
            for policy_network, evidence in policy_networks:
                if address in policy_network and evidence not in record["policy_evidence"]:
                    record["policy_evidence"].append(evidence)
            source = {
                "run_id": manifest["run_id"],
                "label": manifest.get("display_name") or manifest.get("name") or manifest["run_id"][:8],
                "completed_at": manifest.get("completed_at") or manifest.get("created_at"),
                "url": f"/api/scan-runs/{manifest['run_id']}/artifacts/xml",
            }
            if source not in record["sources"]:
                record["sources"].append(source)
    result = []
    for item in observed.values():
        item["interface_networks"] = sorted(item["interface_networks"])
        item["confidence"] = "high"
        item["provenance"] = ["parsed device interface", "retained Nmap XML"]
        if item["policy_evidence"]:
            item["provenance"].append("parsed policy, NAT, or object evidence")
        result.append(item)
    return sorted(result, key=lambda item: ipaddress.ip_address(item["ip"]))


def analyze_device_collection(
    run_id: str,
    *,
    config_dir: Path | None = None,
    db_path: Path | None = None,
    data_dir: Path | None = None,
) -> dict:
    config_dir = CONFIG_DIR if config_dir is None else config_dir
    db_path = DB_PATH if db_path is None else db_path
    data_dir = DATA_DIR if data_dir is None else data_dir
    summary = device_collection_summary(run_id, config_dir=config_dir)
    run_dir = device_collection_directory(run_id, config_dir)
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    manifest.pop("key_path", None)
    interfaces = [
        {
            **item,
            "role": _interface_role(item),
            "network": str(network) if (network := _interface_network(item)) else None,
        }
        for item in summary.get("interfaces", [])
    ]
    routes = [{**item, "protocol": _route_protocol(item)} for item in summary.get("routes", [])]
    protocol_counts = Counter(item["protocol"] for item in routes)
    next_hops: dict[str, list[str]] = defaultdict(list)
    paths_by_network: dict[str, set[tuple[str, str]]] = defaultdict(set)
    for route in routes:
        network = str(route.get("network") or "")
        via = str(route.get("via") or "direct")
        interface = str(route.get("interface") or "")
        if route.get("via"):
            next_hops[via].append(network)
        if network:
            paths_by_network[network].add((via, interface))
    multipath = [
        {
            "network": network,
            "paths": [
                {"via": via if via != "direct" else None, "interface": interface or None}
                for via, interface in sorted(paths)
            ],
        }
        for network, paths in sorted(paths_by_network.items())
        if len(paths) > 1
    ]
    interface_networks = [network for item in interfaces if (network := _interface_network(item))]
    review_items = []
    default_routes = [item for item in routes if item.get("route_type") == "default"]
    if not default_routes:
        review_items.append({
            "severity": "warning", "category": "routing",
            "title": "No default route was parsed",
            "detail": "Confirm whether this device intentionally relies only on specific routes or whether the collection omitted routing evidence.",
        })
    for route in routes:
        via = route.get("via")
        if not via:
            continue
        try:
            reachable = any(ipaddress.ip_address(via) in network for network in interface_networks)
        except ValueError:
            reachable = False
        if not reachable:
            review_items.append({
                "severity": "warning", "category": "routing",
                "title": f"Next hop {via} is not on a parsed interface network",
                "detail": f"Route {route.get('network')} references {via}. The interface collection may be incomplete or the route may require recursive resolution.",
                "evidence": route.get("line"),
            })
    unclassified = [item.get("name") for item in interfaces if item["role"] == "unclassified"]
    if unclassified:
        review_items.append({
            "severity": "info", "category": "interfaces",
            "title": f"{len(unclassified)} interface role(s) remain unclassified",
            "detail": ", ".join(str(value) for value in unclassified if value),
        })
    if multipath:
        review_items.append({
            "severity": "info", "category": "routing",
            "title": f"{len(multipath)} multipath destination(s) detected",
            "detail": "Review equal-cost or redundant paths when comparing expected reachability.",
        })
    policy_count = len(summary.get("firewall_acl", []))
    nat_count = len(summary.get("nat", []))
    if manifest.get("device_type") == "firewall" and not policy_count:
        review_items.append({
            "severity": "warning", "category": "policy",
            "title": "No firewall or ACL evidence was parsed",
            "detail": "Confirm that the selected collection profile returned the active policy configuration.",
        })
    policy_items = [
        *summary.get("firewall_acl", []),
        *summary.get("nat", []),
        *summary.get("network_objects", []),
    ]
    saved_matches = _saved_network_correlations(interfaces, routes, policy_items, db_path)
    nmap_matches = _nmap_correlations(
        interfaces, policy_items, db_path=db_path, data_dir=data_dir
    )
    evidence = []
    for filename, label in (
        (summary.get("source_filename"), "Configuration evidence"),
        (summary.get("raw_filename"), "Raw collection output"),
    ):
        if filename and not any(item["filename"] == filename for item in evidence):
            evidence.append({
                "label": label,
                "filename": filename,
                "url": f"/api/device-configs/{run_id}/files/{filename}",
            })
    evidence.append({
        "label": "Collection manifest",
        "filename": "manifest.json",
        "url": f"/api/device-configs/{run_id}/files/manifest.json",
    })
    return {
        "run_id": run_id,
        "status": "analysis_complete",
        "device": {
            "name": manifest.get("device_name"),
            "address": manifest.get("device_address"),
            "vendor": manifest.get("vendor"),
            "type": manifest.get("device_type"),
        },
        "collection": {
            "status": manifest.get("status"),
            "operation": manifest.get("operation"),
            "operator": manifest.get("operator"),
            "reason": manifest.get("reason"),
            "originating_host": manifest.get("originating_host"),
            "created_at": manifest.get("created_at"),
            "completed_at": manifest.get("completed_at"),
        },
        "counts": {
            **summary.get("counts", {}),
            "default_routes": len(default_routes),
            "next_hops": len(next_hops),
            "multipath_destinations": len(multipath),
            "saved_network_matches": len(saved_matches),
            "nmap_host_matches": len(nmap_matches),
            "review_items": len(review_items),
        },
        "interfaces": interfaces,
        "route_analysis": {
            "routes": routes,
            "default_routes": default_routes,
            "protocol_counts": dict(sorted(protocol_counts.items())),
            "next_hops": [
                {"address": address, "route_count": len(networks), "networks": sorted(networks)}
                for address, networks in sorted(next_hops.items())
            ],
            "multipath": multipath,
        },
        "policy": {
            "firewall_acl": summary.get("firewall_acl", []),
            "nat": summary.get("nat", []),
            "network_objects": summary.get("network_objects", []),
        },
        "neighbors": summary.get("neighbors", []),
        "topology_neighbors": summary.get("topology_neighbors", []),
        "saved_network_correlations": saved_matches,
        "nmap_host_correlations": nmap_matches,
        "review_items": review_items,
        "evidence": evidence,
    }


def _index(items: list[dict], fields: tuple[str, ...]) -> dict[tuple, dict]:
    return {tuple(str(item.get(field) or "") for field in fields): item for item in items}


def compare_device_analyses(before: dict, after: dict) -> dict:
    before_interfaces = _index(before.get("interfaces", []), ("name",))
    after_interfaces = _index(after.get("interfaces", []), ("name",))
    before_routes = _index(
        before.get("route_analysis", {}).get("routes", []),
        ("network", "via", "interface", "protocol"),
    )
    after_routes = _index(
        after.get("route_analysis", {}).get("routes", []),
        ("network", "via", "interface", "protocol"),
    )

    def evidence_delta(section: str) -> tuple[list[dict], list[dict]]:
        old = _index(before.get("policy", {}).get(section, []), ("evidence",))
        new = _index(after.get("policy", {}).get(section, []), ("evidence",))
        return (
            [new[key] for key in sorted(new.keys() - old.keys())],
            [old[key] for key in sorted(old.keys() - new.keys())],
        )

    firewall_added, firewall_removed = evidence_delta("firewall_acl")
    nat_added, nat_removed = evidence_delta("nat")
    objects_added, objects_removed = evidence_delta("network_objects")
    shared_interfaces = before_interfaces.keys() & after_interfaces.keys()
    interface_fields = ("address", "network", "role", "zone", "mac")
    interfaces_changed = []
    for key in sorted(shared_interfaces):
        old = before_interfaces[key]
        new = after_interfaces[key]
        changes = {
            field: {"before": old.get(field), "after": new.get(field)}
            for field in interface_fields
            if old.get(field) != new.get(field)
        }
        if changes:
            interfaces_changed.append({"name": new.get("name"), "changes": changes})
    identity_mismatch = before.get("device", {}).get("address") != after.get("device", {}).get("address")
    return {
        "status": "comparison_complete",
        "before": {"run_id": before["run_id"], "device": before["device"], "collection": before["collection"], "evidence": before["evidence"]},
        "after": {"run_id": after["run_id"], "device": after["device"], "collection": after["collection"], "evidence": after["evidence"]},
        "identity_mismatch": identity_mismatch,
        "summary": {
            "interfaces_added": len(after_interfaces.keys() - before_interfaces.keys()),
            "interfaces_removed": len(before_interfaces.keys() - after_interfaces.keys()),
            "interfaces_changed": len(interfaces_changed),
            "routes_added": len(after_routes.keys() - before_routes.keys()),
            "routes_removed": len(before_routes.keys() - after_routes.keys()),
            "firewall_acl_added": len(firewall_added),
            "firewall_acl_removed": len(firewall_removed),
            "nat_added": len(nat_added),
            "nat_removed": len(nat_removed),
            "network_objects_added": len(objects_added),
            "network_objects_removed": len(objects_removed),
        },
        "interfaces_added": [after_interfaces[key] for key in sorted(after_interfaces.keys() - before_interfaces.keys())],
        "interfaces_removed": [before_interfaces[key] for key in sorted(before_interfaces.keys() - after_interfaces.keys())],
        "interfaces_changed": interfaces_changed,
        "routes_added": [after_routes[key] for key in sorted(after_routes.keys() - before_routes.keys())],
        "routes_removed": [before_routes[key] for key in sorted(before_routes.keys() - after_routes.keys())],
        "policy_changes": {
            "firewall_acl_added": firewall_added,
            "firewall_acl_removed": firewall_removed,
            "nat_added": nat_added,
            "nat_removed": nat_removed,
            "network_objects_added": objects_added,
            "network_objects_removed": objects_removed,
        },
    }


@router.get("/compare")
def compare_device_collections(before: str, after: str) -> dict:
    try:
        return compare_device_analyses(
            analyze_device_collection(before), analyze_device_collection(after)
        )
    except (ValueError, FileNotFoundError, json.JSONDecodeError, OSError):
        raise HTTPException(status_code=404, detail="One or both device collections were not found") from None


@router.get("/{run_id}")
def device_analysis(run_id: str) -> dict:
    try:
        return analyze_device_collection(run_id)
    except (ValueError, FileNotFoundError, json.JSONDecodeError, OSError):
        raise HTTPException(status_code=404, detail="Device collection was not found") from None
