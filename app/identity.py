from __future__ import annotations


TOPOLOGY_SOURCE_RANK = {
    "arp_neighbor_table": 4,
    "device_configuration": 3,
    "configuration_output": 3,
    "lldp_cdp_neighbor": 3,
    "automated_nmap": 2,
    "imported_nmap": 2,
}


def _topology_nodes_by_ip(topology: dict) -> dict[str, dict]:
    result = {}
    for node in topology.get("nodes") or []:
        for value in [node.get("ip"), *(node.get("addresses") or [])]:
            if value:
                result[str(value)] = node
    return result


def _best_mac_observation(node: dict) -> dict | None:
    values = [
        item for item in (node.get("mac_observations") or []) if item.get("mac")
    ]
    values.sort(
        key=lambda item: (
            TOPOLOGY_SOURCE_RANK.get(str(item.get("source_kind") or ""), 1),
            str(item.get("last_observed") or ""),
        ),
        reverse=True,
    )
    return values[0] if values else None


def enrich_analysis_macs(
    analysis: dict,
    topology: dict,
    *,
    direct_source_label: str = "Selected Nmap XML",
    direct_source_url: str | None = None,
) -> dict:
    """Cross-reference missing scan MACs while retaining their evidence origin."""
    result = dict(analysis)
    nodes_by_ip = _topology_nodes_by_ip(topology)
    hosts = []
    for original in analysis.get("hosts") or []:
        host = dict(original)
        direct_mac = str(host.get("mac") or "").strip()
        if direct_mac:
            host["mac_provenance"] = {
                "indirect": False,
                "origin": "Selected Nmap scan",
                "source_kind": "nmap",
                "source_label": direct_source_label,
                "source_url": direct_source_url,
                "detail": "MAC address reported directly in this Nmap scan.",
            }
            hosts.append(host)
            continue
        node = nodes_by_ip.get(str(host.get("ip") or ""))
        observation = _best_mac_observation(node or {})
        if not observation:
            hosts.append(host)
            continue
        host["mac"] = observation.get("mac")
        if not host.get("vendor"):
            host["vendor"] = observation.get("vendor") or (node or {}).get("vendor")
        is_neighbor = observation.get("source_kind") == "arp_neighbor_table"
        details = [
            "MAC address correlated by IP; it was not reported in this Nmap scan.",
            f"Protocol: {observation.get('protocol')}" if observation.get("protocol") else None,
            f"Interface: {observation.get('interface')}" if observation.get("interface") else None,
            f"Segment: {observation.get('segment')}" if observation.get("segment") else None,
        ]
        host["mac_provenance"] = {
            "indirect": True,
            "origin": (
                "Router/firewall neighbor table" if is_neighbor
                else "Other retained topology evidence"
            ),
            "source_kind": observation.get("source_kind"),
            "source_label": observation.get("source_label") or "Saved topology evidence",
            "source_url": observation.get("source_url"),
            "timestamp": observation.get("last_observed"),
            "detail": " ".join(item for item in details if item),
        }
        hosts.append(host)
    result["hosts"] = hosts
    result["mac_count"] = sum(1 for host in hosts if host.get("mac"))
    result["direct_mac_count"] = sum(
        1 for host in hosts
        if host.get("mac") and not (host.get("mac_provenance") or {}).get("indirect")
    )
    result["correlated_mac_count"] = sum(
        1 for host in hosts if (host.get("mac_provenance") or {}).get("indirect")
    )
    return result
