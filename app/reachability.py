from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass


EXTERNAL_TOKENS = {"internet", "wan", "external", "external wan"}


@dataclass(frozen=True)
class Endpoint:
    entered: str
    kind: str
    value: ipaddress.IPv4Address | ipaddress.IPv4Network | None


def parse_endpoint(value: str) -> Endpoint:
    entered = value.strip()
    if not entered:
        raise ValueError("Enter both a source and destination")
    if entered.casefold() in EXTERNAL_TOKENS:
        return Endpoint(entered=entered, kind="external", value=None)
    try:
        if "/" in entered:
            parsed = ipaddress.ip_network(entered, strict=False)
            if parsed.version != 4:
                raise ValueError
            return Endpoint(entered=entered, kind="network", value=parsed)
        parsed_address = ipaddress.ip_address(entered)
        if parsed_address.version != 4:
            raise ValueError
        return Endpoint(entered=entered, kind="host", value=parsed_address)
    except ValueError as exc:
        raise ValueError(f"Invalid IPv4 host, CIDR, or Internet endpoint: {entered}") from exc


def _network_for(endpoint: Endpoint, saved_networks: list[dict]) -> dict | None:
    if endpoint.kind == "external" or endpoint.value is None:
        return None
    for item in saved_networks:
        try:
            network = ipaddress.ip_network(str(item.get("cidr") or ""), strict=False)
        except ValueError:
            continue
        if (
            endpoint.kind == "host" and endpoint.value in network
        ) or (
            endpoint.kind == "network" and endpoint.value.subnet_of(network)
        ):
            return item
    return None


def _destination_matches(route_network: str, destination: Endpoint) -> bool:
    try:
        route = ipaddress.ip_network(route_network, strict=False)
    except ValueError:
        return False
    if destination.kind == "external":
        return route.prefixlen == 0
    if destination.value is None:
        return False
    if destination.kind == "host":
        return destination.value in route
    return destination.value.subnet_of(route) or destination.value.overlaps(route)


def _matching_routes(destination: Endpoint, device_analyses: list[dict]) -> list[dict]:
    candidates = []
    for analysis in device_analyses:
        device = analysis.get("device") or {}
        for route in (analysis.get("route_analysis") or {}).get("routes") or []:
            network = str(route.get("network") or "")
            if not _destination_matches(network, destination):
                continue
            try:
                prefix = ipaddress.ip_network(network, strict=False).prefixlen
            except ValueError:
                prefix = -1
            candidates.append({
                "device": device.get("name") or device.get("address") or "Network device",
                "device_address": device.get("address"),
                "network": network,
                "via": route.get("via"),
                "interface": route.get("interface"),
                "protocol": route.get("protocol"),
                "evidence": route.get("line"),
                "run_id": analysis.get("run_id"),
                "prefix": prefix,
            })
    return sorted(candidates, key=lambda item: item["prefix"], reverse=True)


def _service_observation(destination: Endpoint, protocol: str, port: int, hunting: dict) -> dict:
    if destination.kind != "host" or destination.value is None:
        return {"state": "not_applicable", "host": None, "finding": None}
    address = str(destination.value)
    host = next((item for item in hunting.get("hosts") or [] if str(item.get("ip")) == address), None)
    finding = next((
        item for item in hunting.get("findings") or []
        if str(item.get("ip")) == address
        and str(item.get("protocol") or "tcp").lower() == protocol
        and int(item.get("port") or 0) == port
    ), None)
    if finding:
        return {"state": "observed_exposed", "host": host, "finding": finding}
    if host:
        return {"state": "not_observed", "host": host, "finding": None}
    return {"state": "host_not_observed", "host": None, "finding": None}


def _policy_decisions(
    source: Endpoint,
    destination: Endpoint,
    protocol: str,
    port: int,
    device_analyses: list[dict],
) -> list[dict]:
    """Recognize only narrow, explicit Cisco-style host/any ACL evidence."""
    if destination.kind != "host" or destination.value is None:
        return []
    destination_ip = str(destination.value)
    decisions = []
    pattern = re.compile(
        rf"\b(?P<action>permit|deny)\s+{re.escape(protocol)}\s+"
        rf"(?P<source>any|host\s+\d{{1,3}}(?:\.\d{{1,3}}){{3}})\s+"
        rf"host\s+{re.escape(destination_ip)}\s+(?:eq\s+)?{port}\b",
        re.I,
    )
    for analysis in device_analyses:
        device = analysis.get("device") or {}
        for item in (analysis.get("policy") or {}).get("firewall_acl") or []:
            line = str(item.get("evidence") or item.get("line") or "")
            match = pattern.search(line)
            if not match:
                continue
            source_token = match.group("source").lower()
            if source_token != "any":
                if source.kind != "host" or source.value is None:
                    continue
                if source_token.split()[-1] != str(source.value):
                    continue
            decisions.append({
                "action": match.group("action").lower(),
                "device": device.get("name") or device.get("address") or "Network device",
                "device_address": device.get("address"),
                "evidence": line,
                "run_id": analysis.get("run_id"),
            })
    return decisions


def evaluate_reachability(
    *,
    source_text: str,
    destination_text: str,
    protocol: str,
    port: int,
    hunting: dict,
    saved_networks: list[dict],
    device_analyses: list[dict],
) -> dict:
    source = parse_endpoint(source_text)
    destination = parse_endpoint(destination_text)
    protocol = protocol.strip().lower()
    if protocol not in {"tcp", "udp"}:
        raise ValueError("Protocol must be TCP or UDP")
    if not 1 <= port <= 65535:
        raise ValueError("Port must be between 1 and 65535")

    source_network = _network_for(source, saved_networks)
    destination_network = _network_for(destination, saved_networks)
    service = _service_observation(destination, protocol, port, hunting)
    routes = _matching_routes(destination, device_analyses)
    policy = _policy_decisions(source, destination, protocol, port, device_analyses)
    evidence = []
    caveats = []

    if source_network:
        evidence.append({"kind": "source_network", "title": source_network.get("name"), "detail": source_network.get("cidr")})
    if destination_network:
        evidence.append({"kind": "destination_network", "title": destination_network.get("name"), "detail": destination_network.get("cidr")})
    if service["finding"]:
        finding = service["finding"]
        service_name = finding.get("service") or "unknown service"
        evidence.append({
            "kind": "service",
            "title": f"{protocol.upper()}/{port} observed open",
            "detail": " · ".join(str(value) for value in (service_name, finding.get("product"), finding.get("version")) if value),
        })
    elif service["state"] == "not_observed":
        caveats.append(f"The destination host was observed, but {protocol.upper()}/{port} was not present in retained open-port evidence. This is not proof that policy blocks it.")
    elif service["state"] == "host_not_observed":
        caveats.append("The destination host is not present in the current retained network-wide scan evidence.")

    for route in routes[:5]:
        evidence.append({
            "kind": "route",
            "title": f"Route on {route['device']}",
            "detail": f"{route['network']} via {route.get('via') or 'direct'}" + (f" · {route['interface']}" if route.get("interface") else ""),
            "raw": route.get("evidence"),
            "run_id": route.get("run_id"),
        })
    for decision in policy:
        evidence.append({
            "kind": "policy",
            "title": f"Explicit {decision['action']} on {decision['device']}",
            "detail": decision["evidence"],
            "run_id": decision.get("run_id"),
        })

    outcome = "Unknown"
    confidence = "low"
    explanation = "Retained evidence does not establish an end-to-end decision."
    if any(item["action"] == "deny" for item in policy):
        outcome, confidence = "Expected Blocked", "high"
        explanation = "An explicit retained ACL entry denies this exact destination service."
    elif any(item["action"] == "permit" for item in policy):
        outcome, confidence = "Expected Allowed", "high"
        explanation = "An explicit retained ACL entry permits this exact destination service."
    elif source_network and destination_network and source_network.get("saved_network_id") == destination_network.get("saved_network_id"):
        outcome, confidence = "Local", "medium"
        explanation = "Source and destination are within the same Saved Network. Host firewall and local segmentation may still affect access."
    elif routes:
        outcome, confidence = "Routed", "medium"
        explanation = "A retained route covers the destination, but no exact allow or deny policy was established."

    if not policy:
        caveats.append("No exact supported ACL statement established an allow or deny decision. NAT, zones, state, rule order, and policy objects may change the real path.")
    if service["state"] == "observed_exposed" and outcome == "Unknown":
        caveats.append("The service was observed open from the NCT host, but that does not prove it is reachable from the selected source.")

    return {
        "status": "reachability_analysis_complete",
        "outcome": outcome,
        "confidence": confidence,
        "explanation": explanation,
        "query": {
            "source": source.entered,
            "destination": destination.entered,
            "protocol": protocol,
            "port": port,
        },
        "source_network": source_network,
        "destination_network": destination_network,
        "service_observation": service["state"],
        "evidence": evidence,
        "caveats": list(dict.fromkeys(caveats)),
        "counts": {
            "routes": len(routes),
            "policy_decisions": len(policy),
            "evidence": len(evidence),
        },
    }
