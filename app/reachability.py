from __future__ import annotations

import ipaddress
import re
from copy import deepcopy
from datetime import datetime, timezone
from dataclasses import dataclass
from urllib.parse import urlencode

from app.iptables_policy import (
    evaluate_iptables_flow,
    evaluate_iptables_nat,
    parse_iptables_policy,
)
from app.ip_sort import ip_sort_key
from app.vendor_policy import (
    evaluate_vendor_nat,
    evaluate_vendor_policy,
    parse_vendor_policy,
)


EXTERNAL_TOKENS = {"internet", "wan", "external", "external wan"}


@dataclass(frozen=True)
class Endpoint:
    entered: str
    kind: str
    value: ipaddress.IPv4Address | ipaddress.IPv4Network | None
    external: bool = False


def parse_endpoint(value: str, *, external: bool = False) -> Endpoint:
    entered = value.strip()
    if not entered:
        raise ValueError("Enter both a source and destination")
    if entered.casefold() in EXTERNAL_TOKENS:
        return Endpoint(entered=entered, kind="external", value=None, external=True)
    try:
        if "/" in entered:
            parsed = ipaddress.ip_network(entered, strict=False)
            if parsed.version != 4:
                raise ValueError
            return Endpoint(entered=entered, kind="network", value=parsed, external=external)
        parsed_address = ipaddress.ip_address(entered)
        if parsed_address.version != 4:
            raise ValueError
        return Endpoint(entered=entered, kind="host", value=parsed_address, external=external)
    except ValueError as exc:
        raise ValueError(f"Invalid IPv4 host, CIDR, or Internet endpoint: {entered}") from exc


def _is_external_endpoint(endpoint: Endpoint) -> bool:
    return endpoint.kind == "external" or endpoint.external


def _network_for(endpoint: Endpoint, saved_networks: list[dict]) -> dict | None:
    if _is_external_endpoint(endpoint) or endpoint.value is None:
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


def _endpoint_has_retained_internal_context(
    endpoint: Endpoint,
    *,
    hunting: dict,
    saved_networks: list[dict],
    device_analyses: list[dict],
) -> bool:
    if endpoint.value is None or _network_for(endpoint, saved_networks):
        return endpoint.value is not None
    for host in hunting.get("hosts") or []:
        try:
            address = ipaddress.ip_address(str(host.get("ip") or ""))
        except ValueError:
            continue
        if (
            endpoint.kind == "host" and address == endpoint.value
        ) or (
            endpoint.kind == "network" and address in endpoint.value
        ):
            return True
    for analysis in device_analyses:
        for interface in analysis.get("interfaces") or []:
            try:
                network = ipaddress.ip_network(
                    str(interface.get("network") or ""), strict=False
                )
            except ValueError:
                continue
            if (
                endpoint.kind == "host" and endpoint.value in network
            ) or (
                endpoint.kind == "network" and endpoint.value.overlaps(network)
            ):
                return True
    return False


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


def _is_transit_device(analysis: dict) -> bool:
    return str((analysis.get("device") or {}).get("type") or "").lower() in {
        "router", "firewall"
    }


def _default_route_interface(analysis: dict) -> str | None:
    for route in (analysis.get("route_analysis") or {}).get("routes") or []:
        if str(route.get("network") or "") in {"0.0.0.0/0", "default"}:
            interface = str(route.get("interface") or "") or None
            if interface:
                return interface
    return None


def _external_ingress_analyses(
    device_analyses: list[dict],
) -> tuple[list[dict], bool]:
    """Choose outside ingress only when retained evidence makes it unambiguous."""
    transit = [item for item in device_analyses if _is_transit_device(item)]
    designated = [item for item in transit if item.get("external_wan_gateway")]
    if designated:
        return designated, False

    internet_labeled = []
    for analysis in transit:
        for interface in analysis.get("interfaces") or []:
            label = " ".join(
                str(interface.get(field) or "")
                for field in ("zone", "description", "label")
            )
            if re.search(r"\b(?:internet|inet)\b", label, re.I):
                internet_labeled.append(analysis)
                break
    if len(internet_labeled) == 1:
        return internet_labeled, False
    if len(internet_labeled) > 1:
        return [], True

    outside_role = [
        item for item in transit
        if any(
            str(interface.get("role") or "").casefold() == "external"
            for interface in item.get("interfaces") or []
        )
    ]
    boundary_role = []
    for analysis in outside_role:
        others = [item for item in transit if item is not analysis]
        for interface in analysis.get("interfaces") or []:
            if str(interface.get("role") or "").casefold() != "external":
                continue
            try:
                network = ipaddress.ip_network(
                    str(interface.get("network") or ""), strict=False
                )
            except ValueError:
                continue
            attached_elsewhere = False
            for other in others:
                for other_interface in other.get("interfaces") or []:
                    try:
                        other_network = ipaddress.ip_network(
                            str(other_interface.get("network") or ""), strict=False
                        )
                    except ValueError:
                        continue
                    if network.overlaps(other_network):
                        attached_elsewhere = True
                        break
                if attached_elsewhere:
                    break
            if not attached_elsewhere:
                boundary_role.append(analysis)
                break
    if len(boundary_role) == 1:
        return boundary_role, False
    if len(boundary_role) > 1:
        return [], True
    if len(outside_role) == 1:
        return outside_role, False
    if len(outside_role) > 1:
        return [], True

    default_route = [item for item in transit if _default_route_interface(item)]
    if len(default_route) == 1:
        return default_route, False
    if len(default_route) > 1:
        return [], True
    return [], False


def _source_attached(source: Endpoint, analysis: dict) -> bool:
    interfaces = analysis.get("interfaces") or []
    if _is_external_endpoint(source):
        return any(item.get("role") == "external" for item in interfaces) or bool(
            _default_route_interface(analysis)
        )
    if source.value is None:
        return False
    for item in interfaces:
        try:
            network = ipaddress.ip_network(str(item.get("network") or ""), strict=False)
        except ValueError:
            continue
        if source.kind == "host" and source.value in network:
            return True
        if source.kind == "network" and source.value.overlaps(network):
            return True
    return False


def _route_priority_value(route: dict, field: str) -> int | None:
    value = route.get(field)
    if value not in (None, ""):
        try:
            parsed = int(value)
        except (TypeError, ValueError):
            return None
        return parsed if parsed >= 0 else None
    match = re.search(
        rf"\b{re.escape(field)}\s+(\d+)\b",
        str(route.get("line") or ""),
        re.I,
    )
    return int(match.group(1)) if match else None


def _rank_route_candidates(candidates: list[dict]) -> list[dict]:
    """Rank equally specific routes only when their retained priority is comparable."""
    groups: dict[int, list[dict]] = {}
    for item in candidates:
        groups.setdefault(int(item["prefix"]), []).append(item)
    ranked = []
    for prefix in sorted(groups, reverse=True):
        group = groups[prefix]
        preferences = [item.get("preference") for item in group]
        metrics = [item.get("metric") for item in group]
        if len(group) == 1:
            basis = "longest prefix"
            comparable = True
        elif all(value is not None for value in preferences):
            if all(value is not None for value in metrics):
                group = sorted(
                    group,
                    key=lambda item: (int(item["preference"]), int(item["metric"])),
                )
                best = (int(group[0]["preference"]), int(group[0]["metric"]))
                comparable = sum(
                    (int(item["preference"]), int(item["metric"])) == best
                    for item in group
                ) == 1
                basis = "explicit preference then metric"
            else:
                group = sorted(group, key=lambda item: int(item["preference"]))
                best = int(group[0]["preference"])
                comparable = sum(int(item["preference"]) == best for item in group) == 1
                basis = "explicit preference"
        elif all(value is not None for value in metrics):
            group = sorted(group, key=lambda item: int(item["metric"]))
            best = int(group[0]["metric"])
            comparable = sum(int(item["metric"]) == best for item in group) == 1
            basis = "explicit metric"
        else:
            basis = "unresolved equal-prefix priority"
            comparable = False
        if not comparable and "unresolved" not in basis:
            basis += " with unresolved tie"
        for index, item in enumerate(group, 1):
            ranked.append({
                **item,
                "selection_basis": basis,
                "selection_order": index,
                "priority_comparable": comparable,
            })
    return ranked


def _matching_routes(source: Endpoint, destination: Endpoint, device_analyses: list[dict]) -> tuple[list[dict], list[dict]]:
    candidates = []
    excluded = []
    seen = set()
    route_analyses = device_analyses
    if _is_external_endpoint(source):
        route_analyses, _ = _external_ingress_analyses(device_analyses)
    for analysis in route_analyses:
        device = analysis.get("device") or {}
        for route in (analysis.get("route_analysis") or {}).get("routes") or []:
            network = str(route.get("network") or "")
            if not _destination_matches(network, destination):
                continue
            via = str(route.get("via") or "").strip()
            if via and not route.get("interface"):
                try:
                    if ipaddress.ip_address(via).is_loopback:
                        excluded.append({
                            "device": device.get("name") or device.get("address") or "Network device",
                            "device_type": device.get("type"),
                            "network": network,
                            "reason": "Loopback metadata without a forwarding interface is not usable route evidence.",
                        })
                        continue
                except ValueError:
                    pass
            if not _is_transit_device(analysis):
                excluded.append({
                    "device": device.get("name") or device.get("address") or "Network device",
                    "device_type": device.get("type"),
                    "network": network,
                    "reason": "Switch management routes are not transit-path evidence unless Layer-3 forwarding is explicitly established.",
                })
                continue
            if not _is_external_endpoint(source) and not _source_attached(source, analysis):
                continue
            key = (
                str(device.get("address") or device.get("name") or ""),
                network,
                str(route.get("via") or ""),
                str(route.get("interface") or ""),
            )
            if key in seen:
                continue
            seen.add(key)
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
                "preference": _route_priority_value(route, "preference"),
                "metric": _route_priority_value(route, "metric"),
                "evidence": route.get("line"),
                "run_id": analysis.get("run_id"),
                "prefix": prefix,
                "analyst_external_gateway": bool(
                    analysis.get("external_wan_gateway")
                ),
            })
    return _rank_route_candidates(candidates), excluded


def _analysis_identity(analysis: dict) -> tuple[str, str]:
    device = analysis.get("device") or {}
    return (
        str(device.get("address") or "").casefold(),
        str(device.get("name") or "").casefold(),
    )


def _analysis_for_next_hop(
    next_hop: ipaddress.IPv4Address,
    device_analyses: list[dict],
    visited: set[tuple[str, str]],
) -> dict | None:
    exact = []
    attached = []
    for analysis in device_analyses:
        identity = _analysis_identity(analysis)
        if identity in visited or not _is_transit_device(analysis):
            continue
        device = analysis.get("device") or {}
        addresses = [device.get("address")]
        addresses.extend(
            value
            for interface in analysis.get("interfaces") or []
            for value in (interface.get("address"), interface.get("ip"))
        )
        if any(str(value or "").split("/")[0] == str(next_hop) for value in addresses):
            exact.append(analysis)
            continue
        for interface in analysis.get("interfaces") or []:
            try:
                network = ipaddress.ip_network(
                    str(interface.get("network") or ""), strict=False
                )
            except ValueError:
                continue
            if next_hop in network:
                attached.append(analysis)
                break
    candidates = exact or attached
    return candidates[0] if len(candidates) == 1 else None


def _selected_route_chain(
    source: Endpoint,
    destination: Endpoint,
    device_analyses: list[dict],
    initial_routes: list[dict],
) -> tuple[list[dict], str | None]:
    """Follow retained next hops without inventing intermediate devices."""
    if not initial_routes:
        return [], None
    chain = [initial_routes[0]]
    visited: set[tuple[str, str]] = {
        (
            str(initial_routes[0].get("device_address") or "").casefold(),
            str(initial_routes[0].get("device") or "").casefold(),
        )
    }
    for _ in range(len(device_analyses)):
        selected = chain[-1]
        next_hop_text = str(selected.get("via") or "").strip()
        if not next_hop_text:
            return chain, None
        try:
            next_hop = ipaddress.ip_address(next_hop_text)
        except ValueError:
            return chain, (
                f"Path is partial after {selected['device']}; retained route evidence "
                f"uses an unresolved next hop ({next_hop_text})."
            )
        if destination.kind == "host" and destination.value == next_hop:
            return chain, None
        analysis = _analysis_for_next_hop(next_hop, device_analyses, visited)
        if analysis is None:
            return chain, (
                f"Path is partial after {selected['device']}; no single retained "
                f"routing configuration matches next hop {next_hop}."
            )
        identity = _analysis_identity(analysis)
        visited.add(identity)
        next_source = Endpoint(
            entered=str(next_hop), kind="host", value=next_hop
        )
        next_routes, _ = _matching_routes(next_source, destination, [analysis])
        if not next_routes:
            device = analysis.get("device") or {}
            name = device.get("name") or device.get("address") or str(next_hop)
            return chain, (
                f"Path is partial at {name}; its retained routing configuration "
                f"does not contain a route toward {destination.entered}."
            )
        chain.append(next_routes[0])
    return chain, "Path is partial because the retained next-hop chain contains a loop."


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
    if finding and str(finding.get("state") or "").casefold() == "open|filtered":
        return {
            "state": "observed_inconclusive",
            "host": host,
            "finding": None,
            "coverage": None,
            "port_observation": finding,
        }
    if finding:
        return {"state": "observed_exposed", "host": host, "finding": finding, "coverage": None}
    if host:
        observed = next((
            item for item in host.get("observed_ports") or []
            if str(item.get("protocol") or "").lower() == protocol
            and int(item.get("port") or 0) == port
        ), None)
        if observed and str(observed.get("state") or "").lower() in {
            "open", "open|filtered"
        }:
            return {
                "state": "observed_inconclusive",
                "host": host,
                "finding": None,
                "coverage": None,
                "port_observation": observed,
            }
        proof = _scan_coverage_proof(host, protocol, port)
        if proof:
            return {
                "state": "not_exposed",
                "host": host,
                "finding": None,
                "coverage": proof,
            }
        return {"state": "not_observed", "host": host, "finding": None, "coverage": None}
    return {"state": "host_not_observed", "host": None, "finding": None, "coverage": None}


def _service_range_contains(services: str, port: int) -> bool:
    """Return whether an exact Nmap scaninfo service list includes a port."""
    for token in str(services or "").split(","):
        token = token.strip()
        if ":" in token:
            token = token.rsplit(":", 1)[-1].strip()
        if not token:
            continue
        if re.fullmatch(r"\d+", token):
            if int(token) == port:
                return True
            continue
        match = re.fullmatch(r"(\d+)\s*-\s*(\d+)", token)
        if match and int(match.group(1)) <= port <= int(match.group(2)):
            return True
    return False


def _scan_type_supports_exposure(scan_type: dict, protocol: str) -> bool:
    kind = str(scan_type.get("type") or "").casefold()
    if protocol == "tcp":
        return kind in {"syn", "connect"}
    return kind == "udp"


def _scan_analysis_url(
    source_refs: list[dict] | None,
    *,
    host: str | None = None,
    protocol: str | None = None,
    port: int | None = None,
) -> str | None:
    """Return the retained Analyze destination represented by scan evidence."""
    for reference in source_refs or []:
        match = re.search(r"/api/scan-runs/([^/]+)/", str(reference.get("url") or ""))
        if match:
            query = {"run": match.group(1), "focus": "host"}
            if host:
                query["host"] = host
            if protocol:
                query["protocol"] = protocol
            if port is not None:
                query["port"] = str(port)
            return f"/analysis?{urlencode(query)}"
    return None


def _scan_coverage_proof(host: dict, protocol: str, port: int) -> dict | None:
    if str(host.get("state") or "up").casefold() not in {"", "up"}:
        return None
    for coverage in host.get("scan_coverages") or []:
        for scan_type in coverage.get("scan_types") or []:
            if str(scan_type.get("protocol") or "").casefold() != protocol:
                continue
            if not _scan_type_supports_exposure(scan_type, protocol):
                continue
            services = str(scan_type.get("services") or "").strip()
            if services and _service_range_contains(services, port):
                return {
                    "scan_type": scan_type,
                    "observed_at": coverage.get("observed_at"),
                    "source_refs": list(coverage.get("source_refs") or []),
                    "command": coverage.get("command"),
                }
    return None


def _endpoint_interface(endpoint: Endpoint, analysis: dict, *, role: str | None = None) -> str | None:
    candidates = []
    for item in analysis.get("interfaces") or []:
        if _is_external_endpoint(endpoint):
            if item.get("role") == "external":
                candidates.append((0, str(item.get("name") or "")))
            continue
        if endpoint.kind not in {"host", "network"} or endpoint.value is None:
            continue
        try:
            network = ipaddress.ip_network(str(item.get("network") or ""), strict=False)
        except ValueError:
            continue
        if (
            endpoint.kind == "host" and endpoint.value in network
        ) or (
            endpoint.kind == "network" and endpoint.value.subnet_of(network)
        ):
            candidates.append((network.prefixlen, str(item.get("name") or "")))
    if _is_external_endpoint(endpoint) and not candidates:
        default_interface = _default_route_interface(analysis)
        if default_interface:
            candidates.append((0, default_interface))
    if role:
        role_candidates = [item for item in candidates if item[1] and any(
            value.get("name") == item[1] and value.get("role") == role
            for value in analysis.get("interfaces") or []
        )]
        if role_candidates:
            candidates = role_candidates
    return max(candidates, default=(0, ""))[1] or None


def _destination_nat_translations(
    source: Endpoint,
    destination: Endpoint,
    protocol: str,
    port: int,
    device_analyses: list[dict],
) -> tuple[list[dict], list[str], bool]:
    translations = []
    unresolved = []
    conflict = False
    current_destination = destination
    current_port = port
    remaining = list(enumerate(device_analyses))
    while remaining:
        candidates = []
        step_unresolved = []
        for index, analysis in remaining:
            if not (
                _source_attached(source, analysis)
                or _source_attached(current_destination, analysis)
            ):
                continue
            policies = analysis.get("policy") or {}
            iptables = policies.get("iptables") or {}
            applied = policies.get("applied") or {}
            device = analysis.get("device") or {}
            device_name = device.get("name") or device.get("address") or "Network device"
            input_interface = _endpoint_interface(source, analysis)
            arguments = {
                "source": str(source.value) if source.value is not None else None,
                "destination": str(current_destination.value) if current_destination.value is not None else None,
                "protocol": protocol, "port": current_port,
                "source_external": source.kind == "external",
                "destination_external": current_destination.kind == "external",
                "input_interface": input_interface,
                "output_interface": _egress_interface(current_destination, analysis),
            }
            evaluations = []
            if iptables.get("nat_rules"):
                evaluations.append(("ordered", evaluate_iptables_nat(iptables, **arguments)))
            if applied.get("nat_rules"):
                evaluations.append((
                    f"applied {applied.get('vendor') or 'vendor'}",
                    evaluate_vendor_nat(applied, **arguments),
                ))
            for engine, result in evaluations:
                if result.get("status") == "unknown":
                    step_unresolved.append(
                        f"{engine.capitalize()} NAT on {device_name}: "
                        f"{result.get('reason') or 'the translation path could not be resolved.'}"
                    )
                elif result.get("status") in {"translated", "redirected"}:
                    candidates.append((index, analysis, engine, result, input_interface))
        if step_unresolved:
            unresolved.extend(step_unresolved)
            break
        if not candidates:
            break
        if len(candidates) > 1:
            conflict = True
            break
        index, analysis, engine, result, input_interface = candidates[0]
        device = analysis.get("device") or {}
        rule = result.get("rule") or {}
        translation = {
            "kind": result.get("translation"), "status": result.get("status"),
            "device": device.get("name") or device.get("address") or "Network device",
            "device_address": device.get("address"),
            "original_destination": current_destination.entered,
            "original_port": current_port,
            "destination": result.get("destination"), "port": result.get("port"),
            "input_interface": input_interface, "evidence": rule.get("evidence"),
            "run_id": analysis.get("run_id"), "trace": result.get("trace") or [],
            "match_basis": result.get("match_basis") or [], "engine": engine,
            "sequence": len(translations) + 1,
        }
        translations.append(translation)
        remaining = [item for item in remaining if item[0] != index]
        if result.get("status") == "redirected" or not result.get("destination"):
            break
        next_destination = str(result["destination"])
        next_port = int(result.get("port") or current_port)
        if next_destination == current_destination.entered and next_port == current_port:
            unresolved.append("The retained destination NAT path contains a translation loop.")
            break
        current_destination = Endpoint(
            entered=next_destination, kind="host", value=ipaddress.ip_address(next_destination),
        )
        current_port = next_port
    return translations, unresolved, conflict


def _interface_address(analysis: dict, interface: str | None) -> str | None:
    if not interface:
        return None
    item = next((
        value for value in analysis.get("interfaces") or []
        if str(value.get("name") or "") == interface
    ), None)
    if not item:
        return None
    addresses = item.get("addresses") or []
    if isinstance(addresses, str):
        addresses = [addresses]
    values = [item.get("address"), *addresses]
    for value in values:
        if not value:
            continue
        try:
            parsed = ipaddress.ip_interface(str(value))
        except ValueError:
            continue
        if parsed.version == 4:
            return str(parsed.ip)
    return None


def _source_nat_translations(
    source: Endpoint,
    destination: Endpoint,
    protocol: str,
    port: int,
    device_analyses: list[dict],
) -> tuple[list[dict], list[str], bool]:
    translations = []
    unresolved = []
    conflict = False
    current_source = source
    remaining = list(enumerate(device_analyses))
    while remaining:
        candidates = []
        step_unresolved = []
        for index, analysis in remaining:
            if not _source_attached(current_source, analysis):
                continue
            policies = analysis.get("policy") or {}
            iptables = policies.get("iptables") or {}
            applied = policies.get("applied") or {}
            device = analysis.get("device") or {}
            device_name = device.get("name") or device.get("address") or "Network device"
            input_interface = _endpoint_interface(current_source, analysis)
            output_interface = _egress_interface(destination, analysis)
            arguments = {
                "source": str(current_source.value) if current_source.value is not None else None,
                "destination": str(destination.value) if destination.value is not None else None,
                "protocol": protocol, "port": port,
                "source_external": current_source.kind == "external",
                "destination_external": destination.kind == "external",
                "input_interface": input_interface, "output_interface": output_interface,
                "stage": "source",
                "masquerade_source": _interface_address(analysis, output_interface),
            }
            evaluations = []
            if iptables.get("nat_rules"):
                evaluations.append(("ordered", evaluate_iptables_nat(iptables, **arguments)))
            if applied.get("nat_rules"):
                evaluations.append((
                    f"applied {applied.get('vendor') or 'vendor'}",
                    evaluate_vendor_nat(applied, **arguments),
                ))
            for engine, result in evaluations:
                if result.get("status") == "unknown":
                    step_unresolved.append(
                        f"{engine.capitalize()} source NAT on {device_name}: "
                        f"{result.get('reason') or 'the translation path could not be resolved.'}"
                    )
                elif result.get("status") == "translated":
                    candidates.append((index, analysis, engine, result, input_interface, output_interface))
        if step_unresolved:
            unresolved.extend(step_unresolved)
            break
        if not candidates:
            break
        if len(candidates) > 1:
            conflict = True
            break
        index, analysis, engine, result, input_interface, output_interface = candidates[0]
        device = analysis.get("device") or {}
        rule = result.get("rule") or {}
        translation = {
            "kind": result.get("translation"), "status": "translated",
            "device": device.get("name") or device.get("address") or "Network device",
            "device_address": device.get("address"),
            "original_source": current_source.entered,
            "source": result.get("source"), "source_port": result.get("source_port"),
            "dynamic": bool(result.get("dynamic")), "input_interface": input_interface,
            "output_interface": output_interface, "evidence": rule.get("evidence"),
            "run_id": analysis.get("run_id"), "trace": result.get("trace") or [],
            "match_basis": result.get("match_basis") or [], "engine": engine,
            "sequence": len(translations) + 1,
        }
        translations.append(translation)
        remaining = [item for item in remaining if item[0] != index]
        if not result.get("source"):
            unresolved.append("The retained source NAT path does not identify one effective IPv4 source.")
            break
        next_source = str(result["source"])
        if next_source == current_source.entered:
            unresolved.append("The retained source NAT path contains a translation loop.")
            break
        current_source = Endpoint(
            entered=next_source, kind="host", value=ipaddress.ip_address(next_source),
        )
    return translations, unresolved, conflict


def _egress_interface(destination: Endpoint, analysis: dict) -> str | None:
    connected = _endpoint_interface(destination, analysis)
    if connected:
        return connected
    routes = [
        item for item in (analysis.get("route_analysis") or {}).get("routes") or []
        if _destination_matches(str(item.get("network") or ""), destination)
    ]
    if not routes:
        return None
    def prefix(item: dict) -> int:
        try:
            return ipaddress.ip_network(str(item.get("network") or ""), strict=False).prefixlen
        except ValueError:
            return -1
    return str(max(routes, key=prefix).get("interface") or "") or None


def _policy_decisions(
    source: Endpoint,
    destination: Endpoint,
    protocol: str,
    port: int,
    device_analyses: list[dict],
    flow_state: str = "new",
) -> tuple[list[dict], list[str]]:
    """Evaluate supported ordered iptables policy, then narrow explicit ACLs."""
    decisions = []
    unresolved = []
    for analysis in device_analyses:
        policy = (analysis.get("policy") or {}).get("iptables") or {}
        if not policy.get("rules") or not _source_attached(source, analysis):
            continue
        device = analysis.get("device") or {}
        result = evaluate_iptables_flow(
            policy,
            source=str(source.value) if source.value is not None else None,
            destination=str(destination.value) if destination.value is not None else None,
            protocol=protocol,
            port=port,
            source_external=source.kind == "external",
            destination_external=destination.kind == "external",
            input_interface=_endpoint_interface(source, analysis),
            output_interface=_egress_interface(destination, analysis),
            flow_state=flow_state,
        )
        if result.get("status") != "decided":
            unresolved.append(
                f"Ordered policy on {device.get('name') or device.get('address') or 'network device'}: "
                f"{result.get('reason') or 'no supported final verdict was reached.'}"
            )
            continue
        rule = result.get("rule") or {}
        trace = result.get("trace") or []
        chain_path = list(dict.fromkeys(
            str(item.get("chain")) for item in trace if item.get("chain")
        ))
        resolved_sets = list(dict.fromkeys(
            basis
            for item in trace
            for basis in (item.get("match_basis") or [])
            if basis.endswith(" matched")
        ))
        match_basis = []
        if chain_path:
            match_basis.append("Chain path " + " → ".join(chain_path))
        input_interface = _endpoint_interface(source, analysis)
        output_interface = _egress_interface(destination, analysis)
        if input_interface or output_interface:
            match_basis.append(
                f"Interface path {input_interface or '?'} → {output_interface or '?'}"
            )
        match_basis.extend(resolved_sets)
        match_basis.extend(result.get("match_basis") or [])
        decisions.append({
            "action": "permit" if result.get("verdict") == "allow" else "deny",
            "device": device.get("name") or device.get("address") or "Network device",
            "device_address": device.get("address"),
            "evidence": rule.get("evidence") or f"FORWARD default policy {result.get('action')}",
            "run_id": analysis.get("run_id"),
            "engine": "ordered_iptables",
            "chain": rule.get("chain") or "FORWARD",
            "rule_order": rule.get("rule_order"),
            "match_basis": list(dict.fromkeys(match_basis)),
            "trace": trace,
        })

    for analysis in device_analyses:
        applied = (analysis.get("policy") or {}).get("applied") or {}
        if not applied.get("rules") or not _source_attached(source, analysis):
            continue
        device = analysis.get("device") or {}
        result = evaluate_vendor_policy(
            applied,
            source=str(source.value) if source.value is not None else None,
            destination=str(destination.value) if destination.value is not None else None,
            protocol=protocol,
            port=port,
            source_external=source.kind == "external",
            destination_external=destination.kind == "external",
            input_interface=_endpoint_interface(source, analysis),
            output_interface=_egress_interface(destination, analysis),
            flow_state=flow_state,
        )
        if result.get("status") == "not_applied":
            continue
        if result.get("status") != "decided":
            unresolved.append(
                f"Applied {applied.get('vendor') or 'vendor'} policy on "
                f"{device.get('name') or device.get('address') or 'network device'}: "
                f"{result.get('reason') or 'no supported final verdict was reached.'}"
            )
            continue
        rule = result.get("rule") or {}
        decisions.append({
            "action": "permit" if result.get("verdict") == "allow" else "deny",
            "device": device.get("name") or device.get("address") or "Network device",
            "device_address": device.get("address"),
            "evidence": rule.get("evidence") or "Applied vendor policy",
            "run_id": analysis.get("run_id"),
            "engine": f"applied_{applied.get('vendor') or 'vendor'}",
            "rule_order": rule.get("order"),
            "match_basis": result.get("match_basis") or [],
        })

    if destination.kind != "host" or destination.value is None:
        return decisions, unresolved
    destination_ip = str(destination.value)
    pattern = re.compile(
        rf"\b(?P<action>permit|deny)\s+{re.escape(protocol)}\s+"
        rf"(?P<source>any|host\s+\d{{1,3}}(?:\.\d{{1,3}}){{3}})\s+"
        rf"host\s+{re.escape(destination_ip)}\s+(?:eq\s+)?{port}\b",
        re.I,
    )
    for analysis in device_analyses:
        analyzed_policy = analysis.get("policy") or {}
        if (
            (analyzed_policy.get("iptables") or {}).get("rules")
            or (analyzed_policy.get("applied") or {}).get("rules")
        ):
            continue
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
                "engine": "explicit_acl",
                "match_basis": ["Exact protocol, destination host, and destination port"],
            })
    return decisions, unresolved


def evaluate_reachability(
    *,
    source_text: str,
    destination_text: str,
    protocol: str,
    port: int,
    hunting: dict,
    saved_networks: list[dict],
    device_analyses: list[dict],
    flow_state: str = "new",
    source_external: bool = False,
) -> dict:
    source = parse_endpoint(source_text, external=source_external)
    destination = parse_endpoint(destination_text)
    protocol = protocol.strip().lower()
    if protocol not in {"tcp", "udp"}:
        raise ValueError("Protocol must be TCP or UDP")
    if not 1 <= port <= 65535:
        raise ValueError("Port must be between 1 and 65535")
    flow_state = str(flow_state or "new").strip().lower()
    if flow_state not in {"new", "established"}:
        raise ValueError("Flow state must be new or established")

    transit_analyses = [item for item in device_analyses if _is_transit_device(item)]
    source_external_inferred = bool(
        not source_external
        and not _is_external_endpoint(source)
        and not _endpoint_has_retained_internal_context(
            source,
            hunting=hunting,
            saved_networks=saved_networks,
            device_analyses=device_analyses,
        )
    )
    if source_external_inferred:
        source = Endpoint(
            entered=source.entered,
            kind=source.kind,
            value=source.value,
            external=True,
        )
    external_ingress_ambiguous = False
    ingress_analyses: list[dict] = []
    if _is_external_endpoint(source):
        ingress_analyses, external_ingress_ambiguous = _external_ingress_analyses(
            transit_analyses
        )
        if external_ingress_ambiguous:
            # A default route points out of a device; it does not prove that an
            # unsolicited outside flow enters through that device. In a
            # multi-edge network, do not apply unrelated site NAT or policy.
            transit_analyses = []
    (
        destination_translations,
        destination_nat_unresolved,
        translation_conflict,
    ) = _destination_nat_translations(
        source, destination, protocol, port, transit_analyses
    )
    effective_destination = destination
    effective_port = port
    if destination_translations and not translation_conflict:
        final_translation = destination_translations[-1]
        translated_address = final_translation.get("destination")
        if translated_address:
            effective_port = int(final_translation.get("port") or effective_port)
            effective_destination = Endpoint(
                entered=str(translated_address),
                kind="host",
                value=ipaddress.ip_address(str(translated_address)),
            )
    (
        source_translations,
        source_nat_unresolved,
        source_translation_conflict,
    ) = _source_nat_translations(
        source, effective_destination, protocol, effective_port,
        ingress_analyses if _is_external_endpoint(source) else transit_analyses,
    )
    translations = [*destination_translations, *source_translations]
    nat_unresolved = [*destination_nat_unresolved, *source_nat_unresolved]
    effective_source = source.entered
    if source_translations and not source_translation_conflict:
        translation = source_translations[-1]
        effective_source = translation.get("source") or (
            f"{translation.get('output_interface') or 'outgoing'} interface address"
        )

    source_network = _network_for(source, saved_networks)
    destination_network = _network_for(effective_destination, saved_networks)
    service = _service_observation(effective_destination, protocol, effective_port, hunting)
    selected_flow = (
        f"{source.entered} → {effective_destination.entered} "
        f"{protocol.upper()}/{effective_port}"
    )
    routes, excluded_routes = _matching_routes(source, effective_destination, device_analyses)
    selected_path_routes, partial_path_caveat = _selected_route_chain(
        source, effective_destination, device_analyses, routes
    )
    path_run_ids = {
        str(item.get("run_id") or "") for item in selected_path_routes
        if item.get("run_id")
    }
    policy_analyses = (
        [
            item for item in transit_analyses
            if str(item.get("run_id") or "") in path_run_ids
        ]
        if path_run_ids else transit_analyses
    )
    same_saved_network = bool(
        source_network and destination_network
        and source_network.get("saved_network_id") == destination_network.get("saved_network_id")
    )
    redirect_present = any(item.get("status") == "redirected" for item in translations)
    if (
        same_saved_network or nat_unresolved or translation_conflict
        or source_translation_conflict or redirect_present
    ):
        policy, policy_unresolved = [], []
    else:
        policy, policy_unresolved = _policy_decisions(
            source, effective_destination, protocol, effective_port, policy_analyses,
            flow_state,
        )
    evidence = []
    caveats = []
    if external_ingress_ambiguous:
        caveats.append(
            "More than one retained router or firewall could be mistaken for the "
            "outside entry point. Mark the actual External WAN gateway on the map "
            "before NCT selects an Internet-origin path."
        )
    if partial_path_caveat:
        caveats.append(partial_path_caveat)
    if source_external_inferred:
        caveats.append(
            "NCT inferred this source is external because it is absent from Saved "
            "Networks, observed hosts, and retained device interface networks. This "
            "is an evidence-boundary inference, not proof of address ownership."
        )
    elif source.external and source.value is not None:
        caveats.append(
            "The outside source designation is analyst-supplied. NCT uses the exact address or range for retained policy matching but does not verify ownership or live path availability."
        )
    if flow_state == "established":
        caveats.append(
            "Established / related evaluates retained policy for packets already marked as part of an existing or related flow; it does not prove that a live device state-table entry exists."
        )

    if source_network:
        evidence.append({"kind": "source_network", "title": source_network.get("name"), "detail": source_network.get("cidr")})
    if destination_network:
        evidence.append({"kind": "destination_network", "title": destination_network.get("name"), "detail": destination_network.get("cidr")})
    for translation in translations:
        chain_path = list(dict.fromkeys(
            str(item.get("chain")) for item in translation.get("trace") or [] if item.get("chain")
        ))
        if translation.get("kind") == "dnat":
            title = f"DNAT on {translation['device']}"
            detail = (
                f"{translation['original_destination']}:{translation['original_port']} → "
                f"{translation['destination']}:{translation['port']}"
            )
        elif translation.get("kind") == "redirect":
            title = f"Local redirect on {translation['device']}"
            detail = f"{translation['original_destination']}:{translation['original_port']} → local device:{translation['port']}"
        else:
            title = (
                f"Masquerade on {translation['device']}"
                if translation.get("kind") == "masquerade"
                else f"Source NAT on {translation['device']}"
            )
            translated_source = translation.get("source")
            if translated_source:
                translated_display = str(translated_source)
            else:
                translated_display = (
                    f"outgoing {translation.get('output_interface') or 'interface'} address"
                )
            detail = f"{translation['original_source']} → {translated_display}"
            if translation.get("source_port"):
                detail += f":{translation['source_port']}"
        if chain_path:
            detail += " · " + " → ".join(chain_path)
        evidence.append({
            "kind": "nat",
            "title": title,
            "effect": (
                f"This retained NAT rule changes the selected flow before routing and "
                f"firewall policy are evaluated: {detail}."
            ),
            "detail": detail,
            "raw": translation.get("evidence"),
            "run_id": translation.get("run_id"),
            "source_url": (
                f"/device-analysis?run={translation['run_id']}&focus=nat"
                if translation.get("run_id") else None
            ),
        })
    if service["finding"]:
        finding = service["finding"]
        service_name = finding.get("service") or "unknown service"
        evidence.append({
            "kind": "service",
            "title": f"{protocol.upper()}/{effective_port} observed open",
            "effect": (
                f"The retained Nmap result observed {protocol.upper()}/{effective_port} "
                f"open on {effective_destination.entered} from the NCT host. This proves "
                "service exposure from that scan location, not from every possible source."
            ),
            "detail": " · ".join(str(value) for value in (service_name, finding.get("product"), finding.get("version")) if value),
            "source_url": _scan_analysis_url(
                finding.get("source_refs"), host=effective_destination.entered,
                protocol=protocol, port=effective_port,
            ),
        })
    elif service["state"] == "not_exposed":
        coverage = service["coverage"] or {}
        scan_type = coverage.get("scan_type") or {}
        scan_label = str(scan_type.get("type") or "Nmap").upper()
        observed_at = coverage.get("observed_at")
        detail = (
            f"The observed host was included in retained {scan_label} coverage "
            f"that explicitly assessed {protocol.upper()}/{effective_port}; no open service was observed."
        )
        if observed_at:
            detail += f" Evidence time: {observed_at}."
        evidence.append({
            "kind": "coverage",
            "title": f"{protocol.upper()}/{effective_port} assessed — not exposed",
            "effect": (
                f"The retained Nmap scan explicitly assessed {protocol.upper()}/{effective_port} "
                f"on {effective_destination.entered} and did not observe an exposed service "
                "from the NCT host. The missing listener is expected to prevent an application "
                "connection from that scan vantage, but it is not proof that a firewall rule "
                "caused the result."
            ),
            "detail": detail,
            "raw": coverage.get("command"),
            "source_url": _scan_analysis_url(
                coverage.get("source_refs"), host=effective_destination.entered,
                protocol=protocol, port=effective_port,
            ),
        })
        caveats.append(
            "Not Exposed reflects the retained Nmap observation from the NCT host at scan time; later service or filtering changes require a new scan."
        )
    elif service["state"] == "observed_inconclusive":
        caveats.append(
            f"The retained result for {protocol.upper()}/{effective_port} was open|filtered, so NCT cannot establish whether the service was exposed."
        )
    elif service["state"] == "not_observed":
        caveats.append(f"The destination host was observed, but {protocol.upper()}/{effective_port} was not present in retained open-port evidence. This is not proof that policy blocks it.")
    elif service["state"] == "host_not_observed":
        caveats.append("The destination host is not present in the current retained network-wide scan evidence.")

    selected_prefix = routes[0].get("prefix") if routes else None
    for route_index, route in enumerate(routes[:5]):
        priority = ""
        if route.get("preference") is not None:
            priority += f" · preference {route['preference']}"
        if route.get("metric") is not None:
            priority += f" · metric {route['metric']}"
        route_role = (
            "selected" if route_index == 0
            else "alternate" if route.get("prefix") == selected_prefix
            else "fallback"
        )
        title_prefix = {
            "selected": "Selected route",
            "alternate": "Equal-prefix alternate route",
            "fallback": "Fallback route — not selected",
        }[route_role]
        effect = (
            f"This retained route is the most-specific forwarding path toward "
            f"{effective_destination.entered}. It does not by itself allow or block "
            f"{protocol.upper()}/{effective_port}."
            if route_role == "selected"
            else (
                f"This equally specific retained route may provide another path toward "
                f"{effective_destination.entered}; live forwarding and tie-break behavior were not verified."
                if route_role == "alternate"
                else (
                    f"This broader retained route is not used while the selected more-specific route "
                    f"exists. It would only become relevant if that route were removed or unavailable."
                )
            )
        )
        evidence.append({
            "kind": "route",
            "route_role": route_role,
            "title": f"{title_prefix} on {route['device']}",
            "effect": effect,
            "detail": f"{route['network']} via {route.get('via') or 'direct'}" + (f" · {route['interface']}" if route.get("interface") else "") + priority,
            "raw": route.get("evidence"),
            "run_id": route.get("run_id"),
            "source_url": (
                f"/device-analysis?run={route['run_id']}&focus=routing"
                if route.get("run_id") else None
            ),
        })
    for hop_index, route in enumerate(selected_path_routes[1:], 2):
        evidence.append({
            "kind": "route",
            "route_role": "selected_path_hop",
            "title": f"Selected path hop {hop_index} on {route['device']}",
            "effect": (
                "This retained next-hop routing decision extends the selected path. "
                "It does not by itself allow or block the service."
            ),
            "detail": (
                f"{route['network']} via {route.get('via') or 'direct'}"
                + (f" · {route['interface']}" if route.get("interface") else "")
            ),
            "raw": route.get("evidence"),
            "run_id": route.get("run_id"),
            "source_url": (
                f"/device-analysis?run={route['run_id']}&focus=routing"
                if route.get("run_id") else None
            ),
        })
    top_prefix_routes = [
        item for item in routes
        if routes and item.get("prefix") == routes[0].get("prefix")
    ]
    if len(top_prefix_routes) > 1:
        if all(item.get("priority_comparable") for item in top_prefix_routes):
            caveats.append(
                f"Equally specific retained routes were ordered by {routes[0].get('selection_basis')}; live forwarding, health checks, and vendor-specific tie-breakers were not verified."
            )
        else:
            caveats.append(
                "More than one equally specific route covers the destination, but explicit comparable preference or metric evidence is incomplete; NCT cannot establish the active path."
            )
    for decision in policy:
        basis = ", ".join(decision.get("match_basis") or [])
        engine = str(decision.get("engine") or "")
        policy_kind = "Ordered" if engine == "ordered_iptables" else "Applied" if engine.startswith("applied_") else "Explicit"
        evidence.append({
            "kind": "policy",
            "title": f"{policy_kind} {decision['action']} on {decision['device']}",
            "action": decision["action"],
            "effect": (
                f"This retained {'ACL entry' if engine == 'explicit_acl' else 'firewall rule'} "
                f"is expected to {'allow' if decision['action'] == 'permit' else 'block'} "
                f"{selected_flow}."
            ),
            "detail": decision["evidence"] + (f" · {basis}" if basis else ""),
            "run_id": decision.get("run_id"),
            "source_url": (
                f"/device-analysis?run={decision['run_id']}&focus=policy"
                if decision.get("run_id") else None
            ),
        })
    if any(
        "resolved dynamic object" in str(basis).lower()
        for decision in policy for basis in (decision.get("match_basis") or [])
    ):
        caveats.append(
            "Dynamic/DNS object matches use a retained runtime table snapshot from the device collection; refresh the collection after DNS or alias membership changes."
        )

    caveats.extend(nat_unresolved)
    caveats.extend(policy_unresolved)
    if translation_conflict:
        caveats.append("Retained devices produced conflicting destination translations, so NCT did not choose an effective target.")
    if source_translation_conflict:
        caveats.append("More than one retained device produced a source translation for this flow, so NCT did not carry a translated source identity through the path.")
    if redirect_present:
        caveats.append("The retained NAT policy redirects this flow to the network device itself; a normal forwarded-path verdict is not applicable.")

    outcome = "Unknown"
    confidence = "low"
    explanation = "Retained evidence does not establish an end-to-end decision."
    actions = {item["action"] for item in policy}
    if external_ingress_ambiguous:
        outcome, confidence = "Unknown", "low"
        explanation = (
            "The outside entry point is ambiguous, so NCT did not guess an "
            "Internet-origin path."
        )
    elif nat_unresolved or translation_conflict or source_translation_conflict or redirect_present:
        outcome, confidence = "Unknown", "low"
        explanation = "NAT changes or may change the selected flow before forwarded policy is evaluated."
    elif len(actions) > 1:
        outcome, confidence = "Unknown", "low"
        explanation = "Retained policy sources produced conflicting ordered decisions."
        caveats.append("Conflicting allow and deny results require path and device review before drawing a conclusion.")
    elif actions == {"deny"}:
        outcome, confidence = "Expected Blocked", "high"
        explanation = (
            "The retained ordered policy denies this established or related flow for the selected endpoints and service."
            if flow_state == "established"
            else "The retained ordered policy denies this new flow for the selected endpoints and service."
        )
    elif service["state"] == "not_exposed":
        outcome, confidence = "Not Exposed", "high"
        explanation = (
            f"Retained Nmap evidence explicitly assessed {protocol.upper()}/{effective_port} "
            "on the observed destination and did not find the service exposed from the NCT host."
        )
    elif actions == {"permit"}:
        outcome, confidence = "Expected Allowed", "high"
        explanation = (
            "The retained ordered policy permits this established or related flow for the selected endpoints and service."
            if flow_state == "established"
            else "The retained ordered policy permits this new flow for the selected endpoints and service."
        )
    elif same_saved_network:
        outcome, confidence = "Local", "medium"
        explanation = "Source and destination are within the same Saved Network. Host firewall and local segmentation may still affect access."
    elif partial_path_caveat:
        outcome, confidence = "Unknown", "low"
        explanation = (
            "Retained routing evidence establishes only a partial path; the next "
            "forwarding device could not be proven."
        )
    elif routes:
        outcome, confidence = "Routed", "medium"
        explanation = "A retained route covers the destination, but no exact allow or deny policy was established."

    if not policy and not same_saved_network:
        caveats.append("No complete supported ordered-policy path established an allow or deny decision. NAT translation or unsupported application-aware criteria may still change the real path.")
    if service["state"] == "observed_exposed" and outcome == "Unknown":
        caveats.append("The service was observed open from the NCT host, but that does not prove it is reachable from the selected source.")

    path = []
    if source_network:
        path.append({"kind": "source", "label": source_network.get("name") or source.entered, "detail": source_network.get("cidr")})
    else:
        path.append({
            "kind": "source", "label": source.entered,
            "detail": "External address / range" if _is_external_endpoint(source) else "Selected source",
        })
    for translation in destination_translations:
        if translation.get("kind") != "dnat":
            continue
        path.append({
            "kind": "nat",
            "label": f"DNAT on {translation['device']}",
            "detail": (
                f"{translation['original_destination']}:{translation['original_port']} → "
                f"{translation['destination']}:{translation['port']}"
            ),
        })
    if outcome == "Local":
        path.append({"kind": "segment", "label": "Same local segment", "detail": destination_network.get("cidr") if destination_network else ""})
    elif selected_path_routes:
        for route in selected_path_routes:
            path.append({"kind": "device", "label": route["device"], "detail": route.get("device_address") or "Routing device"})
            priority = ""
            if route.get("preference") is not None:
                priority += f" · preference {route['preference']}"
            if route.get("metric") is not None:
                priority += f" · metric {route['metric']}"
            path.append({"kind": "route", "label": route["network"], "detail": f"via {route.get('via') or 'direct'}" + (f" · {route['interface']}" if route.get("interface") else "") + priority})
    for translation in source_translations:
        translated_display = translation.get("source") or (
            f"{translation.get('output_interface') or 'outgoing interface'} address"
        )
        path.append({
            "kind": "nat",
            "label": (
                f"Masquerade on {translation['device']}"
                if translation.get("kind") == "masquerade"
                else f"Source NAT on {translation['device']}"
            ),
            "detail": f"{translation['original_source']} → {translated_display}",
        })
    path.append({
        "kind": "destination",
        "label": effective_destination.entered,
        "detail": f"{protocol.upper()}/{effective_port}",
    })

    return {
        "status": "reachability_analysis_complete",
        "outcome": outcome,
        "confidence": confidence,
        "explanation": explanation,
        "query": {
            "source": source.entered,
            "effective_source": effective_source,
            "destination": destination.entered,
            "protocol": protocol,
            "port": port,
            "effective_destination": effective_destination.entered,
            "effective_port": effective_port,
            "flow_state": flow_state,
            "source_external": _is_external_endpoint(source),
            "source_external_basis": (
                "inferred_outside_retained_network"
                if source_external_inferred else
                "operator_designated" if source.external else "retained_internal_context"
            ),
        },
        "source_network": source_network,
        "destination_network": destination_network,
        "service_observation": service["state"],
        "path": path,
        "evidence": evidence,
        "retained_objects": {
            "routes": routes,
            "selected_path_routes": selected_path_routes,
            "policy": policy,
            "nat": translations,
        },
        "caveats": list(dict.fromkeys(caveats)),
        "counts": {
            "routes": len(routes),
            "excluded_non_transit_routes": len(excluded_routes),
            "policy_decisions": len(policy),
            "policy_unresolved": len(policy_unresolved),
            "nat_translations": len(translations),
            "destination_nat_translations": len(destination_translations),
            "source_nat_translations": len(source_translations),
            "nat_unresolved": len(nat_unresolved),
            "coverage_proofs": 1 if service["state"] == "not_exposed" else 0,
            "evidence": len(evidence),
        },
    }


def _range_group_prefix(network: ipaddress.IPv4Network) -> int:
    """Use the next octet boundary so a broad query stays bounded to 256 rows."""
    if network.prefixlen >= 24:
        return 32
    return min(24, ((network.prefixlen // 8) + 1) * 8)


def _overlap_network(
    candidate: ipaddress.IPv4Network, target: ipaddress.IPv4Network
) -> ipaddress.IPv4Network | None:
    if not candidate.overlaps(target):
        return None
    return candidate if candidate.subnet_of(target) else target


def _ipv4_network(value: object) -> ipaddress.IPv4Network | None:
    try:
        network = ipaddress.ip_network(str(value or "").strip(), strict=False)
    except ValueError:
        return None
    return network if network.version == 4 else None


def _range_port_matches(specification: object, port: int) -> bool:
    text = str(specification or "").strip()
    if not text:
        return True
    understood = False
    for raw in text.split(","):
        value = raw.strip()
        if not value:
            continue
        if value.isdigit():
            understood = True
            if int(value) == port:
                return True
            continue
        match = re.fullmatch(r"(\d+)[:\-](\d+)", value)
        if match:
            understood = True
            if int(match.group(1)) <= port <= int(match.group(2)):
                return True
    # Unknown named or object-based service criteria remain relevant so the
    # coverage view never hides a possible policy boundary.
    return not understood


def _range_rule_service_relevant(rule: dict, protocol: str, port: int) -> bool:
    rule_protocol = str(rule.get("protocol") or "").strip().lower()
    if rule_protocol and rule_protocol not in {"ip", "any", "all", "tcp_udp"}:
        if rule_protocol != protocol:
            return False
    if rule.get("destination_port") is not None:
        try:
            if int(rule["destination_port"]) != port:
                return False
        except (TypeError, ValueError):
            pass
    if rule.get("destination_ports") and not _range_port_matches(
        rule.get("destination_ports"), port
    ):
        return False
    return True


def _range_object_networks(
    objects: dict[str, dict], name: str, stack: tuple[str, ...] = ()
) -> list[ipaddress.IPv4Network]:
    if name in stack or len(stack) >= 20:
        return []
    item = objects.get(name) or {}
    networks = []
    for member in item.get("members") or []:
        if member.get("ref"):
            networks.extend(_range_object_networks(
                objects, str(member["ref"]), stack + (name,)
            ))
            continue
        if member.get("value"):
            network = _ipv4_network(member["value"])
            if network:
                networks.append(network)
            continue
        if member.get("range"):
            try:
                start, end = (
                    ipaddress.ip_address(value) for value in member["range"]
                )
            except (TypeError, ValueError):
                continue
            if start.version == 4 and end.version == 4 and start <= end:
                networks.extend(ipaddress.summarize_address_range(start, end))
    return networks


def _range_policy_networks(
    source: Endpoint,
    target: ipaddress.IPv4Network,
    protocol: str,
    port: int,
    device_analyses: list[dict],
) -> list[ipaddress.IPv4Network]:
    """Return retained destination boundaries that may change this service result."""
    found: set[ipaddress.IPv4Network] = set()

    def add(network: ipaddress.IPv4Network | None) -> None:
        if network and (overlap := _overlap_network(network, target)):
            found.add(overlap)

    for analysis in device_analyses:
        if not _is_transit_device(analysis) or not _source_attached(source, analysis):
            continue
        policy = analysis.get("policy") or {}
        iptables = policy.get("iptables") or {}
        ipsets = {
            str(item.get("name") or ""): item
            for item in iptables.get("ipsets") or [] if item.get("name")
        }
        for rule in [
            *(iptables.get("rules") or []),
            *(iptables.get("nat_rules") or []),
        ]:
            if not _range_rule_service_relevant(rule, protocol, port):
                continue
            add(_ipv4_network(rule.get("destination")))
            for match in rule.get("set_matches") or []:
                if "dst" not in (match.get("directions") or []):
                    continue
                for network in _range_object_networks(
                    ipsets, str(match.get("name") or "")
                ):
                    add(network)

        applied = policy.get("applied") or {}
        address_objects = dict(applied.get("address_objects") or {})
        for book in (applied.get("address_books") or {}).values():
            for name, item in (book or {}).items():
                address_objects.setdefault(name, item)
        for rule in [
            *(applied.get("rules") or []),
            *(applied.get("nat_rules") or []),
        ]:
            if not _range_rule_service_relevant(rule, protocol, port):
                continue
            destinations = rule.get("destinations") or [rule.get("destination")]
            for value in destinations:
                text = str(value or "").strip()
                if not text or text.lower() in {"any", "any-ipv4", "any-ipv6"}:
                    continue
                if text.startswith("@"):
                    for network in _range_object_networks(address_objects, text[1:]):
                        add(network)
                    continue
                network = _ipv4_network(text)
                if network:
                    add(network)
                elif text in address_objects:
                    for network in _range_object_networks(address_objects, text):
                        add(network)
    return sorted(found, key=lambda item: (int(item.network_address), item.prefixlen))


def _range_scoped_analyses(
    target: ipaddress.IPv4Network, device_analyses: list[dict]
) -> list[dict]:
    """Keep only routes that can affect the selected range or a default fallback."""
    scoped = []
    for analysis in device_analyses:
        route_analysis = analysis.get("route_analysis") or {}
        routes = []
        for route in route_analysis.get("routes") or []:
            network = _ipv4_network(route.get("network"))
            if network and (network.prefixlen == 0 or network.overlaps(target)):
                routes.append(route)
        scoped.append({
            **analysis,
            "route_analysis": {**route_analysis, "routes": routes},
        })
    return scoped


def _range_route_is_connected(route: dict) -> bool:
    return bool(
        route.get("direct") is True
        or str(route.get("route_type") or "").strip().lower() == "connected"
        or str(route.get("protocol") or "").strip().lower() in {"connected", "local"}
    )


def evaluate_reachability_range(
    *,
    source_text: str,
    destination_text: str,
    protocol: str,
    port: int,
    hunting: dict,
    saved_networks: list[dict],
    device_analyses: list[dict],
    flow_state: str = "new",
    source_external: bool = False,
) -> dict:
    """Summarize only evidence-backed targets inside a broad destination range."""
    source = parse_endpoint(source_text, external=source_external)
    destination = parse_endpoint(destination_text)
    if destination.kind != "network" or not isinstance(
        destination.value, ipaddress.IPv4Network
    ):
        raise ValueError("Range coverage requires an IPv4 destination CIDR")
    protocol = protocol.strip().lower()
    if protocol not in {"tcp", "udp"}:
        raise ValueError("Protocol must be TCP or UDP")
    if not 1 <= port <= 65535:
        raise ValueError("Port must be between 1 and 65535")
    flow_state = str(flow_state or "new").strip().lower()
    if flow_state not in {"new", "established"}:
        raise ValueError("Flow state must be new or established")

    target = destination.value
    grouping_prefix = _range_group_prefix(target)
    if (
        not _is_external_endpoint(source)
        and not _endpoint_has_retained_internal_context(
            source,
            hunting=hunting,
            saved_networks=saved_networks,
            device_analyses=device_analyses,
        )
    ):
        source = Endpoint(
            entered=source.entered, kind=source.kind, value=source.value, external=True
        )

    entries: list[dict] = []

    def add(kind: str, network: ipaddress.IPv4Network | None, **details: object) -> None:
        if network and (overlap := _overlap_network(network, target)):
            entries.append({"kind": kind, "network": overlap, **details})

    for saved in saved_networks:
        add(
            "saved_network", _ipv4_network(saved.get("cidr")),
            label=saved.get("name") or saved.get("cidr"),
        )
    for analysis in device_analyses:
        device = analysis.get("device") or {}
        for interface in analysis.get("interfaces") or []:
            add(
                "interface", _ipv4_network(interface.get("network")),
                label=f"{device.get('name') or device.get('address') or 'Device'} · {interface.get('name') or 'interface'}",
            )
        if not _is_transit_device(analysis):
            continue
        for route in (analysis.get("route_analysis") or {}).get("routes") or []:
            network = _ipv4_network(route.get("network"))
            if network and network.prefixlen:
                add(
                    "connected_route" if _range_route_is_connected(route) else "route",
                    network,
                    label=device.get("name") or device.get("address") or "Network device",
                    line=route.get("line"),
                )
    observed = {}
    for host in [*(hunting.get("hosts") or []), *(hunting.get("findings") or [])]:
        network = _ipv4_network(host.get("ip"))
        if not network or network.prefixlen != 32 or not network.subnet_of(target):
            continue
        observed[str(network.network_address)] = host
    for address, host in observed.items():
        add(
            "observed_host", _ipv4_network(address),
            label=host.get("hostname") or address,
        )

    # Only specific evidence creates candidate rows. Summary/default routes and
    # non-connected routes still participate in each candidate's evaluation but
    # do not manufacture target subnets from the routing table alone.
    discovery_entries = [
        item for item in entries
        if item["kind"] != "route"
        and item["network"].prefixlen >= grouping_prefix
    ]
    buckets: dict[str, ipaddress.IPv4Network] = {}
    for item in discovery_entries:
        network = item["network"]
        bucket = (
            network
            if network.prefixlen == grouping_prefix
            else network.supernet(new_prefix=grouping_prefix)
        )
        buckets[str(bucket)] = bucket

    policy_networks = _range_policy_networks(
        source, target, protocol, port, device_analyses
    )
    scoped_analyses = _range_scoped_analyses(target, device_analyses)
    rows = []
    for bucket in sorted(buckets.values(), key=lambda item: int(item.network_address)):
        bucket_entries = [item for item in entries if item["network"].overlaps(bucket)]
        specific_entries = [
            item for item in discovery_entries if item["network"].overlaps(bucket)
        ]
        covered = list(ipaddress.collapse_addresses(
            item["network"] for item in specific_entries
        ))
        identified_addresses = sum(int(item.num_addresses) for item in covered)
        source_counts = {
            kind: sum(item["kind"] == kind for item in bucket_entries)
            for kind in (
                "saved_network", "interface", "connected_route", "route", "observed_host"
            )
        }
        route_networks = sorted({
            item["network"] for item in bucket_entries
            if item["kind"] in {"connected_route", "route"}
        }, key=lambda item: (int(item.network_address), item.prefixlen))
        route_coverage = list(ipaddress.collapse_addresses(
            network if network.subnet_of(bucket) else bucket
            for network in route_networks if network.overlaps(bucket)
        ))
        routed_addresses = sum(int(item.num_addresses) for item in route_coverage)
        policy_boundaries = [
            network for network in policy_networks
            if network.overlaps(bucket)
        ]
        has_more_specific_route = any(
            network.subnet_of(bucket) and network.prefixlen > bucket.prefixlen
            for network in route_networks
        )
        has_more_specific_policy = any(
            network.subnet_of(bucket) and network.prefixlen > bucket.prefixlen
            for network in policy_boundaries
        )
        full_identification = identified_addresses == int(bucket.num_addresses)
        mixed = (
            not full_identification
            or has_more_specific_route
            or has_more_specific_policy
        )
        exact_result = None
        if not mixed:
            exact_result = evaluate_reachability(
                source_text=source_text,
                destination_text=str(bucket),
                protocol=protocol,
                port=port,
                flow_state=flow_state,
                source_external=source_external,
                # Host-level scan results cannot safely represent a whole range.
                hunting={"hosts": [], "findings": []},
                saved_networks=saved_networks,
                device_analyses=scoped_analyses,
            )
        if mixed:
            outcome, confidence = "Mixed", "low"
            explanation = (
                "Retained evidence identifies targets inside this segment, but "
                "more-specific route, policy, or host evidence differs within it."
            )
        else:
            outcome = str(exact_result.get("outcome") or "Unknown")
            confidence = str(exact_result.get("confidence") or "low")
            explanation = str(exact_result.get("explanation") or "")
            if (
                outcome == "Unknown"
                and not (exact_result.get("retained_objects") or {}).get("routes")
            ):
                outcome = "No Route"
                explanation = "No retained route from the selected source covers this target segment."
        rows.append({
            "network": str(bucket),
            "address_count": int(bucket.num_addresses),
            "identified_address_count": identified_addresses,
            "identified_percent": round(
                identified_addresses * 100 / int(bucket.num_addresses), 4
            ),
            "routed_address_count": routed_addresses,
            "routed_percent": round(
                routed_addresses * 100 / int(bucket.num_addresses), 4
            ),
            "outcome": outcome,
            "confidence": confidence,
            "explanation": explanation,
            "evidence_counts": source_counts,
            "route_prefix_count": len(route_networks),
            "policy_boundary_count": len(policy_boundaries),
            "drill_down": bucket.prefixlen < 32,
            "detail_target": str(bucket) if bucket.prefixlen < 32 else None,
            "path": (exact_result or {}).get("path") or [],
            "caveats": (exact_result or {}).get("caveats") or [],
        })

    outcome_counts = {}
    for row in rows:
        outcome_counts[row["outcome"]] = outcome_counts.get(row["outcome"], 0) + 1
    broad_counts = {
        kind: sum(
            item["kind"] == kind and item["network"].prefixlen < grouping_prefix
            for item in entries
        )
        for kind in ("saved_network", "interface", "connected_route", "route")
    }
    evidence_counts = {
        kind: sum(item["kind"] == kind for item in entries)
        for kind in (
            "saved_network", "interface", "connected_route", "observed_host", "route"
        )
    }
    return {
        "status": "reachability_range_analysis_complete",
        "query": {
            "source": source_text,
            "destination": str(target),
            "protocol": protocol,
            "port": port,
            "flow_state": flow_state,
            "source_external": _is_external_endpoint(source),
        },
        "destination_network": str(target),
        "grouping_prefix": grouping_prefix,
        "candidate_count": len(rows),
        "candidates": rows,
        "outcome_counts": outcome_counts,
        "evidence_counts": evidence_counts,
        "broad_evidence_counts": broad_counts,
        "observed_host_count": len(observed),
        "explanation": (
            f"NCT identified {len(rows)} evidence-backed /{grouping_prefix} target "
            f"segment{'s' if len(rows) != 1 else ''} inside {target}."
        ),
        "caveats": [
            "Only target segments supported by retained connected networks, Saved Networks, or observed hosts are shown; unobserved theoretical addresses are omitted.",
            "Static, dynamic, summary, and default routes help evaluate identified targets but do not create target segments by themselves.",
            "Range results use routing and policy evidence. Host-level Nmap service observations are used to identify targets but are not generalized to an entire subnet.",
            "Open any /16 or /24 row to evaluate the next level. NCT continues to show only evidence-backed targets rather than expanding every possible address.",
        ],
    }


def _endpoint_address_count(endpoint: Endpoint) -> int | None:
    if endpoint.value is None:
        return None
    if endpoint.kind == "host":
        return 1
    return int(endpoint.value.num_addresses)


def _path_without_proposals(result: dict) -> list[dict]:
    return [
        {key: item.get(key) for key in ("kind", "label", "detail")}
        for item in result.get("path") or [] if item.get("kind") != "proposal"
    ]


def _compact_route_options(routes: list[dict]) -> list[dict]:
    fields = (
        "device", "device_address", "network", "via", "interface",
        "preference", "metric", "selection_basis", "selection_order",
        "priority_comparable",
    )
    return [{field: item.get(field) for field in fields} for item in routes]


SUPPORTED_POLICY_VENDORS = {"cisco", "vyos", "pfsense", "juniper", "unifi"}


def _selected_policy_device(device_analyses: list[dict], device_key: str) -> dict:
    selected = next((
        item for item in device_analyses
        if device_key in {
            str(item.get("run_id") or ""),
            str((item.get("device") or {}).get("address") or ""),
            str((item.get("device") or {}).get("name") or ""),
        }
    ), None)
    if selected is None or not _is_transit_device(selected):
        raise ValueError("Choose a retained router or firewall for the proposed control")
    return selected


def _policy_vendor(analysis: dict) -> str:
    device = analysis.get("device") or {}
    applied = (analysis.get("policy") or {}).get("applied") or {}
    vendor = str(device.get("vendor") or applied.get("vendor") or "").strip().lower()
    aliases = {
        "ios": "cisco", "ios-xe": "cisco", "asa": "cisco",
        "junos": "juniper", "pf": "pfsense", "ubiquiti": "unifi",
        "linux": "unifi",
    }
    vendor = aliases.get(vendor, vendor)
    if vendor not in SUPPORTED_POLICY_VENDORS:
        if ((analysis.get("policy") or {}).get("iptables") or {}).get("rules"):
            return "unifi"
        if applied.get("vendor") in SUPPORTED_POLICY_VENDORS:
            return str(applied["vendor"])
        # Older retained collections did not always record vendor. Cisco syntax
        # is the safest legacy fallback because their generic ACLs were retained.
        return "cisco"
    return vendor


def policy_templates(vendor: str) -> list[dict]:
    names = {
        "cisco": "Extended ACL service rule",
        "vyos": "IPv4 forward service rule",
        "pfsense": "Interface quick service rule",
        "juniper": "Zone policy service rule",
        "unifi": "FORWARD chain service rule",
    }
    return [
        {
            "id": "exact-service",
            "name": names.get(vendor, "Exact service rule"),
            "description": "Match the entered source, destination, protocol, and port.",
        },
        {
            "id": "interface-service",
            "name": f"{names.get(vendor, 'Service rule')} from any source",
            "description": "Match any source arriving on the selected interface to the entered destination service.",
        },
    ]


def policy_rule_context(analysis: dict) -> dict:
    """Return interface-aware, ordered policy evidence for a planning UI."""
    device = analysis.get("device") or {}
    policy = analysis.get("policy") or {}
    applied = policy.get("applied") or {}
    iptables = policy.get("iptables") or {}
    attachments = applied.get("attachments") or []
    rules = []
    for item in applied.get("rules") or []:
        matching = [
            attachment for attachment in attachments
            if attachment.get("policy") == item.get("policy")
        ]
        rules.append({
            "engine": "vendor",
            "policy": item.get("policy"),
            "order": item.get("sequence") or item.get("order"),
            "action": item.get("action"),
            "interface": ", ".join(dict.fromkeys(
                str(value.get("interface")) for value in matching if value.get("interface")
            )) or item.get("interface") or item.get("input_interface"),
            "direction": ", ".join(dict.fromkeys(
                str(value.get("direction")) for value in matching if value.get("direction")
            )) or item.get("direction"),
            "evidence": item.get("evidence") or "Parsed vendor policy rule",
        })
    for item in iptables.get("rules") or []:
        rules.append({
            "engine": "iptables",
            "policy": item.get("chain") or "FORWARD",
            "order": item.get("rule_order") or item.get("order"),
            "action": {
                "accept": "permit", "drop": "deny", "reject": "deny",
            }.get(str(item.get("action") or "").lower(), item.get("action")),
            "interface": item.get("input_interface"),
            "direction": "in",
            "evidence": item.get("evidence") or "Parsed ordered firewall rule",
        })
    if not rules:
        for order, item in enumerate(policy.get("firewall_acl") or [], start=1):
            evidence = item.get("evidence") if isinstance(item, dict) else str(item)
            action_match = re.search(r"\b(permit|deny|allow|block)\b", evidence or "", re.I)
            action = action_match.group(1).lower() if action_match else None
            rules.append({
                "engine": "retained_acl", "policy": "Retained ACL", "order": order,
                "action": {"allow": "permit", "block": "deny"}.get(action, action),
                "interface": None, "direction": None,
                "evidence": evidence or "Retained firewall / ACL evidence",
            })
    for index, item in enumerate(rules):
        item["index"] = index
        item["position"] = index + 1
    interfaces = [
        {
            "name": str(item.get("name") or ""),
            "address": item.get("address"),
            "network": item.get("network"),
            "role": item.get("role"),
        }
        for item in analysis.get("interfaces") or [] if item.get("name")
    ]
    vendor = _policy_vendor(analysis)
    return {
        "run_id": analysis.get("run_id"),
        "device": {
            "name": device.get("name"), "address": device.get("address"),
            "type": device.get("type"), "vendor": vendor,
        },
        "vendor": vendor,
        "interfaces": interfaces,
        "rules": rules,
        "positions": [
            {
                "index": index,
                "label": (
                    "First rule"
                    if index == 0 else
                    f"After rule {index}" if index < len(rules) else
                    f"After rule {len(rules)} (last)"
                ),
            }
            for index in range(len(rules) + 1)
        ],
        "templates": policy_templates(vendor),
    }


def _endpoint_rule_value(endpoint: Endpoint, *, any_source: bool = False) -> str:
    if any_source or endpoint.value is None:
        return "any"
    return str(endpoint.value)


def _cisco_endpoint(value: str) -> str:
    if value == "any":
        return "any"
    network = ipaddress.ip_network(value, strict=False)
    if network.prefixlen == 32:
        return f"host {network.network_address}"
    wildcard = ipaddress.IPv4Address(int(network.hostmask))
    return f"{network.network_address} {wildcard}"


def _policy_sequence(context: dict, insertion_index: int) -> int:
    existing = [
        int(item["order"]) for item in context.get("rules") or []
        if str(item.get("order") or "").isdigit()
    ]
    if not existing:
        return 10
    if insertion_index <= 0:
        return max(1, existing[0] // 2)
    if insertion_index >= len(existing):
        return existing[-1] + 10
    before, after = existing[insertion_index - 1], existing[insertion_index]
    return before + max(1, (after - before) // 2)


def build_vendor_policy_rule(
    *, analysis: dict, source_text: str, destination_text: str,
    protocol: str, port: int, action: str, interface_name: str,
    insertion_index: int = 0, template_id: str = "exact-service",
    source_external: bool = False,
) -> dict:
    """Build an editable, vendor-native rule for one retained device."""
    context = policy_rule_context(analysis)
    vendor = context["vendor"]
    interfaces = {item["name"] for item in context["interfaces"]}
    if interface_name not in interfaces:
        raise ValueError("Choose one retained interface on the selected device")
    if not 0 <= insertion_index <= len(context["rules"]):
        raise ValueError("Choose a valid position in the existing rule order")
    if template_id not in {item["id"] for item in context["templates"]}:
        raise ValueError("Choose a supported rule template for the selected vendor")
    action = str(action or "").lower()
    if action not in {"permit", "deny"}:
        raise ValueError("Proposed policy action must be permit or deny")
    source = parse_endpoint(source_text, external=source_external)
    destination = parse_endpoint(destination_text)
    any_source = template_id == "interface-service"
    source_value = _endpoint_rule_value(source, any_source=any_source)
    destination_value = _endpoint_rule_value(destination)
    sequence = _policy_sequence(context, insertion_index)
    output_interface = _egress_interface(destination, analysis)
    token = re.sub(r"[^A-Za-z0-9_-]+", "-", interface_name).strip("-") or "INTERFACE"
    policy_name = f"NCT-IN-{token}"[:48]
    rule_text = ""
    if vendor == "cisco":
        attached = next((
            item for item in ((analysis.get("policy") or {}).get("applied") or {}).get("attachments") or []
            if item.get("interface") == interface_name and item.get("direction") == "in"
        ), None)
        policy_name = str((attached or {}).get("policy") or policy_name)
        rule_text = (
            f"ip access-list extended {policy_name}\n"
            f" {sequence} {action} {protocol} {_cisco_endpoint(source_value)} "
            f"{_cisco_endpoint(destination_value)} eq {port}\n!\n"
            f"interface {interface_name}\n ip access-group {policy_name} in"
        )
    elif vendor == "vyos":
        decision = "accept" if action == "permit" else "drop"
        lines = [
            f"set firewall ipv4 forward filter rule {sequence} action '{decision}'",
            f"set firewall ipv4 forward filter rule {sequence} inbound-interface name '{interface_name}'",
            f"set firewall ipv4 forward filter rule {sequence} protocol '{protocol}'",
        ]
        if source_value != "any":
            lines.append(f"set firewall ipv4 forward filter rule {sequence} source address '{source_value}'")
        if destination_value != "any":
            lines.append(f"set firewall ipv4 forward filter rule {sequence} destination address '{destination_value}'")
        lines.append(f"set firewall ipv4 forward filter rule {sequence} destination port '{port}'")
        rule_text = "\n".join(lines)
        policy_name = "forward-filter"
    elif vendor == "pfsense":
        decision = "pass" if action == "permit" else "block"
        rule_text = (
            f"{decision} in quick on {interface_name} inet proto {protocol} "
            f"from {source_value} to {destination_value} port = {port}"
        )
        policy_name = "pfctl-active"
    elif vendor == "unifi":
        decision = "ACCEPT" if action == "permit" else "DROP"
        parts = [f"-A FORWARD", f"-i {interface_name}"]
        if output_interface:
            parts.append(f"-o {output_interface}")
        parts.append(f"-p {protocol}")
        if source_value != "any":
            parts.append(f"-s {source_value}")
        if destination_value != "any":
            parts.append(f"-d {destination_value}")
        parts.extend([f"--dport {port}", f"-j {decision}"])
        rule_text = "*filter\n:FORWARD ACCEPT [0:0]\n" + " ".join(parts) + "\nCOMMIT"
        policy_name = "FORWARD"
    elif vendor == "juniper":
        applied = (analysis.get("policy") or {}).get("applied") or {}
        zones = applied.get("interface_zones") or {}
        from_zone = str(zones.get(interface_name) or f"nct-{token.lower()}")
        output_token = re.sub(r"[^A-Za-z0-9_-]+", "-", output_interface or "destination").strip("-")
        to_zone = str(zones.get(output_interface) or f"nct-{output_token.lower()}")
        policy_name = f"NCT-{protocol.upper()}-{port}-{sequence}"[:63]
        application = f"NCT-{protocol.upper()}-{port}"[:63]
        lines = []
        if interface_name not in zones:
            lines.append(f"set security zones security-zone {from_zone} interfaces {interface_name}")
        if output_interface and output_interface not in zones:
            lines.append(f"set security zones security-zone {to_zone} interfaces {output_interface}")
        lines.extend([
            f"set applications application {application} protocol {protocol}",
            f"set applications application {application} destination-port {port}",
            f"set security policies from-zone {from_zone} to-zone {to_zone} policy {policy_name} match source-address {source_value}",
            f"set security policies from-zone {from_zone} to-zone {to_zone} policy {policy_name} match destination-address {destination_value}",
            f"set security policies from-zone {from_zone} to-zone {to_zone} policy {policy_name} match application {application}",
            f"set security policies from-zone {from_zone} to-zone {to_zone} policy {policy_name} then {action}",
        ])
        rule_text = "\n".join(lines)
    placement = context["positions"][insertion_index]
    return {
        "vendor": vendor,
        "template_id": template_id,
        "template": next(item for item in context["templates"] if item["id"] == template_id),
        "interface": interface_name,
        "output_interface": output_interface,
        "policy": policy_name,
        "sequence": sequence,
        "insertion_index": insertion_index,
        "placement": placement["label"],
        "rule_text": rule_text,
        "match_scope": {
            "source": source_value, "destination": destination_value,
            "protocol": protocol.lower(), "port": port,
        },
    }


def validate_vendor_policy_rule(
    *, analysis: dict, rule_text: str, source_text: str, destination_text: str,
    protocol: str, port: int, action: str, interface_name: str,
    source_external: bool = False, flow_state: str = "new",
) -> dict:
    """Parse submitted vendor text and prove it decides the selected flow."""
    if not str(rule_text or "").strip():
        raise ValueError("Enter or generate the vendor rule text to validate")
    vendor = _policy_vendor(analysis)
    source = parse_endpoint(source_text, external=source_external)
    destination = parse_endpoint(destination_text)
    input_interface = _endpoint_interface(source, analysis)
    if input_interface and interface_name != input_interface:
        raise ValueError(
            f"The selected flow enters this device on {input_interface or 'an unknown interface'}, not {interface_name}"
        )
    output_interface = _egress_interface(destination, analysis)
    values = {
        "source": str(source.value) if source.value is not None else None,
        "destination": str(destination.value) if destination.value is not None else None,
        "protocol": protocol, "port": port,
        "source_external": _is_external_endpoint(source),
        "destination_external": _is_external_endpoint(destination),
        "input_interface": interface_name, "output_interface": output_interface,
        "flow_state": flow_state,
    }
    if vendor == "unifi":
        parsed = parse_iptables_policy(rule_text)
        result = evaluate_iptables_flow(parsed, **values)
        parsed_vendor = "unifi"
        parsed_count = len(parsed.get("rules") or [])
    else:
        parsed = parse_vendor_policy(rule_text)
        parsed_vendor = parsed.get("vendor")
        result = evaluate_vendor_policy(parsed, **values)
        parsed_count = len(parsed.get("rules") or [])
    if parsed_vendor != vendor:
        raise ValueError(
            f"The written rule was not recognized as {vendor} policy for the selected device"
        )
    if not parsed_count:
        raise ValueError("No supported policy rule could be parsed from the written text")
    expected = "allow" if action == "permit" else "deny"
    if result.get("status") != "decided":
        raise ValueError(
            "The written rule does not apply to the selected interface and flow: "
            + str(result.get("reason") or "no final decision was reached")
        )
    if result.get("verdict") != expected:
        raise ValueError(
            f"The written rule produces {result.get('verdict')}, not the requested {expected} result"
        )
    matched = result.get("rule") or {}
    return {
        "valid": True,
        "vendor": vendor,
        "verdict": result.get("verdict"),
        "interface": interface_name,
        "output_interface": output_interface,
        "parsed_rule_count": parsed_count,
        "matched_rule": {
            "policy": matched.get("policy") or matched.get("chain"),
            "order": matched.get("order") or matched.get("rule_order"),
            "evidence": matched.get("evidence"),
        },
        "match_basis": result.get("match_basis") or [],
        "message": f"Validated as {vendor} policy on {interface_name} for this exact flow.",
    }


def simulate_proposed_policy_control(
    *, source_text: str, destination_text: str, protocol: str, port: int,
    hunting: dict, saved_networks: list[dict], device_analyses: list[dict],
    action: str, device_key: str, flow_state: str = "new",
    source_external: bool = False, interface_name: str | None = None,
    insertion_index: int = 0, vendor_rule: str | None = None,
    template_id: str = "exact-service",
) -> dict:
    """Project one exact policy control without changing retained or live data."""
    action = str(action or "").strip().lower()
    if action not in {"permit", "deny"}:
        raise ValueError("Proposed policy action must be permit or deny")
    selected = _selected_policy_device(device_analyses, device_key)

    baseline = evaluate_reachability(
        source_text=source_text, destination_text=destination_text,
        protocol=protocol, port=port, hunting=hunting,
        saved_networks=saved_networks, device_analyses=device_analyses,
        flow_state=flow_state, source_external=source_external,
    )
    source = parse_endpoint(source_text, external=source_external)
    destination = parse_endpoint(destination_text)
    projected = deepcopy(baseline)
    device = selected.get("device") or {}
    device_name = str(device.get("name") or device.get("address") or "Network device")
    device_address = str(device.get("address") or "") or None
    attached = _source_attached(source, selected)
    interface_name = str(interface_name or _endpoint_interface(source, selected) or "").strip()
    if not interface_name:
        interface_name = str(next((
            item.get("name") for item in selected.get("interfaces") or [] if item.get("name")
        ), ""))
    generated_rule = build_vendor_policy_rule(
        analysis=selected, source_text=source_text, destination_text=destination_text,
        protocol=protocol, port=port, action=action, interface_name=interface_name,
        insertion_index=insertion_index, template_id=template_id,
        source_external=source_external,
    )
    rule_text = str(vendor_rule or generated_rule["rule_text"]).strip()
    validation = validate_vendor_policy_rule(
        analysis=selected, rule_text=rule_text,
        source_text=source_text, destination_text=destination_text,
        protocol=protocol, port=port, action=action,
        interface_name=interface_name, source_external=source_external,
        flow_state=flow_state,
    )
    context = policy_rule_context(selected)
    prior_decisions = list((baseline.get("retained_objects") or {}).get("policy") or [])
    selected_decisions = [
        item for item in prior_decisions
        if str(item.get("device_address") or "") == str(device_address or "")
        or str(item.get("device") or "") == device_name
    ]
    other_decisions = [
        item for item in prior_decisions
        if str(item.get("device_address") or "") != str(device_address or "")
        and str(item.get("device") or "") != device_name
    ]
    existing_match_index = None
    if selected_decisions:
        retained_evidence = str(selected_decisions[0].get("evidence") or "")
        existing_match_index = next((
            item["index"] for item in context["rules"]
            if retained_evidence and (
                retained_evidence == str(item.get("evidence") or "")
                or retained_evidence in str(item.get("evidence") or "")
                or str(item.get("evidence") or "") in retained_evidence
            )
        ), None)
        if existing_match_index is None:
            existing_match_index = 0
    proposal_effective = existing_match_index is None or insertion_index <= existing_match_index
    proposal_decision = {
        "action": action,
        "device": device_name,
        "device_address": device_address,
        "engine": "proposed_exact_control",
        "evidence": rule_text,
        "match_basis": [
            "Written rule parsed with the selected vendor policy engine",
            f"Applied on input interface {interface_name}",
            generated_rule["placement"],
        ],
        "simulated": True,
        "effective": proposal_effective,
        "insertion_index": insertion_index,
    }
    projected_decisions = (
        [*other_decisions, proposal_decision]
        if proposal_effective else
        [*prior_decisions, proposal_decision]
    )
    projected["retained_objects"]["policy"] = projected_decisions
    projected["counts"]["policy_decisions"] = len(projected_decisions)
    proposed_evidence = {
        "kind": "proposal",
        "title": f"Proposed {action} on {device_name}",
        "detail": (
            f"{source.entered} → {destination.entered} · "
            f"{protocol.upper()}/{port} · simulation only"
        ),
        "raw": rule_text,
    }
    projected["evidence"] = [
        *[
            item for item in projected.get("evidence") or []
            if item.get("kind") != "policy" or device_name not in str(item.get("title") or "")
        ],
        proposed_evidence,
    ]
    projected["path"] = list(projected.get("path") or [])
    projected["path"].insert(max(1, len(projected["path"]) - 1), {
        "kind": "proposal",
        "label": f"Proposed {action} · {device_name}",
        "detail": f"{generated_rule['placement']} · {interface_name} · {protocol.upper()}/{port}",
    })
    projected["simulated"] = True
    projected["confidence"] = "medium" if attached else "low"
    projected_caveats = [
        "Simulation only: NCT did not connect to or change any network device.",
        "The written rule was parsed and checked against the selected vendor, interface, flow, and requested action.",
        "The projection assumes the observed path still traverses the selected device.",
    ]
    if not attached:
        projected["outcome"] = "Unknown"
        projected["explanation"] = (
            "The selected device is not attached to the proposed source in retained evidence, so NCT cannot place this control on the path."
        )
        projected_caveats.append("Choose a source-attached router or firewall, or refresh its retained interface evidence.")
    elif not proposal_effective:
        projected["outcome"] = baseline.get("outcome")
        projected["confidence"] = baseline.get("confidence")
        projected["explanation"] = (
            f"The proposed rule is placed after existing rule {existing_match_index + 1}, "
            "which already decides this flow. The retained outcome therefore does not change."
        )
        projected_caveats.append(
            "Move the proposal before the existing matching rule if it is intended to change this flow."
        )
    else:
        actions = {str(item.get("action") or "") for item in projected_decisions}
        if len(actions) > 1:
            projected["outcome"] = "Unknown"
            projected["confidence"] = "low"
            projected["explanation"] = (
                "The proposed control and another retained path decision conflict, so the end-to-end result remains unresolved."
            )
            projected_caveats.append("Review the remaining retained policy decisions before treating the proposal as effective end to end.")
        elif action == "deny":
            projected["outcome"] = "Expected Blocked"
            projected["explanation"] = (
                "The exact proposed deny would block the selected flow on the chosen path device if deployed in the modeled position."
            )
        elif baseline.get("service_observation") == "not_exposed":
            projected["outcome"] = "Not Exposed"
            projected["explanation"] = (
                "The proposed permit would allow policy on the selected device, but retained Nmap coverage did not find the service exposed."
            )
        else:
            projected["outcome"] = "Expected Allowed"
            projected["explanation"] = (
                "The exact proposed permit would allow the selected flow on the modeled path, with no conflicting retained decision established."
            )
    projected["caveats"] = list(dict.fromkeys([
        *projected_caveats, *(projected.get("caveats") or []),
    ]))
    source_count = (
        None
        if generated_rule.get("match_scope", {}).get("source") == "any"
        else _endpoint_address_count(source)
    )
    destination_count = _endpoint_address_count(destination)
    address_pairs = (
        source_count * destination_count
        if source_count is not None and destination_count is not None else None
    )
    comparison = {
        "outcome_changed": baseline.get("outcome") != projected.get("outcome"),
        "before": baseline.get("outcome"),
        "after": projected.get("outcome"),
        "selected_device": device_name,
        "selected_device_address": device_address,
        "source_attached": attached,
        "proposal_effective": proposal_effective,
        "existing_matching_rule_index": existing_match_index,
        "insertion_index": insertion_index,
        "existing_rules": context["rules"],
        "scope": {
            "source_addresses": source_count,
            "destination_addresses": destination_count,
            "address_pairs": address_pairs,
            "protocol": protocol.lower(),
            "port": port,
        },
        "current_path": _path_without_proposals(baseline),
        "projected_path": _path_without_proposals(projected),
        "path_changed": (
            _path_without_proposals(baseline) != _path_without_proposals(projected)
        ),
        "alternate_routes_before": _compact_route_options(
            list((baseline.get("retained_objects") or {}).get("routes") or [])[1:]
        ),
        "alternate_routes_after": _compact_route_options(
            list((projected.get("retained_objects") or {}).get("routes") or [])[1:]
        ),
        "collateral_impact": {
            "bounded": address_pairs is not None,
            "address_pairs": address_pairs,
            "protocols": [protocol.lower()],
            "ports": [port],
            "evaluated_flows": 1,
            "summary": (
                f"The proposal is limited to {address_pairs} address pair{'s' if address_pairs != 1 else ''} on {protocol.upper()}/{port}; only the selected representative flow was evaluated."
                if address_pairs is not None
                else f"The proposal is limited to the entered endpoints on {protocol.upper()}/{port}; unbounded Internet scope is not enumerated."
            ),
        },
    }
    return {
        "status": "reachability_policy_simulation_complete",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "proposal": {
            "action": action, "device": device_name,
            "device_address": device_address,
            "source": source.entered, "source_external": _is_external_endpoint(source),
            "destination": destination.entered,
            "protocol": protocol.lower(), "port": port,
            "flow_state": flow_state,
            "vendor": generated_rule["vendor"],
            "interface": interface_name,
            "output_interface": generated_rule.get("output_interface"),
            "template_id": template_id,
            "insertion_index": insertion_index,
            "placement": generated_rule["placement"],
            "rule_text": rule_text,
            "validation": validation,
        },
        "baseline": baseline,
        "projected": projected,
        "comparison": comparison,
        "disclaimer": (
            "Read-only planning projection from retained evidence. It sends no network traffic and changes no device configuration."
        ),
    }


def simulate_proposed_route_control(
    *, source_text: str, destination_text: str, protocol: str, port: int,
    hunting: dict, saved_networks: list[dict], device_analyses: list[dict],
    action: str, device_key: str, route_network: str,
    route_interface: str | None = None, next_hop: str | None = None,
    priority_kind: str | None = None, priority_value: int | None = None,
    flow_state: str = "new", source_external: bool = False,
) -> dict:
    """Project one retained-device route change in memory only."""
    action = str(action or "").strip().lower()
    if action not in {"add", "remove", "set_priority"}:
        raise ValueError("Proposed route action must be add, remove, or set_priority")
    priority_kind = str(priority_kind or "").strip().lower() or None
    if action == "set_priority":
        if priority_kind not in {"metric", "preference"}:
            raise ValueError("Choose metric or preference for the proposed priority")
        if priority_value is None or not 0 <= int(priority_value) <= 4_294_967_295:
            raise ValueError("Route priority must be from 0 through 4294967295")
        priority_value = int(priority_value)
    try:
        network = ipaddress.ip_network(str(route_network or "").strip(), strict=False)
    except ValueError as exc:
        raise ValueError("Enter a valid IPv4 route network") from exc
    if network.version != 4:
        raise ValueError("Enter a valid IPv4 route network")
    route_interface = str(route_interface or "").strip() or None
    next_hop = str(next_hop or "").strip() or None
    if next_hop:
        try:
            if ipaddress.ip_address(next_hop).version != 4:
                raise ValueError
        except ValueError as exc:
            raise ValueError("Next hop must be one IPv4 address") from exc
    selected_index = next((
        index for index, item in enumerate(device_analyses)
        if device_key in {
            str((item.get("device") or {}).get("address") or ""),
            str((item.get("device") or {}).get("name") or ""),
        }
    ), None)
    if selected_index is None or not _is_transit_device(device_analyses[selected_index]):
        raise ValueError("Choose a retained router or firewall for the proposed route")
    selected = device_analyses[selected_index]
    source = parse_endpoint(source_text, external=source_external)
    destination = parse_endpoint(destination_text)
    if not _source_attached(source, selected):
        raise ValueError("The selected device is not attached to the proposed source in retained evidence")
    if not _destination_matches(str(network), destination):
        raise ValueError("The proposed route network does not cover the selected destination")
    device = selected.get("device") or {}
    device_name = str(device.get("name") or device.get("address") or "Network device")
    device_address = str(device.get("address") or "") or None
    baseline = evaluate_reachability(
        source_text=source_text, destination_text=destination_text,
        protocol=protocol, port=port, hunting=hunting,
        saved_networks=saved_networks, device_analyses=device_analyses,
        flow_state=flow_state, source_external=source_external,
    )
    projected_analyses = deepcopy(device_analyses)
    projected_device = projected_analyses[selected_index]
    route_analysis = projected_device.setdefault("route_analysis", {})
    routes = list(route_analysis.get("routes") or [])
    retained_interfaces = {
        str(item.get("name") or "") for item in selected.get("interfaces") or []
        if item.get("name")
    }
    changed_routes = []
    if action == "add":
        if not route_interface or route_interface not in retained_interfaces:
            raise ValueError("Choose one retained interface on the selected device")
        proposed_route = {
            "network": str(network), "interface": route_interface,
            "via": next_hop, "protocol": "proposed", "direct": not next_hop,
            "line": (
                f"PROPOSED ROUTE {network} via {next_hop or 'direct'} "
                f"interface {route_interface}"
            ),
            "simulated": True,
        }
        routes.append(proposed_route)
        changed_routes.append(proposed_route)
    else:
        exact_matches = []
        for index, item in enumerate(routes):
            try:
                existing = ipaddress.ip_network(str(item.get("network") or ""), strict=False)
            except ValueError:
                continue
            if existing != network:
                continue
            if route_interface and str(item.get("interface") or "") != route_interface:
                continue
            if next_hop and str(item.get("via") or "") != next_hop:
                continue
            exact_matches.append((index, item))
        if not exact_matches:
            raise ValueError("The selected device has no retained route with that exact network")
        if len(exact_matches) > 1:
            raise ValueError(
                "More than one exact retained route matched; choose its interface and/or next hop"
            )
        route_index, matched_route = exact_matches[0]
        changed_routes.append(matched_route)
        if action == "remove":
            routes.pop(route_index)
        else:
            updated = {
                **matched_route,
                priority_kind: priority_value,
                "simulated": True,
                "line": (
                    f"PROPOSED {priority_kind.upper()} {priority_value} for "
                    f"{network} via {matched_route.get('via') or 'direct'} "
                    f"interface {matched_route.get('interface') or 'unspecified'}"
                ),
            }
            routes[route_index] = updated
    route_analysis["routes"] = routes
    projected = evaluate_reachability(
        source_text=source_text, destination_text=destination_text,
        protocol=protocol, port=port, hunting=hunting,
        saved_networks=saved_networks, device_analyses=projected_analyses,
        flow_state=flow_state, source_external=source_external,
    )
    proposal_label = {
        "add": "Proposed route",
        "remove": "Proposed route removal",
        "set_priority": "Proposed route priority",
    }[action]
    proposed_evidence = {
        "kind": "proposal",
        "title": f"{proposal_label} on {device_name}",
        "detail": (
            f"{network} · "
            + (
                f"via {next_hop or 'direct'} · {route_interface}"
                if action == "add"
                else (
                    f"{priority_kind} {priority_value} · retained route selected by exact network"
                    if action == "set_priority"
                    else "1 exact retained route removed from projection"
                )
            )
        ),
    }
    projected["evidence"] = [proposed_evidence, *(projected.get("evidence") or [])]
    projected["path"] = list(projected.get("path") or [])
    projected["path"].insert(max(1, len(projected["path"]) - 1), {
        "kind": "proposal", "label": f"{proposal_label} · {device_name}",
        "detail": str(network),
    })
    projected["simulated"] = True
    projected["caveats"] = list(dict.fromkeys([
        "Simulation only: NCT did not connect to or change any network device.",
        "The projection changes only the selected retained route record; route redistribution, dynamic convergence, policy-based routing, health checks, and vendor-specific tie-breakers are not modeled.",
        "Preference and metric order is used only among equally specific routes when every competing retained route has an explicit comparable value.",
        *(projected.get("caveats") or []),
    ]))
    baseline_routes = list((baseline.get("retained_objects") or {}).get("routes") or [])
    projected_routes = list((projected.get("retained_objects") or {}).get("routes") or [])
    baseline_selected = baseline_routes[0] if baseline_routes else None
    projected_selected = projected_routes[0] if projected_routes else None
    selected_fields = (
        "device", "device_address", "network", "via", "interface",
        "preference", "metric", "selection_basis", "priority_comparable",
    )
    compact_selected = lambda item: (
        {field: item.get(field) for field in selected_fields} if item else None
    )
    return {
        "status": "reachability_route_simulation_complete",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "proposal": {
            "action": action, "device": device_name, "device_address": device_address,
            "network": str(network), "interface": route_interface,
            "next_hop": next_hop, "changed_route_count": len(changed_routes),
            "priority_kind": priority_kind, "priority_value": priority_value,
        },
        "baseline": baseline,
        "projected": projected,
        "comparison": {
            "outcome_changed": baseline.get("outcome") != projected.get("outcome"),
            "before": baseline.get("outcome"), "after": projected.get("outcome"),
            "baseline_route_count": len(baseline_routes),
            "projected_route_count": len(projected_routes),
            "changed_route_count": len(changed_routes),
            "network_addresses": int(network.num_addresses),
            "selected_route_before": compact_selected(baseline_selected),
            "selected_route_after": compact_selected(projected_selected),
            "path_changed": compact_selected(baseline_selected) != compact_selected(projected_selected),
            "current_path": _path_without_proposals(baseline),
            "projected_path": _path_without_proposals(projected),
            "alternate_routes_before": _compact_route_options(baseline_routes[1:]),
            "alternate_routes_after": _compact_route_options(projected_routes[1:]),
            "collateral_impact": {
                "bounded": True,
                "destination_addresses": int(network.num_addresses),
                "evaluated_flows": 1,
                "summary": (
                    f"The changed prefix covers {int(network.num_addresses)} destination address{'es' if int(network.num_addresses) != 1 else ''}; NCT evaluated only the selected flow and did not recompute every service or policy path in that prefix."
                ),
            },
        },
        "disclaimer": (
            "Read-only route projection from retained evidence. It sends no network traffic and changes no device configuration."
        ),
    }


def _compact_exposure_result(source: dict, result: dict) -> dict:
    return {
        "source": source,
        "outcome": result.get("outcome"),
        "confidence": result.get("confidence"),
        "explanation": result.get("explanation"),
        "evidence": [
            {
                field: item.get(field)
                for field in ("kind", "title", "detail", "raw", "run_id")
                if item.get(field) not in (None, "")
            }
            for item in result.get("evidence") or []
        ],
        "caveats": list(result.get("caveats") or []),
    }


def _exposure_summary(external: dict, internal: list[dict]) -> dict:
    external_outcome = external.get("outcome")
    permitted = [
        item for item in internal if item.get("outcome") == "Expected Allowed"
    ]
    local = [item for item in internal if item.get("outcome") == "Local"]
    if external_outcome == "Expected Allowed":
        return {
            "classification": "external_reachable",
            "label": "Externally reachable",
            "confidence": "high",
            "summary": "Retained policy permits the matched service from the Internet source.",
        }
    if external_outcome == "Not Exposed":
        return {
            "classification": "not_exposed",
            "label": "Not exposed",
            "confidence": "high",
            "summary": "Exact retained scan coverage did not observe the matched service exposed.",
        }
    if external_outcome == "Expected Blocked" and permitted:
        names = ", ".join(
            str(item.get("source", {}).get("name") or item.get("source", {}).get("cidr"))
            for item in permitted
        )
        return {
            "classification": "internal_only",
            "label": "Internal only",
            "confidence": "high",
            "summary": f"Internet access is explicitly blocked; retained policy permits access from {names}.",
        }
    if permitted:
        names = ", ".join(
            str(item.get("source", {}).get("name") or item.get("source", {}).get("cidr"))
            for item in permitted
        )
        return {
            "classification": "internal_reachable",
            "label": "Internal permitted · external unknown",
            "confidence": "medium",
            "summary": f"Retained policy permits access from {names}, but external exposure is not established.",
        }
    if external_outcome == "Expected Blocked" and local:
        names = ", ".join(
            str(item.get("source", {}).get("name") or item.get("source", {}).get("cidr"))
            for item in local
        )
        return {
            "classification": "local_segment",
            "label": "External blocked · local segment",
            "confidence": "medium",
            "summary": f"Internet access is explicitly blocked; {names} contains the destination, but local host controls remain unknown.",
        }
    if external_outcome == "Expected Blocked":
        return {
            "classification": "external_blocked",
            "label": "External blocked",
            "confidence": "high",
            "summary": "Retained policy explicitly blocks Internet access; no internal permit was established.",
        }
    if local:
        names = ", ".join(
            str(item.get("source", {}).get("name") or item.get("source", {}).get("cidr"))
            for item in local
        )
        return {
            "classification": "local_segment",
            "label": "Local segment · external unknown",
            "confidence": "medium",
            "summary": f"{names} contains the destination, but external and routed policy remain unresolved.",
        }
    return {
        "classification": "unknown",
        "label": "Exposure unknown",
        "confidence": "low",
        "summary": "Retained routes and policy do not establish whether this matched service is externally or internally reachable.",
    }


def classify_searchsploit_exposure(
    enrichment: dict,
    *,
    hunting: dict,
    saved_networks: list[dict],
    device_analyses: list[dict],
) -> dict:
    """Attach conservative retained-path classifications to SearchSploit matches."""
    classified_matches = []
    facet_counts: dict[str, dict] = {}
    for original in enrichment.get("matches") or []:
        match = dict(original)
        try:
            destination = str(ipaddress.ip_address(str(match.get("ip") or "")))
            protocol = str(match.get("protocol") or "").lower()
            port = int(match.get("port") or 0)
            if protocol not in {"tcp", "udp"} or not 1 <= port <= 65535:
                raise ValueError
        except (TypeError, ValueError):
            exposure = {
                "classification": "unknown",
                "label": "Exposure unknown",
                "confidence": "low",
                "summary": "The matched finding does not contain a usable IPv4 service endpoint.",
                "external": None,
                "internal": [],
            }
        else:
            external_result = evaluate_reachability(
                source_text="Internet",
                destination_text=destination,
                protocol=protocol,
                port=port,
                hunting=hunting,
                saved_networks=saved_networks,
                device_analyses=device_analyses,
            )
            external = _compact_exposure_result(
                {"kind": "external", "name": "Internet", "cidr": None},
                external_result,
            )
            internal = []
            seen_networks = set()
            for network in saved_networks:
                cidr = str(network.get("cidr") or "").strip()
                if not cidr or cidr in seen_networks:
                    continue
                seen_networks.add(cidr)
                try:
                    internal_result = evaluate_reachability(
                        source_text=cidr,
                        destination_text=destination,
                        protocol=protocol,
                        port=port,
                        hunting=hunting,
                        saved_networks=saved_networks,
                        device_analyses=device_analyses,
                    )
                except ValueError:
                    continue
                internal.append(_compact_exposure_result(
                    {
                        "kind": "saved_network",
                        "saved_network_id": network.get("saved_network_id"),
                        "name": network.get("name") or cidr,
                        "cidr": cidr,
                    },
                    internal_result,
                ))
            summary = _exposure_summary(external, internal)
            exposure = {**summary, "external": external, "internal": internal}
        match["exposure"] = exposure
        classified_matches.append(match)
        key = str(exposure["classification"])
        facet = facet_counts.setdefault(key, {
            "classification": key,
            "label": exposure["label"],
            "match_count": 0,
            "candidate_count": 0,
        })
        facet["match_count"] += 1
        facet["candidate_count"] += int(match.get("candidate_count") or 0)
    return {
        **enrichment,
        "matches": classified_matches,
        "exposure_facets": sorted(
            facet_counts.values(), key=lambda item: (-item["match_count"], item["label"])
        ),
        "exposure_disclaimer": (
            "Exposure describes the retained path to the matched service, not proof "
            "that a SearchSploit candidate is exploitable."
        ),
    }


REPORT_OUTCOMES = (
    "Expected Allowed",
    "Routed",
    "Local",
    "Unknown",
    "Expected Blocked",
    "Not Exposed",
)


def _report_service_key(ip: object, protocol: object, port: object) -> str | None:
    try:
        address = ipaddress.ip_address(str(ip or "").strip())
        protocol_text = str(protocol or "").strip().lower()
        port_number = int(port or 0)
    except (TypeError, ValueError):
        return None
    if address.version != 4 or protocol_text not in {"tcp", "udp"}:
        return None
    if not 1 <= port_number <= 65535:
        return None
    return f"{address}|{protocol_text}|{port_number}"


def _exposure_report_services(hunting: dict, searchsploit: dict) -> list[dict]:
    hosts_by_ip = {
        str(item.get("ip") or ""): item for item in hunting.get("hosts") or []
        if item.get("ip")
    }
    services: dict[str, dict] = {}
    for finding in hunting.get("findings") or []:
        if finding.get("evidence_kind") == "device_configuration":
            continue
        key = _report_service_key(
            finding.get("ip"), finding.get("protocol"), finding.get("port")
        )
        if not key:
            continue
        host = hosts_by_ip.get(str(finding.get("ip") or ""), {})
        service = services.setdefault(key, {
            "service_key": key,
            "host_key": finding.get("host_key") or host.get("host_key"),
            "ip": str(finding.get("ip")),
            "hostname": finding.get("hostname") or host.get("hostname"),
            "mac": finding.get("mac") or host.get("mac"),
            "vendor": finding.get("vendor") or host.get("vendor"),
            "os": finding.get("os") or host.get("os"),
            "subnet": finding.get("subnet") or host.get("subnet"),
            "protocol": str(finding.get("protocol")).lower(),
            "port": int(finding.get("port")),
            "state": finding.get("state") or "open",
            "service": finding.get("service"),
            "product": finding.get("product"),
            "version": finding.get("version"),
            "categories": [],
            "source_refs": [],
            "searchsploit": {"candidate_count": 0, "cves": [], "candidates": []},
        })
        category = str(finding.get("category") or "").strip()
        if category and category not in service["categories"]:
            service["categories"].append(category)
        for reference in finding.get("source_refs") or []:
            if reference not in service["source_refs"]:
                service["source_refs"].append(reference)
        for field in ("hostname", "mac", "vendor", "os", "subnet", "service", "product", "version"):
            if not service.get(field) and finding.get(field):
                service[field] = finding.get(field)

    candidate_keys: dict[str, set[tuple[str, str]]] = {}
    for match in searchsploit.get("matches") or []:
        key = _report_service_key(match.get("ip"), match.get("protocol"), match.get("port"))
        if not key or key not in services:
            continue
        service = services[key]
        seen = candidate_keys.setdefault(key, set())
        for candidate in match.get("candidates") or []:
            candidate_key = (
                str(candidate.get("edb_id") or ""),
                str(candidate.get("title") or ""),
            )
            if candidate_key in seen:
                continue
            seen.add(candidate_key)
            service["searchsploit"]["candidates"].append(dict(candidate))
    for service in services.values():
        candidates = service["searchsploit"]["candidates"]
        cves = sorted({
            str(cve)
            for candidate in candidates
            for cve in candidate.get("cves") or []
            if cve
        })
        service["categories"].sort()
        service["searchsploit"]["candidate_count"] = len(candidates)
        service["searchsploit"]["cves"] = cves
    return sorted(
        services.values(),
        key=lambda item: (*ip_sort_key(item.get("ip")), item.get("protocol"), item.get("port")),
    )


def build_source_exposure_report(
    *,
    hunting: dict,
    saved_networks: list[dict],
    device_analyses: list[dict],
    searchsploit: dict | None = None,
) -> dict:
    """Evaluate retained observed services from Internet and each Saved Network."""
    searchsploit = searchsploit or {"status": "not_requested", "matches": []}
    services = _exposure_report_services(hunting, searchsploit)
    sources = [{
        "source_id": "external:internet",
        "kind": "external",
        "name": "Internet",
        "cidr": None,
        "query": "Internet",
    }]
    seen_networks = set()
    for network in saved_networks:
        cidr = str(network.get("cidr") or "").strip()
        if not cidr or cidr in seen_networks:
            continue
        try:
            parsed = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        if parsed.version != 4:
            continue
        seen_networks.add(cidr)
        sources.append({
            "source_id": f"saved:{network.get('saved_network_id') or cidr}",
            "saved_network_id": network.get("saved_network_id"),
            "kind": "saved_network",
            "name": network.get("name") or cidr,
            "cidr": cidr,
            "query": cidr,
        })

    grouped_sources = []
    outcome_order = {value: index for index, value in enumerate(REPORT_OUTCOMES)}
    services_by_key = {item["service_key"]: item for item in services}
    for source in sources:
        counts = {outcome: 0 for outcome in REPORT_OUTCOMES}
        results = []
        for service in services:
            try:
                evaluation = evaluate_reachability(
                    source_text=source["query"],
                    destination_text=service["ip"],
                    protocol=service["protocol"],
                    port=service["port"],
                    hunting=hunting,
                    saved_networks=saved_networks,
                    device_analyses=device_analyses,
                )
            except ValueError as exc:
                evaluation = {
                    "outcome": "Unknown",
                    "confidence": "low",
                    "explanation": str(exc),
                    "query": {
                        "source": source["query"],
                        "destination": service["ip"],
                        "protocol": service["protocol"],
                        "port": service["port"],
                    },
                    "path": [],
                    "evidence": [],
                    "retained_objects": {"routes": [], "policy": [], "nat": []},
                    "caveats": ["The retained service could not be evaluated."],
                }
            outcome = str(evaluation.get("outcome") or "Unknown")
            counts[outcome] = counts.get(outcome, 0) + 1
            results.append({
                "service_key": service["service_key"],
                "outcome": outcome,
                "confidence": evaluation.get("confidence"),
                "explanation": evaluation.get("explanation"),
                "query": evaluation.get("query") or {},
                "path": evaluation.get("path") or [],
                "evidence": evaluation.get("evidence") or [],
                "retained_objects": evaluation.get("retained_objects") or {},
                "caveats": evaluation.get("caveats") or [],
            })
        results.sort(key=lambda item: (
            outcome_order.get(item["outcome"], len(outcome_order)),
            *ip_sort_key(services_by_key.get(item["service_key"], {}).get("ip")),
            item.get("query", {}).get("port") or 0,
        ))
        grouped_sources.append({
            **source,
            "service_count": len(results),
            "counts": counts,
            "results": results,
        })

    candidate_count = sum(
        int(service.get("searchsploit", {}).get("candidate_count") or 0)
        for service in services
    )
    return {
        "status": "source_exposure_report_complete",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "service_count": len(services),
        "source_count": len(grouped_sources),
        "evaluated_path_count": len(services) * len(grouped_sources),
        "searchsploit_candidate_count": candidate_count,
        "searchsploit": {
            "status": searchsploit.get("status"),
            "provider": searchsploit.get("provider"),
            "warnings": list(searchsploit.get("warnings") or []),
            "disclaimer": searchsploit.get("disclaimer"),
        },
        "services": services,
        "sources": grouped_sources,
        "disclaimer": (
            "This report evaluates retained evidence only and sends no network traffic. "
            "Expected reachability does not prove that a SearchSploit candidate is exploitable."
        ),
    }
