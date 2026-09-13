from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

from app.iptables_policy import evaluate_iptables_flow, evaluate_iptables_nat
from app.vendor_policy import evaluate_vendor_policy


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


def _source_attached(source: Endpoint, analysis: dict) -> bool:
    interfaces = analysis.get("interfaces") or []
    if source.kind == "external":
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


def _matching_routes(source: Endpoint, destination: Endpoint, device_analyses: list[dict]) -> tuple[list[dict], list[dict]]:
    candidates = []
    excluded = []
    seen = set()
    for analysis in device_analyses:
        device = analysis.get("device") or {}
        for route in (analysis.get("route_analysis") or {}).get("routes") or []:
            network = str(route.get("network") or "")
            if not _destination_matches(network, destination):
                continue
            if not _is_transit_device(analysis):
                excluded.append({
                    "device": device.get("name") or device.get("address") or "Network device",
                    "device_type": device.get("type"),
                    "network": network,
                    "reason": "Switch management routes are not transit-path evidence unless Layer-3 forwarding is explicitly established.",
                })
                continue
            if not _source_attached(source, analysis):
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
                "evidence": route.get("line"),
                "run_id": analysis.get("run_id"),
                "prefix": prefix,
            })
    return sorted(candidates, key=lambda item: item["prefix"], reverse=True), excluded


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


def _endpoint_interface(endpoint: Endpoint, analysis: dict, *, role: str | None = None) -> str | None:
    candidates = []
    for item in analysis.get("interfaces") or []:
        if endpoint.kind == "external":
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
    if endpoint.kind == "external" and not candidates:
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
) -> tuple[list[dict], list[str]]:
    translations = []
    unresolved = []
    for analysis in device_analyses:
        policy = (analysis.get("policy") or {}).get("iptables") or {}
        if not policy.get("nat_rules") or not _source_attached(source, analysis):
            continue
        device = analysis.get("device") or {}
        device_name = device.get("name") or device.get("address") or "Network device"
        input_interface = _endpoint_interface(source, analysis)
        result = evaluate_iptables_nat(
            policy,
            source=str(source.value) if source.value is not None else None,
            destination=str(destination.value) if destination.value is not None else None,
            protocol=protocol,
            port=port,
            source_external=source.kind == "external",
            destination_external=destination.kind == "external",
            input_interface=input_interface,
            output_interface=_egress_interface(destination, analysis),
        )
        if result.get("status") == "unknown":
            unresolved.append(
                f"Ordered NAT on {device_name}: "
                f"{result.get('reason') or 'the translation path could not be resolved.'}"
            )
            continue
        if result.get("status") not in {"translated", "redirected"}:
            continue
        rule = result.get("rule") or {}
        trace = result.get("trace") or []
        translations.append({
            "kind": result.get("translation"),
            "status": result.get("status"),
            "device": device_name,
            "device_address": device.get("address"),
            "original_destination": destination.entered,
            "original_port": port,
            "destination": result.get("destination"),
            "port": result.get("port"),
            "input_interface": input_interface,
            "evidence": rule.get("evidence"),
            "run_id": analysis.get("run_id"),
            "trace": trace,
            "match_basis": result.get("match_basis") or [],
        })
    return translations, unresolved


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
) -> tuple[list[dict], list[str]]:
    translations = []
    unresolved = []
    for analysis in device_analyses:
        policy = (analysis.get("policy") or {}).get("iptables") or {}
        if not policy.get("nat_rules") or not _source_attached(source, analysis):
            continue
        device = analysis.get("device") or {}
        device_name = device.get("name") or device.get("address") or "Network device"
        input_interface = _endpoint_interface(source, analysis)
        output_interface = _egress_interface(destination, analysis)
        result = evaluate_iptables_nat(
            policy,
            source=str(source.value) if source.value is not None else None,
            destination=str(destination.value) if destination.value is not None else None,
            protocol=protocol,
            port=port,
            source_external=source.kind == "external",
            destination_external=destination.kind == "external",
            input_interface=input_interface,
            output_interface=output_interface,
            stage="source",
            masquerade_source=_interface_address(analysis, output_interface),
        )
        if result.get("status") == "unknown":
            unresolved.append(
                f"Ordered source NAT on {device_name}: "
                f"{result.get('reason') or 'the translation path could not be resolved.'}"
            )
            continue
        if result.get("status") != "translated":
            continue
        rule = result.get("rule") or {}
        translations.append({
            "kind": result.get("translation"),
            "status": "translated",
            "device": device_name,
            "device_address": device.get("address"),
            "original_source": source.entered,
            "source": result.get("source"),
            "source_port": result.get("source_port"),
            "dynamic": bool(result.get("dynamic")),
            "input_interface": input_interface,
            "output_interface": output_interface,
            "evidence": rule.get("evidence"),
            "run_id": analysis.get("run_id"),
            "trace": result.get("trace") or [],
            "match_basis": result.get("match_basis") or [],
        })
    return translations, unresolved


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
) -> dict:
    source = parse_endpoint(source_text)
    destination = parse_endpoint(destination_text)
    protocol = protocol.strip().lower()
    if protocol not in {"tcp", "udp"}:
        raise ValueError("Protocol must be TCP or UDP")
    if not 1 <= port <= 65535:
        raise ValueError("Port must be between 1 and 65535")

    transit_analyses = [item for item in device_analyses if _is_transit_device(item)]
    destination_translations, destination_nat_unresolved = _destination_nat_translations(
        source, destination, protocol, port, transit_analyses
    )
    translated_targets = {
        (str(item.get("destination")), int(item.get("port") or port))
        for item in destination_translations
        if item.get("status") == "translated" and item.get("destination")
    }
    effective_destination = destination
    effective_port = port
    translation_conflict = len(translated_targets) > 1
    if len(translated_targets) == 1:
        translated_address, effective_port = next(iter(translated_targets))
        effective_destination = Endpoint(
            entered=translated_address,
            kind="host",
            value=ipaddress.ip_address(translated_address),
        )
    source_translations, source_nat_unresolved = _source_nat_translations(
        source, effective_destination, protocol, effective_port, transit_analyses
    )
    translations = [*destination_translations, *source_translations]
    nat_unresolved = [*destination_nat_unresolved, *source_nat_unresolved]
    source_translation_signatures = {
        (
            str(item.get("device_address") or item.get("device")),
            str(item.get("source") or f"interface:{item.get('output_interface') or '?'}"),
        )
        for item in source_translations
    }
    source_translation_conflict = len(source_translation_signatures) > 1
    effective_source = source.entered
    if len(source_translation_signatures) == 1 and source_translations:
        translation = source_translations[0]
        effective_source = translation.get("source") or (
            f"{translation.get('output_interface') or 'outgoing'} interface address"
        )

    source_network = _network_for(source, saved_networks)
    destination_network = _network_for(effective_destination, saved_networks)
    service = _service_observation(effective_destination, protocol, effective_port, hunting)
    routes, excluded_routes = _matching_routes(source, effective_destination, device_analyses)
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
            source, effective_destination, protocol, effective_port, transit_analyses
        )
    evidence = []
    caveats = []

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
            "detail": detail,
            "raw": translation.get("evidence"),
            "run_id": translation.get("run_id"),
        })
    if service["finding"]:
        finding = service["finding"]
        service_name = finding.get("service") or "unknown service"
        evidence.append({
            "kind": "service",
            "title": f"{protocol.upper()}/{effective_port} observed open",
            "detail": " · ".join(str(value) for value in (service_name, finding.get("product"), finding.get("version")) if value),
        })
    elif service["state"] == "not_observed":
        caveats.append(f"The destination host was observed, but {protocol.upper()}/{effective_port} was not present in retained open-port evidence. This is not proof that policy blocks it.")
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
        basis = ", ".join(decision.get("match_basis") or [])
        engine = str(decision.get("engine") or "")
        policy_kind = "Ordered" if engine == "ordered_iptables" else "Applied" if engine.startswith("applied_") else "Explicit"
        evidence.append({
            "kind": "policy",
            "title": f"{policy_kind} {decision['action']} on {decision['device']}",
            "detail": decision["evidence"] + (f" · {basis}" if basis else ""),
            "run_id": decision.get("run_id"),
        })

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
    if nat_unresolved or translation_conflict or source_translation_conflict or redirect_present:
        outcome, confidence = "Unknown", "low"
        explanation = "NAT changes or may change the selected flow before forwarded policy is evaluated."
    elif len(actions) > 1:
        outcome, confidence = "Unknown", "low"
        explanation = "Retained policy sources produced conflicting ordered decisions."
        caveats.append("Conflicting allow and deny results require path and device review before drawing a conclusion.")
    elif actions == {"deny"}:
        outcome, confidence = "Expected Blocked", "high"
        explanation = "The retained ordered policy denies this new flow for the selected endpoints and service."
    elif actions == {"permit"}:
        outcome, confidence = "Expected Allowed", "high"
        explanation = "The retained ordered policy permits this new flow for the selected endpoints and service."
    elif same_saved_network:
        outcome, confidence = "Local", "medium"
        explanation = "Source and destination are within the same Saved Network. Host firewall and local segmentation may still affect access."
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
        path.append({"kind": "source", "label": source.entered, "detail": "Selected source"})
    if len(translated_targets) == 1:
        translation = next(item for item in destination_translations if item.get("kind") == "dnat")
        path.append({
            "kind": "nat",
            "label": f"DNAT on {translation['device']}",
            "detail": f"{destination.entered}:{port} → {effective_destination.entered}:{effective_port}",
        })
    if outcome == "Local":
        path.append({"kind": "segment", "label": "Same local segment", "detail": destination_network.get("cidr") if destination_network else ""})
    elif routes:
        route = routes[0]
        path.append({"kind": "device", "label": route["device"], "detail": route.get("device_address") or "Routing device"})
        path.append({"kind": "route", "label": route["network"], "detail": f"via {route.get('via') or 'direct'}" + (f" · {route['interface']}" if route.get("interface") else "")})
    if len(source_translation_signatures) == 1 and source_translations:
        translation = source_translations[0]
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
            "detail": f"{source.entered} → {translated_display}",
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
        },
        "source_network": source_network,
        "destination_network": destination_network,
        "service_observation": service["state"],
        "path": path,
        "evidence": evidence,
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
            "evidence": len(evidence),
        },
    }
