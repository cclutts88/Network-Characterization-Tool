from __future__ import annotations

import ipaddress
import re
from collections import defaultdict


SERVICE_PORTS = {
    "domain": 53, "dns": 53, "http": 80, "https": 443,
    "ssh": 22, "telnet": 23, "smtp": 25, "snmp": 161,
}
JUNOS_APPLICATIONS = {
    "junos-http": ("tcp", 80), "junos-https": ("tcp", 443),
    "junos-ssh": ("tcp", 22), "junos-telnet": ("tcp", 23),
    "junos-smtp": ("tcp", 25), "junos-snmp": ("udp", 161),
}


def _wildcard_network(address: str, wildcard: str) -> str | None:
    try:
        base = ipaddress.IPv4Address(address)
        wildcard_value = int(ipaddress.IPv4Address(wildcard))
    except ipaddress.AddressValueError:
        return None
    mask_value = (~wildcard_value) & 0xFFFFFFFF
    bits = f"{mask_value:032b}"
    if "01" in bits:
        return None
    return str(ipaddress.ip_network((int(base) & mask_value, bits.count("1"))))


def _address_token(tokens: list[str], index: int) -> tuple[str | None, int, bool]:
    if index >= len(tokens):
        return None, index, True
    value = tokens[index]
    if value.lower() == "any":
        return "any", index + 1, False
    if value.lower() == "host" and index + 1 < len(tokens):
        return f"{tokens[index + 1]}/32", index + 2, False
    if index + 1 < len(tokens):
        network = _wildcard_network(value, tokens[index + 1])
        if network:
            return network, index + 2, False
    try:
        return str(ipaddress.ip_network(value, strict=False)), index + 1, False
    except ValueError:
        return value, index + 1, True


def _port(value: str) -> int | None:
    if value.isdigit():
        result = int(value)
        return result if 1 <= result <= 65535 else None
    return SERVICE_PORTS.get(value.lower())


def _parse_acl_rule(line: str, acl_name: str, body: str, order: int) -> dict | None:
    tokens = body.split()
    if tokens and tokens[0].isdigit():
        tokens = tokens[1:]
    if tokens and tokens[0].lower() in {"extended", "standard"}:
        acl_type = tokens.pop(0).lower()
    else:
        acl_type = "extended"
    if len(tokens) < 2 or tokens[0].lower() not in {"permit", "deny"}:
        return None
    action = tokens.pop(0).lower()
    protocol = tokens.pop(0).lower() if acl_type == "extended" else "ip"
    source, index, source_unresolved = _address_token(tokens, 0)
    destination, index, destination_unresolved = _address_token(tokens, index)
    destination_port = None
    port_unresolved = False
    if index < len(tokens) and tokens[index].lower() == "eq":
        if index + 1 < len(tokens):
            destination_port = _port(tokens[index + 1])
            port_unresolved = destination_port is None
        else:
            port_unresolved = True
    elif index < len(tokens) and tokens[index].lower() in {"range", "gt", "lt", "neq"}:
        port_unresolved = True
    return {
        "policy": acl_name, "order": order, "action": action,
        "protocol": protocol, "source": source, "destination": destination,
        "destination_port": destination_port,
        "unresolved": source_unresolved or destination_unresolved or port_unresolved,
        "evidence": line.strip()[:2000],
    }


def _parse_cisco(text: str) -> dict:
    rules = []
    attachments = []
    order_by_acl: dict[str, int] = defaultdict(int)
    current_acl = None
    current_interface = None
    for raw in text.splitlines():
        line = raw.strip()
        named = re.match(r"^ip access-list (?:extended|standard) (\S+)$", line, re.I)
        if named:
            current_acl = named.group(1)
            current_interface = None
            continue
        interface = re.match(r"^interface\s+(\S+)$", line, re.I)
        if interface:
            current_interface = interface.group(1)
            current_acl = None
            continue
        if line == "!":
            current_acl = None
            current_interface = None
            continue
        numbered = re.match(r"^access-list\s+(\S+)\s+(.*)$", line, re.I)
        if numbered:
            name, body = numbered.groups()
            if body.lower().startswith("line "):
                body = re.sub(r"^line\s+\d+\s+", "", body, flags=re.I)
            order_by_acl[name] += 1
            rule = _parse_acl_rule(line, name, body, order_by_acl[name])
            if rule:
                rules.append(rule)
            continue
        if current_acl and re.match(r"^(?:\d+\s+)?(?:permit|deny)\b", line, re.I):
            order_by_acl[current_acl] += 1
            rule = _parse_acl_rule(line, current_acl, line, order_by_acl[current_acl])
            if rule:
                rules.append(rule)
            continue
        binding = re.match(r"^ip access-group\s+(\S+)\s+(in|out)$", line, re.I)
        if binding and current_interface:
            attachments.append({"policy": binding.group(1), "interface": current_interface, "direction": binding.group(2).lower(), "evidence": line})
            continue
        asa = re.match(r"^access-group\s+(\S+)\s+(in|out)\s+interface\s+(\S+)$", line, re.I)
        if asa:
            attachments.append({"policy": asa.group(1), "interface": asa.group(3), "direction": asa.group(2).lower(), "evidence": line})
    return {"vendor": "cisco", "rules": rules, "attachments": attachments}


def _parse_vyos(text: str) -> dict:
    records: dict[tuple[str, int], dict] = {}
    attachments = []
    defaults = {}
    custom_pattern = re.compile(r"^set firewall(?: ipv4)? name (\S+) rule (\d+) (\S+)(?: (.+))?$", re.I)
    base_pattern = re.compile(r"^set firewall ipv4 forward filter rule (\d+) (\S+)(?: (.+))?$", re.I)
    for raw in text.splitlines():
        line = raw.strip()
        match = custom_pattern.match(line)
        name = None
        if match:
            name, number, field, value = match.groups()
        else:
            match = base_pattern.match(line)
            if match:
                number, field, value = match.groups()
                name = "forward-filter"
        if match and name:
            item = records.setdefault((name, int(number)), {
                "policy": name, "order": int(number), "action": None,
                "protocol": "ip", "source": "any", "destination": "any",
                "destination_port": None, "input_interface": None,
                "output_interface": None, "states": [], "jump_target": None,
                "unresolved": False, "evidence_lines": [],
            })
            value = (value or "").replace("'", "").replace('"', "").strip()
            item["evidence_lines"].append(line)
            field = field.lower()
            if field == "action":
                item["action"] = {
                    "accept": "permit", "drop": "deny", "reject": "deny",
                    "jump": "jump", "return": "return", "continue": "continue",
                }.get(value.lower())
                item["unresolved"] |= item["action"] is None
            elif field == "jump-target":
                item["jump_target"] = value
            elif field == "protocol":
                item["protocol"] = value.lower()
            elif field == "source" and value.lower().startswith("address "):
                item["source"] = value.split(maxsplit=1)[1]
            elif field == "destination" and value.lower().startswith("address "):
                item["destination"] = value.split(maxsplit=1)[1]
            elif field == "destination" and value.lower().startswith("port "):
                item["destination_port"] = _port(value.split(maxsplit=1)[1])
                item["unresolved"] |= item["destination_port"] is None
            elif field == "inbound-interface" and value.lower().startswith("name "):
                item["input_interface"] = value.split(maxsplit=1)[1]
            elif field == "outbound-interface" and value.lower().startswith("name "):
                item["output_interface"] = value.split(maxsplit=1)[1]
            elif field == "state":
                item["states"].append(value.lower())
            elif field not in {"description", "log"}:
                item["unresolved"] = True
            continue
        default = re.match(r"^set firewall ipv4 (forward filter|name \S+) default-action (\S+)$", line, re.I)
        if default:
            chain = "forward-filter" if default.group(1).lower() == "forward filter" else default.group(1).split(maxsplit=1)[1]
            defaults[chain] = default.group(2).strip(" '").lower()
            continue
        binding = re.match(r"^set interfaces \S+ (\S+)(?: vif \d+)? firewall (in|out|local) name (\S+)$", line, re.I)
        if binding:
            interface, direction, name = binding.groups()
            if direction.lower() != "local":
                attachments.append({"policy": name, "interface": interface, "direction": direction.lower(), "evidence": line})
    rules = []
    for item in sorted(records.values(), key=lambda value: (value["policy"], value["order"])):
        item["evidence"] = " | ".join(item.pop("evidence_lines"))[:2000]
        if item.get("action"):
            rules.append(item)
    return {"vendor": "vyos", "rules": rules, "attachments": attachments, "defaults": defaults}


def _parse_pfsense(text: str) -> dict:
    rules = []
    for order, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        match = re.match(r"^(pass|block)(?:\s+drop)?\s+(in|out)\b(.*)$", line, re.I)
        if not match:
            continue
        action, direction, body = match.groups()
        iface = re.search(r"\bon\s+(\S+)", body, re.I)
        proto = re.search(r"\bproto\s+(tcp|udp|icmp)\b", body, re.I)
        addresses = re.search(r"\bfrom\s+(\S+)\s+to\s+(\S+)", body, re.I)
        port_match = re.search(r"\bport\s*(?:=)?\s*(\S+)", body, re.I)
        rules.append({
            "policy": "pfctl-active", "order": order,
            "action": "permit" if action.lower() == "pass" else "deny",
            "direction": direction.lower(), "interface": iface.group(1) if iface else None,
            "protocol": proto.group(1).lower() if proto else "ip",
            "source": addresses.group(1) if addresses else "any",
            "destination": addresses.group(2) if addresses else "any",
            "destination_port": _port(port_match.group(1)) if port_match else None,
            "unresolved": iface is None or addresses is None or (port_match is not None and _port(port_match.group(1)) is None),
            "evidence": line[:2000],
        })
    return {"vendor": "pfsense", "rules": rules, "attachments": []}


def _parse_juniper(text: str) -> dict:
    zones = {}
    records: dict[tuple[str, str, str], dict] = {}
    for raw in text.splitlines():
        line = raw.strip()
        zone = re.match(r"^set security zones security-zone (\S+) interfaces (\S+)", line, re.I)
        if zone:
            zones[zone.group(2)] = zone.group(1)
            continue
        match = re.match(r"^set security policies from-zone (\S+) to-zone (\S+) policy (\S+) (match|then) (.+)$", line, re.I)
        if not match:
            continue
        from_zone, to_zone, name, section, value = match.groups()
        key = (from_zone, to_zone, name)
        item = records.setdefault(key, {
            "policy": name, "from_zone": from_zone, "to_zone": to_zone,
            "action": None, "sources": [], "destinations": [], "applications": [],
            "evidence_lines": [],
        })
        item["evidence_lines"].append(line)
        if section.lower() == "then":
            decision = value.split()[0].lower()
            if decision in {"permit", "deny", "reject"}:
                item["action"] = "permit" if decision == "permit" else "deny"
        else:
            field, _, entry = value.partition(" ")
            target = {"source-address": "sources", "destination-address": "destinations", "application": "applications"}.get(field.lower())
            if target:
                item[target].append(entry.strip(" []'"))
    rules = []
    order_by_pair: dict[tuple[str, str], int] = defaultdict(int)
    for item in records.values():
        if not item.get("action"):
            continue
        pair = (item["from_zone"], item["to_zone"])
        order_by_pair[pair] += 1
        item["order"] = order_by_pair[pair]
        item["evidence"] = " | ".join(item.pop("evidence_lines"))[:2000]
        rules.append(item)
    return {"vendor": "juniper", "rules": rules, "attachments": [], "interface_zones": zones}


def parse_vendor_policy(text: str) -> dict:
    """Parse applied policy forms that retain both ordered rules and attachment context."""
    candidates = [_parse_cisco(text), _parse_vyos(text), _parse_pfsense(text), _parse_juniper(text)]
    populated = [item for item in candidates if item.get("rules")]
    if not populated:
        return {"vendor": None, "rules": [], "attachments": [], "complete": False}
    result = max(populated, key=lambda item: len(item.get("rules") or []))
    result["complete"] = True
    result["counts"] = {
        "rules": len(result.get("rules") or []),
        "attachments": len(result.get("attachments") or []),
    }
    return result


def _address_matches(specification: str | None, endpoint: object, external: bool) -> bool | None:
    if not specification or specification.lower() == "any":
        return True
    try:
        network = ipaddress.ip_network(specification, strict=False)
    except ValueError:
        return None
    if external:
        return True if network.prefixlen == 0 else False
    try:
        return ipaddress.ip_address(str(endpoint)) in network
    except ValueError:
        return None


def _basic_rule_match(
    rule: dict, *, source: object, destination: object, protocol: str, port: int,
    source_external: bool, destination_external: bool,
    input_interface: str | None = None, output_interface: str | None = None,
) -> bool | None:
    checks = [
        _address_matches(rule.get("source"), source, source_external),
        _address_matches(rule.get("destination"), destination, destination_external),
    ]
    rule_protocol = str(rule.get("protocol") or "ip").lower()
    if rule_protocol not in {"ip", "any", "all"}:
        checks.append(
            protocol.lower() in {"tcp", "udp"}
            if rule_protocol == "tcp_udp"
            else rule_protocol == protocol.lower()
        )
    if rule.get("destination_port") is not None:
        checks.append(int(rule["destination_port"]) == port)
    if rule.get("input_interface"):
        checks.append(input_interface == rule.get("input_interface"))
    if rule.get("output_interface"):
        checks.append(output_interface == rule.get("output_interface"))
    states = set(rule.get("states") or [])
    if states:
        checks.append("new" in states)
    if False in checks:
        return False
    if rule.get("unresolved") or None in checks:
        return None
    return True


def _evaluate_vyos(
    policy: dict, *, source: object, destination: object, protocol: str, port: int,
    source_external: bool, destination_external: bool,
    input_interface: str | None, output_interface: str | None,
) -> dict:
    rules_by_chain: dict[str, list[dict]] = defaultdict(list)
    for rule in policy.get("rules") or []:
        rules_by_chain[str(rule.get("policy") or "")].append(rule)
    for values in rules_by_chain.values():
        values.sort(key=lambda item: int(item.get("order") or 0))

    roots = []
    if rules_by_chain.get("forward-filter"):
        roots = ["forward-filter"]
    else:
        roots = list(dict.fromkeys(
            str(item.get("policy")) for item in policy.get("attachments") or []
            if (
                item.get("direction") == "in" and input_interface and item.get("interface") == input_interface
            ) or (
                item.get("direction") == "out" and output_interface and item.get("interface") == output_interface
            )
        ))
    if not roots:
        return {"status": "not_applied", "reason": "No retained VyOS policy attachment or forward base chain matches the interface path."}

    def walk(chain: str, stack: tuple[str, ...]) -> dict:
        if chain in stack or len(stack) >= 20:
            return {"status": "unknown", "reason": f"VyOS policy recursion could not be resolved at {chain}."}
        if chain not in rules_by_chain:
            return {"status": "unknown", "reason": f"VyOS jump target {chain} was not retained."}
        for rule in rules_by_chain[chain]:
            matched = _basic_rule_match(
                rule, source=source, destination=destination, protocol=protocol, port=port,
                source_external=source_external, destination_external=destination_external,
                input_interface=input_interface, output_interface=output_interface,
            )
            if matched is False:
                continue
            if matched is None:
                return {"status": "unknown", "reason": f"Applied VyOS policy {chain} contains unresolved match criteria.", "rule": rule}
            action = rule.get("action")
            if action in {"permit", "deny"}:
                return {"status": "decided", "verdict": "allow" if action == "permit" else "deny", "rule": rule, "match_basis": [f"Applied policy {chain}"]}
            if action == "jump":
                if not rule.get("jump_target"):
                    return {"status": "unknown", "reason": f"VyOS jump rule {chain} #{rule.get('order')} has no retained target.", "rule": rule}
                nested = walk(str(rule["jump_target"]), stack + (chain,))
                if nested.get("status") == "return":
                    continue
                return nested
            if action == "return":
                return {"status": "return"}
            if action == "continue":
                continue
        default = str((policy.get("defaults") or {}).get(chain) or "").lower()
        if default in {"accept", "drop", "reject"}:
            return {
                "status": "decided", "verdict": "allow" if default == "accept" else "deny",
                "rule": {"policy": chain, "order": None, "evidence": f"set firewall ipv4 {'forward filter' if chain == 'forward-filter' else 'name ' + chain} default-action {default}"},
                "match_basis": [f"Applied policy {chain} default action"],
            }
        return {"status": "return" if chain != "forward-filter" else "unknown", "reason": f"VyOS policy {chain} reached no retained terminal action."}

    results = [walk(root, ()) for root in roots]
    decisions = {item.get("verdict") for item in results if item.get("status") == "decided"}
    if len(decisions) > 1:
        return {"status": "unknown", "reason": "Applied VyOS interface policies produced conflicting decisions."}
    if decisions:
        return next(item for item in results if item.get("status") == "decided")
    return next((item for item in results if item.get("status") == "unknown"), {"status": "unknown", "reason": "Applied VyOS policy returned without a final decision."})


def evaluate_vendor_policy(
    policy: dict, *, source: object, destination: object, protocol: str, port: int,
    source_external: bool = False, destination_external: bool = False,
    input_interface: str | None = None, output_interface: str | None = None,
) -> dict:
    vendor = policy.get("vendor")
    rules = policy.get("rules") or []
    relevant = []
    if vendor == "vyos":
        return _evaluate_vyos(
            policy, source=source, destination=destination, protocol=protocol, port=port,
            source_external=source_external, destination_external=destination_external,
            input_interface=input_interface, output_interface=output_interface,
        )
    if vendor == "cisco":
        names = {
            item.get("policy") for item in policy.get("attachments") or []
            if (
                item.get("direction") == "in" and input_interface and item.get("interface") == input_interface
            ) or (
                item.get("direction") == "out" and output_interface and item.get("interface") == output_interface
            )
        }
        relevant = [item for item in rules if item.get("policy") in names]
    elif vendor == "pfsense":
        relevant = [
            item for item in rules
            if (item.get("direction") == "in" and item.get("interface") == input_interface)
            or (item.get("direction") == "out" and item.get("interface") == output_interface)
        ]
    elif vendor == "juniper":
        zones = policy.get("interface_zones") or {}
        from_zone, to_zone = zones.get(input_interface), zones.get(output_interface)
        relevant = [item for item in rules if item.get("from_zone") == from_zone and item.get("to_zone") == to_zone]
        for item in relevant:
            sources, destinations, applications = item.get("sources") or ["any"], item.get("destinations") or ["any"], item.get("applications") or ["any"]
            app_results = []
            for application in applications:
                if application == "any":
                    app_results.append(True)
                elif application in JUNOS_APPLICATIONS:
                    app_results.append(JUNOS_APPLICATIONS[application] == (protocol.lower(), port))
                else:
                    app_results.append(None)
            source_results = [_address_matches(value, source, source_external) for value in sources]
            destination_results = [_address_matches(value, destination, destination_external) for value in destinations]
            if True not in source_results or True not in destination_results or True not in app_results:
                unresolved_dimension = any(
                    True not in results and None in results
                    for results in (source_results, destination_results, app_results)
                )
                if unresolved_dimension:
                    return {"status": "unknown", "reason": f"Juniper policy {item['policy']} uses unresolved address or application objects.", "rule": item}
                continue
            return {"status": "decided", "verdict": "allow" if item["action"] == "permit" else "deny", "rule": item, "match_basis": [f"Zone path {from_zone} → {to_zone}"]}
    if not relevant:
        return {"status": "not_applied", "reason": "No retained policy attachment matches the interface path."}
    for rule in sorted(relevant, key=lambda item: int(item.get("order") or 0)):
        matched = _basic_rule_match(
            rule, source=source, destination=destination, protocol=protocol, port=port,
            source_external=source_external, destination_external=destination_external,
            input_interface=input_interface, output_interface=output_interface,
        )
        if matched is None:
            return {"status": "unknown", "reason": f"Applied {vendor} policy {rule.get('policy')} contains unresolved match criteria.", "rule": rule}
        if matched:
            return {"status": "decided", "verdict": "allow" if rule.get("action") == "permit" else "deny", "rule": rule, "match_basis": [f"Applied policy {rule.get('policy')}"]}
    return {"status": "unknown", "reason": f"Applied {vendor} policy had no supported matching terminal rule."}
