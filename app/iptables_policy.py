from __future__ import annotations

import ipaddress
import re
import shlex
from collections import defaultdict


MAX_POLICY_RULES = 20_000
MAX_IPSET_OBJECTS = 5_000
MAX_IPSET_MEMBERS = 100_000

TERMINAL_TARGETS = {"ACCEPT": "allow", "DROP": "deny", "REJECT": "deny"}
NON_TERMINAL_TARGETS = {
    "AUDIT", "CHECKSUM", "CLASSIFY", "CONNMARK", "CT", "DNPT", "DSCP",
    "ECN", "HMARK", "IDLETIMER", "LED", "LOG", "MARK", "MASQUERADE",
    "NETMAP", "NFLOG", "NFQUEUE", "NOTRACK", "RATEEST", "REDIRECT",
    "SAME", "SECMARK", "SET", "SNAT", "SYNPROXY", "TCPMSS", "TEE",
    "TOS", "TRACE", "TTL", "ULOG",
}
HARMLESS_MATCH_MODULES = {"comment", "conntrack", "multiport", "set", "state", "tcp", "udp"}


def _tokenize(line: str) -> list[str]:
    try:
        return shlex.split(line, comments=False, posix=True)
    except ValueError:
        return line.split()


def _option(tokens: list[str], *names: str) -> tuple[str | None, bool]:
    for index, token in enumerate(tokens):
        if token not in names or index + 1 >= len(tokens):
            continue
        negated = index > 0 and tokens[index - 1] == "!"
        return tokens[index + 1], negated
    return None, False


def _parse_rule(line: str, table: str, order: int) -> dict:
    tokens = _tokenize(line)
    chain = tokens[1] if len(tokens) > 1 else ""
    action, _ = _option(tokens, "-j", "--jump", "-g", "--goto")
    protocol, protocol_negated = _option(tokens, "-p", "--protocol")
    source, source_negated = _option(tokens, "-s", "--source")
    destination, destination_negated = _option(tokens, "-d", "--destination")
    input_interface, input_interface_negated = _option(tokens, "-i", "--in-interface")
    output_interface, output_interface_negated = _option(tokens, "-o", "--out-interface")
    destination_ports, destination_ports_negated = _option(
        tokens, "--dport", "--destination-port", "--dports", "--destination-ports"
    )
    source_ports, source_ports_negated = _option(
        tokens, "--sport", "--source-port", "--sports", "--source-ports"
    )
    states, _ = _option(tokens, "--state", "--ctstate")
    to_destination, _ = _option(tokens, "--to-destination")
    to_source, _ = _option(tokens, "--to-source")
    to_ports, _ = _option(tokens, "--to-ports")
    set_matches = []
    for index, token in enumerate(tokens):
        if token != "--match-set" or index + 2 >= len(tokens):
            continue
        set_matches.append({
            "name": tokens[index + 1],
            "directions": tokens[index + 2].lower().split(","),
            "negated": index > 0 and tokens[index - 1] == "!",
        })
    modules = [
        tokens[index + 1].lower()
        for index, token in enumerate(tokens[:-1])
        if token in {"-m", "--match"}
    ]
    unsupported_modules = sorted(set(modules) - HARMLESS_MATCH_MODULES)
    return {
        "table": table,
        "chain": chain,
        "rule_order": order,
        "action": action,
        "protocol": protocol,
        "protocol_negated": protocol_negated,
        "source": source,
        "source_negated": source_negated,
        "destination": destination,
        "destination_negated": destination_negated,
        "input_interface": input_interface,
        "input_interface_negated": input_interface_negated,
        "output_interface": output_interface,
        "output_interface_negated": output_interface_negated,
        "destination_ports": destination_ports,
        "destination_ports_negated": destination_ports_negated,
        "source_ports": source_ports,
        "source_ports_negated": source_ports_negated,
        "states": [item.upper() for item in states.split(",")] if states else [],
        "to_destination": to_destination,
        "to_source": to_source,
        "to_ports": to_ports,
        "set_matches": set_matches,
        "unsupported_modules": unsupported_modules,
        "evidence": line[:2000],
        "source_format": "iptables_save",
    }


def parse_iptables_policy(text: str, *, source_truncated: bool = False) -> dict:
    """Parse ordered iptables-save chains and compact ipset definitions."""
    rules = []
    nat_rules = []
    chain_policies: dict[str, str] = {}
    nat_chain_policies: dict[str, str] = {}
    ipsets: dict[str, dict] = {}
    table: str | None = None
    chain_orders: dict[tuple[str, str], int] = defaultdict(int)
    member_total = 0
    retained_member_total = 0
    rule_truncated = False
    object_truncated = False
    member_truncated = False

    for line_number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if line.startswith("*") and len(line) > 1:
            table = line[1:].strip().lower()
            continue
        if line == "COMMIT":
            table = None
            continue
        declaration = re.match(r"^:(?P<chain>\S+)\s+(?P<policy>\S+)", line)
        if table in {"filter", "nat"} and declaration:
            target = chain_policies if table == "filter" else nat_chain_policies
            target[declaration.group("chain")] = declaration.group("policy").upper()
            continue
        if table in {"filter", "nat"} and line.startswith("-A "):
            chain = line.split(maxsplit=2)[1]
            key = (table, chain)
            chain_orders[key] += 1
            target_rules = rules if table == "filter" else nat_rules
            if len(rules) + len(nat_rules) < MAX_POLICY_RULES:
                rule = _parse_rule(line, table, chain_orders[key])
                rule["line_number"] = line_number
                target_rules.append(rule)
            else:
                rule_truncated = True
            continue

        created = re.match(r"^create\s+(?P<name>\S+)\s+(?P<type>\S+)(?P<options>.*)$", line, re.I)
        if created:
            name = created.group("name")
            if name not in ipsets:
                if len(ipsets) >= MAX_IPSET_OBJECTS:
                    object_truncated = True
                    continue
                options = created.group("options").strip()
                family = re.search(r"(?:^|\s)family\s+(\S+)", options, re.I)
                ipsets[name] = {
                    "name": name,
                    "set_type": created.group("type").lower(),
                    "family": family.group(1).lower() if family else None,
                    "options": options,
                    "members": [],
                    "member_count": 0,
                    "has_nomatch": False,
                    "evidence": line[:1000],
                }
            continue

        added = re.match(r"^add\s+(?P<name>\S+)\s+(?P<member>\S+)(?P<options>.*)$", line, re.I)
        if added:
            member_total += 1
            item = ipsets.get(added.group("name"))
            if item is None:
                if len(ipsets) >= MAX_IPSET_OBJECTS:
                    object_truncated = True
                    continue
                item = {
                    "name": added.group("name"), "set_type": "unknown", "family": None,
                    "options": "", "members": [], "member_count": 0,
                    "has_nomatch": False, "evidence": "Definition was not retained before this member.",
                }
                ipsets[item["name"]] = item
            item["member_count"] += 1
            options = added.group("options").strip()
            nomatch = bool(re.search(r"(?:^|\s)nomatch(?:\s|$)", options, re.I))
            item["has_nomatch"] = item["has_nomatch"] or nomatch
            if retained_member_total < MAX_IPSET_MEMBERS:
                item["members"].append({"value": added.group("member"), "nomatch": nomatch})
                retained_member_total += 1
            else:
                member_truncated = True

    return {
        "rules": rules,
        "nat_rules": nat_rules,
        "chain_policies": chain_policies,
        "nat_chain_policies": nat_chain_policies,
        "ipsets": list(ipsets.values()),
        "counts": {
            "rules": len(rules),
            "nat_rules": len(nat_rules),
            "chains": len(chain_policies),
            "nat_chains": len(nat_chain_policies),
            "ipsets": len(ipsets),
            "ipset_members": member_total,
        },
        "complete": not (source_truncated or rule_truncated or object_truncated or member_truncated),
        "source_truncated": source_truncated,
        "rule_truncated": rule_truncated,
        "object_truncated": object_truncated,
        "member_truncated": member_truncated,
    }


def _endpoint_ip(value: object) -> ipaddress.IPv4Address | None:
    try:
        parsed = ipaddress.ip_address(str(value))
    except ValueError:
        return None
    return parsed if parsed.version == 4 else None


def _network_match(endpoint: object, network_text: str, *, external: bool) -> bool | None:
    try:
        network = ipaddress.ip_network(network_text, strict=False)
    except ValueError:
        return None
    if network.version != 4:
        return False
    if external:
        return True if network.prefixlen == 0 else None
    address = _endpoint_ip(endpoint)
    return address in network if address is not None else None


def _port_match(port: int, specification: str) -> bool | None:
    matched_any = False
    for part in specification.split(","):
        part = part.strip().lower()
        if not part:
            continue
        part = part.split(":", 1)[-1] if re.match(r"^(?:tcp|udp):", part) else part
        match = re.fullmatch(r"(\d+)(?:[:-](\d+))?", part)
        if not match:
            return None
        matched_any = True
        start, end = int(match.group(1)), int(match.group(2) or match.group(1))
        if start <= port <= end:
            return True
    return False if matched_any else None


def _interface_match(actual: str | None, pattern: str) -> bool | None:
    if actual is None:
        return None
    if pattern.endswith("+"):
        return actual.startswith(pattern[:-1])
    return actual == pattern


def _invert(result: bool | None, negated: bool) -> bool | None:
    return (not result) if negated and result is not None else result


def _member_matches(
    item: dict,
    directions: list[str],
    *,
    source: object,
    destination: object,
    source_external: bool,
    destination_external: bool,
    protocol: str,
    port: int,
    input_interface: str | None,
    output_interface: str | None,
    ipsets: dict[str, dict],
    stack: set[str],
) -> bool | None:
    set_type = str(item.get("set_type") or "").lower()
    if item.get("has_nomatch"):
        return None
    if set_type == "list:set":
        results = []
        for member in item.get("members") or []:
            nested_name = str(member.get("value") or "")
            if nested_name in stack:
                return None
            nested = ipsets.get(nested_name)
            if nested is None:
                return None
            results.append(_member_matches(
                nested, directions, source=source, destination=destination,
                source_external=source_external, destination_external=destination_external,
                protocol=protocol, port=port, input_interface=input_interface,
                output_interface=output_interface, ipsets=ipsets, stack=stack | {nested_name},
            ))
        return True if True in results else (None if None in results else False)

    components = set_type.removeprefix("hash:").removeprefix("bitmap:").split(",")
    if set_type == "unknown":
        return None
    results = []
    for member in item.get("members") or []:
        raw = str(member.get("value") or "")
        values = raw.split(",")
        if len(values) < len(components):
            values += [""] * (len(components) - len(values))
        component_results = []
        for index, component in enumerate(components):
            direction = directions[index] if index < len(directions) else directions[-1] if directions else ""
            value = values[index]
            if component in {"ip", "net"}:
                endpoint = source if direction == "src" else destination
                external = source_external if direction == "src" else destination_external
                component_results.append(_network_match(endpoint, value, external=external))
            elif component == "port":
                if direction == "src":
                    component_results.append(None)
                else:
                    proto, _, port_value = value.partition(":")
                    if port_value and proto not in {protocol, "any"}:
                        component_results.append(False)
                    else:
                        component_results.append(_port_match(port, port_value or proto))
            elif component == "iface":
                actual = input_interface if direction == "src" else output_interface
                component_results.append(_interface_match(actual, value))
            else:
                component_results.append(None)
        if False in component_results:
            results.append(False)
        elif None in component_results:
            results.append(None)
        else:
            results.append(True)
    return True if True in results else (None if None in results else False)


def _rule_matches(rule: dict, context: dict, ipsets: dict[str, dict]) -> tuple[bool | None, list[str]]:
    checks: list[bool | None] = []
    basis = []
    protocol = str(rule.get("protocol") or "").lower()
    if protocol and protocol not in {"all", "0"}:
        checks.append(_invert(protocol == context["protocol"], bool(rule.get("protocol_negated"))))
    for field, external_field, rule_field, negated_field in (
        ("source", "source_external", "source", "source_negated"),
        ("destination", "destination_external", "destination", "destination_negated"),
    ):
        if rule.get(rule_field):
            checks.append(_invert(
                _network_match(context[field], str(rule[rule_field]), external=context[external_field]),
                bool(rule.get(negated_field)),
            ))
    for actual_field, rule_field, negated_field in (
        ("input_interface", "input_interface", "input_interface_negated"),
        ("output_interface", "output_interface", "output_interface_negated"),
    ):
        if rule.get(rule_field):
            checks.append(_invert(
                _interface_match(context.get(actual_field), str(rule[rule_field])),
                bool(rule.get(negated_field)),
            ))
    if rule.get("destination_ports"):
        checks.append(_invert(
            _port_match(context["port"], str(rule["destination_ports"])),
            bool(rule.get("destination_ports_negated")),
        ))
    if rule.get("source_ports"):
        checks.append(None)
    states = set(rule.get("states") or [])
    if states:
        checks.append("NEW" in states)
    for set_match in rule.get("set_matches") or []:
        item = ipsets.get(set_match["name"])
        result = None if item is None else _member_matches(
            item, set_match.get("directions") or [],
            source=context["source"], destination=context["destination"],
            source_external=context["source_external"], destination_external=context["destination_external"],
            protocol=context["protocol"], port=context["port"],
            input_interface=context.get("input_interface"), output_interface=context.get("output_interface"),
            ipsets=ipsets, stack={set_match["name"]},
        )
        checks.append(_invert(result, bool(set_match.get("negated"))))
        if result is True:
            basis.append(f"{set_match['name']} matched")
        elif result is None:
            basis.append(f"{set_match['name']} could not be fully resolved")
    if False in checks:
        return False, basis
    if rule.get("unsupported_modules"):
        basis.append("Unsupported match: " + ", ".join(rule["unsupported_modules"]))
        checks.append(None)
    return (None if None in checks else True), basis


def evaluate_iptables_flow(
    policy: dict,
    *,
    source: object,
    destination: object,
    protocol: str,
    port: int,
    source_external: bool = False,
    destination_external: bool = False,
    input_interface: str | None = None,
    output_interface: str | None = None,
) -> dict:
    """Conservatively walk the ordered FORWARD chain for a new IPv4 flow."""
    rules_by_chain: dict[str, list[dict]] = defaultdict(list)
    for rule in policy.get("rules") or []:
        if rule.get("table") == "filter" and rule.get("chain"):
            rules_by_chain[str(rule["chain"])].append(rule)
    for rules in rules_by_chain.values():
        rules.sort(key=lambda item: int(item.get("rule_order") or 0))
    ipsets = {item["name"]: item for item in policy.get("ipsets") or [] if item.get("name")}
    context = {
        "source": source, "destination": destination,
        "source_external": source_external, "destination_external": destination_external,
        "protocol": protocol.lower(), "port": port,
        "input_interface": input_interface, "output_interface": output_interface,
    }
    trace = []

    def walk(chain: str, stack: tuple[str, ...]) -> dict:
        if chain in stack or len(stack) >= 24:
            return {"status": "unknown", "reason": f"Policy chain recursion could not be resolved at {chain}."}
        if chain not in rules_by_chain and chain not in (policy.get("chain_policies") or {}):
            return {"status": "unknown", "reason": f"Referenced policy chain {chain} was not retained."}
        for rule in rules_by_chain.get(chain, []):
            matched, basis = _rule_matches(rule, context, ipsets)
            if matched is False:
                continue
            action = str(rule.get("action") or "").upper()
            if matched is None:
                if action in NON_TERMINAL_TARGETS:
                    continue
                return {
                    "status": "unknown",
                    "reason": f"Rule {chain} #{rule.get('rule_order')} may affect the flow but contains unresolved match criteria.",
                    "rule": rule,
                    "match_basis": basis,
                    "trace": trace.copy(),
                }
            trace.append({
                "chain": chain, "rule_order": rule.get("rule_order"),
                "action": action, "evidence": rule.get("evidence"), "match_basis": basis,
            })
            if action in TERMINAL_TARGETS:
                return {
                    "status": "decided", "verdict": TERMINAL_TARGETS[action],
                    "action": action, "rule": rule, "match_basis": basis,
                    "trace": trace.copy(),
                }
            if action == "RETURN":
                return {"status": "return", "trace": trace.copy()}
            if action in NON_TERMINAL_TARGETS or not action:
                continue
            nested = walk(action, stack + (chain,))
            if nested["status"] == "return":
                continue
            return nested
        policy_action = str((policy.get("chain_policies") or {}).get(chain) or "-").upper()
        if not stack and policy_action in TERMINAL_TARGETS:
            return {
                "status": "decided", "verdict": TERMINAL_TARGETS[policy_action],
                "action": policy_action, "rule": None,
                "match_basis": [f"{chain} default policy"], "trace": trace.copy(),
            }
        return {"status": "return", "trace": trace.copy()}

    if not policy.get("complete", False):
        return {
            "status": "unknown",
            "reason": "The retained policy or referenced address-set membership is incomplete.",
            "trace": [],
        }
    result = walk("FORWARD", ())
    if result["status"] == "return":
        result = {
            "status": "unknown", "reason": "The retained FORWARD chain returned without a supported final verdict.",
            "trace": result.get("trace") or [],
        }
    return result


def _translation_target(value: str | None) -> tuple[str | None, int | None]:
    if not value:
        return None, None
    host = value
    translated_port = None
    if value.count(":") == 1:
        possible_host, possible_port = value.rsplit(":", 1)
        if possible_port.isdigit():
            host, translated_port = possible_host, int(possible_port)
    try:
        parsed = ipaddress.ip_address(host)
    except ValueError:
        return None, translated_port
    return (str(parsed) if parsed.version == 4 else None), translated_port


def evaluate_iptables_nat(
    policy: dict,
    *,
    source: object,
    destination: object,
    protocol: str,
    port: int,
    source_external: bool = False,
    destination_external: bool = False,
    input_interface: str | None = None,
    output_interface: str | None = None,
    stage: str = "destination",
    masquerade_source: str | None = None,
) -> dict:
    """Walk ordered destination or source NAT and report a supported translation."""
    if stage not in {"destination", "source"}:
        raise ValueError("NAT stage must be destination or source")
    rules_by_chain: dict[str, list[dict]] = defaultdict(list)
    for rule in policy.get("nat_rules") or []:
        if rule.get("chain"):
            rules_by_chain[str(rule["chain"])].append(rule)
    for rules in rules_by_chain.values():
        rules.sort(key=lambda item: int(item.get("rule_order") or 0))
    if not rules_by_chain:
        return {"status": "not_present", "trace": []}
    if not policy.get("complete", False):
        return {
            "status": "unknown", "reason": "The retained NAT policy or address-set membership is incomplete.",
            "trace": [],
        }
    ipsets = {item["name"]: item for item in policy.get("ipsets") or [] if item.get("name")}
    context = {
        "source": source, "destination": destination,
        "source_external": source_external, "destination_external": destination_external,
        "protocol": protocol.lower(), "port": port,
        "input_interface": input_interface, "output_interface": output_interface,
    }
    trace = []

    def walk(chain: str, stack: tuple[str, ...]) -> dict:
        if chain in stack or len(stack) >= 24:
            return {"status": "unknown", "reason": f"NAT chain recursion could not be resolved at {chain}."}
        if chain not in rules_by_chain:
            return {"status": "return", "trace": trace.copy()}
        for rule in rules_by_chain[chain]:
            matched, basis = _rule_matches(rule, context, ipsets)
            action = str(rule.get("action") or "").upper()
            if matched is False:
                continue
            if matched is None:
                if action in {"LOG", "NFLOG", "MARK", "CONNMARK"}:
                    continue
                return {
                    "status": "unknown",
                    "reason": f"NAT rule {chain} #{rule.get('rule_order')} may affect the flow but contains unresolved match criteria.",
                    "rule": rule, "match_basis": basis, "trace": trace.copy(),
                }
            trace.append({
                "chain": chain, "rule_order": rule.get("rule_order"), "action": action,
                "evidence": rule.get("evidence"), "match_basis": basis,
            })
            if action == "DNAT":
                if stage != "destination":
                    return {"status": "no_translation", "trace": trace.copy()}
                address, translated_port = _translation_target(rule.get("to_destination"))
                if address is None:
                    return {"status": "unknown", "reason": "The matched DNAT target is not a supported IPv4 address.", "rule": rule, "trace": trace.copy()}
                return {
                    "status": "translated", "translation": "dnat",
                    "destination": address, "port": translated_port or port,
                    "rule": rule, "match_basis": basis, "trace": trace.copy(),
                }
            if action == "REDIRECT":
                if stage != "destination":
                    return {"status": "no_translation", "trace": trace.copy()}
                redirect_port = rule.get("to_ports")
                return {
                    "status": "redirected", "translation": "redirect",
                    "destination": "local_device",
                    "port": int(redirect_port) if str(redirect_port or "").isdigit() else port,
                    "rule": rule, "match_basis": basis, "trace": trace.copy(),
                }
            if action == "SNAT":
                if stage != "source":
                    return {"status": "no_translation", "trace": trace.copy()}
                address, translated_port = _translation_target(rule.get("to_source"))
                if address is None:
                    return {
                        "status": "unknown",
                        "reason": "The matched SNAT target is not a supported single IPv4 address.",
                        "rule": rule, "match_basis": basis, "trace": trace.copy(),
                    }
                return {
                    "status": "translated", "translation": "snat",
                    "source": address, "source_port": translated_port,
                    "dynamic": False, "rule": rule,
                    "match_basis": basis, "trace": trace.copy(),
                }
            if action == "MASQUERADE":
                if stage != "source":
                    return {"status": "no_translation", "trace": trace.copy()}
                return {
                    "status": "translated", "translation": "masquerade",
                    "source": masquerade_source, "source_port": None,
                    "dynamic": True, "output_interface": output_interface,
                    "rule": rule, "match_basis": basis, "trace": trace.copy(),
                }
            if action == "RETURN":
                return {"status": "return", "trace": trace.copy()}
            if action == "ACCEPT":
                return {"status": "no_translation", "trace": trace.copy()}
            if action in NON_TERMINAL_TARGETS or not action:
                continue
            nested = walk(action, stack + (chain,))
            if nested["status"] == "return":
                continue
            return nested
        return {"status": "return", "trace": trace.copy()}

    result = walk("PREROUTING" if stage == "destination" else "POSTROUTING", ())
    if result["status"] == "return":
        return {"status": "no_translation", "trace": result.get("trace") or []}
    return result
