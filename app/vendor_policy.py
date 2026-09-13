from __future__ import annotations

import ipaddress
import html
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
    if value.lower() in {"object", "object-group"} and index + 1 < len(tokens):
        return f"@{tokens[index + 1]}", index + 2, False
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
    service_ref = None
    if acl_type == "extended" and len(tokens) >= 2 and tokens[0].lower() == "object-group":
        service_ref = tokens[1]
        protocol = "any"
        tokens = tokens[2:]
    else:
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
    elif index + 1 < len(tokens) and tokens[index].lower() in {"object", "object-group"}:
        service_ref = tokens[index + 1]
    return {
        "policy": acl_name, "order": order, "action": action,
        "protocol": protocol, "source": source, "destination": destination,
        "destination_port": destination_port, "service_ref": service_ref,
        "unresolved": source_unresolved or destination_unresolved or port_unresolved,
        "evidence": line.strip()[:2000],
    }


def _empty_object(kind: str, evidence: str, **extra) -> dict:
    return {
        "kind": kind, "members": [], "complete": True,
        "evidence": evidence.strip()[:1000], **extra,
    }


def _network_from_mask(address: str, mask: str) -> str | None:
    try:
        return str(ipaddress.ip_network(f"{address}/{mask}", strict=False))
    except ValueError:
        return None


def _service_member(protocol: str, operator: str, values: list[str]) -> dict | None:
    protocol = protocol.lower().replace("tcp-udp", "tcp_udp")
    if operator.lower() == "source":
        return None
    if operator.lower() == "destination" and values:
        operator, values = values[0], values[1:]
    if operator.lower() == "eq" and values:
        port = _port(values[0])
        return {"protocol": protocol, "start": port, "end": port} if port else None
    if operator.lower() == "range" and len(values) >= 2:
        start, end = _port(values[0]), _port(values[1])
        return {"protocol": protocol, "start": start, "end": end} if start and end else None
    return None


def _parse_cisco_objects(text: str) -> tuple[dict[str, dict], dict[str, dict]]:
    addresses: dict[str, dict] = {}
    services: dict[str, dict] = {}
    current_kind = None
    current_name = None
    for raw in text.splitlines():
        line = html.unescape(raw.strip())
        network_header = re.match(r"^object(?:-group)? network (\S+)$", line, re.I)
        service_header = re.match(r"^object(?:-group)? service (\S+)(?:\s+(tcp|udp|tcp-udp))?$", line, re.I)
        if network_header:
            current_kind, current_name = "address", network_header.group(1)
            addresses.setdefault(current_name, _empty_object("address", line))
            continue
        if service_header:
            current_kind, current_name = "service", service_header.group(1)
            services.setdefault(
                current_name,
                _empty_object("service", line, default_protocol=(service_header.group(2) or "any").lower()),
            )
            continue
        if line == "!" or re.match(r"^(?:interface|ip access-list|access-list|access-group)\b", line, re.I):
            current_kind = current_name = None
            continue
        if not current_kind or not current_name or not line or line.lower().startswith("description "):
            continue
        if current_kind == "address":
            item = addresses[current_name]
            host_match = re.match(r"^(?:network-object\s+)?host\s+(\S+)$", line, re.I)
            fqdn_match = re.match(r"^fqdn(?:\s+v4)?\s+(\S+)$", line, re.I)
            subnet_match = re.match(r"^(?:network-object\s+|subnet\s+)?(\d{1,3}(?:\.\d{1,3}){3})\s+(\d{1,3}(?:\.\d{1,3}){3})$", line, re.I)
            cidr_match = re.match(r"^(?:network-object\s+)?(\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})$", line, re.I)
            reference = re.match(r"^(?:group-object|network-object object)\s+(\S+)$", line, re.I)
            range_match = re.match(r"^(?:network-object\s+)?range\s+(\S+)\s+(\S+)$", line, re.I)
            if fqdn_match:
                item["members"].append({"dns_name": fqdn_match.group(1)})
                item["dynamic"] = True
                item["resolution_source"] = "No retained runtime resolution"
                item["complete"] = False
            elif host_match:
                try:
                    item["members"].append({"value": f"{ipaddress.IPv4Address(host_match.group(1))}/32"})
                except ipaddress.AddressValueError:
                    item["complete"] = False
            elif subnet_match and (network := _network_from_mask(*subnet_match.groups())):
                item["members"].append({"value": network})
            elif cidr_match:
                item["members"].append({"value": cidr_match.group(1)})
            elif reference:
                item["members"].append({"ref": reference.group(1)})
            elif range_match:
                item["members"].append({"range": list(range_match.groups())})
            else:
                item["complete"] = False
            continue
        item = services[current_name]
        reference = re.match(r"^(?:group-object|service-object object)\s+(\S+)$", line, re.I)
        if reference:
            item["members"].append({"ref": reference.group(1)})
            continue
        tokens = line.split()
        if not tokens:
            continue
        if tokens[0].lower() == "port-object":
            protocol = item.get("default_protocol") or "any"
            member = _service_member(protocol, tokens[1] if len(tokens) > 1 else "", tokens[2:])
        elif tokens[0].lower() in {"service", "service-object"} and len(tokens) >= 3:
            member = _service_member(tokens[1], tokens[2], tokens[3:])
        elif tokens[0].lower() in {"tcp", "udp", "tcp-udp"} and len(tokens) >= 2:
            member = _service_member(tokens[0], tokens[1], tokens[2:])
        else:
            member = None
        if member:
            item["members"].append(member)
        else:
            item["complete"] = False
    return addresses, services


def _parse_cisco(text: str) -> dict:
    address_objects, service_objects = _parse_cisco_objects(text)
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
    return {
        "vendor": "cisco", "rules": rules, "attachments": attachments,
        "address_objects": address_objects, "service_objects": service_objects,
    }


def _parse_vyos_groups(text: str) -> tuple[dict[str, dict], dict[str, dict], dict[str, dict]]:
    addresses: dict[str, dict] = {}
    services: dict[str, dict] = {}
    interfaces: dict[str, dict] = {}
    pattern = re.compile(
        r"^set firewall group (address-group|network-group|domain-group|port-group|interface-group) "
        r"(\S+) (address|network|port|interface) (.+)$",
        re.I,
    )
    for raw in text.splitlines():
        line = raw.strip()
        match = pattern.match(line)
        if not match:
            continue
        group_type, name, _, raw_value = match.groups()
        value = raw_value.replace("'", "").replace('"', "").strip()
        group_type = group_type.lower()
        if group_type in {"address-group", "network-group", "domain-group"}:
            item = addresses.setdefault(name, _empty_object("address", line))
            if group_type == "domain-group":
                item["members"].append({"dns_name": value})
                item["dynamic"] = True
                item["resolution_source"] = "No retained runtime resolution"
                item["complete"] = False
            elif group_type == "address-group" and "-" in value:
                start, end = value.split("-", 1)
                try:
                    ipaddress.IPv4Address(start)
                    ipaddress.IPv4Address(end)
                    item["members"].append({"range": [start, end]})
                except ipaddress.AddressValueError:
                    item["complete"] = False
            else:
                try:
                    network = ipaddress.ip_network(value, strict=False)
                    item["members"].append({"value": str(network)})
                except ValueError:
                    item["complete"] = False
        elif group_type == "port-group":
            item = services.setdefault(name, _empty_object("service", line, default_protocol="any"))
            for port_value in re.split(r"\s*,\s*", value):
                values = port_value.split("-", 1)
                start = _port(values[0])
                end = _port(values[-1])
                if start and end:
                    item["members"].append({"protocol": "any", "start": start, "end": end})
                else:
                    item["complete"] = False
        else:
            item = interfaces.setdefault(name, _empty_object("interface", line))
            item["members"].append({"value": value})
    return addresses, services, interfaces


def _parse_vyos(text: str) -> dict:
    address_objects, service_objects, interface_objects = _parse_vyos_groups(text)
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
                "service_ref": None, "input_interface_ref": None,
                "output_interface_ref": None,
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
            elif field == "source" and re.match(r"^group (?:address-group|network-group|domain-group) \S+$", value, re.I):
                item["source"] = "@" + value.split()[-1]
            elif field == "destination" and value.lower().startswith("address "):
                item["destination"] = value.split(maxsplit=1)[1]
            elif field == "destination" and re.match(r"^group (?:address-group|network-group|domain-group) \S+$", value, re.I):
                item["destination"] = "@" + value.split()[-1]
            elif field == "destination" and value.lower().startswith("port "):
                item["destination_port"] = _port(value.split(maxsplit=1)[1])
                item["unresolved"] |= item["destination_port"] is None
            elif field == "destination" and re.match(r"^group port-group \S+$", value, re.I):
                item["service_ref"] = value.split()[-1]
            elif field == "inbound-interface" and value.lower().startswith("name "):
                item["input_interface"] = value.split(maxsplit=1)[1]
            elif field == "inbound-interface" and value.lower().startswith("group "):
                item["input_interface_ref"] = value.split()[-1]
            elif field == "outbound-interface" and value.lower().startswith("name "):
                item["output_interface"] = value.split(maxsplit=1)[1]
            elif field == "outbound-interface" and value.lower().startswith("group "):
                item["output_interface_ref"] = value.split()[-1]
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
    return {
        "vendor": "vyos", "rules": rules, "attachments": attachments,
        "defaults": defaults, "address_objects": address_objects,
        "service_objects": service_objects, "interface_objects": interface_objects,
    }


def _xml_tag(block: str, name: str) -> str:
    match = re.search(rf"<{name}>(.*?)</{name}>", block, re.I | re.S)
    return html.unescape(match.group(1).strip()) if match else ""


def _pfsense_runtime_tables(text: str) -> dict[str, list[str]]:
    tables: dict[str, list[str]] = defaultdict(list)
    current = None
    for raw in text.splitlines():
        line = raw.strip()
        marker = re.match(r"^__NCT_PF_TABLE__\s+<?([^>\s]+)>?$", line)
        if marker:
            current = marker.group(1)
            continue
        if line.startswith("====="):
            current = None
            continue
        if not current or not line:
            continue
        try:
            network = ipaddress.ip_network(line, strict=False)
        except ValueError:
            continue
        if network.version == 4:
            tables[current].append(str(network))
    return dict(tables)


def _parse_pfsense_aliases(text: str) -> tuple[dict[str, dict], dict[str, dict]]:
    runtime_tables = _pfsense_runtime_tables(text)
    raw_aliases = []
    for match in re.finditer(r"<alias>(.*?)</alias>", text, re.I | re.S):
        block = match.group(1)
        name = _xml_tag(block, "name")
        alias_type = _xml_tag(block, "type").lower()
        values = _xml_tag(block, "address").split()
        if name:
            raw_aliases.append((name, alias_type, values, match.group(0)[:1000]))
    names = {item[0] for item in raw_aliases}
    addresses: dict[str, dict] = {}
    services: dict[str, dict] = {}
    for name, alias_type, values, evidence in raw_aliases:
        if alias_type == "port":
            item = services.setdefault(name, _empty_object("service", evidence, default_protocol="any"))
            for value in values:
                if value in names:
                    item["members"].append({"ref": value})
                    continue
                parts = re.split(r"[:-]", value, maxsplit=1)
                start, end = _port(parts[0]), _port(parts[-1])
                if start and end:
                    item["members"].append({"protocol": "any", "start": start, "end": end})
                else:
                    item["complete"] = False
            continue
        item = addresses.setdefault(name, _empty_object("address", evidence))
        if alias_type not in {"host", "network"}:
            item["complete"] = False
        for value in values:
            if value in names:
                item["members"].append({"ref": value})
                continue
            try:
                network = ipaddress.ip_network(value, strict=False)
                if network.version == 4:
                    item["members"].append({"value": str(network)})
                else:
                    item["complete"] = False
            except ValueError:
                item["members"].append({"dns_name": value})
                item["dynamic"] = True
                item["resolution_source"] = "No retained runtime resolution"
                item["complete"] = False
        if item.get("dynamic"):
            resolved = runtime_tables.get(name) or []
            if resolved:
                known = {member.get("value") for member in item["members"] if member.get("value")}
                item["members"].extend(
                    {"value": value, "resolved_from": "pfctl runtime table"}
                    for value in resolved if value not in known
                )
                item["resolution_source"] = "Retained pfctl runtime table snapshot"
                item["complete"] = True
    return addresses, services


def _parse_pfsense(text: str) -> dict:
    address_objects, service_objects = _parse_pfsense_aliases(text)
    rules = []
    for order, raw in enumerate(text.splitlines(), start=1):
        line = html.unescape(raw.strip())
        match = re.match(r"^(pass|block)(?:\s+drop)?\s+(in|out)\b(.*)$", line, re.I)
        if not match:
            continue
        action, direction, body = match.groups()
        iface = re.search(r"\bon\s+(\S+)", body, re.I)
        proto = re.search(r"\bproto\s+(tcp|udp|icmp)\b", body, re.I)
        addresses = re.search(r"\bfrom\s+(\S+)\s+to\s+(\S+)", body, re.I)
        port_match = re.search(r"\bport\s*(?:=)?\s*(\S+)", body, re.I)
        source_value = addresses.group(1) if addresses else "any"
        destination_value = addresses.group(2) if addresses else "any"
        source_ref = re.fullmatch(r"<([^>]+)>", source_value)
        destination_ref = re.fullmatch(r"<([^>]+)>", destination_value)
        raw_port = port_match.group(1) if port_match else None
        port_ref = re.fullmatch(r"<([^>]+)>", raw_port or "")
        rules.append({
            "policy": "pfctl-active", "order": order,
            "action": "permit" if action.lower() == "pass" else "deny",
            "direction": direction.lower(), "interface": iface.group(1) if iface else None,
            "protocol": proto.group(1).lower() if proto else "ip",
            "source": f"@{source_ref.group(1)}" if source_ref else source_value,
            "destination": f"@{destination_ref.group(1)}" if destination_ref else destination_value,
            "destination_port": _port(raw_port) if raw_port and not port_ref else None,
            "service_ref": port_ref.group(1) if port_ref else None,
            "unresolved": iface is None or addresses is None or (
                port_match is not None and not port_ref and _port(raw_port or "") is None
            ),
            "evidence": line[:2000],
        })
    return {
        "vendor": "pfsense", "rules": rules, "attachments": [],
        "address_objects": address_objects, "service_objects": service_objects,
    }


def _parse_juniper_objects(text: str) -> tuple[dict[str, dict[str, dict]], dict[str, str], dict[str, dict]]:
    books: dict[str, dict[str, dict]] = defaultdict(dict)
    zone_books: dict[str, str] = {}
    services: dict[str, dict] = {}
    for raw in text.splitlines():
        line = raw.strip()
        address = re.match(r"^set security address-book (\S+) address (\S+) (\S+)(?:\s+(.+))?$", line, re.I)
        zone_address = re.match(r"^set security zones security-zone (\S+) address-book address (\S+) (\S+)(?:\s+(.+))?$", line, re.I)
        if address or zone_address:
            if address:
                book, name, value, remainder = address.groups()
            else:
                zone, name, value, remainder = zone_address.groups()
                book = f"zone:{zone}"
                zone_books[zone] = book
            item = books[book].setdefault(name, _empty_object("address", line))
            if value.lower() == "range-address" and remainder:
                parts = remainder.replace(" to ", " ").split()
                if len(parts) >= 2:
                    item["members"].append({"range": parts[:2]})
                else:
                    item["complete"] = False
            elif value.lower() in {"dns-name", "wildcard-address"}:
                if value.lower() == "dns-name" and remainder:
                    item["members"].append({"dns_name": remainder.split()[0]})
                    item["dynamic"] = True
                    item["resolution_source"] = "No retained runtime resolution"
                item["complete"] = False
            else:
                try:
                    network = ipaddress.ip_network(value, strict=False)
                    if network.version == 4:
                        item["members"].append({"value": str(network)})
                    else:
                        item["complete"] = False
                except ValueError:
                    item["complete"] = False
            continue
        address_set = re.match(r"^set security address-book (\S+) address-set (\S+) (?:address|address-set) (\S+)$", line, re.I)
        zone_set = re.match(r"^set security zones security-zone (\S+) address-book address-set (\S+) (?:address|address-set) (\S+)$", line, re.I)
        if address_set or zone_set:
            if address_set:
                book, name, member = address_set.groups()
            else:
                zone, name, member = zone_set.groups()
                book = f"zone:{zone}"
                zone_books[zone] = book
            books[book].setdefault(name, _empty_object("address", line))["members"].append({"ref": member})
            continue
        attached = re.match(r"^set security address-book (\S+) attach zone (\S+)$", line, re.I)
        if attached:
            zone_books[attached.group(2)] = attached.group(1)
            continue
        application = re.match(r"^set applications application (\S+) (protocol|destination-port) (.+)$", line, re.I)
        if application:
            name, field, value = application.groups()
            item = services.setdefault(name, _empty_object("service", line, protocols=[], ports=[]))
            value = value.replace("'", "").replace('"', "").strip()
            if field.lower() == "protocol":
                item["protocols"].append(value.lower())
            else:
                item["ports"].append(value)
            continue
        app_set = re.match(r"^set applications application-set (\S+) application (\S+)$", line, re.I)
        if app_set:
            name, member = app_set.groups()
            services.setdefault(name, _empty_object("service", line))["members"].append({"ref": member})
    for item in services.values():
        protocols = item.pop("protocols", [])
        ports = item.pop("ports", [])
        if protocols or ports:
            if not protocols or not ports:
                item["complete"] = False
            for protocol in protocols:
                for raw_port in ports:
                    for port_value in raw_port.replace("[", " ").replace("]", " ").replace(",", " ").split():
                        parts = re.split(r"[:-]", port_value, maxsplit=1)
                        start, end = _port(parts[0]), _port(parts[-1])
                        if start and end:
                            item["members"].append({"protocol": protocol, "start": start, "end": end})
                        else:
                            item["complete"] = False
    return {name: dict(items) for name, items in books.items()}, zone_books, services


def _parse_juniper(text: str) -> dict:
    address_books, zone_books, service_objects = _parse_juniper_objects(text)
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
                item[target].extend(
                    value for value in entry.replace("[", "").replace("]", "").replace("'", "").replace('"', "").split()
                    if value
                )
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
    return {
        "vendor": "juniper", "rules": rules, "attachments": [],
        "interface_zones": zones, "address_books": address_books,
        "zone_books": zone_books, "service_objects": service_objects,
    }


def _object_inventory(policy: dict) -> list[dict]:
    inventory = []

    def add(scope: str, name: str, item: dict) -> None:
        members = []
        for member in item.get("members") or []:
            if member.get("ref"):
                members.append(f"object {member['ref']}")
            elif member.get("range"):
                members.append("–".join(str(value) for value in member["range"][:2]))
            elif member.get("value"):
                members.append(str(member["value"]))
            elif member.get("dns_name"):
                members.append(f"DNS {member['dns_name']}")
            elif member.get("start") is not None:
                start, end = member.get("start"), member.get("end")
                port = str(start) if start == end else f"{start}–{end}"
                members.append(f"{member.get('protocol') or 'any'}/{port}")
        inventory.append({
            "name": name,
            "object_type": item.get("object_type") or "object",
            "scope": scope,
            "member_count": len(item.get("members") or []),
            "member_preview": ", ".join(members[:8]),
            "complete": bool(item.get("complete", False)),
            "dynamic": bool(item.get("dynamic", False)),
            "resolution_source": item.get("resolution_source"),
        })

    for object_type, field in (
        ("Address", "address_objects"),
        ("Service", "service_objects"),
        ("Interface", "interface_objects"),
    ):
        for name, item in sorted((policy.get(field) or {}).items()):
            add(object_type, name, item)
    for book, objects in sorted((policy.get("address_books") or {}).items()):
        for name, item in sorted(objects.items()):
            add(f"Address · {book}", name, item)
    return inventory


def parse_vendor_policy(text: str) -> dict:
    """Parse applied policy forms that retain both ordered rules and attachment context."""
    candidates = [_parse_cisco(text), _parse_vyos(text), _parse_pfsense(text), _parse_juniper(text)]
    populated = [
        item for item in candidates
        if item.get("rules") or item.get("address_objects") or item.get("address_books")
        or item.get("service_objects") or item.get("interface_objects")
    ]
    if not populated:
        return {
            "vendor": None, "rules": [], "attachments": [], "object_inventory": [],
            "counts": {"rules": 0, "attachments": 0, "address_objects": 0,
                       "service_objects": 0, "interface_objects": 0, "objects": 0},
            "complete": False,
        }
    result = max(populated, key=lambda item: (
        len(item.get("rules") or []) * 100
        + len(item.get("address_objects") or {})
        + sum(len(items) for items in (item.get("address_books") or {}).values())
        + len(item.get("service_objects") or {})
        + len(item.get("interface_objects") or {})
    ))
    result["complete"] = True
    address_object_count = len(result.get("address_objects") or {}) + sum(
        len(items) for items in (result.get("address_books") or {}).values()
    )
    result["object_inventory"] = _object_inventory(result)
    result["counts"] = {
        "rules": len(result.get("rules") or []),
        "attachments": len(result.get("attachments") or []),
        "address_objects": address_object_count,
        "service_objects": len(result.get("service_objects") or {}),
        "interface_objects": len(result.get("interface_objects") or {}),
        "objects": len(result["object_inventory"]),
    }
    return result


def _literal_address_matches(specification: str, endpoint: object, external: bool) -> bool | None:
    if external:
        return None
    try:
        expected = ipaddress.ip_network(specification, strict=False)
    except ValueError:
        return None
    try:
        actual = ipaddress.ip_network(str(endpoint), strict=False)
    except ValueError:
        return None
    if actual.subnet_of(expected):
        return True
    if actual.overlaps(expected):
        return None
    return False


def _address_object_matches(
    objects: dict[str, dict], name: str, endpoint: object, external: bool,
    stack: tuple[str, ...] = (),
) -> bool | None:
    if name in stack or len(stack) >= 20:
        return None
    item = objects.get(name)
    if item is None:
        return None
    results = []
    for member in item.get("members") or []:
        if member.get("ref"):
            results.append(_address_object_matches(
                objects, str(member["ref"]), endpoint, external, stack + (name,)
            ))
        elif member.get("value"):
            results.append(_literal_address_matches(str(member["value"]), endpoint, external))
        elif member.get("range"):
            if external:
                results.append(None)
                continue
            try:
                actual = ipaddress.ip_address(str(endpoint))
                start, end = (ipaddress.ip_address(value) for value in member["range"])
                results.append(start <= actual <= end)
            except ValueError:
                results.append(None)
    if True in results:
        return True
    if None in results or not item.get("complete", False):
        return None
    return False


def _address_matches(
    specification: str | None, endpoint: object, external: bool,
    policy: dict | None = None,
) -> bool | None:
    if not specification or specification.lower() in {"any", "any-ipv4"}:
        return True
    if specification.startswith("@"):
        return _address_object_matches(
            (policy or {}).get("address_objects") or {}, specification[1:], endpoint, external
        )
    return _literal_address_matches(specification, endpoint, external)


def _service_object_matches(
    objects: dict[str, dict], name: str, protocol: str, port: int,
    stack: tuple[str, ...] = (),
) -> bool | None:
    if name in stack or len(stack) >= 20:
        return None
    item = objects.get(name)
    if item is None:
        return None
    results = []
    for member in item.get("members") or []:
        if member.get("ref"):
            results.append(_service_object_matches(
                objects, str(member["ref"]), protocol, port, stack + (name,)
            ))
            continue
        member_protocol = str(member.get("protocol") or "any").lower()
        protocol_match = (
            member_protocol in {"any", "ip", "all"}
            or member_protocol == protocol.lower()
            or member_protocol == "tcp_udp" and protocol.lower() in {"tcp", "udp"}
        )
        start, end = member.get("start"), member.get("end")
        if start is None or end is None:
            results.append(None)
        else:
            results.append(protocol_match and int(start) <= port <= int(end))
    if True in results:
        return True
    if None in results or not item.get("complete", False):
        return None
    return False


def _interface_object_matches(objects: dict[str, dict], name: str, interface: str | None) -> bool | None:
    if interface is None:
        return None
    item = objects.get(name)
    if item is None:
        return None
    for member in item.get("members") or []:
        value = str(member.get("value") or "")
        if (value.endswith("*") and interface.startswith(value[:-1])) or interface == value:
            return True
    return None if not item.get("complete", False) else False


def _basic_rule_match(
    rule: dict, *, source: object, destination: object, protocol: str, port: int,
    source_external: bool, destination_external: bool,
    input_interface: str | None = None, output_interface: str | None = None,
    policy: dict | None = None,
    flow_state: str = "new",
) -> bool | None:
    checks = [
        _address_matches(rule.get("source"), source, source_external, policy),
        _address_matches(rule.get("destination"), destination, destination_external, policy),
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
    if rule.get("service_ref"):
        checks.append(_service_object_matches(
            (policy or {}).get("service_objects") or {},
            str(rule["service_ref"]), protocol, port,
        ))
    if rule.get("input_interface"):
        checks.append(input_interface == rule.get("input_interface"))
    if rule.get("output_interface"):
        checks.append(output_interface == rule.get("output_interface"))
    if rule.get("input_interface_ref"):
        checks.append(_interface_object_matches(
            (policy or {}).get("interface_objects") or {},
            str(rule["input_interface_ref"]), input_interface,
        ))
    if rule.get("output_interface_ref"):
        checks.append(_interface_object_matches(
            (policy or {}).get("interface_objects") or {},
            str(rule["output_interface_ref"]), output_interface,
        ))
    states = set(rule.get("states") or [])
    if states:
        requested_states = {"new" if flow_state == "new" else "established"}
        if flow_state == "established":
            requested_states.add("related")
        checks.append(bool(states & requested_states))
    if False in checks:
        return False
    if rule.get("unresolved") or None in checks:
        return None
    return True


def _resolved_basis(
    rule: dict, flow_state: str = "new", policy: dict | None = None,
) -> list[str]:
    names = []
    for value in (rule.get("source"), rule.get("destination")):
        if str(value or "").startswith("@"):
            names.append(str(value)[1:])
    for field in ("service_ref", "input_interface_ref", "output_interface_ref"):
        if rule.get(field):
            names.append(str(rule[field]))
    basis = []
    objects = (policy or {}).get("address_objects") or {}
    for name in dict.fromkeys(names):
        item = objects.get(name) or {}
        if item.get("dynamic") and item.get("complete"):
            basis.append(
                f"Resolved dynamic object {name} from retained runtime table snapshot"
            )
        else:
            basis.append(f"Resolved object {name}")
    states = set(rule.get("states") or [])
    requested = {"new" if flow_state == "new" else "established"}
    if flow_state == "established":
        requested.add("related")
    matched_states = sorted(states & requested)
    if matched_states:
        basis.append("Connection state " + "/".join(matched_states) + " matched")
    return basis


def _junos_address_matches(
    policy: dict, name: str, zone: str | None, endpoint: object, external: bool,
) -> bool | None:
    if name.lower() in {"any", "any-ipv4"}:
        return True
    literal = _literal_address_matches(name, endpoint, external)
    if literal is not None:
        return literal
    books = policy.get("address_books") or {}
    candidate_books = []
    zone_book = (policy.get("zone_books") or {}).get(zone)
    if zone_book:
        candidate_books.append(zone_book)
    candidate_books.extend([f"zone:{zone}" if zone else None, "global"])
    for book_name in dict.fromkeys(value for value in candidate_books if value):
        objects = books.get(book_name) or {}
        if name in objects:
            return _address_object_matches(objects, name, endpoint, external)
    return None


def _junos_application_matches(policy: dict, name: str, protocol: str, port: int) -> bool | None:
    lowered = name.lower()
    if lowered == "any":
        return True
    if lowered in JUNOS_APPLICATIONS:
        return JUNOS_APPLICATIONS[lowered] == (protocol.lower(), port)
    services = policy.get("service_objects") or {}
    if name in services:
        return _service_object_matches(services, name, protocol, port)
    return None


def _evaluate_vyos(
    policy: dict, *, source: object, destination: object, protocol: str, port: int,
    source_external: bool, destination_external: bool,
    input_interface: str | None, output_interface: str | None,
    flow_state: str,
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
                policy=policy,
                flow_state=flow_state,
            )
            if matched is False:
                continue
            if matched is None:
                return {"status": "unknown", "reason": f"Applied VyOS policy {chain} contains unresolved match criteria.", "rule": rule}
            action = rule.get("action")
            if action in {"permit", "deny"}:
                return {"status": "decided", "verdict": "allow" if action == "permit" else "deny", "rule": rule, "match_basis": [f"Applied policy {chain}", *_resolved_basis(rule, flow_state, policy)]}
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
    flow_state: str = "new",
) -> dict:
    flow_state = str(flow_state or "new").lower()
    if flow_state not in {"new", "established"}:
        raise ValueError("Flow state must be new or established")
    vendor = policy.get("vendor")
    rules = policy.get("rules") or []
    relevant = []
    if vendor == "vyos":
        return _evaluate_vyos(
            policy, source=source, destination=destination, protocol=protocol, port=port,
            source_external=source_external, destination_external=destination_external,
            input_interface=input_interface, output_interface=output_interface,
            flow_state=flow_state,
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
                app_results.append(_junos_application_matches(policy, application, protocol, port))
            source_results = [
                _junos_address_matches(policy, value, from_zone, source, source_external)
                for value in sources
            ]
            destination_results = [
                _junos_address_matches(policy, value, to_zone, destination, destination_external)
                for value in destinations
            ]
            if True not in source_results or True not in destination_results or True not in app_results:
                unresolved_dimension = any(
                    True not in results and None in results
                    for results in (source_results, destination_results, app_results)
                )
                if unresolved_dimension:
                    return {"status": "unknown", "reason": f"Juniper policy {item['policy']} uses unresolved address or application objects.", "rule": item}
                continue
            object_names = [
                value for value in [*sources, *destinations, *applications]
                if value.lower() not in {"any", "any-ipv4"} and "/" not in value
            ]
            return {
                "status": "decided", "verdict": "allow" if item["action"] == "permit" else "deny",
                "rule": item,
                "match_basis": [
                    f"Zone path {from_zone} → {to_zone}",
                    *(f"Resolved object {name}" for name in dict.fromkeys(object_names)),
                ],
            }
    if not relevant:
        return {"status": "not_applied", "reason": "No retained policy attachment matches the interface path."}
    for rule in sorted(relevant, key=lambda item: int(item.get("order") or 0)):
        matched = _basic_rule_match(
            rule, source=source, destination=destination, protocol=protocol, port=port,
            source_external=source_external, destination_external=destination_external,
            input_interface=input_interface, output_interface=output_interface,
            policy=policy,
            flow_state=flow_state,
        )
        if matched is None:
            return {"status": "unknown", "reason": f"Applied {vendor} policy {rule.get('policy')} contains unresolved match criteria.", "rule": rule}
        if matched:
            return {"status": "decided", "verdict": "allow" if rule.get("action") == "permit" else "deny", "rule": rule, "match_basis": [f"Applied policy {rule.get('policy')}", *_resolved_basis(rule, flow_state, policy)]}
    return {"status": "unknown", "reason": f"Applied {vendor} policy had no supported matching terminal rule."}
