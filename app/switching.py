from __future__ import annotations

import re

from app.mac_enrichment import is_unicast_mac, normalize_mac


MAC_TOKEN = r"(?:(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}|(?:[0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4})"
IFACE_TOKEN = r"[A-Za-z][A-Za-z0-9_.:/-]*"
UNAVAILABLE_MARKERS = (
    "[nct] command unavailable",
    "% invalid input",
    "unknown command",
    "command not found",
    "not found",
    "syntax error",
    "invalid command",
    "not supported",
)


def _clean_interface(value: object) -> str | None:
    clean = str(value or "").strip(" ,()[]")
    if not clean or clean.lower() in {"cpu", "router", "switch", "drop", "-"}:
        return None
    return clean[:120]


def interface_key(value: object) -> str:
    """Normalize common long/short switch port names for evidence correlation."""
    clean = re.sub(r"\s+", "", str(value or "")).lower()
    for long_name, short_name in (
        ("tengigabitethernet", "te"),
        ("twentyfivegige", "twe"),
        ("gigabitethernet", "gi"),
        ("fastethernet", "fa"),
        ("ethernet", "eth"),
        ("port-channel", "po"),
    ):
        if clean.startswith(long_name):
            return short_name + clean[len(long_name):]
    return clean


def _vlan_id(value: object) -> int | None:
    match = re.search(r"(?<!\d)(\d{1,4})(?!\d)", str(value or ""))
    if not match:
        return None
    number = int(match.group(1))
    return number if 0 <= number <= 4095 else None


def parse_command_results(text: str, commands: list[str] | None = None) -> list[dict]:
    """Report per-command observability without inventing success for unlabeled CLI output."""
    requested = [str(command) for command in commands or []]
    section_re = re.compile(r"(?m)^=====\s*(.+?)\s*=====\s*$")
    matches = list(section_re.finditer(text))
    sections: dict[str, str] = {}
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        sections[match.group(1).strip()] = text[match.end():end].strip()
    results = []
    for command in requested:
        body = sections.get(command)
        if body is None:
            results.append({
                "command": command,
                "status": "not_individually_reported",
                "detail": "The device CLI returned one combined stream without a reliable per-command exit status.",
            })
            continue
        unavailable = next((marker for marker in UNAVAILABLE_MARKERS if marker in body.lower()), None)
        results.append({
            "command": command,
            "status": "unavailable" if unavailable else "completed",
            "detail": (
                "The device reported this command as unavailable or unsuccessful."
                if unavailable else "A labeled output section was retained for this command."
            ),
            "evidence": body[:500],
        })
    for command, body in sections.items():
        if command in requested:
            continue
        unavailable = next((marker for marker in UNAVAILABLE_MARKERS if marker in body.lower()), None)
        results.append({
            "command": command,
            "status": "unavailable" if unavailable else "completed",
            "detail": "A labeled output section was retained for this command.",
            "evidence": body[:500],
        })
    return results


def parse_switch_evidence(text: str, commands: list[str] | None = None) -> dict:
    """Parse bounded Cisco, Junos, and Linux/UniFi switching evidence."""
    mac_table: list[dict] = []
    vlans: dict[tuple[int | None, str], dict] = {}
    ports: dict[str, dict] = {}
    port_channels: dict[str, dict] = {}
    spanning_tree: list[dict] = []
    seen_macs: set[tuple[str, int | None, str | None]] = set()
    seen_stp: set[tuple[str | None, int | None, str | None]] = set()
    current_interface: str | None = None

    def port(name: object) -> dict | None:
        interface = _clean_interface(name)
        if not interface:
            return None
        return ports.setdefault(interface, {
            "interface": interface,
            "mode": None,
            "access_vlan": None,
            "native_vlan": None,
            "allowed_vlans": [],
            "port_channel": None,
            "status": None,
            "description": None,
            "poe": None,
            "uplink": False,
            "evidence": [],
        })

    def add_port_evidence(item: dict | None, line: str) -> None:
        if item is not None and line not in item["evidence"] and len(item["evidence"]) < 25:
            item["evidence"].append(line[:500])

    def add_vlan(vlan: int | None, name: object, line: str, interfaces: list[str] | None = None) -> None:
        clean_name = str(name or "").strip()[:120]
        key = (vlan, clean_name.casefold())
        item = vlans.setdefault(key, {
            "vlan_id": vlan,
            "name": clean_name or (f"VLAN {vlan}" if vlan is not None else "Unnumbered VLAN"),
            "interfaces": [],
            "evidence": line[:500],
        })
        for interface in interfaces or []:
            clean = _clean_interface(interface)
            if clean and clean not in item["interfaces"]:
                item["interfaces"].append(clean)

    def add_mac(mac_value: object, vlan: int | None, interface_value: object, entry_type: object, line_number: int, line: str) -> None:
        mac = normalize_mac(mac_value)
        interface = _clean_interface(interface_value)
        if not mac or not is_unicast_mac(mac):
            return
        key = (mac, vlan, interface)
        if key in seen_macs:
            return
        seen_macs.add(key)
        mac_table.append({
            "mac": mac,
            "vlan_id": vlan,
            "interface": interface,
            "entry_type": str(entry_type or "learned").strip().lower(),
            "line_number": line_number,
            "evidence": line[:500],
        })
        item = port(interface)
        if item:
            add_port_evidence(item, line)

    lines = text.splitlines()
    for line_number, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line:
            continue

        header = re.match(r"^interface\s+(%s)\b" % IFACE_TOKEN, line, re.I)
        name_header = re.match(r"^Name:\s*(%s)\s*$" % IFACE_TOKEN, line, re.I)
        if header or name_header:
            current_interface = (header or name_header).group(1)
            port(current_interface)

        cisco_mac = re.match(
            rf"^(?P<vlan>\d{{1,4}}|All|---)\s+(?P<mac>{MAC_TOKEN})\s+"
            rf"(?P<type>dynamic|static|secure|self|system|igmp|learn)\S*\s*(?P<interface>{IFACE_TOKEN})?\s*$",
            line, re.I,
        )
        bridge_mac = re.match(
            rf"^(?P<mac>{MAC_TOKEN})\s+dev\s+(?P<interface>{IFACE_TOKEN})(?P<rest>.*)$",
            line, re.I,
        )
        junos_mac = re.match(
            rf"^(?P<mac>{MAC_TOKEN})\s+(?P<type>learn|static|dynamic|[DSLP-]+)\s+"
            rf"(?:(?P<vlan>\d{{1,4}}|\S+)\s+)?(?P<interface>{IFACE_TOKEN})\s*$",
            line, re.I,
        )
        if cisco_mac:
            add_mac(
                cisco_mac.group("mac"), _vlan_id(cisco_mac.group("vlan")),
                cisco_mac.group("interface"), cisco_mac.group("type"), line_number, line,
            )
            continue
        if bridge_mac:
            rest = bridge_mac.group("rest")
            vlan_match = re.search(r"\bvlan\s+(\d{1,4})\b", rest, re.I)
            state_match = re.search(r"\b(static|permanent|self|master|offload)\b", rest, re.I)
            add_mac(
                bridge_mac.group("mac"), _vlan_id(vlan_match.group(1) if vlan_match else None),
                bridge_mac.group("interface"), state_match.group(1) if state_match else "learned", line_number, line,
            )
            continue
        if junos_mac and not re.search(r"\b(?:address|hardware|current)\b", line, re.I):
            add_mac(
                junos_mac.group("mac"), _vlan_id(junos_mac.group("vlan")),
                junos_mac.group("interface"), junos_mac.group("type"), line_number, line,
            )
            continue

        vlan_row = re.match(r"^(\d{1,4})\s+(.+?)\s+(active|act/unsup|suspended)\s*(.*)$", line, re.I)
        junos_vlan = re.match(r"^(\S+)\s+(\d{1,4})\s+(?:\S+\s+)*(\S+(?:\s*,\s*\S+)*)?\s*$", line)
        set_vlan = re.search(r"\bset\s+vlans\s+(\S+)\s+vlan-id\s+(\d{1,4})\b", line, re.I)
        if vlan_row:
            interfaces = re.split(r"\s*,\s*|\s+", vlan_row.group(4).strip()) if vlan_row.group(4).strip() else []
            add_vlan(int(vlan_row.group(1)), vlan_row.group(2), line, interfaces)
        elif set_vlan:
            add_vlan(int(set_vlan.group(2)), set_vlan.group(1), line)
        elif junos_vlan and any(word in line.lower() for word in ("default", "vlan", "users", "voice", "native")):
            add_vlan(int(junos_vlan.group(2)), junos_vlan.group(1), line)

        item = port(current_interface)
        if item:
            mode = re.search(r"\b(?:switchport\s+mode|administrative\s+mode:|interface-mode|port-mode)\s+(access|trunk|hybrid)\b", line, re.I)
            access = re.search(r"\b(?:switchport\s+access\s+vlan|access\s+mode\s+vlan:)\s*(\d{1,4})\b", line, re.I)
            native = re.search(r"\b(?:switchport\s+trunk\s+native\s+vlan|trunking\s+native\s+mode\s+vlan:)\s*(\d{1,4})\b", line, re.I)
            allowed = re.search(r"\bswitchport\s+trunk\s+allowed\s+vlan(?:\s+add)?\s+(.+)$", line, re.I)
            channel = re.search(r"\bchannel-group\s+(\d+)\b", line, re.I)
            description = re.match(r"^description\s+(.+)$", line, re.I)
            if mode:
                item["mode"] = mode.group(1).lower(); item["uplink"] = item["mode"] in {"trunk", "hybrid"}
            if access:
                item["access_vlan"] = int(access.group(1))
            if native:
                item["native_vlan"] = int(native.group(1))
            if allowed:
                item["allowed_vlans"] = [value.strip() for value in allowed.group(1).split(",") if value.strip()][:128]
            if channel:
                item["port_channel"] = f"Port-channel{channel.group(1)}"; item["uplink"] = True
            if description:
                item["description"] = description.group(1).strip()[:200]
            if re.search(r"\b(?:connected|up\s+up|link\s+up)\b", line, re.I):
                item["status"] = "up"
            elif re.search(r"\b(?:notconnect|down\s+down|disabled)\b", line, re.I):
                item["status"] = "down"
            poe = re.search(r"\b(?:power\s+inline|poe)\b.*?\b(auto|on|off|enabled|disabled|delivering)\b", line, re.I)
            if poe:
                item["poe"] = poe.group(1).lower()
            if any((mode, access, native, allowed, channel, description, poe)):
                add_port_evidence(item, line)

        junos_port = re.search(r"\bset\s+interfaces\s+(%s).*?family\s+ethernet-switching\s+(?:interface-mode|port-mode)\s+(access|trunk|hybrid)\b" % IFACE_TOKEN, line, re.I)
        junos_member = re.search(r"\bset\s+interfaces\s+(%s).*?family\s+ethernet-switching\s+vlan\s+members\s+(.+)$" % IFACE_TOKEN, line, re.I)
        if junos_port:
            item = port(junos_port.group(1)); item["mode"] = junos_port.group(2).lower(); item["uplink"] = item["mode"] != "access"; add_port_evidence(item, line)
        if junos_member:
            item = port(junos_member.group(1)); member = junos_member.group(2).strip(" []'"); item["allowed_vlans"] = [value for value in re.split(r"[\s,]+", member) if value][:128]; add_port_evidence(item, line)

        bridge_vlan = re.match(r"^(%s)\s+(\d{1,4})(.*)$" % IFACE_TOKEN, line, re.I)
        if bridge_vlan and re.search(r"\b(?:pvid|egress|untagged|self|master)\b", bridge_vlan.group(3), re.I):
            item = port(bridge_vlan.group(1)); vlan = int(bridge_vlan.group(2)); flags = bridge_vlan.group(3).lower()
            if "pvid" in flags and "untagged" in flags:
                item["mode"] = "access"; item["access_vlan"] = vlan
            else:
                item["mode"] = item["mode"] or "trunk"; item["uplink"] = True
                if str(vlan) not in item["allowed_vlans"]: item["allowed_vlans"].append(str(vlan))
            add_vlan(vlan, f"VLAN {vlan}", line, [item["interface"]]); add_port_evidence(item, line)

        pc_row = re.match(r"^(\d+)\s+(Po\S+)\([^)]*\)\s+(LACP|PAgP|NONE|-)?\s*(.*)$", line, re.I)
        if pc_row:
            name = pc_row.group(2).split("(", 1)[0]
            members = re.findall(rf"({IFACE_TOKEN})\([A-Za-z]+\)", pc_row.group(4))
            port_channels[name] = {"name": name, "protocol": (pc_row.group(3) or "unknown").lower(), "members": members, "evidence": line[:500]}
            for member in members:
                item = port(member); item["port_channel"] = name; item["uplink"] = True; add_port_evidence(item, line)
        slave = re.search(r"^Slave Interface:\s*(%s)" % IFACE_TOKEN, line, re.I)
        if slave:
            aggregate = port_channels.setdefault("bond", {"name": "bond", "protocol": "802.3ad", "members": [], "evidence": line[:500]})
            if slave.group(1) not in aggregate["members"]: aggregate["members"].append(slave.group(1))
            item = port(slave.group(1)); item["port_channel"] = "bond"; item["uplink"] = True; add_port_evidence(item, line)

        stp_row = re.match(r"^(%s)\s+(Root|Desg|Altn|Back|Mstr)\s+(FWD|BLK|LRN|LIS|DIS)\b" % IFACE_TOKEN, line, re.I)
        if stp_row:
            key = (stp_row.group(1), None, stp_row.group(3).upper())
            if key not in seen_stp:
                seen_stp.add(key); spanning_tree.append({"interface": stp_row.group(1), "vlan_id": None, "role": stp_row.group(2).lower(), "state": stp_row.group(3).lower(), "evidence": line[:500]})
                item = port(stp_row.group(1)); item["uplink"] = item["uplink"] or stp_row.group(2).lower() in {"root", "altn"}; add_port_evidence(item, line)

    learned_port_keys = {interface_key(item.get("interface")) for item in mac_table if item.get("interface")}
    normalized_ports = []
    for item in ports.values():
        has_layer2_evidence = bool(
            item.get("mode")
            or item.get("access_vlan") is not None
            or item.get("native_vlan") is not None
            or item.get("allowed_vlans")
            or item.get("port_channel")
            or item.get("status")
            or item.get("poe")
            or item.get("uplink")
            or interface_key(item.get("interface")) in learned_port_keys
        )
        if not has_layer2_evidence:
            continue
        normalized_ports.append({**item, "evidence": " | ".join(item["evidence"])[:1000]})
    return {
        "mac_table": mac_table[:5000],
        "vlans": sorted(vlans.values(), key=lambda item: (item["vlan_id"] is None, item["vlan_id"] or 0, item["name"].casefold()))[:1000],
        "ports": sorted(normalized_ports, key=lambda item: item["interface"].casefold())[:2000],
        "port_channels": sorted(port_channels.values(), key=lambda item: item["name"].casefold())[:500],
        "spanning_tree": spanning_tree[:2000],
        "command_results": parse_command_results(text, commands),
    }


def merge_switch_interfaces(interfaces: list[dict], switching: dict) -> list[dict]:
    """Merge Layer-2 port evidence into interface records without losing L3 data."""
    merged = [dict(item) for item in interfaces]
    by_name = {str(item.get("name") or ""): item for item in merged if item.get("name")}
    for port in switching.get("ports") or []:
        name = str(port.get("interface") or "")
        if not name:
            continue
        item = by_name.get(name)
        if item is None:
            item = {"name": name, "address": None}
            by_name[name] = item
            merged.append(item)
        item["switching"] = {key: value for key, value in port.items() if key != "interface"}
    return merged
