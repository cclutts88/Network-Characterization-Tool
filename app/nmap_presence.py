from __future__ import annotations

import xml.etree.ElementTree as ET


DIRECT_RESPONSE_PORT_STATES = {"open", "closed", "unfiltered"}
DIRECT_RESPONSE_REASONS = {
    "arp-response",
    "echo-reply",
    "localhost-response",
    "reset",
    "syn-ack",
    "tcp-response",
    "udp-response",
}


def nmap_host_presence(host: ET.Element) -> tuple[str, str]:
    """Classify whether an Nmap host record proves that the target responded.

    Nmap's ``-Pn`` mode writes ``state=up reason=user-set`` before probing ports.
    That state means "scan this target", not "this target answered".  A MAC
    observation or a direct port response upgrades that target to confirmed.
    """

    status = host.find("status")
    if status is None:
        return "confirmed", "Nmap emitted a host record without an assumed-up marker"
    if status.get("state", "unknown") != "up":
        return "not_up", status.get("reason", "")

    reason = status.get("reason", "").strip().lower()
    if reason != "user-set":
        return "confirmed", reason or "Nmap discovery response"

    if any(
        address.get("addrtype") == "mac" and address.get("addr")
        for address in host.findall("address")
    ):
        return "confirmed", "MAC address response"

    for port in host.findall("./ports/port"):
        state = port.find("state")
        if state is None:
            continue
        port_state = state.get("state", "").strip().lower()
        port_reason = state.get("reason", "").strip().lower()
        if (
            port_state in DIRECT_RESPONSE_PORT_STATES
            or port_reason in DIRECT_RESPONSE_REASONS
        ):
            return "confirmed", f"port response ({port_state or port_reason})"

    return "assumed", "Nmap -Pn user-set state without direct response evidence"


def nmap_presence_counts(root: ET.Element) -> dict[str, int]:
    counts = {"reported_up": 0, "confirmed": 0, "assumed": 0}
    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.get("state", "unknown") != "up":
            continue
        counts["reported_up"] += 1
        presence, _detail = nmap_host_presence(host)
        if presence == "confirmed":
            counts["confirmed"] += 1
        elif presence == "assumed":
            counts["assumed"] += 1
    return counts
