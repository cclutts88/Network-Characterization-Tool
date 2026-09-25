from __future__ import annotations

from typing import Iterable


UNKNOWN_OS_VALUES = {
    "",
    "unknown",
    "unknown os",
    "unknown server",
    "unclassified",
    "none",
    "n/a",
}

NETWORK_ROLES = (
    "router",
    "firewall",
    "switch",
    "access point",
    "wireless access point",
    "network appliance",
    "security gateway",
)

NETWORK_VENDORS = (
    "arista",
    "cisco",
    "fortinet",
    "juniper",
    "mikrotik",
    "netgear",
    "palo alto",
    "pfsense",
    "opnsense",
    "ubiquiti",
    "unifi",
    "vyos",
)


def _clean(value: object) -> str:
    return str(value or "").strip()


def _known(value: object) -> bool:
    text = _clean(value).lower()
    return bool(text) and text not in UNKNOWN_OS_VALUES and not text.startswith("unknown ")


def authoritative_os(record: dict) -> str | None:
    """Return direct scanner/analyst OS evidence, never an inferred value."""
    override = record.get("analyst_os_override")
    if isinstance(override, dict) and _known(override.get("os_name")):
        return _clean(override["os_name"])
    if _known(record.get("effective_os")) and record.get("os_source") == "analyst":
        return _clean(record["effective_os"])
    if _known(record.get("os")):
        return _clean(record["os"])
    group = record.get("os_group")
    if isinstance(group, str) and _known(group):
        return group.strip()
    if isinstance(group, dict):
        pieces = [
            group.get("vendor") or record.get("os_vendor"),
            group.get("family") or record.get("os_family"),
            group.get("generation") or record.get("os_generation"),
        ]
        label = " ".join(_clean(piece) for piece in pieces if _known(piece))
        if label:
            return label
    return None


def _service_records(record: dict) -> list[dict]:
    values = record.get("ports") or record.get("services") or []
    records = []
    seen = set()
    for value in values:
        if not isinstance(value, dict):
            continue
        signature = tuple(
            _clean(value.get(field)).lower()
            for field in ("port", "protocol", "service", "product", "version")
        )
        if signature in seen:
            continue
        seen.add(signature)
        records.append(value)
    return records


def _service_description(item: dict) -> str:
    port = _clean(item.get("port"))
    protocol = _clean(item.get("protocol")).lower()
    transport = f"{port}/{protocol}" if port and protocol else port or protocol
    fingerprint = " ".join(
        value for value in (
            _clean(item.get("service")),
            _clean(item.get("product")),
            _clean(item.get("version")),
        ) if value
    )
    return " · ".join(value for value in (transport, fingerprint) if value)


def _append(evidence: list[str], value: str) -> None:
    if value and value not in evidence:
        evidence.append(value)


def _confidence(score: int) -> str:
    if score >= 7:
        return "high"
    if score >= 4:
        return "medium"
    return "low"


def _candidate(family: str, score: int, evidence: Iterable[str]) -> dict:
    reasons = list(dict.fromkeys(value for value in evidence if value))[:4]
    return {
        "family": family,
        "display": f"{family} (inferred)",
        "confidence": _confidence(score),
        "evidence": reasons,
        "source": "service_and_device_evidence",
    }


def infer_os_identity(record: dict) -> dict | None:
    """Conservatively infer an OS family without replacing direct OS evidence."""
    if authoritative_os(record):
        return None

    services = _service_records(record)
    role_text = " ".join(
        _clean(record.get(field)).lower() for field in ("role", "device_type")
    )
    vendor_text = _clean(record.get("vendor")).lower()
    candidates: list[tuple[int, int, dict]] = []

    network_evidence: list[str] = []
    network_score = 0
    role = next((value for value in NETWORK_ROLES if value in role_text), None)
    if role:
        network_score += 8
        _append(network_evidence, f"Device role identifies a {role}")
    network_vendor = next((value for value in NETWORK_VENDORS if value in vendor_text), None)
    service_blob = " ".join(
        " ".join(
            _clean(item.get(field)).lower()
            for field in ("service", "product", "version")
        )
        for item in services
    )
    if network_vendor and any(marker in service_blob for marker in ("dropbear", "snmp", "routeros", "junos", "ios")):
        network_score += 5
        _append(network_evidence, f"{_clean(record.get('vendor'))} vendor and appliance service fingerprint")
    if network_score:
        candidates.append((network_score, 4, _candidate("Network appliance", network_score, network_evidence)))

    windows_evidence: list[str] = []
    windows_score = 0
    windows_ports: set[int] = set()
    for item in services:
        text = " ".join(_clean(item.get(field)).lower() for field in ("service", "product", "version"))
        try:
            port = int(item.get("port") or 0)
        except (TypeError, ValueError):
            port = 0
        if port in {135, 137, 138, 139, 445, 3389, 5985, 5986}:
            windows_ports.add(port)
        if "microsoft windows" in text or "windows rpc" in text:
            windows_score += 6
            _append(windows_evidence, f"Microsoft Windows fingerprint: {_service_description(item)}")
        elif any(marker in text for marker in ("ms-wbt-server", "winrm", "microsoft-ds")):
            windows_score += 3
            _append(windows_evidence, f"Windows-oriented service: {_service_description(item)}")
        elif any(marker in text for marker in ("msrpc", "netbios-ssn")):
            windows_score += 2
            _append(windows_evidence, f"Windows-compatible service: {_service_description(item)}")
    if {135, 139, 445}.issubset(windows_ports):
        windows_score += 4
        _append(windows_evidence, "RPC, NetBIOS, and SMB ports are exposed together")
    elif 445 in windows_ports and ({135, 139} & windows_ports):
        windows_score += 2
        _append(windows_evidence, "SMB is exposed with RPC or NetBIOS")
    if windows_score >= 3:
        candidates.append((windows_score, 3, _candidate("Windows", windows_score, windows_evidence)))

    apple_evidence: list[str] = []
    apple_score = 0
    for item in services:
        text = " ".join(_clean(item.get(field)).lower() for field in ("service", "product", "version"))
        if any(marker in text for marker in ("mac os", "macos", "darwin")):
            apple_score += 7
            _append(apple_evidence, f"Apple OS fingerprint: {_service_description(item)}")
        elif "apple" in text or "afp" in text:
            apple_score += 4
            _append(apple_evidence, f"Apple service fingerprint: {_service_description(item)}")
    if apple_score >= 4:
        candidates.append((apple_score, 2, _candidate("Apple platform", apple_score, apple_evidence)))

    linux_evidence: list[str] = []
    linux_score = 0
    unix_evidence: list[str] = []
    unix_score = 0
    unix_services: set[str] = set()
    for item in services:
        text = " ".join(_clean(item.get(field)).lower() for field in ("service", "product", "version"))
        service = _clean(item.get("service")).lower()
        if any(marker in text for marker in ("linux", "ubuntu", "debian", "red hat", "rhel", "centos", "fedora", "suse", "alpine")):
            linux_score += 7
            _append(linux_evidence, f"Linux fingerprint: {_service_description(item)}")
        elif any(marker in text for marker in ("dropbear", "busybox")):
            linux_score += 4
            _append(linux_evidence, f"Embedded Linux-oriented fingerprint: {_service_description(item)}")
        if service in {"nfs", "nfs_acl", "rpcbind", "mountd"}:
            unix_services.add(service)
            unix_score += 2
            _append(unix_evidence, f"Unix-oriented service: {_service_description(item)}")
    if linux_score >= 4:
        candidates.append((linux_score, 1, _candidate("Linux / Unix-like", linux_score, linux_evidence)))
    if len(unix_services) >= 2:
        unix_score += 2
        _append(unix_evidence, "Multiple Unix file-service protocols agree")
    if unix_score >= 4:
        candidates.append((unix_score, 0, _candidate("Unix-like", unix_score, unix_evidence)))

    if not candidates:
        return None
    return max(candidates, key=lambda item: (item[0], item[1]))[2]


def os_display(record: dict) -> str:
    direct = authoritative_os(record)
    if direct:
        return direct
    inference = record.get("os_inference")
    if not isinstance(inference, dict):
        inference = infer_os_identity(record)
    review = record.get("os_inference_review")
    if (
        isinstance(review, dict)
        and review.get("current")
        and review.get("status") == "dismissed"
    ):
        return "Unclassified"
    return _clean((inference or {}).get("display")) or "Unclassified"
