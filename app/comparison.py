from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Iterable

from app.ip_sort import ip_sort_key


TERMINAL_STATES = {
    "completed",
    "completed_without_nmap",
    "failed",
    "cancelled",
    "timed_out",
}

_CHUNK_NAME_RE = re.compile(
    r"(?:[ _])Chunk(?:[ _])\d+(?:[ _])of(?:[ _])\d+",
    re.IGNORECASE,
)


def _entries(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item).strip() for item in value if str(item).strip()]


def _ipv4_networks(entries: Iterable[str]) -> list[ipaddress.IPv4Network]:
    result: list[ipaddress.IPv4Network] = []
    for entry in entries:
        try:
            network = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            continue
        if network.version == 4:
            result.append(network)
    return list(ipaddress.collapse_addresses(result))


def _subtract_networks(
    targets: Iterable[ipaddress.IPv4Network],
    exclusions: Iterable[ipaddress.IPv4Network],
) -> list[ipaddress.IPv4Network]:
    remaining = list(ipaddress.collapse_addresses(targets))
    for exclusion in ipaddress.collapse_addresses(exclusions):
        updated: list[ipaddress.IPv4Network] = []
        for target in remaining:
            if not target.overlaps(exclusion):
                updated.append(target)
            elif target.subnet_of(exclusion):
                continue
            elif exclusion.subnet_of(target):
                updated.extend(target.address_exclude(exclusion))
        remaining = list(ipaddress.collapse_addresses(updated))
    return remaining


def run_group_key(manifest: dict) -> str:
    batch_id = str(manifest.get("schedule_batch_id") or "").strip()
    if batch_id:
        return f"schedule-batch:{batch_id}"
    return f"run:{manifest.get('run_id', '')}"


def group_run_manifests(manifests: Iterable[dict]) -> list[list[dict]]:
    groups: defaultdict[str, list[dict]] = defaultdict(list)
    for manifest in manifests:
        if manifest.get("run_id"):
            groups[run_group_key(manifest)].append(manifest)
    return [
        sorted(group, key=lambda item: (item.get("chunk_number") or 0, item.get("created_at") or ""))
        for group in groups.values()
    ]


def effective_scope(manifests: Iterable[dict]) -> dict:
    target_entries: list[str] = []
    exclusion_entries: list[str] = []
    for manifest in manifests:
        coverage = manifest.get("coverage") or {}
        target_entries.extend(_entries(coverage.get("targets") or manifest.get("targets")))
        exclusion_entries.extend(_entries(coverage.get("no_strike") or manifest.get("no_strike")))
    targets = _ipv4_networks(target_entries)
    exclusions = _ipv4_networks(exclusion_entries)
    effective = _subtract_networks(targets, exclusions)
    collapsed = [str(network) for network in effective]
    payload = json.dumps(collapsed, separators=(",", ":"), sort_keys=True)
    return {
        "fingerprint": hashlib.sha256(payload.encode("utf-8")).hexdigest(),
        "targets": collapsed,
        "address_count": sum(network.num_addresses for network in effective),
        "excluded_address_count": (
            sum(network.num_addresses for network in targets)
            - sum(network.num_addresses for network in effective)
        ),
    }


def _timestamp(manifests: Iterable[dict]) -> datetime:
    values = []
    for manifest in manifests:
        raw = manifest.get("completed_at") or manifest.get("created_at")
        if not raw:
            continue
        try:
            parsed = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
        except ValueError:
            continue
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        values.append(parsed.astimezone(timezone.utc))
    return max(values, default=datetime.min.replace(tzinfo=timezone.utc))


def describe_run_group(manifests: list[dict]) -> dict:
    first = manifests[0]
    display_name = str(first.get("display_name") or first.get("name") or "Scan")
    display_name = _CHUNK_NAME_RE.sub("", display_name)
    return {
        "group_id": run_group_key(first),
        "run_ids": [item["run_id"] for item in manifests],
        "display_name": display_name,
        "schedule_id": first.get("schedule_id"),
        "schedule_batch_id": first.get("schedule_batch_id"),
        "created_at": min((item.get("created_at") or "" for item in manifests), default=""),
        "completed_at": max((item.get("completed_at") or "" for item in manifests), default=""),
        "chunk_count": len(manifests),
        "scope": effective_scope(manifests),
    }


def group_is_finished(manifests: list[dict]) -> bool:
    return bool(manifests) and all(item.get("status") in TERMINAL_STATES for item in manifests)


def group_is_comparable(manifests: list[dict]) -> bool:
    return bool(manifests) and all(
        item.get("status") == "completed"
        and item.get("_comparison_xml_available", True)
        for item in manifests
    )


def select_same_scope_baseline(current_run_id: str, manifests: list[dict]) -> dict:
    groups = group_run_manifests(manifests)
    current_group = next(
        (group for group in groups if any(item.get("run_id") == current_run_id for item in group)),
        None,
    )
    if current_group is None:
        raise KeyError("Scan run not found")
    current = describe_run_group(current_group)
    if not group_is_finished(current_group):
        return {"status": "current_running", "current": current, "baseline": None}
    if not group_is_comparable(current_group):
        return {"status": "current_incomplete", "current": current, "baseline": None}

    current_fingerprint = current["scope"]["fingerprint"]
    current_time = _timestamp(current_group)
    candidates = []
    for group in groups:
        if group is current_group or not group_is_comparable(group):
            continue
        group_time = _timestamp(group)
        if group_time >= current_time:
            continue
        description = describe_run_group(group)
        if description["scope"]["fingerprint"] == current_fingerprint:
            candidates.append((group_time, group, description))
    if not candidates:
        return {"status": "no_baseline", "current": current, "baseline": None}
    _, baseline_group, baseline = max(candidates, key=lambda item: item[0])
    return {
        "status": "baseline_found",
        "current": current,
        "baseline": baseline,
        "current_manifests": current_group,
        "baseline_manifests": baseline_group,
    }


def representative_coverage(manifests: list[dict]) -> dict:
    coverage = dict((manifests[0].get("coverage") or {}) if manifests else {})
    coverage["profile_id"] = manifests[0].get("profile_id") if manifests else None
    coverage["profile_version"] = manifests[0].get("profile_version") if manifests else None
    coverage["interface"] = manifests[0].get("interface") if manifests else None
    if manifests:
        scope = effective_scope(manifests)
        coverage["effective_targets"] = scope["targets"]
        coverage["effective_address_count"] = scope["address_count"]
        coverage["excluded_address_count"] = scope["excluded_address_count"]
    return coverage


def _protocol_port_coverage(coverage: dict, protocol: str) -> object:
    scan_services = sorted({
        str(item.get("services") or "")
        for item in coverage.get("scan_types", []) or []
        if str(item.get("protocol") or "").upper() == protocol and item.get("services") is not None
    })
    if scan_services:
        return scan_services
    prefix = protocol.lower()
    scope = coverage.get(f"{prefix}_scope")
    ports = coverage.get(f"{prefix}_ports")
    return {"scope": scope, "ports": ports} if scope is not None or ports is not None else None


def coverage_warnings(before: dict, after: dict) -> list[str]:
    labels = {
        "effective_targets": "Effective targets differ",
        "target_arguments": "Scan targets differ",
        "protocols": "Protocols differ",
        "service_detection": "Service/version detection differs",
        "os_detection": "OS detection differs",
        "discovery_mode": "Host discovery method differs",
        "traceroute": "Traceroute collection differs",
        "timing": "Nmap timing differs",
        "dns_resolution_disabled": "DNS resolution behavior differs",
        "profile_id": "Saved profile differs",
        "profile_version": "Profile version differs",
        "interface": "Analyzer interface differs",
    }
    warnings = []
    for field, label in labels.items():
        old = before.get(field)
        new = after.get(field)
        if field == "protocols":
            old = sorted(old or [])
            new = sorted(new or [])
        if old != new:
            warnings.append(f"{label}: {old!r} -> {new!r}")
    for protocol in ("TCP", "UDP"):
        old = _protocol_port_coverage(before, protocol)
        new = _protocol_port_coverage(after, protocol)
        if old != new and (old is not None or new is not None):
            prefix = protocol.lower()
            label = (
                f"{protocol} port scope differs"
                if before.get(f"{prefix}_scope") is not None
                or after.get(f"{prefix}_scope") is not None
                else f"{protocol} port coverage differs"
            )
            warnings.append(f"{label}: {old!r} -> {new!r}")
    return warnings


def merge_analyses(analyses: Iterable[dict]) -> dict:
    analysis_list = list(analyses)
    if not analysis_list:
        return {
            "hosts": [], "host_count": 0, "up_count": 0, "mac_count": 0,
            "peer_groups": [], "os_groups": [], "rare_ports": [],
        }
    if len(analysis_list) == 1:
        return analysis_list[0]

    hosts: dict[str, dict] = {}
    for analysis in analysis_list:
        for host in analysis.get("hosts", []) or []:
            key = canonical_host_key(host)
            if key:
                if key not in hosts:
                    hosts[key] = dict(host)
                    continue
                merged = hosts[key]
                for field in ("ports", "observed_ports"):
                    values = {_port_key(item): item for item in merged.get(field, []) or []}
                    values.update({_port_key(item): item for item in host.get(field, []) or []})
                    merged[field] = [values[item] for item in sorted(values)]
                for field, value in host.items():
                    if field not in {"ports", "observed_ports"} and value not in (None, "", [], {}):
                        merged[field] = value
    values = sorted(hosts.values(), key=lambda item: ip_sort_key(item.get("ip") or item.get("hostname")))
    summary = _summarize_hosts(values)
    first, last = analysis_list[0], analysis_list[-1]
    return {
        **first,
        "started": first.get("started") or "",
        "finished": last.get("finished") or "",
        "reported_total": sum(int(item.get("reported_total") or 0) for item in analysis_list),
        "coverage": _merge_xml_coverage(analysis_list),
        "warnings": list(dict.fromkeys(
            warning
            for item in analysis_list
            for warning in (item.get("warnings") or [])
        )),
        "hosts": values,
        **summary,
    }


def _merge_xml_coverage(analyses: list[dict]) -> dict:
    coverages = [item.get("coverage") or {} for item in analyses]
    merged = dict(coverages[0]) if coverages else {}
    merged["protocols"] = sorted({
        str(protocol)
        for coverage in coverages
        for protocol in (coverage.get("protocols") or [])
        if protocol
    })
    scan_types = []
    seen_scan_types = set()
    for coverage in coverages:
        for scan_type in coverage.get("scan_types", []) or []:
            key = (
                scan_type.get("type"), scan_type.get("protocol"),
                scan_type.get("services"), scan_type.get("service_count"),
            )
            if key not in seen_scan_types:
                scan_types.append(scan_type)
                seen_scan_types.add(key)
    merged["scan_types"] = scan_types
    merged["target_arguments"] = sorted({
        str(target)
        for coverage in coverages
        for target in (coverage.get("target_arguments") or [])
        if target
    })
    commands = list(dict.fromkeys(
        str(coverage.get("command"))
        for coverage in coverages
        if coverage.get("command")
    ))
    merged["command"] = "\n".join(commands)
    for field in ("dns_resolution_disabled", "traceroute"):
        values = [coverage.get(field) for coverage in coverages]
        merged[field] = all(values) if values else False
    timings = {coverage.get("timing") for coverage in coverages}
    merged["timing"] = timings.pop() if len(timings) == 1 else "mixed"
    return merged


def _summarize_hosts(hosts: list[dict]) -> dict:
    up_hosts = [host for host in hosts if host.get("state") == "up"]
    peer_groups: defaultdict[str, list[str]] = defaultdict(list)
    grouped_hosts: defaultdict[str, list[dict]] = defaultdict(list)
    port_frequency: Counter[tuple[str, int]] = Counter()
    for host in hosts:
        open_ports = host.get("ports", []) or []
        signature = ",".join(
            f"{port.get('port')}/{port.get('protocol')}"
            for port in sorted(open_ports, key=_port_key)
        ) or "no-open-ports"
        if host.get("ip"):
            peer_groups[signature].append(host["ip"])
        if host.get("state") == "up":
            grouped_hosts[str(host.get("os_group") or "Unclassified")].append(host)
            port_frequency.update({_port_key(port) for port in open_ports})

    os_groups = []
    for group_name, members in sorted(grouped_hosts.items()):
        port_members: defaultdict[tuple[str, int], list[dict]] = defaultdict(list)
        port_examples: dict[tuple[str, int], dict] = {}
        for host in members:
            for port in host.get("ports", []) or []:
                key = _port_key(port)
                port_examples.setdefault(key, port)
                if host not in port_members[key]:
                    port_members[key].append(host)
        outlier_limit = max(1, math.ceil(len(members) * 0.20))
        outlier_keys = {
            key for key, affected in port_members.items()
            if len(members) >= 2 and len(affected) <= outlier_limit
        }
        for host in members:
            for port in host.get("ports", []) or []:
                key = _port_key(port)
                port["outlier"] = key in outlier_keys
                port["group_host_count"] = len(members)
                port["group_port_host_count"] = len(port_members[key])
        os_groups.append({
            "name": group_name,
            "host_count": len(members),
            "outlier_limit": outlier_limit,
            "outlying_ports": [{
                "port": key[1],
                "protocol": key[0],
                "service": port_examples[key].get("service", "unknown"),
                "product": port_examples[key].get("product", ""),
                "host_count": len(port_members[key]),
                "group_host_count": len(members),
                "prevalence_percent": round((len(port_members[key]) / len(members)) * 100, 1),
                "hosts": [host.get("ip") for host in port_members[key] if host.get("ip")],
            } for key in sorted(outlier_keys, key=lambda value: (value[1], value[0]))],
        })

    rare_limit = max(1, len(up_hosts) // 10)
    return {
        "host_count": len(hosts),
        "up_count": len(up_hosts),
        "mac_count": sum(1 for host in hosts if host.get("mac")),
        "peer_groups": [
            {"open_ports": signature, "hosts": members}
            for signature, members in sorted(peer_groups.items())
        ],
        "os_groups": os_groups,
        "rare_ports": [
            {"protocol": key[0], "port": key[1], "host_count": count}
            for key, count in sorted(port_frequency.items(), key=lambda item: (item[0][1], item[0][0]))
            if count <= rare_limit
        ],
    }


def canonical_host_key(host: dict) -> str:
    raw_ip = str(host.get("ip") or "").strip()
    if raw_ip:
        try:
            return str(ipaddress.ip_address(raw_ip))
        except ValueError:
            pass
    return str(host.get("hostname") or host.get("name") or "").strip().lower()


def _port_key(port: dict) -> tuple[str, int]:
    return str(port.get("protocol") or "").lower(), int(port.get("port") or 0)


def _service_evidence(port: dict) -> dict:
    return {
        "protocol": port.get("protocol"),
        "port": port.get("port"),
        "state": port.get("state"),
        "reason": port.get("reason"),
        "service": port.get("service"),
        "product": port.get("product"),
        "version": port.get("version"),
    }


def _port_inventory(host: dict) -> dict[tuple[str, int], dict]:
    values = host.get("observed_ports")
    if not isinstance(values, list) or not values:
        values = host.get("ports", []) or []
    return {_port_key(port): port for port in values}


def _trace_evidence(host: dict) -> dict | None:
    trace = host.get("trace")
    if not trace:
        return None
    return {
        "port": trace.get("port"),
        "protocol": trace.get("protocol"),
        "hops": [
            {
                "ttl": hop.get("ttl"),
                "ip": hop.get("ip"),
                "hostname": hop.get("hostname"),
            }
            for hop in trace.get("hops", []) or []
        ],
    }


def compare_analyses(
    before_analysis: dict,
    after_analysis: dict,
    *,
    before_evidence: dict | None = None,
    after_evidence: dict | None = None,
) -> dict:
    before = {
        canonical_host_key(host): host
        for host in before_analysis.get("hosts", []) or []
        if canonical_host_key(host)
    }
    after = {
        canonical_host_key(host): host
        for host in after_analysis.get("hosts", []) or []
        if canonical_host_key(host)
    }
    added_keys = sorted(set(after) - set(before), key=ip_sort_key)
    removed_keys = sorted(set(before) - set(after), key=ip_sort_key)
    changed = []
    for key in sorted(set(before) & set(after), key=ip_sort_key):
        old_host, new_host = before[key], after[key]
        old_ports = _port_inventory(old_host)
        new_ports = _port_inventory(new_host)
        added_ports = [_service_evidence(new_ports[item]) for item in sorted(set(new_ports) - set(old_ports))]
        removed_ports = [_service_evidence(old_ports[item]) for item in sorted(set(old_ports) - set(new_ports))]
        service_changes = []
        port_state_changes = []
        for port_key in sorted(set(old_ports) & set(new_ports)):
            old_service = _service_evidence(old_ports[port_key])
            new_service = _service_evidence(new_ports[port_key])
            if old_service != new_service:
                changed_fields = [
                    field for field in ("state", "reason", "service", "product", "version")
                    if old_service.get(field) != new_service.get(field)
                ]
                service_changes.append({
                    "protocol": port_key[0],
                    "port": port_key[1],
                    "before": old_service,
                    "after": new_service,
                    "changed_fields": changed_fields,
                })
                if "state" in changed_fields:
                    port_state_changes.append({
                        "protocol": port_key[0],
                        "port": port_key[1],
                        "before": old_service.get("state"),
                        "after": new_service.get("state"),
                        "reason_before": old_service.get("reason"),
                        "reason_after": new_service.get("reason"),
                    })
        identity_fields = (
            "hostname", "hostnames", "state", "mac", "vendor", "os", "os_group",
            "os_vendor", "os_family", "os_generation", "device_type",
        )
        identity_changes = {
            field: {"before": old_host.get(field), "after": new_host.get(field)}
            for field in identity_fields
            if old_host.get(field) != new_host.get(field)
        }
        old_trace, new_trace = _trace_evidence(old_host), _trace_evidence(new_host)
        route_change = (
            {"before": old_trace, "after": new_trace}
            if old_trace != new_trace else None
        )
        if added_ports or removed_ports or service_changes or identity_changes or route_change:
            changed.append({
                "key": key,
                "ip": new_host.get("ip") or old_host.get("ip"),
                "hostname": new_host.get("hostname") or old_host.get("hostname"),
                "added_ports": added_ports,
                "removed_ports": removed_ports,
                "service_changes": service_changes,
                "port_state_changes": port_state_changes,
                "identity_changes": identity_changes,
                "route_change": route_change,
                "evidence": {"before": before_evidence, "after": after_evidence},
            })

    def public_host(host: dict, key: str) -> dict:
        return {
            "key": key,
            "ip": host.get("ip"),
            "hostname": host.get("hostname") or host.get("name"),
            "mac": host.get("mac"),
            "vendor": host.get("vendor"),
            "os": host.get("os"),
            "state": host.get("state"),
            "ports": [_service_evidence(port) for port in _port_inventory(host).values()],
            "evidence": after_evidence if key in after else before_evidence,
        }

    return {
        "summary": {
            "hosts_added": len(added_keys),
            "hosts_removed": len(removed_keys),
            "hosts_changed": len(changed),
            "ports_added": sum(len(host["added_ports"]) for host in changed),
            "ports_removed": sum(len(host["removed_ports"]) for host in changed),
            "service_changes": sum(len(host["service_changes"]) for host in changed),
            "port_state_changes": sum(len(host["port_state_changes"]) for host in changed),
            "identity_changes": sum(len(host["identity_changes"]) for host in changed),
            "route_changes": sum(1 for host in changed if host["route_change"]),
            "before_hosts": len(before),
            "after_hosts": len(after),
        },
        "hosts_added": [public_host(after[key], key) for key in added_keys],
        "hosts_removed": [public_host(before[key], key) for key in removed_keys],
        "hosts_changed": changed,
        "evidence": {"before": before_evidence, "after": after_evidence},
    }
