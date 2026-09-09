from __future__ import annotations

import hashlib
import ipaddress
import json
from collections import defaultdict
from datetime import datetime, timezone
from typing import Iterable


TERMINAL_STATES = {
    "completed",
    "completed_without_nmap",
    "failed",
    "cancelled",
    "timed_out",
}


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
    return {
        "group_id": run_group_key(first),
        "run_ids": [item["run_id"] for item in manifests],
        "display_name": first.get("display_name") or first.get("name") or "Scan",
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
    return coverage


def coverage_warnings(before: dict, after: dict) -> list[str]:
    labels = {
        "protocols": "Protocols differ",
        "tcp_scope": "TCP port scope differs",
        "tcp_ports": "Custom TCP ports differ",
        "udp_scope": "UDP port scope differs",
        "udp_ports": "Custom UDP ports differ",
        "service_detection": "Service/version detection differs",
        "os_detection": "OS detection differs",
        "discovery_mode": "Host discovery method differs",
        "traceroute": "Traceroute collection differs",
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
    return warnings


def merge_analyses(analyses: Iterable[dict]) -> dict:
    hosts: dict[str, dict] = {}
    for analysis in analyses:
        for host in analysis.get("hosts", []) or []:
            key = canonical_host_key(host)
            if key:
                hosts[key] = host
    values = [hosts[key] for key in sorted(hosts)]
    return {
        "hosts": values,
        "host_count": len(values),
        "up_count": sum(1 for host in values if host.get("state") == "up"),
        "mac_count": sum(1 for host in values if host.get("mac")),
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


def compare_analyses(before_analysis: dict, after_analysis: dict) -> dict:
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
    added_keys = sorted(set(after) - set(before))
    removed_keys = sorted(set(before) - set(after))
    changed = []
    for key in sorted(set(before) & set(after)):
        old_host, new_host = before[key], after[key]
        old_ports = {_port_key(port): port for port in old_host.get("ports", []) or []}
        new_ports = {_port_key(port): port for port in new_host.get("ports", []) or []}
        added_ports = [_service_evidence(new_ports[item]) for item in sorted(set(new_ports) - set(old_ports))]
        removed_ports = [_service_evidence(old_ports[item]) for item in sorted(set(old_ports) - set(new_ports))]
        service_changes = []
        for port_key in sorted(set(old_ports) & set(new_ports)):
            old_service = _service_evidence(old_ports[port_key])
            new_service = _service_evidence(new_ports[port_key])
            if old_service != new_service:
                service_changes.append({
                    "protocol": port_key[0],
                    "port": port_key[1],
                    "before": old_service,
                    "after": new_service,
                })
        identity_fields = (
            "hostname", "state", "mac", "vendor", "os", "os_group",
            "os_family", "os_generation", "device_type",
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
                "identity_changes": identity_changes,
                "route_change": route_change,
            })

    def public_host(host: dict, key: str) -> dict:
        return {
            "key": key,
            "ip": host.get("ip"),
            "hostname": host.get("hostname") or host.get("name"),
            "mac": host.get("mac"),
            "ports": [_service_evidence(port) for port in host.get("ports", []) or []],
        }

    return {
        "summary": {
            "hosts_added": len(added_keys),
            "hosts_removed": len(removed_keys),
            "hosts_changed": len(changed),
            "ports_added": sum(len(host["added_ports"]) for host in changed),
            "ports_removed": sum(len(host["removed_ports"]) for host in changed),
            "service_changes": sum(len(host["service_changes"]) for host in changed),
            "identity_changes": sum(len(host["identity_changes"]) for host in changed),
            "route_changes": sum(1 for host in changed if host["route_change"]),
            "before_hosts": len(before),
            "after_hosts": len(after),
        },
        "hosts_added": [public_host(after[key], key) for key in added_keys],
        "hosts_removed": [public_host(before[key], key) for key in removed_keys],
        "hosts_changed": changed,
    }
