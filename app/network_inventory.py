from __future__ import annotations

import math
import re
from copy import deepcopy
from collections import defaultdict
from typing import Any


NETWORK_INVENTORY_SORTS = {
    "ip", "port", "service", "mac", "hostname", "os", "last",
}


class StaleNetworkEvidenceError(ValueError):
    """The requested page belongs to an older exact-source network model."""


def _natural_key(value: Any) -> tuple:
    text = str(value or "")
    return tuple(
        (0, int(part)) if part.isdigit() else (1, part.casefold())
        for part in re.split(r"(\d+)", text)
        if part
    )


def _port_number(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 65536


def network_inventory_services(host: dict) -> list[dict]:
    unique: dict[tuple, dict] = {}
    for item in host.get("services") or []:
        key = (
            item.get("port"), item.get("protocol"), item.get("service"),
            item.get("product"), item.get("version"),
        )
        unique.setdefault(key, item)
    return sorted(
        unique.values(),
        key=lambda item: (
            _port_number(item.get("port")),
            _natural_key(item.get("service")),
            _natural_key(item.get("protocol")),
        ),
    )


def network_inventory_search_text(host: dict) -> str:
    analyst_hostname = host.get("analyst_hostname") or {}
    values = [
        host.get("ip"), host.get("hostname"), analyst_hostname.get("hostname"),
        *(host.get("hostname_aliases") or []), host.get("mac"), host.get("vendor"),
        host.get("os"), host.get("os_display"), host.get("effective_os"),
        host.get("os_group"), host.get("device_type"), host.get("subnet"),
        *(host.get("categories") or []),
    ]
    for item in network_inventory_services(host):
        values.extend([
            item.get("port"), item.get("protocol"), item.get("service"),
            item.get("product"), item.get("version"),
        ])
    return " ".join(str(value) for value in values if value not in (None, "")).casefold()


def _host_sort_key(host: dict, sort: str) -> tuple:
    ip_key = _natural_key(host.get("ip") or host.get("hostname"))
    services = network_inventory_services(host)
    if sort == "port":
        primary = (0, _port_number(services[0].get("port"))) if services else (1, 65536)
    elif sort == "service":
        names = sorted(
            (item.get("service") for item in services if item.get("service")),
            key=_natural_key,
        )
        primary = (0, _natural_key(names[0])) if names else (1, ())
    elif sort == "mac":
        primary = (0, _natural_key(host.get("mac"))) if host.get("mac") else (1, ())
    elif sort == "hostname":
        primary = (
            (0, _natural_key(host.get("hostname")))
            if host.get("hostname") else (1, ())
        )
    elif sort == "os":
        value = (
            host.get("os_display") or host.get("effective_os") or host.get("os")
            or host.get("os_group")
        )
        primary = (0, _natural_key(value)) if value else (1, ())
    else:
        primary = (0, ip_key)
    return primary, ip_key, _natural_key(host.get("host_key"))


def _filtered_hosts(
    model: dict, *, search: str = "", subnet: str = "", sort: str = "ip",
) -> list[dict]:
    if sort not in NETWORK_INVENTORY_SORTS:
        raise ValueError(f"Unsupported network inventory sort: {sort}")
    term = search.strip().casefold()
    selected_subnet = subnet.strip()
    hosts = [
        host for host in (model.get("hosts") or [])
        if (
            not selected_subnet
            or str(host.get("subnet") or "Unmapped") == selected_subnet
        ) and (not term or term in network_inventory_search_text(host))
    ]
    if sort == "last":
        hosts.sort(key=lambda host: (
            _natural_key(host.get("ip") or host.get("hostname")),
            _natural_key(host.get("host_key")),
        ))
        hosts.sort(
            key=lambda host: str(host.get("last_observed") or ""), reverse=True
        )
    else:
        hosts.sort(key=lambda host: _host_sort_key(host, sort))
    return hosts


def _verify_revision(model: dict, expected_revision: str | None) -> str:
    revision = str(model.get("source_revision") or "")
    if not revision:
        raise ValueError("Current Network source revision is unavailable")
    if expected_revision and expected_revision != revision:
        raise StaleNetworkEvidenceError(
            "Current Network evidence changed while these pages were open"
        )
    return revision


def page_network_inventory(
    model: dict,
    *,
    limit: int,
    offset: int = 0,
    search: str = "",
    subnet: str = "",
    sort: str = "ip",
    expected_revision: str | None = None,
) -> dict:
    revision = _verify_revision(model, expected_revision)
    hosts = _filtered_hosts(model, search=search, subnet=subnet, sort=sort)
    visible = hosts[offset:offset + limit]
    visible_keys = {str(host.get("host_key") or "") for host in visible}
    findings = [
        item for item in (model.get("findings") or [])
        if str(item.get("host_key") or "") in visible_keys
    ]
    result = {
        key: value for key, value in model.items()
        if key not in {"hosts", "findings"}
    }
    result.update({
        "hosts": visible,
        "findings": findings,
        "source_revision": revision,
        "pagination": {
            "limit": limit,
            "offset": offset,
            "total": len(hosts),
            "has_more": offset + len(visible) < len(hosts),
            "revision": revision,
        },
        "filter": {"search": search, "subnet": subnet, "sort": sort},
    })
    return deepcopy(result)


def filtered_network_inventory_ips(
    model: dict,
    *,
    search: str = "",
    subnet: str = "",
    expected_revision: str | None = None,
) -> dict:
    revision = _verify_revision(model, expected_revision)
    ips = sorted(
        {
            str(host.get("ip")).strip()
            for host in _filtered_hosts(
                model, search=search, subnet=subnet, sort="ip"
            )
            if str(host.get("ip") or "").strip()
        },
        key=_natural_key,
    )
    return {"ips": ips, "count": len(ips), "source_revision": revision}


def network_inventory_outliers(
    model: dict,
    *,
    threshold: int,
    subnet: str = "",
    expected_revision: str | None = None,
) -> dict:
    revision = _verify_revision(model, expected_revision)
    selected_subnet = subnet.strip()
    members_by_os: dict[str, list[dict]] = defaultdict(list)
    for host in model.get("hosts") or []:
        if host.get("evidence_origin") == "configuration_only":
            continue
        if selected_subnet and str(host.get("subnet") or "Unmapped") != selected_subnet:
            continue
        name = str(
            host.get("os_display") or host.get("effective_os") or host.get("os")
            or host.get("os_group") or "Unclassified"
        )
        name = re.sub(r"\s+\(inferred\)$", "", name, flags=re.IGNORECASE).strip()
        members_by_os[name or "Unclassified"].append(host)

    groups = []
    outlier_total = 0
    eligible_groups = 0
    for name in sorted(members_by_os, key=_natural_key):
        members = members_by_os[name]
        if len(members) < 2:
            continue
        eligible_groups += 1
        maximum = max(1, math.floor(len(members) * (threshold / 100)))
        affected: dict[tuple[str, Any], list[dict]] = defaultdict(list)
        samples: dict[tuple[str, Any], dict] = {}
        for host in members:
            seen = set()
            for service in network_inventory_services(host):
                key = (str(service.get("protocol") or "?"), service.get("port", "?"))
                if key in seen:
                    continue
                seen.add(key)
                affected[key].append(host)
                samples.setdefault(key, service)
        unusual = []
        for key, hosts in affected.items():
            if len(hosts) > maximum:
                continue
            protocol, port = key
            sample = samples[key]
            unusual.append({
                "protocol": protocol,
                "port": port,
                "service": sample.get("service"),
                "product": sample.get("product"),
                "affected_count": len(hosts),
                "affected_hosts": sorted(
                    [str(host.get("ip") or host.get("hostname") or "Unknown host") for host in hosts],
                    key=_natural_key,
                ),
            })
        unusual.sort(key=lambda item: (
            _port_number(item.get("port")), _natural_key(item.get("protocol")),
        ))
        outlier_total += len(unusual)
        groups.append({
            "name": name,
            "member_count": len(members),
            "unusual": unusual,
        })
    return {
        "status": "network_outliers_complete",
        "source_revision": revision,
        "threshold": threshold,
        "subnet": selected_subnet,
        "outlier_total": outlier_total,
        "eligible_group_count": eligible_groups,
        "groups": groups,
    }
