from __future__ import annotations

import hashlib
import ipaddress
import json
import base64
from typing import Iterable


def _group_id(kind: str, value: str) -> str:
    digest = hashlib.sha256(f"{kind}\0{value}".encode("utf-8")).hexdigest()[:24]
    return f"{kind}-{digest}"


def _saved_network_snapshots(run: dict) -> list[dict]:
    selection = run.get("target_selection") or {}
    snapshots = run.get("saved_networks") or selection.get("saved_networks") or []
    return [item for item in snapshots if isinstance(item, dict)]


def _recorded_targets(run: dict) -> list[str]:
    selection = run.get("target_selection") or {}
    values: list[str] = []
    for snapshot in _saved_network_snapshots(run):
        values.append(str(snapshot.get("cidr") or ""))
    values.extend(str(value) for value in (run.get("manual_targets") or selection.get("manual_targets") or []))
    if not any(value.strip() for value in values):
        values.extend(str(value) for value in (run.get("targets") or []))
    return list(dict.fromkeys(value.strip() for value in values if value.strip()))


def scan_history_memberships(run: dict) -> list[dict]:
    """Return honest history groups from targets recorded on one scan.

    Exact CIDRs are canonicalized, but a host address is never promoted to a
    containing subnet. Saved Network names are presentation metadata only.
    """
    snapshots_by_cidr: dict[str, dict] = {}
    for snapshot in _saved_network_snapshots(run):
        raw = str(snapshot.get("cidr") or "").strip()
        if not raw or "/" not in raw:
            continue
        try:
            network = ipaddress.ip_network(raw, strict=False)
        except ValueError:
            continue
        if network.version == 4:
            snapshots_by_cidr.setdefault(str(network), snapshot)

    subnets: dict[str, dict] = {}
    hosts: list[str] = []
    unsupported: list[str] = []
    for raw in _recorded_targets(run):
        if "/" in raw:
            try:
                network = ipaddress.ip_network(raw, strict=False)
            except ValueError:
                unsupported.append(raw)
                continue
            if network.version != 4:
                unsupported.append(raw)
                continue
            cidr = str(network)
            snapshot = snapshots_by_cidr.get(cidr) or {}
            subnets.setdefault(
                cidr,
                {
                    "group_id": _group_id("subnet", cidr),
                    "kind": "subnet",
                    "name": snapshot.get("name") or f"Subnet {cidr}",
                    "cidr": cidr,
                    "description": snapshot.get("description")
                    or "Retained scans that explicitly recorded this exact subnet.",
                    "category": snapshot.get("category") or "",
                    "tags": list(snapshot.get("tags") or []),
                },
            )
            continue
        try:
            address = ipaddress.ip_address(raw)
        except ValueError:
            unsupported.append(raw)
            continue
        if address.version == 4:
            hosts.append(str(address))
        else:
            unsupported.append(raw)

    memberships = list(subnets.values())
    hosts = sorted(set(hosts), key=ipaddress.ip_address)
    if hosts:
        identity = json.dumps(hosts, separators=(",", ":"))
        memberships.append(
            {
                "group_id": _group_id("hosts", identity),
                "kind": "host_targets",
                "name": hosts[0] if len(hosts) == 1 else "Manual host list",
                "cidr": "",
                "description": (
                    f"One exact host target: {hosts[0]}."
                    if len(hosts) == 1
                    else f"{len(hosts)} exact host targets; no subnet is inferred."
                ),
                "category": "",
                "tags": [],
            }
        )
    if unsupported:
        values = sorted(set(unsupported))
        identity = json.dumps(values, separators=(",", ":"))
        memberships.append(
            {
                "group_id": _group_id("legacy", identity),
                "kind": "legacy_targets",
                "name": "Other / legacy targets",
                "cidr": "",
                "description": "Recorded targets could not be assigned to an IPv4 subnet honestly.",
                "category": "",
                "tags": [],
            }
        )
    if not memberships:
        memberships.append(
            {
                "group_id": _group_id("missing", "missing-recorded-target"),
                "kind": "missing_targets",
                "name": "Unassigned legacy scans",
                "cidr": "",
                "description": "No usable recorded target metadata is available; no subnet is inferred.",
                "category": "",
                "tags": [],
            }
        )
    return memberships


def _run_sort_key(run: dict) -> tuple[str, str]:
    return str(run.get("created_at") or ""), str(run.get("run_id") or "")


def encode_scan_history_cursor(run: dict) -> str:
    payload = json.dumps(list(_run_sort_key(run)), separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")


def decode_scan_history_cursor(value: str | None) -> tuple[str, str] | None:
    if not value:
        return None
    try:
        padded = value + "=" * (-len(value) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Invalid scan history cursor") from exc
    if (
        not isinstance(payload, list)
        or len(payload) != 2
        or any(not isinstance(item, str) for item in payload)
    ):
        raise ValueError("Invalid scan history cursor")
    return payload[0], payload[1]


def build_scan_history_catalog(runs: Iterable[dict]) -> list[dict]:
    groups: dict[str, dict] = {}
    for run in sorted(runs, key=_run_sort_key, reverse=True):
        for membership in scan_history_memberships(run):
            group_id = membership["group_id"]
            group = groups.get(group_id)
            if group is None:
                group = {
                    **membership,
                    "scan_count": 0,
                    "latest_scan_at": run.get("completed_at") or run.get("created_at"),
                    "latest_scan_name": run.get("display_name") or run.get("name"),
                    "latest_host_count": run.get("host_count"),
                }
                groups[group_id] = group
            group["scan_count"] += 1

    kind_order = {
        "subnet": 0,
        "host_targets": 1,
        "legacy_targets": 2,
        "missing_targets": 3,
    }
    return sorted(
        groups.values(),
        key=lambda item: (
            kind_order.get(item["kind"], 99),
            str(item.get("name") or "").casefold(),
            str(item.get("cidr") or ""),
            item["group_id"],
        ),
    )


def scan_history_group_page(
    runs: Iterable[dict], group_id: str, *, limit: int, cursor: str | None = None
) -> dict | None:
    matched: list[dict] = []
    group: dict | None = None
    for run in runs:
        memberships = scan_history_memberships(run)
        current = next(
            (item for item in memberships if item["group_id"] == group_id), None
        )
        if current is None:
            continue
        if group is None:
            group = dict(current)
        other_groups = [
            {
                "group_id": item["group_id"],
                "name": item["name"],
                "cidr": item.get("cidr") or "",
            }
            for item in memberships
            if item["group_id"] != group_id
        ]
        matched.append({**run, "history_also_covers": other_groups})
    if group is None:
        return None
    matched.sort(key=_run_sort_key, reverse=True)
    total = len(matched)
    before = decode_scan_history_cursor(cursor)
    eligible = [run for run in matched if before is None or _run_sort_key(run) < before]
    page = eligible[:limit]
    has_more = len(eligible) > len(page)
    return {
        "group": group,
        "runs": page,
        "total": total,
        "limit": limit,
        "next_cursor": encode_scan_history_cursor(page[-1]) if page and has_more else None,
        "has_more": has_more,
    }
