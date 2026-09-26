from __future__ import annotations

import ipaddress
import hashlib
import json
import re
import sqlite3
import threading
from collections import Counter, defaultdict
from pathlib import Path

from fastapi import APIRouter, HTTPException

from app.device_configs import CONFIG_DIR, device_collection_directory, device_collection_summary
from app.database import configure_database, connect_database
from app.network_map import parse_nmap_xml
from app.poc import DATA_DIR, DB_PATH, RUNS_DIR_NAME
from app.saved_networks import list_saved_networks


router = APIRouter(prefix="/api/device-analysis", tags=["device-analysis"])

# Increment whenever retained device evidence parsing changes so previously
# completed pulls are re-analyzed without requiring another network collection.
DEVICE_SUMMARY_VERSION = 2
_DEVICE_STORAGE_READY: set[str] = set()
_DEVICE_STORAGE_LOCK = threading.RLock()


def init_device_analysis_storage(db_path: Path = DB_PATH) -> None:
    storage_key = str(db_path.resolve())
    if storage_key in _DEVICE_STORAGE_READY and db_path.is_file():
        return
    with _DEVICE_STORAGE_LOCK:
        if storage_key in _DEVICE_STORAGE_READY and db_path.is_file():
            return
        configure_database(db_path)
        with connect_database(db_path) as db:
            db.execute(
                """
                CREATE TABLE IF NOT EXISTS device_collections (
                    run_id TEXT PRIMARY KEY,
                    created_at TEXT,
                    completed_at TEXT,
                    device_address TEXT,
                    device_name TEXT,
                    vendor TEXT,
                    device_type TEXT,
                    status TEXT,
                    evidence_fingerprint TEXT NOT NULL
                )
                """
            )
            db.execute(
                """
                CREATE TABLE IF NOT EXISTS device_analysis_cache (
                    run_id TEXT PRIMARY KEY,
                    analysis_version INTEGER NOT NULL,
                    evidence_fingerprint TEXT NOT NULL,
                    summary_json TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY (run_id) REFERENCES device_collections(run_id) ON DELETE CASCADE
                )
                """
            )
            db.execute(
                """
                CREATE TABLE IF NOT EXISTS device_command_observations (
                    observation_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT NOT NULL,
                    position INTEGER NOT NULL,
                    line_number INTEGER,
                    command TEXT NOT NULL,
                    classification TEXT NOT NULL,
                    label TEXT NOT NULL,
                    UNIQUE(run_id, position),
                    FOREIGN KEY (run_id) REFERENCES device_collections(run_id) ON DELETE CASCADE
                )
                """
            )
            db.execute(
                "CREATE INDEX IF NOT EXISTS device_collections_address_created "
                "ON device_collections(device_address, created_at DESC)"
            )
            db.execute(
                "CREATE INDEX IF NOT EXISTS device_commands_run_classification "
                "ON device_command_observations(run_id, classification, position)"
            )
            command_columns = {
                row[1]
                for row in db.execute(
                    "PRAGMA table_info(device_command_observations)"
                ).fetchall()
            }
            if "line_number" not in command_columns:
                db.execute(
                    "ALTER TABLE device_command_observations "
                    "ADD COLUMN line_number INTEGER"
                )
        _DEVICE_STORAGE_READY.add(storage_key)


def delete_device_analysis_storage(run_id: str, db_path: Path = DB_PATH) -> None:
    init_device_analysis_storage(db_path)
    with connect_database(db_path) as db:
        db.execute("DELETE FROM device_collections WHERE run_id = ?", (run_id,))


def _device_evidence_fingerprint(run_dir: Path) -> str:
    records = []
    for path in sorted(item for item in run_dir.iterdir() if item.is_file()):
        if path.name == "accountability.pcap":
            continue
        stat = path.stat()
        records.append((path.name, stat.st_size, stat.st_mtime_ns))
    return hashlib.sha256(json.dumps(records, separators=(",", ":")).encode()).hexdigest()


def _cached_device_summary(run_id: str, config_dir: Path, db_path: Path) -> dict:
    init_device_analysis_storage(db_path)
    run_dir = device_collection_directory(run_id, config_dir)
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    fingerprint = _device_evidence_fingerprint(run_dir)
    with connect_database(db_path) as db:
        row = db.execute(
            """
            SELECT summary_json FROM device_analysis_cache
            WHERE run_id = ? AND analysis_version = ? AND evidence_fingerprint = ?
            """,
            (run_id, DEVICE_SUMMARY_VERSION, fingerprint),
        ).fetchone()
        if row:
            summary = json.loads(row[0])
            observations = db.execute(
                """
                SELECT position, line_number, command, classification, label
                FROM device_command_observations
                WHERE run_id = ? ORDER BY position
                """,
                (run_id,),
            ).fetchall()
            summary.setdefault("command_history", {})["entries"] = [
                {
                    "position": item[0], "line_number": item[1],
                    "command": item[2], "classification": item[3],
                    "label": item[4],
                }
                for item in observations
            ]
            return summary
    summary = device_collection_summary(run_id, config_dir=config_dir)
    cached = json.loads(json.dumps(summary))
    cached.pop("configuration_text", None)
    cached.pop("raw_output", None)
    observations = list((cached.get("command_history") or {}).pop("entries", []))
    with connect_database(db_path) as db:
        db.execute(
            """
            INSERT INTO device_collections (
                run_id, created_at, completed_at, device_address, device_name,
                vendor, device_type, status, evidence_fingerprint
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(run_id) DO UPDATE SET
                completed_at = excluded.completed_at,
                device_address = excluded.device_address,
                device_name = excluded.device_name,
                vendor = excluded.vendor,
                device_type = excluded.device_type,
                status = excluded.status,
                evidence_fingerprint = excluded.evidence_fingerprint
            """,
            (
                run_id, manifest.get("created_at"), manifest.get("completed_at"),
                manifest.get("device_address"), manifest.get("device_name"),
                manifest.get("vendor"), manifest.get("device_type"),
                manifest.get("status"), fingerprint,
            ),
        )
        db.execute("DELETE FROM device_command_observations WHERE run_id = ?", (run_id,))
        db.executemany(
            """
            INSERT INTO device_command_observations (
                run_id, position, line_number, command, classification, label
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    run_id, item["position"], item.get("line_number"), item["command"],
                    item["classification"], item["label"],
                )
                for item in observations
            ],
        )
        db.execute(
            """
            INSERT INTO device_analysis_cache (
                run_id, analysis_version, evidence_fingerprint, summary_json, updated_at
            ) VALUES (?, ?, ?, ?, datetime('now'))
            ON CONFLICT(run_id) DO UPDATE SET
                analysis_version = excluded.analysis_version,
                evidence_fingerprint = excluded.evidence_fingerprint,
                summary_json = excluded.summary_json,
                updated_at = excluded.updated_at
            """,
            (run_id, DEVICE_SUMMARY_VERSION, fingerprint, json.dumps(cached, separators=(",", ":"))),
        )
    cached.setdefault("command_history", {})["entries"] = observations
    return cached


def _route_protocol(route: dict) -> str:
    if route.get("direct"):
        return "connected"
    line = str(route.get("line") or "")
    lower = line.lower()
    patterns = (
        ("bgp", r"(?:^|\s)(?:b|bgp)(?:\s|\*)"),
        ("ospf", r"(?:^|\s)(?:o|ospf)(?:\s|\*)"),
        ("eigrp", r"(?:^|\s)(?:d|eigrp)(?:\s|\*)"),
        ("rip", r"(?:^|\s)(?:r|rip)(?:\s|\*)"),
        ("isis", r"(?:^|\s)(?:i|isis)(?:\s|\*)"),
    )
    for name, pattern in patterns:
        if re.search(pattern, lower):
            return name
    if (
        lower.startswith(("ip route ", "route "))
        or " protocols static " in f" {lower} "
        or re.match(r"^s(?:\*|\s)", lower)
    ):
        return "static"
    return "other"


def _interface_role(interface: dict) -> str:
    text = f"{interface.get('name', '')} {interface.get('zone', '')}".lower()
    for role, markers in (
        ("external", ("wan", "outside", "untrust", "external", "internet")),
        ("internal", ("lan", "inside", "trust", "user", "server")),
        ("dmz", ("dmz",)),
        ("management", ("mgmt", "management", "admin")),
        ("transit", ("transit", "uplink", "peer", "core")),
    ):
        if any(marker in text for marker in markers):
            return role
    return "unclassified"


def _interface_network(interface: dict) -> ipaddress.IPv4Network | None:
    try:
        parsed = ipaddress.ip_interface(str(interface.get("address") or ""))
    except ValueError:
        return None
    return parsed.network if parsed.version == 4 else None


def _wan_interface_candidates(
    interfaces: list[dict], routes: list[dict], nat_items: list[dict]
) -> list[dict]:
    """Rank explainable WAN candidates without turning an inference into a fact."""
    grouped: dict[str, dict] = {}
    for interface in interfaces:
        name = str(interface.get("name") or "").strip()
        if not name:
            continue
        candidate = grouped.setdefault(
            name,
            {
                "name": name,
                "addresses": [],
                "networks": [],
                "role": str(interface.get("role") or "unclassified"),
                "zone": str(interface.get("zone") or ""),
            },
        )
        address = str(interface.get("address") or "").strip()
        network = str(interface.get("network") or "").strip()
        if address and address not in candidate["addresses"]:
            candidate["addresses"].append(address)
        if network and network not in candidate["networks"]:
            candidate["networks"].append(network)
        if candidate["role"] == "unclassified" and interface.get("role"):
            candidate["role"] = str(interface["role"])
        if not candidate["zone"] and interface.get("zone"):
            candidate["zone"] = str(interface["zone"])

    # Some valid uplinks (DHCP, PPPoE, unnumbered, or route-only interfaces)
    # have no retained address/MAC record. An explicitly named default-route
    # interface is still useful evidence and must remain available for review.
    for route in routes:
        if not (
            route.get("route_type") == "default"
            or route.get("network") in {"0.0.0.0/0", "::/0"}
        ):
            continue
        name = str(route.get("interface") or "").strip()
        if name and name not in grouped:
            grouped[name] = {
                "name": name,
                "addresses": [],
                "networks": [],
                "role": _interface_role({"name": name}),
                "zone": "",
            }

    default_routes = [
        route for route in routes
        if route.get("route_type") == "default"
        or route.get("network") in {"0.0.0.0/0", "::/0"}
    ]
    strong_names: set[str] = set()
    candidates: list[dict] = []
    for name, candidate in grouped.items():
        score = 0
        reasons: list[str] = []
        evidence: list[str] = []
        parsed_networks = []
        for value in candidate["addresses"]:
            try:
                parsed_networks.append(ipaddress.ip_interface(value).network)
            except ValueError:
                continue

        explicit_defaults = [
            route for route in default_routes
            if str(route.get("interface") or "").casefold() == name.casefold()
        ]
        next_hop_defaults = []
        for route in default_routes:
            via = str(route.get("via") or "")
            try:
                address = ipaddress.ip_address(via)
            except ValueError:
                continue
            if any(address in network for network in parsed_networks):
                next_hop_defaults.append(route)
        matched_defaults = explicit_defaults or next_hop_defaults
        if explicit_defaults:
            score += 100
            reasons.append("A retained default route explicitly exits this interface.")
        elif next_hop_defaults:
            score += 90
            reasons.append("A retained default route's next hop is on this interface network.")
        if matched_defaults:
            strong_names.add(name)
            evidence.extend(
                str(route.get("line") or "") for route in matched_defaults
                if route.get("line")
            )

        if candidate["role"] == "external":
            score += 45
            reasons.append("Its name or description identifies it as WAN, outside, or Internet-facing.")

        interface_pattern = re.compile(
            rf"(?<![A-Za-z0-9_.:/-]){re.escape(name)}(?![A-Za-z0-9_.:/-])",
            re.I,
        )
        matching_nat = [
            item for item in nat_items
            if interface_pattern.search(
                str(item.get("evidence") or item.get("line") or "")
            )
        ]
        if matching_nat:
            score += 35
            reasons.append("Retained NAT evidence names this interface.")
            evidence.extend(
                str(item.get("evidence") or item.get("line") or "")
                for item in matching_nat
            )

        parsed_addresses = []
        for value in candidate["addresses"]:
            try:
                parsed_addresses.append(ipaddress.ip_interface(value))
            except ValueError:
                continue
        if any(item.ip.is_global for item in parsed_addresses):
            score += 15
            reasons.append("It has a globally routable address.")
        if any(
            (item.version == 4 and item.network.prefixlen >= 30)
            or (item.version == 6 and item.network.prefixlen >= 126)
            for item in parsed_addresses
        ):
            score += 10
            reasons.append("Its small point-to-point network is consistent with an uplink.")

        unique_evidence = list(dict.fromkeys(value[:500] for value in evidence if value))
        candidate.update(
            {
                "score": score,
                "confidence": "high" if score >= 80 else "medium" if score >= 45 else "low",
                "reasons": reasons or ["No strong WAN indicators were found in the retained evidence."],
                "evidence": unique_evidence[:12],
                "evidence_count": len(unique_evidence),
            }
        )
        candidates.append(candidate)

    highest_score = max((item["score"] for item in candidates), default=0)
    for candidate in candidates:
        candidate["recommended"] = (
            candidate["name"] in strong_names
            if strong_names
            else highest_score >= 45 and candidate["score"] == highest_score
        )
    return sorted(
        candidates,
        key=lambda item: (
            not item["recommended"], -item["score"], item["name"].casefold()
        ),
    )


def _evidence_networks(items: list[dict]) -> list[tuple[ipaddress.IPv4Network, dict]]:
    """Return IPv4 hosts/networks explicitly present in retained evidence lines."""
    found: list[tuple[ipaddress.IPv4Network, dict]] = []
    for item in items:
        evidence = str(item.get("evidence") or "")
        for token in re.findall(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?", evidence):
            try:
                network = ipaddress.ip_network(token, strict=False)
            except ValueError:
                continue
            if network.version == 4:
                found.append((network, item))
    return found


def _saved_network_correlations(
    interfaces: list[dict], routes: list[dict], policy_items: list[dict], db_path: Path
) -> list[dict]:
    matches = []
    for saved in list_saved_networks(db_path):
        try:
            saved_network = ipaddress.ip_network(saved["cidr"], strict=False)
        except ValueError:
            continue
        interface_names = sorted({
            str(item.get("name") or "interface")
            for item in interfaces
            if (network := _interface_network(item)) is not None
            and network.overlaps(saved_network)
        })
        route_networks = []
        for item in routes:
            try:
                route_network = ipaddress.ip_network(str(item.get("network") or ""), strict=False)
            except ValueError:
                continue
            if route_network.overlaps(saved_network):
                route_networks.append(str(route_network))
        route_networks = sorted(set(route_networks))
        policy_evidence = [
            item
            for network, item in _evidence_networks(policy_items)
            if network.overlaps(saved_network)
        ][:25]
        if interface_names or route_networks or policy_evidence:
            provenance = []
            if interface_names:
                provenance.append("parsed interface addressing")
            if route_networks:
                provenance.append("parsed routing table")
            if policy_evidence:
                provenance.append("parsed policy, NAT, or object evidence")
            matches.append({
                "saved_network_id": saved["saved_network_id"],
                "name": saved["name"],
                "cidr": saved["cidr"],
                "interface_names": interface_names,
                "route_networks": route_networks,
                "policy_evidence": policy_evidence,
                "confidence": "high" if interface_names else "medium",
                "provenance": provenance,
            })
    return matches


def _nmap_correlations(
    interfaces: list[dict], policy_items: list[dict], *, db_path: Path, data_dir: Path
) -> list[dict]:
    networks = [network for item in interfaces if (network := _interface_network(item))]
    if not networks or not db_path.is_file():
        return []
    try:
        with connect_database(db_path) as db:
            rows = db.execute(
                "SELECT manifest_json FROM scan_runs ORDER BY created_at DESC LIMIT 200"
            ).fetchall()
    except sqlite3.Error:
        return []
    policy_networks = _evidence_networks(policy_items)
    observed: dict[str, dict] = {}
    for (manifest_json,) in rows:
        try:
            manifest = json.loads(manifest_json)
        except (TypeError, json.JSONDecodeError):
            continue
        if manifest.get("status") != "completed" or not manifest.get("run_id"):
            continue
        xml_path = data_dir / RUNS_DIR_NAME / manifest["run_id"] / "scan.xml"
        for host in parse_nmap_xml(xml_path):
            try:
                address = ipaddress.ip_address(host.get("ip") or "")
            except ValueError:
                continue
            matching = [str(network) for network in networks if address in network]
            if not matching:
                continue
            record = observed.setdefault(
                str(address),
                {
                    "ip": str(address),
                    "hostname": host.get("hostname"),
                    "ports": host.get("ports") or [],
                    "interface_networks": set(),
                    "policy_evidence": [],
                    "sources": [],
                },
            )
            record["interface_networks"].update(matching)
            for policy_network, evidence in policy_networks:
                if address in policy_network and evidence not in record["policy_evidence"]:
                    record["policy_evidence"].append(evidence)
            source = {
                "run_id": manifest["run_id"],
                "label": manifest.get("display_name") or manifest.get("name") or manifest["run_id"][:8],
                "completed_at": manifest.get("completed_at") or manifest.get("created_at"),
                "url": f"/api/scan-runs/{manifest['run_id']}/artifacts/xml",
            }
            if source not in record["sources"]:
                record["sources"].append(source)
    result = []
    for item in observed.values():
        item["interface_networks"] = sorted(item["interface_networks"])
        item["confidence"] = "high"
        item["provenance"] = ["parsed device interface", "retained Nmap XML"]
        if item["policy_evidence"]:
            item["provenance"].append("parsed policy, NAT, or object evidence")
        result.append(item)
    return sorted(result, key=lambda item: ipaddress.ip_address(item["ip"]))


def analyze_device_collection(
    run_id: str,
    *,
    config_dir: Path | None = None,
    db_path: Path | None = None,
    data_dir: Path | None = None,
    include_correlations: bool = True,
) -> dict:
    config_dir = CONFIG_DIR if config_dir is None else config_dir
    db_path = DB_PATH if db_path is None else db_path
    data_dir = DATA_DIR if data_dir is None else data_dir
    summary = _cached_device_summary(run_id, config_dir, db_path)
    run_dir = device_collection_directory(run_id, config_dir)
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    manifest.pop("key_path", None)
    interfaces = [
        {
            **item,
            "role": _interface_role(item),
            "network": str(network) if (network := _interface_network(item)) else None,
        }
        for item in summary.get("interfaces", [])
    ]
    routes = [{**item, "protocol": _route_protocol(item)} for item in summary.get("routes", [])]
    protocol_counts = Counter(item["protocol"] for item in routes)
    next_hops: dict[str, list[str]] = defaultdict(list)
    paths_by_network: dict[str, set[tuple[str, str]]] = defaultdict(set)
    for route in routes:
        network = str(route.get("network") or "")
        via = str(route.get("via") or "direct")
        interface = str(route.get("interface") or "")
        if route.get("via"):
            next_hops[via].append(network)
        if network:
            paths_by_network[network].add((via, interface))
    multipath = [
        {
            "network": network,
            "paths": [
                {"via": via if via != "direct" else None, "interface": interface or None}
                for via, interface in sorted(paths)
            ],
        }
        for network, paths in sorted(paths_by_network.items())
        if len(paths) > 1
    ]
    interface_networks = [network for item in interfaces if (network := _interface_network(item))]
    review_items = []
    default_routes = [item for item in routes if item.get("route_type") == "default"]
    wan_candidates = _wan_interface_candidates(
        interfaces, routes, summary.get("nat", [])
    )
    if not default_routes:
        review_items.append({
            "severity": "warning", "category": "routing",
            "title": "No default route was parsed",
            "detail": "Confirm whether this device intentionally relies only on specific routes or whether the collection omitted routing evidence.",
        })
    for route in routes:
        via = route.get("via")
        if not via:
            continue
        try:
            reachable = any(ipaddress.ip_address(via) in network for network in interface_networks)
        except ValueError:
            reachable = False
        if not reachable:
            review_items.append({
                "severity": "warning", "category": "routing",
                "title": f"Next hop {via} is not on a parsed interface network",
                "detail": f"Route {route.get('network')} references {via}. The interface collection may be incomplete or the route may require recursive resolution.",
                "evidence": route.get("line"),
            })
    unclassified = [item.get("name") for item in interfaces if item["role"] == "unclassified"]
    if unclassified:
        review_items.append({
            "severity": "info", "category": "interfaces",
            "title": f"{len(unclassified)} interface role(s) remain unclassified",
            "detail": ", ".join(str(value) for value in unclassified if value),
        })
    if multipath:
        review_items.append({
            "severity": "info", "category": "routing",
            "title": f"{len(multipath)} multipath destination(s) detected",
            "detail": "Review equal-cost or redundant paths when comparing expected reachability.",
        })
    policy_count = len(summary.get("firewall_acl", []))
    nat_count = len(summary.get("nat", []))
    declared_type = str(manifest.get("device_type") or "").lower()
    declared_types = {
        str(item).lower() for item in (manifest.get("device_types") or [declared_type])
        if item
    }
    observed_roles: set[str] = set()
    observed_roles.update(declared_types & {"router", "firewall", "switch"})
    if routes and declared_types & {"router", "firewall"}:
        observed_roles.add("router")
    if (policy_count or nat_count) and declared_types & {"router", "firewall"}:
        observed_roles.add("firewall")
    role_order = ("router", "firewall", "switch")
    roles = [role for role in role_order if role in observed_roles]
    collection_status = str(manifest.get("status") or "unknown").lower()
    if collection_status not in {"completed", "uploaded"}:
        review_items.append({
            "severity": "warning", "category": "collection",
            "title": f"Collection status is {collection_status}",
            "detail": "Treat parsed content as partial evidence. Review the retained command status and rerun with the current guarded profile before relying on missing sections.",
        })
    if manifest.get("output_truncated"):
        review_items.append({
            "severity": "warning", "category": "collection",
            "title": "Collection output reached the retention limit",
            "detail": "Later command sections may be absent. Reduce optional output or increase the reviewed deployment limit before relying on missing evidence.",
        })
    iptables_policy = summary.get("iptables_policy") or {}
    if iptables_policy and not iptables_policy.get("complete", False):
        review_items.append({
            "severity": "warning", "category": "policy",
            "title": "Ordered policy evidence is incomplete",
            "detail": "One or more retained rules, address sets, or set members exceeded the reviewed evidence boundary. Reachability will not claim an allow or deny decision from this policy.",
        })
    if manifest.get("device_type") == "firewall" and not policy_count:
        review_items.append({
            "severity": "warning", "category": "policy",
            "title": "No firewall or ACL evidence was parsed",
            "detail": "Confirm that the selected collection profile returned the active policy configuration.",
        })
    switching_count = len(summary.get("switching", []))
    switch_detail = summary.get("switch_detail") or {}
    structured_switching_count = sum(
        len(switch_detail.get(section) or [])
        for section in ("ports", "mac_table", "port_channels", "spanning_tree")
    )
    if manifest.get("device_type") == "switch" and not structured_switching_count:
        review_items.append({
            "severity": "warning", "category": "switching",
            "title": "No structured switch forwarding evidence was parsed",
            "detail": "No usable port, learned-MAC, aggregation, or spanning-tree records were found. Confirm the vendor profile and rerun with the current guarded switch commands.",
        })
    command_history = summary.get("command_history") or {}
    if command_history.get("attempted") and command_history.get("status") != "captured":
        review_items.append({
            "severity": "warning", "category": "command history",
            "title": "Command history was not available",
            "detail": "NCT attempted the history command before the configuration pull, but the device returned no usable entries. Review platform history settings and centralized AAA accounting.",
        })
    elif command_history.get("other_command_count"):
        review_items.append({
            "severity": "info", "category": "command history",
            "title": f"{command_history['other_command_count']} non-NCT command(s) retained",
            "detail": "Review the highlighted operator or other activity. Known NCT collection commands are labeled separately so they can be ignored during triage.",
        })
    volatile_configuration = summary.get("volatile_configuration") or {}
    if volatile_configuration.get("status") == "different":
        review_items.append({
            "severity": "warning", "category": "volatile configuration",
            "title": "Running configuration differs from startup configuration",
            "detail": volatile_configuration.get("detail"),
            "evidence": (
                f"{volatile_configuration.get('running_only_count', 0)} running-only line(s); "
                f"{volatile_configuration.get('startup_only_count', 0)} startup-only line(s)"
            ),
        })
    policy_items = [
        *summary.get("firewall_acl", []),
        *summary.get("nat", []),
        *summary.get("network_objects", []),
    ]
    # Reach consumes the complete route and policy evidence below, but it does
    # not use the Device Analysis presentation correlations. Let that caller
    # skip the expensive all-routes-by-Saved-Network pass and repeated Nmap XML
    # parsing while preserving the full Device Analysis response by default.
    if include_correlations:
        saved_matches = _saved_network_correlations(
            interfaces, routes, policy_items, db_path
        )
        nmap_matches = _nmap_correlations(
            interfaces, policy_items, db_path=db_path, data_dir=data_dir
        )
    else:
        saved_matches = []
        nmap_matches = []
    evidence = []
    for filename, label in (
        (summary.get("source_filename"), "Configuration evidence"),
        (summary.get("raw_filename"), "Raw collection output"),
    ):
        if filename and not any(item["filename"] == filename for item in evidence):
            evidence.append({
                "label": label,
                "filename": filename,
                "url": f"/api/device-configs/{run_id}/files/{filename}",
            })
    evidence.append({
        "label": "Collection manifest",
        "filename": "manifest.json",
        "url": f"/api/device-configs/{run_id}/files/manifest.json",
    })
    if (run_dir / "command-history.txt").is_file():
        evidence.append({
            "label": "Command history",
            "filename": "command-history.txt",
            "url": f"/api/device-configs/{run_id}/files/command-history.txt",
        })
    return {
        "run_id": run_id,
        "status": "analysis_complete",
        "device": {
            "name": manifest.get("device_name"),
            "address": manifest.get("device_address"),
            "vendor": manifest.get("vendor"),
            "type": manifest.get("device_type"),
            "roles": roles,
            "role_label": " + ".join(role.title() for role in roles) or "Network Device",
        },
        "collection": {
            "status": manifest.get("status"),
            "operation": manifest.get("operation"),
            "operator": manifest.get("operator"),
            "reason": manifest.get("reason"),
            "originating_host": manifest.get("originating_host"),
            "created_at": manifest.get("created_at"),
            "completed_at": manifest.get("completed_at"),
        },
        "counts": {
            **summary.get("counts", {}),
            "default_routes": len(default_routes),
            "next_hops": len(next_hops),
            "multipath_destinations": len(multipath),
            "saved_network_matches": len(saved_matches),
            "nmap_host_matches": len(nmap_matches),
            "review_items": len(review_items),
        },
        "interfaces": interfaces,
        "wan_candidates": wan_candidates,
        "route_analysis": {
            "routes": routes,
            "default_routes": default_routes,
            "protocol_counts": dict(sorted(protocol_counts.items())),
            "next_hops": [
                {"address": address, "route_count": len(networks), "networks": sorted(networks)}
                for address, networks in sorted(next_hops.items())
            ],
            "multipath": multipath,
        },
        "policy": {
            "firewall_acl": summary.get("firewall_acl", []),
            "nat": summary.get("nat", []),
            "network_objects": summary.get("network_objects", []),
            "iptables": iptables_policy,
            "applied": summary.get("vendor_policy") or {},
        },
        "neighbors": summary.get("neighbors", []),
        "topology_neighbors": summary.get("topology_neighbors", []),
        "switching": summary.get("switching", []),
        "switch_detail": switch_detail,
        "command_results": summary.get("command_results", []),
        "command_history": command_history,
        "volatile_configuration": volatile_configuration,
        "saved_network_correlations": saved_matches,
        "nmap_host_correlations": nmap_matches,
        "review_items": review_items,
        "evidence": evidence,
    }


def _index(items: list[dict], fields: tuple[str, ...]) -> dict[tuple, dict]:
    return {tuple(str(item.get(field) or "") for field in fields): item for item in items}


def compare_device_analyses(before: dict, after: dict) -> dict:
    before_interfaces = _index(before.get("interfaces", []), ("name",))
    after_interfaces = _index(after.get("interfaces", []), ("name",))
    before_routes = _index(
        before.get("route_analysis", {}).get("routes", []),
        ("network", "via", "interface", "protocol"),
    )
    after_routes = _index(
        after.get("route_analysis", {}).get("routes", []),
        ("network", "via", "interface", "protocol"),
    )

    def evidence_delta(section: str) -> tuple[list[dict], list[dict]]:
        old = _index(before.get("policy", {}).get(section, []), ("evidence",))
        new = _index(after.get("policy", {}).get(section, []), ("evidence",))
        return (
            [new[key] for key in sorted(new.keys() - old.keys())],
            [old[key] for key in sorted(old.keys() - new.keys())],
        )

    firewall_added, firewall_removed = evidence_delta("firewall_acl")
    nat_added, nat_removed = evidence_delta("nat")
    objects_added, objects_removed = evidence_delta("network_objects")
    before_switching = _index(before.get("switching", []), ("evidence",))
    after_switching = _index(after.get("switching", []), ("evidence",))
    switching_added = [
        after_switching[key] for key in sorted(after_switching.keys() - before_switching.keys())
    ]
    switching_removed = [
        before_switching[key] for key in sorted(before_switching.keys() - after_switching.keys())
    ]
    shared_interfaces = before_interfaces.keys() & after_interfaces.keys()
    interface_fields = ("address", "network", "role", "zone", "mac")
    interfaces_changed = []
    for key in sorted(shared_interfaces):
        old = before_interfaces[key]
        new = after_interfaces[key]
        changes = {
            field: {"before": old.get(field), "after": new.get(field)}
            for field in interface_fields
            if old.get(field) != new.get(field)
        }
        if changes:
            interfaces_changed.append({"name": new.get("name"), "changes": changes})
    identity_mismatch = before.get("device", {}).get("address") != after.get("device", {}).get("address")
    return {
        "status": "comparison_complete",
        "before": {"run_id": before["run_id"], "device": before["device"], "collection": before["collection"], "evidence": before["evidence"]},
        "after": {"run_id": after["run_id"], "device": after["device"], "collection": after["collection"], "evidence": after["evidence"]},
        "identity_mismatch": identity_mismatch,
        "summary": {
            "interfaces_added": len(after_interfaces.keys() - before_interfaces.keys()),
            "interfaces_removed": len(before_interfaces.keys() - after_interfaces.keys()),
            "interfaces_changed": len(interfaces_changed),
            "routes_added": len(after_routes.keys() - before_routes.keys()),
            "routes_removed": len(before_routes.keys() - after_routes.keys()),
            "firewall_acl_added": len(firewall_added),
            "firewall_acl_removed": len(firewall_removed),
            "nat_added": len(nat_added),
            "nat_removed": len(nat_removed),
            "network_objects_added": len(objects_added),
            "network_objects_removed": len(objects_removed),
            "switching_added": len(switching_added),
            "switching_removed": len(switching_removed),
        },
        "interfaces_added": [after_interfaces[key] for key in sorted(after_interfaces.keys() - before_interfaces.keys())],
        "interfaces_removed": [before_interfaces[key] for key in sorted(before_interfaces.keys() - after_interfaces.keys())],
        "interfaces_changed": interfaces_changed,
        "routes_added": [after_routes[key] for key in sorted(after_routes.keys() - before_routes.keys())],
        "routes_removed": [before_routes[key] for key in sorted(before_routes.keys() - after_routes.keys())],
        "switching_changes": {
            "added": switching_added,
            "removed": switching_removed,
        },
        "policy_changes": {
            "firewall_acl_added": firewall_added,
            "firewall_acl_removed": firewall_removed,
            "nat_added": nat_added,
            "nat_removed": nat_removed,
            "network_objects_added": objects_added,
            "network_objects_removed": objects_removed,
        },
    }


@router.get("/compare")
def compare_device_collections(before: str, after: str) -> dict:
    try:
        return compare_device_analyses(
            analyze_device_collection(before), analyze_device_collection(after)
        )
    except (ValueError, FileNotFoundError, json.JSONDecodeError, OSError):
        raise HTTPException(status_code=404, detail="One or both device collections were not found") from None


@router.get("/{run_id}")
def device_analysis(run_id: str, include_correlations: bool = True) -> dict:
    try:
        return analyze_device_collection(
            run_id, include_correlations=include_correlations
        )
    except (ValueError, FileNotFoundError, json.JSONDecodeError, OSError):
        raise HTTPException(status_code=404, detail="Device collection was not found") from None
