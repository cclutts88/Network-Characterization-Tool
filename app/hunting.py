from __future__ import annotations

from collections import Counter, defaultdict
import ipaddress

from app.comparison import canonical_host_key


CATEGORY_RULES = {
    "Remote Access": {
        "services": ("ssh", "telnet", "rdp", "ms-wbt", "vnc", "winrm", "pcanywhere", "x11"),
        "ports": {22, 23, 3389, 5800, 5900, 5901, 5985, 5986},
    },
    "File Transfer": {
        "services": ("ftp", "tftp", "sftp", "scp", "rsync"),
        "ports": {20, 21, 69, 115, 873, 989, 990},
    },
    "File Sharing": {
        "services": ("smb", "microsoft-ds", "netbios-ssn", "nfs", "afp"),
        "ports": {111, 137, 138, 139, 445, 548, 2049},
    },
    "Web": {
        "services": ("http", "https", "http-proxy", "ssl/http", "web"),
        "ports": {80, 443, 8000, 8008, 8080, 8081, 8088, 8443, 8888},
    },
    "Identity": {
        "services": ("ldap", "kerberos", "kpasswd", "radius", "tacacs"),
        "ports": {49, 88, 389, 464, 636, 1812, 1813, 3268, 3269},
    },
    "Databases": {
        "services": (
            "mysql", "mariadb", "postgres", "ms-sql", "mssql", "oracle",
            "mongodb", "redis", "cassandra", "couchdb", "db2", "sybase",
        ),
        "ports": {1433, 1521, 3306, 5432, 5984, 6379, 9042, 27017},
    },
    "Email": {
        "services": ("smtp", "submission", "pop3", "imap"),
        "ports": {25, 110, 143, 465, 587, 993, 995},
    },
    "Network Management": {
        "services": ("snmp", "netconf", "restconf", "syslog", "gnmi"),
        "ports": {161, 162, 514, 6514, 830, 9339},
    },
}

CATEGORY_ORDER = (*CATEGORY_RULES.keys(), "Other Exposed Service")
STATE_ORDER = ("exposed", "inferred", "observed", "correlated")
UNKNOWN_IDENTITY = {"", "unknown", "unclassified", "unknown server"}


def _port_number(port: dict) -> int:
    try:
        return int(port.get("port") or 0)
    except (TypeError, ValueError):
        return 0


def _service_text(port: dict) -> str:
    return " ".join(
        str(port.get(field) or "").strip().lower()
        for field in ("service", "product")
    ).strip()


def _scope_subnet(ip_value: object, subnets: list[str] | None) -> str:
    try:
        address = ipaddress.ip_address(str(ip_value or ""))
    except ValueError:
        return "Unmapped"
    matches = []
    for value in subnets or []:
        try:
            network = ipaddress.ip_network(str(value), strict=False)
        except ValueError:
            continue
        if address.version == network.version and address in network:
            matches.append(network)
    if not matches:
        return "Unmapped"
    return str(max(matches, key=lambda network: network.prefixlen))


def _device_type(host: dict, categories: set[str]) -> str:
    explicit = str(host.get("device_type") or host.get("role") or "").strip()
    if explicit:
        return explicit.replace("_", " ").title()
    identity = " ".join(
        str(host.get(field) or "").strip().lower()
        for field in ("os", "os_group")
    )
    for marker, label in (
        ("firewall", "Firewall"), ("router", "Router"), ("switch", "Switch"),
        ("access point", "Wireless access point"), ("printer", "Printer"),
        ("phone", "Phone"), ("workstation", "Workstation"),
        ("server", "Server"),
    ):
        if marker in identity:
            return label
    for category, label in (
        ("Identity", "Identity server"), ("Databases", "Database server"),
        ("Email", "Mail server"), ("File Sharing", "File server"),
        ("File Transfer", "File-transfer host"),
        ("Network Management", "Network device"), ("Web", "Web host"),
        ("Remote Access", "Remote-access host"),
    ):
        if category in categories:
            return label
    return "Unclassified"


def _facet_values(items: list[dict], field: str) -> list[dict]:
    counts = Counter(str(item.get(field) or "Unclassified") for item in items)
    return [
        {"name": name, "host_count": count}
        for name, count in sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    ]


def _summarize_hunting(
    hosts: list[dict], findings: list[dict], *, source: dict, warnings: list[str]
) -> dict:
    findings.sort(key=lambda item: (
        item.get("ip") or item.get("hostname") or "",
        CATEGORY_ORDER.index(item["category"]),
        item["port"],
        item["protocol"],
    ))
    hosts.sort(key=lambda item: item.get("ip") or item.get("hostname") or "")
    category_counts = Counter(item["category"] for item in findings)
    state_counts = Counter(
        state for item in findings for state in item["evidence_states"]
    )
    return {
        "status": "hunting_complete",
        "source": source,
        "host_count": len(hosts),
        "hosts_with_findings_count": sum(
            1 for item in hosts if item.get("finding_count")
        ),
        "finding_count": len(findings),
        "nonstandard_finding_count": sum(
            1 for item in findings if item["nonstandard_port"]
        ),
        "categories": [
            {"name": name, "finding_count": category_counts.get(name, 0)}
            for name in CATEGORY_ORDER
            if category_counts.get(name)
        ],
        "capability_states": {
            state: state_counts.get(state, 0) for state in STATE_ORDER
        },
        "facets": {
            "operating_systems": _facet_values(hosts, "os_filter"),
            "subnets": _facet_values(hosts, "subnet"),
            "device_types": _facet_values(hosts, "device_type"),
        },
        "hosts": hosts,
        "findings": findings,
        "warnings": list(dict.fromkeys(warnings)),
    }


def categorize_port(port: dict) -> list[dict]:
    """Classify one open service using independent port and fingerprint signals."""
    number = _port_number(port)
    service_text = _service_text(port)
    categories = []
    for category, rules in CATEGORY_RULES.items():
        service_matches = sorted({
            marker for marker in rules["services"] if marker in service_text
        })
        port_matches = number in rules["ports"]
        if not service_matches and not port_matches:
            continue
        if service_matches and port_matches:
            capability_state = "correlated"
        elif service_matches:
            capability_state = "observed"
        else:
            capability_state = "inferred"
        evidence_states = ["exposed"]
        if port_matches:
            evidence_states.append("inferred")
        if service_matches:
            evidence_states.append("observed")
        if service_matches and port_matches:
            evidence_states.append("correlated")
        basis = []
        if port_matches:
            basis.append(f"port {number}/{str(port.get('protocol') or '').lower()}")
        if service_matches:
            basis.append("fingerprint: " + ", ".join(service_matches))
        categories.append({
            "category": category,
            "capability_state": capability_state,
            "evidence_states": evidence_states,
            "standard_port": port_matches,
            "nonstandard_port": bool(service_matches and not port_matches),
            "match_basis": basis,
        })
    if categories:
        return categories
    return [{
        "category": "Other Exposed Service",
        "capability_state": "exposed",
        "evidence_states": ["exposed"],
        "standard_port": False,
        "nonstandard_port": False,
        "match_basis": ["open service exposure"],
    }]


def build_hunting_analysis(
    analysis: dict,
    *,
    evidence: dict | None = None,
    subnets: list[str] | None = None,
) -> dict:
    findings = []
    hosts = []
    for host in analysis.get("hosts", []) or []:
        host_findings = []
        for port in host.get("ports", []) or []:
            if port.get("state") not in (None, "", "open", "open|filtered"):
                continue
            for classification in categorize_port(port):
                finding = {
                    "host_key": canonical_host_key(host),
                    "ip": host.get("ip"),
                    "hostname": host.get("hostname"),
                    "os": host.get("os"),
                    "os_group": host.get("os_group"),
                    "protocol": str(port.get("protocol") or "").lower(),
                    "port": _port_number(port),
                    "state": port.get("state") or "open",
                    "service": port.get("service"),
                    "product": port.get("product"),
                    "version": port.get("version"),
                    "outlier": bool(port.get("outlier")),
                    **classification,
                }
                findings.append(finding)
                host_findings.append(finding)
        categories = {item["category"] for item in host_findings}
        subnet = _scope_subnet(host.get("ip"), subnets)
        os_name = str(host.get("os") or "").strip()
        os_group = str(host.get("os_group") or "Unclassified").strip()
        os_filter = os_name if os_name.lower() not in UNKNOWN_IDENTITY else os_group
        if os_filter.lower() in UNKNOWN_IDENTITY:
            os_filter = "Unclassified"
        device_type = _device_type(host, categories)
        source_refs = list((evidence or {}).get("evidence", {}).get("sources") or [])
        for finding in host_findings:
            finding.update({
                "subnet": subnet,
                "device_type": device_type,
                "os_filter": os_filter,
                "source_refs": source_refs,
                "last_observed": (evidence or {}).get("completed_at")
                or (evidence or {}).get("created_at"),
            })
        hosts.append({
            "host_key": canonical_host_key(host),
            "ip": host.get("ip"),
            "hostname": host.get("hostname"),
            "mac": host.get("mac"),
            "vendor": host.get("vendor"),
            "os": host.get("os"),
            "os_group": os_group,
            "os_filter": os_filter,
            "subnet": subnet,
            "device_type": device_type,
            "categories": sorted(
                categories, key=lambda item: CATEGORY_ORDER.index(item)
            ),
            "protocols": sorted({
                item["protocol"] for item in host_findings if item.get("protocol")
            }),
            "services": [{
                "port": item.get("port"),
                "protocol": item.get("protocol"),
                "service": item.get("service"),
                "product": item.get("product"),
                "version": item.get("version"),
            } for item in host_findings],
            "nonstandard_port": any(
                item.get("nonstandard_port") for item in host_findings
            ),
            "capability_states": [
                state for state in STATE_ORDER
                if any(state in item["evidence_states"] for item in host_findings)
            ],
            "finding_count": len(host_findings),
            "source_refs": source_refs,
            "last_observed": (evidence or {}).get("completed_at")
            or (evidence or {}).get("created_at"),
        })
    return _summarize_hunting(
        hosts,
        findings,
        source=evidence or {},
        warnings=list(analysis.get("warnings") or []),
    )


def merge_hunting_analyses(
    analyses: list[dict], *, source: dict | None = None
) -> dict:
    """Combine newest-first hunting results while retaining one current host/service view."""
    hosts: dict[str, dict] = {}
    findings: dict[tuple[str, str, int, str], dict] = {}
    warnings = []
    for analysis in analyses:
        warnings.extend(analysis.get("warnings") or [])
        for host in analysis.get("hosts") or []:
            key = str(host.get("host_key") or "")
            if not key:
                continue
            if key not in hosts:
                hosts[key] = dict(host)
            else:
                known_sources = {
                    item.get("url") for item in hosts[key].get("source_refs") or []
                }
                hosts[key].setdefault("source_refs", []).extend(
                    item for item in host.get("source_refs") or []
                    if item.get("url") not in known_sources
                )
        for finding in analysis.get("findings") or []:
            key = _finding_key(finding)
            if key not in findings:
                findings[key] = dict(finding)
            else:
                known_sources = {
                    item.get("url") for item in findings[key].get("source_refs") or []
                }
                findings[key].setdefault("source_refs", []).extend(
                    item for item in finding.get("source_refs") or []
                    if item.get("url") not in known_sources
                )
    return _summarize_hunting(
        list(hosts.values()),
        list(findings.values()),
        source=source or {},
        warnings=warnings,
    )


def _finding_key(item: dict) -> tuple[str, str, int, str]:
    return (
        str(item.get("host_key") or ""),
        str(item.get("protocol") or ""),
        int(item.get("port") or 0),
        str(item.get("category") or ""),
    )


def compare_hunting_results(before: dict, after: dict) -> dict:
    old = {_finding_key(item): item for item in before.get("findings", [])}
    new = {_finding_key(item): item for item in after.get("findings", [])}
    added = [new[key] for key in sorted(new.keys() - old.keys())]
    removed = [old[key] for key in sorted(old.keys() - new.keys())]
    changed = []
    watched_fields = (
        "capability_state", "evidence_states", "service", "product", "version",
        "state", "nonstandard_port",
    )
    for key in sorted(old.keys() & new.keys()):
        changes = {
            field: {"before": old[key].get(field), "after": new[key].get(field)}
            for field in watched_fields
            if old[key].get(field) != new[key].get(field)
        }
        if changes:
            changed.append({"finding": new[key], "changes": changes})

    def categories_by_host(result: dict) -> dict[str, set[str]]:
        values: defaultdict[str, set[str]] = defaultdict(set)
        for item in result.get("findings", []):
            values[str(item.get("host_key") or "")].add(str(item.get("category") or ""))
        return values

    old_hosts, new_hosts = categories_by_host(before), categories_by_host(after)
    host_category_changes = []
    for host_key in sorted(old_hosts.keys() | new_hosts.keys()):
        categories_added = sorted(new_hosts[host_key] - old_hosts[host_key])
        categories_removed = sorted(old_hosts[host_key] - new_hosts[host_key])
        if categories_added or categories_removed:
            host_category_changes.append({
                "host_key": host_key,
                "categories_added": categories_added,
                "categories_removed": categories_removed,
            })
    return {
        "status": "hunting_comparison_complete",
        "before": before.get("source") or {},
        "after": after.get("source") or {},
        "summary": {
            "findings_added": len(added),
            "findings_removed": len(removed),
            "findings_changed": len(changed),
            "hosts_with_category_changes": len(host_category_changes),
        },
        "findings_added": added,
        "findings_removed": removed,
        "findings_changed": changed,
        "host_category_changes": host_category_changes,
    }
