from __future__ import annotations

from collections import Counter, defaultdict
import ipaddress

from app.comparison import canonical_host_key
from app.ip_sort import ip_sort_key


DATASET_RULES = {
    "Authentication": {
        "services": ("kerberos", "kpasswd", "radius", "tacacs", "diameter", "ntlm"),
        "ports": {49, 88, 464, 1645, 1646, 1812, 1813, 3868},
        "source_types": ("nmap",),
    },
    "Directory & Identity": {
        "services": ("ldap", "ldaps", "globalcatldap", "active directory"),
        "ports": {389, 636, 3268, 3269},
        "source_types": ("nmap",),
    },
    "Remote Access & Administration": {
        "services": ("ssh", "telnet", "rdp", "ms-wbt", "vnc", "winrm", "pcanywhere", "x11"),
        "ports": {22, 23, 3389, 5800, 5900, 5901, 5985, 5986},
        "source_types": ("nmap",),
    },
    "Web Applications & APIs": {
        "services": ("http", "https", "http-proxy", "ssl/http", "web"),
        "ports": {80, 443, 8000, 8008, 8080, 8081, 8088, 8443, 8888},
        "source_types": ("nmap",),
    },
    "File Sharing": {
        "services": ("smb", "microsoft-ds", "netbios-ssn", "nfs", "afp"),
        "ports": {111, 137, 138, 139, 445, 548, 2049},
        "source_types": ("nmap",),
    },
    "File Transfer": {
        "services": ("ftp", "tftp", "sftp", "scp", "rsync"),
        "ports": {20, 21, 69, 115, 873, 989, 990},
        "source_types": ("nmap",),
    },
    "Databases & Data Stores": {
        "services": (
            "mysql", "mariadb", "postgres", "ms-sql", "mssql", "oracle",
            "mongodb", "redis", "cassandra", "couchdb", "db2", "sybase",
            "elasticsearch", "opensearch",
        ),
        "ports": {1433, 1521, 3306, 5432, 5984, 6379, 9042, 9200, 27017},
        "source_types": ("nmap",),
    },
    "Name Resolution": {
        "services": ("domain", "dns", "mdns", "llmnr", "netbios-ns"),
        "ports": {53, 137, 5353, 5355},
        "source_types": ("nmap",),
    },
    "Address Assignment": {
        "services": ("bootps", "bootpc", "dhcp", "dhcpv6"),
        "ports": {67, 68, 546, 547},
        "source_types": ("nmap",),
    },
    "Network Management": {
        "services": ("snmp", "netconf", "restconf", "gnmi"),
        "ports": {161, 162, 830, 9339},
        "source_types": ("nmap", "network_device"),
    },
    "Monitoring, Logging & Security": {
        "services": (
            "syslog", "zabbix", "nagios", "nrpe", "splunk", "beats",
            "kibana", "prometheus", "grafana",
        ),
        "ports": {514, 5044, 5601, 5666, 6514, 9090, 10050, 10051},
        "source_types": ("nmap",),
    },
    "VPN & Tunneling": {
        "services": ("isakmp", "ike", "ipsec", "openvpn", "wireguard", "pptp", "l2tp", "sstp"),
        "ports": {500, 1194, 1701, 1723, 4500, 51820},
        "source_types": ("nmap", "network_device"),
    },
    "Proxies, Gateways & Load Balancers": {
        "services": ("socks", "squid", "http-proxy", "haproxy", "load balancer", "reverse proxy"),
        "ports": {1080, 3128},
        "source_types": ("nmap",),
    },
    "Email & Messaging": {
        "services": (
            "smtp", "submission", "pop3", "imap", "amqp", "rabbitmq",
            "kafka", "xmpp",
        ),
        "ports": {25, 110, 143, 465, 587, 993, 995, 5222, 5269, 5671, 5672, 9092},
        "source_types": ("nmap",),
    },
    "Virtualization & Containers": {
        "services": (
            "vmware", "vcenter", "docker", "kubernetes", "kube", "libvirt",
            "proxmox", "openstack",
        ),
        "ports": {902, 903, 2375, 2376, 6443, 8006, 10250, 16509},
        "source_types": ("nmap",),
    },
    "Backup & Storage": {
        "services": ("iscsi", "ndmp", "bacula", "veeam", "backup", "storage"),
        "ports": {3260, 9101, 9102, 9103, 10000},
        "source_types": ("nmap",),
    },
    "Development & Automation": {
        "services": ("git", "svn", "jenkins", "gitea", "gitlab", "artifactory", "nexus repository"),
        "ports": {3690, 9418},
        "source_types": ("nmap",),
    },
    "Time Synchronization": {
        "services": ("ntp", "ptp", "precision time"),
        "ports": {123, 319, 320},
        "source_types": ("nmap",),
    },
    "Voice, Video & Collaboration": {
        "services": ("sip", "h323", "rtsp", "mgcp", "voip"),
        "ports": {554, 1720, 2427, 2727, 5060, 5061},
        "source_types": ("nmap",),
    },
    "Printing & Imaging": {
        "services": ("ipp", "printer", "jetdirect", "pdl-datastream", "lpd"),
        "ports": {515, 631, 9100},
        "source_types": ("nmap",),
    },
    "Discovery & Device Advertisement": {
        "services": ("ssdp", "upnp", "ws-discovery", "slp", "mdns"),
        "ports": {427, 1900, 3702, 5353},
        "source_types": ("nmap",),
    },
    "IoT & Building Automation": {
        "services": ("mqtt", "coap", "bacnet", "home assistant", "building automation"),
        "ports": {1883, 5683, 5684, 8883, 47808},
        "source_types": ("nmap",),
    },
    "Industrial / OT": {
        "services": (
            "modbus", "dnp3", "ethernet-ip", "enip", "s7", "opcua",
            "bacnet", "iec-104", "fox",
        ),
        "ports": {102, 502, 1911, 2404, 4840, 20000, 44818, 47808},
        "source_types": ("nmap",),
    },
    "Routing & Network Control Plane": {
        "services": ("bgp", "ospf", "rip", "bfd", "ldp", "isis", "vrrp"),
        "ports": {179, 520, 521, 646, 3784, 3785},
        "source_types": ("nmap", "network_device"),
    },
    "Firewall, NAT & Policy": {
        "services": ("firewall", "pfsense", "opnsense", "pan-os", "fortigate", "cisco asa"),
        "ports": set(),
        "source_types": ("network_device",),
    },
}

# CATEGORY_RULES remains as a compatibility alias for older integrations while
# the analyst-facing language uses datasets.
CATEGORY_RULES = DATASET_RULES
OTHER_DATASET = "Unknown / Other Exposed Service"
DATASET_ORDER = (*DATASET_RULES.keys(), OTHER_DATASET)
CATEGORY_ORDER = DATASET_ORDER
STATE_ORDER = ("exposed", "inferred", "observed", "correlated", "configuration")
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


def _configured_subnet(node: dict) -> str:
    """Choose the most relevant configured network for a topology device."""
    try:
        management_ip = ipaddress.ip_address(str(node.get("ip") or ""))
    except ValueError:
        management_ip = None
    networks = []
    for interface in node.get("interfaces") or []:
        try:
            network = ipaddress.ip_interface(str(interface.get("address") or "")).network
        except ValueError:
            continue
        if network.is_loopback:
            continue
        networks.append(network)
    if not networks:
        return "Unmapped"
    containing = [
        network for network in networks
        if management_ip and management_ip.version == network.version and management_ip in network
    ]
    return str(max(containing, key=lambda network: network.prefixlen) if containing else networks[0])


def _configuration_categories(node: dict) -> list[tuple[str, list[str]]]:
    """Map explicit retained device roles to non-port configuration evidence."""
    role = str(node.get("role") or "").strip().lower()
    interfaces = len(node.get("interfaces") or [])
    routes = len(node.get("routes") or [])
    categories = []
    if role == "router":
        basis = ["retained device configuration identifies a router"]
        if interfaces:
            basis.append(f"{interfaces} configured interface{'s' if interfaces != 1 else ''}")
        if routes:
            basis.append(f"{routes} retained route{'s' if routes != 1 else ''}")
        categories.append(("Routing & Network Control Plane", basis))
    if role == "firewall":
        basis = ["retained device configuration identifies a firewall"]
        if interfaces:
            basis.append(f"{interfaces} configured interface{'s' if interfaces != 1 else ''}")
        categories.append(("Firewall, NAT & Policy", basis))
    return categories


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
        ("Authentication", "Authentication server"),
        ("Directory & Identity", "Identity server"),
        ("Databases & Data Stores", "Database server"),
        ("Email & Messaging", "Messaging server"), ("File Sharing", "File server"),
        ("File Transfer", "File-transfer host"),
        ("Virtualization & Containers", "Virtualization host"),
        ("Printing & Imaging", "Printer"),
        ("Industrial / OT", "Industrial / OT device"),
        ("IoT & Building Automation", "IoT / building device"),
        ("Network Management", "Network device"),
        ("Web Applications & APIs", "Web host"),
        ("Remote Access & Administration", "Remote-access host"),
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
        ip_sort_key(item.get("ip") or item.get("hostname")),
        CATEGORY_ORDER.index(item["category"]),
        int(item.get("port") or 0),
        item.get("protocol") or "",
    ))
    hosts.sort(key=lambda item: ip_sort_key(item.get("ip") or item.get("hostname")))
    category_counts = Counter(item["category"] for item in findings)
    state_counts = Counter(
        state for item in findings for state in item["evidence_states"]
    )
    active_datasets = [
        {"name": name, "finding_count": category_counts.get(name, 0)}
        for name in DATASET_ORDER
        if category_counts.get(name)
    ]
    return {
        "status": "hunting_complete",
        "source": source,
        "host_count": len(hosts),
        "nmap_host_count": sum(
            1 for item in hosts if item.get("evidence_origin") != "configuration_only"
        ),
        "configuration_device_count": sum(
            1 for item in hosts if item.get("has_configuration_evidence")
        ),
        "configuration_only_device_count": sum(
            1 for item in hosts if item.get("evidence_origin") == "configuration_only"
        ),
        "hosts_with_findings_count": sum(
            1 for item in hosts if item.get("finding_count")
        ),
        "finding_count": len(findings),
        "nonstandard_finding_count": sum(
            1 for item in findings if item["nonstandard_port"]
        ),
        "datasets": active_datasets,
        "categories": active_datasets,
        "dataset_catalog": [
            {
                "name": name,
                "active": bool(category_counts.get(name)),
                "finding_count": category_counts.get(name, 0),
                "source_types": list(
                    DATASET_RULES.get(name, {}).get("source_types", ("nmap",))
                ),
            }
            for name in DATASET_ORDER
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
        "category": OTHER_DATASET,
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
            "evidence_origin": "nmap",
            "has_configuration_evidence": False,
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


def correlate_hunting_identity(
    result: dict, topology: dict, *, include_configuration_devices: bool = False
) -> dict:
    """Add attributable topology identity without replacing direct scan evidence."""
    nodes_by_ip = {}
    for node in topology.get("nodes") or []:
        for value in [node.get("ip"), *(node.get("addresses") or [])]:
            if value:
                nodes_by_ip[str(value)] = node

    hosts = [dict(item) for item in result.get("hosts") or []]
    hosts_by_key = {}
    hosts_by_ip = {}
    for host in hosts:
        key = str(host.get("host_key") or "")
        hosts_by_key[key] = host
        if host.get("ip"):
            hosts_by_ip[str(host["ip"])] = host
        direct_mac = str(host.get("mac") or "").strip()
        if direct_mac:
            source_ref = next(iter(host.get("source_refs") or []), {})
            host["mac_provenance"] = {
                "indirect": False,
                "origin": "Selected Nmap scan",
                "source_kind": "nmap",
                "source_label": source_ref.get("label") or "Selected Nmap XML",
                "source_url": source_ref.get("url"),
                "timestamp": host.get("last_observed"),
                "detail": "MAC address reported directly in the selected Nmap evidence.",
            }
        node = nodes_by_ip.get(str(host.get("ip") or ""))
        if not node:
            continue
        if not host.get("hostname") and node.get("hostname"):
            host["hostname"] = node["hostname"]
        if not host.get("vendor") and node.get("vendor"):
            host["vendor"] = node["vendor"]
        if not host.get("os") and node.get("os"):
            host["os"] = node["os"]
        role = str(node.get("role") or "").strip()
        if role and host.get("device_type") in {None, "", "Unclassified"}:
            host["device_type"] = role.replace("_", " ").title()
        if direct_mac:
            continue
        observations = [
            item for item in (node.get("mac_observations") or []) if item.get("mac")
        ]
        observations.sort(
            key=lambda item: (
                item.get("source_kind") == "arp_neighbor_table",
                item.get("source_kind") in {
                    "device_configuration", "configuration_output", "lldp_cdp_neighbor",
                },
                item.get("last_observed") or "",
            ),
            reverse=True,
        )
        if not observations:
            continue
        observation = observations[0]
        host["mac"] = observation.get("mac")
        if not host.get("vendor") and observation.get("vendor"):
            host["vendor"] = observation["vendor"]
        is_neighbor = observation.get("source_kind") == "arp_neighbor_table"
        detail_parts = [
            "MAC address was correlated by IP and was not reported in the selected Nmap scan.",
            f"Protocol: {observation.get('protocol')}" if observation.get("protocol") else None,
            f"Interface: {observation.get('interface')}" if observation.get("interface") else None,
            f"Segment: {observation.get('segment')}" if observation.get("segment") else None,
        ]
        host["mac_provenance"] = {
            "indirect": True,
            "origin": (
                "Router/firewall neighbor table" if is_neighbor
                else "Other retained topology evidence"
            ),
            "source_kind": observation.get("source_kind"),
            "source_label": observation.get("source_label") or "Saved topology evidence",
            "source_url": observation.get("source_url"),
            "timestamp": observation.get("last_observed"),
            "detail": " ".join(item for item in detail_parts if item),
        }

    findings = []
    for item in result.get("findings") or []:
        finding = dict(item)
        identity = hosts_by_key.get(str(finding.get("host_key") or ""), {})
        for field in ("hostname", "mac", "vendor", "device_type", "mac_provenance"):
            if identity.get(field) not in (None, "", {}):
                finding[field] = identity[field]
        findings.append(finding)

    if include_configuration_devices:
        for node in topology.get("nodes") or []:
            if node.get("kind") != "device":
                continue
            configuration_sources = [
                dict(item) for item in (node.get("sources") or [])
                if item.get("kind") in {"device_configuration", "configuration_output"}
            ]
            if not configuration_sources:
                continue
            addresses = [
                str(value) for value in [node.get("ip"), *(node.get("addresses") or [])]
                if value
            ]
            host = next((hosts_by_ip[value] for value in addresses if value in hosts_by_ip), None)
            role = str(node.get("role") or "network_device").strip()
            timestamp = max(
                (str(item.get("timestamp") or "") for item in configuration_sources),
                default="",
            ) or None
            if host is None:
                host_key = f"configuration:{node.get('id') or node.get('ip') or node.get('hostname')}"
                os_name = str(node.get("os") or "").strip()
                os_filter = os_name if os_name.lower() not in UNKNOWN_IDENTITY else "Unclassified"
                host = {
                    "host_key": host_key,
                    "ip": node.get("ip"),
                    "hostname": node.get("hostname") or node.get("label"),
                    "mac": node.get("mac"),
                    "vendor": node.get("vendor"),
                    "os": node.get("os"),
                    "os_group": "Network device",
                    "os_filter": os_filter,
                    "subnet": _configured_subnet(node),
                    "device_type": role.replace("_", " ").title(),
                    "categories": [],
                    "protocols": ["configuration"],
                    "services": [],
                    "nonstandard_port": False,
                    "capability_states": ["configuration"],
                    "finding_count": 0,
                    "evidence_origin": "configuration_only",
                    "has_configuration_evidence": True,
                    "source_refs": configuration_sources,
                    "last_observed": timestamp,
                }
                hosts.append(host)
                hosts_by_key[host_key] = host
                for value in addresses:
                    hosts_by_ip[value] = host
            else:
                host["has_configuration_evidence"] = True
                host["evidence_origin"] = "nmap_and_configuration"
                known_urls = {item.get("url") for item in host.get("source_refs") or []}
                host.setdefault("source_refs", []).extend(
                    item for item in configuration_sources if item.get("url") not in known_urls
                )
                if timestamp and timestamp > str(host.get("last_observed") or ""):
                    host["last_observed"] = timestamp

            configuration_findings = []
            for category, basis in _configuration_categories(node):
                configuration_findings.append({
                    "host_key": host["host_key"],
                    "ip": host.get("ip"),
                    "hostname": host.get("hostname"),
                    "mac": host.get("mac"),
                    "vendor": host.get("vendor"),
                    "os": host.get("os"),
                    "os_group": host.get("os_group"),
                    "os_filter": host.get("os_filter"),
                    "subnet": host.get("subnet"),
                    "device_type": host.get("device_type"),
                    "protocol": "configuration",
                    "port": None,
                    "state": "retained",
                    "service": f"{role.replace('_', ' ')} configuration",
                    "product": node.get("vendor"),
                    "version": None,
                    "outlier": False,
                    "category": category,
                    "capability_state": "configuration",
                    "evidence_states": ["configuration"],
                    "evidence_kind": "device_configuration",
                    "standard_port": False,
                    "nonstandard_port": False,
                    "match_basis": basis,
                    "source_refs": configuration_sources,
                    "last_observed": timestamp,
                })
            findings.extend(configuration_findings)
            if configuration_findings:
                categories = set(host.get("categories") or [])
                categories.update(item["category"] for item in configuration_findings)
                host["categories"] = sorted(
                    categories, key=lambda item: CATEGORY_ORDER.index(item)
                )
                host["finding_count"] = int(host.get("finding_count") or 0) + len(configuration_findings)
                if "configuration" not in (host.get("capability_states") or []):
                    host.setdefault("capability_states", []).append("configuration")
        for finding in findings:
            identity = hosts_by_key.get(str(finding.get("host_key") or ""), {})
            for field in ("evidence_origin", "has_configuration_evidence"):
                if field in identity:
                    finding[field] = identity[field]
    return _summarize_hunting(
        hosts,
        findings,
        source=result.get("source") or {},
        warnings=list(result.get("warnings") or []),
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
