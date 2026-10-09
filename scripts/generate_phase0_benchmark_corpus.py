"""Build and verify the deterministic, synthetic Phase 0 benchmark corpus.

The corpus contains no captured operator or mission data and performs no network
access.  It is intentionally generated outside the application data directory so
benchmark runs can create a fresh disposable NCT installation for each revision.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import xml.etree.ElementTree as ET


GENERATOR_VERSION = "phase0-benchmark-corpus:1"
FIXED_SEED = 20261009
MANIFEST_NAME = "phase0-benchmark-manifest.json"


PRODUCTS = (
    ("OpenSSH", "9.2p1", "ssh", 22),
    ("nginx", "1.24.0", "http", 80),
    ("Apache httpd", "2.4.62", "https", 443),
    ("BIND", "9.18.28", "domain", 53),
    ("Net-SNMP", "5.9.4", "snmp", 161),
    ("PostgreSQL", "16.4", "postgresql", 5432),
    ("Redis", "7.2.5", "redis", 6379),
    ("Jetty", "12.0.12", "http-proxy", 8080),
)


def _service(protocol: str, port: int, name: str, product: str, version: str) -> dict:
    return {
        "protocol": protocol,
        "port": port,
        "name": name,
        "product": product,
        "version": version,
        "state": "open",
    }


def _host(ip: str, index: int, services: list[dict], *, trace: bool = False) -> dict:
    mac_value = (0x020000000000 + FIXED_SEED + index) & 0xFEFFFFFFFFFF
    return {
        "ip": ip,
        "hostname": f"benchmark-{index:04d}.example.invalid",
        "mac": ":".join(f"{(mac_value >> shift) & 0xff:02X}" for shift in (40, 32, 24, 16, 8, 0)),
        "services": services,
        "trace": trace,
    }


def _nmap_xml(hosts: list[dict], scan_ports: dict[str, list[int]], *, start: int) -> bytes:
    root = ET.Element("nmaprun", scanner="nmap", version="7.95", start=str(start))
    for protocol in sorted(scan_ports):
        ports = sorted(scan_ports[protocol])
        ET.SubElement(
            root,
            "scaninfo",
            type="syn" if protocol == "tcp" else "udp",
            protocol=protocol,
            numservices=str(len(ports)),
            services=",".join(str(port) for port in ports),
        )
    for item in hosts:
        node = ET.SubElement(root, "host", starttime=str(start + 1), endtime=str(start + 9))
        ET.SubElement(node, "status", state="up", reason="syn-ack", reason_ttl="64")
        ET.SubElement(node, "address", addr=item["ip"], addrtype="ipv4")
        ET.SubElement(node, "address", addr=item["mac"], addrtype="mac", vendor="NCT Synthetic")
        hostnames = ET.SubElement(node, "hostnames")
        ET.SubElement(hostnames, "hostname", name=item["hostname"], type="user")
        ports_node = ET.SubElement(node, "ports")
        for service in sorted(item["services"], key=lambda value: (value["protocol"], value["port"])):
            port_node = ET.SubElement(
                ports_node, "port", protocol=service["protocol"], portid=str(service["port"])
            )
            ET.SubElement(port_node, "state", state=service["state"], reason="syn-ack")
            ET.SubElement(
                port_node,
                "service",
                name=service["name"],
                product=service["product"],
                version=service["version"],
            )
        os_node = ET.SubElement(node, "os")
        match = ET.SubElement(os_node, "osmatch", name="Linux 6.x", accuracy="96")
        ET.SubElement(
            match, "osclass", type="general purpose", vendor="Linux", osfamily="Linux", osgen="6.X", accuracy="96"
        )
        if item["trace"]:
            trace = ET.SubElement(node, "trace", port="443", proto="tcp")
            ET.SubElement(trace, "hop", ttl="1", ipaddr="192.0.2.1", rtt="0.45", host="benchmark-gateway")
            ET.SubElement(trace, "hop", ttl="2", ipaddr=item["ip"], rtt="1.25", host=item["hostname"])
    stats = ET.SubElement(root, "runstats")
    ET.SubElement(stats, "finished", time=str(start + 10), timestr="synthetic", elapsed="10.00", exit="success")
    ET.SubElement(stats, "hosts", up=str(len(hosts)), down="0", total=str(len(hosts)))
    ET.indent(root, space="  ")
    return ET.tostring(root, encoding="utf-8", xml_declaration=True) + b"\n"


def _small_tcp() -> bytes:
    ports = [_service("tcp", 22, "ssh", "OpenSSH", "9.2p1"), _service("tcp", 443, "https", "nginx", "1.24.0")]
    hosts = [_host(f"10.10.0.{index}", index, ports[: 1 + (index % 2)], trace=index == 1) for index in range(1, 4)]
    return _nmap_xml(hosts, {"tcp": [22, 80, 443]}, start=1_800_000_000)


def _medium_udp() -> bytes:
    hosts = []
    for index in range(1, 121):
        services = [_service("udp", 53, "domain", "BIND", "9.18.28")]
        if index % 3 == 0:
            services.append(_service("udp", 161, "snmp", "Net-SNMP", "5.9.4"))
        hosts.append(_host(str(ipaddress.ip_address("10.20.0.0") + index), 1000 + index, services))
    return _nmap_xml(hosts, {"udp": [53, 67, 68, 123, 161]}, start=1_800_001_000)


def _history_pair() -> tuple[bytes, bytes]:
    scan_ports = {"tcp": [22, 80, 443, 8443], "udp": [53, 161]}
    before = []
    after = []
    for index in range(1, 65):
        ip = f"10.30.0.{index}"
        services = [
            _service("tcp", 22, "ssh", "OpenSSH", "9.2p1"),
            _service("tcp", 80, "http", "nginx", "1.24.0"),
            _service("udp", 53, "domain", "BIND", "9.18.28"),
        ]
        before.append(_host(ip, 2000 + index, services))
        if index == 64:
            continue
        next_services = [dict(value) for value in services]
        if index == 1:
            next_services[1]["version"] = "1.26.1"
        if index == 2:
            next_services.append(_service("tcp", 443, "https", "nginx", "1.26.1"))
        if index == 3:
            next_services = [value for value in next_services if value["port"] != 80]
        if index == 4:
            next_services.append(_service("udp", 161, "snmp", "Net-SNMP", "5.9.4"))
        after.append(_host(ip, 2000 + index, next_services))
    after.append(
        _host(
            "10.30.0.65",
            2065,
            [_service("tcp", 22, "ssh", "OpenSSH", "9.2p1"), _service("tcp", 443, "https", "Apache httpd", "2.4.62")],
        )
    )
    return (
        _nmap_xml(before, scan_ports, start=1_800_002_000),
        _nmap_xml(after, scan_ports, start=1_800_088_400),
    )


def _large_segments() -> dict[str, bytes]:
    files: dict[str, bytes] = {}
    for segment in range(4):
        base = ipaddress.ip_address("10.200.0.0") + segment * 4096
        hosts = []
        for index in range(1, 1001):
            product, version, name, port = PRODUCTS[(index + segment) % len(PRODUCTS)]
            protocol = "udp" if port in {53, 161} else "tcp"
            services = [_service(protocol, port, name, product, version)]
            if index % 10 == 0:
                services.append(_service("tcp", 22, "ssh", "OpenSSH", "9.2p1"))
            hosts.append(_host(str(base + index), 10_000 + segment * 1000 + index, services, trace=index % 100 == 0))
        files[f"nmap/large_segment_{segment + 1:02d}.xml"] = _nmap_xml(
            hosts,
            {"tcp": [22, 80, 443, 5432, 6379, 8080], "udp": [53, 161]},
            start=1_800_100_000 + segment * 100,
        )
    return files


def _nmap_file_oracle(content: bytes) -> dict:
    root = ET.fromstring(content)
    hosts = root.findall("host")
    ports = root.findall("./host/ports/port")
    protocols: dict[str, int] = {}
    for port in ports:
        protocol = str(port.get("protocol") or "unknown")
        protocols[protocol] = protocols.get(protocol, 0) + 1
    return {
        "hosts": len(hosts),
        "service_observations": len(ports),
        "service_observations_by_protocol": dict(sorted(protocols.items())),
        "ipv4_addresses": len(root.findall('./host/address[@addrtype="ipv4"]')),
        "mac_addresses": len(root.findall('./host/address[@addrtype="mac"]')),
        "traces": len(root.findall("./host/trace")),
        "scan_protocols": sorted(
            str(node.get("protocol")) for node in root.findall("scaninfo")
        ),
    }


def _device_files() -> dict[str, bytes]:
    router = """hostname phase0-router
interface GigabitEthernet0/0
 description ISP-A
 ip address 192.0.2.2 255.255.255.252
interface GigabitEthernet0/1
 description USERS
 ip address 10.40.0.1 255.255.255.0
ip route 0.0.0.0 0.0.0.0 GigabitEthernet0/0 192.0.2.1
ip route 10.50.0.0 255.255.0.0 GigabitEthernet0/1 10.40.0.2
Internet 10.40.0.10 2 0200.0000.0010 ARPA GigabitEthernet0/1
Device ID: phase0-access-switch
Interface: GigabitEthernet0/1, Port ID (outgoing port): GigabitEthernet1/0/48
IP address: 10.40.0.2
Platform: NCT Synthetic Switch, Capabilities: Switch IGMP
"""
    firewall = """hostname phase0-firewall
interface GigabitEthernet0/0
 description OUTSIDE
 ip address 198.51.100.2 255.255.255.252
interface GigabitEthernet0/1
 description INSIDE
 ip address 10.41.0.1 255.255.255.0
ip route 0.0.0.0 0.0.0.0 198.51.100.1
access-list OUTSIDE_IN permit tcp any host 10.41.0.10 eq 443
access-list OUTSIDE_IN deny ip any any
ip nat inside source list 1 interface GigabitEthernet0/0 overload
object network PHASE0_WEB
 host 10.41.0.10
"""
    switch = """hostname phase0-switch
vlan 10
 name USERS
vlan 20
 name SERVERS
10 USERS active GigabitEthernet1/0/1
20 SERVERS active GigabitEthernet1/0/24
interface GigabitEthernet1/0/1
 description analyst-workstation
 switchport mode access
 switchport access vlan 10
interface GigabitEthernet1/0/48
 description phase0-router
 switchport mode trunk
 switchport trunk native vlan 10
 switchport trunk allowed vlan 10,20
10 0200.0000.1010 dynamic GigabitEthernet1/0/1
20 0200.0000.2020 dynamic GigabitEthernet1/0/24
Device ID: phase0-router
Interface: GigabitEthernet1/0/48, Port ID (outgoing port): GigabitEthernet0/1
IP address: 10.40.0.1
Platform: NCT Synthetic Router, Capabilities: Router
"""
    boundary = ["hostname phase0-boundary-switch", "vlan 10", " name USERS"]
    for index in range(1, 1001):
        boundary.extend(
            [
                f"interface GigabitEthernet1/{(index - 1) // 48}/{((index - 1) % 48) + 1}",
                f" description synthetic-endpoint-{index:04d}",
                " switchport mode access",
                " switchport access vlan 10",
            ]
        )
    return {
        "devices/router.txt": router.encode(),
        "devices/firewall.txt": firewall.encode(),
        "devices/switch.txt": switch.encode(),
        "devices/switch_1000_interfaces.txt": ("\n".join(boundary) + "\n").encode(),
    }


def _enrichment_files() -> tuple[dict[str, bytes], dict]:
    rows = []
    findings = []
    for product_index in range(24):
        product = f"NCT Benchmark Product {product_index:02d}"
        version = f"{1 + product_index // 8}.{product_index % 8}.0"
        for candidate_index in range(2):
            edb_id = str(900000 + product_index * 2 + candidate_index)
            rows.append(
                {
                    "id": edb_id,
                    "file": f"exploits/{edb_id}.txt",
                    "description": f"{product} {version} synthetic candidate {candidate_index + 1}",
                    "date_published": "2026-01-01",
                    "author": "NCT benchmark",
                    "type": "remote",
                    "platform": "multiple",
                    "port": "",
                    "date_added": "2026-01-01",
                    "date_updated": "2026-01-01",
                    "verified": "1",
                    "codes": f"CVE-2026-{product_index + 1000:04d}",
                    "tags": "synthetic",
                    "aliases": "",
                    "screenshot_url": "",
                    "application_url": "",
                    "source_url": "",
                }
            )
        for occurrence in range(5):
            findings.append(
                {
                    "host_key": f"ip:10.220.{product_index}.{occurrence + 1}",
                    "ip": f"10.220.{product_index}.{occurrence + 1}",
                    "hostname": f"enrichment-{product_index:02d}-{occurrence + 1}.example.invalid",
                    "port": 10000 + product_index,
                    "protocol": "tcp",
                    "service": "benchmark",
                    "product": product,
                    "version": version,
                }
            )
    from io import StringIO

    output = StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=list(rows[0]), lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    workload = json.dumps({"findings": findings}, indent=2, sort_keys=True).encode() + b"\n"
    provider = '''#!/usr/bin/env python3
import csv
import json
from pathlib import Path
import sys

root = Path(__file__).resolve().parent
query = sys.argv[-1].casefold().split() if len(sys.argv) > 1 else []
results = []
with (root / "files_exploits.csv").open(newline="", encoding="utf-8") as source:
    for row in csv.DictReader(source):
        if query and all(token in row["description"].casefold() for token in query):
            results.append({
                "EDB-ID": row["id"],
                "Title": row["description"],
                "Platform": row["platform"],
                "Type": row["type"],
                "Codes": row["codes"],
                "Verified": row["verified"],
                "Date_Published": row["date_published"],
                "Path": str(root / row["file"]),
            })
print(json.dumps({"DB_PATH_EXPLOITS": str(root), "RESULTS_EXPLOIT": results}, sort_keys=True))
'''.encode()
    configuration = '''files_array+=("files_exploits.csv")
path_array+=("$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)")
'''.encode()
    oracle = {
        "finding_count": 120,
        "unique_product_version_queries": 24,
        "candidate_rows": 48,
        "expected_candidates_per_query": 2,
        "expected_cache_misses_first_pass": 24,
        "expected_cache_hits_second_pass": 24,
        "provider_files": ["enrichment/searchsploit", "enrichment/.searchsploit_rc"],
    }
    return {
        "enrichment/files_exploits.csv": output.getvalue().encode(),
        "enrichment/findings.json": workload,
        "enrichment/searchsploit": provider,
        "enrichment/.searchsploit_rc": configuration,
    }, oracle


def corpus_files() -> tuple[dict[str, bytes], dict]:
    before, after = _history_pair()
    enrichment, enrichment_oracle = _enrichment_files()
    files = {
        "nmap/small_tcp.xml": _small_tcp(),
        "nmap/medium_udp.xml": _medium_udp(),
        "nmap/history_before.xml": before,
        "nmap/history_before_duplicate.xml": before,
        "nmap/history_after.xml": after,
        **_large_segments(),
        **_device_files(),
        **enrichment,
    }
    nmap_oracle = {
        name: _nmap_file_oracle(content)
        for name, content in sorted(files.items())
        if name.startswith("nmap/")
    }
    device_count_defaults = {
        "applied_policy_objects": 0, "applied_policy_rules": 0,
        "command_history": 0, "command_results": 0, "commands": 0,
        "firewall_acl": 0, "interfaces": 0, "learned_macs": 0,
        "lines": 0, "nat": 0, "neighbors": 0, "network_objects": 0,
        "network_objects_total": 0, "non_nct_commands": 0,
        "policy_attachments": 0, "policy_chains": 0, "policy_rules": 0,
        "policy_set_members": 0, "policy_sets": 0, "port_channels": 0,
        "routes": 0, "running_only_config": 0, "spanning_tree": 0,
        "startup_only_config": 0, "switch_ports": 0, "switch_vlans": 0,
        "switching": 0, "topology_neighbors": 0, "vlans": 0,
    }
    device_counts = {
        "devices/router.txt": {
            **device_count_defaults, "interfaces": 2, "routes": 2,
            "neighbors": 1, "topology_neighbors": 1, "lines": 14,
        },
        "devices/firewall.txt": {
            **device_count_defaults, "applied_policy_objects": 1,
            "applied_policy_rules": 2, "firewall_acl": 2, "interfaces": 2,
            "lines": 13, "nat": 1, "network_objects": 2,
            "network_objects_total": 2, "routes": 1,
        },
        "devices/switch.txt": {
            **device_count_defaults, "interfaces": 3, "learned_macs": 2,
            "lines": 22, "switch_ports": 3, "switch_vlans": 2,
            "switching": 5, "topology_neighbors": 1, "vlans": 5,
        },
        "devices/switch_1000_interfaces.txt": {
            **device_count_defaults, "interfaces": 1000, "lines": 4003,
            "switch_ports": 1000, "switching": 2, "vlans": 2,
        },
    }
    oracle = {
        "nmap_files": nmap_oracle,
        "history": {
            "before_hosts": 64,
            "after_hosts": 64,
            "hosts_added": ["10.30.0.65"],
            "hosts_no_longer_confirmed": ["10.30.0.64"],
            "version_changes": 1,
            "ports_added": 2,
            "ports_no_longer_observed": 1,
            "exact_duplicate_files": ["nmap/history_before.xml", "nmap/history_before_duplicate.xml"],
        },
        "devices": {
            "includes": ["addresses", "routes", "firewall policy", "NAT", "VLANs", "learned MACs", "topology neighbors"],
            "parsed_counts": device_counts,
        },
        "enrichment": enrichment_oracle,
    }
    return files, oracle


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _canonical_manifest(files: dict[str, bytes], oracle: dict) -> dict:
    return {
        "schema_version": 1,
        "generator_version": GENERATOR_VERSION,
        "seed": FIXED_SEED,
        "purpose": "Synthetic local development comparison of stable main and the foundation branch",
        "data_classification": "synthetic; no operator, Range, mission, or production evidence",
        "network_access_required": False,
        "files": [
            {"path": name, "sha256": _sha256(files[name]), "size_bytes": len(files[name])}
            for name in sorted(files)
        ],
        "oracle": oracle,
        "limitations": [
            "This corpus does not establish Range or mission readiness.",
            "It does not reproduce production history, hardware, storage, or concurrency.",
            "Performance conclusions require the retained benchmark runner and exact revision records.",
        ],
    }


def generate_corpus(output_dir: Path) -> dict:
    output_dir = Path(output_dir)
    if output_dir.is_symlink() or output_dir.exists():
        raise ValueError("Output directory must not already exist; benchmark evidence is never overwritten")
    output_dir = output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    files, oracle = corpus_files()
    for relative_name in sorted(files):
        path = output_dir / Path(relative_name)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(files[relative_name])
        if relative_name == "enrichment/searchsploit" and os.name != "nt":
            path.chmod(path.stat().st_mode | 0o111)
    manifest = _canonical_manifest(files, oracle)
    (output_dir / MANIFEST_NAME).write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


def verify_corpus(output_dir: Path) -> dict:
    output_dir = output_dir.resolve()
    manifest_path = output_dir / MANIFEST_NAME
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    raw_entries = manifest.get("files")
    if not isinstance(raw_entries, list):
        raise ValueError("Corpus manifest files must be a list")
    for entry in raw_entries:
        if not isinstance(entry, dict):
            raise ValueError("Corpus manifest file entries must be objects")
        raw_relative = str(entry.get("path") or "")
        relative = PurePosixPath(raw_relative)
        if (
            "\\" in raw_relative
            or relative.is_absolute()
            or ".." in relative.parts
            or not relative.parts
            or relative.as_posix() != raw_relative
        ):
            raise ValueError("Corpus manifest contains an unsafe file path")
    expected_files, expected_oracle = corpus_files()
    expected_manifest = _canonical_manifest(expected_files, expected_oracle)
    if manifest != expected_manifest:
        raise ValueError("Corpus manifest does not match this generator's exact schema, files, hashes, and oracle")
    seen = set()
    for entry in raw_entries:
        raw_relative = str(entry.get("path") or "")
        relative = PurePosixPath(raw_relative)
        path = output_dir.joinpath(*relative.parts)
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"Corpus file is unavailable: {relative.as_posix()}")
        content = path.read_bytes()
        expected_content = expected_files[relative.as_posix()]
        if (
            content != expected_content
            or len(content) != int(entry["size_bytes"])
            or _sha256(content) != entry["sha256"]
        ):
            raise ValueError(f"Corpus file failed exact-content verification: {relative.as_posix()}")
        seen.add(relative.as_posix())
    actual_files = set()
    for path in output_dir.rglob("*"):
        if path.is_symlink():
            raise ValueError("Corpus contains a linked path")
        if path.is_file() and path != manifest_path:
            actual_files.add(path.relative_to(output_dir).as_posix())
    if actual_files != seen:
        raise ValueError("Corpus contains missing or unexpected files")
    if set(expected_files) != seen:
        raise ValueError("Corpus manifest does not contain the complete expected workload and oracle")
    return {"verified": True, "file_count": len(seen), "total_bytes": sum(item["size_bytes"] for item in manifest["files"])}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--generate", type=Path, metavar="DIR")
    mode.add_argument("--verify", type=Path, metavar="DIR")
    args = parser.parse_args()
    if args.generate:
        manifest = generate_corpus(args.generate)
        result = verify_corpus(args.generate)
        result["manifest"] = str((args.generate.resolve() / MANIFEST_NAME))
        result["generator_version"] = manifest["generator_version"]
    else:
        result = verify_corpus(args.verify)
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
