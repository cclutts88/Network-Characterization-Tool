"""Verified Nmap XML adapter for the internal scoped endpoint store."""
from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
import hashlib
import ipaddress
import os
from pathlib import Path
import re
import shlex
import stat

from defusedxml import ElementTree as ET
from defusedxml.common import DefusedXmlException

from app.artifacts import (
    artifact_root_for,
    canonical_artifact_path,
    get_artifact_observation,
)
from app.entities import PreparedAssessment, persist_prepared_assessment, prepare_assessment
from app.nmap_presence import nmap_host_presence


NMAP_ENDPOINT_PARSER = "nmap-endpoints:1"
MAX_NMAP_XML_BYTES = 100 * 1024 * 1024
SUPPORTED_TRANSPORTS = {"tcp", "udp", "sctp"}


def nmap_xml_coverage(root: ET.Element) -> dict:
    arguments = root.get("args", "")
    try:
        argument_tokens = shlex.split(arguments)
    except ValueError:
        argument_tokens = arguments.split()
    scan_types = []
    protocols: list[str] = []
    for info in root.findall("scaninfo"):
        protocol = (info.get("protocol") or "").upper()
        if protocol and protocol not in protocols:
            protocols.append(protocol)
        scan_types.append({
            "type": info.get("type", ""), "protocol": protocol,
            "services": info.get("services", ""),
            "service_count": int(info.get("numservices", "0") or 0),
        })
    if not protocols:
        if "-sU" in argument_tokens:
            protocols.append("UDP")
        if any(flag in argument_tokens for flag in ("-sS", "-sT", "-sA")):
            protocols.append("TCP")
    command_tokens = argument_tokens[1:] if (
        argument_tokens and argument_tokens[0].lower().endswith("nmap")
    ) else argument_tokens
    # Nmap has a large option grammar that changes across versions. Values for an
    # unknown option are indistinguishable from targets in the flattened `args`
    # string. Only claim positional targets when there are no options to interpret.
    targets = sorted(command_tokens) if all(
        not token.startswith("-") for token in command_tokens
    ) else None
    return {
        "source": "nmap_xml", "protocols": protocols, "scan_types": scan_types,
        "command": arguments,
        "timing": next((t for t in argument_tokens if re.fullmatch(r"-T[0-5]", t)), None),
        "dns_resolution_disabled": "-n" in argument_tokens,
        "traceroute": "--traceroute" in argument_tokens,
        "target_arguments": targets,
        "target_arguments_basis": (
            "unambiguous positional arguments" if targets is not None
            else "unknown because Nmap option values cannot be separated safely"
        ),
    }


def _epoch(raw: str | None) -> dict:
    result = {"raw": raw, "utc": None, "valid": False}
    if raw is None:
        return result
    try:
        value = Decimal(raw)
        if not value.is_finite() or value < 0:
            return result
        result["utc"] = datetime.fromtimestamp(float(value), timezone.utc).isoformat()
        result["valid"] = True
    except (InvalidOperation, OverflowError, OSError, ValueError):
        pass
    return result


def _invalidate_time(value: dict, conflict: str) -> None:
    value["utc"] = None
    value["valid"] = False
    value["conflict"] = conflict


def _epoch_value(value: dict) -> Decimal:
    return Decimal(value["raw"])


def _time_window(start_raw: str | None, end_raw: str | None, *,
                 outer_start: dict | None = None,
                 outer_end: dict | None = None) -> tuple[dict, dict]:
    start, end = _epoch(start_raw), _epoch(end_raw)
    if start["valid"] and end["valid"] and _epoch_value(end) < _epoch_value(start):
        _invalidate_time(start, "window end precedes start")
        _invalidate_time(end, "window end precedes start")
        return start, end
    if start["valid"] and outer_start and outer_start["valid"] and (
            _epoch_value(start) < _epoch_value(outer_start)):
        _invalidate_time(start, "host start precedes scan start")
    if start["valid"] and outer_end and outer_end["valid"] and (
            _epoch_value(start) > _epoch_value(outer_end)):
        _invalidate_time(start, "host start follows scan end")
    if end["valid"] and outer_start and outer_start["valid"] and (
            _epoch_value(end) < _epoch_value(outer_start)):
        _invalidate_time(end, "host end precedes scan start")
    if end["valid"] and outer_end and outer_end["valid"] and (
            _epoch_value(end) > _epoch_value(outer_end)):
        _invalidate_time(end, "host end follows scan end")
    return start, end


def _verified_xml(db_path: Path, observation_id: str) -> tuple[dict, bytes]:
    observation = get_artifact_observation(db_path, observation_id)
    if observation is None:
        raise ValueError("Artifact observation does not exist")
    if observation["size_bytes"] > MAX_NMAP_XML_BYTES:
        raise ValueError("Nmap XML exceeds the verified adapter size limit")
    expected = canonical_artifact_path(artifact_root_for(db_path), observation["sha256"])
    registered = Path(observation["canonical_path"])
    if registered.resolve() != expected.resolve() or registered.is_symlink():
        raise ValueError("Artifact observation does not reference its canonical file")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(registered, flags)
        with os.fdopen(descriptor, "rb") as source:
            before = os.fstat(source.fileno())
            if not stat.S_ISREG(before.st_mode):
                raise ValueError("Canonical artifact is not a regular file")
            if before.st_size > MAX_NMAP_XML_BYTES:
                raise ValueError("Nmap XML exceeds the verified adapter size limit")
            if before.st_size != observation["size_bytes"]:
                raise ValueError("Canonical artifact failed content verification")
            content = source.read(MAX_NMAP_XML_BYTES + 1)
            after = os.fstat(source.fileno())
    except ValueError:
        raise
    except OSError as exc:
        raise ValueError("Canonical artifact is unavailable") from exc
    if len(content) > MAX_NMAP_XML_BYTES:
        raise ValueError("Nmap XML exceeds the verified adapter size limit")
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
            before.st_ctime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
            after.st_ctime_ns):
        raise ValueError("Canonical artifact changed while being read")
    if (len(content) != observation["size_bytes"]
            or hashlib.sha256(content).hexdigest() != observation["sha256"]):
        raise ValueError("Canonical artifact failed content verification")
    return observation, content


def _service_facts(port: ET.Element, locator: str) -> dict:
    state = port.find("state")
    service = port.find("service")
    return {
        "extraction_locator": locator,
        "state": dict(sorted(state.attrib.items())) if state is not None else {},
        "service": dict(sorted(service.attrib.items())) if service is not None else {},
        "scripts": [dict(sorted(script.attrib.items())) for script in port.findall("script")],
    }


def _host_facts(host: ET.Element, locator: str, coverage: dict,
                scan_start: dict, scan_end: dict) -> dict:
    status = host.find("status")
    if status is None:
        presence, presence_detail = "unknown", "Nmap host status is missing"
    else:
        presence, presence_detail = nmap_host_presence(host)
    addresses = [dict(sorted(node.attrib.items())) for node in host.findall("address")]
    hostnames = [dict(sorted(node.attrib.items())) for node in host.findall("./hostnames/hostname")]
    host_start, host_end = _time_window(
        host.get("starttime"), host.get("endtime"),
        outer_start=scan_start, outer_end=scan_end,
    )
    return {
        "extraction_locator": locator,
        "status": dict(sorted(status.attrib.items())) if status is not None else {},
        "presence": {"classification": presence, "detail": presence_detail},
        "addresses": addresses,
        "hostnames": hostnames,
        "os_matches": [dict(sorted(node.attrib.items())) for node in host.findall("./os/osmatch")],
        "evidence_time": {
            "host_start": host_start,
            "host_end": host_end,
            "scan_start": scan_start,
            "scan_end": scan_end,
            "precision": "nmap epoch seconds when valid",
        },
        "coverage_ref": "assessment",
    }


def prepare_nmap_observation(
    db_path: Path, *, observation_id: str, scope_id: str,
    parser_version: str = NMAP_ENDPOINT_PARSER,
) -> tuple[PreparedAssessment, dict]:
    """Verify, parse, validate and freeze one scoped Nmap assessment.

    The caller asserts that the entire artifact belongs to `scope_id`. No Saved
    Network, CIDR, filename or command target is used to infer identity.
    """
    if not isinstance(scope_id, str) or not scope_id.strip() or scope_id != scope_id.strip():
        raise ValueError("scope_id must be a nonblank, trimmed string")
    observation, content = _verified_xml(db_path, observation_id)
    try:
        root = ET.fromstring(content)
    except (ET.ParseError, DefusedXmlException) as exc:
        raise ValueError(f"Invalid Nmap XML: {exc}") from exc
    if root.tag != "nmaprun":
        raise ValueError("Artifact root is not <nmaprun>")

    coverage = nmap_xml_coverage(root)
    finished = root.find("./runstats/finished")
    scan_start, scan_end = _time_window(
        root.get("start"), finished.get("time") if finished is not None else None,
    )
    hosts = []
    for host_index, host in enumerate(root.findall("host"), start=1):
        host_locator = f"./host[{host_index}]"
        services = []
        for port_index, port in enumerate(host.findall("./ports/port"), start=1):
            protocol = (port.get("protocol") or "").strip().lower()
            if protocol not in SUPPORTED_TRANSPORTS:
                raise ValueError(f"Unsupported Nmap transport protocol: {protocol or 'missing'}")
            try:
                port_id = int(port.get("portid", ""))
            except ValueError as exc:
                raise ValueError("Invalid Nmap port number") from exc
            locator = f"{host_locator}/ports/port[{port_index}]"
            services.append({"protocol": protocol, "port": port_id,
                             "facts": _service_facts(port, locator)})
        facts = _host_facts(host, host_locator, coverage, scan_start, scan_end)
        for address_node in host.findall("address"):
            if address_node.get("addrtype") not in {"ipv4", "ipv6"}:
                continue
            raw_address = address_node.get("addr", "")
            try:
                address = str(ipaddress.ip_address(raw_address))
            except ValueError as exc:
                raise ValueError(f"Invalid Nmap IP address: {raw_address}") from exc
            hosts.append({"address": address, "facts": facts, "services": services})

    assessed_at = scan_end["utc"] if scan_end["valid"] else None
    prepared = prepare_assessment(
        scope_id=scope_id, artifact_observation_id=observation_id,
        parser_version=parser_version, assessed_at=assessed_at,
        time_basis="nmap runstats finished epoch" if assessed_at else None,
        assessment_facts={
            "adapter": "nmap_xml", "scope_assignment": "explicit_whole_artifact",
            "artifact_sha256": observation["sha256"],
            "source_kind": observation["source_kind"],
            "source_ref": observation["source_ref"],
            "coverage": coverage, "scan_start": scan_start, "scan_end": scan_end,
        },
        hosts=hosts,
    )
    return prepared, {
        "assessment_id": prepared.assessment_id,
        "scope_id": scope_id,
        "artifact_observation_id": observation_id,
        "parser_version": parser_version,
        "address_count": len(hosts),
        "service_receipt_count": sum(len(host["services"]) for host in hosts),
        "assessed_at": assessed_at,
    }


def ingest_nmap_observation(db_path: Path, *, observation_id: str, scope_id: str) -> dict:
    """Translate one verified observation into one caller-selected scope.

    This low-level internal adapter remains unwired. New assigned ingestion must use
    the assignment coordinator so scope cannot be supplied independently.
    """
    prepared, result = prepare_nmap_observation(
        db_path, observation_id=observation_id, scope_id=scope_id,
    )
    persist_prepared_assessment(db_path, prepared)
    return result
