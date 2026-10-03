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


NMAP_ENDPOINT_PARSER = "nmap-endpoints:2"
NMAP_COVERAGE_CONTRACT = "nmap-coverage:1"
MAX_NMAP_XML_BYTES = 100 * 1024 * 1024
SUPPORTED_TRANSPORTS = {"tcp", "udp", "sctp"}


def _service_intervals(raw: str, declared_count: int, protocol: str) -> dict:
    """Normalize an Nmap scaninfo service list without expanding large ranges."""
    intervals: list[dict[str, int]] = []
    reasons: list[str] = []
    for token in str(raw or "").split(","):
        token = token.strip()
        if not token:
            continue
        if ":" in token:
            prefix, token = (part.strip() for part in token.rsplit(":", 1))
            expected = {"tcp": {"t", "tcp"}, "udp": {"u", "udp"},
                        "sctp": {"s", "sctp"}}.get(protocol.lower(), set())
            if prefix.lower() not in expected:
                reasons.append(f"service-list prefix {prefix} does not match {protocol}")
                continue
        match = re.fullmatch(r"(\d+)(?:\s*-\s*(\d+))?", token)
        if match is None:
            reasons.append(f"unrecognized service-list token: {token}")
            continue
        start = int(match.group(1))
        end = int(match.group(2) or start)
        if start < 0 or end > 65535 or end < start:
            reasons.append(f"invalid service-list range: {token}")
            continue
        intervals.append({"start": start, "end": end})
    intervals.sort(key=lambda item: (item["start"], item["end"]))
    merged: list[dict[str, int]] = []
    for interval in intervals:
        if merged and interval["start"] <= merged[-1]["end"] + 1:
            merged[-1]["end"] = max(merged[-1]["end"], interval["end"])
        else:
            merged.append(dict(interval))
    normalized_count = sum(item["end"] - item["start"] + 1 for item in merged)
    if normalized_count != declared_count:
        reasons.append(
            f"service-list count {normalized_count} does not match declared count {declared_count}"
        )
    return {
        "intervals": merged,
        "normalized_count": normalized_count,
        "exact": not reasons and declared_count > 0,
        "reasons": reasons,
    }


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
        try:
            declared_count = int(info.get("numservices", "0") or 0)
        except ValueError:
            declared_count = 0
        service_list = _service_intervals(
            info.get("services", ""), declared_count, protocol,
        )
        scan_types.append({
            "type": info.get("type", ""), "protocol": protocol,
            "services": info.get("services", ""),
            "service_count": declared_count,
            "service_intervals": service_list["intervals"],
            "service_list_exact": service_list["exact"],
            "service_list_reasons": service_list["reasons"],
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
    finished = root.find("./runstats/finished")
    finish_exit = finished.get("exit") if finished is not None else None
    source_kind = root.get("nct_source")
    phase_count_raw = root.get("nct_phase_count")
    phase_count = None
    provenance_reasons = []
    if source_kind == "protocol-phase-merge":
        try:
            phase_count = int(phase_count_raw or "")
            if phase_count < 1:
                raise ValueError
        except ValueError:
            provenance_reasons.append("NCT phase count is missing or invalid")
    elif source_kind is not None:
        provenance_reasons.append(f"unknown NCT source composition: {source_kind}")
    elif phase_count_raw is not None:
        provenance_reasons.append("NCT phase count is present without source composition")
    composition = {
        "kind": source_kind or "native_or_unmarked",
        "phase_count": phase_count,
        "timing_attribution": (
            "invalid_merge_provenance" if provenance_reasons
            else "ambiguous_across_phases" if phase_count is not None and phase_count > 1
            else "single_run_or_phase"
        ),
        "provenance_valid": not provenance_reasons,
        "reasons": provenance_reasons,
    }
    return {
        "source": "nmap_xml", "protocols": protocols, "scan_types": scan_types,
        "coverage_contract": NMAP_COVERAGE_CONTRACT,
        "completion": {
            "finished_present": finished is not None,
            "exit": finish_exit,
            "successful": finish_exit == "success",
            "reason": (
                "Nmap recorded a successful finished state" if finish_exit == "success"
                else "Nmap did not record a successful finished state"
            ),
        },
        "source_composition": composition,
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


def _port_in_intervals(port: int, intervals: list[dict]) -> bool:
    return any(int(item.get("start", 0)) <= port <= int(item.get("end", -1))
               for item in intervals)


def _host_port_coverage(host: ET.Element, coverage: dict, presence: str,
                        host_start: dict, host_end: dict) -> dict:
    explicit_by_protocol: dict[str, list[int]] = {}
    for port in host.findall("./ports/port"):
        protocol = (port.get("protocol") or "").strip().lower()
        try:
            port_id = int(port.get("portid", ""))
        except ValueError:
            continue
        if protocol and 0 <= port_id <= 65535:
            explicit_by_protocol.setdefault(protocol, []).append(port_id)
    extraports = []
    extraports_valid = True
    for node in host.findall("./ports/extraports"):
        state = (node.get("state") or "").strip()
        if not state:
            extraports_valid = False
        count_raw = node.get("count")
        count_valid = True
        try:
            if not re.fullmatch(r"\d+", count_raw or ""):
                raise ValueError
            count = int(count_raw)
        except ValueError:
            count = 0
            count_valid = False
            extraports_valid = False
        reason_rows = [dict(sorted(item.attrib.items()))
                       for item in node.findall("extrareasons")]
        reason_total = 0
        reason_counts_valid = True
        for reason in reason_rows:
            try:
                reason_count = int(reason.get("count", ""))
                if reason_count < 0:
                    raise ValueError
                reason_total += reason_count
            except ValueError:
                reason_counts_valid = False
        if reason_rows and (not reason_counts_valid or reason_total != count):
            extraports_valid = False
        extraports.append({
            "state": state,
            "count": count,
            "count_raw": count_raw,
            "reasons": reason_rows,
            "reason_count_total": reason_total if reason_rows else None,
            "valid": bool(state) and count_valid and (
                not reason_rows or (reason_counts_valid and reason_total == count)
            ),
        })
    aggregate_count = sum(item["count"] for item in extraports)
    scan_types = coverage.get("scan_types") or []
    protocol_counts: dict[str, int] = {}
    for item in scan_types:
        protocol = str(item.get("protocol") or "").lower()
        if protocol:
            protocol_counts[protocol] = protocol_counts.get(protocol, 0) + 1
    results = {}
    for item in scan_types:
        protocol = str(item.get("protocol") or "").lower()
        if not protocol or protocol in results:
            continue
        base_reasons = []
        if not coverage.get("completion", {}).get("successful"):
            base_reasons.append("source run did not record successful completion")
        if presence != "confirmed":
            base_reasons.append(f"host presence is {presence}, not confirmed")
        if protocol_counts.get(protocol) != 1:
            base_reasons.append("multiple scan sections exist for this protocol")
        if not item.get("service_list_exact"):
            base_reasons.append("requested port list is not exact")
        composition = coverage.get("source_composition") or {}
        if not composition.get("provenance_valid", True):
            base_reasons.extend(composition.get("reasons") or ["source composition is invalid"])
        elif composition.get("timing_attribution") == "ambiguous_across_phases":
            base_reasons.append("source combines phases with ambiguous host timing")
        unexpected_protocols = sorted(
            set(explicit_by_protocol) - set(protocol_counts)
        )
        if unexpected_protocols:
            base_reasons.append(
                "explicit ports use protocols not declared by scaninfo: "
                + ", ".join(unexpected_protocols)
            )
        explicit_ports = explicit_by_protocol.get(protocol, [])
        requested_intervals = item.get("service_intervals") or []
        outside = sorted({port for port in explicit_ports
                          if not _port_in_intervals(port, requested_intervals)})
        if outside:
            base_reasons.append(
                "explicit ports fall outside the requested list: "
                + ", ".join(str(port) for port in outside)
            )
        omission_reasons = list(base_reasons)
        if len(protocol_counts) != 1:
            omission_reasons.append(
                "aggregate omitted-port counts cannot be assigned to one protocol"
            )
        if not extraports_valid:
            omission_reasons.append(
                "aggregate omitted-port evidence is invalid or contradictory"
            )
        explicit_count = len(explicit_ports)
        declared_count = int(item.get("service_count") or 0)
        accounted_count = explicit_count + aggregate_count if len(protocol_counts) == 1 else None
        if accounted_count is not None and accounted_count != declared_count:
            omission_reasons.append(
                f"explicit plus aggregate port count {accounted_count} does not match requested count {declared_count}"
            )
        aggregate_states = sorted({
            item["state"] for item in extraports if item.get("valid") and item.get("count", 0) > 0
        })
        state_reasons = []
        if len(aggregate_states) != 1:
            state_reasons.append(
                "aggregate omitted ports do not have one attributable reported state"
            )
        results[protocol] = {
            "requested_port_count": declared_count,
            "requested_intervals": requested_intervals,
            "explicit_port_count": explicit_count,
            "aggregate_omitted_port_count": aggregate_count if len(protocol_counts) == 1 else None,
            "accounted_port_count": accounted_count,
            "explicit_observation_eligible": not base_reasons,
            "explicit_observation_reasons": base_reasons,
            "omission_coverage_eligible": not omission_reasons,
            "reasons": omission_reasons,
            "aggregate_states": aggregate_states,
            "omitted_reported_state": aggregate_states[0] if len(aggregate_states) == 1 else None,
            "omitted_state_eligible": not omission_reasons and not state_reasons,
            "omitted_state_reasons": omission_reasons + state_reasons,
        }
    interval_reasons = []
    if not host_start.get("valid") or not host_end.get("valid"):
        interval_reasons.append("host collection start and end are not both valid")
    elif Decimal(host_start["raw"]) >= Decimal(host_end["raw"]):
        interval_reasons.append("host collection interval is empty or reversed")
    composition = coverage.get("source_composition") or {}
    if composition.get("timing_attribution") == "ambiguous_across_phases":
        interval_reasons.append("host collection interval does not cover every merged phase")
    elif not composition.get("provenance_valid", True):
        interval_reasons.extend(
            composition.get("reasons") or ["source composition is invalid"]
        )
    return {
        "contract": NMAP_COVERAGE_CONTRACT,
        "collection_interval": {
            "eligible": not interval_reasons,
            "reasons": interval_reasons,
            "start": host_start,
            "end": host_end,
        },
        "protocols": results,
        "extraports": extraports,
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
    port_coverage = _host_port_coverage(
        host, coverage, presence, host_start, host_end,
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
        "port_coverage": port_coverage,
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
    composition = coverage["source_composition"]
    if (
        observation["source_kind"] == "nmap_scan"
        and observation.get("original_filename") == "scan.xml"
        and composition["kind"] == "native_or_unmarked"
    ):
        composition.update({
            "kind": "legacy_unmarked_automated_aggregate",
            "timing_attribution": "invalid_merge_provenance",
            "provenance_valid": False,
            "reasons": [
                "legacy automated aggregate lacks phase provenance; re-run collection to create attributable coverage"
            ],
        })
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
