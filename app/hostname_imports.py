from __future__ import annotations

import csv
import io
import ipaddress
import json
import os
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path


DATA_DIR = Path(os.environ.get("ANALYZER_DATA_DIR", "/data"))
HOSTNAME_EVIDENCE_DIR = DATA_DIR / "hostname-evidence"
_SOURCES = {"dhcp", "dns"}
_IP_HEADERS = {"ip", "ip_address", "ipaddress", "address", "client_ip"}
_HOST_HEADERS = {
    "hostname", "host_name", "hostname_fqdn", "fqdn", "name", "client_name"
}
_EXPIRY_HEADERS = {
    "lease_expires_at", "lease_expiry", "lease_expiry_time", "leaseexpirytime",
    "expires", "expire", "ends",
}
_OBSERVED_HEADERS = {"observed_at", "collected_at", "timestamp"}
_HOSTNAME = re.compile(r"^[A-Za-z0-9_](?:[A-Za-z0-9_.-]{0,251}[A-Za-z0-9_])?$", re.I)
_IPV4 = r"(?:\d{1,3}\.){3}\d{1,3}"


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _safe_name(value: str, fallback: str = "hostname-evidence.txt") -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip()).strip("-._")
    return cleaned[:100] or fallback


def _normal_header(value: object) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(value or "").strip().casefold()).strip("_")


def _clean_ip(value: object) -> str | None:
    try:
        address = ipaddress.ip_address(str(value or "").strip())
    except ValueError:
        return None
    return str(address) if address.version == 4 else None


def _clean_hostname(value: object) -> str | None:
    hostname = str(value or "").strip().strip("'\"").rstrip(".")
    if not hostname or len(hostname) > 253 or not _HOSTNAME.fullmatch(hostname):
        return None
    if any(len(label) > 63 for label in hostname.split(".")):
        return None
    return hostname


def _normal_time(value: object) -> str | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    if raw.isdigit() and len(raw) >= 9:
        try:
            return datetime.fromtimestamp(int(raw), timezone.utc).isoformat()
        except (OSError, OverflowError, ValueError):
            return None
    candidate = raw.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(candidate)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc).isoformat()
    except ValueError:
        pass
    for pattern in (
        "%Y/%m/%d %H:%M:%S", "%Y-%m-%d %H:%M:%S",
        "%m/%d/%Y %H:%M:%S", "%m/%d/%Y %I:%M:%S %p",
    ):
        try:
            return datetime.strptime(raw, pattern).replace(tzinfo=timezone.utc).isoformat()
        except ValueError:
            continue
    return None


def _first(row: dict[str, str], names: set[str]) -> str:
    return next((row[name] for name in names if row.get(name)), "")


def _csv_records(text: str, filename: str) -> tuple[list[dict], list[dict]] | None:
    meaningful = [line for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")]
    if not meaningful or "," not in meaningful[0]:
        return None
    reader = csv.DictReader(io.StringIO("\n".join(meaningful)))
    if not reader.fieldnames:
        return None
    headers = {_normal_header(item) for item in reader.fieldnames}
    if not (headers & _IP_HEADERS and headers & _HOST_HEADERS):
        return None
    normalized_filename = filename.casefold()
    default_source = ""
    if "dhcp" in normalized_filename or "kea" in normalized_filename or headers & _EXPIRY_HEADERS:
        default_source = "dhcp"
    elif "dns" in normalized_filename:
        default_source = "dns"
    records: list[dict] = []
    errors: list[dict] = []
    for line_number, raw_row in enumerate(reader, start=2):
        row = {_normal_header(key): str(value or "").strip() for key, value in raw_row.items()}
        source = _normal_header(row.get("source") or default_source)
        ip = _clean_ip(_first(row, _IP_HEADERS))
        hostname = _clean_hostname(_first(row, _HOST_HEADERS))
        if source not in _SOURCES or not ip or not hostname:
            if len(errors) < 100:
                errors.append({
                    "line": line_number,
                    "reason": "expected source (dhcp or dns), IPv4 address, and hostname",
                })
            continue
        records.append({
            "source": source,
            "ip": ip,
            "hostname": hostname,
            "lease_expires_at": _normal_time(_first(row, _EXPIRY_HEADERS)),
            "observed_at": _normal_time(_first(row, _OBSERVED_HEADERS)),
            "evidence": f"Uploaded CSV line {line_number}",
        })
    return records, errors


def _dns_text_records(text: str) -> list[dict]:
    """Read A records from BIND zone text and legacy dnscmd sections."""
    records: list[dict] = []
    origin: str | None = None
    in_dns_section = False
    for line in text.splitlines():
        heading = re.match(r"^=====\s*DNS(?:\s+zone)?\s+(.+?)\s*=====\s*$", line, re.I)
        if heading:
            candidate = heading.group(1).strip()
            candidate = re.sub(r"^(?:db\.)|(?:\.zone)$", "", candidate, flags=re.I)
            origin = _clean_hostname(candidate)
            in_dns_section = True
            continue
        if line.startswith("====="):
            in_dns_section = False
            origin = None
            continue
        origin_match = re.match(r"^\s*\$ORIGIN\s+(\S+)", line, re.I)
        if origin_match:
            origin = _clean_hostname(origin_match.group(1))
            in_dns_section = True
            continue
        if not in_dns_section:
            continue
        match = re.match(
            rf"^\s*(?P<owner>\S+)\s+.*?\bA\b.*?(?P<ip>{_IPV4})\s*(?:;.*)?$",
            line,
            re.I,
        )
        if not match:
            continue
        owner = match.group("owner").strip()
        if owner == "@":
            hostname = origin
        elif owner.endswith("."):
            hostname = _clean_hostname(owner)
        elif origin and not owner.casefold().endswith(origin.casefold()):
            hostname = _clean_hostname(f"{owner}.{origin}")
        else:
            hostname = _clean_hostname(owner)
        ip = _clean_ip(match.group("ip"))
        if ip and hostname:
            records.append({
                "source": "dns",
                "ip": ip,
                "hostname": hostname,
                "lease_expires_at": None,
                "observed_at": None,
                "evidence": line.strip()[:1000],
            })
    return records


def parse_hostname_evidence_file(content: bytes, filename: str) -> dict:
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValueError("Hostname evidence files must use UTF-8 text") from exc
    if "\x00" in text:
        raise ValueError("The uploaded file does not appear to be text")
    csv_result = _csv_records(text, filename)
    if csv_result is None:
        from app.hostname_evidence import parse_retained_hostname_evidence

        records = [
            item for item in parse_retained_hostname_evidence(text)
            if item.get("source") in _SOURCES
        ]
        records.extend(_dns_text_records(text))
        errors: list[dict] = []
    else:
        records, errors = csv_result
    unique: dict[tuple[str, str, str], dict] = {}
    duplicate_count = 0
    for record in records:
        key = (record["source"], record["ip"], record["hostname"].casefold())
        if key in unique:
            duplicate_count += 1
        unique[key] = record
    if not unique:
        raise ValueError(
            "No valid DHCP or DNS hostname records were found. Use the NCT collection format shown on the Hostnames page."
        )
    ordered = sorted(unique.values(), key=lambda item: (item["ip"], item["source"], item["hostname"].casefold()))
    return {
        "records": ordered,
        "valid_count": len(ordered),
        "skipped_count": len(errors),
        "duplicate_count": duplicate_count,
        "errors": errors,
        "source_counts": {
            source: sum(record["source"] == source for record in ordered)
            for source in sorted(_SOURCES)
        },
    }


def store_hostname_evidence(
    evidence_dir: Path,
    content: bytes,
    *,
    filename: str,
    imported_by: str,
    accountability_pcap: bytes | None = None,
    accountability_filename: str | None = None,
) -> dict:
    parsed = parse_hostname_evidence_file(content, filename)
    evidence_id = uuid.uuid4().hex
    run_dir = evidence_dir / evidence_id
    run_dir.mkdir(parents=True, exist_ok=False)
    safe_filename = _safe_name(filename)
    stored_name = f"uploaded-{safe_filename}"
    (run_dir / stored_name).write_bytes(content)
    pcap_name = None
    if accountability_pcap:
        pcap_name = _safe_name(
            accountability_filename or "hostname-collection-accountability.pcap",
            "hostname-collection-accountability.pcap",
        )
        (run_dir / "accountability.pcap").write_bytes(accountability_pcap)
    imported_at = _now()
    manifest = {
        "evidence_id": evidence_id,
        "filename": safe_filename,
        "stored_name": stored_name,
        "imported_by": str(imported_by or "local operator")[:100],
        "imported_at": imported_at,
        "accountability_filename": pcap_name,
        "records": parsed["records"],
    }
    (run_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    return {
        **parsed,
        "evidence_id": evidence_id,
        "source_filename": safe_filename,
        "imported_by": manifest["imported_by"],
        "imported_at": imported_at,
        "evidence_url": f"/api/hostnames/evidence/{evidence_id}/file",
        "accountability_url": (
            f"/api/hostnames/evidence/{evidence_id}/accountability"
            if pcap_name else None
        ),
    }


def list_hostname_evidence(evidence_dir: Path = HOSTNAME_EVIDENCE_DIR) -> list[dict]:
    if not evidence_dir.exists():
        return []
    imported: list[dict] = []
    for manifest_path in evidence_dir.glob("*/manifest.json"):
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        evidence_id = str(manifest.get("evidence_id") or manifest_path.parent.name)
        for record in manifest.get("records") or []:
            if record.get("source") not in _SOURCES:
                continue
            imported.append({
                **record,
                "observed_at": record.get("observed_at") or manifest.get("imported_at"),
                "evidence_id": evidence_id,
                "evidence_label": f"{record.get('source', '').upper()} server export · {manifest.get('filename', 'uploaded evidence')}",
                "evidence_url": f"/api/hostnames/evidence/{evidence_id}/file",
                "accountability_url": (
                    f"/api/hostnames/evidence/{evidence_id}/accountability"
                    if manifest.get("accountability_filename") else None
                ),
            })
    return imported


def hostname_evidence_file(
    evidence_dir: Path, evidence_id: str
) -> tuple[Path, str] | None:
    if not re.fullmatch(r"[a-f0-9]{32}", evidence_id):
        return None
    run_dir = evidence_dir / evidence_id
    manifest_path = run_dir / "manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    stored_name = str(manifest.get("stored_name") or "")
    if not stored_name or Path(stored_name).name != stored_name:
        return None
    path = run_dir / stored_name
    if not path.is_file():
        return None
    return path, str(manifest.get("filename") or stored_name)


def hostname_accountability_file(
    evidence_dir: Path, evidence_id: str
) -> tuple[Path, str] | None:
    if not re.fullmatch(r"[a-f0-9]{32}", evidence_id):
        return None
    run_dir = evidence_dir / evidence_id
    manifest_path = run_dir / "manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    path = run_dir / "accountability.pcap"
    if not path.is_file():
        return None
    return path, str(
        manifest.get("accountability_filename")
        or "hostname-collection-accountability.pcap"
    )
