from __future__ import annotations

import ipaddress
import os
import stat
import xml.etree.ElementTree as ET
from pathlib import Path


MAX_LIVE_XML_BYTES = 8 * 1024 * 1024
MAX_LIVE_HOSTS = 512
MAX_LIVE_ROWS = 2000
LIVE_PHASE_FILES = (
    ("discovery", "discovery.xml"),
    ("tcp", "tcp-scan.xml"),
    ("udp", "udp-scan.xml"),
)


class UnsafeLiveScanPath(ValueError):
    """Raised when an active run folder cannot be opened without following links."""


def _closed_host_fragments(data: bytes):
    """Yield only complete Nmap host elements from a possibly unfinished XML file."""
    cursor = 0
    while True:
        start = data.find(b"<host", cursor)
        if start < 0:
            return
        marker_end = start + len(b"<host")
        if marker_end < len(data) and data[marker_end : marker_end + 1] not in b" \t\r\n>":
            cursor = marker_end
            continue
        end = data.find(b"</host>", marker_end)
        if end < 0:
            return
        yield data[start : end + len(b"</host>")]
        cursor = end + len(b"</host>")


def _directory_fd(path: Path) -> int:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise UnsafeLiveScanPath("The active scan folder is unsafe or unavailable") from exc
    try:
        if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise UnsafeLiveScanPath("The active scan folder is not a directory")
    except Exception:
        os.close(descriptor)
        raise
    return descriptor


def _bounded_file_bytes(directory_fd: int, filename: str, max_bytes: int) -> tuple[bytes, bool]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(filename, flags, dir_fd=directory_fd)
    except OSError:
        return b"", False
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            return b"", False
        truncated = metadata.st_size > max_bytes
        if truncated:
            os.lseek(descriptor, metadata.st_size - max_bytes, os.SEEK_SET)
        chunks: list[bytes] = []
        remaining = max_bytes
        while remaining > 0:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks), truncated
    finally:
        os.close(descriptor)


def _host_address(host: ET.Element) -> str | None:
    fallback = None
    for address in host.findall("address"):
        value = (address.get("addr") or "").strip()
        if not value:
            continue
        if address.get("addrtype") in {"ipv4", "ipv6"}:
            return value
        fallback = fallback or value
    return fallback


def _host_name(host: ET.Element) -> str | None:
    hostname = host.find("hostnames/hostname")
    value = (hostname.get("name") if hostname is not None else "") or ""
    return value.strip() or None


def _service_label(service: ET.Element | None) -> str | None:
    if service is None:
        return None
    fields = []
    for name in ("name", "product", "version", "extrainfo"):
        value = (service.get(name) or "").strip()
        if value and value not in fields:
            fields.append(value)
    return " · ".join(fields) or None


def _address_sort_key(value: str) -> tuple:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return (1, 0, value.casefold())
    return (0, address.version, int(address))


def live_scan_discoveries(
    run_dir: Path,
    *,
    max_bytes_per_file: int = MAX_LIVE_XML_BYTES,
    max_hosts: int = MAX_LIVE_HOSTS,
    max_rows: int = MAX_LIVE_ROWS,
) -> dict:
    """Read bounded provisional rows from fully closed hosts in active Nmap XML."""
    rows: list[dict] = []
    host_keys: set[tuple[str, str | None]] = set()
    row_keys: set[tuple[str, str, int | None, str, str | None]] = set()
    sources: list[dict] = []
    parse_errors = 0
    truncated = False
    directory_fd = _directory_fd(run_dir)
    try:
        for phase, filename in LIVE_PHASE_FILES:
            data, file_truncated = _bounded_file_bytes(
                directory_fd, filename, max_bytes_per_file
            )
            if not data:
                continue
            truncated = truncated or file_truncated
            source_rows = 0
            source_hosts: set[tuple[str, str | None]] = set()
            for fragment in _closed_host_fragments(data):
                try:
                    host = ET.fromstring(fragment)
                except ET.ParseError:
                    parse_errors += 1
                    continue
                address = _host_address(host)
                if not address:
                    continue
                hostname = _host_name(host)
                host_key = (address, hostname)
                host_keys.add(host_key)
                source_hosts.add(host_key)
                ports = host.findall("ports/port")
                if not ports:
                    key = (address, "", None, "responsive", None)
                    if key not in row_keys:
                        row_keys.add(key)
                        rows.append({
                            "address": address,
                            "hostname": hostname,
                            "protocol": None,
                            "port": None,
                            "state": "responsive",
                            "service": None,
                            "phase": phase,
                        })
                        source_rows += 1
                    continue
                for port in ports:
                    state_node = port.find("state")
                    state = ((state_node.get("state") if state_node is not None else "") or "unknown").strip()
                    if state == "closed":
                        continue
                    protocol = (port.get("protocol") or "").strip().lower()
                    try:
                        port_number = int(port.get("portid") or "")
                    except ValueError:
                        port_number = None
                    service = _service_label(port.find("service"))
                    key = (address, protocol, port_number, state, service)
                    if key in row_keys:
                        continue
                    row_keys.add(key)
                    rows.append({
                        "address": address,
                        "hostname": hostname,
                        "protocol": protocol or None,
                        "port": port_number,
                        "state": state,
                        "service": service,
                        "phase": phase,
                    })
                    source_rows += 1
                    if len(rows) >= max_rows:
                        truncated = True
                        break
                if len(rows) >= max_rows or len(host_keys) >= max_hosts:
                    truncated = True
                    break
            sources.append({
                "phase": phase,
                "filename": filename,
                "bytes_read": len(data),
                "file_truncated": file_truncated,
                "hosts": len(source_hosts),
                "rows": source_rows,
            })
            if len(rows) >= max_rows or len(host_keys) >= max_hosts:
                break
    finally:
        os.close(directory_fd)

    rows.sort(key=lambda item: (
        _address_sort_key(item["address"]),
        item["protocol"] or "",
        item["port"] if item["port"] is not None else -1,
        item["phase"],
    ))
    return {
        "provisional": True,
        "host_count": len(host_keys),
        "row_count": len(rows),
        "rows": rows,
        "sources": sources,
        "truncated": truncated,
        "parse_errors": parse_errors,
    }
