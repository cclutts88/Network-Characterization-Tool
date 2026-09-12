from __future__ import annotations

import csv
import io


HOST_SUMMARY_FIELDS = (
    "ip",
    "hostname",
    "state",
    "mac",
    "vendor",
    "os",
    "analyst_os",
    "effective_os",
    "os_disagreement",
    "os_family",
    "os_generation",
    "os_group",
    "classification_basis",
    "outlying_ports",
    "open_services",
)

PORT_LEVEL_FIELDS = (
    "ip",
    "hostname",
    "host_state",
    "mac",
    "mac_vendor",
    "protocol",
    "port",
    "port_state",
    "reason",
    "service",
    "product",
    "version",
    "detected_os",
    "analyst_os",
    "effective_os",
    "os_disagreement",
    "os_group",
    "outlier",
)


def host_summary_rows(analysis: dict) -> list[dict]:
    rows = []
    for host in analysis.get("hosts", []) or []:
        ports = host.get("ports", []) or []
        rows.append(
            {
                "ip": host.get("ip", ""),
                "hostname": host.get("hostname", ""),
                "state": host.get("state", ""),
                "mac": host.get("mac", ""),
                "vendor": host.get("vendor", ""),
                "os": host.get("os", ""),
                "analyst_os": (host.get("analyst_os_override") or {}).get("os_name", ""),
                "effective_os": host.get("effective_os", ""),
                "os_disagreement": "yes" if host.get("os_disagreement") else "no",
                "os_family": host.get("os_family", ""),
                "os_generation": host.get("os_generation", ""),
                "os_group": host.get("os_group", ""),
                "classification_basis": host.get("classification_basis", ""),
                "outlying_ports": "; ".join(
                    f"{port.get('port', '')}/{port.get('protocol', '')}"
                    for port in ports if port.get("outlier")
                ),
                "open_services": "; ".join(
                    " ".join(
                        str(value) for value in (
                            f"{port.get('port', '')}/{port.get('protocol', '')}",
                            port.get("service", ""),
                            port.get("product", ""),
                            port.get("version", ""),
                        ) if value
                    )
                    for port in ports
                ),
            }
        )
    return rows


def port_level_rows(analysis: dict) -> list[dict]:
    """Return exactly one normalized record per observed IP/protocol/port."""
    rows = []
    for host in analysis.get("hosts", []) or []:
        for port in host.get("ports", []) or []:
            rows.append(
                {
                    "ip": host.get("ip", ""),
                    "hostname": host.get("hostname", ""),
                    "host_state": host.get("state", ""),
                    "mac": host.get("mac", ""),
                    "mac_vendor": host.get("vendor", ""),
                    "protocol": port.get("protocol", ""),
                    "port": port.get("port", ""),
                    "port_state": port.get("state", "open"),
                    "reason": port.get("reason", ""),
                    "service": port.get("service", ""),
                    "product": port.get("product", ""),
                    "version": port.get("version", ""),
                    "detected_os": host.get("os", ""),
                    "analyst_os": (host.get("analyst_os_override") or {}).get("os_name", ""),
                    "effective_os": host.get("effective_os", ""),
                    "os_disagreement": "yes" if host.get("os_disagreement") else "no",
                    "os_group": host.get("os_group", ""),
                    "outlier": "yes" if port.get("outlier") else "no",
                }
            )
    return rows


def rows_to_csv(rows: list[dict], fields: tuple[str, ...]) -> bytes:
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(rows)
    return stream.getvalue().encode("utf-8-sig")
