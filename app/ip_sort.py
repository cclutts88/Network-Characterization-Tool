from __future__ import annotations

import ipaddress


def ip_sort_key(value: object) -> tuple[int, int, int, int, str]:
    """Sort IPv4/IPv6 addresses and CIDRs numerically, then non-IP labels."""
    text = str(value or "").strip()
    candidate = text[3:] if text.lower().startswith("ip:") else text
    address_text, separator, prefix_text = candidate.partition("/")
    address_text = address_text.split("%", 1)[0]
    try:
        address = ipaddress.ip_address(address_text)
    except ValueError:
        return (1, 0, 0, 0, text.casefold())
    try:
        prefix = int(prefix_text) if separator else address.max_prefixlen
    except ValueError:
        prefix = address.max_prefixlen
    return (0, address.version, int(address), prefix, text.casefold())
