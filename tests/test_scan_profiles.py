from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.scan_profiles import build_nmap_flags, scan_display_name


@pytest.mark.parametrize(
    ("options", "required"),
    [
        ({"protocol": "tcp", "tcp_scope": "top_1000"}, {"-n", "-sS", "--top-ports"}),
        ({"protocol": "udp", "udp_scope": "top_100"}, {"-n", "-sU", "--top-ports"}),
        (
            {
                "protocol": "tcp_udp",
                "tcp_scope": "ics",
                "udp_scope": "ics",
                "timing": "conservative",
            },
            {"-n", "-sS", "-sU", "-p", "-T2"},
        ),
    ],
)
def test_every_scan_mode_preserves_required_n(options, required):
    flags = build_nmap_flags(options)
    assert required.issubset(set(flags))
    assert flags.count("-n") == 1


def test_combined_scan_uses_independent_protocol_port_scopes():
    flags = build_nmap_flags(
        {"protocol": "tcp_udp", "tcp_scope": "ics", "udp_scope": "ics"}
    )
    expression = flags[flags.index("-p") + 1]
    assert expression.startswith("T:")
    assert ",U:" in expression
    assert "502" in expression
    assert "47808" in expression


def test_fping_and_traceroute_options_are_retained_without_losing_required_n():
    flags = build_nmap_flags(
        {
            "protocol": "tcp_udp",
            "tcp_scope": "common",
            "udp_scope": "ics",
            "discovery_mode": "fping",
            "traceroute": True,
        }
    )
    assert "-n" in flags
    assert "-Pn" in flags
    assert "--traceroute" in flags


def test_combined_top_port_counts_are_rejected_instead_of_misrepresented():
    with pytest.raises(ValueError, match="independently"):
        build_nmap_flags(
            {"protocol": "tcp_udp", "tcp_scope": "top_1000", "udp_scope": "top_100"}
        )


def test_human_friendly_manual_and_scheduled_names():
    when = datetime(2026, 9, 9, 14, 30, tzinfo=timezone.utc)
    assert scan_display_name("DMZ Baseline", when=when) == "DMZ_Baseline_2026-09-09_1430"
    assert scan_display_name("DMZ Baseline", scheduled=True, when=when) == "DMZ_Baseline_(S)_2026-09-09_1430"
