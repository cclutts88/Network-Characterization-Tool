from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.poc import (
    FallbackDecision,
    apply_fping_fallback,
    build_execution_phases,
    build_nmap_argv,
    build_nmap_execution_argv,
    merge_nmap_xml,
)
from app.scan_profiles import build_nmap_flags, build_phase_nmap_flags, scan_display_name


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


def test_generated_nmap_command_enables_real_host_progress_statistics():
    command = build_nmap_argv(
        "Standard",
        "eth0",
        include_no_strike=False,
        scan_options={"protocol": "tcp", "tcp_scope": "common"},
    )

    assert command[command.index("--stats-every") + 1] == "2s"
    assert "-n" in command


def test_linux_nmap_execution_uses_a_terminal_and_preserves_exit_status():
    command = ["nmap", "-n", "-iL", "targets.txt", "-oX", "scan.xml"]

    execution = build_nmap_execution_argv(command, platform_name="posix")

    assert execution[:4] == ["script", "--quiet", "--return", "--flush"]
    assert execution[-1] == "/dev/null"
    assert "nmap -n -iL targets.txt -oX scan.xml" in execution
    assert build_nmap_execution_argv(command, platform_name="nt") == command


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


def test_split_protocol_phases_allow_independent_top_port_counts_and_bound_udp():
    settings = {
        "protocol": "tcp_udp",
        "tcp_scope": "top_1000",
        "udp_scope": "top_100",
        "service_detection": True,
        "os_detection": True,
        "timing": "fast",
    }
    tcp = build_phase_nmap_flags(settings, "tcp", pre_discovered=True)
    udp = build_phase_nmap_flags(settings, "udp", pre_discovered=True)

    assert tcp[tcp.index("--top-ports") + 1] == "1000"
    assert "-Pn" in tcp
    assert udp[udp.index("--top-ports") + 1] == "100"
    assert "-Pn" in udp
    assert "-O" not in udp
    assert "--version-light" in udp
    assert udp[udp.index("--max-retries") + 1] == "1"
    assert udp[udp.index("--host-timeout") + 1] == "3m"


def test_combined_workflow_builds_tcp_then_udp_with_separate_evidence():
    phases = build_execution_phases(
        "eth0",
        {
            "protocol": "tcp_udp",
            "tcp_scope": "common",
            "udp_scope": "common",
        },
        include_no_strike=True,
        target_file="discovery-alive.txt",
        pre_discovered=True,
    )

    assert [item["name"] for item in phases] == ["tcp", "udp"]
    assert phases[0]["xml_filename"] == "tcp-scan.xml"
    assert phases[1]["xml_filename"] == "udp-scan.xml"
    assert phases[0]["command_argv"][phases[0]["command_argv"].index("-iL") + 1] == "discovery-alive.txt"
    assert "--excludefile" in phases[1]["command_argv"]


def test_tcp_and_udp_xml_merge_preserves_both_protocols(tmp_path):
    tcp_xml = tmp_path / "tcp.xml"
    udp_xml = tmp_path / "udp.xml"
    merged_xml = tmp_path / "scan.xml"
    tcp_xml.write_text(
        '<nmaprun scanner="nmap"><scaninfo type="syn" protocol="tcp"/><host><status state="up"/><address addr="192.0.2.10" addrtype="ipv4"/><ports><port protocol="tcp" portid="443"><state state="open"/></port></ports></host><runstats><finished time="1"/><hosts up="1" down="0" total="1"/></runstats></nmaprun>',
        encoding="utf-8",
    )
    udp_xml.write_text(
        '<nmaprun scanner="nmap"><scaninfo type="udp" protocol="udp"/><host><status state="up"/><address addr="192.0.2.10" addrtype="ipv4"/><ports><port protocol="udp" portid="53"><state state="open"/></port></ports></host><runstats><finished time="2"/><hosts up="1" down="0" total="1"/></runstats></nmaprun>',
        encoding="utf-8",
    )

    assert merge_nmap_xml([tcp_xml, udp_xml], merged_xml) == 1
    text = merged_xml.read_text(encoding="utf-8")
    assert 'protocol="tcp" portid="443"' in text
    assert 'protocol="udp" portid="53"' in text


def test_approved_fping_fallback_scans_the_full_approved_scope():
    manifest = {
        "profile": "Custom",
        "interface": "eth0",
        "no_strike": ["192.0.2.3/32"],
        "profile_settings": {
            "protocol": "tcp",
            "tcp_scope": "common",
            "discovery_mode": "fping",
        },
    }

    apply_fping_fallback(manifest)

    command = manifest["command_argv"]
    assert command[command.index("-iL") + 1] == "targets.txt"
    assert command[command.index("--excludefile") + 1] == "no-strike.txt"
    assert "-n" in command
    assert command[command.index("--stats-every") + 1] == "2s"
    assert manifest["execution_command_argv"][0] == (
        "script" if __import__("os").name == "posix" else "nmap"
    )
    assert manifest["discovery_fallback_used"] is True
    assert "discovery_note" not in manifest


def test_fallback_decision_requires_identity_and_audit_note():
    decision = FallbackDecision(
        decision="approve",
        decided_by="  Mission Partner  ",
        authorization_note="  Approval reference 17  ",
    )
    assert decision.decided_by == "Mission Partner"
    assert decision.authorization_note == "Approval reference 17"

    with pytest.raises(ValueError):
        FallbackDecision(
            decision="approve", decided_by="   ", authorization_note="approval"
        )
    with pytest.raises(ValueError):
        FallbackDecision(
            decision="decline", decided_by="Operator", authorization_note="   "
        )
    with pytest.raises(ValueError):
        FallbackDecision(
            decision="automatic", decided_by="Operator", authorization_note="none"
        )


def test_human_friendly_manual_and_scheduled_names():
    when = datetime(2026, 9, 9, 14, 30, tzinfo=timezone.utc)
    assert scan_display_name("DMZ Baseline", when=when) == "DMZ_Baseline_2026-09-09_1430"
    assert scan_display_name("DMZ Baseline", scheduled=True, when=when) == "DMZ_Baseline_(S)_2026-09-09_1430"
