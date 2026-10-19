from __future__ import annotations

import pytest

from app.comparison import (
    ComparisonLimitExceeded,
    compare_analyses,
    coverage_warnings,
    describe_run_group,
    effective_scope,
    merge_analyses,
    select_same_scope_baseline,
)


def run(
    run_id: str,
    created_at: str,
    targets: list[str],
    *,
    status: str = "completed",
    batch: str | None = None,
    chunk: int | None = None,
    no_strike: list[str] | None = None,
) -> dict:
    return {
        "run_id": run_id,
        "name": run_id,
        "display_name": run_id,
        "created_at": created_at,
        "completed_at": created_at,
        "status": status,
        "schedule_batch_id": batch,
        "chunk_number": chunk,
        "targets": targets,
        "no_strike": no_strike or [],
        "coverage": {"targets": targets, "no_strike": no_strike or []},
        "_comparison_xml_available": True,
    }


def test_effective_scope_matches_chunked_and_unchunked_targets_after_exclusions():
    manual = [run("a" * 32, "2026-09-09T10:00:00+00:00", ["192.0.2.0/24"], no_strike=["192.0.2.9"])]
    chunked = [
        run(
            "b" * 32,
            "2026-09-09T11:00:00+00:00",
            [str(address) for address in range_start("192.0.2.0", 0, 128) if address != "192.0.2.9"],
            batch="c" * 32,
            chunk=1,
            no_strike=["192.0.2.9/32"],
        ),
        run(
            "d" * 32,
            "2026-09-09T11:01:00+00:00",
            list(range_start("192.0.2.0", 128, 256)),
            batch="c" * 32,
            chunk=2,
            no_strike=["192.0.2.9/32"],
        ),
    ]

    first = effective_scope(manual)
    second = effective_scope(chunked)

    assert first["fingerprint"] == second["fingerprint"]
    assert first["address_count"] == 255
    assert second["address_count"] == 255


def range_start(network: str, start: int, stop: int):
    import ipaddress

    base = int(ipaddress.ip_address(network))
    for offset in range(start, stop):
        yield str(ipaddress.ip_address(base + offset))


def test_baseline_is_latest_completed_same_scope_not_latest_global_run():
    old_match = run("1" * 32, "2026-09-09T10:00:00+00:00", ["198.51.100.0/24"])
    newer_match = run("2" * 32, "2026-09-09T11:00:00+00:00", ["198.51.100.0/25", "198.51.100.128/25"])
    unrelated_latest = run("3" * 32, "2026-09-09T12:00:00+00:00", ["203.0.113.0/24"])
    current = run("4" * 32, "2026-09-09T13:00:00+00:00", ["198.51.100.0/24"])

    selected = select_same_scope_baseline(
        current["run_id"], [current, unrelated_latest, newer_match, old_match]
    )

    assert selected["status"] == "baseline_found"
    assert selected["baseline"]["run_ids"] == [newer_match["run_id"]]


def test_chunked_schedule_batch_is_compared_as_one_scan():
    baseline_batch = "a" * 32
    current_batch = "b" * 32
    manifests = [
        run("1" * 32, "2026-09-09T10:00:00+00:00", ["10.0.0.0/25"], batch=baseline_batch, chunk=1),
        run("2" * 32, "2026-09-09T10:01:00+00:00", ["10.0.0.128/25"], batch=baseline_batch, chunk=2),
        run("3" * 32, "2026-09-09T12:00:00+00:00", ["10.0.0.0/25"], batch=current_batch, chunk=1),
        run("4" * 32, "2026-09-09T12:01:00+00:00", ["10.0.0.128/25"], batch=current_batch, chunk=2),
    ]

    selected = select_same_scope_baseline("4" * 32, manifests)

    assert selected["baseline"]["chunk_count"] == 2
    assert selected["current"]["chunk_count"] == 2
    assert selected["current"]["scope"]["targets"] == ["10.0.0.0/24"]


def test_legacy_chunk_names_are_collapsed_to_one_readable_group_name():
    manifests = [
        {
            **run("1" * 32, "2026-09-09T10:00:00+00:00", ["10.0.0.0/25"], batch="a" * 32, chunk=1),
            "display_name": "DMZ_Baseline_Chunk_1_of_2_(S)_2026-09-09_1000",
        },
        {
            **run("2" * 32, "2026-09-09T10:01:00+00:00", ["10.0.0.128/25"], batch="a" * 32, chunk=2),
            "display_name": "DMZ_Baseline_Chunk_2_of_2_(S)_2026-09-09_1001",
        },
    ]

    description = describe_run_group(manifests)

    assert description["display_name"] == "DMZ_Baseline_(S)_2026-09-09_1000"


def test_group_description_exposes_human_reference_context():
    manifests = [{
        **run("1" * 32, "2026-09-09T10:00:00+00:00", ["10.0.0.0/24"]),
        "name": "DMZ Baseline",
        "display_name": "DMZ_Baseline_(S)_2026-09-09_1000",
        "scheduled": True,
        "manual_targets": ["192.0.2.10"],
        "saved_networks": [{
            "saved_network_id": "dmz",
            "name": "Operations DMZ",
            "cidr": "10.0.0.0/24",
        }],
    }]

    description = describe_run_group(manifests)

    assert description["name"] == "DMZ Baseline"
    assert description["scheduled"] is True
    assert description["saved_networks"][0]["name"] == "Operations DMZ"
    assert description["manual_targets"] == ["192.0.2.10"]


def test_chunked_analysis_retains_full_summary_and_merged_coverage():
    first = {
        "scanner": "nmap", "started": "start-1", "finished": "finish-1",
        "reported_total": 1, "reported_up_count": 1, "assumed_up_count": 0, "warnings": [],
        "coverage": {
            "protocols": ["TCP"], "scan_types": [], "target_arguments": ["10.0.0.1"],
            "command": "nmap -n 10.0.0.1", "dns_resolution_disabled": True,
            "traceroute": False, "timing": "-T3",
        },
        "hosts": [{
            "ip": "10.0.0.1", "state": "up", "os_group": "Linux Server", "mac": "",
            "ports": [{"protocol": "tcp", "port": 22, "state": "open", "service": "ssh"}],
            "observed_ports": [{"protocol": "tcp", "port": 22, "state": "open", "service": "ssh"}],
        }],
    }
    second = {
        **first, "started": "start-2", "finished": "finish-2",
        "reported_up_count": 2, "assumed_up_count": 1,
        "coverage": {**first["coverage"], "target_arguments": ["10.0.0.2"], "command": "nmap -n 10.0.0.2"},
        "hosts": [{
            "ip": "10.0.0.2", "state": "up", "os_group": "Linux Server", "mac": "00:11:22:33:44:55",
            "ports": [{"protocol": "tcp", "port": 443, "state": "open", "service": "https"}],
            "observed_ports": [{"protocol": "tcp", "port": 443, "state": "open", "service": "https"}],
        }],
    }

    merged = merge_analyses([first, second])

    assert merged["host_count"] == 2
    assert merged["up_count"] == 2
    assert merged["reported_up_count"] == 3
    assert merged["assumed_up_count"] == 1
    assert merged["mac_count"] == 1
    assert merged["started"] == "start-1"
    assert merged["finished"] == "finish-2"
    assert merged["coverage"]["target_arguments"] == ["10.0.0.1", "10.0.0.2"]
    assert merged["os_groups"][0]["host_count"] == 2
    assert len(merged["os_groups"][0]["outlying_ports"]) == 2


def test_coverage_changes_are_explicit_warnings():
    before = {"protocols": ["TCP"], "tcp_scope": "common", "profile_id": "mission", "profile_version": 1}
    after = {"protocols": ["TCP", "UDP"], "tcp_scope": "common", "udp_scope": "ics", "profile_id": "mission", "profile_version": 2}

    warnings = coverage_warnings(before, after)

    assert any("Protocols differ" in warning for warning in warnings)
    assert any("UDP port scope differs" in warning for warning in warnings)
    assert any("Profile version differs" in warning for warning in warnings)


def test_merged_host_retains_only_coverage_from_xmls_where_it_appeared():
    tcp_coverage = {
        "protocols": ["TCP"],
        "scan_types": [{"type": "syn", "protocol": "TCP", "services": "22"}],
    }
    udp_coverage = {
        "protocols": ["UDP"],
        "scan_types": [{"type": "udp", "protocol": "UDP", "services": "53"}],
    }
    shared = {
        "ip": "10.0.0.10", "state": "up", "os_group": "Unclassified",
        "ports": [], "observed_ports": [], "scan_coverages": [tcp_coverage],
    }
    first = {"hosts": [shared], "coverage": tcp_coverage, "warnings": []}
    second = {
        "hosts": [
            {**shared, "scan_coverages": [udp_coverage]},
            {**shared, "ip": "10.0.0.20", "scan_coverages": [udp_coverage]},
        ],
        "coverage": udp_coverage,
        "warnings": [],
    }

    merged = merge_analyses([first, second])

    by_ip = {item["ip"]: item for item in merged["hosts"]}
    assert by_ip["10.0.0.10"]["scan_coverages"] == [tcp_coverage, udp_coverage]
    assert by_ip["10.0.0.20"]["scan_coverages"] == [udp_coverage]


def test_xml_coverage_warnings_include_targets_and_exact_port_sets():
    warnings = coverage_warnings(
        {
            "target_arguments": ["192.0.2.0/24"],
            "protocols": ["TCP"],
            "scan_types": [{"protocol": "TCP", "services": "22,80"}],
        },
        {
            "target_arguments": ["192.0.2.0/25"],
            "protocols": ["TCP"],
            "scan_types": [{"protocol": "TCP", "services": "22,443"}],
        },
    )

    assert any("Scan targets differ" in warning for warning in warnings)
    assert any("TCP port coverage differs" in warning for warning in warnings)


def test_comparison_surfaces_ports_identity_mac_and_route_evidence():
    before = {"hosts": [{
        "ip": "192.0.2.10", "hostname": "plc-a", "state": "up",
        "mac": "00:11:22:33:44:55", "vendor": "Old Vendor", "os": "Linux",
        "ports": [{"protocol": "tcp", "port": 80, "state": "open", "service": "http", "product": "nginx", "version": "1"}],
        "trace": {"port": "80", "protocol": "tcp", "hops": [{"ttl": 1, "ip": "192.0.2.1", "hostname": "gw"}]},
    }]}
    after = {"hosts": [{
        "ip": "192.0.2.10", "hostname": "plc-a", "state": "up",
        "mac": "00:11:22:33:44:66", "vendor": "New Vendor", "os": "Linux",
        "ports": [{"protocol": "tcp", "port": 443, "state": "open", "service": "https", "product": "nginx", "version": "2"}],
        "trace": {"port": "443", "protocol": "tcp", "hops": [{"ttl": 1, "ip": "192.0.2.254", "hostname": "new-gw"}]},
    }]}

    result = compare_analyses(before, after)
    changed = result["hosts_changed"][0]

    assert result["summary"]["ports_added"] == 0
    assert result["summary"]["ports_removed"] == 0
    assert result["summary"]["ports_not_assessed"] == 2
    assert "mac" in changed["identity_changes"]
    assert changed["route_change"] is not None


def test_traceroute_metadata_does_not_create_a_path_change():
    before = {"hosts": [{
        "ip": "192.0.2.10",
        "trace": {
            "port": "80", "protocol": "tcp",
            "hops": [{"ttl": 1, "ip": "192.0.2.1", "hostname": "gateway.local"}],
        },
    }]}
    after = {"hosts": [{
        "ip": "192.0.2.10",
        "trace": {
            "port": "443", "protocol": "udp",
            "hops": [{"ttl": "1", "ip": "192.0.2.1", "hostname": "GATEWAY"}],
        },
    }]}

    result = compare_analyses(before, after)

    assert result["summary"]["route_changes"] == 0
    assert result["summary"]["routes_not_assessed"] == 0
    assert result["hosts_changed"] == []
    assert result["path_assessments_not_assessed"] == []


@pytest.mark.parametrize("before_trace,after_trace", [
    (None, {"hops": [{"ttl": 1, "ip": "192.0.2.1"}]}),
    ({"hops": [{"ttl": 1, "ip": "192.0.2.1"}]}, None),
    (
        {"hops": [{"ttl": 1, "ip": "192.0.2.1"}]},
        {"hops": [{"ttl": 1, "ip": ""}, {"ttl": 2, "ip": "192.0.2.2"}]},
    ),
])
def test_missing_or_incomplete_traceroute_is_not_assessed(
    before_trace, after_trace,
):
    before = {"hosts": [{"ip": "192.0.2.10", "trace": before_trace}]}
    after = {"hosts": [{"ip": "192.0.2.10", "trace": after_trace}]}

    result = compare_analyses(before, after)

    assert result["summary"]["route_changes"] == 0
    assert result["summary"]["routes_not_assessed"] == 1
    assert result["hosts_changed"] == []
    assessment = result["path_assessments_not_assessed"][0]["route_assessment"]
    assert assessment["classification"] == "not_assessed"
    assert "cannot determine whether the route changed" in assessment["reason"]


def test_hosts_without_requested_or_retained_traceroute_do_not_create_path_rows():
    before = {"coverage": {"traceroute": False}, "hosts": [{"ip": "192.0.2.10"}]}
    after = {"coverage": {"traceroute": False}, "hosts": [{"ip": "192.0.2.10"}]}

    result = compare_analyses(before, after)

    assert result["summary"]["routes_not_assessed"] == 0
    assert result["path_assessments_not_assessed"] == []


def test_requested_traceroute_without_retained_paths_is_not_assessed():
    before = {"coverage": {"traceroute": True}, "hosts": [{"ip": "192.0.2.10"}]}
    after = {"coverage": {"traceroute": True}, "hosts": [{"ip": "192.0.2.10"}]}

    result = compare_analyses(before, after)

    assert result["summary"]["routes_not_assessed"] == 1
    assert result["path_assessments_not_assessed"][0]["ip"] == "192.0.2.10"


@pytest.mark.parametrize("invalid_hops", [
    [{"ttl": 1, "ip": "192.0.2.1"}, {"ttl": 3, "ip": "192.0.2.3"}],
    [{"ttl": 1, "ip": "192.0.2.1"}, {"ttl": 1, "ip": "192.0.2.2"}],
    [{"ttl": 0, "ip": "192.0.2.1"}],
    [{"ttl": 2, "ip": "192.0.2.2"}, {"ttl": 1, "ip": "192.0.2.1"}],
    [{"ttl": 1, "ip": "not-an-address"}],
])
def test_invalid_or_noncontiguous_traceroute_is_not_assessed(invalid_hops):
    before = {"hosts": [{"ip": "192.0.2.10", "trace": {"hops": invalid_hops}}]}
    after = {"hosts": [{
        "ip": "192.0.2.10",
        "trace": {"hops": [{"ttl": 1, "ip": "192.0.2.1"}]},
    }]}

    result = compare_analyses(before, after)

    assert result["summary"]["route_changes"] == 0
    assert result["summary"]["routes_not_assessed"] == 1


def test_equivalent_ipv6_hop_spellings_are_the_same_path():
    before = {"hosts": [{
        "ip": "2001:db8::10",
        "trace": {"hops": [{"ttl": 1, "ip": "2001:0db8:0:0:0:0:0:1"}]},
    }]}
    after = {"hosts": [{
        "ip": "2001:db8::10",
        "trace": {"hops": [{"ttl": "1", "ip": "2001:db8::1"}]},
    }]}

    result = compare_analyses(before, after)

    assert result["summary"]["route_changes"] == 0
    assert result["summary"]["routes_not_assessed"] == 0


def test_path_not_assessed_rows_obey_host_detail_limit():
    hosts = [{"ip": f"10.0.{index // 256}.{index % 256}"} for index in range(2001)]
    before = {"coverage": {"traceroute": True}, "hosts": hosts}
    after = {"coverage": {"traceroute": True}, "hosts": hosts}

    with pytest.raises(ComparisonLimitExceeded):
        compare_analyses(before, after, max_host_details=2000)


def test_comparison_distinguishes_port_state_changes_and_links_evidence():
    before_evidence = {"label": "Earlier", "sources": [{"label": "Earlier XML", "url": "/before.xml"}]}
    after_evidence = {"label": "Later", "sources": [{"label": "Later XML", "url": "/after.xml"}]}
    before = {"hosts": [{
        "ip": "198.51.100.10",
        "ports": [{"protocol": "tcp", "port": 443, "state": "open"}],
        "observed_ports": [{"protocol": "tcp", "port": 443, "state": "open", "reason": "syn-ack"}],
    }]}
    after = {"hosts": [{
        "ip": "198.51.100.10",
        "ports": [],
        "observed_ports": [{"protocol": "tcp", "port": 443, "state": "filtered", "reason": "no-response"}],
    }]}

    result = compare_analyses(
        before, after,
        before_evidence=before_evidence,
        after_evidence=after_evidence,
    )

    changed = result["hosts_changed"][0]
    assert result["summary"]["port_state_changes"] == 1
    assert changed["port_state_changes"][0]["before"] == "open"
    assert changed["port_state_changes"][0]["after"] == "filtered"
    assert changed["service_changes"][0]["changed_fields"] == ["state", "reason"]
    assert changed["evidence"]["before"]["sources"][0]["url"] == "/before.xml"


def coverage(protocol: str, ports: str, *, successful: bool = True) -> dict:
    values = [int(value) for value in ports.split(",")]
    return {
        "protocols": [protocol.upper()],
        "completion": {"successful": successful},
        "scan_types": [{
            "protocol": protocol.upper(), "services": ports,
            "service_list_exact": True,
            "service_intervals": [{"start": value, "end": value} for value in values],
        }],
    }


def test_comparison_requires_explicit_later_state_before_no_longer_observed():
    before = {
        "coverage": coverage("tcp", "22,80"),
        "hosts": [{
            "ip": "192.0.2.10",
            "observed_ports": [
                {"protocol": "tcp", "port": 22, "state": "open", "service": "ssh"},
                {"protocol": "tcp", "port": 80, "state": "open", "service": "http"},
            ],
        }],
    }
    narrower = {
        "coverage": coverage("tcp", "22"),
        "hosts": [{
            "ip": "192.0.2.10",
            "observed_ports": [
                {"protocol": "tcp", "port": 22, "state": "open", "service": "ssh"},
            ],
        }],
    }
    result = compare_analyses(before, narrower)
    changed = result["hosts_changed"][0]
    omitted = next(item for item in changed["port_deltas"] if item["port"] == 80)
    assert omitted["classification"] == "not_assessed"
    assert result["summary"]["ports_removed"] == 0
    assert result["summary"]["ports_not_assessed"] == 1

    explicit_closed = {
        "coverage": coverage("tcp", "22,80"),
        "hosts": [{
            "ip": "192.0.2.10",
            "observed_ports": [
                {"protocol": "tcp", "port": 22, "state": "open", "service": "ssh"},
                {"protocol": "tcp", "port": 80, "state": "closed", "service": "http"},
            ],
        }],
    }
    closed = compare_analyses(before, explicit_closed)
    delta = next(item for item in closed["hosts_changed"][0]["port_deltas"] if item["port"] == 80)
    assert delta["classification"] == "no_longer_observed"
    assert closed["summary"]["ports_removed"] == 1


def test_comparison_exposes_protocol_coverage_without_claiming_device_identity():
    before = {
        "coverage": coverage("tcp", "443"),
        "hosts": [{"ip": "192.0.2.10", "mac": "00:11:22:33:44:55", "observed_ports": []}],
    }
    after = {
        "coverage": coverage("udp", "53"),
        "hosts": [{"ip": "192.0.2.10", "mac": "00:11:22:33:44:66", "observed_ports": []}],
    }
    result = compare_analyses(before, after)
    by_protocol = {item["protocol"]: item for item in result["protocol_deltas"]}
    assert by_protocol["tcp"]["classification"] == "not_assessed_later"
    assert by_protocol["udp"]["classification"] == "newly_assessed"
    assert "mac" in result["hosts_changed"][0]["identity_changes"]


@pytest.mark.parametrize("scenario", ["added", "removed", "changed"])
def test_comparison_stops_oversized_port_details_during_construction(scenario):
    ports = [
        {"protocol": "tcp", "port": port, "state": "open", "service": "test"}
        for port in range(1, 10_002)
    ]
    large_host = {"ip": "192.0.2.10", "observed_ports": ports}
    if scenario == "added":
        before, after = {"hosts": []}, {"hosts": [large_host]}
    elif scenario == "removed":
        before, after = {"hosts": [large_host]}, {"hosts": []}
    else:
        before, after = {"hosts": [large_host]}, {"hosts": [large_host]}
    with pytest.raises(ComparisonLimitExceeded):
        compare_analyses(before, after, max_port_details=10_000)
