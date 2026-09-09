from __future__ import annotations

from app.comparison import (
    compare_analyses,
    coverage_warnings,
    effective_scope,
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


def test_coverage_changes_are_explicit_warnings():
    before = {"protocols": ["TCP"], "tcp_scope": "common", "profile_id": "mission", "profile_version": 1}
    after = {"protocols": ["TCP", "UDP"], "tcp_scope": "common", "udp_scope": "ics", "profile_id": "mission", "profile_version": 2}

    warnings = coverage_warnings(before, after)

    assert any("Protocols differ" in warning for warning in warnings)
    assert any("UDP port scope differs" in warning for warning in warnings)
    assert any("Profile version differs" in warning for warning in warnings)


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

    assert result["summary"]["ports_added"] == 1
    assert result["summary"]["ports_removed"] == 1
    assert "mac" in changed["identity_changes"]
    assert changed["route_change"] is not None
