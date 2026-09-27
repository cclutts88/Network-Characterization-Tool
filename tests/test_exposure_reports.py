from __future__ import annotations

from app.exposure_reports import (
    exposure_port_snapshot,
    get_exposure_report,
    init_exposure_report_storage,
    list_exposure_report_summaries,
    save_exposure_report,
    snapshot_changes,
)


def test_exposure_report_snapshot_tracks_only_target_observed_ports():
    hunting = {
        "findings": [
            {"ip": "10.20.0.10", "protocol": "tcp", "port": 443, "state": "open"},
            {"ip": "10.20.0.10", "protocol": "tcp", "port": 443, "state": "open"},
            {"ip": "10.30.0.10", "protocol": "udp", "port": 53, "state": "open"},
            {
                "ip": "10.20.0.1",
                "protocol": "tcp",
                "port": 22,
                "evidence_kind": "device_configuration",
            },
        ]
    }

    assert exposure_port_snapshot(hunting, "10.20.0.0/24") == [
        "10.20.0.10|tcp|443|open"
    ]


def test_snapshot_changes_reports_added_and_removed_services():
    changes = snapshot_changes(
        ["10.20.0.10|tcp|80|open", "10.20.0.10|tcp|443|open"],
        ["10.20.0.10|tcp|443|open", "10.20.0.11|udp|53|open"],
    )

    assert changes["changed"] is True
    assert changes["added"] == ["10.20.0.11|udp|53|open"]
    assert changes["removed"] == ["10.20.0.10|tcp|80|open"]


def test_saved_network_catalog_distinguishes_missing_current_and_outdated_reports(tmp_path):
    db_path = tmp_path / "analyzer.db"
    init_exposure_report_storage(db_path)
    networks = [
        {"saved_network_id": "current", "name": "Current", "cidr": "10.20.0.0/24"},
        {"saved_network_id": "stale", "name": "Stale", "cidr": "10.30.0.0/24"},
        {"saved_network_id": "missing", "name": "Missing", "cidr": "10.40.0.0/24"},
    ]
    report = {
        "generated_at": "2026-09-26T12:00:00+00:00",
        "service_count": 1,
        "source_count": 2,
        "evaluated_path_count": 2,
    }
    save_exposure_report(
        db_path,
        saved_network=networks[0],
        generated_by="analyst",
        port_snapshot=["10.20.0.10|tcp|443|open"],
        report=report,
    )
    save_exposure_report(
        db_path,
        saved_network=networks[1],
        generated_by="analyst",
        port_snapshot=["10.30.0.10|tcp|80|open"],
        report=report,
    )
    hunting = {
        "findings": [
            {"ip": "10.20.0.10", "protocol": "tcp", "port": 443, "state": "open"},
            {"ip": "10.30.0.10", "protocol": "tcp", "port": 443, "state": "open"},
        ]
    }

    summaries = {
        item["saved_network_id"]: item
        for item in list_exposure_report_summaries(db_path, networks, hunting)
    }

    assert summaries["current"]["freshness"] == "current"
    assert summaries["stale"]["freshness"] == "out_of_date"
    assert summaries["stale"]["changes"]["added_count"] == 1
    assert summaries["stale"]["changes"]["removed_count"] == 1
    assert summaries["missing"]["freshness"] == "not_generated"
    assert get_exposure_report(db_path, "current")["generated_by"] == "analyst"
