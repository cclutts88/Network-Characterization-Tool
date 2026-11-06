from __future__ import annotations

from app.exposure_reports import (
    exposure_port_snapshot,
    get_exposure_report,
    init_exposure_report_storage,
    list_exposure_report_summaries,
    save_exposure_report,
    snapshot_changes,
)
from app.database import connect_database
from app.evidence_retirement import (
    EvidenceRetirementAdapter,
    RetiredEvidenceDependency,
    init_evidence_retirement_storage,
    retire_evidence,
    retirement_authority_token,
)
from app.evidence_retirement_sources import NMAP_SCAN_RUN
import pytest


def _token(db_path):
    with connect_database(db_path, read_only=True) as db:
        return retirement_authority_token(db)


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
    init_evidence_retirement_storage(db_path)
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
        authority_token=_token(db_path),
    )
    save_exposure_report(
        db_path,
        saved_network=networks[1],
        generated_by="analyst",
        port_snapshot=["10.30.0.10|tcp|80|open"],
        report=report,
        authority_token=_token(db_path),
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


def test_saved_report_is_withheld_after_exact_source_retirement(tmp_path):
    db_path = tmp_path / "analyzer.db"
    init_exposure_report_storage(db_path)
    init_evidence_retirement_storage(db_path)
    network = {
        "saved_network_id": "network-a",
        "name": "Network A",
        "cidr": "10.20.0.0/24",
    }
    run_id = "a" * 32
    report = {
        "generated_at": "2026-11-05T12:00:00+00:00",
        "service_count": 1,
        "source_count": 1,
        "evaluated_path_count": 1,
    }
    save_exposure_report(
        db_path,
        saved_network=network,
        generated_by="analyst",
        port_snapshot=["10.20.0.10|tcp|443|open"],
        report=report,
        source_dependencies=[{
            "source_family": NMAP_SCAN_RUN,
            "encounter_id": run_id,
        }],
        authority_token=_token(db_path),
    )
    assert get_exposure_report(db_path, "network-a", active_only=True) is not None

    retire_evidence(
        db_path,
        source_family=NMAP_SCAN_RUN,
        encounter_id=run_id,
        actor="analyst",
        reason="wrong source",
        adapter=EvidenceRetirementAdapter(
            resolve_identities=lambda _db, encounter_id: {
                "encounter_id": encounter_id
            },
            active_work_detail=lambda _db, _encounter_id: None,
        ),
    )

    assert get_exposure_report(db_path, "network-a", active_only=True) is None
    summary = list_exposure_report_summaries(
        db_path, [network], {"findings": []}, active_only=True,
    )[0]
    assert summary["freshness"] == "not_generated"
    assert get_exposure_report(db_path, "network-a") is not None


def test_legacy_saved_report_without_source_binding_is_audit_only(tmp_path):
    db_path = tmp_path / "analyzer.db"
    init_exposure_report_storage(db_path)
    init_evidence_retirement_storage(db_path)
    with connect_database(db_path) as db:
        db.execute(
            """INSERT INTO reach_exposure_reports(
                   saved_network_id,target_name,target_cidr,generated_at,
                   generated_by,port_snapshot_json,report_json
               ) VALUES (?,?,?,?,?,?,?)""",
            (
                "legacy", "Legacy", "10.30.0.0/24",
                "2026-11-05T12:00:00+00:00", "analyst", "[]",
                '{"generated_at":"2026-11-05T12:00:00+00:00"}',
            ),
        )
    assert get_exposure_report(db_path, "legacy", active_only=True) is None
    assert get_exposure_report(db_path, "legacy") is not None


def test_saved_report_publication_fails_when_authority_changed_during_build(tmp_path):
    db_path = tmp_path / "analyzer.db"
    init_exposure_report_storage(db_path)
    init_evidence_retirement_storage(db_path)
    stale = _token(db_path)
    run_id = "b" * 32
    retire_evidence(
        db_path,
        source_family=NMAP_SCAN_RUN,
        encounter_id=run_id,
        actor="analyst",
        reason="changed while report was built",
        adapter=EvidenceRetirementAdapter(
            resolve_identities=lambda _db, encounter_id: {
                "encounter_id": encounter_id
            },
            active_work_detail=lambda _db, _encounter_id: None,
        ),
    )
    with pytest.raises(RetiredEvidenceDependency, match="changed"):
        save_exposure_report(
            db_path,
            saved_network={
                "saved_network_id": "network-a",
                "name": "Network A",
                "cidr": "10.20.0.0/24",
            },
            generated_by="analyst",
            port_snapshot=[],
            report={"generated_at": "2026-11-05T12:00:00+00:00"},
            authority_token=stale,
        )
    assert get_exposure_report(db_path, "network-a") is None
