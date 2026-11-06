import json
from pathlib import Path

import pytest
from fastapi import HTTPException

from app import device_configs, poc
from app.database import connect_database
from app.evidence_retirement import (
    EvidenceRetirementAdapter,
    init_evidence_retirement_storage,
    retire_evidence,
)
from app.evidence_retirement_sources import DEVICE_COLLECTION, NMAP_SCAN_RUN


def _adapter() -> EvidenceRetirementAdapter:
    return EvidenceRetirementAdapter(
        resolve_identities=lambda _db, encounter_id: {"encounter_id": encounter_id},
        active_work_detail=lambda _db, _encounter_id: None,
    )


def _retirement_db(tmp_path: Path) -> Path:
    db_path = tmp_path / "analyzer.db"
    with connect_database(db_path) as db:
        db.execute("CREATE TABLE fixture(id TEXT PRIMARY KEY)")
    init_evidence_retirement_storage(db_path)
    return db_path


def _retire(db_path: Path, family: str, encounter_id: str) -> None:
    retire_evidence(
        db_path,
        source_family=family,
        encounter_id=encounter_id,
        actor="operator",
        reason="wrong retained source",
        adapter=_adapter(),
    )


def test_direct_scan_artifact_route_hides_retired_encounter(
    tmp_path, monkeypatch,
):
    db_path = _retirement_db(tmp_path)
    run_id = "1" * 32
    _retire(db_path, NMAP_SCAN_RUN, run_id)
    monkeypatch.setattr(poc, "DB_PATH", db_path)
    monkeypatch.setattr(
        poc,
        "get_scan_run_plan",
        lambda value: {"run_id": value, "artifacts": [{"name": "xml"}]},
    )
    monkeypatch.setattr(
        poc, "artifact_path", lambda *_args: (tmp_path / "scan.xml", "text/xml")
    )

    with pytest.raises(HTTPException) as exc:
        poc.download_scan_artifact(run_id, "xml")
    assert exc.value.status_code == 404


def test_scan_history_and_detail_hide_retired_encounter(tmp_path, monkeypatch):
    db_path = _retirement_db(tmp_path)
    poc.init_poc_storage(db_path)
    run_id = "3" * 32
    manifest = {
        "run_id": run_id, "created_at": "2026-11-05T12:00:00+00:00",
        "status": "completed", "operator": "operator", "reason": "test",
        "originating_host": "nct", "interface": "eth0", "profile": "safe",
        "targets": ["10.0.0.0/24"],
    }
    poc.insert_scan_run_manifest(manifest, db_path)
    _retire(db_path, NMAP_SCAN_RUN, run_id)
    assert poc.list_scan_run_plans(db_path) == []
    monkeypatch.setattr(poc, "DB_PATH", db_path)
    monkeypatch.setattr(poc, "get_scan_run_plan", lambda _value: manifest)
    with pytest.raises(HTTPException) as exc:
        poc.scan_run_detail(run_id)
    assert exc.value.status_code == 404


def test_direct_device_artifact_route_hides_retired_encounter(
    tmp_path, monkeypatch,
):
    db_path = _retirement_db(tmp_path)
    run_id = "2" * 32
    config_dir = tmp_path / "device-configs"
    run_dir = config_dir / run_id
    run_dir.mkdir(parents=True)
    (run_dir / "manifest.json").write_text(
        json.dumps({"run_id": run_id, "status": "completed"}), encoding="utf-8"
    )
    _retire(db_path, DEVICE_COLLECTION, run_id)
    monkeypatch.setattr(device_configs, "DB_PATH", db_path)
    monkeypatch.setattr(device_configs, "CONFIG_DIR", config_dir)

    with pytest.raises(HTTPException) as exc:
        device_configs.download_artifact(run_id, "manifest.json")
    assert exc.value.status_code == 404


def test_device_history_and_detail_hide_retired_encounter(tmp_path, monkeypatch):
    db_path = _retirement_db(tmp_path)
    run_id = "4" * 32
    config_dir = tmp_path / "device-configs"
    run_dir = config_dir / run_id
    run_dir.mkdir(parents=True)
    (run_dir / "manifest.json").write_text(json.dumps({
        "run_id": run_id, "status": "uploaded", "operation": "manual_upload",
        "created_at": "2026-11-05T12:00:00+00:00", "vendor": "cisco",
    }), encoding="utf-8")
    _retire(db_path, DEVICE_COLLECTION, run_id)
    monkeypatch.setattr(device_configs, "DB_PATH", db_path)
    monkeypatch.setattr(device_configs, "CONFIG_DIR", config_dir)
    assert device_configs.history(limit=25, offset=0) == []
    with pytest.raises(HTTPException) as exc:
        device_configs.collection_detail(run_id)
    assert exc.value.status_code == 404
