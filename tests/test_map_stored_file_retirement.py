import json
from pathlib import Path

import pytest

from app.database import connect_database
from app.evidence_retirement import (
    EvidenceRetirementAdapter,
    EvidenceRetirementError,
    init_evidence_retirement_storage,
    retire_evidence,
)
from app.evidence_retirement_sources import (
    DEVICE_COLLECTION,
    NMAP_IMPORT,
    NMAP_SCAN_RUN,
)
from app import poc


def _adapter() -> EvidenceRetirementAdapter:
    return EvidenceRetirementAdapter(
        resolve_identities=lambda _db, encounter_id: {"encounter_id": encounter_id},
        active_work_detail=lambda _db, _encounter_id: None,
    )


def _foundation(tmp_path: Path):
    data = tmp_path / "data"
    data.mkdir()
    db_path = data / "analyzer.db"
    with connect_database(db_path) as db:
        db.execute(
            "CREATE TABLE imports(sha256 TEXT PRIMARY KEY,filename TEXT NOT NULL,"
            "stored_path TEXT NOT NULL,imported_at TEXT NOT NULL,analysis_json TEXT NOT NULL)"
        )
        db.execute(
            "CREATE TABLE artifact_observations("
            "observation_id TEXT PRIMARY KEY,sha256 TEXT NOT NULL,source_kind TEXT NOT NULL,"
            "source_ref TEXT NOT NULL,observed_at TEXT NOT NULL,original_filename TEXT,"
            "actor TEXT,metadata_json TEXT NOT NULL DEFAULT '{}')"
        )
    init_evidence_retirement_storage(db_path)
    return data, db_path


def _retire(db_path: Path, family: str, encounter_id: str):
    retire_evidence(
        db_path,
        source_family=family,
        encounter_id=encounter_id,
        actor="operator",
        reason="no longer used in ordinary work",
        adapter=_adapter(),
    )


def _ids(result: dict) -> set[str]:
    return {item["id"] for item in result["locations"]}


def test_stored_files_hide_retired_scan_and_device_encounters(tmp_path):
    data, db_path = _foundation(tmp_path)
    scan_id = "1" * 32
    device_id = "2" * 32
    active_scan = "3" * 32
    for folder, run_id in (
        (data / poc.RUNS_DIR_NAME, scan_id),
        (data / poc.RUNS_DIR_NAME, active_scan),
        (data / "device-configs", device_id),
    ):
        run = folder / run_id
        run.mkdir(parents=True)
        (run / "manifest.json").write_text(
            json.dumps({"run_id": run_id, "status": "completed"}), encoding="utf-8",
        )
    _retire(db_path, NMAP_SCAN_RUN, scan_id)
    _retire(db_path, DEVICE_COLLECTION, device_id)
    result = poc.list_stored_files(data_dir=data, db_path=db_path)
    assert f"scan:{scan_id}" not in _ids(result)
    assert f"device:{device_id}" not in _ids(result)
    assert f"scan:{active_scan}" in _ids(result)


def test_shared_import_stays_visible_until_every_exact_encounter_is_retired(tmp_path):
    data, db_path = _foundation(tmp_path)
    digest = "a" * 64
    with connect_database(db_path) as db:
        db.execute(
            "INSERT INTO imports VALUES (?,?,?,?,?)",
            (digest, "canonical.xml", "/data/import.xml", "2026-11-05", "{}"),
        )
        db.executemany(
            "INSERT INTO artifact_observations VALUES (?,?,?,?,?,?,?,?)",
            [
                ("observation-old", digest, "nmap_import", "one", "2026-11-04", "old.xml", "a", "{}"),
                ("observation-new", digest, "nmap_import", "two", "2026-11-05", "new.xml", "b", "{}"),
            ],
        )
    _retire(db_path, NMAP_IMPORT, "observation-new")
    first = poc.list_stored_files(data_dir=data, db_path=db_path)
    item = next(item for item in first["locations"] if item["id"] == f"import:{digest}")
    assert item["label"] == "old.xml"
    _retire(db_path, NMAP_IMPORT, "observation-old")
    second = poc.list_stored_files(data_dir=data, db_path=db_path)
    assert f"import:{digest}" not in _ids(second)


def test_true_legacy_import_remains_visible_without_guessing_retirement(tmp_path):
    data, db_path = _foundation(tmp_path)
    digest = "b" * 64
    with connect_database(db_path) as db:
        db.execute(
            "INSERT INTO imports VALUES (?,?,?,?,?)",
            (digest, "legacy.xml", "/data/legacy.xml", "2026-11-05", "{}"),
        )
    result = poc.list_stored_files(data_dir=data, db_path=db_path)
    assert f"import:{digest}" in _ids(result)


def test_stored_file_snapshot_fails_closed_after_repeated_retirement_change(
    tmp_path, monkeypatch,
):
    data, db_path = _foundation(tmp_path)
    monkeypatch.setattr(poc, "retirement_cache_token", lambda _path: "changed")
    with pytest.raises(EvidenceRetirementError, match="changed"):
        poc.list_stored_files(data_dir=data, db_path=db_path)
