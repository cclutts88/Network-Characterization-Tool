from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from fastapi import HTTPException

from app import main, poc
from app.artifacts import init_artifact_storage, register_artifact_bytes
from app.database import configure_database, connect_database
from app.evidence_retirement import (
    EvidenceRetirementError,
    init_evidence_retirement_storage,
    retire_evidence,
)
from app.evidence_retirement_sources import NMAP_IMPORT, nmap_import_adapter


ANALYSIS = {
    "hosts": [{"ip": "192.0.2.10", "status": "up", "ports": []}],
    "up_count": 1,
    "mac_count": 0,
    "os_groups": [],
    "coverage": {},
    "warnings": [],
}


@pytest.fixture
def import_store(tmp_path):
    db_path = tmp_path / "analyzer.db"
    artifact_root = tmp_path / "artifacts"
    configure_database(db_path)
    init_artifact_storage(db_path, artifact_root)
    init_evidence_retirement_storage(db_path)
    with connect_database(db_path) as db:
        db.execute(
            """CREATE TABLE imports(
                sha256 TEXT PRIMARY KEY,filename TEXT NOT NULL,
                stored_path TEXT NOT NULL,imported_at TEXT NOT NULL,
                analysis_json TEXT NOT NULL,metadata_json TEXT NOT NULL DEFAULT '{}'
            )"""
        )
    return db_path, artifact_root


def add_import(
    store, content: bytes, *, filenames=("first.xml", "second.xml"),
    times=("2026-11-05T10:00:00+00:00", "2026-11-05T11:00:00+00:00"),
):
    db_path, artifact_root = store
    observations = []
    for index, (filename, observed_at) in enumerate(zip(filenames, times), start=1):
        observations.append(register_artifact_bytes(
            db_path=db_path,
            artifact_root=artifact_root,
            content=content,
            source_kind=NMAP_IMPORT,
            source_ref=f"upload:{index}:{hashlib.sha256(content).hexdigest()}",
            original_filename=filename,
            actor=f"analyst-{index}",
            observed_at=observed_at,
        ))
    first = observations[0]
    with connect_database(db_path) as db:
        db.execute(
            "INSERT INTO imports VALUES (?,?,?,?,?,?)",
            (
                first["sha256"], filenames[0], first["canonical_path"], times[0],
                json.dumps(ANALYSIS), json.dumps({
                    "display_name": filenames[0],
                    "created_by": "retired-metadata-must-not-leak",
                    "scope_id": "retired-scope-must-not-leak",
                }),
            ),
        )
    return first["sha256"], [item["observation_id"] for item in observations]


def retire(db_path: Path, observation_id: str):
    retire_evidence(
        db_path,
        source_family=NMAP_IMPORT,
        encounter_id=observation_id,
        actor="retirement-test",
        reason="incorrect retained upload",
        adapter=nmap_import_adapter(),
    )


@pytest.mark.parametrize("retired_index,expected_filename", [(0, "second.xml"), (1, "first.xml")])
def test_identical_content_uses_only_the_remaining_active_upload_metadata(
    import_store, retired_index, expected_filename, monkeypatch,
):
    digest, observations = add_import(import_store, b"<nmaprun/>")
    retire(import_store[0], observations[retired_index])

    history = poc.list_import_history(import_store[0])
    detail = poc.get_import_history_item(digest, import_store[0])
    monkeypatch.setattr(main, "DB_PATH", import_store[0])
    raw = main.download_imported_xml(digest)

    assert [item["filename"] for item in history] == [expected_filename]
    assert detail["filename"] == expected_filename
    assert detail["display_name"] == expected_filename
    assert detail["active_observation_id"] == observations[1 - retired_index]
    assert detail["metadata"]["created_by"] == f"analyst-{2 - retired_index}"
    assert "scope_id" not in detail["metadata"]
    assert expected_filename in raw.headers["content-disposition"]


def test_fully_retired_registered_content_is_withheld_from_every_hash_route(
    import_store, monkeypatch,
):
    digest, observations = add_import(import_store, b"<nmaprun/>\n")
    for observation_id in observations:
        retire(import_store[0], observation_id)
    monkeypatch.setattr(main, "DB_PATH", import_store[0])

    assert poc.list_import_history(import_store[0]) == []
    assert poc.get_import_history_item(digest, import_store[0]) is None
    with pytest.raises(KeyError):
        poc.compare_import_results(digest, digest, import_store[0])
    with pytest.raises(HTTPException) as raw_error:
        main.download_imported_xml(digest)
    with pytest.raises(HTTPException) as export_error:
        main.export_import_host_summary(digest)
    assert raw_error.value.status_code == 404
    assert export_error.value.status_code == 404


def test_true_legacy_import_remains_readable_until_backfill(import_store):
    db_path, _artifact_root = import_store
    content = b"<nmaprun legacy='true'/>"
    digest = hashlib.sha256(content).hexdigest()
    path = db_path.parent / "imports" / "legacy.xml"
    path.parent.mkdir()
    path.write_bytes(content)
    with connect_database(db_path) as db:
        db.execute(
            "INSERT INTO imports VALUES (?,?,?,?,?,?)",
            (
                digest, "legacy.xml", str(path), "2026-01-01T00:00:00+00:00",
                json.dumps(ANALYSIS), json.dumps({"display_name": "Legacy label"}),
            ),
        )

    item = poc.get_import_history_item(digest, db_path)

    assert item["filename"] == "legacy.xml"
    assert item["display_name"] == "Legacy label"
    assert item["active_observation_id"] is None


@pytest.mark.parametrize("missing_table", [
    "evidence_retirement_events", "artifact_observations",
])
def test_import_gateway_fails_closed_when_authority_is_incomplete(
    import_store, missing_table,
):
    add_import(import_store, b"<nmaprun authority='test'/>")
    with connect_database(import_store[0]) as db:
        db.execute(f"DROP TABLE {missing_table}")

    with pytest.raises(EvidenceRetirementError, match="authority is unavailable"):
        poc.list_import_history(import_store[0])


def test_comparison_with_one_fully_retired_side_is_not_available(import_store):
    first_digest, first_observations = add_import(
        import_store, b"<nmaprun id='one'/>", filenames=("one-a.xml", "one-b.xml"),
    )
    second_digest, _ = add_import(
        import_store, b"<nmaprun id='two'/>", filenames=("two-a.xml", "two-b.xml"),
        times=("2026-11-05T12:00:00+00:00", "2026-11-05T13:00:00+00:00"),
    )
    for observation_id in first_observations:
        retire(import_store[0], observation_id)

    with pytest.raises(KeyError, match="not found"):
        poc.compare_import_results(first_digest, second_digest, import_store[0])


def test_export_rechecks_activity_after_preparation(import_store, monkeypatch):
    digest, observations = add_import(
        import_store, b"<nmaprun export='race'/>", filenames=("only.xml",),
        times=("2026-11-05T14:00:00+00:00",),
    )
    monkeypatch.setattr(main, "DB_PATH", import_store[0])
    monkeypatch.setattr(main, "apply_analysis_os_overrides", lambda analysis, _db: analysis)
    monkeypatch.setattr(main, "apply_analysis_host_identities", lambda analysis, _db: analysis)
    original = main.rows_to_csv

    def retire_during_export(rows, fields):
        content = original(rows, fields)
        retire(import_store[0], observations[0])
        return content

    monkeypatch.setattr(main, "rows_to_csv", retire_during_export)

    with pytest.raises(HTTPException) as error:
        main.export_import_host_summary(digest)
    assert error.value.status_code == 404


def test_export_reselects_active_sibling_metadata_after_preparation(
    import_store, monkeypatch,
):
    digest, observations = add_import(
        import_store, b"<nmaprun export='sibling-race'/>",
        filenames=("older-active.xml", "newest-retired.xml"),
    )
    monkeypatch.setattr(main, "DB_PATH", import_store[0])
    monkeypatch.setattr(main, "apply_analysis_os_overrides", lambda analysis, _db: analysis)
    monkeypatch.setattr(main, "apply_analysis_host_identities", lambda analysis, _db: analysis)
    original = main.rows_to_csv

    def retire_latest_during_export(rows, fields):
        content = original(rows, fields)
        retire(import_store[0], observations[1])
        return content

    monkeypatch.setattr(main, "rows_to_csv", retire_latest_during_export)

    response = main.export_import_host_summary(digest)

    assert "older-active" in response.headers["content-disposition"]
    assert "newest-retired" not in response.headers["content-disposition"]


def test_raw_download_reselects_active_sibling_metadata_before_publication(
    import_store, monkeypatch,
):
    digest, observations = add_import(
        import_store, b"<nmaprun raw='sibling-race'/>",
        filenames=("older-active.xml", "newest-retired.xml"),
    )
    monkeypatch.setattr(main, "DB_PATH", import_store[0])
    original = main.get_artifact

    def retire_latest_during_path_resolution(db_path, sha256):
        retire(import_store[0], observations[1])
        return original(db_path, sha256)

    monkeypatch.setattr(main, "get_artifact", retire_latest_during_path_resolution)

    response = main.download_imported_xml(digest)

    assert "older-active.xml" in response.headers["content-disposition"]
    assert "newest-retired.xml" not in response.headers["content-disposition"]
