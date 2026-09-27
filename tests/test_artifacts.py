from __future__ import annotations

from pathlib import Path

from app.artifacts import (
    artifact_storage_summary,
    get_artifact,
    link_artifact,
    register_artifact_bytes,
    register_artifact_file,
)


def test_artifact_registry_deduplicates_content_and_retains_observations(tmp_path):
    db_path = tmp_path / "analyzer.db"
    content = b"same retained evidence\n"

    first = register_artifact_bytes(
        db_path=db_path,
        content=content,
        source_kind="nmap_import",
        source_ref="import-1",
        original_filename="first.xml",
        media_type="application/xml",
        actor="analyst-a",
        observed_at="2026-09-27T10:00:00+00:00",
    )
    second = register_artifact_bytes(
        db_path=db_path,
        content=content,
        source_kind="nmap_import",
        source_ref="import-2",
        original_filename="renamed.xml",
        media_type="application/xml",
        actor="analyst-b",
        observed_at="2026-09-27T11:00:00+00:00",
    )

    assert first["sha256"] == second["sha256"]
    assert first["duplicate"] is False
    assert second["duplicate"] is True
    assert Path(first["canonical_path"]).read_bytes() == content
    assert first["canonical_path"] == second["canonical_path"]

    retained = get_artifact(db_path, first["sha256"])
    assert retained is not None
    assert retained["first_seen_at"] == "2026-09-27T10:00:00+00:00"
    assert retained["last_seen_at"] == "2026-09-27T11:00:00+00:00"
    assert [item["original_filename"] for item in retained["observations"]] == [
        "first.xml",
        "renamed.xml",
    ]
    assert [item["actor"] for item in retained["observations"]] == [
        "analyst-a",
        "analyst-b",
    ]

    summary = artifact_storage_summary(db_path)
    assert summary == {
        "unique_artifact_count": 1,
        "unique_artifact_bytes": len(content),
        "observation_count": 2,
    }


def test_file_registration_can_materialize_run_local_reference(tmp_path):
    db_path = tmp_path / "analyzer.db"
    source = tmp_path / "incoming.txt"
    source.write_text("router configuration\n", encoding="utf-8")

    record = register_artifact_file(
        db_path=db_path,
        source_path=source,
        source_kind="device_config_upload",
        source_ref="run-1",
        original_filename="router.txt",
        media_type="text/plain",
        actor="analyst",
    )
    destination = tmp_path / "device-configs" / "run-1" / "uploaded-router.txt"
    mode = link_artifact(record, destination)

    assert mode in {"hardlink", "copy"}
    assert destination.read_text(encoding="utf-8") == "router configuration\n"
    assert Path(record["canonical_path"]).read_bytes() == destination.read_bytes()


def test_identical_files_from_different_sources_share_one_canonical_artifact(tmp_path):
    db_path = tmp_path / "analyzer.db"
    nmap = tmp_path / "nmap.xml"
    config = tmp_path / "copy.txt"
    evidence = b"identical byte content"
    nmap.write_bytes(evidence)
    config.write_bytes(evidence)

    first = register_artifact_file(
        db_path=db_path,
        source_path=nmap,
        source_kind="nmap_scan",
        source_ref="scan-1",
        original_filename="scan.xml",
        media_type="application/xml",
    )
    second = register_artifact_file(
        db_path=db_path,
        source_path=config,
        source_kind="device_config_upload",
        source_ref="device-1",
        original_filename="config.txt",
        media_type="text/plain",
    )

    assert first["sha256"] == second["sha256"]
    assert first["canonical_path"] == second["canonical_path"]
    assert second["duplicate"] is True
    retained = get_artifact(db_path, first["sha256"])
    assert {item["source_kind"] for item in retained["observations"]} == {
        "nmap_scan",
        "device_config_upload",
    }
