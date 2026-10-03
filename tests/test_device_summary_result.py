from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

import app.device_summary_result as device_result
from app.artifacts import register_artifact_file
from app.database import connect_database
from app.device_configs import (
    calculate_device_collection_summary,
    device_collection_summary,
)


CONFIG = b'''===== show running-config =====
interface Ethernet1
 ip address 10.80.0.1 255.255.255.0
ip route 10.90.0.0 255.255.0.0 10.80.0.2
===== show history =====
1 show version
2 configure terminal
'''


def manual_upload(
    db_path: Path,
    config_dir: Path,
    run_id: str,
    *,
    content: bytes = CONFIG,
    retained_filename: str = "uploaded-router.txt",
    vendor: str = "cisco",
) -> tuple[Path, dict]:
    run_dir = config_dir / run_id
    run_dir.mkdir(parents=True)
    evidence_path = run_dir / retained_filename
    evidence_path.write_bytes(content)
    artifact = register_artifact_file(
        db_path=db_path,
        source_path=evidence_path,
        source_kind="device_config_upload",
        source_ref=run_id,
        original_filename="router.txt",
        actor="analyst",
        observation_key=f"device_config_upload:{run_id}:{retained_filename}",
    )
    manifest = {
        "run_id": run_id,
        "operation": "manual_upload",
        "status": "uploaded",
        "vendor": vendor,
        "device_type": "router",
        "device_name": f"Router {run_id[:4]}",
        "device_address": "192.0.2.1",
        "operator": "analyst",
        "created_at": "2026-10-03T21:00:00+00:00",
        "completed_at": "2026-10-03T21:00:00+00:00",
        "retained_filename": retained_filename,
        "artifact_sha256": artifact["sha256"],
        "artifact_observation_id": artifact["observation_id"],
        "output_complete": True,
        "commands": [],
    }
    (run_dir / "manifest.json").write_text(
        json.dumps(manifest, sort_keys=True), encoding="utf-8"
    )
    return run_dir, manifest


def test_frozen_calculation_matches_file_wrapper_and_preserves_history_lines(tmp_path):
    db_path = tmp_path / "nct.db"
    config_dir = tmp_path / "device-configs"
    run_id = "a" * 32
    run_dir, _ = manual_upload(db_path, config_dir, run_id)

    expected = device_collection_summary(run_id, config_dir=config_dir)
    text = (run_dir / "uploaded-router.txt").read_text()
    calculated = calculate_device_collection_summary(
        run_id=run_id,
        configuration_text=text,
        source_filename="uploaded-router.txt",
        configuration_truncated=False,
        raw_output=text,
        raw_filename="uploaded-router.txt",
        raw_truncated=False,
        history_text="1 show version\n2 configure terminal",
        history_attempted=False,
        vendor="cisco",
        commands=[],
        output_complete=True,
    )

    assert calculated == expected
    assert calculated["command_history"]["entries"][1]["line_number"] == 2


def test_verified_manual_upload_adapter_reuses_exact_bytes_across_encounters(
    tmp_path, monkeypatch,
):
    db_path = tmp_path / "nct.db"
    config_dir = tmp_path / "device-configs"
    first_dir, _ = manual_upload(
        db_path, config_dir, "b" * 32, retained_filename="uploaded-first.txt"
    )
    second_dir, _ = manual_upload(
        db_path, config_dir, "c" * 32, retained_filename="uploaded-second.txt"
    )
    calls = []
    original = device_result.calculate_device_collection_summary

    def calculate(**kwargs):
        calls.append(kwargs["run_id"])
        return original(**kwargs)

    monkeypatch.setattr(device_result, "calculate_device_collection_summary", calculate)
    first = device_result.analyze_manual_upload_summary(db_path, "b" * 32, first_dir)
    second = device_result.analyze_manual_upload_summary(db_path, "c" * 32, second_dir)
    warm = device_result.analyze_manual_upload_summary(db_path, "b" * 32, first_dir)

    assert first["reused"] is False
    assert second["reused"] is True
    assert warm["reused"] is True
    assert first["result_id"] == second["result_id"] == warm["result_id"]
    assert first["payload"]["source_filename"] == "uploaded-first.txt"
    assert second["payload"]["source_filename"] == "uploaded-second.txt"
    assert len(calls) == 1
    with connect_database(db_path, read_only=True) as db:
        assert db.execute(
            "SELECT COUNT(*) FROM derived_results WHERE family = ?",
            (device_result.DEVICE_SUMMARY_FAMILY,),
        ).fetchone()[0] == 1
        assert db.execute(
            "SELECT COUNT(*) FROM derived_result_observation_links"
        ).fetchone()[0] == 4

    writer = connect_database(db_path)
    try:
        writer.execute("BEGIN IMMEDIATE")
        assert device_result.analyze_manual_upload_summary(
            db_path, "b" * 32, first_dir
        )["reused"] is True
    finally:
        writer.rollback()
        writer.close()
    assert len(calls) == 1


def test_presentation_metadata_does_not_change_identity_but_semantics_do(tmp_path):
    db_path = tmp_path / "nct.db"
    config_dir = tmp_path / "device-configs"
    run_id = "d" * 32
    run_dir, manifest = manual_upload(db_path, config_dir, run_id)
    first = device_result.analyze_manual_upload_summary(db_path, run_id, run_dir)

    manifest["device_name"] = "Renamed by analyst"
    manifest["operator"] = "different-analyst"
    (run_dir / "manifest.json").write_text(json.dumps(manifest, sort_keys=True))
    presentation = device_result.analyze_manual_upload_summary(db_path, run_id, run_dir)
    assert presentation["result_id"] == first["result_id"]

    manifest["vendor"] = "juniper"
    (run_dir / "manifest.json").write_text(json.dumps(manifest, sort_keys=True))
    semantic = device_result.analyze_manual_upload_summary(db_path, run_id, run_dir)
    assert semantic["result_id"] != first["result_id"]


def test_changed_run_local_bytes_and_unreviewed_selection_shape_fail_closed(tmp_path):
    db_path = tmp_path / "nct.db"
    config_dir = tmp_path / "device-configs"
    run_id = "e" * 32
    run_dir, _ = manual_upload(db_path, config_dir, run_id)
    evidence = run_dir / "uploaded-router.txt"
    original_time = evidence.stat().st_mtime_ns
    changed = CONFIG.replace(b"10.90.0.0", b"10.91.0.0")
    assert len(changed) == len(CONFIG)
    evidence.write_bytes(changed)
    os.utime(evidence, ns=(original_time, original_time))

    with pytest.raises(ValueError, match="does not match its registered artifact"):
        device_result.analyze_manual_upload_summary(db_path, run_id, run_dir)

    evidence.write_bytes(CONFIG)
    (run_dir / "uploaded-extra.txt").write_text("hostname unexpected")
    with pytest.raises(ValueError, match="single-file selection shape"):
        device_result.analyze_manual_upload_summary(db_path, run_id, run_dir)


def test_manifest_change_during_calculation_cannot_publish(tmp_path, monkeypatch):
    db_path = tmp_path / "nct.db"
    config_dir = tmp_path / "device-configs"
    run_id = "f" * 32
    run_dir, manifest = manual_upload(db_path, config_dir, run_id)
    original = device_result.calculate_device_collection_summary

    def calculate(**kwargs):
        manifest["vendor"] = "juniper"
        (run_dir / "manifest.json").write_text(json.dumps(manifest, sort_keys=True))
        return original(**kwargs)

    monkeypatch.setattr(device_result, "calculate_device_collection_summary", calculate)
    with pytest.raises(ValueError, match="snapshot changed"):
        device_result.analyze_manual_upload_summary(db_path, run_id, run_dir)
    with connect_database(db_path, read_only=True) as db:
        assert db.execute("SELECT COUNT(*) FROM derived_results").fetchone()[0] == 0


def test_existing_empty_higher_priority_file_wins_and_missing_history_is_distinct(tmp_path):
    config_dir = tmp_path / "device-configs"
    run_id = "1" * 32
    run_dir = config_dir / run_id
    run_dir.mkdir(parents=True)
    (run_dir / "manifest.json").write_text(json.dumps({
        "run_id": run_id,
        "status": "uploaded",
        "vendor": "cisco",
        "commands": [],
    }))
    (run_dir / "uploaded-a.txt").write_text("")
    (run_dir / "uploaded-z.txt").write_text(
        "ip route 10.90.0.0 255.255.0.0 192.0.2.1"
    )

    result = device_collection_summary(run_id, config_dir=config_dir)
    assert result["source_filename"] == "uploaded-a.txt"
    assert result["routes"] == []
    assert result["command_history"]["status"] == "not_collected"

    attempted_empty = calculate_device_collection_summary(
        run_id=run_id,
        configuration_text="",
        source_filename="uploaded-a.txt",
        configuration_truncated=False,
        raw_output="",
        raw_filename="uploaded-a.txt",
        raw_truncated=False,
        history_text="",
        history_attempted=True,
        vendor="cisco",
        commands=[],
        output_complete=True,
    )
    assert attempted_empty["command_history"]["status"] == "unavailable"
