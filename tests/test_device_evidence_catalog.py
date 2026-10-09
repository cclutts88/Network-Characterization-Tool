from __future__ import annotations

import hashlib
import json
import os
import sqlite3

import pytest

from app import device_evidence_catalog
from app.derived_contracts import (
    DEVICE_SUMMARY_FAMILY,
    DEVICE_SUMMARY_PARAMETERS,
    DEVICE_SUMMARY_SCHEMA_VERSION,
    DEVICE_SUMMARY_VERSION,
)
from app.derived_jobs import init_derived_job_storage
from app.device_collection_authority import (
    MANUAL_UPLOAD_SELECTION_CONTRACT,
    authority_manifest_marker,
    init_device_collection_authority_storage,
)
from app.device_evidence_catalog import (
    DeviceEvidenceCatalogError,
    record_device_evidence_activation,
    record_device_evidence_deletion,
    reconcile_device_evidence_catalog,
    select_latest_device_evidence,
)
from app.pipeline_intake import DEVICE_SUMMARY_JOB_TYPE


def _canonical(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _setup(tmp_path):
    db_path = tmp_path / "analyzer.db"
    config_dir = tmp_path / "device-configs"
    config_dir.mkdir()
    init_device_collection_authority_storage(db_path)
    init_derived_job_storage(db_path)
    return db_path, config_dir


def _add_collection(
    db_path,
    config_dir,
    *,
    run_id: str,
    address: str,
    completed_at: str,
    attempt_state: str = "completed",
):
    manifest = {
        "run_id": run_id,
        "created_at": completed_at,
        "completed_at": completed_at,
        "vendor": "cisco",
        "device_type": "router",
        "device_address": address,
        "operation": "manual_upload",
        "status": "uploaded",
        "commands": [],
        "output_complete": True,
        "summary_authority": authority_manifest_marker(),
    }
    run_dir = config_dir / run_id
    run_dir.mkdir()
    (run_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    semantics_json = _canonical({"test": run_id})
    authority = {
        "run_id": run_id,
        "state": "active",
        "revision": 1,
        "selection_contract": MANUAL_UPLOAD_SELECTION_CONTRACT,
        "semantic_manifest_json": semantics_json,
        "semantic_manifest_sha256": _digest(semantics_json),
        "artifact_observation_id": f"observation-{run_id}",
        "artifact_sha256": _digest(f"artifact-{run_id}"),
        "retained_filename": "uploaded-config.txt",
        "created_at": completed_at,
        "activated_at": completed_at,
        "deleted_at": None,
    }
    parameters = _canonical(dict(DEVICE_SUMMARY_PARAMETERS))
    result_id = f"result-{run_id}"
    job_id = f"job-{run_id}"
    attempt_id = f"attempt-{run_id}"
    with sqlite3.connect(db_path) as db:
        db.execute(
            """INSERT INTO device_collection_authority (
                   run_id, state, revision, artifact_observation_id, artifact_sha256,
                   retained_filename, selection_contract, semantic_manifest_json,
                   semantic_manifest_sha256, created_at, activated_at
               ) VALUES (?, 'active', 1, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                run_id, authority["artifact_observation_id"], authority["artifact_sha256"],
                authority["retained_filename"], authority["selection_contract"],
                semantics_json, authority["semantic_manifest_sha256"], completed_at,
                completed_at,
            ),
        )
        record_device_evidence_activation(db, manifest, authority)
        db.execute(
            """INSERT INTO derived_results (
                   result_id, computation_key, family, analysis_version,
                   payload_schema_version, parameters_json, inputs_json,
                   result_json, result_sha256, generated_at
               ) VALUES (?, ?, ?, ?, ?, ?, '[]', '{}', ?, ?)""",
            (
                result_id, f"computation-{run_id}", DEVICE_SUMMARY_FAMILY,
                str(DEVICE_SUMMARY_VERSION), int(DEVICE_SUMMARY_SCHEMA_VERSION),
                parameters, _digest("{}"), completed_at,
            ),
        )
        db.execute(
            """INSERT INTO pipeline_jobs (
                   job_id, job_key, job_type, source_run_id, source_observation_id,
                   source_status, source_sha256, source_size_bytes, target_family,
                   target_analysis_version, target_payload_schema_version,
                   target_parameters_json, target_computation_key, target_result_id,
                   source_kind, source_ref, definition_json, requested_by, requested_at
               ) VALUES (?, ?, ?, ?, ?, 'completed', ?, 1, ?, ?, ?, ?, ?, ?,
                         'device_collection', ?, '{}', 'tester', ?)""",
            (
                job_id, f"key-{run_id}", DEVICE_SUMMARY_JOB_TYPE, run_id,
                authority["artifact_observation_id"], authority["artifact_sha256"],
                DEVICE_SUMMARY_FAMILY, str(DEVICE_SUMMARY_VERSION),
                int(DEVICE_SUMMARY_SCHEMA_VERSION), parameters,
                f"computation-{run_id}", result_id, run_id, completed_at,
            ),
        )
        db.execute(
            """INSERT INTO pipeline_job_attempts (
                   attempt_id, job_id, attempt_number, state, requested_by,
                   requested_at, finished_at, outcome, result_id, output_kind,
                   output_id
               ) VALUES (?, ?, 1, ?, 'tester', ?, ?, ?, ?, ?, ?)""",
            (
                attempt_id, job_id, attempt_state, completed_at,
                completed_at if attempt_state == "completed" else None,
                "created" if attempt_state == "completed" else None,
                result_id if attempt_state == "completed" else None,
                "derived_result" if attempt_state == "completed" else None,
                result_id if attempt_state == "completed" else None,
            ),
        )
    return manifest


def test_selector_keeps_distinct_device_beyond_old_hundred_record_window(
    tmp_path, monkeypatch,
):
    db_path, config_dir = _setup(tmp_path)
    _add_collection(
        db_path, config_dir, run_id="f" * 32, address="10.0.0.2",
        completed_at="2029-01-01T00:00:00+00:00",
    )
    for index in range(101):
        _add_collection(
            db_path,
            config_dir,
            run_id=f"{index + 1:032x}",
            address="10.0.0.1",
            completed_at=f"2030-01-01T00:{index // 60:02d}:{index % 60:02d}+00:00",
        )

    manifest_reads = []
    original_safe_manifest = device_evidence_catalog._safe_manifest

    def counted_safe_manifest(directory, run_id):
        manifest_reads.append(run_id)
        return original_safe_manifest(directory, run_id)

    monkeypatch.setattr(
        device_evidence_catalog, "_safe_manifest", counted_safe_manifest
    )
    selected, descriptor = select_latest_device_evidence(db_path, config_dir)

    assert descriptor["eligible_count"] == 102
    assert len(descriptor["rows"]) == 2
    assert len(manifest_reads) == 2
    assert {item["device_key"] for item in selected} == {"ip:10.0.0.1", "ip:10.0.0.2"}
    assert next(item for item in selected if item["device_key"] == "ip:10.0.0.1")[
        "run_id"
    ] == f"{101:032x}"


def test_selector_uses_stable_run_id_tie_breaker(tmp_path):
    db_path, config_dir = _setup(tmp_path)
    stamp = "2030-01-01T00:00:00+00:00"
    _add_collection(db_path, config_dir, run_id="1" * 32, address="10.0.0.1", completed_at=stamp)
    _add_collection(db_path, config_dir, run_id="2" * 32, address="10.0.0.1", completed_at=stamp)

    selected, _descriptor = select_latest_device_evidence(db_path, config_dir)

    assert [item["run_id"] for item in selected] == ["2" * 32]


def test_pending_newer_collection_does_not_displace_ready_collection(tmp_path):
    db_path, config_dir = _setup(tmp_path)
    _add_collection(
        db_path, config_dir, run_id="1" * 32, address="10.0.0.1",
        completed_at="2030-01-01T00:00:00+00:00",
    )
    _add_collection(
        db_path, config_dir, run_id="2" * 32, address="10.0.0.1",
        completed_at="2030-01-02T00:00:00+00:00", attempt_state="queued",
    )

    selected, _descriptor = select_latest_device_evidence(db_path, config_dir)

    assert [item["run_id"] for item in selected] == ["1" * 32]


def test_current_deletion_removes_catalog_row_atomically(tmp_path):
    db_path, config_dir = _setup(tmp_path)
    run_id = "a" * 32
    _add_collection(
        db_path, config_dir, run_id=run_id, address="10.0.0.1",
        completed_at="2030-01-01T00:00:00+00:00",
    )
    with sqlite3.connect(db_path) as db:
        db.execute(
            """UPDATE device_collection_authority
               SET state='deleted', revision=2, deleted_at='2030-01-02T00:00:00+00:00'
               WHERE run_id=?""",
            (run_id,),
        )
        record_device_evidence_deletion(db, run_id)

    selected, descriptor = select_latest_device_evidence(db_path, config_dir)

    assert selected == []
    assert descriptor["dirty"] == []


def test_rollback_authority_write_is_detected_until_startup_reconcile(tmp_path):
    db_path, config_dir = _setup(tmp_path)
    run_id = "b" * 32
    _add_collection(
        db_path, config_dir, run_id=run_id, address="10.0.0.1",
        completed_at="2030-01-01T00:00:00+00:00",
    )
    with sqlite3.connect(db_path) as db:
        db.execute(
            """UPDATE device_collection_authority
               SET state='deleted', revision=2, deleted_at='2030-01-02T00:00:00+00:00'
               WHERE run_id=?""",
            (run_id,),
        )

    with pytest.raises(DeviceEvidenceCatalogError, match="restart NCT"):
        select_latest_device_evidence(db_path, config_dir)

    result = reconcile_device_evidence_catalog(db_path, config_dir)
    selected, descriptor = select_latest_device_evidence(db_path, config_dir)
    assert result["indexed"] == 0
    assert selected == []
    assert descriptor["dirty"] == []


def test_selector_reads_do_not_modify_database_or_manifests(tmp_path):
    db_path, config_dir = _setup(tmp_path)
    run_id = "c" * 32
    _add_collection(
        db_path, config_dir, run_id=run_id, address="10.0.0.1",
        completed_at="2030-01-01T00:00:00+00:00",
    )
    manifest_path = config_dir / run_id / "manifest.json"
    before_db = hashlib.sha256(db_path.read_bytes()).hexdigest()
    before_manifest = hashlib.sha256(manifest_path.read_bytes()).hexdigest()

    first = select_latest_device_evidence(db_path, config_dir)
    second = select_latest_device_evidence(db_path, config_dir)

    assert first == second
    assert hashlib.sha256(db_path.read_bytes()).hexdigest() == before_db
    assert hashlib.sha256(manifest_path.read_bytes()).hexdigest() == before_manifest


def test_same_size_same_time_manifest_change_requires_reconciliation(tmp_path):
    db_path, config_dir = _setup(tmp_path)
    run_id = "d" * 32
    _add_collection(
        db_path, config_dir, run_id=run_id, address="10.0.0.1",
        completed_at="2030-01-01T00:00:00+00:00",
    )
    manifest_path = config_dir / run_id / "manifest.json"
    before = manifest_path.read_text()
    stat = manifest_path.stat()
    first, first_descriptor = select_latest_device_evidence(db_path, config_dir)
    after = before.replace("10.0.0.1", "10.0.0.2")
    assert len(after.encode()) == len(before.encode())
    manifest_path.write_text(after)
    os.utime(manifest_path, ns=(stat.st_atime_ns, stat.st_mtime_ns))

    assert first[0]["device_key"] == "ip:10.0.0.1"
    assert first_descriptor["selected_run_ids"] == [run_id]
    with pytest.raises(DeviceEvidenceCatalogError, match="changed after selector indexing"):
        select_latest_device_evidence(db_path, config_dir)


def test_newest_integrity_failure_is_visible_instead_of_falling_back(tmp_path):
    db_path, config_dir = _setup(tmp_path)
    _add_collection(
        db_path, config_dir, run_id="1" * 32, address="10.0.0.1",
        completed_at="2030-01-01T00:00:00+00:00",
    )
    newest = _add_collection(
        db_path, config_dir, run_id="2" * 32, address="10.0.0.1",
        completed_at="2030-01-02T00:00:00+00:00",
    )
    newest["summary_authority"]["selection_contract"] = "wrong-contract"
    (config_dir / ("2" * 32) / "manifest.json").write_text(json.dumps(newest))

    with pytest.raises(DeviceEvidenceCatalogError, match="changed after selector indexing"):
        select_latest_device_evidence(db_path, config_dir)


def test_catalog_order_change_is_detected_instead_of_served(tmp_path):
    db_path, config_dir = _setup(tmp_path)
    run_id = "9" * 32
    _add_collection(
        db_path, config_dir, run_id=run_id, address="10.0.0.1",
        completed_at="2030-01-01T00:00:00+00:00",
    )
    with sqlite3.connect(db_path) as db:
        db.execute(
            "UPDATE device_evidence_catalog SET completed_at = ? WHERE run_id = ?",
            ("2099-01-01T00:00:00+00:00", run_id),
        )

    with pytest.raises(DeviceEvidenceCatalogError, match="no longer matches"):
        select_latest_device_evidence(db_path, config_dir)


def test_linked_manifest_is_rejected(tmp_path):
    db_path, config_dir = _setup(tmp_path)
    run_id = "e" * 32
    _add_collection(
        db_path, config_dir, run_id=run_id, address="10.0.0.1",
        completed_at="2030-01-01T00:00:00+00:00",
    )
    manifest_path = config_dir / run_id / "manifest.json"
    target = tmp_path / "linked-manifest.json"
    target.write_bytes(manifest_path.read_bytes())
    manifest_path.unlink()
    try:
        manifest_path.symlink_to(target)
    except OSError:
        pytest.skip("symbolic links are unavailable")

    with pytest.raises(DeviceEvidenceCatalogError, match="unsafe path"):
        select_latest_device_evidence(db_path, config_dir)
