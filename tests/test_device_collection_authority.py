from __future__ import annotations

import json
import sqlite3

import pytest
from fastapi.testclient import TestClient

from app.database import connect_database
from app.device_collection_authority import (
    AUTHORITY_MARKER,
    DeviceCollectionDeleted,
    DeviceCollectionIntegrityError,
    activate_manual_upload_authority,
    authority_manifest_marker,
    begin_manual_upload_authority,
    get_device_collection_authority,
    tombstone_device_collection,
)
from app.main import app
from app.poc import issue_delete_challenge


CONFIG = """===== show running-config =====
interface GigabitEthernet0/1
 ip address 10.80.0.1 255.255.255.0
ip route 0.0.0.0 0.0.0.0 192.0.2.1
"""


def _upload(client: TestClient, filename: str = "router.txt"):
    return client.post(
        "/api/device-configs/upload",
        data={
            "operator": "authority-analyst",
            "originating_host": "nct-test",
            "vendor": "cisco",
            "device_type": "router",
            "device_address": "192.0.2.10",
            "device_name": "Authority Router",
        },
        files={"result_file": (filename, CONFIG, "text/plain")},
    )


def test_new_uploads_use_active_authority_and_reuse_one_verified_result(
    tmp_path, monkeypatch,
):
    from app import device_analysis, device_configs

    db_path = tmp_path / "analyzer.db"
    config_dir = tmp_path / "device-configs"
    monkeypatch.setattr(device_configs, "DB_PATH", db_path)
    monkeypatch.setattr(device_configs, "CONFIG_DIR", config_dir)
    with TestClient(app) as client:
        first = _upload(client, "first.txt")
        second = _upload(client, "second.txt")

    assert first.status_code == second.status_code == 200
    first_id = first.json()["run_id"]
    second_id = second.json()["run_id"]
    assert get_device_collection_authority(db_path, first_id)["state"] == "active"
    assert get_device_collection_authority(db_path, second_id)["state"] == "active"

    first_analysis = device_analysis.analyze_device_collection(
        first_id,
        config_dir=config_dir,
        db_path=db_path,
        data_dir=tmp_path,
        include_correlations=False,
    )
    second_analysis = device_analysis.analyze_device_collection(
        second_id,
        config_dir=config_dir,
        db_path=db_path,
        data_dir=tmp_path,
        include_correlations=False,
    )
    warm = device_analysis.analyze_device_collection(
        first_id,
        config_dir=config_dir,
        db_path=db_path,
        data_dir=tmp_path,
        include_correlations=False,
    )

    assert first_analysis["counts"]["routes"] == 1
    assert second_analysis["counts"]["routes"] == 1
    assert warm == first_analysis
    with connect_database(db_path, read_only=True) as db:
        assert db.execute(
            "SELECT COUNT(*) FROM device_collection_authority WHERE state = 'active'"
        ).fetchone()[0] == 2
        assert db.execute(
            "SELECT COUNT(*) FROM derived_results WHERE family = 'device_collection_summary'"
        ).fetchone()[0] == 1
        cache_table = db.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'device_analysis_cache'"
        ).fetchone()
        assert cache_table is None


def test_presentation_change_is_visible_but_semantic_change_is_rejected(
    tmp_path, monkeypatch,
):
    from app import device_analysis, device_configs

    db_path = tmp_path / "analyzer.db"
    config_dir = tmp_path / "device-configs"
    monkeypatch.setattr(device_configs, "DB_PATH", db_path)
    monkeypatch.setattr(device_configs, "CONFIG_DIR", config_dir)
    monkeypatch.setattr(device_analysis, "DB_PATH", db_path)
    monkeypatch.setattr(device_analysis, "CONFIG_DIR", config_dir)
    with TestClient(app) as client:
        response = _upload(client)
    run_id = response.json()["run_id"]
    run_dir = config_dir / run_id

    initial = device_analysis.analyze_device_collection(
        run_id, config_dir=config_dir, db_path=db_path, data_dir=tmp_path,
        include_correlations=False,
    )
    manifest_path = run_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["device_name"] = "Renamed Router"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    renamed = device_analysis.analyze_device_collection(
        run_id, config_dir=config_dir, db_path=db_path, data_dir=tmp_path,
        include_correlations=False,
    )
    assert initial["device"]["name"] == "Authority Router"
    assert renamed["device"]["name"] == "Renamed Router"

    manifest["vendor"] = "juniper"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    with pytest.raises(DeviceCollectionIntegrityError, match="authority changed"):
        device_analysis.analyze_device_collection(
            run_id, config_dir=config_dir, db_path=db_path, data_dir=tmp_path,
            include_correlations=False,
        )
    with TestClient(app) as client:
        conflict = client.get(
            f"/api/device-analysis/{run_id}?include_correlations=false"
        )
    assert conflict.status_code == 409
    assert "authority changed" in conflict.json()["detail"]


def test_deletion_tombstone_blocks_analysis_and_can_retry_file_cleanup(
    tmp_path, monkeypatch,
):
    from app import device_analysis, device_configs

    db_path = tmp_path / "analyzer.db"
    config_dir = tmp_path / "device-configs"
    monkeypatch.setattr(device_configs, "DB_PATH", db_path)
    monkeypatch.setattr(device_configs, "CONFIG_DIR", config_dir)
    with TestClient(app) as client:
        response = _upload(client)
    run_id = response.json()["run_id"]
    run_dir = config_dir / run_id
    challenge = issue_delete_challenge("device-collection", run_id)["challenge"]
    original_rmtree = device_configs.shutil.rmtree

    def fail_cleanup(target):
        (target / "manifest.json").unlink()
        raise OSError("simulated cleanup failure")

    monkeypatch.setattr(device_configs.shutil, "rmtree", fail_cleanup)
    with pytest.raises(RuntimeError, match="marked deleted"):
        device_configs.delete_device_collection(
            run_id, challenge, config_dir=config_dir, db_path=db_path
        )
    assert run_dir.is_dir()
    assert not (run_dir / "manifest.json").exists()
    assert get_device_collection_authority(db_path, run_id)["state"] == "deleted"
    with pytest.raises(DeviceCollectionDeleted):
        device_analysis.analyze_device_collection(
            run_id, config_dir=config_dir, db_path=db_path, data_dir=tmp_path,
            include_correlations=False,
        )
    assert device_configs.history(limit=25) == []

    monkeypatch.setattr(device_configs.shutil, "rmtree", original_rmtree)
    retry = device_configs.collection_delete_challenge(run_id)["challenge"]
    assert device_configs.delete_device_collection(
        run_id, retry, config_dir=config_dir, db_path=db_path
    )["deleted"] is True
    assert not run_dir.exists()


def test_legacy_cache_writer_cannot_resurrect_collection_deleted_mid_analysis(
    tmp_path, monkeypatch,
):
    from app import device_analysis

    db_path = tmp_path / "analyzer.db"
    config_dir = tmp_path / "device-configs"
    run_id = "a" * 32
    run_dir = config_dir / run_id
    run_dir.mkdir(parents=True)
    (run_dir / "manifest.json").write_text(json.dumps({
        "run_id": run_id,
        "status": "uploaded",
        "vendor": "cisco",
        "commands": [],
    }))
    (run_dir / "uploaded-router.txt").write_text(CONFIG)
    original = device_analysis.device_collection_summary

    def calculate(*args, **kwargs):
        result = original(*args, **kwargs)
        tombstone_device_collection(db_path, run_id)
        return result

    monkeypatch.setattr(device_analysis, "device_collection_summary", calculate)
    with pytest.raises(DeviceCollectionDeleted, match="during analysis"):
        device_analysis._cached_device_summary(run_id, config_dir, db_path)
    with connect_database(db_path, read_only=True) as db:
        assert db.execute(
            "SELECT COUNT(*) FROM device_collections WHERE run_id = ?", (run_id,)
        ).fetchone()[0] == 0


def test_expected_authority_missing_is_not_treated_as_legacy(tmp_path):
    from app.device_collection_authority import require_available_collection

    manifest = {
        "run_id": "b" * 32,
        AUTHORITY_MARKER: authority_manifest_marker(),
    }
    with pytest.raises(DeviceCollectionIntegrityError, match="lifecycle record is missing"):
        require_available_collection(tmp_path / "missing.db", "b" * 32, manifest=manifest)


def test_changed_registered_bytes_return_integrity_conflict_from_both_summary_routes(
    tmp_path, monkeypatch,
):
    from app import device_analysis, device_configs

    db_path = tmp_path / "analyzer.db"
    config_dir = tmp_path / "device-configs"
    monkeypatch.setattr(device_configs, "DB_PATH", db_path)
    monkeypatch.setattr(device_configs, "CONFIG_DIR", config_dir)
    monkeypatch.setattr(device_analysis, "DB_PATH", db_path)
    monkeypatch.setattr(device_analysis, "CONFIG_DIR", config_dir)
    with TestClient(app) as client:
        response = _upload(client)
        run_id = response.json()["run_id"]
        manifest = json.loads((config_dir / run_id / "manifest.json").read_text())
        evidence = config_dir / run_id / manifest["retained_filename"]
        evidence.write_bytes(evidence.read_bytes().replace(b"10.80.0.1", b"10.81.0.1"))
        summary = client.get(f"/api/device-configs/{run_id}/summary")
        analysis = client.get(
            f"/api/device-analysis/{run_id}?include_correlations=false"
        )
    assert summary.status_code == 409
    assert analysis.status_code == 409
    assert "exact-content verification" in summary.json()["detail"]
    assert "exact-content verification" in analysis.json()["detail"]


@pytest.mark.parametrize("failure_stage", ["registration", "activation"])
def test_failed_upload_is_tombstoned_and_cannot_fall_back_to_legacy(
    tmp_path, monkeypatch, failure_stage,
):
    from app import device_configs

    db_path = tmp_path / "analyzer.db"
    config_dir = tmp_path / "device-configs"
    monkeypatch.setattr(device_configs, "DB_PATH", db_path)
    monkeypatch.setattr(device_configs, "CONFIG_DIR", config_dir)
    if failure_stage == "registration":
        monkeypatch.setattr(
            device_configs,
            "register_artifact_file",
            lambda **_: (_ for _ in ()).throw(RuntimeError("registration failed")),
        )
    else:
        monkeypatch.setattr(
            device_configs,
            "activate_manual_upload_authority",
            lambda *_, **__: (_ for _ in ()).throw(
                DeviceCollectionIntegrityError("activation failed")
            ),
        )
    with TestClient(app, raise_server_exceptions=False) as client:
        response = _upload(client)
    assert response.status_code == (500 if failure_stage == "registration" else 409)
    assert list(config_dir.iterdir()) == []
    with connect_database(db_path, read_only=True) as db:
        rows = db.execute(
            "SELECT state FROM device_collection_authority"
        ).fetchall()
    assert rows == [("deleted",)]


def test_rejected_empty_upload_never_creates_authority(tmp_path, monkeypatch):
    from app import device_configs

    db_path = tmp_path / "analyzer.db"
    config_dir = tmp_path / "device-configs"
    monkeypatch.setattr(device_configs, "DB_PATH", db_path)
    monkeypatch.setattr(device_configs, "CONFIG_DIR", config_dir)
    with TestClient(app) as client:
        response = client.post(
            "/api/device-configs/upload",
            data={
                "operator": "authority-analyst",
                "originating_host": "nct-test",
                "vendor": "cisco",
                "device_type": "router",
                "device_address": "192.0.2.10",
            },
            files={"result_file": ("empty.txt", b"", "text/plain")},
        )
    assert response.status_code == 422
    assert not db_path.exists()


def test_deleted_identity_cannot_be_reactivated(tmp_path):
    db_path = tmp_path / "analyzer.db"
    run_id = "c" * 32
    begin_manual_upload_authority(db_path, run_id)
    tombstone_device_collection(db_path, run_id)
    with pytest.raises(DeviceCollectionIntegrityError, match="already in use"):
        begin_manual_upload_authority(db_path, run_id)
    with connect_database(db_path) as db:
        with pytest.raises(sqlite3.IntegrityError, match="transition|reactivated"):
            db.execute(
                "UPDATE device_collection_authority SET state = 'preparing' WHERE run_id = ?",
                (run_id,),
            )


def test_active_authority_cannot_be_downgraded_or_rewritten_during_deletion(
    tmp_path, monkeypatch,
):
    from app import device_configs

    db_path = tmp_path / "analyzer.db"
    config_dir = tmp_path / "device-configs"
    monkeypatch.setattr(device_configs, "DB_PATH", db_path)
    monkeypatch.setattr(device_configs, "CONFIG_DIR", config_dir)
    with TestClient(app) as client:
        response = _upload(client)
    run_id = response.json()["run_id"]
    before = get_device_collection_authority(db_path, run_id)
    with connect_database(db_path) as db:
        with pytest.raises(sqlite3.IntegrityError, match="illegal.*transition"):
            db.execute(
                "UPDATE device_collection_authority SET state = 'preparing' WHERE run_id = ?",
                (run_id,),
            )
    with connect_database(db_path) as db:
        with pytest.raises(sqlite3.IntegrityError, match="authority is immutable"):
            db.execute(
                """UPDATE device_collection_authority
                   SET state = 'deleted', revision = revision + 1,
                       artifact_sha256 = 'rewritten', deleted_at = '2026-10-03T00:00:00+00:00'
                   WHERE run_id = ?""",
                (run_id,),
            )
    after = tombstone_device_collection(db_path, run_id)
    assert after["state"] == "deleted"
    for key in (
        "artifact_observation_id", "artifact_sha256", "retained_filename",
        "selection_contract", "semantic_manifest_json", "semantic_manifest_sha256",
    ):
        assert after[key] == before[key]
