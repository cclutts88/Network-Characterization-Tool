import json
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.database import connect_database
from app.device_collection_authority import (
    COLLECTED_DEVICE_SELECTION_CONTRACT,
    DeviceCollectionIncomplete,
    DeviceCollectionIntegrityError,
    get_device_collection_authority,
)
from app import device_configs
from app.device_summary_result import analyze_collected_device_summary


CONFIG = """===== show running-config =====
hostname verified-router
interface GigabitEthernet0/1
 ip address 10.88.0.1 255.255.255.0
ip route 0.0.0.0 0.0.0.0 192.0.2.1
===== show startup-config =====
hostname verified-router
interface GigabitEthernet0/1
 ip address 10.88.0.1 255.255.255.0
ip route 0.0.0.0 0.0.0.0 192.0.2.1
"""


def finalized_collection(tmp_path, monkeypatch, *, run_id="1" * 32, history=True):
    db_path = tmp_path / "analyzer.db"
    config_dir = tmp_path / "device-configs"
    run_dir = config_dir / run_id
    run_dir.mkdir(parents=True)
    monkeypatch.setattr(device_configs, "DB_PATH", db_path)
    monkeypatch.setattr(device_configs, "CONFIG_DIR", config_dir)
    (run_dir / "router-config.txt").write_text(CONFIG)
    (run_dir / "stdout.txt").write_text("bounded response preview\n")
    (run_dir / "stderr.txt").write_text("")
    if history is not None:
        (run_dir / "command-history.txt").write_text(
            "10 show version\n11 configure terminal\n" if history else ""
        )
    manifest = {
        "run_id": run_id,
        "created_at": "2026-10-03T20:00:00+00:00",
        "completed_at": "2026-10-03T20:01:00+00:00",
        "operator": "analyst",
        "originating_host": "nct-test",
        "vendor": "cisco",
        "device_type": "router",
        "device_address": "10.88.0.1",
        "device_name": "Verified Router",
        "operation": "configuration_pull",
        "status": "completed",
        "output_complete": True,
        "output_truncated": False,
        "command_history_truncated": False,
        "command_history_status": "captured" if history else "unavailable",
        "command_history_artifact": "command-history.txt" if history is not None else None,
        "history_command": "show history",
        "commands": ["show running-config", "show startup-config", "show history"],
        "local_output_name": "router-config.txt",
    }
    (run_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    assert device_configs._finalize_device_collection(run_dir, manifest) is True
    return db_path, config_dir, run_dir, manifest


def test_completed_ssh_collection_uses_verified_reusable_summary(tmp_path, monkeypatch):
    db_path, _, run_dir, manifest = finalized_collection(tmp_path, monkeypatch)
    run_id = manifest["run_id"]
    authority = get_device_collection_authority(db_path, run_id)
    assert authority["state"] == "active"
    assert authority["selection_contract"] == COLLECTED_DEVICE_SELECTION_CONTRACT

    first = analyze_collected_device_summary(db_path, run_id, run_dir)
    warm = analyze_collected_device_summary(db_path, run_id, run_dir)
    assert first["payload"]["counts"]["routes"] == 1
    assert first["source_content"]["raw_output"] == "bounded response preview\n"
    assert first["payload"]["command_history"]["entries"][1]["line_number"] == 2
    assert warm["result_id"] == first["result_id"]
    assert warm["reused"] is True
    with connect_database(db_path, read_only=True) as db:
        assert db.execute(
            "SELECT COUNT(*) FROM device_collection_authority_inputs WHERE run_id = ?",
            (run_id,),
        ).fetchone()[0] == 3
        assert db.execute(
            "SELECT COUNT(*) FROM derived_results WHERE family = 'device_collection_summary'"
        ).fetchone()[0] == 1
        assert db.execute(
            "SELECT COUNT(*) FROM derived_result_observation_links WHERE result_id = ?",
            (first["result_id"],),
        ).fetchone()[0] == 3


def test_interactive_finalization_uses_same_verified_authority(tmp_path, monkeypatch):
    db_path = tmp_path / "analyzer.db"
    config_dir = tmp_path / "device-configs"
    monkeypatch.setattr(device_configs, "DB_PATH", db_path)
    monkeypatch.setattr(device_configs, "CONFIG_DIR", config_dir)
    monkeypatch.setattr(device_configs, "_close_interactive_resources", lambda session: None)
    monkeypatch.setattr(device_configs, "capture_is_valid", lambda run_dir: True)
    plan = device_configs.DeviceConfigPlan(
        vendor="cisco", device_type="router", device_address="10.88.0.1",
        username="analyst", authentication_mode="password_prompt",
        operator="analyst", originating_host="nct-test",
        accountability_interface="eth0",
    )
    preview = device_configs.build_plan(plan)
    run_dir = config_dir / preview["run_id"]
    run_dir.mkdir(parents=True)
    (run_dir / preview["local_output_name"]).write_text(CONFIG)
    (run_dir / "stdout.txt").write_text("preview\n")
    (run_dir / "command-history.txt").write_text("10 show version\n")
    manifest = device_configs.manifest_for(
        plan, preview, "running", operation="interactive_configuration_pull"
    )
    session = SimpleNamespace(
        session_id="interactive-test", plan=plan, preview=preview,
        run_dir=run_dir, manifest=manifest,
    )
    result = device_configs._finish_interactive_session(
        session,
        status="completed",
        stderr="",
        failure_class=None,
        exit_code=0,
        extra={
            "local_output_name": preview["local_output_name"],
            "output_truncated": False,
            "command_history_status": "captured",
            "command_history_truncated": False,
            "command_history_artifact": "command-history.txt",
        },
    )
    assert result["summary_verification_status"] == "verified"
    authority = get_device_collection_authority(db_path, preview["run_id"])
    assert authority["state"] == "active"
    assert authority["selection_contract"] == COLLECTED_DEVICE_SELECTION_CONTRACT


def test_empty_history_file_wins_over_embedded_history(tmp_path, monkeypatch):
    db_path, _, run_dir, manifest = finalized_collection(
        tmp_path, monkeypatch, history=False
    )
    result = analyze_collected_device_summary(
        db_path, manifest["run_id"], run_dir
    )
    assert result["payload"]["command_history"]["status"] == "unavailable"
    with connect_database(db_path, read_only=True) as db:
        row = db.execute(
            """SELECT source_kind, filename, size_bytes
               FROM device_collection_authority_inputs
               WHERE run_id = ? AND input_role = 'command_history'""",
            (manifest["run_id"],),
        ).fetchone()
    assert row == ("artifact_file", "command-history.txt", 0)


def test_missing_history_uses_frozen_absence_descriptor(tmp_path, monkeypatch):
    db_path, _, run_dir, manifest = finalized_collection(
        tmp_path, monkeypatch, history=None
    )
    result = analyze_collected_device_summary(
        db_path, manifest["run_id"], run_dir
    )
    assert result["payload"]["command_history"]["status"] == "unavailable"
    with connect_database(db_path, read_only=True) as db:
        row = db.execute(
            """SELECT source_kind, filename
               FROM device_collection_authority_inputs
               WHERE run_id = ? AND input_role = 'command_history'""",
            (manifest["run_id"],),
        ).fetchone()
    assert row == ("absent", None)


def test_changed_or_newly_preferred_file_is_an_integrity_conflict(tmp_path, monkeypatch):
    db_path, _, run_dir, manifest = finalized_collection(tmp_path, monkeypatch)
    (run_dir / "router-config.txt").unlink()
    (run_dir / "router-config.txt").write_text(CONFIG.replace("10.88.0.1", "10.89.0.1"))
    with pytest.raises(ValueError, match="exact-content verification"):
        analyze_collected_device_summary(db_path, manifest["run_id"], run_dir)

    db_path, _, run_dir, manifest = finalized_collection(
        tmp_path, monkeypatch, run_id="2" * 32
    )
    (run_dir / "aaa-config.txt").write_text(CONFIG)
    with pytest.raises(ValueError, match="registration is incomplete"):
        analyze_collected_device_summary(db_path, manifest["run_id"], run_dir)


def test_verification_failure_retries_locally_without_duplicate_observations(
    tmp_path, monkeypatch,
):
    original_activate = device_configs.activate_collected_device_authority
    monkeypatch.setattr(
        device_configs,
        "activate_collected_device_authority",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            DeviceCollectionIntegrityError("simulated activation interruption")
        ),
    )
    db_path = tmp_path / "analyzer.db"
    config_dir = tmp_path / "device-configs"
    run_id = "3" * 32
    run_dir = config_dir / run_id
    run_dir.mkdir(parents=True)
    monkeypatch.setattr(device_configs, "DB_PATH", db_path)
    monkeypatch.setattr(device_configs, "CONFIG_DIR", config_dir)
    (run_dir / "router-config.txt").write_text(CONFIG)
    (run_dir / "stdout.txt").write_text("preview\n")
    manifest = {
        "run_id": run_id, "created_at": "2026-10-03T20:00:00+00:00",
        "completed_at": "2026-10-03T20:01:00+00:00", "operator": "analyst",
        "vendor": "cisco", "device_type": "router", "device_address": "10.88.0.1",
        "operation": "configuration_pull", "status": "completed",
        "output_complete": True, "output_truncated": False,
        "command_history_truncated": False, "commands": ["show running-config"],
        "history_command": "show history", "local_output_name": "router-config.txt",
    }
    (run_dir / "manifest.json").write_text(json.dumps(manifest))
    assert device_configs._finalize_device_collection(run_dir, manifest) is False
    assert manifest["status"] == "completed"
    assert manifest["summary_verification_status"] == "conflict"
    assert get_device_collection_authority(db_path, run_id)["state"] == "preparing"
    with connect_database(db_path, read_only=True) as db:
        before = db.execute(
            "SELECT COUNT(*) FROM artifact_observations WHERE source_ref = ?", (run_id,)
        ).fetchone()[0]

    monkeypatch.setattr(
        device_configs, "activate_collected_device_authority", original_activate
    )
    changed_config = run_dir / "router-config.txt"
    changed_config.unlink()
    changed_config.write_text(CONFIG.replace("10.88.0.1", "10.89.0.1"))
    with pytest.raises(HTTPException) as rejected:
        device_configs.retry_summary_verification(run_id)
    assert rejected.value.status_code == 409
    assert "could not verify" in rejected.value.detail
    assert get_device_collection_authority(db_path, run_id)["state"] == "preparing"
    with connect_database(db_path, read_only=True) as db:
        unchanged = db.execute(
            "SELECT COUNT(*) FROM artifact_observations WHERE source_ref = ?", (run_id,)
        ).fetchone()[0]
    assert unchanged == before

    changed_config.unlink()
    changed_config.write_text(CONFIG)
    retried = device_configs.retry_summary_verification(run_id)
    assert retried["status"] == "verified"
    assert retried["network_contacted"] is False
    assert get_device_collection_authority(db_path, run_id)["state"] == "active"
    with connect_database(db_path, read_only=True) as db:
        after = db.execute(
            "SELECT COUNT(*) FROM artifact_observations WHERE source_ref = ?", (run_id,)
        ).fetchone()[0]
    assert after == before


def test_file_replacement_between_freeze_and_registration_cannot_activate(
    tmp_path, monkeypatch,
):
    original_register = device_configs.register_finalized_files
    replaced = False

    def replace_before_registration(*args, **kwargs):
        nonlocal replaced
        run_dir = args[1]
        if kwargs.get("expected_files") is not None and not replaced:
            path = run_dir / "router-config.txt"
            path.unlink()
            path.write_text(CONFIG.replace("10.88.0.1", "10.89.0.1"))
            replaced = True
        return original_register(*args, **kwargs)

    monkeypatch.setattr(
        device_configs, "register_finalized_files", replace_before_registration
    )
    db_path = tmp_path / "analyzer.db"
    config_dir = tmp_path / "device-configs"
    run_id = "5" * 32
    run_dir = config_dir / run_id
    run_dir.mkdir(parents=True)
    monkeypatch.setattr(device_configs, "DB_PATH", db_path)
    monkeypatch.setattr(device_configs, "CONFIG_DIR", config_dir)
    (run_dir / "router-config.txt").write_text(CONFIG)
    (run_dir / "stdout.txt").write_text("preview\n")
    manifest = {
        "run_id": run_id, "created_at": "2026-10-03T20:00:00+00:00",
        "completed_at": "2026-10-03T20:01:00+00:00", "operator": "analyst",
        "vendor": "cisco", "device_type": "router", "device_address": "10.88.0.1",
        "operation": "configuration_pull", "status": "completed",
        "output_complete": True, "output_truncated": False,
        "command_history_truncated": False, "commands": ["show running-config"],
        "history_command": "show history", "local_output_name": "router-config.txt",
    }
    (run_dir / "manifest.json").write_text(json.dumps(manifest))

    assert device_configs._finalize_device_collection(run_dir, manifest) is False
    assert manifest["summary_verification_status"] == "conflict"
    assert get_device_collection_authority(db_path, run_id)["state"] == "preparing"
    frozen = manifest["summary_verification_contract"]["files"]
    expected = next(item for item in frozen if item["filename"] == "router-config.txt")
    with connect_database(db_path, read_only=True) as db:
        rows = db.execute(
            "SELECT sha256 FROM artifact_observations WHERE source_ref = ?",
            (run_id,),
        ).fetchall()
    assert expected["sha256"] not in {row[0] for row in rows}


@pytest.mark.parametrize(
    "status,output_complete,output_truncated",
    [("failed", False, False), ("completed", False, True)],
)
def test_incomplete_collections_never_fall_back_to_old_analysis(
    tmp_path, monkeypatch, status, output_complete, output_truncated,
):
    db_path = tmp_path / "analyzer.db"
    config_dir = tmp_path / "device-configs"
    run_id = "4" * 32
    run_dir = config_dir / run_id
    run_dir.mkdir(parents=True)
    monkeypatch.setattr(device_configs, "DB_PATH", db_path)
    monkeypatch.setattr(device_configs, "CONFIG_DIR", config_dir)
    (run_dir / "router-config.txt").write_text(CONFIG)
    manifest = {
        "run_id": run_id, "created_at": "2026-10-03T20:00:00+00:00",
        "completed_at": "2026-10-03T20:01:00+00:00", "operator": "analyst",
        "vendor": "cisco", "operation": "configuration_pull", "status": status,
        "output_complete": output_complete, "output_truncated": output_truncated,
        "command_history_truncated": False,
    }
    (run_dir / "manifest.json").write_text(json.dumps(manifest))
    assert device_configs._finalize_device_collection(run_dir, manifest) is False
    assert get_device_collection_authority(db_path, run_id) is None
    with pytest.raises(DeviceCollectionIncomplete, match="not eligible"):
        from app.device_analysis import _device_summary_snapshot

        _device_summary_snapshot(run_id, config_dir, db_path)
