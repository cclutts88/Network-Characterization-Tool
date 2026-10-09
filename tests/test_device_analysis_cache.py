from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from app import database
from app import device_analysis_cache
from app import derived_jobs as jobs
from app import device_analysis, main
from app.artifacts import register_artifact_file
from app.database import connect_database
from app.device_analysis_cache import (
    DeviceAnalysisSnapshotError,
    capture_device_analysis_snapshot,
)
from app.device_collection_authority import (
    AUTHORITY_MARKER,
    activate_manual_upload_authority,
    authority_manifest_marker,
    begin_manual_upload_authority,
    tombstone_device_collection,
)
from app.device_observations import init_device_observation_storage
from app.device_observations import assign_device_scope, correct_device_scope
from app.network_scopes import archive_network_scope, create_network_scope
from app.network_semantics import init_network_semantics_storage, set_external_wan_gateway


CONFIG = b"""===== show running-config =====
hostname cache-router
interface GigabitEthernet0/1
 ip address 10.90.0.1 255.255.255.0
ip route 0.0.0.0 0.0.0.0 192.0.2.1
"""


def _ready_device(
    tmp_path: Path,
    *,
    run_id: str = "a" * 32,
    address: str = "192.0.2.1",
    name: str = "Cache Router",
):
    db_path = tmp_path / "analyzer.db"
    config_dir = tmp_path / "device-configs"
    run_dir = config_dir / run_id
    run_dir.mkdir(parents=True)
    init_device_observation_storage(db_path)
    init_network_semantics_storage(db_path)
    begin_manual_upload_authority(db_path, run_id)
    evidence = run_dir / "uploaded-router.txt"
    evidence.write_bytes(CONFIG)
    artifact = register_artifact_file(
        db_path=db_path,
        source_path=evidence,
        source_kind="device_config_upload",
        source_ref=run_id,
        original_filename="router.txt",
        actor="cache-tester",
        observation_key=f"device_config_upload:{run_id}:uploaded-router.txt",
    )
    manifest = {
        "run_id": run_id,
        "operation": "manual_upload",
        "status": "uploaded",
        "vendor": "cisco",
        "device_type": "router",
        "device_name": name,
        "device_address": address,
        "operator": "cache-tester",
        "created_at": "2030-01-01T00:00:00+00:00",
        "completed_at": "2030-01-01T00:00:00+00:00",
        "retained_filename": "uploaded-router.txt",
        "artifact_sha256": artifact["sha256"],
        "artifact_observation_id": artifact["observation_id"],
        "output_complete": True,
        "commands": [],
        AUTHORITY_MARKER: authority_manifest_marker(),
    }
    (run_dir / "manifest.json").write_text(
        json.dumps(manifest, sort_keys=True), encoding="utf-8"
    )
    activate_manual_upload_authority(
        db_path,
        run_id,
        observation_id=artifact["observation_id"],
        artifact_sha256=artifact["sha256"],
        retained_filename="uploaded-router.txt",
        manifest=manifest,
    )
    assert jobs.dispatch_next_pipeline_intake(db_path) is True
    assert jobs.run_next_derived_job(db_path, tmp_path) is True
    return db_path, config_dir, run_id, evidence


def _logical_dump(db_path: Path) -> str:
    with sqlite3.connect(db_path) as db:
        return "\n".join(db.iterdump())


def _deny_database_writes(monkeypatch) -> None:
    original_connect = database.sqlite3.connect
    denied_actions = {
        sqlite3.SQLITE_INSERT, sqlite3.SQLITE_UPDATE, sqlite3.SQLITE_DELETE,
        sqlite3.SQLITE_CREATE_INDEX, sqlite3.SQLITE_CREATE_TABLE,
        sqlite3.SQLITE_CREATE_TRIGGER, sqlite3.SQLITE_CREATE_VIEW,
        sqlite3.SQLITE_DROP_INDEX, sqlite3.SQLITE_DROP_TABLE,
        sqlite3.SQLITE_DROP_TRIGGER, sqlite3.SQLITE_DROP_VIEW,
        sqlite3.SQLITE_ALTER_TABLE, sqlite3.SQLITE_REINDEX,
    }

    def connect(*args, **kwargs):
        connection = original_connect(*args, **kwargs)
        connection.set_authorizer(
            lambda action, *_args: (
                sqlite3.SQLITE_DENY if action in denied_actions else sqlite3.SQLITE_OK
            )
        )
        return connection

    monkeypatch.setattr(database.sqlite3, "connect", connect)


def test_snapshot_captures_completed_verified_device_without_writes(tmp_path):
    db_path, config_dir, run_id, _evidence = _ready_device(tmp_path)
    before = _logical_dump(db_path)

    first = capture_device_analysis_snapshot(db_path=db_path, config_dir=config_dir)
    second = capture_device_analysis_snapshot(db_path=db_path, config_dir=config_dir)

    assert first.key is not None and second.key == first.key
    assert first.context["selected_run_ids"] == [run_id]
    assert _logical_dump(db_path) == before


def test_exact_same_size_same_time_evidence_change_fails_closed(tmp_path):
    db_path, config_dir, _run_id, evidence = _ready_device(tmp_path)
    times = evidence.stat()
    changed = CONFIG.replace(b"10.90.0.1", b"10.91.0.1")
    assert len(changed) == len(CONFIG)
    evidence.write_bytes(changed)
    os.utime(evidence, ns=(times.st_atime_ns, times.st_mtime_ns))

    with pytest.raises(DeviceAnalysisSnapshotError, match="exact authority"):
        capture_device_analysis_snapshot(db_path=db_path, config_dir=config_dir)


def test_missing_intent_and_result_link_fail_without_page_read_repairs(tmp_path):
    db_path, config_dir, run_id, _evidence = _ready_device(tmp_path)
    with connect_database(db_path) as db:
        db.execute("DROP TRIGGER pipeline_admission_intents_no_delete")
        db.execute(
            "DELETE FROM pipeline_admission_intents WHERE source_id = ?", (run_id,)
        )
    before = _logical_dump(db_path)
    with pytest.raises(DeviceAnalysisSnapshotError, match="admission intent"):
        capture_device_analysis_snapshot(db_path=db_path, config_dir=config_dir)
    assert _logical_dump(db_path) == before

    # Restore with a fresh fixture and independently remove one immutable link.
    other = tmp_path / "link-case"
    other.mkdir()
    db_path, config_dir, _run_id, _evidence = _ready_device(other)
    with connect_database(db_path) as db:
        db.execute(
            """DELETE FROM derived_result_observation_links
               WHERE input_role = 'raw_output'"""
        )
    before = _logical_dump(db_path)
    with pytest.raises(DeviceAnalysisSnapshotError, match="links are incomplete"):
        capture_device_analysis_snapshot(db_path=db_path, config_dir=config_dir)
    assert _logical_dump(db_path) == before


def test_main_cache_returns_private_results_and_cold_build_is_read_only(
    tmp_path, monkeypatch,
):
    db_path, config_dir, _run_id, _evidence = _ready_device(tmp_path)
    monkeypatch.setattr(main, "DB_PATH", db_path)
    monkeypatch.setattr(main, "CONFIG_DIR", config_dir)
    monkeypatch.setattr(device_analysis, "DB_PATH", db_path)
    monkeypatch.setattr(device_analysis, "CONFIG_DIR", config_dir)
    main._DEVICE_ANALYSIS_CACHE.clear()
    before = _logical_dump(db_path)
    _deny_database_writes(monkeypatch)

    first = main._latest_device_reachability_evidence()
    first[0]["device"]["name"] = "caller mutation"
    second = main._latest_device_reachability_evidence()

    assert second[0]["device"]["name"] == "Cache Router"
    assert first is not second
    assert main._DEVICE_ANALYSIS_CACHE.status()["hits"] == 1
    assert _logical_dump(db_path) == before


def test_database_replacement_forces_read_only_cold_build(tmp_path, monkeypatch):
    db_path, config_dir, _run_id, _evidence = _ready_device(tmp_path)
    monkeypatch.setattr(main, "DB_PATH", db_path)
    monkeypatch.setattr(main, "CONFIG_DIR", config_dir)
    monkeypatch.setattr(device_analysis, "DB_PATH", db_path)
    monkeypatch.setattr(device_analysis, "CONFIG_DIR", config_dir)
    main._DEVICE_ANALYSIS_CACHE.clear()
    assert main._latest_device_reachability_evidence()

    replacement = tmp_path / "replacement.db"
    with sqlite3.connect(db_path) as source, sqlite3.connect(replacement) as target:
        source.backup(target)
    os.replace(replacement, db_path)
    before = _logical_dump(db_path)
    _deny_database_writes(monkeypatch)

    rebuilt = main._latest_device_reachability_evidence()

    assert rebuilt[0]["device"]["name"] == "Cache Router"
    assert main._DEVICE_ANALYSIS_CACHE.status()["misses"] == 2
    assert _logical_dump(db_path) == before


def test_warm_cache_invalidates_after_authority_deletion(tmp_path, monkeypatch):
    db_path, config_dir, run_id, _evidence = _ready_device(tmp_path)
    monkeypatch.setattr(main, "DB_PATH", db_path)
    monkeypatch.setattr(main, "CONFIG_DIR", config_dir)
    monkeypatch.setattr(device_analysis, "DB_PATH", db_path)
    monkeypatch.setattr(device_analysis, "CONFIG_DIR", config_dir)
    main._DEVICE_ANALYSIS_CACHE.clear()

    assert len(main._latest_device_reachability_evidence()) == 1
    tombstone_device_collection(db_path, run_id)
    assert main._latest_device_reachability_evidence() == []
    assert main._DEVICE_ANALYSIS_CACHE.status()["misses"] == 2


def test_database_replacement_between_selector_and_dependencies_is_rejected(
    tmp_path, monkeypatch,
):
    db_path, config_dir, _run_id, _evidence = _ready_device(tmp_path)
    replacement = tmp_path / "replacement.db"
    with sqlite3.connect(db_path) as source, sqlite3.connect(replacement) as target:
        source.backup(target)
    original_select = device_analysis_cache.select_latest_device_evidence
    calls = 0

    def replacing_select(*args, **kwargs):
        nonlocal calls
        result = original_select(*args, **kwargs)
        calls += 1
        if calls == 1:
            os.replace(replacement, db_path)
        return result

    monkeypatch.setattr(
        device_analysis_cache, "select_latest_device_evidence", replacing_select
    )

    with pytest.raises(DeviceAnalysisSnapshotError, match="dependencies were captured"):
        capture_device_analysis_snapshot(db_path=db_path, config_dir=config_dir)


def test_manifest_candidate_scope_wan_and_contract_changes_change_key(tmp_path, monkeypatch):
    db_path, config_dir, run_id, _evidence = _ready_device(tmp_path)
    first = capture_device_analysis_snapshot(db_path=db_path, config_dir=config_dir)

    manifest_path = config_dir / run_id / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    formatted = capture_device_analysis_snapshot(db_path=db_path, config_dir=config_dir)
    assert formatted.key != first.key

    extra = config_dir / run_id / "uploaded-z.txt"
    extra.write_text("candidate", encoding="utf-8")
    candidate = capture_device_analysis_snapshot(db_path=db_path, config_dir=config_dir)
    assert candidate.key != formatted.key
    extra.unlink()

    scope_a = create_network_scope(
        db_path, label="Alpha", created_by="tester", reason="cache test"
    )
    assignment = assign_device_scope(
        db_path, run_id=run_id, scope_id=scope_a["scope_id"], actor="tester",
        reason="cache test", whole_collection_confirmed=True,
    )
    scoped = capture_device_analysis_snapshot(db_path=db_path, config_dir=config_dir)
    assert scoped.key != candidate.key

    scope_b = create_network_scope(
        db_path, label="Bravo", created_by="tester", reason="cache test"
    )
    correct_device_scope(
        db_path,
        expected_assignment_id=assignment["assignment_id"],
        destination_scope_id=scope_b["scope_id"], actor="tester",
        reason="corrected", whole_collection_confirmed=True,
    )
    corrected = capture_device_analysis_snapshot(db_path=db_path, config_dir=config_dir)
    assert corrected.key != scoped.key
    archive_network_scope(
        db_path, scope_b["scope_id"], expected_version=1,
        archived_by="tester", reason="archive test",
    )
    archived = capture_device_analysis_snapshot(db_path=db_path, config_dir=config_dir)
    assert archived.key != corrected.key

    set_external_wan_gateway(
        db_path, node_id="ip:192.0.2.1", device_name="Cache Router",
        device_address="192.0.2.1", interface_names=["GigabitEthernet0/1"],
        changed_by="tester",
    )
    wan = capture_device_analysis_snapshot(db_path=db_path, config_dir=config_dir)
    assert wan.key != archived.key
    assert wan.context["gateways"][0]["interface_names"] == ["GigabitEthernet0/1"]

    monkeypatch.setattr(
        device_analysis_cache, "DEVICE_ANALYSIS_VIEW_CONTRACT_VERSION", 999
    )
    contract = capture_device_analysis_snapshot(db_path=db_path, config_dir=config_dir)
    assert contract.key != wan.key


def test_completed_interface_assessment_refreshes_returned_scope_observation(
    tmp_path, monkeypatch,
):
    db_path, config_dir, run_id, _evidence = _ready_device(tmp_path)
    monkeypatch.setattr(main, "DB_PATH", db_path)
    monkeypatch.setattr(main, "CONFIG_DIR", config_dir)
    monkeypatch.setattr(device_analysis, "DB_PATH", db_path)
    monkeypatch.setattr(device_analysis, "CONFIG_DIR", config_dir)
    main._DEVICE_ANALYSIS_CACHE.clear()
    scope = create_network_scope(
        db_path, label="Assessment scope", created_by="tester", reason="cache test"
    )
    assign_device_scope(
        db_path, run_id=run_id, scope_id=scope["scope_id"], actor="tester",
        reason="confirmed collection scope", whole_collection_confirmed=True,
    )

    pending = main._latest_device_reachability_evidence()[0]["scope_observation"]
    assert pending["state"] == "waiting"
    assert jobs.dispatch_next_pipeline_intake(db_path) is True
    assert jobs.run_next_derived_job(db_path, tmp_path) is True

    completed = main._latest_device_reachability_evidence()[0]["scope_observation"]
    assert completed["state"] == "completed"
    assert completed["assignment"]["scope_id"] == scope["scope_id"]
    assert completed["assessment"]["assessment_id"]
    assert completed != pending


def test_more_than_one_hundred_distinct_devices_reach_cached_builder(
    tmp_path, monkeypatch,
):
    for index in range(101):
        _ready_device(
            tmp_path,
            run_id=f"{index + 1:032x}",
            address=f"10.0.{index // 254}.{index % 254 + 1}",
            name=f"Router {index + 1}",
        )
    db_path = tmp_path / "analyzer.db"
    config_dir = tmp_path / "device-configs"
    monkeypatch.setattr(main, "DB_PATH", db_path)
    monkeypatch.setattr(main, "CONFIG_DIR", config_dir)
    monkeypatch.setattr(device_analysis, "DB_PATH", db_path)
    monkeypatch.setattr(device_analysis, "CONFIG_DIR", config_dir)
    main._DEVICE_ANALYSIS_CACHE.clear()
    seen = []

    def counted(run_id, **_kwargs):
        seen.append(run_id)
        return {"run_id": run_id, "device": {"name": run_id}}

    monkeypatch.setattr(main, "analyze_device_collection", counted)
    result = main._latest_device_reachability_evidence()

    assert len(result) == 101
    assert len(seen) == 101
    assert main._DEVICE_ANALYSIS_CACHE.status()["misses"] == 1
    assert main._latest_device_reachability_evidence() == result
    assert len(seen) == 101


def test_mid_build_manifest_change_retries_and_recovers(tmp_path, monkeypatch):
    db_path, config_dir, run_id, _evidence = _ready_device(tmp_path)
    monkeypatch.setattr(main, "DB_PATH", db_path)
    monkeypatch.setattr(main, "CONFIG_DIR", config_dir)
    monkeypatch.setattr(device_analysis, "DB_PATH", db_path)
    monkeypatch.setattr(device_analysis, "CONFIG_DIR", config_dir)
    main._DEVICE_ANALYSIS_CACHE.clear()
    original_analyze = main.analyze_device_collection
    calls = 0

    def changing(run_id, **kwargs):
        nonlocal calls
        calls += 1
        result = original_analyze(run_id, **kwargs)
        if calls == 1:
            manifest_path = config_dir / run_id / "manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest_path.write_text(
                json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
            )
        return result

    monkeypatch.setattr(main, "analyze_device_collection", changing)
    result = main._latest_device_reachability_evidence()

    assert result[0]["run_id"] == run_id
    assert calls == 2
    assert main._DEVICE_ANALYSIS_CACHE.status()["misses"] == 2


def test_identical_device_requests_share_one_build_and_recover_after_failure(
    tmp_path, monkeypatch,
):
    db_path, config_dir, _run_id, _evidence = _ready_device(tmp_path)
    monkeypatch.setattr(main, "DB_PATH", db_path)
    monkeypatch.setattr(main, "CONFIG_DIR", config_dir)
    monkeypatch.setattr(device_analysis, "DB_PATH", db_path)
    monkeypatch.setattr(device_analysis, "CONFIG_DIR", config_dir)
    real_analyze = main.analyze_device_collection
    entered = threading.Event()
    release = threading.Event()
    build_count = 0

    def delayed(*args, **kwargs):
        nonlocal build_count
        build_count += 1
        entered.set()
        assert release.wait(5)
        return real_analyze(*args, **kwargs)

    main._DEVICE_ANALYSIS_CACHE.clear()
    monkeypatch.setattr(main, "analyze_device_collection", delayed)
    with ThreadPoolExecutor(max_workers=6) as pool:
        futures = [
            pool.submit(main._latest_device_reachability_evidence) for _ in range(6)
        ]
        assert entered.wait(5)
        release.set()
        results = [future.result(timeout=10) for future in futures]
    assert build_count == 1
    assert all(value == results[0] for value in results)
    assert len({id(value) for value in results}) == len(results)

    attempts = 0

    def fail_once(*args, **kwargs):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise RuntimeError("injected cold-build failure")
        return real_analyze(*args, **kwargs)

    main._DEVICE_ANALYSIS_CACHE.clear()
    monkeypatch.setattr(main, "analyze_device_collection", fail_once)
    with pytest.raises(RuntimeError, match="injected cold-build failure"):
        main._latest_device_reachability_evidence()
    assert main._DEVICE_ANALYSIS_CACHE.status()["in_flight"] == 0
    assert main._latest_device_reachability_evidence()
    assert attempts == 2


def test_intent_change_and_deletion_invalidate_selected_device_snapshot(tmp_path):
    db_path, config_dir, run_id, _evidence = _ready_device(tmp_path)
    first = capture_device_analysis_snapshot(db_path=db_path, config_dir=config_dir)
    with connect_database(db_path) as db:
        db.execute(
            """UPDATE pipeline_admission_intents
               SET last_error = 'retained status note', updated_at = updated_at
               WHERE source_id = ?""",
            (run_id,),
        )
    changed = capture_device_analysis_snapshot(db_path=db_path, config_dir=config_dir)
    assert changed.key != first.key

    tombstone_device_collection(db_path, run_id)
    deleted = capture_device_analysis_snapshot(db_path=db_path, config_dir=config_dir)
    assert deleted.context["selected_run_ids"] == []
    assert deleted.key != changed.key


def test_linked_or_changed_canonical_device_evidence_fails_closed(tmp_path):
    db_path, config_dir, run_id, evidence = _ready_device(tmp_path)
    with connect_database(db_path, read_only=True) as db:
        canonical_path = Path(db.execute(
            """SELECT registry.canonical_path
               FROM device_collection_authority authority
               JOIN artifact_registry registry
                 ON registry.sha256 = authority.artifact_sha256
               WHERE authority.run_id = ?""",
            (run_id,),
        ).fetchone()[0])
    canonical_times = canonical_path.stat()
    changed = CONFIG.replace(b"10.90.0.1", b"10.91.0.1")
    canonical_path.write_bytes(changed)
    os.utime(
        canonical_path,
        ns=(canonical_times.st_atime_ns, canonical_times.st_mtime_ns),
    )
    with pytest.raises(DeviceAnalysisSnapshotError, match="exact authority"):
        capture_device_analysis_snapshot(db_path=db_path, config_dir=config_dir)

    canonical_path.write_bytes(CONFIG)
    target = tmp_path / "linked-evidence.txt"
    target.write_bytes(CONFIG)
    evidence.unlink()
    try:
        evidence.symlink_to(target)
    except OSError:
        pytest.skip("symbolic links are unavailable")
    with pytest.raises(DeviceAnalysisSnapshotError, match="linked path|symbolic link"):
        capture_device_analysis_snapshot(db_path=db_path, config_dir=config_dir)
