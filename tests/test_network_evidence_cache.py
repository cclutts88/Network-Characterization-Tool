from __future__ import annotations

import json
import os
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from app.artifacts import init_artifact_storage, register_artifact_file
from app.database import connect_database
from app.host_identities import init_host_identity_storage
from app.identity_overrides import init_os_override_storage
from app.network_evidence_cache import (
    NetworkEvidenceCache,
    NetworkEvidenceSourceChanged,
    NetworkEvidenceSnapshot,
    capture_network_evidence_snapshot,
    select_map_configuration_file,
    select_map_configuration_records,
    select_map_import_rows,
    select_map_scan_rows,
)
from app.poc import init_poc_storage
from app.saved_networks import init_saved_network_storage


def test_cache_returns_private_nested_values_and_keeps_one_entry():
    cache = NetworkEvidenceCache()
    state = {"key": "one"}
    builds = []

    def snapshot():
        return NetworkEvidenceSnapshot(state["key"], {"key": state["key"]})

    def build(context):
        builds.append(context["key"])
        return {"source": {"warnings": ["retained"]}, "hosts": [{"ip": "10.0.0.1"}]}

    first = cache.get(snapshot, build)
    first["source"]["warnings"].append("caller mutation")
    first["hosts"][0]["ip"] = "changed"
    second = cache.get(snapshot, build)

    assert second == {
        "source": {"warnings": ["retained"]},
        "hosts": [{"ip": "10.0.0.1"}],
    }
    assert builds == ["one"]
    assert cache.status()["entry_count"] == 1

    state["key"] = "two"
    cache.get(snapshot, build)
    assert builds == ["one", "two"]
    assert cache.status()["entry_count"] == 1


def test_identical_threads_share_one_build():
    cache = NetworkEvidenceCache()
    entered = threading.Event()
    release = threading.Event()
    build_count = 0

    def snapshot():
        return NetworkEvidenceSnapshot("same", {})

    def build(_context):
        nonlocal build_count
        build_count += 1
        entered.set()
        assert release.wait(5)
        return {"hosts": [{"ip": "10.0.0.1"}]}

    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = [pool.submit(cache.get, snapshot, build) for _ in range(8)]
        assert entered.wait(5)
        release.set()
        results = [future.result(timeout=5) for future in futures]

    assert build_count == 1
    assert all(result == results[0] for result in results)
    assert len({id(result) for result in results}) == len(results)


def test_changed_source_during_build_is_discarded_and_retried():
    cache = NetworkEvidenceCache()
    state = {"key": "before"}
    builds = []

    def snapshot():
        return NetworkEvidenceSnapshot(state["key"], state["key"])

    def build(context):
        builds.append(context)
        if context == "before":
            state["key"] = "after"
        return {"built_from": context}

    result = cache.get(snapshot, build)

    assert result == {"built_from": "after"}
    assert builds == ["before", "after"]
    assert cache.get(snapshot, build) == {"built_from": "after"}
    assert builds == ["before", "after"]


def test_sustained_source_churn_fails_without_publishing_stale_data():
    cache = NetworkEvidenceCache()
    revision = 0

    def snapshot():
        nonlocal revision
        revision += 1
        return NetworkEvidenceSnapshot(str(revision), revision)

    with pytest.raises(NetworkEvidenceSourceChanged):
        cache.get(snapshot, lambda context: {"revision": context})

    assert cache.status()["entry_count"] == 0
    assert cache.status()["in_flight"] == 0


def test_failed_build_releases_waiters_and_recovery_does_not_deadlock():
    cache = NetworkEvidenceCache()
    entered = threading.Event()
    release = threading.Event()

    def snapshot():
        return NetworkEvidenceSnapshot("same", {})

    def fail(_context):
        entered.set()
        assert release.wait(5)
        raise RuntimeError("build failed")

    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = [pool.submit(cache.get, snapshot, fail) for _ in range(4)]
        assert entered.wait(5)
        release.set()
        for future in futures:
            with pytest.raises(RuntimeError, match="build failed"):
                future.result(timeout=5)

    assert cache.status()["in_flight"] == 0
    assert cache.get(snapshot, lambda _context: {"recovered": True}) == {
        "recovered": True
    }


def test_uncacheable_snapshot_never_creates_or_reuses_an_entry():
    cache = NetworkEvidenceCache()
    builds = 0

    def snapshot():
        return NetworkEvidenceSnapshot(None, {}, "legacy evidence")

    def build(_context):
        nonlocal builds
        builds += 1
        return {"build": builds}

    assert cache.get(snapshot, build) == {"build": 1}
    assert cache.get(snapshot, build) == {"build": 2}
    assert cache.status()["entry_count"] == 0


def _init_descriptor_database(db_path: Path) -> None:
    init_poc_storage(db_path)
    init_artifact_storage(db_path)
    init_host_identity_storage(db_path)
    init_os_override_storage(db_path)
    init_saved_network_storage(db_path)
    with connect_database(db_path) as db:
        db.execute(
            """CREATE TABLE IF NOT EXISTS imports (
                sha256 TEXT PRIMARY KEY,
                filename TEXT NOT NULL,
                stored_path TEXT NOT NULL,
                imported_at TEXT NOT NULL,
                analysis_json TEXT NOT NULL,
                metadata_json TEXT NOT NULL DEFAULT '{}'
            )"""
        )


def _capture(db_path: Path, config_dir: Path) -> NetworkEvidenceSnapshot:
    return capture_network_evidence_snapshot(
        db_path=db_path,
        config_dir=config_dir,
        run_directory=lambda run_id: db_path.parent / "runs" / run_id,
        prepare_manifests=lambda manifests, _queued: manifests,
        select_groups=lambda _manifests: [],
    )


def test_exact_database_rows_invalidate_without_timestamp_or_length_changes(tmp_path):
    db_path = tmp_path / "analyzer.db"
    config_dir = tmp_path / "device-configs"
    _init_descriptor_database(db_path)
    previous = _capture(db_path, config_dir)
    assert previous.key is not None

    mutations = [
        (
            "INSERT INTO imports VALUES (?, ?, ?, ?, ?, ?)",
            ("a" * 64, "a.xml", "imports/a.xml", "2026-01-01", '{"hosts":[0]}', "{}"),
        ),
        (
            "INSERT INTO scan_runs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "1" * 32,
                "2026-01-01",
                "completed",
                "a",
                "r",
                "host",
                "eth0",
                "safe",
                json.dumps({
                    "run_id": "1" * 32,
                    "created_at": "2026-01-01",
                    "status": "completed",
                    "targets": ["10.0.0.0/24"],
                }, sort_keys=True),
            ),
        ),
        (
            "INSERT INTO analyst_host_identities "
            "(ip, hostname, source_filename, imported_by, imported_at, selection_source, version) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("10.0.0.1", "alpha", "manual", "a", "t", "operator_input", 1),
        ),
        (
            "INSERT INTO host_os_overrides VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("ip:10.0.0.1", "10.0.0.1", None, "Linux", "a", "r", None, "t", "t"),
        ),
        (
            "INSERT INTO host_os_inference_reviews VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("ip:10.0.0.1", "10.0.0.1", None, "s", "{}", "investigate", "a", "r", "t", "t"),
        ),
        (
            "INSERT INTO saved_networks VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("net", "Alpha", "10.0.0.0/24", "", "", "[]", "t", "a", "t", "a", 1),
        ),
    ]
    for statement, parameters in mutations:
        with connect_database(db_path) as db:
            db.execute(statement, parameters)
        current = _capture(db_path, config_dir)
        assert current.key is not None
        assert current.key != previous.key
        previous = current

    with connect_database(db_path) as db:
        db.execute(
            "UPDATE imports SET analysis_json = ? WHERE sha256 = ?",
            ('{"hosts":[1]}', "a" * 64),
        )
    current = _capture(db_path, config_dir)
    assert current.key != previous.key
    previous = current

    with connect_database(db_path) as db:
        manifest_json = db.execute(
            "SELECT manifest_json FROM scan_runs WHERE run_id = ?", ("1" * 32,)
        ).fetchone()[0]
        changed = manifest_json.replace("10.0.0.0/24", "10.0.1.0/24")
        assert len(changed) == len(manifest_json)
        db.execute(
            "UPDATE scan_runs SET manifest_json = ? WHERE run_id = ?",
            (changed, "1" * 32),
        )
    current = _capture(db_path, config_dir)
    assert current.key != previous.key
    previous = current

    with connect_database(db_path) as db:
        db.execute("DELETE FROM saved_networks WHERE saved_network_id = 'net'")
    current = _capture(db_path, config_dir)
    assert current.key != previous.key


def test_same_size_same_mtime_device_and_oui_replacement_invalidates(tmp_path, monkeypatch):
    db_path = tmp_path / "analyzer.db"
    config_dir = tmp_path / "device-configs"
    run_dir = config_dir / ("d" * 32)
    run_dir.mkdir(parents=True)
    _init_descriptor_database(db_path)
    manifest = {
        "run_id": "d" * 32,
        "operation": "manual_upload",
        "status": "uploaded",
        "created_at": "2026-01-01T00:00:00+00:00",
        "completed_at": "2026-01-01T00:00:00+00:00",
        "vendor": "generic",
        "device_type": "router",
        "device_address": "10.0.0.1",
    }
    (run_dir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    evidence = run_dir / "stdout.txt"
    evidence.write_text("interface a\n", encoding="utf-8")
    oui_primary = tmp_path / "nmap-mac-prefixes-primary"
    oui_primary.write_text("AABBCC Primary\n", encoding="utf-8")
    oui = tmp_path / "nmap-mac-prefixes-fallback"
    oui.write_text("001122 VendorA\n", encoding="utf-8")
    monkeypatch.setattr(
        "app.network_evidence_cache.oui_search_paths", lambda: (oui_primary, oui)
    )

    first = _capture(db_path, config_dir)
    assert first.key is not None
    evidence_times = evidence.stat()
    evidence.write_text("interface b\n", encoding="utf-8")
    os.utime(evidence, ns=(evidence_times.st_atime_ns, evidence_times.st_mtime_ns))
    second = _capture(db_path, config_dir)
    assert second.key is not None and second.key != first.key

    oui_times = oui.stat()
    oui.write_text("001122 VendorB\n", encoding="utf-8")
    os.utime(oui, ns=(oui_times.st_atime_ns, oui_times.st_mtime_ns))
    third = _capture(db_path, config_dir)
    assert third.key is not None and third.key != second.key


def test_selected_group_context_is_part_of_descriptor(tmp_path):
    db_path = tmp_path / "analyzer.db"
    config_dir = tmp_path / "device-configs"
    run_id = "4" * 32
    run_dir = tmp_path / "runs" / run_id
    run_dir.mkdir(parents=True)
    _init_descriptor_database(db_path)
    manifest = {
        "run_id": run_id,
        "created_at": "2026-01-01",
        "completed_at": "2026-01-01",
        "status": "completed",
        "targets": ["10.0.0.0/24"],
    }
    with connect_database(db_path) as db:
        db.execute(
            "INSERT INTO scan_runs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                run_id, "2026-01-01", "completed", "a", "r", "host", "eth0",
                "safe", json.dumps(manifest, sort_keys=True),
            ),
        )
    calls = 0

    def select_groups(manifests):
        nonlocal calls
        calls += 1
        if calls == 1:
            (run_dir / "scan.xml").write_bytes(b"<nmaprun/>")
            return []
        return [[manifests[0]]]

    def capture():
        return capture_network_evidence_snapshot(
            db_path=db_path,
            config_dir=config_dir,
            run_directory=lambda value: tmp_path / "runs" / value,
            prepare_manifests=lambda manifests, _queued: manifests,
            select_groups=select_groups,
        )

    before = capture()
    after = capture()
    assert before.key is not None and after.key is not None
    assert before.key != after.key
    assert before.context["groups"] == []
    assert len(after.context["groups"]) == 1


def test_symlinked_selected_device_evidence_bypasses_cache(tmp_path, monkeypatch):
    db_path = tmp_path / "analyzer.db"
    config_dir = tmp_path / "device-configs"
    run_dir = config_dir / ("5" * 32)
    run_dir.mkdir(parents=True)
    _init_descriptor_database(db_path)
    (run_dir / "manifest.json").write_text(
        json.dumps({
            "run_id": "5" * 32,
            "operation": "manual_upload",
            "status": "uploaded",
            "created_at": "2026-01-01",
            "completed_at": "2026-01-01",
            "vendor": "generic",
            "device_type": "router",
            "device_address": "10.0.0.1",
        }),
        encoding="utf-8",
    )
    target = tmp_path / "linked-output.txt"
    target.write_text("interface a\n", encoding="utf-8")
    try:
        (run_dir / "stdout.txt").symlink_to(target)
    except OSError:
        pytest.skip("symbolic links are unavailable on this platform")
    (run_dir / "uploaded-fallback").write_text("interface b\n", encoding="utf-8")
    monkeypatch.setattr("app.network_evidence_cache.oui_search_paths", lambda: ())

    snapshot = _capture(db_path, config_dir)
    assert snapshot.key is None
    assert "Stable regular file is unavailable" in str(snapshot.reason)


def test_database_file_replacement_changes_descriptor_identity(tmp_path):
    db_path = tmp_path / "analyzer.db"
    config_dir = tmp_path / "device-configs"
    _init_descriptor_database(db_path)
    first = _capture(db_path, config_dir)
    replacement = tmp_path / "replacement.db"
    _init_descriptor_database(replacement)
    db_path.unlink()
    replacement.rename(db_path)
    second = _capture(db_path, config_dir)

    assert first.key is not None and second.key is not None
    assert first.key != second.key


def test_nmap_bytes_registration_and_corruption_change_cacheability(tmp_path):
    db_path = tmp_path / "analyzer.db"
    config_dir = tmp_path / "device-configs"
    run_id = "2" * 32
    run_dir = tmp_path / "runs" / run_id
    run_dir.mkdir(parents=True)
    xml_path = run_dir / "scan.xml"
    xml_path.write_bytes(b"<nmaprun>A</nmaprun>")
    _init_descriptor_database(db_path)
    manifest = {
        "run_id": run_id,
        "created_at": "2026-01-01",
        "completed_at": "2026-01-01",
        "status": "completed",
        "targets": ["10.0.0.0/24"],
    }
    with connect_database(db_path) as db:
        db.execute(
            "INSERT INTO scan_runs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                run_id, "2026-01-01", "completed", "a", "r", "host", "eth0",
                "safe", json.dumps(manifest, sort_keys=True),
            ),
        )

    def capture():
        return capture_network_evidence_snapshot(
            db_path=db_path,
            config_dir=config_dir,
            run_directory=lambda value: tmp_path / "runs" / value,
            prepare_manifests=lambda manifests, _queued: manifests,
            select_groups=lambda manifests: [[manifests[0]]],
        )

    legacy = capture()
    assert legacy.key is not None
    original_times = xml_path.stat()
    xml_path.write_bytes(b"<nmaprun>B</nmaprun>")
    os.utime(xml_path, ns=(original_times.st_atime_ns, original_times.st_mtime_ns))
    changed = capture()
    assert changed.key is not None and changed.key != legacy.key

    register_artifact_file(
        db_path=db_path,
        source_path=xml_path,
        source_kind="nmap_scan",
        source_ref=run_id,
        original_filename="scan.xml",
        media_type="application/xml",
        actor="tester",
    )
    registered = capture()
    assert registered.key is not None and registered.key != changed.key

    registered_times = xml_path.stat()
    xml_path.write_bytes(b"<nmaprun>C</nmaprun>")
    os.utime(xml_path, ns=(registered_times.st_atime_ns, registered_times.st_mtime_ns))
    corrupt = capture()
    assert corrupt.key is None
    assert "does not match registry" in str(corrupt.reason)


def test_contract_bump_invalidates_descriptor(tmp_path, monkeypatch):
    db_path = tmp_path / "analyzer.db"
    config_dir = tmp_path / "device-configs"
    _init_descriptor_database(db_path)
    first = _capture(db_path, config_dir)
    monkeypatch.setattr(
        "app.network_evidence_cache.NETWORK_MODEL_CONTRACT_VERSION", 999
    )
    second = _capture(db_path, config_dir)
    assert first.key is not None and second.key is not None
    assert first.key != second.key


def test_analyze_hunt_and_reach_share_only_the_base_model(monkeypatch):
    import app.main as main

    base = {
        "hosts": [],
        "findings": [],
        "warnings": [],
        "source": {"scope_summaries": []},
    }
    builds = []
    candidate_loads = []
    main._NETWORK_EVIDENCE_CACHE.clear()
    monkeypatch.setattr(
        main,
        "_capture_network_evidence_snapshot",
        lambda: NetworkEvidenceSnapshot("stable", {"groups": [], "oui": {}}),
    )
    monkeypatch.setattr(
        main,
        "_build_latest_network_evidence",
        lambda _groups: builds.append("base") or base,
    )
    monkeypatch.setattr(main, "reset_oui_database_cache", lambda: None)
    monkeypatch.setattr(main, "list_saved_networks", lambda _path: [])
    monkeypatch.setattr(main, "_latest_device_reachability_evidence", lambda: [])
    monkeypatch.setattr(
        main,
        "load_retained_searchsploit_candidates",
        lambda _path, run_ids: candidate_loads.append(list(run_ids)) or [],
    )
    monkeypatch.setattr(
        main,
        "classify_searchsploit_exposure",
        lambda _candidates, **_kwargs: {"candidate_count": 0},
    )

    analyzed = main.analyze_current_network()
    hunted_once = main.analyze_hunting_network()
    reached = main.reachability_context()
    hunted_twice = main.analyze_hunting_network()

    assert builds == ["base"]
    assert candidate_loads == [[], []]
    assert analyzed["status"] == "analysis_network_complete"
    assert hunted_once["status"] == hunted_twice["status"] == "hunting_network_complete"
    assert reached["status"] == "reachability_context_complete"
    assert "status" not in base and "searchsploit" not in base


def test_real_empty_model_hits_then_exact_context_change_rebuilds(tmp_path, monkeypatch):
    import app.main as main
    import app.network_map as network_map

    db_path = tmp_path / "analyzer.db"
    config_dir = tmp_path / "device-configs"
    runs_dir = tmp_path / "runs"
    runs_dir.mkdir()
    _init_descriptor_database(db_path)
    monkeypatch.setattr(main, "DB_PATH", db_path)
    monkeypatch.setattr(main, "CONFIG_DIR", config_dir)
    monkeypatch.setattr(main, "run_directory", lambda run_id: runs_dir / run_id)
    monkeypatch.setattr(network_map, "DB_PATH", db_path)
    monkeypatch.setattr(network_map, "CONFIG_DIR", config_dir)
    monkeypatch.setattr(network_map, "DATA_DIR", tmp_path)
    original_build = network_map.build_topology
    builds = []

    def counted_build():
        builds.append("topology")
        return original_build()

    monkeypatch.setattr(network_map, "build_topology", counted_build)
    main._NETWORK_EVIDENCE_CACHE.clear()

    first = main._latest_network_evidence()
    second = main._latest_network_evidence()
    assert first == second and first is not second
    assert first["source_revision"] == main._capture_network_evidence_snapshot().key
    assert builds == ["topology"]
    assert main._NETWORK_EVIDENCE_CACHE.status()["hits"] == 1

    with connect_database(db_path) as db:
        db.execute(
            "INSERT INTO saved_networks VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("net", "Alpha", "10.0.0.0/24", "", "", "[]", "t", "a", "t", "a", 1),
        )
    third = main._latest_network_evidence()
    assert third["source"]["scan_count"] == 0
    assert third["source_revision"] != first["source_revision"]
    assert builds == ["topology", "topology"]


def test_map_boundary_selectors_share_deterministic_limits(tmp_path):
    db_path = tmp_path / "analyzer.db"
    config_dir = tmp_path / "device-configs"
    _init_descriptor_database(db_path)
    stamp = "2030-01-01T00:00:00+00:00"
    with connect_database(db_path) as db:
        for index in range(1, 202):
            run_id = f"{index:032x}"
            db.execute(
                "INSERT INTO scan_runs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    run_id, stamp, "completed", "a", "r", "host", "eth0", "safe",
                    json.dumps({"run_id": run_id, "created_at": stamp}),
                ),
            )
            digest = f"{index:064x}"
            db.execute(
                "INSERT INTO imports VALUES (?, ?, ?, ?, ?, ?)",
                (digest, f"{index}.xml", f"imports/{index}.xml", stamp, '{"hosts":[]}', "{}"),
            )
        scans = select_map_scan_rows(db)
        imports = select_map_import_rows(db)

    scan_run_index = scans["columns"].index("run_id")
    import_name_index = imports["columns"].index("filename")
    assert len(scans["rows"]) == len(imports["rows"]) == 200
    assert scans["rows"][0][scan_run_index] == f"{201:032x}"
    assert scans["rows"][-1][scan_run_index] == f"{2:032x}"
    assert imports["rows"][0][import_name_index] == "201.xml"
    assert imports["rows"][-1][import_name_index] == "2.xml"

    for index in range(1, 302):
        run_id = f"{index:032x}"
        run_dir = config_dir / run_id
        run_dir.mkdir(parents=True)
        (run_dir / "manifest.json").write_text(json.dumps({
            "run_id": run_id,
            "operation": "manual_upload",
            "status": "uploaded",
            "created_at": stamp,
        }))
        (run_dir / "uploaded-z.txt").write_text("z")
        (run_dir / "uploaded-a.txt").write_text("a")
        (run_dir / "uploaded-A.txt").write_text("A")
    records, error = select_map_configuration_records(config_dir)
    assert error is None and len(records) == 300
    assert records[0][1]["run_id"] == f"{301:032x}"
    assert records[-1][1]["run_id"] == f"{2:032x}"
    assert select_map_configuration_file(records[0][0].parent).name == "uploaded-A.txt"


def test_map_only_snapshot_tracks_selected_scans_not_the_excluded_201st(
    tmp_path,
):
    db_path = tmp_path / "analyzer.db"
    config_dir = tmp_path / "device-configs"
    _init_descriptor_database(db_path)
    stamp = "2030-01-01T00:00:00+00:00"
    with connect_database(db_path) as db:
        for index in range(1, 202):
            run_id = f"{index:032x}"
            db.execute(
                "INSERT INTO scan_runs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    run_id, stamp, "completed", "a", "r", "host", "eth0", "safe",
                    json.dumps({
                        "run_id": run_id,
                        "created_at": stamp,
                        "targets": [f"10.0.0.{index}"],
                    }, sort_keys=True),
                ),
            )

    def snapshot():
        return capture_network_evidence_snapshot(
            db_path=db_path,
            config_dir=config_dir,
            run_directory=lambda run_id: tmp_path / "runs" / run_id,
            prepare_manifests=lambda manifests, _queued: manifests,
            select_groups=lambda manifests: [manifests],
            map_only=True,
        )

    original = snapshot()
    assert original.key is not None

    excluded_run_id = f"{1:032x}"
    with connect_database(db_path) as db:
        manifest = json.loads(db.execute(
            "SELECT manifest_json FROM scan_runs WHERE run_id = ?",
            (excluded_run_id,),
        ).fetchone()[0])
        manifest["targets"] = ["10.9.9.1"]
        db.execute(
            "UPDATE scan_runs SET manifest_json = ? WHERE run_id = ?",
            (json.dumps(manifest, sort_keys=True), excluded_run_id),
        )
    assert snapshot().key == original.key

    selected_run_id = f"{201:032x}"
    with connect_database(db_path) as db:
        manifest = json.loads(db.execute(
            "SELECT manifest_json FROM scan_runs WHERE run_id = ?",
            (selected_run_id,),
        ).fetchone()[0])
        manifest["targets"] = ["10.9.9.201"]
        db.execute(
            "UPDATE scan_runs SET manifest_json = ? WHERE run_id = ?",
            (json.dumps(manifest, sort_keys=True), selected_run_id),
        )
    assert snapshot().key != original.key


def test_current_network_and_map_share_private_topology_with_stable_build_time(
    monkeypatch,
):
    import app.main as main
    import app.network_map as network_map

    builds = []
    network_map._MAP_TOPOLOGY_CACHE.clear()
    monkeypatch.setattr(
        network_map,
        "_capture_map_topology_snapshot",
        lambda: NetworkEvidenceSnapshot("stable", {}),
    )
    monkeypatch.setattr(
        network_map,
        "_build_topology_uncached",
        lambda: builds.append("build") or {
            "generated_at": "2030-01-01T00:00:00+00:00",
            "nodes": [{"id": "ip:10.0.0.1", "sources": []}],
            "edges": [], "summary": {}, "warnings": [],
        },
    )
    monkeypatch.setattr(main, "merge_hunting_analyses", lambda _items, source: {
        "hosts": [], "source": source,
    })
    monkeypatch.setattr(
        main, "correlate_hunting_identity",
        lambda hunting, topology, **_kwargs: {
            **hunting, "topology_generated_at": topology["generated_at"],
        },
    )

    current = main._build_latest_network_evidence([])
    direct = network_map.topology()
    direct["nodes"][0]["id"] = "caller mutation"
    again = network_map.build_topology()

    assert builds == ["build"]
    assert current["topology_generated_at"] == direct["generated_at"] == again["generated_at"]
    assert again["nodes"][0]["id"] == "ip:10.0.0.1"


def test_map_cache_retries_recovers_and_bypasses_unverifiable_inputs(monkeypatch):
    import app.network_map as network_map

    state = {"key": "before", "fail": False, "uncacheable": False}
    builds = []
    network_map._MAP_TOPOLOGY_CACHE.clear()

    def snapshot():
        return NetworkEvidenceSnapshot(
            None if state["uncacheable"] else state["key"], {}
        )

    def build():
        builds.append(state["key"])
        if state["fail"]:
            state["fail"] = False
            raise RuntimeError("injected map build failure")
        if state["key"] == "before":
            state["key"] = "after"
        return {"generated_at": state["key"], "nodes": [], "edges": []}

    monkeypatch.setattr(network_map, "_capture_map_topology_snapshot", snapshot)
    monkeypatch.setattr(network_map, "_build_topology_uncached", build)
    assert network_map.build_topology()["generated_at"] == "after"
    assert builds == ["before", "after"]

    network_map._MAP_TOPOLOGY_CACHE.clear()
    state["key"] = "recovery"
    state["fail"] = True
    with pytest.raises(RuntimeError, match="injected map build failure"):
        network_map.build_topology()
    assert network_map._MAP_TOPOLOGY_CACHE.status()["in_flight"] == 0
    assert network_map.build_topology()["generated_at"] == "recovery"

    network_map._MAP_TOPOLOGY_CACHE.clear()
    state["uncacheable"] = True
    network_map.build_topology()
    network_map.build_topology()
    assert builds[-2:] == ["recovery", "recovery"]
    assert network_map._MAP_TOPOLOGY_CACHE.status()["entry_count"] == 0


def test_identical_map_requests_share_one_build(monkeypatch):
    import app.network_map as network_map

    entered = threading.Event()
    release = threading.Event()
    builds = 0
    network_map._MAP_TOPOLOGY_CACHE.clear()
    monkeypatch.setattr(
        network_map,
        "_capture_map_topology_snapshot",
        lambda: NetworkEvidenceSnapshot("same", {}),
    )

    def delayed():
        nonlocal builds
        builds += 1
        entered.set()
        assert release.wait(5)
        return {"generated_at": "stable", "nodes": [], "edges": []}

    monkeypatch.setattr(network_map, "_build_topology_uncached", delayed)
    with ThreadPoolExecutor(max_workers=6) as pool:
        futures = [pool.submit(network_map.build_topology) for _ in range(6)]
        assert entered.wait(5)
        release.set()
        results = [future.result(timeout=10) for future in futures]

    assert builds == 1
    assert all(result == results[0] for result in results)
    assert len({id(result) for result in results}) == len(results)


def test_map_cache_invalidates_on_database_change_and_replacement(tmp_path, monkeypatch):
    import app.network_map as network_map

    db_path = tmp_path / "analyzer.db"
    config_dir = tmp_path / "device-configs"
    _init_descriptor_database(db_path)
    monkeypatch.setattr(network_map, "DB_PATH", db_path)
    monkeypatch.setattr(network_map, "CONFIG_DIR", config_dir)
    monkeypatch.setattr(network_map, "DATA_DIR", tmp_path)
    builds = 0

    def counted():
        nonlocal builds
        builds += 1
        return {"generated_at": str(builds), "nodes": [], "edges": []}

    monkeypatch.setattr(network_map, "_build_topology_uncached", counted)
    network_map._MAP_TOPOLOGY_CACHE.clear()
    assert network_map.build_topology()["generated_at"] == "1"
    assert network_map.build_topology()["generated_at"] == "1"

    with connect_database(db_path) as db:
        db.execute(
            "INSERT INTO saved_networks VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("net", "Alpha", "10.0.0.0/24", "", "", "[]", "t", "a", "t", "a", 1),
        )
    assert network_map.build_topology()["generated_at"] == "2"

    replacement = tmp_path / "replacement.db"
    with sqlite3.connect(db_path) as source, sqlite3.connect(replacement) as target:
        source.backup(target)
    os.replace(replacement, db_path)
    assert network_map.build_topology()["generated_at"] == "3"
    assert builds == 3


def test_map_oui_second_fallback_exact_change_invalidates_and_reloads(
    tmp_path, monkeypatch,
):
    import app.mac_enrichment as mac_enrichment
    import app.network_evidence_cache as evidence_cache
    import app.network_map as network_map

    db_path = tmp_path / "analyzer.db"
    config_dir = tmp_path / "device-configs"
    _init_descriptor_database(db_path)
    with connect_database(db_path) as db:
        db.execute(
            "INSERT INTO imports VALUES (?, ?, ?, ?, ?, ?)",
            (
                "a" * 64, "one.xml", "imports/one.xml", "2030-01-01",
                json.dumps({"hosts": [{"ip": "10.0.0.1", "mac": "00:11:22:33:44:55"}]}),
                "{}",
            ),
        )
    primary = tmp_path / "primary-oui"
    fallback = tmp_path / "fallback-oui"
    primary.write_text("AABBCC OtherVendor\n")
    fallback.write_text("001122 VendorOne\n")
    fallback_times = fallback.stat()
    monkeypatch.setattr(evidence_cache, "oui_search_paths", lambda: (primary, fallback))
    monkeypatch.setattr(mac_enrichment, "oui_search_paths", lambda: (primary, fallback))
    monkeypatch.setattr(network_map, "DB_PATH", db_path)
    monkeypatch.setattr(network_map, "CONFIG_DIR", config_dir)
    monkeypatch.setattr(network_map, "DATA_DIR", tmp_path)
    network_map._MAP_TOPOLOGY_CACHE.clear()

    first = network_map.build_topology()
    assert next(node for node in first["nodes"] if node.get("ip") == "10.0.0.1")["vendor"] == "VendorOne"
    fallback.write_text("001122 VendorTwo\n")
    os.utime(fallback, ns=(fallback_times.st_atime_ns, fallback_times.st_mtime_ns))
    second = network_map.build_topology()
    assert next(node for node in second["nodes"] if node.get("ip") == "10.0.0.1")["vendor"] == "VendorTwo"
    assert second["generated_at"] != first["generated_at"] or second != first
