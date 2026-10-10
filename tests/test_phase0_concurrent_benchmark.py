import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys

from scripts.benchmark_phase0_concurrent_clients import (
    CYCLES,
    WORKER_COUNT,
    self_test,
    validate_run,
)
from scripts.summarize_phase0_concurrent_benchmark import summarize
import scripts.summarize_phase0_concurrent_benchmark as concurrent_summary
from scripts.summarize_phase0_concurrent_benchmark import (
    EXPECTED_CLIENT_LIMITS,
    EXPECTED_RESOURCE_LIMITS,
    _validate_collision_bounds,
    _validate_fixed_limits,
    _validate_git_fresh_attestation,
    _validate_result_bindings,
)
from scripts.verify_phase0_concurrent_state import snapshot, verify


def test_concurrent_helpers_support_direct_container_execution(tmp_path):
    project_root = Path(__file__).resolve().parents[1]
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)
    for name in (
        "verify_phase0_concurrent_state.py",
        "summarize_phase0_concurrent_benchmark.py",
    ):
        completed = subprocess.run(
            [sys.executable, str(project_root / "scripts" / name), "--help"],
            cwd=tmp_path,
            env=environment,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        assert completed.returncode == 0, completed.stderr


def test_concurrent_client_runner_self_test_and_fault_injection():
    assert self_test()["passed"] is True
    failed = validate_run([], [{"status": 200}, {"status": 200}], 999)
    assert failed["passed"] is False
    assert any("expected 8 workers" in item for item in failed["failures"])
    assert any("collision" in item for item in failed["failures"])


def _seed_verifier_database(root: Path) -> tuple[dict, dict]:
    root.mkdir()
    (root / "retained.xml").write_bytes(b"<nmaprun />")
    db_path = root / "analyzer.db"
    users = [f"analyst-{index:02d}" for index in range(WORKER_COUNT)]
    setup = {"users": users, "records": {}, "collision": {"note_id": "collision-note", "version": 1}}
    with sqlite3.connect(db_path) as db:
        db.executescript(
            """
            CREATE TABLE analyst_users(username TEXT PRIMARY KEY);
            CREATE TABLE analyst_sessions(token_hash TEXT PRIMARY KEY, username TEXT);
            CREATE TABLE analyst_auth_audit(audit_id INTEGER PRIMARY KEY, username TEXT, action TEXT);
            CREATE TABLE analyst_investigation_notes(note_id TEXT PRIMARY KEY, owner TEXT, version INTEGER, content TEXT);
            CREATE TABLE analyst_investigation_note_audit(audit_id INTEGER PRIMARY KEY, note_id TEXT, owner TEXT, action TEXT, version INTEGER, actor TEXT);
            CREATE TABLE analyst_workspace_layouts(layout_id TEXT PRIMARY KEY, owner TEXT, version INTEGER, snapshot_json TEXT);
            CREATE TABLE analyst_workspace_layout_audit(audit_id INTEGER PRIMARY KEY, layout_id TEXT, owner TEXT, action TEXT, version INTEGER, actor TEXT);
            CREATE TABLE analyst_view_preferences(owner TEXT, page TEXT, version INTEGER, snapshot_json TEXT, PRIMARY KEY(owner,page));
            CREATE TABLE analyst_filter_presets(preset_id TEXT PRIMARY KEY, owner TEXT, version INTEGER, snapshot_json TEXT);
            """
        )
        all_users = ["phase0admin"] + users + ["collision-analyst"]
        db.executemany("INSERT INTO analyst_users VALUES (?)", [(user,) for user in all_users])
        db.executemany(
            "INSERT INTO analyst_auth_audit VALUES (?, ?, 'create')",
            [(index + 1, user) for index, user in enumerate(all_users)],
        )
        db.executemany(
            "INSERT INTO analyst_sessions VALUES (?, ?)",
            [(f"setup-{index}", user) for index, user in enumerate(all_users)],
        )
        note_audit = 1
        layout_audit = 1
        for index, user in enumerate(users):
            note_id, layout_id, preset_id = f"note-{index}", f"layout-{index}", f"preset-{index}"
            setup["records"][user] = {
                "note_id": note_id, "layout_id": layout_id, "preset_id": preset_id,
                "versions": {"note": 1, "layout": 1, "view": 1, "preset": 1},
            }
            db.execute("INSERT INTO analyst_investigation_notes VALUES (?, ?, 1, 'setup')", (note_id, user))
            db.execute(
                "INSERT INTO analyst_investigation_note_audit VALUES (?, ?, ?, 'create', 1, ?)",
                (note_audit, note_id, user, user),
            )
            note_audit += 1
            db.execute(
                "INSERT INTO analyst_workspace_layouts VALUES (?, ?, 1, ?)",
                (layout_id, user, json.dumps({"marker": "setup", "index": index})),
            )
            db.execute(
                "INSERT INTO analyst_workspace_layout_audit VALUES (?, ?, ?, 'create', 1, ?)",
                (layout_audit, layout_id, user, user),
            )
            layout_audit += 1
            db.execute(
                "INSERT INTO analyst_view_preferences VALUES (?, 'hunt', 1, ?)",
                (user, json.dumps({"marker": "setup", "index": index})),
            )
            db.execute(
                "INSERT INTO analyst_filter_presets VALUES (?, ?, 1, ?)",
                (preset_id, user, json.dumps({"marker": "setup", "index": index})),
            )
        db.execute(
            "INSERT INTO analyst_investigation_notes VALUES ('collision-note', 'collision-analyst', 1, 'setup')"
        )
        db.execute(
            "INSERT INTO analyst_investigation_note_audit VALUES (?, 'collision-note', 'collision-analyst', 'create', 1, 'collision-analyst')",
            (note_audit,),
        )
    return setup, snapshot(root)


def test_concurrent_state_verifier_accepts_only_exact_declared_changes(tmp_path):
    root = tmp_path / "data"
    setup, before = _seed_verifier_database(root)
    db_path = root / "analyzer.db"
    with sqlite3.connect(db_path) as db:
        next_note_audit = db.execute("SELECT MAX(audit_id) FROM analyst_investigation_note_audit").fetchone()[0] + 1
        next_layout_audit = db.execute("SELECT MAX(audit_id) FROM analyst_workspace_layout_audit").fetchone()[0] + 1
        for index, user in enumerate(setup["users"]):
            record = setup["records"][user]
            marker = f"{user}:{CYCLES}"
            db.execute(
                "UPDATE analyst_investigation_notes SET version=?, content=? WHERE note_id=?",
                (CYCLES + 1, marker, record["note_id"]),
            )
            db.execute(
                "UPDATE analyst_workspace_layouts SET version=?, snapshot_json=? WHERE layout_id=?",
                (CYCLES + 1, json.dumps({"marker": marker, "index": index}), record["layout_id"]),
            )
            db.execute(
                "UPDATE analyst_view_preferences SET version=?, snapshot_json=? WHERE owner=?",
                (CYCLES + 1, json.dumps({"marker": marker, "index": index}), user),
            )
            db.execute(
                "UPDATE analyst_filter_presets SET version=?, snapshot_json=? WHERE preset_id=?",
                (CYCLES + 1, json.dumps({"marker": marker, "index": index}), record["preset_id"]),
            )
            for version in range(2, CYCLES + 2):
                db.execute(
                    "INSERT INTO analyst_investigation_note_audit VALUES (?, ?, ?, 'update', ?, ?)",
                    (next_note_audit, record["note_id"], user, version, user),
                )
                next_note_audit += 1
                db.execute(
                    "INSERT INTO analyst_workspace_layout_audit VALUES (?, ?, ?, 'update', ?, ?)",
                    (next_layout_audit, record["layout_id"], user, version, user),
                )
                next_layout_audit += 1
        db.execute(
            "UPDATE analyst_investigation_notes SET version=2, content='collision-0' WHERE note_id='collision-note'"
        )
        db.execute(
            "INSERT INTO analyst_investigation_note_audit VALUES (?, 'collision-note', 'collision-analyst', 'update', 2, 'collision-analyst')",
            (next_note_audit,),
        )
        db.executemany(
            "INSERT INTO analyst_sessions VALUES (?, ?)",
            [(f"run-{index}", user) for index, user in enumerate(setup["users"] + ["collision-analyst", "collision-analyst"])],
        )
    result = verify(root, before, setup, {"summary": {"passed": True}})
    assert result["passed"] is True, result["failures"]
    with sqlite3.connect(db_path) as db:
        db.execute(
            "UPDATE analyst_sessions SET username='analyst-00' WHERE username='phase0admin'"
        )
    wrong_sessions = verify(root, before, setup, {"summary": {"passed": True}})
    assert wrong_sessions["passed"] is False
    assert any("session ownership mismatch" in item for item in wrong_sessions["failures"])
    with sqlite3.connect(db_path) as db:
        db.execute(
            "UPDATE analyst_sessions SET username='phase0admin' WHERE token_hash='setup-0'"
        )
        db.execute("UPDATE analyst_users SET username='unexpected' WHERE username='phase0admin'")
    failed = verify(root, before, setup, {"summary": {"passed": True}})
    assert failed["passed"] is False
    assert any("changed tables" in item for item in failed["failures"])


def _summary_result(repeat: int, token: str) -> dict:
    return {
        "passed": True,
        "repeat": repeat,
        "identity": {
            "revision": "a" * 40,
            "target_root": "/source",
            "image_id": "sha256:image",
            "corpus_manifest_sha256": "b" * 64,
            "source_digest_sha256": "c" * 64,
            "runner_sha256": "d" * 64,
            "verifier_sha256": "e" * 64,
            "controller_sha256": "f" * 64,
            "preparation_sha256": "1" * 64,
            "process_capture_sha256": "2" * 64,
            "resource_capture_sha256": "3" * 64,
            "app_container_id": f"app-{token}",
            "client_container_id": f"client-{token}",
            "network_id": f"network-{token}",
            "controller_token": token,
            "data_root_host_path": f"/tmp/data-{token}",
            "single_application_process": {
                "uvicorn_application_process_count": 1,
                "processes": [{"pid": 1, "command": "uvicorn app.main:app"}],
            },
        },
        "resources": {
            "limits": {
                "app_cpu_seconds": 240,
                "client_cpu_seconds": 240,
                "app_peak_memory_bytes": 2147483648,
                "client_peak_memory_bytes": 2147483648,
            },
            "application": {"cpu_seconds": 2, "container_lifetime_peak_memory_bytes": 1000},
            "clients": {"cpu_seconds": 3, "container_lifetime_peak_memory_bytes": 2000},
        },
        "client_summary": {
            "passed": True,
            "wall_seconds": 10,
            "throughput_requests_per_second": 20,
            "read_latency": {"p95_seconds": 1},
            "write_latency": {"p95_seconds": 0.5},
            "limits": {"total_wall_seconds": 240, "read_p95_seconds": 30, "write_p95_seconds": 10},
        },
        "state_verification": {"passed": True},
    }


def test_concurrent_summary_requires_three_unique_clean_repeats(tmp_path, monkeypatch):
    monkeypatch.setattr(concurrent_summary, "_validate_raw", lambda *args: None)
    for repeat in range(1, 4):
        directory = tmp_path / f"repeat-{repeat}"
        directory.mkdir()
        result_path = directory / "result.json"
        result_path.write_text(json.dumps(_summary_result(repeat, f"token-{repeat}")), encoding="utf-8")
        digest = __import__("hashlib").sha256(result_path.read_bytes()).hexdigest()
        (directory / "cleanup.json").write_text(
            json.dumps(
                {
                    "run_succeeded": True,
                    "app_container_removed": True,
                    "client_container_removed": True,
                    "internal_network_removed": True,
                    "data_root_removed": True,
                    "controller_token": f"token-{repeat}",
                    "result_sha256": digest,
                }
            ),
            encoding="utf-8",
        )
    assert summarize(tmp_path)["passed"] is True
    duplicate = json.loads((tmp_path / "repeat-2" / "result.json").read_text())
    duplicate["identity"]["app_container_id"] = "app-token-1"
    (tmp_path / "repeat-2" / "result.json").write_text(json.dumps(duplicate), encoding="utf-8")
    assert summarize(tmp_path)["passed"] is False


def test_strict_summary_helpers_reject_raw_divergence_changed_limits_and_false_identity():
    verification = {
        "passed": True,
        "actual_changed_tables": ["one"],
        "after": {
            "evidence_sha256": "a" * 64,
            "evidence_file_count": 4,
            "database_integrity": ["ok"],
        },
    }
    run = {"summary": {"passed": True, "limits": EXPECTED_CLIENT_LIMITS}}
    result = {
        "client_summary": run["summary"],
        "state_verification": {
            "passed": True,
            "actual_changed_tables": ["one"],
            "evidence_sha256": "a" * 64,
            "evidence_file_count": 4,
            "database_integrity": ["ok"],
        },
        "resources": {"limits": EXPECTED_RESOURCE_LIMITS},
    }
    failures = []
    _validate_result_bindings(result, run, verification, failures, "fixture")
    _validate_fixed_limits(result, run, failures, "fixture")
    assert failures == []
    changed_result = json.loads(json.dumps(result))
    changed_result["client_summary"]["passed"] = False
    changed_result["resources"]["limits"]["app_cpu_seconds"] = 999
    failures = []
    _validate_result_bindings(changed_result, run, verification, failures, "fixture")
    _validate_fixed_limits(changed_result, run, failures, "fixture")
    assert any("diverges" in item for item in failures)
    assert any("resource limits" in item for item in failures)

    identity = {"revision": "a" * 40, "target_root": "/source", "data_root_host_path": "/fresh"}
    attestation = {
        "verification_method": "controller:git-status-and-fresh-root-preflight",
        "revision": "a" * 40,
        "target_root": "/source",
        "status_porcelain": "",
        "clean": True,
        "data_root_host_path": "/fresh",
        "data_root_existed_before": False,
        "data_root_empty_after_creation": True,
    }
    failures = []
    _validate_git_fresh_attestation(identity, attestation, failures, "fixture")
    assert failures == []
    attestation["clean"] = False
    attestation["data_root_existed_before"] = True
    _validate_git_fresh_attestation(identity, attestation, failures, "fixture")
    assert any("attestation" in item for item in failures)

    failures = []
    _validate_collision_bounds(
        [{"bytes": 2_097_153, "latency_seconds": 0.1}], failures, "fixture"
    )
    assert any("collision" in item for item in failures)
