from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

import app.poc as poc
from app.database import connect_database
from app.work_coordination import acquire_work_lease, release_work_lease


DISCOVERY_XML = b'''<?xml version="1.0"?><nmaprun scanner="nmap"><host><status state="up"/><address addr="192.0.2.10" addrtype="ipv4"/></host><runstats><finished time="1"/><hosts up="1" down="0" total="1"/></runstats></nmaprun>'''
TCP_XML = b'''<?xml version="1.0"?><nmaprun scanner="nmap"><scaninfo type="syn" protocol="tcp"/><host><status state="up"/><address addr="192.0.2.10" addrtype="ipv4"/><ports><port protocol="tcp" portid="443"><state state="open"/></port></ports></host><runstats><finished time="2"/><hosts up="1" down="0" total="1"/></runstats></nmaprun>'''


class PollingProcess:
    def __init__(self, polls_before_exit: int):
        self.polls_before_exit = polls_before_exit
        self.polls = 0
        self.terminated = False

    def poll(self):
        if self.terminated:
            return 0
        self.polls += 1
        return 0 if self.polls > self.polls_before_exit else None

    def terminate(self):
        self.terminated = True

    def kill(self):
        self.terminated = True

    def wait(self, timeout=None):
        self.terminated = True
        return 0


def queued_scan(tmp_path: Path) -> tuple[Path, Path, dict]:
    db_path = tmp_path / "nct.db"
    data_dir = tmp_path / "data"
    request = poc.ScanRunRequest(
        operator="Tester",
        originating_host="test-host",
        interface="eth0",
        profile="Custom",
        scan_options=poc.ScanOptions(
            protocol="tcp", tcp_scope="common", discovery_mode="nmap",
        ),
        targets=["192.0.2.10/32"],
        capture=True,
        timeout_seconds=60,
    )
    manifest = poc.prepare_scan_run(request, db_path, interfaces={"eth0"})
    return db_path, data_dir, manifest


def test_progress_only_publication_never_rebuilds_history_memberships(tmp_path):
    db_path, _, manifest = queued_scan(tmp_path)
    manifest = poc.claim_next_queued_scan(db_path)
    assert manifest is not None
    with connect_database(db_path) as db:
        before = db.execute(
            "SELECT * FROM scan_history_memberships WHERE run_id = ?",
            (manifest["run_id"],),
        ).fetchall()
        db.execute(
            """CREATE TRIGGER reject_progress_history_delete
               BEFORE DELETE ON scan_history_memberships
               BEGIN SELECT RAISE(ABORT, 'history rewrite attempted'); END"""
        )
        db.execute(
            """CREATE TRIGGER reject_progress_history_insert
               BEFORE INSERT ON scan_history_memberships
               BEGIN SELECT RAISE(ABORT, 'history rewrite attempted'); END"""
        )

    manifest["progress"]["elapsed_seconds"] = 5
    manifest["progress"]["updated_at"] = "2026-10-12T12:00:05+00:00"
    poc.update_scan_progress_manifest(manifest, db_path)

    with connect_database(db_path, read_only=True) as db:
        after = db.execute(
            "SELECT * FROM scan_history_memberships WHERE run_id = ?",
            (manifest["run_id"],),
        ).fetchall()
        saved = json.loads(db.execute(
            "SELECT manifest_json FROM scan_runs WHERE run_id = ?",
            (manifest["run_id"],),
        ).fetchone()[0])
    assert after == before
    assert saved["progress"]["elapsed_seconds"] == 5

    with pytest.raises(sqlite3.IntegrityError, match="history rewrite attempted"):
        poc.update_scan_run_manifest(manifest, db_path)


def test_long_scan_coalesces_clock_progress_and_retries_one_failed_write(
    tmp_path, monkeypatch
):
    db_path, data_dir, manifest = queued_scan(tmp_path)
    clock = {"value": 0.0}
    monkeypatch.setattr(poc.time, "monotonic", lambda: clock["value"])

    original_publish = poc.update_scan_progress_manifest
    calls: list[int] = []
    failed_once = {"value": False}

    def measured_publish(current: dict, path: Path):
        elapsed = int(current["progress"].get("elapsed_seconds") or 0)
        calls.append(elapsed)
        if elapsed >= 5 and not failed_once["value"]:
            failed_once["value"] = True
            raise sqlite3.OperationalError("database is locked")
        return original_publish(current, path)

    monkeypatch.setattr(poc, "update_scan_progress_manifest", measured_publish)

    def fake_popen(argv, *, cwd: Path, **_kwargs):
        command = " ".join(str(item) for item in argv)
        if command.startswith("tcpdump"):
            return PollingProcess(10_000)
        if "discovery.xml" in command:
            (cwd / "discovery.xml").write_bytes(DISCOVERY_XML)
            return PollingProcess(0)
        if "tcp-scan.xml" in command:
            (cwd / "tcp-scan.xml").write_bytes(TCP_XML)
            return PollingProcess(70)
        raise AssertionError(command)

    def advance(_seconds: float):
        clock["value"] += 0.2

    poc.execute_scan_run(
        manifest["run_id"],
        poc.RunControl(),
        db_path=db_path,
        data_dir=data_dir,
        popen_factory=fake_popen,
        sleep_fn=advance,
    )

    completed = poc.get_scan_run_plan(manifest["run_id"], db_path)
    timed_calls = [value for value in calls if value >= 5]
    assert failed_once["value"] is True
    assert timed_calls[:3] == [5, 6, 11]
    assert len(calls) <= 9
    assert completed["status"] == "completed"
    assert completed["host_count"] == 1
    with connect_database(db_path, read_only=True) as db:
        history = db.execute(
            """SELECT latest_scan_at, latest_scan_name, host_count
                 FROM scan_history_memberships WHERE run_id = ?""",
            (manifest["run_id"],),
        ).fetchone()
        assert db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    assert history == (
        completed["completed_at"], completed["display_name"], 1,
    )


def test_cancellation_between_progress_publications_is_immediate(tmp_path, monkeypatch):
    db_path, data_dir, manifest = queued_scan(tmp_path)
    clock = {"value": 0.0}
    launched: list[str] = []
    monkeypatch.setattr(poc.time, "monotonic", lambda: clock["value"])
    monkeypatch.setattr(poc, "SCAN_PROGRESS_PUBLISH_INTERVAL_SECONDS", 60.0)

    def fake_popen(argv, *, cwd: Path, **_kwargs):
        command = " ".join(str(item) for item in argv)
        launched.append(command)
        if command.startswith("tcpdump"):
            return PollingProcess(10_000)
        if "discovery.xml" in command:
            return PollingProcess(10_000)
        raise AssertionError(command)

    cancellation_requested = {"value": False}

    def advance(_seconds: float):
        clock["value"] += 0.2
        if clock["value"] >= 1.0 and not cancellation_requested["value"]:
            cancellation_requested["value"] = True
            poc.request_scan_cancellation(
                manifest["run_id"], requested_by="shift-lead",
                cause="operator", db_path=db_path,
            )

    progress_publications: list[dict] = []
    original_publish = poc.update_scan_progress_manifest

    def record_publish(current: dict, path: Path):
        progress_publications.append(dict(current["progress"]))
        return original_publish(current, path)

    monkeypatch.setattr(poc, "update_scan_progress_manifest", record_publish)
    poc.execute_scan_run(
        manifest["run_id"], poc.RunControl(), db_path=db_path,
        data_dir=data_dir, popen_factory=fake_popen, sleep_fn=advance,
    )

    completed = poc.get_scan_run_plan(manifest["run_id"], db_path)
    assert completed["status"] == "cancelled"
    assert completed["progress"]["phase"] == "cancelled"
    assert cancellation_requested["value"] is True
    assert not any("tcp-scan.xml" in command for command in launched)
    assert progress_publications == [
        next(item for item in progress_publications if item["phase"] == "discovery")
    ]


def test_timeout_between_progress_publications_is_immediate(tmp_path, monkeypatch):
    db_path, data_dir, manifest = queued_scan(tmp_path)
    manifest["timeout_seconds"] = 10
    poc.update_scan_run_manifest(manifest, db_path)
    clock = {"value": 0.0}
    launched: list[str] = []
    monkeypatch.setattr(poc.time, "monotonic", lambda: clock["value"])
    monkeypatch.setattr(poc, "SCAN_PROGRESS_PUBLISH_INTERVAL_SECONDS", 60.0)

    def fake_popen(argv, *, cwd: Path, **_kwargs):
        command = " ".join(str(item) for item in argv)
        launched.append(command)
        if command.startswith("tcpdump"):
            return PollingProcess(10_000)
        if "discovery.xml" in command:
            return PollingProcess(10_000)
        raise AssertionError(command)

    def advance(_seconds: float):
        clock["value"] += 0.2

    poc.execute_scan_run(
        manifest["run_id"], poc.RunControl(), db_path=db_path,
        data_dir=data_dir, popen_factory=fake_popen, sleep_fn=advance,
    )

    completed = poc.get_scan_run_plan(manifest["run_id"], db_path)
    assert completed["status"] == "timed_out"
    assert completed["progress"]["phase"] == "timed_out"
    assert clock["value"] < 11
    assert not any("tcp-scan.xml" in command for command in launched)


def test_progress_publication_cannot_erase_durable_cancellation(tmp_path):
    db_path, _, manifest = queued_scan(tmp_path)
    stale = poc.claim_next_queued_scan(db_path)
    assert stale is not None
    poc.request_scan_cancellation(
        manifest["run_id"], requested_by="other-process",
        cause="operator", db_path=db_path,
    )

    stale["progress"]["phase"] = "tcp"
    stale["progress"]["elapsed_seconds"] = 5
    poc.update_scan_progress_manifest(stale, db_path)

    assert poc.scan_cancellation_requested(manifest["run_id"], db_path) is True
    visible = poc.get_scan_run_plan(manifest["run_id"], db_path)
    assert visible["cancellation_requested_by"] == "other-process"


def test_progress_publication_requires_execution_fence(tmp_path):
    db_path, _, manifest = queued_scan(tmp_path)
    with pytest.raises(poc.WorkLeaseLost, match="requires the current execution fence"):
        poc.update_scan_progress_manifest(manifest, db_path)


def test_progress_publication_rejects_stale_execution_fence(tmp_path):
    db_path, _, _manifest = queued_scan(tmp_path)
    claimed = poc.claim_next_queued_scan(db_path)
    assert claimed is not None
    claimed["execution_claim"]["lease_id"] = "f" * 32

    with pytest.raises(poc.WorkLeaseLost):
        poc.update_scan_progress_manifest(claimed, db_path)


def test_progress_publication_rejects_released_execution_fence(tmp_path):
    db_path, _, _manifest = queued_scan(tmp_path)
    claimed = poc.claim_next_queued_scan(db_path)
    assert claimed is not None
    release_work_lease(db_path, claimed["execution_claim"], detail="test release")

    with pytest.raises(poc.WorkLeaseLost):
        poc.update_scan_progress_manifest(claimed, db_path)


def test_progress_publication_rejects_replaced_execution_fence(tmp_path):
    db_path, _, _manifest = queued_scan(tmp_path)
    claimed = poc.claim_next_queued_scan(db_path)
    assert claimed is not None
    former = dict(claimed["execution_claim"])
    release_work_lease(db_path, former, detail="replace for test")
    acquire_work_lease(
        db_path,
        lease_key=former["lease_key"],
        work_kind="scan_run",
        work_id=claimed["run_id"],
        owner_id="replacement-worker",
        lease_seconds=30,
        expired_policy="recovery_required",
    )

    with pytest.raises(poc.WorkLeaseLost):
        poc.update_scan_progress_manifest(claimed, db_path)


def test_non_busy_progress_database_error_fails_the_scan(tmp_path, monkeypatch):
    db_path, data_dir, manifest = queued_scan(tmp_path)
    clock = {"value": 0.0}
    monkeypatch.setattr(poc.time, "monotonic", lambda: clock["value"])
    original_publish = poc.update_scan_progress_manifest

    def fail_non_busy(current: dict, path: Path):
        if int(current["progress"].get("elapsed_seconds") or 0) >= 5:
            raise sqlite3.OperationalError("disk I/O error")
        return original_publish(current, path)

    monkeypatch.setattr(poc, "update_scan_progress_manifest", fail_non_busy)

    def fake_popen(argv, *, cwd: Path, **_kwargs):
        command = " ".join(str(item) for item in argv)
        if command.startswith("tcpdump"):
            return PollingProcess(10_000)
        if "discovery.xml" in command:
            (cwd / "discovery.xml").write_bytes(DISCOVERY_XML)
            return PollingProcess(70)
        raise AssertionError(command)

    def advance(_seconds: float):
        clock["value"] += 0.2

    poc.execute_scan_run(
        manifest["run_id"], poc.RunControl(), db_path=db_path,
        data_dir=data_dir, popen_factory=fake_popen, sleep_fn=advance,
    )
    completed = poc.get_scan_run_plan(manifest["run_id"], db_path)
    assert completed["status"] == "failed"
    assert "disk I/O error" in completed["error"]


def test_progress_manifest_file_error_propagates_after_terminal_save(
    tmp_path, monkeypatch
):
    db_path, data_dir, manifest = queued_scan(tmp_path)
    clock = {"value": 0.0}
    monkeypatch.setattr(poc.time, "monotonic", lambda: clock["value"])
    original_write = poc.write_manifest_file

    def fail_progress_file(current: dict, path: Path):
        if int(current["progress"].get("elapsed_seconds") or 0) >= 5:
            raise OSError("simulated manifest disk failure")
        return original_write(current, path)

    monkeypatch.setattr(poc, "write_manifest_file", fail_progress_file)

    def fake_popen(argv, *, cwd: Path, **_kwargs):
        command = " ".join(str(item) for item in argv)
        if command.startswith("tcpdump"):
            return PollingProcess(10_000)
        if "discovery.xml" in command:
            (cwd / "discovery.xml").write_bytes(DISCOVERY_XML)
            return PollingProcess(70)
        raise AssertionError(command)

    def advance(_seconds: float):
        clock["value"] += 0.2

    with pytest.raises(OSError, match="simulated manifest disk failure"):
        poc.execute_scan_run(
            manifest["run_id"], poc.RunControl(), db_path=db_path,
            data_dir=data_dir, popen_factory=fake_popen, sleep_fn=advance,
        )
    completed = poc.get_scan_run_plan(manifest["run_id"], db_path)
    assert completed["status"] == "failed"


def test_restart_during_unpublished_progress_keeps_contact_boundary(tmp_path):
    db_path, data_dir, manifest = queued_scan(tmp_path)
    claimed = poc.claim_next_queued_scan(db_path)
    assert claimed and claimed["run_id"] == manifest["run_id"]
    assert poc.publish_scan_contact_starting(claimed, db_path=db_path) is True
    poc.write_manifest_file(claimed, data_dir)

    claimed["progress"]["phase"] = "tcp"
    claimed["progress"]["elapsed_seconds"] = 4
    recovered = poc.recover_scan_execution_fence(db_path)
    saved = poc.get_scan_run_plan(manifest["run_id"], db_path)

    assert recovered == {
        "run_id": manifest["run_id"],
        "safe_pre_contact": False,
        "state": "interrupted",
    }
    assert saved["status"] == "interrupted"
    assert saved["started_at"]
    assert saved["progress"].get("elapsed_seconds", 0) != 4
