from __future__ import annotations

from pathlib import Path
from datetime import datetime, timezone
import threading
import time

import pytest

pytestmark = pytest.mark.usefixtures("bypass_collection_safety_gate")

import app.poc as poc
from app.scheduled_work import claim_next_chunk, prepare_occurrence


TCP_XML = b'''<?xml version="1.0"?><nmaprun scanner="nmap"><scaninfo type="syn" protocol="tcp"/><host><status state="up"/><address addr="192.0.2.10" addrtype="ipv4"/><ports><port protocol="tcp" portid="443"><state state="open"/></port></ports></host><runstats><finished time="2"/><hosts up="1" down="0" total="1"/></runstats></nmaprun>'''
UDP_XML = b'''<?xml version="1.0"?><nmaprun scanner="nmap"><scaninfo type="udp" protocol="udp"/><host><status state="up"/><address addr="192.0.2.10" addrtype="ipv4"/><ports><port protocol="udp" portid="53"><state state="open"/></port></ports></host><runstats><finished time="3"/><hosts up="1" down="0" total="1"/></runstats></nmaprun>'''


class ImmediateProcess:
    def __init__(self, code: int | None, after_start=None):
        self.code = code
        self.terminated = False
        self.after_start = after_start

    def poll(self):
        if self.after_start is not None:
            callback, self.after_start = self.after_start, None
            callback()
        return 0 if self.terminated else self.code

    def terminate(self):
        self.terminated = True

    def kill(self):
        self.terminated = True

    def wait(self, timeout=None):
        self.terminated = True
        return 0


def fallback_scan(tmp_path: Path, *, protocol: str = "tcp") -> tuple[Path, Path, dict]:
    db_path = tmp_path / "nct.db"
    data_dir = tmp_path / "data"
    manifest = poc.prepare_scan_run(
        poc.ScanRunRequest(
            operator="Tester",
            name="Delayed fallback reliability",
            reason="Exercise the durable fallback handoff",
            originating_host="test-host",
            interface="eth0",
            profile="Custom",
            scan_options=poc.ScanOptions(
                protocol=protocol,
                tcp_scope="common",
                udp_scope="common",
                discovery_mode="fping",
            ),
            targets=["192.0.2.10/32"],
            capture=True,
            timeout_seconds=60,
        ),
        db_path,
        interfaces={"eth0"},
    )
    return db_path, data_dir, manifest


def scheduled_fallback_scan(tmp_path: Path) -> tuple[Path, Path, dict]:
    db_path = tmp_path / "nct.db"
    data_dir = tmp_path / "data"
    profile = poc.create_scan_profile(
        poc.ScanProfileCreate(
            name="Scheduled delayed fallback",
            created_by="scheduler.owner",
            settings=poc.ScanOptions(
                protocol="tcp", tcp_scope="common", discovery_mode="fping"
            ),
            request_token="scheduled-fallback-profile-0001",
        ),
        db_path,
    )
    schedule = poc.create_scan_schedule(
        poc.ScanScheduleCreate(
            name="Scheduled delayed fallback",
            created_by="scheduler.owner",
            profile_id=profile["profile_id"],
            profile_version=profile["version"],
            targets=["192.0.2.10/32"],
            interface="eth0",
            first_run_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            fallback_policy="require_approval",
            enabled=True,
        ),
        db_path,
    )
    occurrence = prepare_occurrence(
        db_path,
        schedule=schedule,
        due_at="2026-01-01T00:00:00+00:00",
        trigger_kind="scheduled",
        trigger_key="cadence",
        actor="scheduler",
        frozen_contract={
            "resolved_targets": ["192.0.2.10/32"],
            "network_scope_context": None,
            "profile": {
                "profile_id": profile["profile_id"],
                "profile_version": profile["version"],
            },
            "schedule_no_strike": [],
            "global_no_strike": {"revision": 0, "entries": []},
            "contact_policy": {"interface": "eth0"},
            "authorization": {"executed_by": "scheduler"},
        },
        chunks=[["192.0.2.10/32"]],
        next_due_at=None,
    )
    claimed = claim_next_chunk(
        db_path,
        occurrence.occurrence_id,
        owner_id="scheduled-fallback-test",
        lease_seconds=30,
    )
    assert claimed is not None
    chunk, lease = claimed
    request = poc._scheduled_request(
        schedule,
        chunk["targets"],
        batch_id=occurrence.occurrence_id,
        chunk_number=1,
        chunk_count=1,
        batch_hosts_total=1,
        batch_hosts_completed_before=0,
        db_path=db_path,
    )
    manifest = poc.prepare_scan_run(
        request,
        db_path,
        {"eth0"},
        reserved_run_id="d" * 32,
        scheduled_chunk_claim=(occurrence.occurrence_id, 1, lease),
    )
    return db_path, data_dir, manifest


def test_fallback_wait_renews_ownership_and_reads_durable_delayed_approval(
    tmp_path, monkeypatch
):
    db_path, data_dir, manifest = fallback_scan(tmp_path)
    clock = {"value": 0.0}
    launched: list[str] = []
    renewals: list[float] = []
    monkeypatch.setattr(poc.time, "monotonic", lambda: clock["value"])
    original_renew = poc.renew_work_lease

    def track_renew(*args, **kwargs):
        renewals.append(clock["value"])
        return original_renew(*args, **kwargs)

    monkeypatch.setattr(poc, "renew_work_lease", track_renew)

    def fake_popen(argv, *, cwd: Path, **_kwargs):
        command = " ".join(str(item) for item in argv)
        launched.append(command)
        if command.startswith("tcpdump"):
            return ImmediateProcess(None)
        if command.startswith("fping"):
            return ImmediateProcess(1)
        if "tcp-scan.xml" in command:
            (cwd / "tcp-scan.xml").write_bytes(TCP_XML)
            return ImmediateProcess(0)
        raise AssertionError(command)

    decision_saved = {"value": False}

    def wait_for_operator(_seconds: float):
        current = poc.get_scan_run_plan(manifest["run_id"], db_path)
        if current["status"] != "awaiting_fallback_approval":
            return
        clock["value"] += 1.0
        if clock["value"] >= 35 and not decision_saved["value"]:
            decision_saved["value"] = True
            saved = poc.record_scan_fallback_decision(
                manifest["run_id"],
                decision="approve",
                decided_by="tester",
                authorization_note="Approved after a deliberate review delay",
                db_path=db_path,
            )
            assert saved["status"] == "awaiting_fallback_approval"

    poc.execute_scan_run(
        manifest["run_id"],
        poc.RunControl(),
        db_path=db_path,
        data_dir=data_dir,
        popen_factory=fake_popen,
        sleep_fn=wait_for_operator,
    )

    completed = poc.get_scan_run_plan(manifest["run_id"], db_path)
    assert decision_saved["value"] is True
    assert len([value for value in renewals if value >= 10]) >= 3
    assert completed["status"] == "completed"
    assert completed["fallback_decision"] == "approve"
    assert completed["fallback_decided_by"] == "tester"
    assert any("tcp-scan.xml" in command for command in launched)


def test_scheduled_fallback_wait_renews_scan_and_schedule_ownership(
    tmp_path, monkeypatch
):
    db_path, data_dir, manifest = scheduled_fallback_scan(tmp_path)
    clock = {"value": 0.0}
    renewed_keys: list[str] = []
    monkeypatch.setattr(poc.time, "monotonic", lambda: clock["value"])
    original_renew = poc.renew_work_lease

    def track_renew(*args, **kwargs):
        claim = args[1]
        renewed_keys.append(str(claim["lease_key"]))
        return original_renew(*args, **kwargs)

    monkeypatch.setattr(poc, "renew_work_lease", track_renew)

    def fake_popen(argv, *, cwd: Path, **_kwargs):
        command = " ".join(str(item) for item in argv)
        if command.startswith("tcpdump"):
            return ImmediateProcess(None)
        if command.startswith("fping"):
            return ImmediateProcess(1)
        if "tcp-scan.xml" in command:
            (cwd / "tcp-scan.xml").write_bytes(TCP_XML)
            return ImmediateProcess(0)
        raise AssertionError(command)

    decision_saved = {"value": False}

    def wait_for_operator(_seconds: float):
        current = poc.get_scan_run_plan(manifest["run_id"], db_path)
        if current["status"] != "awaiting_fallback_approval":
            return
        clock["value"] += 1.0
        if clock["value"] >= 35 and not decision_saved["value"]:
            decision_saved["value"] = True
            poc.record_scan_fallback_decision(
                manifest["run_id"],
                decision="approve",
                decided_by="scheduler.owner",
                authorization_note="Approved after scheduled review delay",
                db_path=db_path,
            )

    poc.execute_scan_run(
        manifest["run_id"],
        poc.RunControl(),
        db_path=db_path,
        data_dir=data_dir,
        popen_factory=fake_popen,
        sleep_fn=wait_for_operator,
    )

    completed = poc.get_scan_run_plan(manifest["run_id"], db_path)
    assert completed["status"] == "completed"
    assert len(set(renewed_keys)) == 2
    for lease_key in set(renewed_keys):
        assert renewed_keys.count(lease_key) >= 3


def test_delayed_fallback_decline_finishes_without_starting_nmap(
    tmp_path, monkeypatch
):
    db_path, data_dir, manifest = fallback_scan(tmp_path)
    clock = {"value": 0.0}
    launched: list[str] = []
    monkeypatch.setattr(poc.time, "monotonic", lambda: clock["value"])

    def fake_popen(argv, *, cwd: Path, **_kwargs):
        command = " ".join(str(item) for item in argv)
        launched.append(command)
        if command.startswith("tcpdump"):
            return ImmediateProcess(None)
        if command.startswith("fping"):
            return ImmediateProcess(1)
        raise AssertionError(command)

    decided = {"value": False}

    def wait_for_operator(_seconds: float):
        current = poc.get_scan_run_plan(manifest["run_id"], db_path)
        if current["status"] != "awaiting_fallback_approval":
            return
        clock["value"] += 1.0
        if clock["value"] >= 35 and not decided["value"]:
            decided["value"] = True
            poc.record_scan_fallback_decision(
                manifest["run_id"],
                decision="decline",
                decided_by="tester",
                authorization_note="Finish without broader contact after review",
                db_path=db_path,
            )

    poc.execute_scan_run(
        manifest["run_id"],
        poc.RunControl(),
        db_path=db_path,
        data_dir=data_dir,
        popen_factory=fake_popen,
        sleep_fn=wait_for_operator,
    )

    completed = poc.get_scan_run_plan(manifest["run_id"], db_path)
    assert completed["status"] == "completed_without_nmap"
    assert completed["fallback_decision"] == "decline"
    assert not any("tcp-scan.xml" in command for command in launched)


def test_scheduled_delayed_cancellation_renews_both_owners_and_starts_no_nmap(
    tmp_path, monkeypatch
):
    db_path, data_dir, manifest = scheduled_fallback_scan(tmp_path)
    clock = {"value": 0.0}
    renewed_keys: list[str] = []
    launched: list[str] = []
    monkeypatch.setattr(poc.time, "monotonic", lambda: clock["value"])
    original_renew = poc.renew_work_lease

    def track_renew(*args, **kwargs):
        renewed_keys.append(str(args[1]["lease_key"]))
        return original_renew(*args, **kwargs)

    monkeypatch.setattr(poc, "renew_work_lease", track_renew)

    def fake_popen(argv, *, cwd: Path, **_kwargs):
        command = " ".join(str(item) for item in argv)
        launched.append(command)
        if command.startswith("tcpdump"):
            return ImmediateProcess(None)
        if command.startswith("fping"):
            return ImmediateProcess(1)
        raise AssertionError(command)

    cancelled = {"value": False}

    def wait_for_operator(_seconds: float):
        current = poc.get_scan_run_plan(manifest["run_id"], db_path)
        if current["status"] != "awaiting_fallback_approval":
            return
        clock["value"] += 1.0
        if clock["value"] >= 35 and not cancelled["value"]:
            cancelled["value"] = True
            poc.request_scan_cancellation(
                manifest["run_id"],
                requested_by="scheduler.owner",
                cause="operator",
                detail="Stop the held scheduled scan",
                db_path=db_path,
            )

    poc.execute_scan_run(
        manifest["run_id"],
        poc.RunControl(),
        db_path=db_path,
        data_dir=data_dir,
        popen_factory=fake_popen,
        sleep_fn=wait_for_operator,
    )

    completed = poc.get_scan_run_plan(manifest["run_id"], db_path)
    assert completed["status"] == "cancelled"
    assert len(set(renewed_keys)) == 2
    for lease_key in set(renewed_keys):
        assert renewed_keys.count(lease_key) >= 3
    assert not any("tcp-scan.xml" in command for command in launched)


def test_saved_cancellation_wins_race_with_saved_fallback_approval(tmp_path):
    db_path, data_dir, manifest = fallback_scan(tmp_path)
    launched: list[str] = []
    decision_saved = {"value": False}

    def fake_popen(argv, *, cwd: Path, **_kwargs):
        command = " ".join(str(item) for item in argv)
        launched.append(command)
        if command.startswith("tcpdump"):
            return ImmediateProcess(None)
        if command.startswith("fping"):
            return ImmediateProcess(1)
        raise AssertionError(command)

    def approve_then_cancel(_seconds: float):
        if decision_saved["value"]:
            return
        current = poc.get_scan_run_plan(manifest["run_id"], db_path)
        if current["status"] != "awaiting_fallback_approval":
            return
        decision_saved["value"] = True
        poc.record_scan_fallback_decision(
            manifest["run_id"],
            decision="approve",
            decided_by="tester",
            authorization_note="Approval raced a stop request",
            db_path=db_path,
        )
        poc.request_scan_cancellation(
            manifest["run_id"],
            requested_by="tester",
            cause="operator",
            detail="Stop before the fallback starts",
            db_path=db_path,
        )

    poc.execute_scan_run(
        manifest["run_id"],
        poc.RunControl(),
        db_path=db_path,
        data_dir=data_dir,
        popen_factory=fake_popen,
        sleep_fn=approve_then_cancel,
    )

    completed = poc.get_scan_run_plan(manifest["run_id"], db_path)
    assert completed["status"] == "cancelled"
    assert completed["fallback_decision"] == "approve"
    assert not any("tcp-scan.xml" in command for command in launched)


def test_cancellation_between_protocols_preserves_tcp_without_starting_udp(tmp_path):
    db_path, data_dir, manifest = fallback_scan(tmp_path, protocol="tcp_udp")
    control = poc.RunControl()
    launched: list[str] = []

    def fake_popen(argv, *, cwd: Path, **_kwargs):
        command = " ".join(str(item) for item in argv)
        launched.append(command)
        if command.startswith("tcpdump"):
            return ImmediateProcess(None)
        if command.startswith("fping"):
            return ImmediateProcess(1)
        if "tcp-scan.xml" in command:
            (cwd / "tcp-scan.xml").write_bytes(TCP_XML)
            def cancel_after_launch():
                poc.request_scan_cancellation(
                    manifest["run_id"],
                    requested_by="tester",
                    cause="operator",
                    detail="Stop after TCP before UDP",
                    db_path=db_path,
                )
                control.cancel_event.set()
            return ImmediateProcess(0, after_start=cancel_after_launch)
        if "udp-scan.xml" in command:
            (cwd / "udp-scan.xml").write_bytes(UDP_XML)
            return ImmediateProcess(0)
        raise AssertionError(command)

    def approve(_seconds: float):
        if control.fallback_decision_event.is_set():
            return
        current = poc.get_scan_run_plan(manifest["run_id"], db_path)
        if current["status"] != "awaiting_fallback_approval":
            return
        control.fallback_decision = "approve"
        control.fallback_decided_by = "tester"
        control.fallback_authorization_note = "Run both protocols"
        control.fallback_decision_event.set()

    poc.execute_scan_run(
        manifest["run_id"],
        control,
        db_path=db_path,
        data_dir=data_dir,
        popen_factory=fake_popen,
        sleep_fn=approve,
    )

    completed = poc.get_scan_run_plan(manifest["run_id"], db_path)
    assert completed["status"] == "cancelled"
    assert completed["success"] is False
    assert completed["partial_results"] is True
    assert (data_dir / "scan-runs" / manifest["run_id"] / "tcp-scan.xml").is_file()
    assert not any("udp-scan.xml" in command for command in launched)
    assert "preserved for review" in completed["execution_note"]


def test_fallback_decision_refuses_after_cancellation_is_saved(tmp_path):
    db_path, _, manifest = fallback_scan(tmp_path)
    claimed = poc.claim_next_queued_scan(db_path)
    assert claimed is not None
    claimed["status"] = "awaiting_fallback_approval"
    claimed["fallback_approval_required"] = True
    poc.update_scan_progress_manifest(claimed, db_path)
    poc.request_scan_cancellation(
        manifest["run_id"],
        requested_by="tester",
        cause="operator",
        detail="Stop before deciding",
        db_path=db_path,
    )

    with pytest.raises(poc.FallbackDecisionConflict, match="Cancellation is already saved"):
        poc.record_scan_fallback_decision(
            manifest["run_id"],
            decision="approve",
            decided_by="tester",
            authorization_note="Must not be accepted",
            db_path=db_path,
        )


def test_saved_cancellation_prevents_the_final_process_launch(tmp_path):
    db_path, _, manifest = fallback_scan(tmp_path)
    control = poc.RunControl()
    launched: list[list[str]] = []
    poc.request_scan_cancellation(
        manifest["run_id"],
        requested_by="tester",
        cause="operator",
        detail="Stop before launch admission",
        db_path=db_path,
    )

    process = poc.spawn_scan_process_unless_cancelled(
        manifest["run_id"],
        control,
        ["nmap", "192.0.2.10"],
        db_path=db_path,
        popen_factory=lambda argv, **_kwargs: launched.append(argv),
    )

    assert process is None
    assert control.cancel_event.is_set()
    assert launched == []


def test_process_launch_admission_finishes_before_cancellation_can_commit(tmp_path):
    db_path, _, manifest = fallback_scan(tmp_path)
    control = poc.RunControl()
    launch_entered = threading.Event()
    allow_launch = threading.Event()
    launch_finished = threading.Event()
    cancellation_finished = threading.Event()
    process = ImmediateProcess(None)

    def delayed_popen(_argv, **_kwargs):
        launch_entered.set()
        assert allow_launch.wait(timeout=5)
        launch_finished.set()
        return process

    launch_thread = threading.Thread(
        target=lambda: poc.spawn_scan_process_unless_cancelled(
            manifest["run_id"],
            control,
            ["nmap", "192.0.2.10"],
            db_path=db_path,
            popen_factory=delayed_popen,
        )
    )
    launch_thread.start()
    assert launch_entered.wait(timeout=5)

    def request_cancel():
        poc.request_scan_cancellation(
            manifest["run_id"],
            requested_by="tester",
            cause="operator",
            detail="Race the launch admission gate",
            db_path=db_path,
        )
        cancellation_finished.set()

    cancel_thread = threading.Thread(target=request_cancel)
    cancel_thread.start()
    time.sleep(0.05)
    assert not cancellation_finished.is_set()
    allow_launch.set()
    launch_thread.join(timeout=5)
    cancel_thread.join(timeout=5)

    assert launch_finished.is_set()
    assert cancellation_finished.is_set()
    assert poc.scan_cancellation_requested(manifest["run_id"], db_path)


def test_terminal_publication_preserves_a_newer_saved_fallback_decision(tmp_path):
    db_path, _, manifest = fallback_scan(tmp_path)
    claimed = poc.claim_next_queued_scan(db_path)
    assert claimed is not None
    claimed["status"] = "awaiting_fallback_approval"
    poc.update_scan_progress_manifest(claimed, db_path)
    stale_terminal = dict(claimed)

    poc.record_scan_fallback_decision(
        manifest["run_id"],
        decision="approve",
        decided_by="tester",
        authorization_note="Approved immediately before cancellation closed the run",
        db_path=db_path,
    )
    stale_terminal.update(
        status="cancelled",
        completed_at="2026-11-05T12:00:00.000Z",
        success=False,
    )
    poc.publish_scan_terminal(stale_terminal, db_path=db_path)

    completed = poc.get_scan_run_plan(manifest["run_id"], db_path)
    assert completed["status"] == "cancelled"
    assert completed["fallback_decision"] == "approve"
    assert completed["fallback_decided_by"] == "tester"
    assert completed["fallback_authorization_note"].startswith("Approved immediately")
    assert completed["fallback_decided_at"]


def test_scheduled_terminal_preserves_a_newer_saved_fallback_decision(tmp_path):
    db_path, _, manifest = scheduled_fallback_scan(tmp_path)
    claimed = poc.claim_next_queued_scan(db_path)
    assert claimed is not None
    claimed["status"] = "awaiting_fallback_approval"
    poc.update_scan_progress_manifest(claimed, db_path)
    stale_terminal = dict(claimed)

    poc.record_scan_fallback_decision(
        manifest["run_id"],
        decision="decline",
        decided_by="scheduler.owner",
        authorization_note="Finish scheduled evidence without broader contact",
        db_path=db_path,
    )
    stale_terminal.update(
        status="cancelled",
        completed_at="2026-11-05T12:00:00.000Z",
        success=False,
        execution_note="Cancelled while the saved decision was closing",
    )
    poc.publish_scheduled_scan_terminal(
        stale_terminal,
        stale_terminal["work_claim"],
        db_path=db_path,
    )

    completed = poc.get_scan_run_plan(manifest["run_id"], db_path)
    assert completed["status"] == "cancelled"
    assert completed["fallback_decision"] == "decline"
    assert completed["fallback_decided_by"] == "scheduler.owner"
    assert completed["fallback_authorization_note"].startswith("Finish scheduled")


def test_worker_releases_in_memory_slot_when_stale_fence_blocks_error_publication(
    tmp_path, monkeypatch
):
    db_path, data_dir, manifest = fallback_scan(tmp_path)
    control = poc.RunControl()
    claimed = poc.claim_next_queued_scan(db_path)
    assert claimed is not None
    claimed["status"] = "running"
    poc.update_scan_progress_manifest(claimed, db_path)
    poc.ACTIVE_RUNS[manifest["run_id"]] = control
    poc.ACTIVE_RUN_THREADS[manifest["run_id"]] = object()

    monkeypatch.setattr(
        poc,
        "execute_scan_run",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            poc.WorkLeaseLost("worker was superseded")
        ),
    )
    monkeypatch.setattr(poc, "requeue_scan_after_precontact_failure", lambda *_args, **_kwargs: False)
    monkeypatch.setattr(
        poc,
        "publish_scan_terminal",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            poc.WorkLeaseLost("terminal publication fence is stale")
        ),
    )

    with pytest.raises(poc.WorkLeaseLost, match="terminal publication fence is stale"):
        poc._scan_worker_entry(
            manifest["run_id"],
            control,
            db_path=db_path,
            data_dir=data_dir,
        )

    assert manifest["run_id"] not in poc.ACTIVE_RUNS
    assert manifest["run_id"] not in poc.ACTIVE_RUN_THREADS
