from types import SimpleNamespace

from app import poc
from app.poc import ScanRunRequest
from app.scan_collaboration import (
    DraftConflict,
    append_scan_audit,
    get_scan_draft,
    save_scan_draft,
    scan_audit_history,
)


def request(name: str) -> ScanRunRequest:
    return ScanRunRequest(
        operator=name,
        created_by=name,
        executed_by=name,
        name=f"{name} scan",
        reason="Authorized collaboration test",
        originating_host="nct-test",
        interface="eth0",
        profile="standard",
        targets=["192.0.2.1"],
        capture=True,
    )


def test_personal_scan_drafts_are_isolated_and_version_checked(tmp_path):
    db_path = tmp_path / "analyzer.db"
    alpha = save_scan_draft(
        db_path, owner="alpha", snapshot={"scanName": "Alpha"}
    )
    save_scan_draft(db_path, owner="bravo", snapshot={"scanName": "Bravo"})

    assert get_scan_draft(db_path, "alpha")["snapshot"]["scanName"] == "Alpha"
    assert get_scan_draft(db_path, "bravo")["snapshot"]["scanName"] == "Bravo"
    updated = save_scan_draft(
        db_path,
        owner="alpha",
        snapshot={"scanName": "Alpha 2"},
        expected_version=alpha["version"],
    )
    assert updated["version"] == 2
    try:
        save_scan_draft(
            db_path,
            owner="alpha",
            snapshot={"scanName": "stale"},
            expected_version=1,
        )
    except DraftConflict:
        pass
    else:
        raise AssertionError("A stale personal draft write was accepted")


def test_scan_audit_retains_actor_event_and_details(tmp_path):
    db_path = tmp_path / "analyzer.db"
    append_scan_audit(
        db_path,
        run_id="a" * 32,
        event="queued",
        actor="alpha",
        details="Submitted to shared queue",
    )
    append_scan_audit(
        db_path,
        run_id="a" * 32,
        event="reassigned",
        actor="admin",
        details="Queue owner changed from alpha to bravo",
    )

    events = scan_audit_history(db_path, "a" * 32)
    assert [item["event"] for item in events] == ["reassigned", "queued"]
    assert events[0]["actor"] == "admin"
    assert "bravo" in events[0]["details"]


def test_manual_scans_join_fifo_queue_instead_of_being_rejected(monkeypatch, tmp_path):
    db_path = tmp_path / "analyzer.db"
    data_dir = tmp_path / "data"
    started = []

    class DeferredThread:
        def __init__(self, *, target, args, kwargs, **_options):
            self.target = target
            self.args = args
            self.kwargs = kwargs

        def start(self):
            started.append(self.args[0])

    monkeypatch.setattr(poc.threading, "Thread", DeferredThread)
    with poc.ACTIVE_RUNS_LOCK:
        poc.ACTIVE_RUNS.clear()

    first = poc.launch_scan_run(
        request("alpha"), db_path=db_path, data_dir=data_dir, interfaces={"eth0"}
    )
    second = poc.launch_scan_run(
        request("bravo"), db_path=db_path, data_dir=data_dir, interfaces={"eth0"}
    )

    assert started == [first["run_id"]]
    assert first["owner"] == "alpha"
    assert second["owner"] == "bravo"
    assert second["queue_position"] == 2
    with poc.ACTIVE_RUNS_LOCK:
        poc.ACTIVE_RUNS.pop(first["run_id"], None)
    first_manifest = poc.get_scan_run_plan(first["run_id"], db_path)
    first_manifest["status"] = "completed"
    poc.update_scan_run_manifest(first_manifest, db_path)
    poc.dispatch_next_queued_run(db_path=db_path, data_dir=data_dir)
    assert started == [first["run_id"], second["run_id"]]

    with poc.ACTIVE_RUNS_LOCK:
        poc.ACTIVE_RUNS.clear()
