from pathlib import Path
import subprocess
import sys
import threading
import time

from fastapi.testclient import TestClient
import pytest


def client_for(tmp_path, monkeypatch):
    import app.main as main
    import app.poc as poc
    import app.device_configs as device_configs

    db_path = tmp_path / "analyzer.db"
    monkeypatch.setattr(main, "DB_PATH", db_path)
    monkeypatch.setattr(poc, "DB_PATH", db_path)
    monkeypatch.setattr(device_configs, "DB_PATH", db_path)
    monkeypatch.setattr(main, "auth_enabled", lambda: False)
    return TestClient(main.app)


def reviewed_setup(client, *, label="Home lab"):
    scope = client.post("/api/network-scopes", json={"label": label}).json()
    response = client.post(
        "/api/collection-safety-setup/reviews",
        json={
            "scope_id": scope["scope_id"],
            "expected_scope_version": scope["version"],
            "expected_no_strike_revision": 0,
            "empty_no_strike_reviewed": True,
            "reason": "Initial setup review",
        },
    )
    assert response.status_code == 201, response.text
    return scope


def test_scope_and_safety_review_is_bound_to_exact_revisions(tmp_path, monkeypatch):
    with client_for(tmp_path, monkeypatch) as client:
        page = client.get("/settings/scope-safety")
        assert page.status_code == 200
        assert page.history
        assert page.url.path == "/settings/mission-environment"
        assert page.url.fragment == "scopeSafetyPanel"
        assert "Scope and collection safety" in page.text
        assert "10.0.0.0/8" in page.text

        scope = client.post(
            "/api/network-scopes", json={"label": "Home lab"}
        ).json()
        initial = client.get("/api/collection-safety-setup").json()
        assert initial["ready"] is False
        assert "have not been reviewed" in initial["missing_checks"][0]

        missing_confirmation = client.post(
            "/api/collection-safety-setup/reviews",
            json={
                "scope_id": scope["scope_id"],
                "expected_scope_version": 1,
                "expected_no_strike_revision": 0,
                "empty_no_strike_reviewed": False,
                "reason": "Initial setup",
            },
        )
        assert missing_confirmation.status_code == 422

        reviewed = client.post(
            "/api/collection-safety-setup/reviews",
            json={
                "scope_id": scope["scope_id"],
                "expected_scope_version": 1,
                "expected_no_strike_revision": 0,
                "empty_no_strike_reviewed": True,
                "reason": "No exclusions currently required",
            },
        )
        assert reviewed.status_code == 201
        assert reviewed.json()["ready"] is True
        assert reviewed.json()["review"]["reviewed_by"] == "local-operator"

        changed = client.post(
            "/api/safety/no-strike",
            json={"entries": ["10.0.0.0/8"], "changed_by": "ignored-client-value"},
        )
        assert changed.status_code == 201
        stale = client.get("/api/collection-safety-setup").json()
        assert stale["ready"] is False
        assert any(
            "Global No-Strike list changed" in item
            for item in stale["missing_checks"]
        )

        refreshed = client.post(
            "/api/collection-safety-setup/reviews",
            json={
                "scope_id": scope["scope_id"],
                "expected_scope_version": 1,
                "expected_no_strike_revision": changed.json()["revision"],
                "empty_no_strike_reviewed": False,
                "reason": "Reviewed protected private range",
            },
        )
        assert refreshed.status_code == 201
        assert refreshed.json()["ready"] is True
        assert refreshed.json()["review"]["revision"] == 2

        client.patch(
            f"/api/network-scopes/{scope['scope_id']}",
            json={
                "expected_version": 1,
                "label": "Home lab updated",
                "reason": "Clarify environment",
            },
        )
        stale_scope = client.get("/api/collection-safety-setup").json()
        assert stale_scope["ready"] is False
        assert any("Network Scope changed" in item for item in stale_scope["missing_checks"])


def test_nmap_scan_details_do_not_duplicate_shared_no_strike_management():
    from app.mission_environment_ui import mission_environment_page
    from app.ui import operator_page

    scan_html = operator_page().body.decode()
    setup_html = mission_environment_page().body.decode()
    assert 'id="noStrikePanel"' not in scan_html
    assert "Add to global No-Strike list" not in scan_html
    assert "beginGlobalNoStrikeRemoval" not in scan_html
    assert "globalNoStrikeAdd" not in scan_html
    assert "optional exclusions below apply only to this scan or schedule" in scan_html
    assert "Global No-Strike" in setup_html
    assert "10.0.0.0/8" in setup_html


def test_manual_scan_is_blocked_until_setup_then_inherits_reviewed_scope(
    tmp_path, monkeypatch,
):
    import app.poc as poc
    from app.poc import ScanRunRequest, prepare_scan_run

    launched = []
    monkeypatch.setenv("NCT_ACTIVE_COLLECTION_MODE", "enabled")
    monkeypatch.setattr(
        poc, "launch_scan_run", lambda request: launched.append(request) or {"status": "queued"}
    )
    payload = {
        "operator": "analyst.one",
        "originating_host": "nct-test",
        "interface": "eth0",
        "targets": ["192.0.2.0/30"],
        "manual_targets": ["192.0.2.0/30"],
        "capture": True,
    }
    with client_for(tmp_path, monkeypatch) as client:
        blocked = client.post("/api/scan-runs", json=payload)
        assert blocked.status_code == 409
        assert "Mission Environment" in blocked.json()["detail"]
        assert launched == []

        scope = reviewed_setup(client)
        accepted = client.post("/api/scan-runs", json=payload)
        assert accepted.status_code == 202, accepted.text
        assert len(launched) == 1
        status = client.get("/api/collection-safety-setup").json()
        assert status["scope"]["scope_id"] == scope["scope_id"]
        retained = prepare_scan_run(
            ScanRunRequest(**payload),
            tmp_path / "analyzer.db",
            interfaces={"eth0"},
        )
        assert retained["network_scope_context"]["scope_id"] == scope["scope_id"]
        assert retained["collection_safety_setup"] == status["review"]


def test_device_hostname_checks_every_ipv4_and_inherits_active_scope(
    tmp_path, monkeypatch,
):
    import socket
    from app.collection_safety_setup import CollectionSafetySetupIncomplete
    from app.device_configs import DeviceConfigPlan, certify_device_collection_plan

    with client_for(tmp_path, monkeypatch) as client:
        scope = reviewed_setup(client)
        plan = DeviceConfigPlan(
            operator="analyst.one",
            originating_host="nct-test",
            vendor="vyos",
            device_type="router",
            device_address="router.example",
            username="operator",
            accountability_interface="eth0",
        )
        monkeypatch.setattr(
            socket,
            "getaddrinfo",
            lambda *_args, **_kwargs: [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.20", 22)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.10", 22)),
            ],
        )
        certified, evidence = certify_device_collection_plan(plan, tmp_path / "analyzer.db")
        assert certified.device_address == "192.0.2.10"
        assert certified.preferred_scope_id == scope["scope_id"]
        assert evidence["resolved_ipv4_addresses"] == ["192.0.2.10", "192.0.2.20"]

        changed = client.post(
            "/api/safety/no-strike",
            json={"entries": ["192.0.2.20"], "changed_by": "analyst.one"},
        ).json()
        rereviewed = client.post(
            "/api/collection-safety-setup/reviews",
            json={
                "scope_id": scope["scope_id"],
                "expected_scope_version": scope["version"],
                "expected_no_strike_revision": changed["revision"],
                "empty_no_strike_reviewed": False,
                "reason": "Protected management address",
            },
        )
        assert rereviewed.status_code == 201, rereviewed.text
        with pytest.raises(CollectionSafetySetupIncomplete, match="192.0.2.20"):
            certify_device_collection_plan(plan, tmp_path / "analyzer.db")


def test_new_global_exclusion_cancels_waiting_device_contact(tmp_path):
    from app.device_contact_work import create_device_contact_run, get_device_contact_run
    from app.poc import NoStrikeUpdate, add_global_no_strike, init_poc_storage

    db_path = tmp_path / "analyzer.db"
    init_poc_storage(db_path)
    run_id = create_device_contact_run(
        db_path,
        operation_kind="configuration_pull",
        subject_key="192.0.2.10:22",
        request={"device_address": "192.0.2.10", "authentication_mode": "key"},
        created_by="analyst.one",
    )
    add_global_no_strike(
        NoStrikeUpdate(entries=["192.0.2.0/24"], changed_by="safety.officer"),
        db_path,
    )
    saved = get_device_contact_run(db_path, run_id)
    assert saved["state"] == "cancelled"
    assert saved["cancellation_requested"] is True
    assert "Global No-Strike" in saved["status_reason"]


def test_device_contact_rechecks_scope_revision_immediately_before_ssh(
    tmp_path, monkeypatch,
):
    from app.collection_safety_setup import CollectionSafetySetupIncomplete
    from app.device_configs import (
        DeviceConfigPlan, certify_device_collection_plan,
        require_device_contact_manifest_ready,
    )

    with client_for(tmp_path, monkeypatch) as client:
        scope = reviewed_setup(client)
        plan, certification = certify_device_collection_plan(
            DeviceConfigPlan(
                operator="analyst.one", originating_host="nct-test",
                vendor="vyos", device_type="router", device_address="192.0.2.10",
                username="operator", accountability_interface="eth0",
            ),
            tmp_path / "analyzer.db",
        )
        manifest = {
            "device_address": plan.device_address,
            "preferred_scope_id": plan.preferred_scope_id,
            "device_contact_certification": certification,
        }
        changed = client.patch(
            f"/api/network-scopes/{scope['scope_id']}",
            json={
                "expected_version": scope["version"], "label": "Home lab reviewed",
                "reason": "Clarify scope before the next device command",
            },
        )
        assert changed.status_code == 200, changed.text
        with pytest.raises(CollectionSafetySetupIncomplete, match="Network Scope changed"):
            require_device_contact_manifest_ready(manifest, tmp_path / "analyzer.db")


def test_device_ssh_ignores_hostile_ambient_config(tmp_path, monkeypatch):
    import app.device_configs as device_configs

    hostile_home = tmp_path / "hostile-home"
    ssh_dir = hostile_home / ".ssh"
    ssh_dir.mkdir(parents=True)
    marker = tmp_path / "ambient-config-ran"
    (ssh_dir / "config").write_text(
        "Host *\n"
        "  HostName 203.0.113.99\n"
        f"  ProxyCommand sh -c 'echo unsafe > {marker}'\n"
        f"  LocalCommand sh -c 'echo unsafe > {marker}'\n"
        "  PermitLocalCommand yes\n"
    )
    monkeypatch.setenv("HOME", str(hostile_home))
    plan = device_configs.DeviceConfigPlan(
        operator="analyst.one", originating_host="nct-test",
        vendor="vyos", device_type="router", device_address="192.0.2.10",
        username="operator", accountability_interface="eth0",
    )
    guard = device_configs._ssh_endpoint_guard_args(plan)
    resolved = subprocess.run(
        ["ssh", *guard, "-G", f"{plan.username}@{plan.device_address}"],
        capture_output=True, text=True, check=True, timeout=10,
    )
    settings = {
        line.split(None, 1)[0].casefold(): line.split(None, 1)[1]
        for line in resolved.stdout.splitlines() if " " in line
    }
    assert settings["hostname"] == "192.0.2.10"
    assert settings.get("proxycommand") in {None, "none"}
    assert settings["permitlocalcommand"] == "no"
    assert settings["clearallforwardings"] == "yes"
    assert not marker.exists()


def test_running_fenced_command_is_stopped_when_scope_review_becomes_stale(
    tmp_path, monkeypatch,
):
    import app.device_configs as device_configs

    db_path = tmp_path / "analyzer.db"
    with client_for(tmp_path, monkeypatch) as client:
        scope = reviewed_setup(client)
        plan, certification = device_configs.certify_device_collection_plan(
            device_configs.DeviceConfigPlan(
                operator="analyst.one", originating_host="nct-test",
                vendor="vyos", device_type="router", device_address="192.0.2.10",
                username="operator", accountability_interface="eth0",
            ),
            db_path,
        )
        run_id = "f" * 32
        fence = device_configs.acquire_device_contact_fence(
            run_id,
            operation_kind="configuration_pull",
            subject_key="192.0.2.10:22",
            request={"device_address": "192.0.2.10", "authentication_mode": "key"},
            created_by="analyst.one",
            contact_certification=certification,
            db_path=db_path,
        )
        marker = tmp_path / "command-finished"

        def invalidate_scope() -> None:
            time.sleep(0.25)
            response = client.patch(
                f"/api/network-scopes/{scope['scope_id']}",
                json={
                    "expected_version": scope["version"],
                    "label": "Changed while contact was active",
                    "reason": "Exercise the live contact fence",
                },
            )
            assert response.status_code == 200, response.text

        thread = threading.Thread(target=invalidate_scope)
        thread.start()
        started = time.monotonic()
        try:
            with pytest.raises(
                device_configs.DeviceContactConflict,
                match="Mission Environment changed",
            ):
                device_configs._run_fenced_process(
                    [
                        sys.executable, "-c",
                        (
                            "import pathlib,time; time.sleep(30); "
                            f"pathlib.Path({str(marker)!r}).write_text('finished')"
                        ),
                    ],
                    fence,
                    timeout=40,
                )
        finally:
            thread.join(timeout=3)
            fence.stop()
        assert time.monotonic() - started < 4
        assert not marker.exists()


def test_new_global_exclusion_cancels_active_scan_and_signals_worker(
    tmp_path, monkeypatch,
):
    import app.poc as poc
    from app.poc import NoStrikeUpdate, RunControl, ScanRunRequest

    with client_for(tmp_path, monkeypatch) as client:
        reviewed_setup(client)
        manifest = poc.prepare_scan_run(
            ScanRunRequest(
                operator="analyst.one", originating_host="nct-test", interface="eth0",
                targets=["192.0.2.10/32"], manual_targets=["192.0.2.10/32"],
                capture=True,
            ),
            tmp_path / "analyzer.db", interfaces={"eth0"},
        )
        manifest["status"] = "running"
        poc.update_scan_run_manifest(manifest, tmp_path / "analyzer.db")
        control = RunControl()
        with poc.ACTIVE_RUNS_LOCK:
            poc.ACTIVE_RUNS[manifest["run_id"]] = control
        try:
            poc.add_global_no_strike(
                NoStrikeUpdate(entries=["192.0.2.10"], changed_by="safety.officer"),
                tmp_path / "analyzer.db",
            )
        finally:
            with poc.ACTIVE_RUNS_LOCK:
                poc.ACTIVE_RUNS.pop(manifest["run_id"], None)
        saved = poc.get_scan_run_plan(manifest["run_id"], tmp_path / "analyzer.db")
        assert control.cancel_event.is_set()
        assert saved["cancellation_requested_at"]
        assert saved["cancellation_cause"] == "global_no_strike"


def test_scheduled_occurrence_halts_after_scope_revision_changes(tmp_path, monkeypatch):
    from datetime import datetime, timezone
    import app.poc as poc
    from app.collection_safety_setup import CollectionSafetySetupIncomplete

    with client_for(tmp_path, monkeypatch) as client:
        scope = reviewed_setup(client)
        schedule = poc.create_scan_schedule(
            poc.ScanScheduleCreate(
                name="Reviewed daily scan", created_by="analyst.one",
                profile_id="builtin-standard", profile_version=1,
                targets=["192.0.2.10/32"], interface="eth0", cadence="daily",
                first_run_at=datetime(2026, 1, 1, tzinfo=timezone.utc), enabled=True,
            ),
            tmp_path / "analyzer.db",
        )
        changed = client.patch(
            f"/api/network-scopes/{scope['scope_id']}",
            json={
                "expected_version": scope["version"], "label": "Changed scope",
                "reason": "Invalidate the earlier schedule review",
            },
        )
        assert changed.status_code == 200, changed.text
        with pytest.raises(CollectionSafetySetupIncomplete):
            poc.prepare_schedule_occurrence(
                schedule["schedule_id"], advance_schedule=True,
                trigger_key="cadence", actor="scheduler",
                now=datetime.fromisoformat(schedule["next_run_at"]),
                db_path=tmp_path / "analyzer.db",
            )
        assert poc.list_active_scan_run_plans(tmp_path / "analyzer.db") == []


def test_restart_preserves_reviewed_queue_but_stale_scope_blocks_contact(
    tmp_path, monkeypatch,
):
    import app.poc as poc
    from app.collection_safety_setup import CollectionSafetySetupIncomplete

    data_dir = tmp_path / "data"
    with client_for(tmp_path, monkeypatch) as client:
        scope = reviewed_setup(client)
        manifest = poc.prepare_scan_run(
            poc.ScanRunRequest(
                operator="analyst.one", originating_host="nct-test", interface="eth0",
                targets=["192.0.2.10/32"], manual_targets=["192.0.2.10/32"],
                capture=True,
            ),
            tmp_path / "analyzer.db", interfaces={"eth0"},
        )
        monkeypatch.setattr(poc, "dispatch_next_queued_run", lambda **_kwargs: None)
        recovered = poc.recover_scheduler_state(tmp_path / "analyzer.db", data_dir)
        assert manifest["run_id"] in recovered["preserved_queue_run_ids"]
        retained = poc.get_scan_run_plan(manifest["run_id"], tmp_path / "analyzer.db")
        assert retained["network_scope_context"]["scope_id"] == scope["scope_id"]
        assert retained["collection_safety_setup"]["scope_id"] == scope["scope_id"]
        client.patch(
            f"/api/network-scopes/{scope['scope_id']}",
            json={
                "expected_version": scope["version"], "label": "Changed after restart",
                "reason": "Verify stale setup cannot contact the network",
            },
        )
        launched = []
        with pytest.raises(CollectionSafetySetupIncomplete, match="Network Scope changed"):
            poc.execute_scan_run(
                manifest["run_id"], poc.RunControl(),
                db_path=tmp_path / "analyzer.db", data_dir=data_dir,
                popen_factory=lambda *args, **kwargs: launched.append((args, kwargs)),
                sleep_fn=lambda _seconds: None,
            )
        assert launched == []
