from __future__ import annotations

from fastapi.testclient import TestClient
from datetime import datetime, timedelta, timezone

import app.main as main
from app.active_collection import active_collection_status
from app.device_ui import device_config_page
from app.storage_ui import storage_page
from app.ui import operator_page


SCAN_REQUEST = {
    "operator": "analyst",
    "originating_host": "nct-test",
    "interface": "eth0",
    "targets": ["192.0.2.1"],
    "capture": True,
    "timeout_seconds": 60,
}

DEVICE_REQUEST = {
    "operator": "analyst",
    "originating_host": "nct-test",
    "vendor": "vyos",
    "device_type": "router",
    "device_address": "192.0.2.1",
    "username": "operator",
    "ssh_port": 22,
    "key_path": None,
    "authentication_mode": "password_prompt",
    "accountability_interface": "eth0",
}


def test_active_collection_defaults_enabled_and_invalid_value_fails(monkeypatch) -> None:
    monkeypatch.delenv("NCT_ACTIVE_COLLECTION_MODE", raising=False)
    assert active_collection_status()["enabled"] is True
    monkeypatch.setenv("NCT_ACTIVE_COLLECTION_MODE", "unexpected")
    try:
        active_collection_status()
    except RuntimeError as exc:
        assert "must be either" in str(exc)
    else:
        raise AssertionError("invalid active-collection mode must fail closed")


def test_analysis_only_profile_rejects_direct_scan_schedule_and_device_contact(monkeypatch) -> None:
    monkeypatch.setenv("NCT_ACTIVE_COLLECTION_MODE", "disabled")
    with TestClient(main.app, base_url="https://testserver") as client:
        identity = client.get("/api/auth/me")
        assert identity.status_code == 200
        assert identity.json()["active_collection"]["enabled"] is False

        scan = client.post("/api/scan-runs", json=SCAN_REQUEST)
        schedule = client.post("/api/scan-schedules/not-a-real-schedule/run")
        enabled_schedule = client.post(
            "/api/scan-schedules",
            json={
                "name": "Must remain paused",
                "created_by": "analyst",
                "profile_id": "builtin-standard",
                "profile_version": 1,
                "targets": ["192.0.2.0/24"],
                "interface": "eth0",
                "first_run_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
                "enabled": True,
            },
        )
        enabled_state = client.post(
            "/api/scan-schedules/not-a-real-schedule/state",
            json={"enabled": True, "changed_by": "analyst"},
        )
        interactive = client.post("/api/device-configs/interactive/start", json=DEVICE_REQUEST)
        preflight = client.post("/api/device-configs/preflight", json=DEVICE_REQUEST)
        execute = client.post("/api/device-configs/execute", json=DEVICE_REQUEST)

    for response in (
        scan,
        schedule,
        enabled_schedule,
        enabled_state,
        interactive,
        preflight,
        execute,
    ):
        assert response.status_code == 503
        assert "analysis-only deployment" in response.json()["detail"]


def test_analysis_only_startup_skips_scan_and_schedule_workers_but_keeps_local_processing(monkeypatch) -> None:
    started: list[str] = []
    monkeypatch.setenv("NCT_ACTIVE_COLLECTION_MODE", "disabled")
    monkeypatch.setattr(
        main,
        "resume_scan_workers",
        lambda: (_ for _ in ()).throw(AssertionError("scan workers must stay disabled")),
    )
    monkeypatch.setattr(
        main,
        "recover_scheduler_state",
        lambda: (_ for _ in ()).throw(AssertionError("scheduler must stay disabled")),
    )
    monkeypatch.setattr(
        main,
        "_new_scheduler_thread",
        lambda *_args: (_ for _ in ()).throw(AssertionError("scheduler thread must stay disabled")),
    )
    monkeypatch.setattr(main, "resume_derived_job_worker", lambda: started.append("resume-derived"))
    monkeypatch.setattr(main, "start_derived_job_worker", lambda *_args: started.append("start-derived"))
    monkeypatch.setattr(main, "stop_derived_job_worker", lambda *_args: True)

    with TestClient(main.app) as client:
        assert client.get("/health/readiness").status_code == 200

    assert started == ["resume-derived", "start-derived"]


def test_analysis_only_mode_is_visible_on_scan_device_and_system_health_pages() -> None:
    scan_html = operator_page().body.decode()
    device_html = device_config_page().body.decode()
    health_html = storage_page().body.decode()

    assert "Active scanning is disabled by deployment policy" in scan_html
    assert "Schedules can be saved here only in a paused state" in scan_html
    assert "Active scanning is disabled in this deployment" in scan_html
    assert "activeCollectionEnabled" in scan_html
    assert "Active device contact and packet capture are disabled by deployment policy" in device_html
    assert "loadActiveCollectionMode" in device_html
    assert "Kubernetes · one replica · analysis only" not in health_html
    assert 'id="deploymentProfile"' in health_html
    assert 'id="activeCollection"' in health_html
    assert "Optional Kubernetes health adapter" in health_html
    assert "deployment profile remains active" in health_html
