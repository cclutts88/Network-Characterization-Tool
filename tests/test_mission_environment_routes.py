import pytest
from fastapi.testclient import TestClient


def local_client(tmp_path, monkeypatch):
    import app.main as main
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "analyzer.db")
    monkeypatch.setattr(main, "auth_enabled", lambda: False)
    return TestClient(main.app)


def test_local_operator_can_review_and_update_mission_environment(tmp_path, monkeypatch):
    with local_client(tmp_path, monkeypatch) as client:
        page = client.get("/settings/mission-environment")
        assert page.status_code == 200
        assert "Exact-scope collection gate active" in page.text
        assert "Every new Nmap or live device collection retains the reviewed active scope" in page.text
        assert "Historical evidence can remain Unknown or unscoped" in page.text
        scope = client.post("/api/network-scopes", json={"label": "Range"}).json()
        initial = client.get("/api/mission-environment?limit=25").json()
        assert initial["can_edit"] is True
        assert initial["declaration_only"] is False
        assert initial["collection_gate"] == "exact_saved_network_review"
        assert initial["scopes"][0]["nmap_authorization"] == "unknown"

        tool = client.patch("/api/mission-environment/tools/nmap", json={
            "expected_version": 0, "availability": "available",
            "version_text": "7.95", "access_method": "Local analyzer container",
            "notes": "Installation does not imply permission", "reason": "Inventory tool",
        })
        assert tool.status_code == 200
        context = client.patch(
            f"/api/mission-environment/scopes/{scope['scope_id']}", json={
                "expected_version": 0, "nmap_coverage": "available",
                "arkime_coverage": "unavailable", "kibana_coverage": "unknown",
                "config_coverage": "partial", "nmap_authorization": "prohibited",
                "device_evidence": "command_output_only",
                "blind_spots": ["no_passive_coverage"], "notes": "Reviewed",
                "reason": "Record range rules",
            },
        )
        assert context.status_code == 200
        assert "active_scan_prohibited" in context.json()["blind_spots"]
        history = client.get(
            f"/api/mission-environment/scope/{scope['scope_id']}/history?limit=10"
        )
        assert history.status_code == 200
        assert history.json()["total"] == 1

        roles = client.post("/api/mission-environment/special-roles", json={
            "scope_id": scope["scope_id"],
            "addresses": ["10.50.15.10", "10.50.15.11"],
            "role_key": "dns_server", "custom_role": "",
            "device_label": "Primary and backup DNS",
            "declared_ports": ["53/tcp", "53/udp"],
            "declared_services": ["domain"],
            "reason": "Mission partner identified both DNS servers",
        })
        assert roles.status_code == 200
        assert roles.json()["created"] == 2
        refreshed = client.get("/api/mission-environment?limit=25").json()
        assert [item["address"] for item in refreshed["special_device_roles"]] == [
            "10.50.15.10", "10.50.15.11"
        ]
        assert refreshed["special_device_roles"][0]["declared_ports"] == [
            "53/tcp", "53/udp"
        ]
        first = refreshed["special_device_roles"][0]
        edited = client.patch(
            f"/api/mission-environment/special-roles/{first['role_id']}", json={
                "expected_version": first["version"], "scope_id": scope["scope_id"],
                "address": first["address"], "role_key": "dns_server",
                "custom_role": "", "device_label": "Primary DNS",
                "declared_ports": ["53/udp"], "declared_services": ["domain"],
                "reason": "Clarify primary member",
            },
        )
        assert edited.status_code == 200
        retired = client.request(
            "DELETE", f"/api/mission-environment/special-roles/{first['role_id']}",
            json={"expected_version": 2, "reason": "Remove retired server"},
        )
        assert retired.status_code == 200
        assert retired.json()["active"] is False


def test_page_keeps_headers_before_rows_and_has_contextual_guidance(tmp_path, monkeypatch):
    from app.shell_ui import SHELL_SCRIPT

    with local_client(tmp_path, monkeypatch) as client:
        html = client.get("/settings/mission-environment").text
    assert html.index("<thead><tr>") < html.index('id="scopeRows"')
    assert "Network Scope</th><th>Nmap evidence</th><th>Nmap authorization" in html
    assert "body.nct-guide-open .tool-grid" in html
    assert "button.dataset.missionTool" in html
    assert "button.dataset.missionScope" in html
    assert 'id="saveTool"' in html
    assert 'id="saveScope"' in html
    assert 'id="specialDeviceRolesPanel"' in html
    assert 'id="roleAddresses"' in html
    assert "Mission Partner Identified" in html
    assert "Possible matches shown by evidence" in html
    assert "Observed ports and services" in html
    assert 'href="/settings/mission-environment">Mission Environment</a>' in SHELL_SCRIPT
    assert "location.pathname==='/settings/mission-environment'" in SHELL_SCRIPT
    assert "Review Network Scope coverage" in SHELL_SCRIPT
    assert "No-Strike controls remain separately authoritative" in SHELL_SCRIPT


@pytest.mark.parametrize(
    "role,page_status,can_edit,write_status",
    [(None, 303, None, 401), ("viewer", 200, False, 403),
     ("analyst", 200, False, 403), ("admin", 200, True, 200)],
)
def test_roles_can_read_but_only_admin_can_change(
    tmp_path, monkeypatch, role, page_status, can_edit, write_status,
):
    import app.main as main

    monkeypatch.setattr(main, "DB_PATH", tmp_path / "analyzer.db")
    monkeypatch.setattr(main, "auth_enabled", lambda: True)
    monkeypatch.setattr(
        main, "session_identity",
        lambda *_args: ({"username": "test", "display_name": "Test", "role": role}
                        if role else None),
    )
    with TestClient(main.app, follow_redirects=False) as client:
        assert client.get("/settings/mission-environment").status_code == page_status
        status = client.get("/api/mission-environment")
        if role is None:
            assert status.status_code == 401
        else:
            assert status.status_code == 200
            assert status.json()["can_edit"] is can_edit
        changed = client.patch("/api/mission-environment/tools/nmap", json={
            "expected_version": 0, "availability": "available",
            "version_text": "7.95", "access_method": "Local binary", "notes": "",
            "reason": "Test role enforcement",
        })
        assert changed.status_code == write_status


def test_mission_environment_change_does_not_change_no_strike_or_create_scan(tmp_path, monkeypatch):
    with local_client(tmp_path, monkeypatch) as client:
        before = client.get("/api/safety/no-strike").json()
        scans_before = client.get("/api/scan-runs").json()
        response = client.patch("/api/mission-environment/tools/nmap", json={
            "expected_version": 0, "availability": "available",
            "version_text": "7.95", "access_method": "Local binary", "notes": "",
            "reason": "Record tool",
        })
        assert response.status_code == 200
        assert client.get("/api/safety/no-strike").json() == before
        assert client.get("/api/scan-runs").json() == scans_before


def test_route_rejects_cross_origin_change(tmp_path, monkeypatch):
    with local_client(tmp_path, monkeypatch) as client:
        response = client.patch(
            "/api/mission-environment/tools/nmap",
            headers={"Origin": "https://unrelated.example"},
            json={"expected_version": 0, "availability": "available",
                  "version_text": "", "access_method": "", "notes": "",
                  "reason": "Blocked"},
        )
        assert response.status_code == 403
