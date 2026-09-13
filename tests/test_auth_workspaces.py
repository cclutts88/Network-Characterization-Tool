import sqlite3

from fastapi.testclient import TestClient

from app.auth import create_user, init_auth_storage, verify_credentials
from app.main import app
from app.workspaces import (
    WorkspaceConflict,
    delete_layout,
    list_layouts,
    save_layout,
    set_default_layout,
)


def test_passwords_are_hashed_and_credentials_are_verified(tmp_path):
    db_path = tmp_path / "analyzer.db"
    init_auth_storage(db_path)
    create_user(
        db_path,
        username="analyst.one",
        display_name="Analyst One",
        role="analyst",
        password="correct horse battery staple",
        created_by="test",
    )

    assert verify_credentials(db_path, "analyst.one", "wrong password") is None
    assert verify_credentials(
        db_path, "analyst.one", "correct horse battery staple"
    )["role"] == "analyst"
    with sqlite3.connect(db_path) as db:
        stored = db.execute(
            "SELECT password_hash FROM analyst_users WHERE username = 'analyst.one'"
        ).fetchone()[0]
    assert "correct horse" not in stored


def test_personal_layouts_enforce_owner_and_version_conflicts(tmp_path):
    db_path = tmp_path / "analyzer.db"
    first = save_layout(
        db_path, owner="alpha", name="Mission view", snapshot={"zoomLevel": 1}
    )
    assert list_layouts(db_path, "alpha")[0]["snapshot"]["zoomLevel"] == 1
    assert list_layouts(db_path, "bravo") == []

    updated = save_layout(
        db_path,
        owner="alpha",
        name="Mission view",
        snapshot={"zoomLevel": 2},
        layout_id=first["layout_id"],
        expected_version=1,
    )
    assert updated["version"] == 2
    try:
        save_layout(
            db_path,
            owner="alpha",
            name="Mission view",
            snapshot={"zoomLevel": 3},
            layout_id=first["layout_id"],
            expected_version=1,
        )
    except WorkspaceConflict:
        pass
    else:
        raise AssertionError("A stale layout write was accepted")
    try:
        delete_layout(
            db_path, owner="bravo", layout_id=first["layout_id"], expected_version=2
        )
    except KeyError:
        pass
    else:
        raise AssertionError("Another analyst deleted a personal layout")


def test_each_analyst_has_at_most_one_visible_default_layout(tmp_path):
    db_path = tmp_path / "analyzer.db"
    first = save_layout(db_path, owner="alpha", name="First", snapshot={"zoomLevel": 1})
    second = save_layout(db_path, owner="alpha", name="Second", snapshot={"zoomLevel": 2})
    shared = save_layout(db_path, owner="bravo", name="Shared", snapshot={"zoomLevel": 3})
    from app.workspaces import publish_layout

    publish_layout(db_path, layout_id=shared["layout_id"], actor="bravo", shared=True)
    set_default_layout(db_path, owner="alpha", layout_id=first["layout_id"])
    assert [item["name"] for item in list_layouts(db_path, "alpha") if item["is_default"]] == ["First"]
    set_default_layout(db_path, owner="alpha", layout_id=second["layout_id"])
    assert [item["name"] for item in list_layouts(db_path, "alpha") if item["is_default"]] == ["Second"]
    set_default_layout(db_path, owner="alpha", layout_id=shared["layout_id"])
    assert [item["name"] for item in list_layouts(db_path, "alpha") if item["is_default"]] == ["Shared"]
    set_default_layout(db_path, owner="alpha", layout_id=None)
    assert not any(item["is_default"] for item in list_layouts(db_path, "alpha"))


def test_optional_authentication_roles_personal_layouts_and_explicit_sharing(
    monkeypatch, tmp_path
):
    db_path = tmp_path / "analyzer.db"
    monkeypatch.setenv("NCT_AUTH_MODE", "local")
    monkeypatch.setenv("NCT_BOOTSTRAP_ADMIN", "nctadmin")
    monkeypatch.setenv("NCT_BOOTSTRAP_PASSWORD", "bootstrap password 123")
    monkeypatch.setattr("app.main.DB_PATH", db_path)

    with TestClient(app) as admin:
        assert admin.get("/api/auth/me").status_code == 401
        assert "Analyst sign in" in admin.get("/network-map").text
        signed_in = admin.post(
            "/api/auth/login",
            json={"username": "nctadmin", "password": "bootstrap password 123"},
        )
        assert signed_in.status_code == 200
        assert signed_in.cookies.get("nct_session")
        assert admin.get("/api/auth/me").json()["analyst"]["role"] == "admin"
        assert "Analyst accounts" in admin.get("/admin/users").text
        account_script = admin.get("/assets/nct-session.js")
        assert account_script.status_code == 200
        assert "Sign out" in account_script.text
        assert "Accounts" in account_script.text
        assert "Personal notes" in account_script.text
        assert "shared notes" in account_script.text
        assert ".nct-note-panel.personal" in account_script.text
        assert ".nct-note-panel.shared" in account_script.text
        assert admin.post(
            "/api/auth/users",
            json={
                "username": "observer",
                "display_name": "Range Observer",
                "role": "viewer",
                "password": "observer password 123",
            },
        ).status_code == 200
        assert admin.post(
            "/api/auth/users/nctadmin/state", json={"disabled": True}
        ).status_code == 409
        reset = admin.post(
            "/api/auth/users/observer/password",
            json={"password": "replacement password 456"},
        )
        assert reset.status_code == 200
        assert reset.json()["sessions_revoked"] is True
        disabled = admin.post(
            "/api/auth/users/observer/state", json={"disabled": True}
        )
        assert disabled.status_code == 200
        assert disabled.json()["disabled"] is True
        assert admin.post(
            "/api/auth/users/observer/state", json={"disabled": False}
        ).status_code == 200
        audit = admin.get("/api/auth/audit").json()
        assert {item["action"] for item in audit} >= {
            "create",
            "password_reset",
            "disable",
            "enable",
        }
        corrected_os = admin.post(
            "/api/os-overrides",
            json={
                "ip": "192.0.2.44",
                "os_name": "Windows 11",
                "analyst": "spoofed-client-name",
                "reason": "Console confirmation",
                "scanner_os": "",
            },
        )
        assert corrected_os.status_code == 200
        assert corrected_os.json()["analyst"] == "nctadmin"
        reviewed_inference = admin.post(
            "/api/os-inference-reviews",
            json={
                "ip": "192.0.2.45",
                "inference": {
                    "family": "Linux",
                    "display": "Likely Linux",
                    "confidence": "medium",
                    "evidence": ["22/tcp SSH"],
                },
                "status": "investigate",
                "analyst": "spoofed-client-name",
                "reason": "Needs console confirmation",
            },
        )
        assert reviewed_inference.status_code == 200
        assert reviewed_inference.json()["analyst"] == "nctadmin"
        saved_network = admin.post(
            "/api/saved-networks",
            json={
                "name": "Authenticated ownership test",
                "cidr": "198.51.100.252/30",
                "created_by": "spoofed-client-name",
            },
        )
        assert saved_network.status_code == 201
        assert saved_network.json()["created_by"] == "nctadmin"
        profile = admin.post(
            "/api/scan-profiles",
            json={
                "name": "Authenticated ownership profile",
                "created_by": "spoofed-client-name",
                "settings": {},
            },
        )
        assert profile.status_code == 201
        assert profile.json()["created_by"] == "nctadmin"
        scan_plan = admin.post(
            "/api/scan-runs/plans",
            json={
                "operator": "spoofed-client-name",
                "created_by": "spoofed-client-name",
                "executed_by": "spoofed-client-name",
                "name": "Authenticated ownership scan",
                "reason": "Ownership test",
                "originating_host": "test-host",
                "interface": "eth0",
                "profile": "standard",
                "targets": ["203.0.113.254"],
            },
        )
        assert scan_plan.status_code == 201
        assert scan_plan.json()["operator"] == "nctadmin"
        assert scan_plan.json()["created_by"] == "nctadmin"
        assert scan_plan.json()["executed_by"] == "nctadmin"
        device_plan = admin.post(
            "/api/device-configs/preview",
            json={
                "operator": "spoofed-client-name",
                "reason": "Authorized ownership test",
                "originating_host": "test-host",
                "vendor": "cisco",
                "device_type": "router",
                "device_address": "192.0.2.1",
                "username": "admin",
                "authentication_mode": "password_prompt",
                "accountability_interface": "eth0",
            },
        )
        assert device_plan.status_code == 200
        assert device_plan.json()["operator"] == "nctadmin"
        saved = admin.post(
            "/api/workspaces/layouts",
            json={"name": "Reviewed map", "snapshot": {"zoomLevel": 1.25}},
        ).json()
        assert saved["owner"] == "nctadmin"
        published = admin.post(
            f"/api/workspaces/layouts/{saved['layout_id']}/publish",
            json={"shared": True},
        )
        assert published.status_code == 200
        defaulted = admin.post(
            f"/api/workspaces/layouts/{saved['layout_id']}/default"
        )
        assert defaulted.status_code == 200
        assert admin.get("/api/workspaces/layouts").json()["layouts"][0]["is_default"] is True
        folder = admin.post(
            "/api/workspaces/notes",
            json={"title": "Investigation", "kind": "folder"},
        ).json()
        note = admin.post(
            "/api/workspaces/notes",
            json={
                "title": "Gateway lead",
                "kind": "note",
                "content": "Validate the outside route.",
                "parent_id": folder["note_id"],
                "context": {"source_url": "/network-map"},
            },
        ).json()
        assert note["owner"] == "nctadmin"
        assert admin.post(
            f"/api/workspaces/notes/{folder['note_id']}/share",
            json={"shared": True, "page": "map", "expected_version": 1},
        ).status_code == 200

    with TestClient(app) as viewer:
        assert viewer.post(
            "/api/auth/login",
            json={"username": "observer", "password": "replacement password 456"},
        ).status_code == 200
        listing = viewer.get("/api/workspaces/layouts").json()
        assert listing["server_persistence"] is True
        assert listing["layouts"][0]["visibility"] == "shared"
        assert viewer.post(
            f"/api/workspaces/layouts/{saved['layout_id']}/default"
        ).status_code == 200
        assert viewer.get("/api/workspaces/layouts").json()["layouts"][0]["is_default"] is True
        assert viewer.get("/api/workspaces/notes?page=hunt").json()["notes"] == []
        shared_notes = viewer.get("/api/workspaces/notes?page=map").json()["notes"]
        assert {item["title"] for item in shared_notes} == {"Investigation", "Gateway lead"}
        assert all(item["writable"] is False for item in shared_notes)
        assert viewer.post(
            "/api/workspaces/notes",
            json={"title": "Viewer edit", "kind": "note"},
        ).status_code == 403
        assert viewer.post(
            "/api/workspaces/layouts",
            json={"name": "Viewer edit", "snapshot": {}},
        ).status_code == 403
        assert viewer.get("/admin/users").status_code == 403
