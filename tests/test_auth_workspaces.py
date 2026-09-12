import sqlite3

from fastapi.testclient import TestClient

from app.auth import create_user, init_auth_storage, verify_credentials
from app.main import app
from app.workspaces import WorkspaceConflict, delete_layout, list_layouts, save_layout


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
        assert admin.post(
            "/api/auth/users",
            json={
                "username": "observer",
                "display_name": "Range Observer",
                "role": "viewer",
                "password": "observer password 123",
            },
        ).status_code == 200
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

    with TestClient(app) as viewer:
        assert viewer.post(
            "/api/auth/login",
            json={"username": "observer", "password": "observer password 123"},
        ).status_code == 200
        listing = viewer.get("/api/workspaces/layouts").json()
        assert listing["server_persistence"] is True
        assert listing["layouts"][0]["visibility"] == "shared"
        assert viewer.post(
            "/api/workspaces/layouts",
            json={"name": "Viewer edit", "snapshot": {}},
        ).status_code == 403
