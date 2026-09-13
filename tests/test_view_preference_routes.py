from fastapi.testclient import TestClient

from app.main import app


def test_private_view_and_preset_routes_are_account_scoped(monkeypatch, tmp_path):
    db_path = tmp_path / "analyzer.db"
    monkeypatch.setenv("NCT_AUTH_MODE", "local")
    monkeypatch.setenv("NCT_BOOTSTRAP_ADMIN", "nctadmin")
    monkeypatch.setenv("NCT_BOOTSTRAP_PASSWORD", "bootstrap password 123")
    monkeypatch.setattr("app.main.DB_PATH", db_path)

    with TestClient(app) as admin:
        assert admin.post(
            "/api/auth/login",
            json={"username": "nctadmin", "password": "bootstrap password 123"},
        ).status_code == 200
        assert admin.post(
            "/api/auth/users",
            json={
                "username": "second",
                "display_name": "Second Analyst",
                "role": "analyst",
                "password": "second analyst password",
            },
        ).status_code == 200
        saved = admin.put(
            "/api/workspaces/views/hunt",
            json={
                "snapshot": {
                    "filters": {"osFilter": "Windows"},
                    "cards": {"inventory": True},
                    "presentation": {"density": "compact", "pageSize": "25"},
                },
                "expected_version": None,
            },
        )
        assert saved.status_code == 200
        preset = admin.post(
            "/api/workspaces/views/hunt/presets",
            json={"name": "Windows", "snapshot": {"filters": {"osFilter": "Windows"}}},
        )
        assert preset.status_code == 200
        assert admin.get("/api/workspaces/views/hunt").json()["presets"][0]["name"] == "Windows"

        with TestClient(app) as second:
            assert second.post(
                "/api/auth/login",
                json={"username": "second", "password": "second analyst password"},
            ).status_code == 200
            personal = second.get("/api/workspaces/views/hunt").json()
            assert personal["preference"] is None
            assert personal["presets"] == []


def test_view_preference_route_rejects_stale_update(monkeypatch, tmp_path):
    db_path = tmp_path / "analyzer.db"
    monkeypatch.setenv("NCT_AUTH_MODE", "local")
    monkeypatch.setenv("NCT_BOOTSTRAP_ADMIN", "nctadmin")
    monkeypatch.setenv("NCT_BOOTSTRAP_PASSWORD", "bootstrap password 123")
    monkeypatch.setattr("app.main.DB_PATH", db_path)
    with TestClient(app) as client:
        client.post(
            "/api/auth/login",
            json={"username": "nctadmin", "password": "bootstrap password 123"},
        )
        assert client.put(
            "/api/workspaces/views/analyze",
            json={"snapshot": {"filters": {}}, "expected_version": None},
        ).status_code == 200
        assert client.put(
            "/api/workspaces/views/analyze",
            json={"snapshot": {"filters": {"hostSearch": "ssh"}}, "expected_version": 1},
        ).status_code == 200
        stale = client.put(
            "/api/workspaces/views/analyze",
            json={"snapshot": {"filters": {}}, "expected_version": 1},
        )
        assert stale.status_code == 409
