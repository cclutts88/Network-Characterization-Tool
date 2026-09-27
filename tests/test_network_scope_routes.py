import pytest
from fastapi.testclient import TestClient


def client_for(tmp_path, monkeypatch):
    import app.main as main
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "analyzer.db")
    monkeypatch.setattr(main, "auth_enabled", lambda: False)
    return TestClient(main.app)


def test_local_operator_can_manage_scope_lifecycle_and_history(tmp_path, monkeypatch):
    with client_for(tmp_path, monkeypatch) as client:
        page = client.get("/settings/network-scopes")
        assert page.status_code == 200
        assert "does not assign evidence" in page.text

        created = client.post("/api/network-scopes", json={
            "label": "Range enclave", "description": "Isolated test context",
            "reason": "Approved test scope",
        })
        assert created.status_code == 201
        scope = created.json()
        assert scope["scope_id"].startswith("scope_")
        assert scope["version"] == 1
        assert client.get("/api/network-scopes").json() == [scope]

        updated = client.patch(f"/api/network-scopes/{scope['scope_id']}", json={
            "expected_version": 1, "label": "Range enclave east",
            "description": "Updated description", "reason": "Clarify location",
        })
        assert updated.status_code == 200
        assert updated.json()["version"] == 2
        conflict = client.patch(f"/api/network-scopes/{scope['scope_id']}", json={
            "expected_version": 1, "label": "Stale edit", "reason": "Old page",
        })
        assert conflict.status_code == 409

        archived = client.post(f"/api/network-scopes/{scope['scope_id']}/archive", json={
            "expected_version": 2, "reason": "Exercise complete",
        })
        assert archived.status_code == 200
        assert archived.json()["active"] is False
        assert client.get("/api/network-scopes").json() == []
        assert len(client.get("/api/network-scopes?include_archived=true").json()) == 1
        history = client.get(f"/api/network-scopes/{scope['scope_id']}/history").json()
        assert [event["event"] for event in history] == ["created", "updated", "archived"]
        assert all(event["actor"] == "local-operator" for event in history)


def test_route_reports_duplicate_and_missing_scope_without_mutation(tmp_path, monkeypatch):
    with client_for(tmp_path, monkeypatch) as client:
        first = client.post("/api/network-scopes", json={"label": "Straße"})
        assert first.status_code == 201
        assert client.post("/api/network-scopes", json={"label": "STRASSE"}).status_code == 409
        assert client.get("/api/network-scopes/scope_missing/history").status_code == 404
        assert len(client.get("/api/network-scopes").json()) == 1


@pytest.mark.parametrize("role,expected", [(None, 401), ("viewer", 403), ("analyst", 403), ("admin", 200)])
def test_scope_routes_require_administrator(tmp_path, monkeypatch, role, expected):
    import app.main as main
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "analyzer.db")
    monkeypatch.setattr(main, "auth_enabled", lambda: True)
    monkeypatch.setattr(
        main, "session_identity",
        lambda *args: {"username": "test", "display_name": "Test", "role": role} if role else None,
    )
    with TestClient(main.app, follow_redirects=False) as client:
        page_expected = 303 if role is None else expected
        assert client.get("/settings/network-scopes").status_code == page_expected
        assert client.get("/api/network-scopes").status_code == expected
        response = client.post("/api/network-scopes", json={"label": "Test scope"})
        assert response.status_code == (201 if role == "admin" else expected)


def test_scope_route_rejects_cross_origin_change(tmp_path, monkeypatch):
    with client_for(tmp_path, monkeypatch) as client:
        response = client.post(
            "/api/network-scopes", json={"label": "Blocked"},
            headers={"Origin": "https://unrelated.example"},
        )
        assert response.status_code == 403
        assert client.get("/api/network-scopes").json() == []
