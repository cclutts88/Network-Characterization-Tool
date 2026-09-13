from fastapi.testclient import TestClient

from app import poc
from app.main import app


def login(client: TestClient, username: str, password: str) -> None:
    response = client.post(
        "/api/auth/login", json={"username": username, "password": password}
    )
    assert response.status_code == 200


def test_queue_control_roles_reassignment_and_personal_drafts(monkeypatch, tmp_path):
    db_path = tmp_path / "analyzer.db"
    data_dir = tmp_path / "data"
    monkeypatch.setenv("NCT_AUTH_MODE", "local")
    monkeypatch.setenv("NCT_BOOTSTRAP_ADMIN", "nctadmin")
    monkeypatch.setenv("NCT_BOOTSTRAP_PASSWORD", "bootstrap password 123")
    monkeypatch.setattr("app.main.DB_PATH", db_path)
    monkeypatch.setattr(poc, "DB_PATH", db_path)
    monkeypatch.setattr(poc, "DATA_DIR", data_dir)
    with poc.ACTIVE_RUNS_LOCK:
        poc.ACTIVE_RUNS.clear()

    with TestClient(app) as client:
        login(client, "nctadmin", "bootstrap password 123")
        for username in ("alpha", "bravo"):
            created = client.post(
                "/api/auth/users",
                json={
                    "username": username,
                    "display_name": username.title(),
                    "role": "analyst",
                    "password": f"{username} password 123",
                },
            )
            assert created.status_code == 200

        client.post("/api/auth/logout")
        login(client, "alpha", "alpha password 123")
        draft = client.put(
            "/api/workspaces/scan-draft",
            json={"snapshot": {"scanName": "Alpha only"}, "expected_version": None},
        )
        assert draft.status_code == 200
        queued = poc.prepare_scan_run(
            poc.ScanRunRequest(
                operator="alpha",
                created_by="alpha",
                executed_by="alpha",
                name="Alpha queued scan",
                reason="Authorized route test",
                originating_host="nct-test",
                interface="eth0",
                profile="standard",
                targets=["192.0.2.1"],
                capture=True,
            ),
            db_path=db_path,
            interfaces={"eth0"},
        )

        client.post("/api/auth/logout")
        login(client, "bravo", "bravo password 123")
        assert client.get("/api/workspaces/scan-draft").json()["draft"] is None
        queue = client.get("/api/scan-runs/queue/status").json()
        assert queue["runs"][0]["owner"] == "alpha"
        assert queue["runs"][0]["can_cancel"] is False
        assert client.post(f"/api/scan-runs/{queued['run_id']}/cancel").status_code == 403
        assert client.post(
            f"/api/scan-runs/{queued['run_id']}/owner", json={"owner": "bravo"}
        ).status_code == 403

        client.post("/api/auth/logout")
        login(client, "nctadmin", "bootstrap password 123")
        reassigned = client.post(
            f"/api/scan-runs/{queued['run_id']}/owner", json={"owner": "bravo"}
        )
        assert reassigned.status_code == 200
        assert reassigned.json()["owner"] == "bravo"

        client.post("/api/auth/logout")
        login(client, "bravo", "bravo password 123")
        cancelled = client.post(f"/api/scan-runs/{queued['run_id']}/cancel")
        assert cancelled.status_code == 202
        assert cancelled.json()["status"] == "cancelled"
        events = client.get(f"/api/scan-runs/{queued['run_id']}/audit").json()
        assert [item["event"] for item in events][:2] == ["cancelled", "reassigned"]

    with poc.ACTIVE_RUNS_LOCK:
        poc.ACTIVE_RUNS.clear()
