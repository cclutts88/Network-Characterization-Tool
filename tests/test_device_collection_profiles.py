import sqlite3

import pytest
from fastapi.testclient import TestClient
from fastapi import HTTPException
from starlette.requests import Request

from app.database import connect_database
from app.device_collection_profiles import (
    archive_device_collection_profile,
    create_device_collection_profile,
    create_device_collection_profile_version,
    get_device_collection_profile,
    list_device_collection_profiles,
)
from app.main import app
from app.network_scopes import archive_network_scope, create_network_scope


def settings(scope_id=None):
    return {
        "vendor": "cisco",
        "device_type": "firewall",
        "device_types": ["router", "firewall"],
        "device_address": "192.0.2.10",
        "device_name": "Edge",
        "username": "analyst",
        "ssh_port": 22,
        "additional_commands": ["show arp", "show lldp neighbors"],
        "preferred_scope_id": scope_id,
    }


def request_body(scope_id=None):
    return {
        "name": "Edge collection",
        "description": "Approved edge-device settings",
        **settings(scope_id),
    }


def preview_body(profile):
    return {
        "operator": "ignored",
        "originating_host": "workstation",
        "reason": "Fresh collection reason",
        "vendor": "vyos",
        "device_type": "router",
        "device_address": "198.51.100.9",
        "username": "wrong-visible-draft",
        "ssh_port": 2022,
        "authentication_mode": "password_prompt",
        "accountability_interface": "eth0",
        "collection_profile_id": profile["profile_id"],
        "collection_profile_version": profile["version"],
    }


def test_profile_versions_are_immutable_conflict_checked_and_archived(tmp_path):
    db = tmp_path / "nct.db"
    scope = create_network_scope(db, label="Mission lab", created_by="alice")
    original = create_device_collection_profile(
        db, name="Edge collection", description="Initial", created_by="alice",
        settings=settings(scope["scope_id"]),
    )
    assert original["version"] == original["current_version"] == 1
    assert original["settings"]["preferred_scope_label"] == "Mission lab"

    revised_settings = settings(scope["scope_id"])
    revised_settings["additional_commands"].append("show ip route")
    revised = create_device_collection_profile_version(
        db, profile_id=original["profile_id"], expected_version=1,
        name="Edge collection", description="Second", created_by="bob",
        settings=revised_settings,
    )
    assert revised["version"] == 2
    assert get_device_collection_profile(db, original["profile_id"], 1)["settings"]["additional_commands"] == [
        "show arp", "show lldp neighbors"
    ]
    with pytest.raises(ValueError, match="changed in another session"):
        create_device_collection_profile_version(
            db, profile_id=original["profile_id"], expected_version=1,
            name="Edge collection", description="Stale", created_by="carol",
            settings=revised_settings,
        )
    with connect_database(db) as connection:
        with pytest.raises(sqlite3.IntegrityError, match="version pointer"):
            connection.execute(
                "UPDATE device_collection_profile_roots SET active_version = 1 WHERE profile_id = ?",
                (original["profile_id"],),
            )
        with pytest.raises(sqlite3.IntegrityError, match="identity is immutable"):
            connection.execute(
                "UPDATE device_collection_profile_roots SET created_by = 'changed' WHERE profile_id = ?",
                (original["profile_id"],),
            )
        with pytest.raises(sqlite3.IntegrityError, match="require a new version"):
            connection.execute(
                "UPDATE device_collection_profile_roots SET active_name = 'Changed in place' WHERE profile_id = ?",
                (original["profile_id"],),
            )

    archived = archive_device_collection_profile(
        db, profile_id=original["profile_id"], expected_version=2, archived_by="bob",
    )
    assert archived["active"] is False
    assert list_device_collection_profiles(db) == []
    with pytest.raises(ValueError, match="Archived"):
        create_device_collection_profile_version(
            db, profile_id=original["profile_id"], expected_version=2,
            name="Edge collection", description="No reactivation", created_by="bob",
            settings=revised_settings,
        )
    with connect_database(db) as connection:
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            connection.execute(
                "UPDATE device_collection_profile_versions SET description = 'changed' WHERE profile_id = ? AND version = 1",
                (original["profile_id"],),
            )
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            connection.execute(
                "DELETE FROM device_collection_profile_versions WHERE profile_id = ? AND version = 1",
                (original["profile_id"],),
            )
        with pytest.raises(sqlite3.IntegrityError, match="archived.*immutable"):
            connection.execute(
                "UPDATE device_collection_profile_roots SET archived_at = NULL, archived_by = NULL WHERE profile_id = ?",
                (original["profile_id"],),
            )
        with pytest.raises(sqlite3.IntegrityError, match="must be archived"):
            connection.execute(
                "DELETE FROM device_collection_profile_roots WHERE profile_id = ?",
                (original["profile_id"],),
            )


def test_profile_name_scope_and_settings_are_validated_atomically(tmp_path):
    db = tmp_path / "nct.db"
    scope = create_network_scope(db, label="Active scope", created_by="alice")
    create_device_collection_profile(
        db, name="Unique name", description="", created_by="alice",
        settings=settings(scope["scope_id"]),
    )
    with pytest.raises(ValueError, match="already uses this name"):
        create_device_collection_profile(
            db, name="unique name", description="", created_by="bob",
            settings=settings(scope["scope_id"]),
        )
    archive_network_scope(
        db, scope["scope_id"], expected_version=1, archived_by="alice",
        reason="Scope closed",
    )
    with pytest.raises(ValueError, match="does not exist or is archived"):
        create_device_collection_profile(
            db, name="Archived scope", description="", created_by="alice",
            settings=settings(scope["scope_id"]),
        )
    with pytest.raises(ValueError, match="approved non-secret settings"):
        create_device_collection_profile(
            db, name="Secret bypass", description="", created_by="alice",
            settings={**settings(), "password": "stored-secret"},
        )
    unsafe = settings()
    unsafe["additional_commands"] = ["configure terminal"]
    with pytest.raises(ValueError, match="read-only command"):
        create_device_collection_profile(
            db, name="Unsafe command", description="", created_by="alice",
            settings=unsafe,
        )


def test_profile_api_resolves_exact_version_and_requires_fresh_preview(tmp_path, monkeypatch):
    import app.device_configs as device_configs

    db = tmp_path / "nct.db"
    monkeypatch.setattr(device_configs, "DB_PATH", db)
    scope = create_network_scope(db, label="Mission lab", created_by="alice")
    with TestClient(app) as client:
        created_response = client.post(
            "/api/device-configs/profiles", json=request_body(scope["scope_id"])
        )
        assert created_response.status_code == 201
        created = created_response.json()

        resolved = client.post("/api/device-configs/preview", json=preview_body(created))
        assert resolved.status_code == 200
        data = resolved.json()
        assert data["device_address"] == "192.0.2.10"
        assert data["additional_commands"] == ["show arp", "show lldp neighbors"]
        assert data["collection_profile"] == {
            "profile_id": created["profile_id"], "version": 1, "name": "Edge collection"
        }
        assert data["preferred_scope_id"] == scope["scope_id"]
        assert data["preferred_scope_available"] is True
        assert "assignment" not in data

        revision = {**request_body(scope["scope_id"]), "expected_version": 1}
        revision["description"] = "Reviewed revision"
        revised_response = client.post(
            f"/api/device-configs/profiles/{created['profile_id']}/versions", json=revision
        )
        assert revised_response.status_code == 201
        revised = revised_response.json()
        stale = client.post("/api/device-configs/preview", json=preview_body(created))
        assert stale.status_code == 409
        stale_key_plan = {
            **preview_body(created),
            "authentication_mode": "key",
            "key_path": "/keys/not-present",
        }
        assert client.post("/api/device-configs/preflight", json=stale_key_plan).status_code == 409
        assert client.post("/api/device-configs/execute", json=stale_key_plan).status_code == 409
        fresh = client.post("/api/device-configs/preview", json=preview_body(revised))
        assert fresh.status_code == 200

        archived = client.post(
            f"/api/device-configs/profiles/{created['profile_id']}/archive",
            json={"expected_version": 2},
        )
        assert archived.status_code == 200
        rejected = client.post("/api/device-configs/preview", json=preview_body(revised))
        assert rejected.status_code == 409


def test_archived_profile_scope_is_retained_but_never_preselected(tmp_path, monkeypatch):
    import app.device_configs as device_configs

    db = tmp_path / "nct.db"
    monkeypatch.setattr(device_configs, "DB_PATH", db)
    scope = create_network_scope(db, label="Former mission", created_by="alice")
    profile = create_device_collection_profile(
        db, name="Former scope profile", description="", created_by="alice",
        settings=settings(scope["scope_id"]),
    )
    archive_network_scope(
        db, scope["scope_id"], expected_version=1, archived_by="alice",
        reason="Mission complete",
    )
    with TestClient(app) as client:
        response = client.post("/api/device-configs/preview", json=preview_body(profile))
    assert response.status_code == 200
    data = response.json()
    assert data["preferred_scope_id"] is None
    assert data["profile_preferred_scope_id"] == scope["scope_id"]
    assert data["preferred_scope_label"] == "Former mission"
    assert data["preferred_scope_available"] is False


@pytest.mark.parametrize("extra", [
    {"password": "must-never-be-stored"},
    {"key_path": "/keys/private"},
])
def test_profile_api_rejects_secret_fields_and_unsafe_commands(tmp_path, monkeypatch, extra):
    import app.device_configs as device_configs

    monkeypatch.setattr(device_configs, "DB_PATH", tmp_path / "nct.db")
    with TestClient(app) as client:
        secret = client.post("/api/device-configs/profiles", json={**request_body(), **extra})
        unsafe_body = request_body()
        unsafe_body["additional_commands"] = ["configure terminal"]
        unsafe = client.post("/api/device-configs/profiles", json=unsafe_body)
    assert secret.status_code == 422
    assert unsafe.status_code == 422


def test_profile_management_requires_analyst_but_listing_remains_readable(monkeypatch):
    import app.device_configs as device_configs

    monkeypatch.setattr(device_configs, "auth_enabled", lambda: True)
    request = Request({"type": "http", "method": "POST", "path": "/", "headers": []})
    request.state.analyst = {"username": "reviewer", "role": "viewer"}
    with pytest.raises(HTTPException) as denied:
        device_configs._device_profile_actor(request)
    assert denied.value.status_code == 403
    request.state.analyst = {"username": "operator", "role": "analyst"}
    assert device_configs._device_profile_actor(request) == "operator"
