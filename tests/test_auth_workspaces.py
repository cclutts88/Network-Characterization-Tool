import sqlite3

from fastapi.testclient import TestClient

from app.auth import create_user, init_auth_storage, verify_credentials
from app.achievements import list_achievements, unlock_achievement
from app.main import app
from app.shell_preferences import (
    delete_shared_theme,
    get_shell_preference,
    list_shared_themes,
    publish_shared_theme,
    save_shell_preference,
)
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


def test_shell_preferences_are_private_to_each_analyst(tmp_path):
    db_path = tmp_path / "analyzer.db"
    saved = save_shell_preference(
        db_path,
        owner="alpha",
        snapshot={
            "appearance": {"preset": "current", "colors": {}},
            "guide_enabled": True,
            "guide_dock": "bottom",
            "sidebar_closed": False,
        },
    )

    assert saved["version"] == 1
    assert get_shell_preference(db_path, owner="alpha")["snapshot"]["guide_dock"] == "bottom"
    assert get_shell_preference(db_path, owner="bravo") is None


def test_shared_themes_are_copied_and_visible_to_other_analysts(tmp_path):
    db_path = tmp_path / "analyzer.db"
    shared = publish_shared_theme(
        db_path,
        owner="alpha",
        source_theme_id="personal-1",
        name="Night watch",
        snapshot={"preset": "graphite_soc", "colors": {}, "options": {}},
    )
    assert shared["owner"] == "alpha"
    assert list_shared_themes(db_path)[0]["name"] == "Night watch"

    updated = publish_shared_theme(
        db_path,
        owner="alpha",
        source_theme_id="personal-1",
        name="Night watch revised",
        snapshot={"preset": "current", "colors": {}, "options": {}},
    )
    assert updated["theme_id"] == shared["theme_id"]
    assert updated["version"] == 2
    assert not delete_shared_theme(
        db_path, owner="bravo", theme_id=shared["theme_id"]
    )
    assert delete_shared_theme(
        db_path, owner="alpha", theme_id=shared["theme_id"]
    )
    assert list_shared_themes(db_path) == []


def test_achievements_are_private_and_unlock_only_once(tmp_path):
    db_path = tmp_path / "analyzer.db"
    achievement, newly_unlocked = unlock_achievement(
        db_path,
        owner="alpha",
        achievement_id="first_scan",
        context={"page": "/scans"},
    )
    assert newly_unlocked is True
    assert achievement["title"] == "First Contact"
    assert achievement["context"] == {"page": "/scans"}

    same_achievement, newly_unlocked = unlock_achievement(
        db_path,
        owner="alpha",
        achievement_id="first_scan",
        context={"page": "/analysis"},
    )
    assert newly_unlocked is False
    assert same_achievement["unlocked_at"] == achievement["unlocked_at"]
    assert [item for item in list_achievements(db_path, owner="bravo") if item["unlocked"]] == []


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
        assert "Account &amp; settings" in account_script.text
        assert "Graphite SOC" in account_script.text
        assert "Theme Workshop" in account_script.text
        assert "Sage Operations" in account_script.text
        assert "Matrix Rain" in account_script.text
        assert "System AI" in account_script.text
        assert "dcc_mordecai" in account_script.text
        assert "dcc_odette" in account_script.text
        assert "dcc_zev" in account_script.text
        assert "`${helper} · Operator Guide`" in account_script.text
        assert "preset==='dcc_mordecai'?'Odette':'Mordecai'" in account_script.text
        assert "button.dataset.guideIdentity=identity" in account_script.text
        assert "#nct-operator-guide[data-guide-identity=odette]" in account_script.text
        assert "applyDccGuideIdentity" in account_script.text
        assert 'html[data-nct-theme^="dcc_"] #nct-operator-guide' in account_script.text
        assert 'html[data-nct-theme="dcc_donut"] body{text-transform:uppercase}' in account_script.text
        assert "Dungeon Anarchist’s Cookbook" in account_script.text
        assert "applyCookbookIdentity" in account_script.text
        assert "NEW CODEX ENTRY: Shared by Crawler" in account_script.text
        assert 'html[data-nct-theme^="dcc_"] .nct-note-panel' in account_script.text
        assert "Network Crawler Terminal" in account_script.text
        assert "applyThemeIdentity" in account_script.text
        assert "nct-system-ai-unlocked-v1" in account_script.text
        assert "Unauthorized curiosity detected" in account_script.text
        assert "Jamal" in account_script.text
        assert "NEW ACHIEVEMENT!" in account_script.text
        assert "Holidays" in account_script.text
        assert "Christmas / Winter Holiday" in account_script.text
        assert "Halloween" in account_script.text
        assert "Thanksgiving" in account_script.text
        assert "Independence Day" in account_script.text
        assert "holiday_christmas" in account_script.text
        assert "holiday_halloween" in account_script.text
        assert "holiday_thanksgiving" in account_script.text
        assert "Midnight fireworks ready" in account_script.text
        assert "one imaginary Platinum Loot Box" in account_script.text
        assert "It was meant to be" in account_script.text
        assert "The System accepts your apology" in account_script.text
        assert "pattern-recognition score" in account_script.text
        assert "nct-effect-glow" in account_script.text
        assert "nct-effect-transparency" in account_script.text
        assert "nct-effect-scanlines" in account_script.text
        assert "nct-effect-background" in account_script.text
        assert "nct-effect-motion" in account_script.text
        assert "Motion amount" in account_script.text
        assert "Settings > Accessibility > Visual effects > Animation effects" in account_script.text
        assert "Enable Performance Mode" in account_script.text
        assert "Personal themes" in account_script.text
        assert "Your Themes" in account_script.text
        assert "Shared Themes" in account_script.text
        assert "/api/workspaces/shared-themes" in account_script.text
        assert "Achievements" in account_script.text
        assert "/api/workspaces/achievements" in account_script.text
        assert "nct-achievement-dialog" in account_script.text
        assert "applyAchievementVisibility" in account_script.text
        assert "startsWith('dcc_')" in account_script.text
        assert "prefers-reduced-motion" in account_script.text
        assert "Appearance never changes evidence meaning" in account_script.text
        assert "nct-sidebar-edge" in account_script.text
        assert "Device collections" in account_script.text
        assert "New collection" in account_script.text
        assert "No-Strike exclusions" in account_script.text
        assert "Active scans" in account_script.text
        assert "Active scans & queue" not in account_script.text
        assert "support:{queuePanel:['currentRunPanel']}" in account_script.text
        assert "support:{scanBuilder:" not in account_script.text
        assert account_script.text.index("Saved Networks") < account_script.text.index("New scan")
        assert "Interfaces and routes" in account_script.text
        assert "Exposure reports" in account_script.text
        assert "nct-task-focused" in account_script.text
        assert "Enable Operator Guide" in account_script.text
        assert "nct-operator-guide-enabled-v1" in account_script.text
        assert "taskGuidance" in account_script.text
        assert "#nct-guide-toggle[aria-expanded=true]" in account_script.text
        assert "z-index:280" in account_script.text
        assert 'id="nct-guide-close"' not in account_script.text
        assert "Close the contextual Operator Guide" in account_script.text
        assert "height:min(46vh,420px)" in account_script.text
        assert "nct-operator-guide-dock-v1" in account_script.text
        assert "#nct-operator-guide[data-dock=bottom]" in account_script.text
        assert 'id="nct-guide-dock"' in account_script.text
        assert "nct-guide-dock-glyph" in account_script.text
        assert 'data-target="bottom"' in account_script.text
        assert "function syncGuideToggleAttachment()" in account_script.text
        assert "guideToggle.dataset.guideAttachment" in account_script.text
        assert "guideDock.textContent" not in account_script.text
        assert "/api/workspaces/shell-preferences" in account_script.text
        assert "saved to your analyst account" in account_script.text
        assert "Sign out" in account_script.text
        assert "Accounts" in account_script.text
        assert "Personal notes" in account_script.text
        assert "'/reachability': 'reach'" in account_script.text
        assert "reach:'Reach'" in account_script.text
        assert "shared notes" in account_script.text
        assert ".nct-note-panel.personal" in account_script.text
        assert ".nct-note-panel.shared" in account_script.text
        shell_preference = admin.put(
            "/api/workspaces/shell-preferences",
            json={
                "snapshot": {
                    "appearance": {"preset": "current", "colors": {}},
                    "guide_enabled": True,
                    "guide_dock": "bottom",
                    "sidebar_closed": False,
                }
            },
        )
        assert shell_preference.status_code == 200
        assert admin.get("/api/workspaces/shell-preferences").json()["preference"][
            "snapshot"
        ]["guide_dock"] == "bottom"
        achievements = admin.get("/api/workspaces/achievements")
        assert achievements.status_code == 200
        assert achievements.json()["server_persistence"] is True
        assert not any(
            item["unlocked"] for item in achievements.json()["achievements"]
        )
        unlocked = admin.post(
            "/api/workspaces/achievements/first_scan/unlock",
            json={"context": {"page": "/scans"}},
        )
        assert unlocked.status_code == 200
        assert unlocked.json()["newly_unlocked"] is True
        repeated = admin.post(
            "/api/workspaces/achievements/first_scan/unlock",
            json={"context": {"page": "/analysis"}},
        )
        assert repeated.status_code == 200
        assert repeated.json()["newly_unlocked"] is False
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


def test_local_operator_notes_are_persistent_without_account_sign_in(
    monkeypatch, tmp_path
):
    monkeypatch.setenv("NCT_AUTH_MODE", "disabled")
    monkeypatch.setattr("app.main.DB_PATH", tmp_path / "analyzer.db")

    with TestClient(app) as client:
        identity = client.get("/api/auth/me").json()
        assert identity == {"authentication_enabled": False, "analyst": None}
        created = client.post(
            "/api/workspaces/notes",
            json={"title": "Local field note", "kind": "note", "content": "Observed."},
        )
        assert created.status_code == 200
        assert created.json()["owner"] == "local-operator"
        listing = client.get("/api/workspaces/notes?page=reach").json()
        assert listing["server_persistence"] is True
        assert listing["analyst"]["display_name"] == "Local operator"
        assert [item["title"] for item in listing["notes"]] == ["Local field note"]
        shared = client.post(
            f"/api/workspaces/notes/{created.json()['note_id']}/share",
            json={"shared": True, "page": "reach", "expected_version": 1},
        )
        assert shared.status_code == 200
        assert shared.json()["shared_page"] == "reach"


def test_local_operator_scan_draft_is_persistent_without_account_sign_in(
    monkeypatch, tmp_path
):
    monkeypatch.setenv("NCT_AUTH_MODE", "disabled")
    monkeypatch.setattr("app.main.DB_PATH", tmp_path / "analyzer.db")

    with TestClient(app) as client:
        initial = client.get("/api/workspaces/scan-draft")
        assert initial.status_code == 200
        assert initial.json() == {"server_persistence": True, "draft": None}
        saved = client.put(
            "/api/workspaces/scan-draft",
            json={"snapshot": {"scanName": "Local draft"}, "expected_version": None},
        )
        assert saved.status_code == 200
        assert saved.json()["owner"] == "local-operator"
        restored = client.get("/api/workspaces/scan-draft").json()["draft"]
        assert restored["snapshot"]["scanName"] == "Local draft"
        removed = client.delete("/api/workspaces/scan-draft")
        assert removed.status_code == 200
        assert removed.json() == {"owner": "local-operator", "deleted": True}
