from concurrent.futures import ThreadPoolExecutor

import pytest

from app.database import connect_database
from app.mission_environment import (
    DERIVED_PROHIBITED_FLAG,
    MissionEnvironmentConflict,
    get_mission_environment,
    init_mission_environment_storage,
    list_mission_history,
    update_mission_tool,
    update_scope_context,
)
from app.network_scopes import archive_network_scope, create_network_scope


def scope_record(db_path):
    return create_network_scope(
        db_path, label="Engineering", description="Reviewed enclave",
        created_by="admin", reason="Create test scope",
    )


def scope_payload(scope_id, **overrides):
    values = {
        "scope_id": scope_id, "expected_version": 0,
        "nmap_coverage": "available", "arkime_coverage": "partial",
        "kibana_coverage": "unknown", "config_coverage": "partial",
        "nmap_authorization": "prohibited",
        "device_evidence": "partial_configuration",
        "blind_spots": ["unknown_nat"], "notes": "Reviewed with site lead",
        "actor": "admin", "reason": "Record known coverage",
    }
    values.update(overrides)
    return values


def test_missing_records_are_synthesized_unknown_without_read_writes(tmp_path):
    db_path = tmp_path / "analyzer.db"
    init_mission_environment_storage(db_path)
    scope = scope_record(db_path)
    with connect_database(db_path) as db:
        before_tools = db.execute("SELECT COUNT(*) FROM mission_environment_tools").fetchone()[0]
        before_scopes = db.execute("SELECT COUNT(*) FROM mission_scope_contexts").fetchone()[0]
        before_audit = db.execute("SELECT COUNT(*) FROM mission_environment_audit").fetchone()[0]

    result = get_mission_environment(db_path)

    assert len(result["tools"]) == 4
    assert all(item["availability"] == "unknown" and item["version"] == 0
               and item["configured"] is False for item in result["tools"])
    assert result["scopes"] == [{
        "scope_id": scope["scope_id"], "scope_label": "Engineering",
        "scope_active": True, "nmap_coverage": "unknown",
        "arkime_coverage": "unknown", "kibana_coverage": "unknown",
        "config_coverage": "unknown", "nmap_authorization": "unknown",
        "device_evidence": "unknown", "blind_spots": [], "notes": "",
        "version": 0, "configured": False, "created_at": None,
        "created_by": None, "updated_at": None, "updated_by": None,
    }]
    with connect_database(db_path) as db:
        assert db.execute("SELECT COUNT(*) FROM mission_environment_tools").fetchone()[0] == before_tools
        assert db.execute("SELECT COUNT(*) FROM mission_scope_contexts").fetchone()[0] == before_scopes
        assert db.execute("SELECT COUNT(*) FROM mission_environment_audit").fetchone()[0] == before_audit


def test_tool_declaration_versions_audits_and_rejects_secrets(tmp_path):
    db_path = tmp_path / "analyzer.db"
    init_mission_environment_storage(db_path)
    saved = update_mission_tool(
        db_path, "arkime", expected_version=0, availability="available",
        version_text="5.5", access_method="Read-only analyst web portal",
        notes="Request access from the environment administrator", actor="admin",
        reason="Record installed passive source",
    )
    assert saved["version"] == 1
    assert saved["availability"] == "available"
    with pytest.raises(MissionEnvironmentConflict):
        update_mission_tool(
            db_path, "arkime", expected_version=0, availability="unavailable",
            version_text="", access_method="", notes="", actor="admin",
            reason="Stale edit",
        )
    unsafe_values = [
        "password=classified",
        "https://analyst:supersecret@example.invalid",
        "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.signature",
        "Bearer abcdefghijklmnopqrstuvwxyz.1234567890.signature",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbmFseXN0In0.signature12345",
        "client_secret=hunter2",
    ]
    for index, unsafe in enumerate(unsafe_values):
        with pytest.raises(ValueError, match="passwords, tokens, or keys"):
            update_mission_tool(
                db_path, "nmap", expected_version=0, availability="available",
                version_text="7.95",
                access_method=unsafe if index % 2 == 0 else "Organization SSO portal",
                notes=unsafe if index % 2 else "",
                actor="admin", reason="Unsafe input",
            )
    benign = update_mission_tool(
        db_path, "nmap", expected_version=0, availability="available",
        version_text="7.95", access_method="HTTPS portal using organization SSO",
        notes="Request access from administrator; use read-only analyst role",
        actor="admin", reason="Record non-secret access instructions",
    )
    assert benign["access_method"] == "HTTPS portal using organization SSO"
    history = list_mission_history(db_path, kind="tool", key="arkime")
    assert history["total"] == 1
    assert history["items"][0]["before"]["configured"] is False
    assert history["items"][0]["after"]["availability"] == "available"
    with connect_database(db_path) as db:
        with pytest.raises(Exception, match="audit is immutable"):
            db.execute("DELETE FROM mission_environment_audit")


def test_scope_context_keeps_coverage_authorization_and_blind_spots_separate(tmp_path):
    db_path = tmp_path / "analyzer.db"
    init_mission_environment_storage(db_path)
    scope = scope_record(db_path)
    saved = update_scope_context(db_path, **scope_payload(scope["scope_id"]))
    assert saved["nmap_coverage"] == "available"
    assert saved["nmap_authorization"] == "prohibited"
    assert saved["blind_spots"] == [DERIVED_PROHIBITED_FLAG, "unknown_nat"]
    assert DERIVED_PROHIBITED_FLAG not in scope_payload(scope["scope_id"])["blind_spots"]
    result = get_mission_environment(db_path)["scopes"][0]
    assert result == saved


def test_archived_scope_keeps_context_but_rejects_changes(tmp_path):
    db_path = tmp_path / "analyzer.db"
    init_mission_environment_storage(db_path)
    scope = scope_record(db_path)
    update_scope_context(db_path, **scope_payload(scope["scope_id"]))
    archive_network_scope(
        db_path, scope["scope_id"], expected_version=1,
        archived_by="admin", reason="Close enclave",
    )
    assert get_mission_environment(db_path)["scopes"] == []
    archived = get_mission_environment(db_path, include_archived=True)["scopes"][0]
    assert archived["scope_active"] is False
    assert archived["nmap_authorization"] == "prohibited"
    with pytest.raises(ValueError, match="Archived"):
        update_scope_context(
            db_path, **scope_payload(scope["scope_id"], expected_version=1,
                                     reason="Should fail"),
        )


def test_scope_update_and_audit_roll_back_together(tmp_path, monkeypatch):
    import app.mission_environment as mission

    db_path = tmp_path / "analyzer.db"
    init_mission_environment_storage(db_path)
    scope = scope_record(db_path)

    def fail_audit(*_args, **_kwargs):
        raise RuntimeError("audit unavailable")

    monkeypatch.setattr(mission, "_audit", fail_audit)
    with pytest.raises(RuntimeError, match="audit unavailable"):
        update_scope_context(db_path, **scope_payload(scope["scope_id"]))
    with connect_database(db_path) as db:
        assert db.execute("SELECT COUNT(*) FROM mission_scope_contexts").fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM mission_environment_audit").fetchone()[0] == 0


def test_concurrent_scope_writers_cannot_overwrite_one_another(tmp_path):
    db_path = tmp_path / "analyzer.db"
    init_mission_environment_storage(db_path)
    scope = scope_record(db_path)

    def save(reason):
        try:
            return update_scope_context(
                db_path, **scope_payload(scope["scope_id"], reason=reason)
            )["version"]
        except MissionEnvironmentConflict:
            return "conflict"

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(save, ["First review", "Second review"]))
    assert sorted(results, key=str) == [1, "conflict"]
    assert list_mission_history(
        db_path, kind="scope", key=scope["scope_id"]
    )["total"] == 1


def test_coverage_and_history_are_bounded(tmp_path):
    db_path = tmp_path / "analyzer.db"
    init_mission_environment_storage(db_path)
    for number in range(105):
        create_network_scope(
            db_path, label=f"Scope {number:03d}", created_by="admin",
            reason="Paging fixture",
        )
    first = get_mission_environment(db_path, limit=500, offset=0)
    second = get_mission_environment(db_path, limit=10, offset=100)
    assert first["scope_total"] == 105
    assert len(first["scopes"]) == 100
    assert len(second["scopes"]) == 5
