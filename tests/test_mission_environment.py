from concurrent.futures import ThreadPoolExecutor

import pytest

import app.mission_environment as mission_environment
from app.database import configure_database
from app.database import connect_database
from app.mission_environment import (
    DERIVED_PROHIBITED_FLAG,
    MissionEnvironmentConflict,
    create_special_device_roles,
    get_mission_environment,
    init_mission_environment_storage,
    list_active_special_device_roles,
    list_mission_history,
    retire_special_device_role,
    save_special_device_role,
    update_mission_tool,
    update_scope_context,
)
from app.network_map import annotate_mission_partner_roles, ensure_ip_node
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


def test_missing_database_read_does_not_initialize_special_role_storage(tmp_path):
    db_path = tmp_path / "missing.db"
    result = get_mission_environment(db_path)
    assert result["special_device_roles"] == []
    assert result["special_role_address_candidates"] == []
    assert not db_path.exists()


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
        "scope_active": True, "network_scope_version": 1,
        "nmap_coverage": "unknown",
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


def test_observed_environment_stays_network_level_and_lists_devices(tmp_path):
    db_path = tmp_path / "analyzer.db"
    init_mission_environment_storage(db_path)
    scope = scope_record(db_path)
    with connect_database(db_path) as db:
        db.executescript(
            """
            CREATE TABLE saved_networks (
                saved_network_id TEXT PRIMARY KEY, name TEXT, cidr TEXT, active INTEGER
            );
            CREATE TABLE saved_network_scope_associations (
                association_id TEXT PRIMARY KEY, saved_network_id TEXT, scope_id TEXT,
                predecessor_id TEXT
            );
            CREATE TABLE endpoint_entities (
                entity_id TEXT PRIMARY KEY, scope_id TEXT, address TEXT
            );
            CREATE TABLE entity_assessments (
                assessment_id TEXT PRIMARY KEY, assessed_at TEXT, recorded_at TEXT
            );
            CREATE TABLE endpoint_receipts (assessment_id TEXT, host_id TEXT);
            CREATE TABLE device_collections (
                run_id TEXT PRIMARY KEY, device_name TEXT, device_address TEXT
            );
            CREATE TABLE device_interface_assessments (
                assessment_id TEXT PRIMARY KEY, run_id TEXT, scope_id TEXT,
                recorded_at TEXT
            );
            CREATE TABLE device_interface_receipts (
                assessment_id TEXT, address TEXT, prefix_length INTEGER,
                address_family TEXT
            );
            CREATE TABLE arkime_imports (
                import_id TEXT PRIMARY KEY, scope_id TEXT, imported_at TEXT
            );
            CREATE TABLE arkime_session_receipts (
                import_id TEXT, source_ip TEXT, destination_ip TEXT
            );
            """
        )
        db.execute(
            "INSERT INTO saved_networks VALUES ('net-1', 'Operations', '10.0.0.0/24', 1)"
        )
        db.execute(
            "INSERT INTO saved_network_scope_associations VALUES ('assoc-1', 'net-1', ?, NULL)",
            (scope["scope_id"],),
        )
        db.executemany(
            "INSERT INTO endpoint_entities VALUES (?, ?, ?)",
            [
                ("host-1", scope["scope_id"], "10.0.0.10"),
                ("host-outside", scope["scope_id"], "192.0.2.5"),
            ],
        )
        db.execute(
            "INSERT INTO entity_assessments VALUES ('scan-1', '2026-10-23T12:00:00+00:00', '2026-10-23T12:01:00+00:00')"
        )
        db.executemany(
            "INSERT INTO endpoint_receipts VALUES ('scan-1', ?)",
            [("host-1",), ("host-outside",)],
        )
        db.execute(
            "INSERT INTO device_collections VALUES ('device-run-1', 'Edge Router', '10.0.0.1')"
        )
        db.execute(
            "INSERT INTO device_interface_assessments VALUES ('device-a-1', 'device-run-1', ?, '2026-10-23T12:02:00+00:00')",
            (scope["scope_id"],),
        )
        db.execute(
            "INSERT INTO device_interface_receipts VALUES ('device-a-1', '10.0.0.1', 24, 'ipv4')"
        )
        db.execute(
            "INSERT INTO arkime_imports VALUES ('arkime-1', ?, '2026-10-23T12:03:00+00:00')",
            (scope["scope_id"],),
        )
        db.execute(
            "INSERT INTO arkime_session_receipts VALUES ('arkime-1', '10.0.0.10', '198.51.100.20')"
        )

    result = get_mission_environment(db_path)

    assert len(result["observed_networks"]) == 1
    row = result["observed_networks"][0]
    assert row["network_name"] == "Operations"
    assert row["network"] == "10.0.0.0/24"
    assert row["observed_host_count"] == 2
    assert row["reported_address_count"] == 2
    assert row["network_device_count"] == 1
    assert row["device_collection_count"] == 1
    assert row["network_device_sources"][0]["run_id"] == "device-run-1"
    assert row["network_devices"] == ["Edge Router"]
    assert row["nmap_address_count"] == 1
    assert row["device_address_count"] == 1
    assert row["arkime_address_count"] == 1
    assert all(item["network"] != "192.0.2.5/32" for item in result["observed_networks"])
    assert result["observed_network_metadata"]["unmapped_nmap_address_count"] == 1
    assert result["observed_network_metadata"]["unmapped_arkime_address_count"] == 1
    assert result["observed_network_metadata"]["authorization_effect"] == "none"


def test_special_role_batch_keeps_addresses_independent_and_supports_multiple_roles(tmp_path):
    db_path = tmp_path / "analyzer.db"
    init_mission_environment_storage(db_path)
    scope = scope_record(db_path)

    created = create_special_device_roles(
        db_path, scope_id=scope["scope_id"],
        addresses=["10.0.0.10", "10.0.0.11"], role_key="dns_server",
        custom_role="", device_label="Primary and backup DNS",
        actor="admin", reason="Mission partner identified both DNS servers",
    )
    create_special_device_roles(
        db_path, scope_id=scope["scope_id"], addresses=["10.0.0.10"],
        role_key="ntp_server", custom_role="", device_label="Shared services",
        actor="admin", reason="The first DNS server also supplies time",
    )

    assert len(created) == 2
    assert len({item["role_id"] for item in created}) == 2
    result = get_mission_environment(db_path)
    roles = result["special_device_roles"]
    assert [(item["address"], item["role_key"]) for item in roles] == [
        ("10.0.0.10", "dns_server"),
        ("10.0.0.11", "dns_server"),
        ("10.0.0.10", "ntp_server"),
    ]
    assert all(item["scope_id"] == scope["scope_id"] for item in roles)
    assert all(item["assessment"]["status"] == "insufficient_evidence" for item in roles)
    assert result["special_role_metadata"]["recommendation_effect"] == "none"
    definitions = {item["role_key"]: item for item in result["special_role_definitions"]}
    assert definitions["web_application_server"]["typical_ports"] == [
        "80/tcp", "443/tcp", "8080/tcp", "8443/tcp",
    ]
    assert definitions["backup_server"]["assessment_support"] == "declaration_only"
    assert definitions["other"]["label"] == "Other mission-specific role"

    updated = save_special_device_role(
        db_path, role_id=created[0]["role_id"], expected_version=1,
        scope_id=scope["scope_id"], address="10.0.0.10", role_key="dns_server",
        custom_role="", device_label="Primary DNS", actor="admin",
        reason="Clarify the primary member",
    )
    assert updated["version"] == 2
    with pytest.raises(MissionEnvironmentConflict):
        save_special_device_role(
            db_path, role_id=created[0]["role_id"], expected_version=1,
            scope_id=scope["scope_id"], address="10.0.0.10", role_key="dns_server",
            custom_role="", device_label="Stale edit", actor="admin", reason="Stale",
        )
    retired = retire_special_device_role(
        db_path, role_id=created[1]["role_id"], expected_version=1,
        actor="admin", reason="Mission partner removed the backup",
    )
    assert retired["active"] is False
    assert {item["address"] for item in list_active_special_device_roles(db_path)} == {
        "10.0.0.10"
    }


def test_special_role_batch_is_atomic_and_rejects_duplicate_active_role(tmp_path):
    db_path = tmp_path / "analyzer.db"
    init_mission_environment_storage(db_path)
    scope = scope_record(db_path)
    with pytest.raises(ValueError, match="address"):
        create_special_device_roles(
            db_path, scope_id=scope["scope_id"],
            addresses=["10.0.0.10", "not-an-address"], role_key="dns_server",
            custom_role="", device_label="DNS", actor="admin", reason="Invalid batch",
        )
    assert get_mission_environment(db_path)["special_device_roles"] == []
    create_special_device_roles(
        db_path, scope_id=scope["scope_id"], addresses=["10.0.0.10"],
        role_key="dns_server", custom_role="", device_label="DNS",
        actor="admin", reason="Valid declaration",
    )
    with pytest.raises(MissionEnvironmentConflict, match="already has"):
        create_special_device_roles(
            db_path, scope_id=scope["scope_id"], addresses=["10.0.0.10"],
            role_key="dns_server", custom_role="", device_label="Duplicate",
            actor="admin", reason="Duplicate declaration",
        )


def test_specific_special_identifier_requires_and_preserves_operator_name(tmp_path):
    db_path = tmp_path / "analyzer.db"
    init_mission_environment_storage(db_path)
    scope = scope_record(db_path)
    with pytest.raises(ValueError, match="Specific Special Identifier"):
        create_special_device_roles(
            db_path, scope_id=scope["scope_id"], addresses=["10.0.0.40"],
            role_key="other", custom_role="", device_label="Mission service",
            actor="admin", reason="The partner identified a special service",
        )
    created = create_special_device_roles(
        db_path, scope_id=scope["scope_id"], addresses=["10.0.0.40", "10.0.0.41"],
        role_key="other", custom_role="PKI certificate authority",
        device_label="Primary and backup PKI", actor="admin",
        reason="Mission partner identified the certificate authorities",
        declared_ports=["443/tcp", "8443/TCP"],
        declared_services=["HTTPS", "Mission PKI"],
    )
    assert [item["custom_role"] for item in created] == [
        "PKI certificate authority", "PKI certificate authority",
    ]
    roles = get_mission_environment(db_path)["special_device_roles"]
    assert {item["role_label"] for item in roles} == {"PKI certificate authority"}
    assert all(item["declared_ports"] == ["443/tcp", "8443/tcp"] for item in roles)
    assert all(item["declared_services"] == ["HTTPS", "Mission PKI"] for item in roles)
    assert all(item["assessment"]["status"] == "insufficient_evidence" for item in roles)
    with pytest.raises(ValueError, match="port/protocol"):
        create_special_device_roles(
            db_path, scope_id=scope["scope_id"], addresses=["10.0.0.42"],
            role_key="other", custom_role="Invalid port fixture",
            device_label="Invalid", actor="admin", reason="Reject ambiguous port",
            declared_ports=["443"],
        )


def test_corrected_nmap_scope_excludes_superseded_observations_from_current_views(tmp_path):
    db_path = tmp_path / "analyzer.db"
    init_mission_environment_storage(db_path)
    old_scope = scope_record(db_path)
    new_scope = create_network_scope(
        db_path, label="Corrected scope", description="Current assignment",
        created_by="admin", reason="Correction fixture",
    )
    with connect_database(db_path) as db:
        db.executescript(
            """
            CREATE TABLE saved_networks (
                saved_network_id TEXT PRIMARY KEY, name TEXT, cidr TEXT, active INTEGER
            );
            CREATE TABLE saved_network_scope_associations (
                association_id TEXT PRIMARY KEY, saved_network_id TEXT, scope_id TEXT,
                predecessor_id TEXT
            );
            CREATE TABLE endpoint_entities (
                entity_id TEXT PRIMARY KEY, scope_id TEXT, address TEXT
            );
            CREATE TABLE service_entities (
                entity_id TEXT PRIMARY KEY, host_id TEXT, protocol TEXT, port INTEGER
            );
            CREATE TABLE entity_assessments (
                assessment_id TEXT PRIMARY KEY, scope_id TEXT,
                artifact_observation_id TEXT, assessed_at TEXT, recorded_at TEXT
            );
            CREATE TABLE endpoint_receipts (assessment_id TEXT, host_id TEXT);
            CREATE TABLE service_receipts (
                assessment_id TEXT, service_id TEXT, facts_json TEXT
            );
            CREATE TABLE artifact_scope_assignments (
                assignment_id TEXT PRIMARY KEY, artifact_observation_id TEXT,
                scope_id TEXT, supersedes_assignment_id TEXT
            );
            CREATE TABLE assessment_scope_assignment_links (
                assignment_id TEXT, assessment_id TEXT
            );
            """
        )
        db.executemany(
            "INSERT INTO saved_networks VALUES (?, ?, ?, 1)",
            [("old-net", "Old network", "10.0.0.0/24"),
             ("new-net", "Corrected network", "10.0.0.0/24")],
        )
        db.executemany(
            "INSERT INTO saved_network_scope_associations VALUES (?, ?, ?, NULL)",
            [("old-assoc", "old-net", old_scope["scope_id"]),
             ("new-assoc", "new-net", new_scope["scope_id"])],
        )
        db.executemany(
            "INSERT INTO endpoint_entities VALUES (?, ?, '10.0.0.53')",
            [("old-host", old_scope["scope_id"]),
             ("new-host", new_scope["scope_id"])],
        )
        db.executemany(
            "INSERT INTO service_entities VALUES (?, ?, 'udp', 53)",
            [("old-service", "old-host"), ("new-service", "new-host")],
        )
        db.executemany(
            "INSERT INTO entity_assessments VALUES (?, ?, 'observation', ?, ?)",
            [("old-assessment", old_scope["scope_id"],
              "2026-10-23T10:00:00+00:00", "2026-10-23T10:01:00+00:00"),
             ("new-assessment", new_scope["scope_id"],
              "2026-10-23T10:02:00+00:00", "2026-10-23T10:03:00+00:00")],
        )
        db.executemany(
            "INSERT INTO endpoint_receipts VALUES (?, ?)",
            [("old-assessment", "old-host"), ("new-assessment", "new-host")],
        )
        db.executemany(
            "INSERT INTO service_receipts VALUES (?, ?, '{\"state\":\"open\",\"service\":\"domain\"}')",
            [("old-assessment", "old-service"),
             ("new-assessment", "new-service")],
        )
        db.executemany(
            "INSERT INTO artifact_scope_assignments VALUES (?, 'observation', ?, ?)",
            [("old-assignment", old_scope["scope_id"], None),
             ("new-assignment", new_scope["scope_id"], "old-assignment")],
        )
        db.executemany(
            "INSERT INTO assessment_scope_assignment_links VALUES (?, ?)",
            [("old-assignment", "old-assessment"),
             ("new-assignment", "new-assessment")],
        )
    for scope in (old_scope, new_scope):
        create_special_device_roles(
            db_path, scope_id=scope["scope_id"], addresses=["10.0.0.53"],
            role_key="dns_server", custom_role="", device_label="DNS",
            actor="admin", reason="Scope-correction regression fixture",
        )

    result = get_mission_environment(db_path)
    networks = {item["scope_id"]: item for item in result["observed_networks"]}
    assert networks[old_scope["scope_id"]]["nmap_address_count"] == 0
    assert networks[new_scope["scope_id"]]["nmap_address_count"] == 1
    roles = {item["scope_id"]: item for item in result["special_device_roles"]}
    assert roles[old_scope["scope_id"]]["assessment"]["status"] == "insufficient_evidence"
    assert roles[new_scope["scope_id"]]["assessment"]["status"] == "some_supporting_evidence"


def test_special_role_assessment_uses_server_signals_without_recommending_devices(tmp_path):
    db_path = tmp_path / "analyzer.db"
    init_mission_environment_storage(db_path)
    scope = scope_record(db_path)
    with connect_database(db_path) as db:
        db.executescript(
            """
            CREATE TABLE endpoint_entities (
                entity_id TEXT PRIMARY KEY, scope_id TEXT, address TEXT
            );
            CREATE TABLE service_entities (
                entity_id TEXT PRIMARY KEY, host_id TEXT, protocol TEXT, port INTEGER
            );
            CREATE TABLE entity_assessments (
                assessment_id TEXT PRIMARY KEY, scope_id TEXT,
                artifact_observation_id TEXT, assessed_at TEXT, recorded_at TEXT
            );
            CREATE TABLE service_receipts (
                assessment_id TEXT, service_id TEXT, facts_json TEXT
            );
            CREATE TABLE arkime_imports (
                import_id TEXT PRIMARY KEY, scope_id TEXT, imported_at TEXT
            );
            CREATE TABLE arkime_session_receipts (
                receipt_id TEXT PRIMARY KEY, import_id TEXT, source_ip TEXT,
                source_port INTEGER, destination_ip TEXT, destination_port INTEGER,
                transport TEXT, applications_json TEXT, first_packet TEXT, last_packet TEXT
            );
            """
        )
        db.executemany(
            "INSERT INTO endpoint_entities VALUES (?, ?, ?)",
            [
                ("dns", scope["scope_id"], "10.0.0.53"),
                ("dns-alt", scope["scope_id"], "10.0.0.54"),
                ("dhcp-client", scope["scope_id"], "10.0.0.25"),
                ("tcp-dhcp", scope["scope_id"], "10.0.0.67"),
            ],
        )
        db.executemany(
            "INSERT INTO service_entities VALUES (?, ?, ?, ?)",
            [("dns-53", "dns", "udp", 53),
             ("dns-alt-53", "dns-alt", "udp", 53),
             ("client-68", "dhcp-client", "udp", 68),
             ("tcp-67", "tcp-dhcp", "tcp", 67)],
        )
        db.execute(
            "INSERT INTO entity_assessments VALUES ('assessment', ?, 'observation', ?, ?)",
            (scope["scope_id"], "2026-10-23T10:00:00+00:00", "2026-10-23T10:01:00+00:00"),
        )
        db.executemany(
            "INSERT INTO service_receipts VALUES ('assessment', ?, ?)",
            [("dns-53", '{"state":"open","service":"domain"}'),
             ("dns-alt-53", '{"state":"open","service":"domain"}'),
             ("client-68", '{"state":"open","service":"dhcpc"}'),
             ("tcp-67", '{"state":"open","service":"not-dhcp"}')],
        )
        db.execute(
            "INSERT INTO arkime_imports VALUES ('arkime', ?, '2026-10-23T10:02:00+00:00')",
            (scope["scope_id"],),
        )
        db.execute(
            "INSERT INTO arkime_imports VALUES ('arkime-copy', ?, '2026-10-23T10:03:00+00:00')",
            (scope["scope_id"],),
        )
        db.executemany(
            "INSERT INTO arkime_session_receipts VALUES (?, 'arkime', ?, ?, ?, ?, ?, '[]', ?, ?)",
            [
                ("r1", "10.0.0.20", 53000, "10.0.0.53", 53, "udp",
                 "2026-10-23T10:00:00+00:00", "2026-10-23T10:00:01+00:00"),
                ("r2", "10.0.0.1", 67, "10.0.0.25", 68, "udp",
                 "2026-10-23T10:00:00+00:00", "2026-10-23T10:00:01+00:00"),
            ],
        )
        db.execute(
            "INSERT INTO arkime_session_receipts VALUES (?, 'arkime-copy', ?, ?, ?, ?, ?, '[]', ?, ?)",
            ("r3", "10.0.0.20", 53000, "10.0.0.53", 53, "udp",
             "2026-10-23T10:00:00+00:00", "2026-10-23T10:00:01+00:00"),
        )
    create_special_device_roles(
        db_path, scope_id=scope["scope_id"], addresses=["10.0.0.53"],
        role_key="dns_server", custom_role="", device_label="DNS",
        actor="admin", reason="Mission partner DNS declaration",
    )
    create_special_device_roles(
        db_path, scope_id=scope["scope_id"], addresses=["10.0.0.25"],
        role_key="dhcp_server", custom_role="", device_label="Client under review",
        actor="admin", reason="Check client and server ambiguity",
    )
    create_special_device_roles(
        db_path, scope_id=scope["scope_id"], addresses=["10.0.0.67"],
        role_key="dhcp_server", custom_role="", device_label="TCP mismatch",
        actor="admin", reason="Ensure TCP port 67 is not DHCP server evidence",
    )
    create_special_device_roles(
        db_path, scope_id=scope["scope_id"], addresses=["10.0.0.53"],
        role_key="other", custom_role="Mission name resolver",
        device_label="Partner supplied name service", actor="admin",
        reason="Compare the partner identifier with retained evidence",
        declared_ports=["53/udp"], declared_services=["domain"],
    )

    roles = {
        (item["address"], item["role_key"]): item
        for item in get_mission_environment(db_path)["special_device_roles"]
    }
    assert roles[("10.0.0.53", "dns_server")]["assessment"]["status"] == "evidence_consistent"
    assert roles[("10.0.0.25", "dhcp_server")]["assessment"]["status"] == "insufficient_evidence"
    assert roles[("10.0.0.67", "dhcp_server")]["assessment"]["status"] == "insufficient_evidence"
    dns = roles[("10.0.0.53", "dns_server")]["assessment"]
    assert dns["service_matches"] == ["53/udp"]
    assert dns["traffic_matches"] == ["53/udp (destination)"]
    traffic = next(item for item in dns["traffic_signals"] if item["port"] == 53)
    assert traffic["session_count"] == 2
    assert traffic["observation_count"] == 2
    assert traffic["duplicate_observation_count"] == 0
    assert {item["import_id"] for item in traffic["observations"]} == {
        "arkime", "arkime-copy"
    }
    assert all(
        item["duplicate_of_retained_session"] is False
        for item in traffic["observations"]
    )
    service = dns["open_services"][0]
    assert service["observations"][0]["assessment_id"] == "assessment"
    assert service["observations"][0]["service_id"] == "dns-53"
    custom = roles[("10.0.0.53", "other")]
    assert custom["assessment"]["status"] == "evidence_consistent"
    assert custom["assessment"]["declared_port_service_matches"] == ["53/udp"]
    assert custom["assessment"]["declared_service_matches"] == ["domain"]
    possible = roles[("10.0.0.53", "dns_server")]["possible_matches"]
    assert [item["address"] for item in possible] == ["10.0.0.54"]
    assert possible[0]["service_matches"] == ["53/udp"]
    assert possible[0]["recognition_only"] is True
    assert possible[0]["role_assignment_effect"] == "none"
    assert "possible_alternates" not in roles[("10.0.0.53", "dns_server")]


def test_special_role_assessment_preserves_same_session_id_receipts_from_all_sensors(tmp_path):
    db_path = tmp_path / "analyzer.db"
    init_mission_environment_storage(db_path)
    scope = scope_record(db_path)
    with connect_database(db_path) as db:
        db.executescript(
            """
            CREATE TABLE arkime_imports (
                import_id TEXT PRIMARY KEY, scope_id TEXT, imported_at TEXT
            );
            CREATE TABLE arkime_session_receipts (
                receipt_id TEXT PRIMARY KEY, import_id TEXT, session_id TEXT,
                source_node TEXT, source_ip TEXT, source_port INTEGER,
                destination_ip TEXT, destination_port INTEGER, transport TEXT,
                applications_json TEXT, first_packet TEXT, last_packet TEXT
            );
            """
        )
        db.execute(
            "INSERT INTO arkime_imports VALUES ('shared-import', ?, ?)",
            (scope["scope_id"], "2026-10-23T12:00:00+00:00"),
        )
        db.executemany(
            """INSERT INTO arkime_session_receipts
                   VALUES (?, 'shared-import', 'shared-session', ?, ?, ?,
                           '10.0.0.53', 53, 'udp', ?, ?, ?)""",
            [
                (
                    "sensor-a-receipt", "sensor-a", "10.0.0.20", 53000,
                    '["dns"]', "2026-10-23T11:59:00+00:00",
                    "2026-10-23T11:59:01+00:00",
                ),
                (
                    "sensor-b-receipt", "sensor-b", "10.0.0.20", 53000,
                    '["dns"]', "2026-10-23T11:59:00+00:00",
                    "2026-10-23T11:59:01+00:00",
                ),
                (
                    "missing-node-conflict", None, "10.0.0.99", 54000,
                    '["dns", "different-capture"]',
                    "2026-10-23T11:58:00+00:00",
                    "2026-10-23T11:59:02+00:00",
                ),
            ],
        )
        db.execute(
            """INSERT INTO arkime_session_receipts
                   VALUES ('arkime-only-receipt', 'shared-import',
                           'arkime-only-session', 'sensor-a', '10.0.0.30', 53001,
                           '10.0.0.54', 53, 'udp', '[\"dns\"]', ?, ?)""",
            (
                "2026-10-23T11:59:03+00:00",
                "2026-10-23T11:59:04+00:00",
            ),
        )

    create_special_device_roles(
        db_path, scope_id=scope["scope_id"], addresses=["10.0.0.53"],
        role_key="dns_server", custom_role="", device_label="DNS",
        actor="admin", reason="Retained receipt identity regression",
    )

    environment = get_mission_environment(db_path)
    role = next(
        item for item in environment["special_device_roles"]
        if item["address"] == "10.0.0.53" and item["role_key"] == "dns_server"
    )
    traffic = next(
        item for item in role["assessment"]["traffic_signals"]
        if item["port"] == 53 and item["side"] == "destination"
    )
    assert traffic["session_count"] == 3
    assert traffic["observation_count"] == 3
    assert traffic["duplicate_observation_count"] == 0
    assert {item["receipt_id"] for item in traffic["observations"]} == {
        "sensor-a-receipt", "sensor-b-receipt", "missing-node-conflict",
    }
    assert all(
        item["session_id"] == "shared-session"
        and item["duplicate_of_retained_session"] is False
        for item in traffic["observations"]
    )
    dns_catalog = next(
        item for item in environment["special_role_catalog"]
        if item["scope_id"] == scope["scope_id"]
        and item["role_key"] == "dns_server"
    )
    arkime_only = next(
        item for item in dns_catalog["possible_matches"]
        if item["address"] == "10.0.0.54"
    )
    assert arkime_only["scope_label"] == scope["label"]
    assert arkime_only["supporting_source_count"] == 1
    assert arkime_only["supporting_sources_truncated"] is False
    assert arkime_only["supporting_sources"] == [{
        "source_kind": "Arkime",
        "label": "Retained 53/udp (destination) session receipt",
        "source_url": "/arkime?analyze=shared-import#arkimeTrafficAnalysis",
        "observed_at": "2026-10-23T11:59:04+00:00",
        "import_id": "shared-import",
        "receipt_id": "arkime-only-receipt",
        "session_id": "arkime-only-session",
    }]


def test_common_role_catalog_is_scope_bound_distinct_and_declaration_only_when_unsupported(tmp_path):
    db_path = tmp_path / "analyzer.db"
    init_mission_environment_storage(db_path)
    first = scope_record(db_path)
    second = create_network_scope(
        db_path, label="Second mission", description="Overlapping address fixture",
        created_by="admin", reason="Catalog scope regression",
    )
    with connect_database(db_path) as db:
        db.executescript(
            """
            CREATE TABLE endpoint_entities (
                entity_id TEXT PRIMARY KEY, scope_id TEXT, address TEXT
            );
            CREATE TABLE service_entities (
                entity_id TEXT PRIMARY KEY, host_id TEXT, protocol TEXT, port INTEGER
            );
            CREATE TABLE entity_assessments (
                assessment_id TEXT PRIMARY KEY, scope_id TEXT,
                artifact_observation_id TEXT, assessed_at TEXT, recorded_at TEXT
            );
            CREATE TABLE service_receipts (
                assessment_id TEXT, service_id TEXT, facts_json TEXT
            );
            """
        )
        db.executemany(
            "INSERT INTO endpoint_entities VALUES (?, ?, '10.0.0.53')",
            [("first-host", first["scope_id"]), ("second-host", second["scope_id"])],
        )
        db.executemany(
            "INSERT INTO service_entities VALUES (?, ?, ?, ?)",
            [
                ("first-dns", "first-host", "udp", 53),
                ("second-dns", "second-host", "udp", 53),
                ("second-snmp-agent", "second-host", "udp", 161),
            ],
        )
        db.executemany(
            "INSERT INTO entity_assessments VALUES (?, ?, ?, ?, ?)",
            [
                ("first-a", first["scope_id"], "first-o", "2026-10-23T12:00:00+00:00", "2026-10-23T12:01:00+00:00"),
                ("second-a", second["scope_id"], "second-o", "2026-10-23T12:00:00+00:00", "2026-10-23T12:01:00+00:00"),
            ],
        )
        db.executemany(
            "INSERT INTO service_receipts VALUES (?, ?, '{\"state\":\"open\",\"service\":\"domain\"}')",
            [
                ("first-a", "first-dns"),
                ("second-a", "second-dns"),
                ("second-a", "second-dns"),
                ("second-a", "second-snmp-agent"),
            ],
        )
    create_special_device_roles(
        db_path, scope_id=first["scope_id"], addresses=["10.0.0.53"],
        role_key="dns_server", custom_role="", device_label="Declared DNS",
        actor="admin", reason="Mission partner declaration",
    )

    result = get_mission_environment(db_path)
    catalog = {
        (item["scope_id"], item["role_key"]): item
        for item in result["special_role_catalog"]
    }
    assert catalog[(first["scope_id"], "dns_server")]["declared_address_count"] == 1
    assert catalog[(first["scope_id"], "dns_server")]["possible_match_count"] == 0
    second_dns = catalog[(second["scope_id"], "dns_server")]
    assert second_dns["declared_address_count"] == 0
    assert second_dns["possible_match_count"] == 1
    assert [item["address"] for item in second_dns["possible_matches"]] == ["10.0.0.53"]
    assert second_dns["possible_matches"][0]["scope_id"] == second["scope_id"]
    unsupported = catalog[(second["scope_id"], "backup_server")]
    assert unsupported["assessment_support"] == "declaration_only"
    assert unsupported["possible_match_count"] == 0
    assert unsupported["possible_matches"] == []
    snmp_agent = catalog[(second["scope_id"], "network_management_server")]
    assert snmp_agent["assessment_support"] == "declaration_only"
    assert snmp_agent["typical_ports"] == []
    assert "Generic SNMP agent ports do not reliably identify" in snmp_agent["description"]
    assert snmp_agent["possible_match_count"] == 0
    assert snmp_agent["possible_matches"] == []


def test_role_supporting_sources_are_selected_before_display_limits():
    evidence = {
        "open_services": {},
        "traffic_ports": {},
        "config_sources": {},
        "latest_evidence_at": "2026-10-23T13:00:00+00:00",
    }
    for offset in range(25):
        port = 1 + offset
        evidence["open_services"][("tcp", port)] = {
            "protocol": "tcp", "port": port, "service": "unrelated",
            "product": "", "source_url": "/analysis#networkChangesPanel",
            "observed_at": "2026-10-23T12:00:00+00:00",
            "observations": [{
                "assessment_id": f"unrelated-service-{offset}",
                "service_id": f"service-{offset}",
                "artifact_observation_id": f"observation-{offset}",
                "assignment_id": None,
                "source_url": "/analysis#networkChangesPanel",
                "observed_at": "2026-10-23T12:00:00+00:00",
            }],
        }
        evidence["traffic_ports"][("tcp", port, "destination")] = {
            "transport": "tcp", "port": port, "side": "destination",
            "session_count": 1, "observation_count": 1,
            "duplicate_observation_count": 0, "applications": set(),
            "source_url": f"/arkime?analyze=unrelated-{offset}#arkimeTrafficAnalysis",
            "first_packet": "2026-10-23T12:00:00+00:00",
            "last_packet": "2026-10-23T12:00:01+00:00",
            "observations": [{
                "import_id": f"unrelated-{offset}",
                "receipt_id": f"unrelated-receipt-{offset}",
                "session_id": f"unrelated-session-{offset}",
                "source_url": f"/arkime?analyze=unrelated-{offset}#arkimeTrafficAnalysis",
                "first_packet": "2026-10-23T12:00:00+00:00",
                "last_packet": "2026-10-23T12:00:01+00:00",
                "duplicate_of_retained_session": False,
            }],
        }
    evidence["open_services"][("udp", 53)] = {
        "protocol": "udp", "port": 53, "service": "domain", "product": "",
        "source_url": "/api/foundation-evidence/exact-dns-service",
        "observed_at": "2026-10-23T13:00:00+00:00",
        "observations": [{
            "assessment_id": "dns-assessment", "service_id": "dns-service",
            "artifact_observation_id": "dns-observation",
            "assignment_id": "dns-assignment",
            "source_url": "/api/foundation-evidence/exact-dns-service",
            "observed_at": "2026-10-23T13:00:00+00:00",
        }],
    }
    evidence["traffic_ports"][("udp", 53, "destination")] = {
        "transport": "udp", "port": 53, "side": "destination",
        "session_count": 1, "observation_count": 1,
        "duplicate_observation_count": 0, "applications": {"dns"},
        "source_url": "/arkime?analyze=dns-import#arkimeTrafficAnalysis",
        "first_packet": "2026-10-23T12:59:59+00:00",
        "last_packet": "2026-10-23T13:00:00+00:00",
        "observations": [{
            "import_id": "dns-import", "receipt_id": "dns-receipt",
            "session_id": "dns-session",
            "source_url": "/arkime?analyze=dns-import#arkimeTrafficAnalysis",
            "first_packet": "2026-10-23T12:59:59+00:00",
            "last_packet": "2026-10-23T13:00:00+00:00",
            "duplicate_of_retained_session": False,
        }],
    }
    draft = {
        "role_key": "dns_server", "declared_ports": [],
        "declared_services": [], "version": 0,
    }

    assessment = mission_environment._assess_special_role(draft, evidence)
    sources, count = mission_environment._special_role_supporting_sources(
        "dns_server", assessment, evidence,
    )

    assert assessment["status"] == "evidence_consistent"
    assert assessment["service_matches"] == ["53/udp"]
    assert assessment["traffic_matches"] == ["53/udp (destination)"]
    assert all(item["port"] != 53 for item in assessment["open_services"])
    assert all(item["port"] != 53 for item in assessment["traffic_signals"])
    assert count == 2
    assert {item["source_kind"] for item in sources} == {"Nmap", "Arkime"}
    assert {item["source_url"] for item in sources} == {
        "/api/foundation-evidence/exact-dns-service",
        "/arkime?analyze=dns-import#arkimeTrafficAnalysis",
    }


def test_map_marks_declared_roles_and_preserves_scope_when_address_is_reused(tmp_path):
    db_path = tmp_path / "analyzer.db"
    init_mission_environment_storage(db_path)
    first = scope_record(db_path)
    second = create_network_scope(
        db_path, label="Partner", description="Separate reused address context",
        created_by="admin", reason="Second scope",
    )
    for scope in (first, second):
        create_special_device_roles(
            db_path, scope_id=scope["scope_id"], addresses=["10.0.0.53"],
            role_key="dns_server", custom_role="", device_label=f"{scope['label']} DNS",
            actor="admin", reason="Scope-specific DNS declaration",
        )
    nodes = {}
    node = ensure_ip_node(nodes, "10.0.0.53")
    node["scope_id"] = first["scope_id"]
    node["scope_ids"] = [first["scope_id"]]

    assert annotate_mission_partner_roles(nodes, db_path) == 2
    observed = nodes["ip:10.0.0.53"]
    assert {item["scope_label"] for item in observed["mission_special_roles"]} == {
        "Engineering"
    }
    separate = nodes[f"mission:{second['scope_id']}:10.0.0.53"]
    assert separate["declaration_only"] is True
    assert separate["scope_id"] == second["scope_id"]
    assert {item["scope_label"] for item in separate["mission_special_roles"]} == {
        "Partner"
    }
    assert all(item["source_url"].endswith("#specialDeviceRolesPanel")
               for item in observed["mission_special_roles"] + separate["mission_special_roles"])


def test_mission_environment_read_is_one_sqlite_snapshot(tmp_path, monkeypatch):
    db_path = tmp_path / "analyzer.db"
    init_mission_environment_storage(db_path)
    configure_database(db_path)
    scope = scope_record(db_path)
    original = mission_environment._observed_environment_rows
    wrote = False

    def interleaved_writer(db, *, scopes, tables):
        nonlocal wrote
        if not wrote:
            wrote = True
            create_special_device_roles(
                db_path, scope_id=scope["scope_id"], addresses=["10.0.0.53"],
                role_key="dns_server", custom_role="", device_label="DNS",
                actor="admin", reason="Concurrent role declaration",
            )
        return original(db, scopes=scopes, tables=tables)

    monkeypatch.setattr(
        mission_environment, "_observed_environment_rows", interleaved_writer
    )
    first = get_mission_environment(db_path)
    second = get_mission_environment(db_path)

    assert first["special_device_roles"] == []
    assert [item["address"] for item in second["special_device_roles"]] == ["10.0.0.53"]
