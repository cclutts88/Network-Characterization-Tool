from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

from fastapi.testclient import TestClient

from app.artifacts import get_artifact_observation, register_artifact_bytes
from app.database import connect_database
from app.network_scopes import archive_network_scope, create_network_scope


XML = b'''<nmaprun scanner="nmap" version="7.95" args="nmap -n -sS 192.0.2.10" start="100">
<scaninfo type="syn" protocol="tcp" numservices="1" services="443"/>
<host starttime="101" endtime="109"><status state="up" reason="syn-ack"/>
<address addr="192.0.2.10" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port>
</ports></host><runstats><finished time="110" timestr="done"/><hosts up="1" down="0" total="1"/></runstats></nmaprun>'''


def configure(monkeypatch, tmp_path, *, role=None, username="operator"):
    import app.main as main

    db = tmp_path / "nct.db"
    monkeypatch.setattr(main, "DB_PATH", db)
    monkeypatch.setattr(main, "auth_enabled", lambda: role is not None)
    if role is not None:
        monkeypatch.setattr(
            main, "session_identity",
            lambda *args: {"username": username, "display_name": username, "role": role},
        )
    return main, db


def upload(client, name="evidence.xml"):
    response = client.post(
        "/api/import", files={"file": (name, XML, "application/xml")},
    )
    assert response.status_code == 200
    return response.json()


def make_scope(db, label="Lab"):
    return create_network_scope(db, label=label, created_by="admin")


def assignment_payload(destination, reason="Confirmed whole-file context"):
    return {
        "scope_id": destination["scope_id"],
        "reason": reason,
        "whole_artifact_confirmed": True,
    }


def test_local_operator_can_assign_then_process_with_recoverable_status(
    tmp_path, monkeypatch,
):
    main, db = configure(monkeypatch, tmp_path)
    destination = make_scope(db)
    with TestClient(main.app) as client:
        imported = upload(client)
        observation_id = imported["artifact_observation_id"]
        unassigned = client.get(
            f"/api/nmap-observations/{observation_id}/scope-assignment"
        )
        assigned = client.post(
            f"/api/nmap-observations/{observation_id}/scope-assignment",
            json=assignment_payload(destination),
        )
        assignment_id = assigned.json()["current_assignment_id"]
        refreshed = client.get(
            f"/api/nmap-observations/{observation_id}/scope-assignment"
        )
        processed = client.post(
            f"/api/nmap-scope-assignments/{assignment_id}/process"
        )
        replay = client.post(
            f"/api/nmap-scope-assignments/{assignment_id}/process"
        )

    assert unassigned.status_code == 200
    assert unassigned.json()["assignment_state"] == "unassigned"
    assert assigned.status_code == 201
    assert assigned.json()["assignment_state"] == "assigned_pending"
    assert assigned.json()["current_assignment"]["actor"] == "local-operator"
    assert refreshed.json()["current_assignment_id"] == assignment_id
    assert processed.status_code == 200
    assert processed.json()["status"]["assignment_state"] == "foundation_complete"
    assert processed.json()["status"]["current_views_changed"] is False
    assert replay.json()["processing"]["completed_replay"] is True


def test_status_and_recent_list_are_observation_level_and_hide_filesystem_paths(
    tmp_path, monkeypatch,
):
    main, db = configure(monkeypatch, tmp_path)
    destination = make_scope(db)
    with TestClient(main.app) as client:
        first = upload(client, "first.xml")
        second = upload(client, "second.xml")
        assert first["sha256"] == second["sha256"]
        for item in (first, second):
            response = client.post(
                f"/api/nmap-observations/{item['artifact_observation_id']}/scope-assignment",
                json=assignment_payload(destination),
            )
            assert response.status_code == 201
        listed = client.get("/api/nmap-observations/assignments").json()

    matching = [item for item in listed if item["sha256"] == first["sha256"]]
    assert len(matching) == 2
    assert len({item["observation_id"] for item in matching}) == 2
    assert {item["original_filename"] for item in matching} == {"first.xml", "second.xml"}
    assert "canonical_path" not in str(listed)


def test_scope_options_are_read_only_minimal_and_exclude_archived(tmp_path, monkeypatch):
    main, db = configure(monkeypatch, tmp_path)
    active = make_scope(db, "Active")
    archived = make_scope(db, "Archived")
    archive_network_scope(
        db, archived["scope_id"], expected_version=1,
        archived_by="admin", reason="No longer eligible",
    )
    with TestClient(main.app) as client:
        response = client.get("/api/nmap-assignment-scopes")
    assert response.status_code == 200
    assert response.json() == [{
        "scope_id": active["scope_id"], "label": "Active",
        "description": "", "version": 1,
    }]


def test_assignment_requires_manual_nmap_observation_and_explicit_confirmation(
    tmp_path, monkeypatch,
):
    main, db = configure(monkeypatch, tmp_path)
    destination = make_scope(db)
    other = register_artifact_bytes(
        db_path=db, content=b"device evidence", source_kind="device_config_upload",
        source_ref="upload:device", actor="tester",
    )
    with TestClient(main.app) as client:
        ineligible = client.post(
            f"/api/nmap-observations/{other['observation_id']}/scope-assignment",
            json=assignment_payload(destination),
        )
        imported = upload(client)
        unconfirmed = client.post(
            f"/api/nmap-observations/{imported['artifact_observation_id']}/scope-assignment",
            json={**assignment_payload(destination), "whole_artifact_confirmed": False},
        )
    assert ineligible.status_code == 422
    assert "manual Nmap" in ineligible.json()["detail"]
    assert unconfirmed.status_code == 422
    assert "confirmation" in unconfirmed.json()["detail"]


def test_body_cannot_supply_actor_or_processing_parser(tmp_path, monkeypatch):
    main, db = configure(monkeypatch, tmp_path, role="analyst", username="alice")
    destination = make_scope(db)
    with TestClient(main.app) as client:
        imported = upload(client)
        observation_id = imported["artifact_observation_id"]
        rejected = client.post(
            f"/api/nmap-observations/{observation_id}/scope-assignment",
            json={**assignment_payload(destination), "actor": "mallory"},
        )
        assigned = client.post(
            f"/api/nmap-observations/{observation_id}/scope-assignment",
            json=assignment_payload(destination),
        )
        parser_rejected = client.post(
            f"/api/nmap-scope-assignments/{assigned.json()['current_assignment_id']}/process",
            json={"parser_version": "caller-controlled"},
        )
    assert rejected.status_code == 422
    assert assigned.json()["current_assignment"]["actor"] == "alice"
    # This endpoint has no request body contract; supplied parser data cannot affect it.
    assert parser_rejected.status_code == 200
    assert parser_rejected.json()["processing"]["parser_version"] == "nmap-endpoints:1"


def test_viewer_reads_status_but_cannot_assign_process_or_correct(tmp_path, monkeypatch):
    main, db = configure(monkeypatch, tmp_path, role="viewer", username="viewer")
    destination = make_scope(db)
    with TestClient(main.app) as client:
        # Register directly because a viewer cannot use the existing mutation route.
        item = register_artifact_bytes(
            db_path=db, content=XML, source_kind="nmap_import",
            source_ref="upload:viewer-test", original_filename="viewer.xml",
            actor="fixture",
        )
        status = client.get(
            f"/api/nmap-observations/{item['observation_id']}/scope-assignment"
        )
        assigned = client.post(
            f"/api/nmap-observations/{item['observation_id']}/scope-assignment",
            json=assignment_payload(destination),
        )
    assert status.status_code == 200
    assert assigned.status_code == 403


def test_analyst_and_admin_can_mutate_but_cross_origin_is_blocked(tmp_path, monkeypatch):
    for role in ("analyst", "admin"):
        role_dir = tmp_path / role
        role_dir.mkdir()
        main, db = configure(monkeypatch, role_dir, role=role, username=role)
        destination = make_scope(db)
        with TestClient(main.app) as client:
            imported = upload(client)
            response = client.post(
                f"/api/nmap-observations/{imported['artifact_observation_id']}/scope-assignment",
                json=assignment_payload(destination),
            )
        assert response.status_code == 201
        assert response.json()["current_assignment"]["actor"] == role

    blocked_dir = tmp_path / "blocked"
    blocked_dir.mkdir()
    main, db = configure(monkeypatch, blocked_dir, role="analyst")
    destination = make_scope(db)
    with TestClient(main.app) as client:
        imported = upload(client)
        blocked = client.post(
            f"/api/nmap-observations/{imported['artifact_observation_id']}/scope-assignment",
            json=assignment_payload(destination),
            headers={"Origin": "https://outside.example"},
        )
    assert blocked.status_code == 403


def test_failed_processing_retains_assignment_without_partial_foundation_rows(
    tmp_path, monkeypatch,
):
    main, db = configure(monkeypatch, tmp_path)
    destination = make_scope(db)
    with TestClient(main.app) as client:
        imported = upload(client)
        observation_id = imported["artifact_observation_id"]
        assigned = client.post(
            f"/api/nmap-observations/{observation_id}/scope-assignment",
            json=assignment_payload(destination),
        ).json()
        assignment_id = assigned["current_assignment_id"]
        observation = get_artifact_observation(db, observation_id)
        canonical = Path(observation["canonical_path"])
        original = canonical.read_bytes()
        canonical.write_bytes(b"corrupted")
        failed = client.post(
            f"/api/nmap-scope-assignments/{assignment_id}/process"
        )
        pending = client.get(
            f"/api/nmap-observations/{observation_id}/scope-assignment"
        )
        with connect_database(db) as connection:
            assert connection.execute(
                "SELECT COUNT(*) FROM entity_assessments"
            ).fetchone()[0] == 0
            assert connection.execute(
                "SELECT COUNT(*) FROM assessment_scope_assignment_links"
            ).fetchone()[0] == 0
        canonical.write_bytes(original)
        retried = client.post(
            f"/api/nmap-scope-assignments/{assignment_id}/process"
        )

    assert failed.status_code == 422
    assert pending.json()["assignment_state"] == "assigned_pending"
    with connect_database(db) as connection:
        assert connection.execute("SELECT COUNT(*) FROM entity_assessments").fetchone()[0] == 1
        assert connection.execute(
            "SELECT COUNT(*) FROM assessment_scope_assignment_links"
        ).fetchone()[0] == 1
    assert retried.status_code == 200
    assert retried.json()["status"]["assignment_state"] == "foundation_complete"


def test_correction_is_append_only_and_requires_separate_processing(tmp_path, monkeypatch):
    main, db = configure(monkeypatch, tmp_path)
    first_scope = make_scope(db, "Lab")
    second_scope = make_scope(db, "Production")
    with TestClient(main.app) as client:
        imported = upload(client)
        observation_id = imported["artifact_observation_id"]
        first = client.post(
            f"/api/nmap-observations/{observation_id}/scope-assignment",
            json=assignment_payload(first_scope),
        ).json()
        first_id = first["current_assignment_id"]
        client.post(f"/api/nmap-scope-assignments/{first_id}/process")
        corrected = client.post(
            f"/api/nmap-scope-assignments/{first_id}/corrections",
            json={
                "destination_scope_id": second_scope["scope_id"],
                "reason": "Confirmed production context",
                "whole_artifact_confirmed": True,
            },
        )
        second_id = corrected.json()["current_assignment_id"]
        completed = client.post(
            f"/api/nmap-scope-assignments/{second_id}/process"
        )

    assert corrected.status_code == 201
    assert corrected.json()["assignment_state"] == "correction_pending"
    assert len(corrected.json()["assignments"]) == 2
    assert corrected.json()["assignments"][0]["processing_complete"] is True
    assert completed.json()["status"]["assignment_state"] == "foundation_complete"
    assert len(completed.json()["status"]["assignments"]) == 2


def test_competing_route_corrections_leave_one_current_history_entry(
    tmp_path, monkeypatch,
):
    main, db = configure(monkeypatch, tmp_path)
    source = make_scope(db, "Source")
    destinations = [make_scope(db, "Red"), make_scope(db, "Blue")]
    with TestClient(main.app) as client:
        imported = upload(client)
        observation_id = imported["artifact_observation_id"]
        root = client.post(
            f"/api/nmap-observations/{observation_id}/scope-assignment",
            json=assignment_payload(source),
        ).json()["current_assignment_id"]

        def correct(destination):
            return client.post(
                f"/api/nmap-scope-assignments/{root}/corrections",
                json={
                    "destination_scope_id": destination["scope_id"],
                    "reason": "Concurrent reviewed correction",
                    "whole_artifact_confirmed": True,
                },
            )

        with ThreadPoolExecutor(max_workers=2) as pool:
            responses = list(pool.map(correct, destinations))
        status = client.get(
            f"/api/nmap-observations/{observation_id}/scope-assignment"
        ).json()

    assert sorted(response.status_code for response in responses) == [201, 409]
    assert len(status["assignments"]) == 2
    assert sum(item["current"] for item in status["assignments"]) == 1
    assert status["assignment_state"] == "correction_pending"


def test_assignment_does_not_change_legacy_import_analysis(tmp_path, monkeypatch):
    main, db = configure(monkeypatch, tmp_path)
    destination = make_scope(db)
    with TestClient(main.app) as client:
        imported = upload(client)
        with connect_database(db) as connection:
            before = connection.execute(
                "SELECT analysis_json, metadata_json FROM imports WHERE sha256 = ?",
                (imported["sha256"],),
            ).fetchone()
        assigned = client.post(
            f"/api/nmap-observations/{imported['artifact_observation_id']}/scope-assignment",
            json=assignment_payload(destination),
        ).json()
        client.post(
            f"/api/nmap-scope-assignments/{assigned['current_assignment_id']}/process"
        )
        with connect_database(db) as connection:
            after = connection.execute(
                "SELECT analysis_json, metadata_json FROM imports WHERE sha256 = ?",
                (imported["sha256"],),
            ).fetchone()
    assert before == after


def test_assignment_routes_and_analysis_page_require_authentication(
    tmp_path, monkeypatch,
):
    import app.main as main

    monkeypatch.setattr(main, "DB_PATH", tmp_path / "nct.db")
    monkeypatch.setattr(main, "auth_enabled", lambda: True)
    monkeypatch.setattr(main, "session_identity", lambda *args: None)
    with TestClient(main.app, follow_redirects=False) as client:
        api_response = client.get("/api/nmap-observations/assignments")
        page_response = client.get("/analysis#xmlImport")

    assert api_response.status_code == 401
    assert api_response.json()["detail"] == "Authentication required"
    assert page_response.status_code == 303
    assert page_response.headers["location"] == "/login?next=/analysis"
