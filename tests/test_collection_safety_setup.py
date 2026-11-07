from pathlib import Path
import subprocess
import sys
import threading
import time

from fastapi.testclient import TestClient
import pytest


def client_for(tmp_path, monkeypatch):
    import app.main as main
    import app.poc as poc
    import app.device_configs as device_configs

    db_path = tmp_path / "analyzer.db"
    monkeypatch.setattr(main, "DB_PATH", db_path)
    monkeypatch.setattr(poc, "DB_PATH", db_path)
    monkeypatch.setattr(device_configs, "DB_PATH", db_path)
    monkeypatch.setattr(main, "auth_enabled", lambda: False)
    return TestClient(main.app)


def reviewed_setup(client, *, label="Home lab"):
    scope = client.post("/api/network-scopes", json={"label": label}).json()
    response = client.post(
        "/api/collection-safety-setup/reviews",
        json={
            "scope_id": scope["scope_id"],
            "expected_scope_version": scope["version"],
            "expected_no_strike_revision": 0,
            "empty_no_strike_reviewed": True,
            "reason": "Initial setup review",
        },
    )
    assert response.status_code == 201, response.text
    return scope


def test_manual_scan_preview_uses_the_reviewed_active_collection_scope(
    tmp_path, monkeypatch
):
    with client_for(tmp_path, monkeypatch) as client:
        scope = reviewed_setup(client, label="Isolated demo")
        preview = client.post(
            "/api/preview",
            json={
                "name": "Manual localhost preview",
                "created_by": "local-operator",
                "profile": "Custom",
                "scan_options": {
                    "protocol": "tcp",
                    "tcp_scope": "common",
                    "discovery_mode": "fping",
                },
                "terrain": [{"name": "Manual", "targets": ["127.0.0.1/32"]}],
                "manual_targets": ["127.0.0.1/32"],
                "reviewed_mission_scopes": [
                    {"scope_id": scope["scope_id"], "version": 0}
                ],
                "no_strike_mode": "none",
                "no_strike": [],
            },
        )

    assert preview.status_code == 200, preview.text
    mission_review = preview.json()["mission_environment_review"]
    assert mission_review["decision"] == "unknown"
    assert mission_review["manual_targets_unknown"] is False
    assert mission_review["scopes"][0]["scope_id"] == scope["scope_id"]


def test_scope_and_safety_review_is_bound_to_exact_revisions(tmp_path, monkeypatch):
    with client_for(tmp_path, monkeypatch) as client:
        page = client.get("/settings/scope-safety")
        assert page.status_code == 200
        assert page.history
        assert page.url.path == "/settings/mission-environment"
        assert page.url.fragment == "noStrikePanel"
        assert "Global No-Strike and collection review" in page.text
        assert "10.0.0.0/8" in page.text

        scope = client.post(
            "/api/network-scopes", json={"label": "Home lab"}
        ).json()
        initial = client.get("/api/collection-safety-setup").json()
        assert initial["ready"] is False
        assert "have not been reviewed" in initial["missing_checks"][0]

        missing_confirmation = client.post(
            "/api/collection-safety-setup/reviews",
            json={
                "scope_id": scope["scope_id"],
                "expected_scope_version": 1,
                "expected_no_strike_revision": 0,
                "empty_no_strike_reviewed": False,
                "reason": "Initial setup",
            },
        )
        assert missing_confirmation.status_code == 422

        reviewed = client.post(
            "/api/collection-safety-setup/reviews",
            json={
                "scope_id": scope["scope_id"],
                "expected_scope_version": 1,
                "expected_no_strike_revision": 0,
                "empty_no_strike_reviewed": True,
                "reason": "No exclusions currently required",
            },
        )
        assert reviewed.status_code == 201
        assert reviewed.json()["ready"] is True
        assert reviewed.json()["review"]["reviewed_by"] == "local-operator"

        changed = client.post(
            "/api/safety/no-strike",
            json={"entries": ["10.0.0.0/8"], "changed_by": "ignored-client-value"},
        )
        assert changed.status_code == 201
        stale = client.get("/api/collection-safety-setup").json()
        assert stale["ready"] is False
        assert any(
            "Global No-Strike list changed" in item
            for item in stale["missing_checks"]
        )

        refreshed = client.post(
            "/api/collection-safety-setup/reviews",
            json={
                "scope_id": scope["scope_id"],
                "expected_scope_version": 1,
                "expected_no_strike_revision": changed.json()["revision"],
                "empty_no_strike_reviewed": False,
                "reason": "Reviewed protected private range",
            },
        )
        assert refreshed.status_code == 201
        assert refreshed.json()["ready"] is True
        assert refreshed.json()["review"]["revision"] == 2

        client.patch(
            f"/api/network-scopes/{scope['scope_id']}",
            json={
                "expected_version": 1,
                "label": "Home lab updated",
                "reason": "Clarify environment",
            },
        )
        stale_scope = client.get("/api/collection-safety-setup").json()
        assert stale_scope["ready"] is False
        assert any("Network Scope changed" in item for item in stale_scope["missing_checks"])


def test_new_saved_network_uses_reviewed_scope_with_optional_initial_note(
    tmp_path, monkeypatch,
):
    with client_for(tmp_path, monkeypatch) as client:
        scope = reviewed_setup(client, label="Home lab")
        setup = client.get("/api/collection-safety-setup").json()
        created = client.post(
            "/api/saved-networks/contextual-save",
            json={
                "name": "Operations",
                "cidr": "10.44.0.0/24",
                "scope_id": scope["scope_id"],
                "scope_reason": "",
                "use_reviewed_scope_default": True,
                "expected_collection_review_revision": setup["review"]["revision"],
                "expected_scope_version": scope["version"],
            },
        )
        assert created.status_code == 200, created.text
        record = created.json()
        history = client.get(
            f"/api/saved-networks/{record['saved_network_id']}/scope-history"
        ).json()

    association = record["network_scope_association"]
    assert association["scope_id"] == scope["scope_id"]
    assert association["revision"] == 1
    assert len(history) == 1
    assert history[0]["actor"] == "local-operator"
    assert history[0]["reason"].startswith("NCT generated: Initial association")
    assert scope["scope_id"] in history[0]["reason"]
    assert "setup review r1" in history[0]["reason"]


def test_reviewed_scope_default_rejects_stale_or_different_context_atomically(
    tmp_path, monkeypatch,
):
    with client_for(tmp_path, monkeypatch) as client:
        reviewed = reviewed_setup(client, label="Reviewed")
        other = client.post("/api/network-scopes", json={"label": "Other"}).json()
        mismatch = client.post(
            "/api/saved-networks/contextual-save",
            json={
                "name": "Wrong context",
                "cidr": "10.45.0.0/24",
                "scope_id": other["scope_id"],
                "use_reviewed_scope_default": True,
                "expected_collection_review_revision": 1,
                "expected_scope_version": other["version"],
            },
        )
        assert mismatch.status_code == 409
        assert client.get("/api/saved-networks").json() == []

        changed = client.patch(
            f"/api/network-scopes/{reviewed['scope_id']}",
            json={
                "expected_version": reviewed["version"],
                "label": "Reviewed after change",
                "reason": "Exercise boundary changed",
            },
        )
        assert changed.status_code == 200
        stale = client.post(
            "/api/saved-networks/contextual-save",
            json={
                "name": "Stale context",
                "cidr": "10.46.0.0/24",
                "scope_id": reviewed["scope_id"],
                "use_reviewed_scope_default": True,
                "expected_collection_review_revision": 1,
                "expected_scope_version": reviewed["version"],
            },
        )
        assert stale.status_code == 409
        assert client.get("/api/saved-networks").json() == []


def test_reviewed_scope_default_rejects_changed_review_revision(tmp_path, monkeypatch):
    with client_for(tmp_path, monkeypatch) as client:
        reviewed = reviewed_setup(client, label="Reviewed")
        no_strike = client.post(
            "/api/safety/no-strike",
            json={"entries": ["192.0.2.0/24"], "changed_by": "ignored"},
        ).json()
        refreshed = client.post(
            "/api/collection-safety-setup/reviews",
            json={
                "scope_id": reviewed["scope_id"],
                "expected_scope_version": reviewed["version"],
                "expected_no_strike_revision": no_strike["revision"],
                "empty_no_strike_reviewed": False,
                "reason": "Reviewed revised exclusions",
            },
        )
        assert refreshed.status_code == 201
        stale = client.post(
            "/api/saved-networks/contextual-save",
            json={
                "name": "Stale review",
                "cidr": "10.47.0.0/24",
                "scope_id": reviewed["scope_id"],
                "use_reviewed_scope_default": True,
                "expected_collection_review_revision": 1,
                "expected_scope_version": reviewed["version"],
            },
        )
        assert stale.status_code == 409
        assert "changed while this Saved Network" in stale.json()["detail"]
        assert client.get("/api/saved-networks").json() == []


def test_reviewed_scope_default_commits_before_waiting_review_change(
    tmp_path, monkeypatch,
):
    import app.poc as poc
    from app.collection_safety_setup import record_collection_safety_review
    from app.saved_network_scope_associations import list_saved_network_scope_history

    db_path = tmp_path / "analyzer.db"
    with client_for(tmp_path, monkeypatch) as client:
        reviewed = reviewed_setup(client, label="Serializable")

    status_read = threading.Event()
    release_save = threading.Event()
    review_started = threading.Event()
    save_result: dict = {}
    failures: list[BaseException] = []
    original_require = poc.require_collection_safety_ready_on_connection

    def pause_after_status(db, *, expected_scope_id=None):
        status = original_require(db, expected_scope_id=expected_scope_id)
        status_read.set()
        assert release_save.wait(timeout=5)
        return status

    monkeypatch.setattr(
        poc, "require_collection_safety_ready_on_connection", pause_after_status,
    )

    def save_network():
        try:
            save_result.update(
                poc.save_saved_network_with_context(
                    poc.SavedNetworkContextSave(
                        name="Serializable network",
                        cidr="10.48.0.0/24",
                        scope_id=reviewed["scope_id"],
                        use_reviewed_scope_default=True,
                        expected_collection_review_revision=1,
                        expected_scope_version=reviewed["version"],
                    ),
                    actor="analyst",
                    db_path=db_path,
                )
            )
        except BaseException as exc:  # pragma: no cover - asserted below
            failures.append(exc)

    def refresh_review():
        try:
            review_started.set()
            record_collection_safety_review(
                db_path,
                scope_id=reviewed["scope_id"],
                expected_scope_version=reviewed["version"],
                expected_no_strike_revision=0,
                empty_no_strike_reviewed=True,
                reviewed_by="admin",
                reason="Concurrent review refresh",
            )
        except BaseException as exc:  # pragma: no cover - asserted below
            failures.append(exc)

    save_thread = threading.Thread(target=save_network)
    review_thread = threading.Thread(target=refresh_review)
    save_thread.start()
    assert status_read.wait(timeout=5)
    review_thread.start()
    assert review_started.wait(timeout=5)
    time.sleep(0.1)
    assert review_thread.is_alive()
    release_save.set()
    save_thread.join(timeout=5)
    review_thread.join(timeout=5)

    assert not failures
    assert not save_thread.is_alive()
    assert not review_thread.is_alive()
    history = list_saved_network_scope_history(
        db_path, save_result["saved_network_id"],
    )
    assert len(history) == 1
    assert "setup review r1" in history[0]["reason"]


def test_waiting_reviewed_scope_default_rechecks_after_review_commits(
    tmp_path, monkeypatch,
):
    import app.collection_safety_setup as safety
    import app.poc as poc
    from app.collection_safety_setup import (
        CollectionSafetySetupIncomplete,
        record_collection_safety_review,
    )
    from app.saved_network_scope_associations import list_saved_network_scope_history

    db_path = tmp_path / "analyzer.db"
    with client_for(tmp_path, monkeypatch) as client:
        reviewed = reviewed_setup(client, label="Review first")

    review_locked = threading.Event()
    release_review = threading.Event()
    save_started = threading.Event()
    failures: list[BaseException] = []
    save_error: list[BaseException] = []
    original_latest = safety._latest_review
    paused = False

    def pause_review_with_write_lock(db):
        nonlocal paused
        result = original_latest(db)
        if threading.current_thread().name == "review-first" and not paused:
            paused = True
            review_locked.set()
            assert release_review.wait(timeout=5)
        return result

    monkeypatch.setattr(safety, "_latest_review", pause_review_with_write_lock)

    def refresh_review():
        try:
            record_collection_safety_review(
                db_path,
                scope_id=reviewed["scope_id"],
                expected_scope_version=reviewed["version"],
                expected_no_strike_revision=0,
                empty_no_strike_reviewed=True,
                reviewed_by="admin",
                reason="Review commits before Saved Network",
            )
        except BaseException as exc:  # pragma: no cover - asserted below
            failures.append(exc)

    def save_network():
        save_started.set()
        try:
            poc.save_saved_network_with_context(
                poc.SavedNetworkContextSave(
                    name="Waiting stale draft",
                    cidr="10.49.0.0/24",
                    scope_id=reviewed["scope_id"],
                    use_reviewed_scope_default=True,
                    expected_collection_review_revision=1,
                    expected_scope_version=reviewed["version"],
                ),
                actor="analyst",
                db_path=db_path,
            )
        except BaseException as exc:
            save_error.append(exc)

    review_thread = threading.Thread(target=refresh_review, name="review-first")
    save_thread = threading.Thread(target=save_network, name="waiting-save")
    review_thread.start()
    assert review_locked.wait(timeout=5)
    save_thread.start()
    assert save_started.wait(timeout=5)
    time.sleep(0.1)
    assert save_thread.is_alive()
    release_review.set()
    review_thread.join(timeout=5)
    save_thread.join(timeout=5)

    assert not failures
    assert not review_thread.is_alive()
    assert not save_thread.is_alive()
    assert len(save_error) == 1
    assert isinstance(save_error[0], CollectionSafetySetupIncomplete)
    assert "changed while this Saved Network" in str(save_error[0])
    assert poc.list_saved_networks(db_path) == []
    assert list_saved_network_scope_history(db_path, "missing") == []


def test_legacy_saved_network_create_remains_unassociated_with_reviewed_scope(
    tmp_path, monkeypatch,
):
    with client_for(tmp_path, monkeypatch) as client:
        reviewed_setup(client, label="Reviewed but not inferred")
        created = client.post(
            "/api/saved-networks",
            json={
                "name": "Legacy path",
                "cidr": "10.50.0.0/24",
                "created_by": "analyst",
            },
        )
        assert created.status_code == 201, created.text
        record = created.json()
        detail = client.get(
            f"/api/saved-networks/{record['saved_network_id']}"
        )
        assert detail.status_code == 200, detail.text
        assert detail.json()["network_scope_association"] is None
        history = client.get(
            f"/api/saved-networks/{record['saved_network_id']}/scope-history"
        )
        assert history.status_code == 200, history.text
        assert history.json() == []


def test_nmap_scan_details_do_not_duplicate_shared_no_strike_management():
    from app.mission_environment_ui import mission_environment_page
    from app.ui import operator_page

    scan_html = operator_page().body.decode()
    setup_html = mission_environment_page().body.decode()
    assert 'id="noStrikePanel"' not in scan_html
    assert "Add to global No-Strike list" not in scan_html
    assert "beginGlobalNoStrikeRemoval" not in scan_html
    assert "globalNoStrikeAdd" not in scan_html
    assert "optional exclusions below apply only to this scan or schedule" in scan_html
    assert "Global No-Strike" in setup_html
    assert "10.0.0.0/8" in setup_html


def test_manual_scan_is_blocked_until_setup_then_inherits_reviewed_scope(
    tmp_path, monkeypatch,
):
    import app.poc as poc
    from app.poc import ScanRunRequest, prepare_scan_run

    launched = []
    monkeypatch.setenv("NCT_ACTIVE_COLLECTION_MODE", "enabled")
    monkeypatch.setattr(
        poc, "launch_scan_run", lambda request: launched.append(request) or {"status": "queued"}
    )
    payload = {
        "operator": "analyst.one",
        "originating_host": "nct-test",
        "interface": "eth0",
        "targets": ["192.0.2.0/30"],
        "manual_targets": ["192.0.2.0/30"],
        "capture": True,
    }
    with client_for(tmp_path, monkeypatch) as client:
        blocked = client.post("/api/scan-runs", json=payload)
        assert blocked.status_code == 409
        assert "Mission Environment" in blocked.json()["detail"]
        assert launched == []

        scope = reviewed_setup(client)
        accepted = client.post("/api/scan-runs", json=payload)
        assert accepted.status_code == 202, accepted.text
        assert len(launched) == 1
        status = client.get("/api/collection-safety-setup").json()
        assert status["scope"]["scope_id"] == scope["scope_id"]
        retained = prepare_scan_run(
            ScanRunRequest(**payload),
            tmp_path / "analyzer.db",
            interfaces={"eth0"},
        )
        assert retained["network_scope_context"]["scope_id"] == scope["scope_id"]
        assert retained["collection_safety_setup"] == status["review"]


def test_completed_manual_scan_keeps_active_scope_into_foundation_intake(
    tmp_path, monkeypatch,
):
    from app.artifacts import register_artifact_file
    from app.automated_nmap_foundation import get_automated_scan_foundation_status
    from app.pipeline_intake import AUTOMATED_NMAP_INTENT, get_admission_intent
    from app.poc import ScanRunRequest, prepare_scan_run, update_scan_run_manifest
    from app.saved_network_scope_associations import get_run_scope_context

    db_path = tmp_path / "analyzer.db"
    with client_for(tmp_path, monkeypatch) as client:
        scope = reviewed_setup(client)
        run = prepare_scan_run(
            ScanRunRequest(
                operator="analyst.one",
                originating_host="nct-test",
                interface="eth0",
                targets=["192.0.2.10"],
                manual_targets=["192.0.2.10"],
                capture=True,
            ),
            db_path,
            interfaces={"eth0"},
        )
        run["status"] = "completed"
        run["completed_at"] = "2030-01-01T00:01:00+00:00"
        xml_path = tmp_path / "manual-scoped.xml"
        xml_path.write_text(
            '<nmaprun scanner="nmap" version="7.95" start="100">'
            '<scaninfo type="syn" protocol="tcp" numservices="1" services="443"/>'
            '<host><status state="up"/><address addr="192.0.2.10" addrtype="ipv4"/>'
            '<ports><port protocol="tcp" portid="443"><state state="open"/>'
            '<service name="https"/></port></ports></host>'
            '<runstats><finished time="110"/><hosts up="1" down="0" total="1"/>'
            '</runstats></nmaprun>',
            encoding="utf-8",
        )
        register_artifact_file(
            db_path=db_path,
            source_path=xml_path,
            source_kind="nmap_scan",
            source_ref=run["run_id"],
            original_filename="scan.xml",
            actor="analyst.one",
            observed_at=run["completed_at"],
            observation_key=f"nmap_scan:{run['run_id']}:scan.xml",
            run_id=run["run_id"],
            scope_context=get_run_scope_context(db_path, run["run_id"]),
        )
        update_scan_run_manifest(run, db_path)

        foundation = get_automated_scan_foundation_status(db_path, run["run_id"])
        intent = get_admission_intent(
            db_path,
            intent_kind=AUTOMATED_NMAP_INTENT,
            source_id=run["run_id"],
        )
        assert foundation["eligible"] is True
        assert foundation["scope_id"] == scope["scope_id"]
        assert intent is not None
        assert intent["state"] in {"pending", "admitted"}


def test_combined_and_unassociated_targets_retain_active_reviewed_scope(
    tmp_path, monkeypatch,
):
    from app.poc import ScanRunRequest, prepare_scan_run
    from app.saved_networks import SavedNetworkCreate, create_saved_network

    with client_for(tmp_path, monkeypatch) as client:
        scope = reviewed_setup(client)
        network = create_saved_network(
            SavedNetworkCreate(
                name="Unassociated operations network",
                cidr="192.0.2.0/30",
                created_by="analyst.one",
            ),
            tmp_path / "analyzer.db",
        )
        base = {
            "operator": "analyst.one",
            "originating_host": "nct-test",
            "interface": "eth0",
            "saved_network_ids": [network["saved_network_id"]],
            "targets": [network["cidr"]],
            "capture": True,
        }
        unassociated = prepare_scan_run(
            ScanRunRequest(**base),
            tmp_path / "analyzer.db",
            interfaces={"eth0"},
        )
        combined = prepare_scan_run(
            ScanRunRequest(
                **{
                    **base,
                    "targets": [network["cidr"], "198.51.100.10"],
                    "manual_targets": ["198.51.100.10"],
                }
            ),
            tmp_path / "analyzer.db",
            interfaces={"eth0"},
        )
        assert unassociated["network_scope_context"]["scope_id"] == scope["scope_id"]
        assert combined["network_scope_context"]["scope_id"] == scope["scope_id"]
        assert unassociated["network_scope_context"]["context_source"] == "collection_safety_setup"


def test_saved_network_scope_must_match_active_mission_environment_scope(
    tmp_path, monkeypatch,
):
    from app.collection_safety_setup import CollectionSafetySetupIncomplete
    from app.network_scopes import create_network_scope
    from app.poc import ScanRunRequest, prepare_scan_run
    from app.saved_networks import SavedNetworkCreate, create_saved_network
    from app.saved_network_scope_associations import change_saved_network_scope_association

    with client_for(tmp_path, monkeypatch) as client:
        reviewed_setup(client, label="Active mission")
        db_path = tmp_path / "analyzer.db"
        other = create_network_scope(
            db_path,
            label="Different mission",
            created_by="admin",
            reason="Separate context",
        )
        network = create_saved_network(
            SavedNetworkCreate(
                name="Different network",
                cidr="198.51.100.0/30",
                created_by="analyst.one",
            ),
            db_path,
        )
        association = change_saved_network_scope_association(
            db_path,
            network["saved_network_id"],
            scope_id=other["scope_id"],
            expected_association_id=None,
            expected_revision=None,
            actor="analyst.one",
            reason="Reviewed separate context",
        )
        request = ScanRunRequest(
            operator="analyst.one",
            originating_host="nct-test",
            interface="eth0",
            targets=[network["cidr"]],
            saved_network_ids=[network["saved_network_id"]],
            reviewed_scope_associations=[{
                "association_id": association["association_id"],
                "revision": association["revision"],
            }],
            reviewed_mission_scopes=[{"scope_id": other["scope_id"], "version": 0}],
            capture=True,
        )
        with pytest.raises(CollectionSafetySetupIncomplete, match="different Network Scope"):
            prepare_scan_run(request, db_path, interfaces={"eth0"})


def test_device_preview_names_missing_inherited_matching_and_conflicting_scope(
    tmp_path, monkeypatch,
):
    base = {
        "operator": "analyst.one",
        "originating_host": "nct-test",
        "vendor": "vyos",
        "device_type": "router",
        "device_types": ["router"],
        "device_address": "192.0.2.10",
        "username": "operator",
        "accountability_interface": "eth0",
    }
    with client_for(tmp_path, monkeypatch) as client:
        missing = client.post("/api/device-configs/preview", json=base)
        assert missing.status_code == 200, missing.text
        assert missing.json()["collection_scope_preview"]["ready"] is False
        assert missing.json()["collection_scope_preview"]["compatible"] is False

        active = reviewed_setup(client)
        inherited = client.post("/api/device-configs/preview", json=base).json()
        assert inherited["collection_scope_preview"]["compatible"] is True
        assert inherited["collection_scope_preview"]["active_scope"]["scope_id"] == active["scope_id"]
        assert inherited["collection_scope_preview"]["selected_scope_id"] is None

        matching = client.post(
            "/api/device-configs/preview",
            json={**base, "preferred_scope_id": active["scope_id"]},
        ).json()
        assert matching["collection_scope_preview"]["compatible"] is True

        other = client.post(
            "/api/network-scopes", json={"label": "Different mission"}
        ).json()
        conflicting = client.post(
            "/api/device-configs/preview",
            json={**base, "preferred_scope_id": other["scope_id"]},
        ).json()
        assert conflicting["collection_scope_preview"]["compatible"] is False
        assert conflicting["collection_scope_preview"]["active_scope"]["scope_id"] == active["scope_id"]


def test_device_hostname_checks_every_ipv4_and_inherits_active_scope(
    tmp_path, monkeypatch,
):
    import socket
    from app.collection_safety_setup import CollectionSafetySetupIncomplete
    from app.device_configs import DeviceConfigPlan, certify_device_collection_plan

    with client_for(tmp_path, monkeypatch) as client:
        scope = reviewed_setup(client)
        plan = DeviceConfigPlan(
            operator="analyst.one",
            originating_host="nct-test",
            vendor="vyos",
            device_type="router",
            device_address="router.example",
            username="operator",
            accountability_interface="eth0",
        )
        monkeypatch.setattr(
            socket,
            "getaddrinfo",
            lambda *_args, **_kwargs: [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.20", 22)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.10", 22)),
            ],
        )
        certified, evidence = certify_device_collection_plan(plan, tmp_path / "analyzer.db")
        assert certified.device_address == "192.0.2.10"
        assert certified.preferred_scope_id == scope["scope_id"]
        assert evidence["resolved_ipv4_addresses"] == ["192.0.2.10", "192.0.2.20"]

        changed = client.post(
            "/api/safety/no-strike",
            json={"entries": ["192.0.2.20"], "changed_by": "analyst.one"},
        ).json()
        rereviewed = client.post(
            "/api/collection-safety-setup/reviews",
            json={
                "scope_id": scope["scope_id"],
                "expected_scope_version": scope["version"],
                "expected_no_strike_revision": changed["revision"],
                "empty_no_strike_reviewed": False,
                "reason": "Protected management address",
            },
        )
        assert rereviewed.status_code == 201, rereviewed.text
        with pytest.raises(CollectionSafetySetupIncomplete, match="192.0.2.20"):
            certify_device_collection_plan(plan, tmp_path / "analyzer.db")


def test_new_global_exclusion_cancels_waiting_device_contact(tmp_path):
    from app.device_contact_work import create_device_contact_run, get_device_contact_run
    from app.poc import NoStrikeUpdate, add_global_no_strike, init_poc_storage

    db_path = tmp_path / "analyzer.db"
    init_poc_storage(db_path)
    run_id = create_device_contact_run(
        db_path,
        operation_kind="configuration_pull",
        subject_key="192.0.2.10:22",
        request={"device_address": "192.0.2.10", "authentication_mode": "key"},
        created_by="analyst.one",
    )
    add_global_no_strike(
        NoStrikeUpdate(entries=["192.0.2.0/24"], changed_by="safety.officer"),
        db_path,
    )
    saved = get_device_contact_run(db_path, run_id)
    assert saved["state"] == "cancelled"
    assert saved["cancellation_requested"] is True
    assert "Global No-Strike" in saved["status_reason"]


def test_device_contact_rechecks_scope_revision_immediately_before_ssh(
    tmp_path, monkeypatch,
):
    from app.collection_safety_setup import CollectionSafetySetupIncomplete
    from app.device_configs import (
        DeviceConfigPlan, certify_device_collection_plan,
        require_device_contact_manifest_ready,
    )

    with client_for(tmp_path, monkeypatch) as client:
        scope = reviewed_setup(client)
        plan, certification = certify_device_collection_plan(
            DeviceConfigPlan(
                operator="analyst.one", originating_host="nct-test",
                vendor="vyos", device_type="router", device_address="192.0.2.10",
                username="operator", accountability_interface="eth0",
            ),
            tmp_path / "analyzer.db",
        )
        manifest = {
            "device_address": plan.device_address,
            "preferred_scope_id": plan.preferred_scope_id,
            "device_contact_certification": certification,
        }
        changed = client.patch(
            f"/api/network-scopes/{scope['scope_id']}",
            json={
                "expected_version": scope["version"], "label": "Home lab reviewed",
                "reason": "Clarify scope before the next device command",
            },
        )
        assert changed.status_code == 200, changed.text
        with pytest.raises(CollectionSafetySetupIncomplete, match="Network Scope changed"):
            require_device_contact_manifest_ready(manifest, tmp_path / "analyzer.db")


def test_device_ssh_ignores_hostile_ambient_config(tmp_path, monkeypatch):
    import app.device_configs as device_configs

    hostile_home = tmp_path / "hostile-home"
    ssh_dir = hostile_home / ".ssh"
    ssh_dir.mkdir(parents=True)
    marker = tmp_path / "ambient-config-ran"
    (ssh_dir / "config").write_text(
        "Host *\n"
        "  HostName 203.0.113.99\n"
        f"  ProxyCommand sh -c 'echo unsafe > {marker}'\n"
        f"  LocalCommand sh -c 'echo unsafe > {marker}'\n"
        "  PermitLocalCommand yes\n"
    )
    monkeypatch.setenv("HOME", str(hostile_home))
    plan = device_configs.DeviceConfigPlan(
        operator="analyst.one", originating_host="nct-test",
        vendor="vyos", device_type="router", device_address="192.0.2.10",
        username="operator", accountability_interface="eth0",
    )
    guard = device_configs._ssh_endpoint_guard_args(plan)
    resolved = subprocess.run(
        ["ssh", *guard, "-G", f"{plan.username}@{plan.device_address}"],
        capture_output=True, text=True, check=True, timeout=10,
    )
    settings = {
        line.split(None, 1)[0].casefold(): line.split(None, 1)[1]
        for line in resolved.stdout.splitlines() if " " in line
    }
    assert settings["hostname"] == "192.0.2.10"
    assert settings.get("proxycommand") in {None, "none"}
    assert settings["permitlocalcommand"] == "no"
    assert settings["clearallforwardings"] == "yes"
    assert not marker.exists()


def test_running_fenced_command_is_stopped_when_scope_review_becomes_stale(
    tmp_path, monkeypatch,
):
    import app.device_configs as device_configs

    db_path = tmp_path / "analyzer.db"
    with client_for(tmp_path, monkeypatch) as client:
        scope = reviewed_setup(client)
        plan, certification = device_configs.certify_device_collection_plan(
            device_configs.DeviceConfigPlan(
                operator="analyst.one", originating_host="nct-test",
                vendor="vyos", device_type="router", device_address="192.0.2.10",
                username="operator", accountability_interface="eth0",
            ),
            db_path,
        )
        run_id = "f" * 32
        fence = device_configs.acquire_device_contact_fence(
            run_id,
            operation_kind="configuration_pull",
            subject_key="192.0.2.10:22",
            request={"device_address": "192.0.2.10", "authentication_mode": "key"},
            created_by="analyst.one",
            contact_certification=certification,
            db_path=db_path,
        )
        marker = tmp_path / "command-finished"

        def invalidate_scope() -> None:
            time.sleep(0.25)
            response = client.patch(
                f"/api/network-scopes/{scope['scope_id']}",
                json={
                    "expected_version": scope["version"],
                    "label": "Changed while contact was active",
                    "reason": "Exercise the live contact fence",
                },
            )
            assert response.status_code == 200, response.text

        thread = threading.Thread(target=invalidate_scope)
        thread.start()
        started = time.monotonic()
        try:
            with pytest.raises(
                device_configs.DeviceContactConflict,
                match="Mission Environment changed",
            ):
                device_configs._run_fenced_process(
                    [
                        sys.executable, "-c",
                        (
                            "import pathlib,time; time.sleep(30); "
                            f"pathlib.Path({str(marker)!r}).write_text('finished')"
                        ),
                    ],
                    fence,
                    timeout=40,
                )
        finally:
            thread.join(timeout=3)
            fence.stop()
        assert time.monotonic() - started < 4
        assert not marker.exists()


def test_new_global_exclusion_cancels_active_scan_and_signals_worker(
    tmp_path, monkeypatch,
):
    import app.poc as poc
    from app.poc import NoStrikeUpdate, RunControl, ScanRunRequest

    with client_for(tmp_path, monkeypatch) as client:
        reviewed_setup(client)
        manifest = poc.prepare_scan_run(
            ScanRunRequest(
                operator="analyst.one", originating_host="nct-test", interface="eth0",
                targets=["192.0.2.10/32"], manual_targets=["192.0.2.10/32"],
                capture=True,
            ),
            tmp_path / "analyzer.db", interfaces={"eth0"},
        )
        manifest["status"] = "running"
        poc.update_scan_run_manifest(manifest, tmp_path / "analyzer.db")
        control = RunControl()
        with poc.ACTIVE_RUNS_LOCK:
            poc.ACTIVE_RUNS[manifest["run_id"]] = control
        try:
            poc.add_global_no_strike(
                NoStrikeUpdate(entries=["192.0.2.10"], changed_by="safety.officer"),
                tmp_path / "analyzer.db",
            )
        finally:
            with poc.ACTIVE_RUNS_LOCK:
                poc.ACTIVE_RUNS.pop(manifest["run_id"], None)
        saved = poc.get_scan_run_plan(manifest["run_id"], tmp_path / "analyzer.db")
        assert control.cancel_event.is_set()
        assert saved["cancellation_requested_at"]
        assert saved["cancellation_cause"] == "global_no_strike"


def test_scheduled_occurrence_halts_after_scope_revision_changes(tmp_path, monkeypatch):
    from datetime import datetime, timezone
    import app.poc as poc
    from app.collection_safety_setup import CollectionSafetySetupIncomplete

    with client_for(tmp_path, monkeypatch) as client:
        scope = reviewed_setup(client)
        schedule = poc.create_scan_schedule(
            poc.ScanScheduleCreate(
                name="Reviewed daily scan", created_by="analyst.one",
                profile_id="builtin-standard", profile_version=1,
                targets=["192.0.2.10/32"], interface="eth0", cadence="daily",
                first_run_at=datetime(2026, 1, 1, tzinfo=timezone.utc), enabled=True,
            ),
            tmp_path / "analyzer.db",
        )
        changed = client.patch(
            f"/api/network-scopes/{scope['scope_id']}",
            json={
                "expected_version": scope["version"], "label": "Changed scope",
                "reason": "Invalidate the earlier schedule review",
            },
        )
        assert changed.status_code == 200, changed.text
        with pytest.raises(CollectionSafetySetupIncomplete):
            poc.prepare_schedule_occurrence(
                schedule["schedule_id"], advance_schedule=True,
                trigger_key="cadence", actor="scheduler",
                now=datetime.fromisoformat(schedule["next_run_at"]),
                db_path=tmp_path / "analyzer.db",
            )
        assert poc.list_active_scan_run_plans(tmp_path / "analyzer.db") == []


def test_restart_preserves_reviewed_queue_but_stale_scope_blocks_contact(
    tmp_path, monkeypatch,
):
    import app.poc as poc

    monkeypatch.setenv("NCT_ACTIVE_COLLECTION_MODE", "enabled")
    data_dir = tmp_path / "data"
    with client_for(tmp_path, monkeypatch) as client:
        scope = reviewed_setup(client)
        manifest = poc.prepare_scan_run(
            poc.ScanRunRequest(
                operator="analyst.one", originating_host="nct-test", interface="eth0",
                targets=["192.0.2.10/32"], manual_targets=["192.0.2.10/32"],
                capture=True,
            ),
            tmp_path / "analyzer.db", interfaces={"eth0"},
        )
        monkeypatch.setattr(poc, "dispatch_next_queued_run", lambda **_kwargs: None)
        recovered = poc.recover_scheduler_state(tmp_path / "analyzer.db", data_dir)
        assert manifest["run_id"] in recovered["preserved_queue_run_ids"]
        retained = poc.get_scan_run_plan(manifest["run_id"], tmp_path / "analyzer.db")
        assert retained["network_scope_context"]["scope_id"] == scope["scope_id"]
        assert retained["collection_safety_setup"]["scope_id"] == scope["scope_id"]
        admitted_context = dict(retained["network_scope_context"])
        admitted_setup = dict(retained["collection_safety_setup"])
        client.patch(
            f"/api/network-scopes/{scope['scope_id']}",
            json={
                "expected_version": scope["version"], "label": "Changed after restart",
                "reason": "Verify stale setup cannot contact the network",
            },
        )
        launched = []
        poc.execute_scan_run(
            manifest["run_id"], poc.RunControl(),
            db_path=tmp_path / "analyzer.db", data_dir=data_dir,
            popen_factory=lambda *args, **kwargs: launched.append((args, kwargs)),
            sleep_fn=lambda _seconds: None,
        )
        assert launched == []
        blocked = poc.get_scan_run_plan(manifest["run_id"], tmp_path / "analyzer.db")
        assert blocked["status"] == "blocked_mission_environment"
        assert "Mission Environment" in blocked["execution_note"]
        assert blocked["network_scope_context"] == admitted_context
        assert blocked["collection_safety_setup"] == admitted_setup


def test_contact_publication_rejects_active_scope_switch_after_queue_claim(
    tmp_path, monkeypatch,
):
    import app.poc as poc

    monkeypatch.setenv("NCT_ACTIVE_COLLECTION_MODE", "enabled")
    db_path = tmp_path / "analyzer.db"
    with client_for(tmp_path, monkeypatch) as client:
        first_scope = reviewed_setup(client, label="Mission A")
        queued = poc.prepare_scan_run(
            poc.ScanRunRequest(
                operator="analyst.one", originating_host="nct-test", interface="eth0",
                targets=["192.0.2.10/32"], manual_targets=["192.0.2.10/32"],
                capture=True,
            ),
            db_path,
            interfaces={"eth0"},
        )
        claimed = poc.claim_next_queued_scan(db_path)
        assert claimed is not None
        assert claimed["network_scope_context"]["scope_id"] == first_scope["scope_id"]

        second_scope = reviewed_setup(client, label="Mission B")
        assert second_scope["scope_id"] != first_scope["scope_id"]
        assert poc.publish_scan_contact_starting(claimed, db_path=db_path) is False

        retained = poc.get_scan_run_plan(queued["run_id"], db_path)
        assert retained["status"] != "running"
        assert retained["network_scope_context"]["scope_id"] == first_scope["scope_id"]
        assert "Mission Environment" in retained["execution_note"]


def test_contact_publication_rejects_same_scope_revision_change_after_queue_claim(
    tmp_path, monkeypatch,
):
    import app.poc as poc

    monkeypatch.setenv("NCT_ACTIVE_COLLECTION_MODE", "enabled")
    db_path = tmp_path / "analyzer.db"
    with client_for(tmp_path, monkeypatch) as client:
        scope = reviewed_setup(client, label="Mission A")
        queued = poc.prepare_scan_run(
            poc.ScanRunRequest(
                operator="analyst.one", originating_host="nct-test", interface="eth0",
                targets=["192.0.2.10/32"], manual_targets=["192.0.2.10/32"],
                capture=True,
            ),
            db_path,
            interfaces={"eth0"},
        )
        claimed = poc.claim_next_queued_scan(db_path)
        assert claimed is not None
        changed = client.patch(
            f"/api/network-scopes/{scope['scope_id']}",
            json={
                "expected_version": scope["version"],
                "label": "Mission A revised",
                "reason": "Exercise the final contact boundary",
            },
        )
        assert changed.status_code == 200, changed.text

        rereviewed = client.post(
            "/api/collection-safety-setup/reviews",
            json={
                "scope_id": scope["scope_id"],
                "expected_scope_version": changed.json()["version"],
                "expected_no_strike_revision": 0,
                "empty_no_strike_reviewed": True,
                "reason": "Review the revised scope",
            },
        )
        assert rereviewed.status_code == 201, rereviewed.text
        admitted_setup = dict(claimed["collection_safety_setup"])
        with pytest.raises(
            poc.CollectionSafetySetupIncomplete,
            match="changed after scan admission",
        ):
            poc.certify_scan_contact_phase(
                claimed, "queue_start", db_path=db_path, data_dir=tmp_path
            )
        assert claimed["collection_safety_setup"] == admitted_setup

        assert poc.publish_scan_contact_starting(claimed, db_path=db_path) is False
        retained = poc.get_scan_run_plan(queued["run_id"], db_path)
        assert retained["status"] != "running"
        assert retained["network_scope_context"]["scope_id"] == scope["scope_id"]
        assert retained["network_scope_context"]["scope_version"] == scope["version"]
        assert "Mission Environment" in retained["execution_note"]
