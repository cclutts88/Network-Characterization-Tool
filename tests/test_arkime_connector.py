from __future__ import annotations

from datetime import datetime, timezone
import json
import os
import sys
import time
from urllib import error as urlerror

import pytest
from fastapi.testclient import TestClient

import app.arkime_connector as connector
import app.arkime_transport as transport
from app.arkime_connector import (
    ArkimeConnectorConfig,
    ArkimeConnectorConflict,
    ArkimeConnectorError,
    ArkimeConnectorUnavailable,
    cancel_pull_run,
    create_pull_profile,
    enqueue_pull_now,
    execute_one_pull,
    get_pull_run,
    list_pull_profiles,
    recover_interrupted_pulls,
    retry_pull_run,
    set_pull_profile_enabled,
)
from app.database import connect_database
from app.network_scopes import archive_network_scope, create_network_scope, update_network_scope


@pytest.fixture
def configured(monkeypatch, tmp_path):
    password = tmp_path / "arkime-password"
    password.write_text("test-only-password\n", encoding="utf-8")
    monkeypatch.setenv("NCT_ARKIME_API_ENABLED", "1")
    monkeypatch.setenv("NCT_ARKIME_API_URL", "https://arkime.invalid:8005")
    monkeypatch.setenv("NCT_ARKIME_API_USERNAME", "nct-reader")
    monkeypatch.setenv("NCT_ARKIME_API_PASSWORD_FILE", str(password))
    monkeypatch.delenv("HTTPS_PROXY", raising=False)
    return password


def _profile(db, scope_id, **overrides):
    payload = {
        "name": "Hourly passive window",
        "scope_id": scope_id,
        "operator_sensor": "range-observation-point",
        "query_expression": "vlan == 10",
        "bounding_mode": "both",
        "cadence_minutes": 60,
        "lookback_minutes": 60,
        "overlap_minutes": 5,
        "collection_delay_seconds": 60,
        "enabled": False,
    }
    payload.update(overrides)
    return create_pull_profile(db, payload, actor="admin")


def _response(parameters, *, filtered=1, rows=1):
    start = int(parameters["startTime"])
    body = {
        "recordsFiltered": filtered,
        "recordsTotal": max(filtered, rows),
        "data": [
            {
                "id": f"session-{index}", "rootId": f"root-{index}", "node": "range-sensor",
                "firstPacket": (start + 120 + index) * 1000,
                "lastPacket": (start + 180 + index) * 1000,
                "source.ip": f"192.0.2.{10 + index}", "source.port": 50000 + index,
                "destination.ip": "198.51.100.20", "destination.port": 443,
                "ipProtocol": 6, "network.packets": 10, "network.bytes": 4096,
                "protocol": ["tls"], "vlan": [10],
            }
            for index in range(rows)
        ],
    }
    return json.dumps(body, separators=(",", ":")).encode()


def test_config_rejects_non_https_and_url_credentials(configured, monkeypatch):
    monkeypatch.setenv("NCT_ARKIME_API_URL", "http://arkime.invalid:8005")
    with pytest.raises(ArkimeConnectorUnavailable, match="HTTPS"):
        ArkimeConnectorConfig.from_environment()


def test_missing_password_file_is_not_reported_ready_and_blocks_contact(configured, tmp_path):
    db = tmp_path / "nct.db"
    scope = create_network_scope(db, label="Range", created_by="admin")
    profile = _profile(db, scope["scope_id"])
    configured.unlink()
    status = connector.connector_status()
    assert status["configured"] is False
    assert "could not be read" in status["detail"]
    with pytest.raises(ArkimeConnectorUnavailable, match="could not be read"):
        enqueue_pull_now(db, profile["profile_id"], actor="analyst")
    assert connector.list_pull_runs(db)["items"] == []


def test_transport_refuses_redirects_compression_and_oversized_entities(configured, monkeypatch):
    config = ArkimeConnectorConfig.from_environment()

    class Response:
        def __init__(self, chunks, encoding="identity"):
            self.chunks = iter(chunks)
            self.headers = {"Content-Encoding": encoding}
        def __enter__(self):
            return self
        def __exit__(self, *_args):
            return False
        def read(self, _size):
            return next(self.chunks, b"")

    class Opener:
        response = None
        failure = None
        def open(self, *_args, **_kwargs):
            if self.failure:
                raise self.failure
            return self.response

    opener = Opener()
    monkeypatch.setattr(transport.request, "build_opener", lambda *_handlers: opener)
    parameters = {"startTime": "1", "stopTime": "2"}
    opener.response = Response([b"{}"], encoding="gzip")
    with pytest.raises(transport.ArkimeTransportError, match="compressed"):
        transport.fetch_sessions({
            "base_url": config.base_url, "username": config.username,
            "password_file": str(config.password_file), "ca_file": None,
            "timeout_seconds": config.timeout_seconds, "parameters": parameters,
        })
    opener.response = Response([b"x" * connector.MAX_ARKIME_JSON_BYTES, b"x"])
    with pytest.raises(transport.ArkimeTransportError, match="10 MiB"):
        transport.fetch_sessions({
            "base_url": config.base_url, "username": config.username,
            "password_file": str(config.password_file), "ca_file": None,
            "timeout_seconds": config.timeout_seconds, "parameters": parameters,
        })
    opener.failure = urlerror.HTTPError(
        config.sessions_url, 302, "Found", {"Location": "https://elsewhere.invalid"}, None,
    )
    with pytest.raises(transport.ArkimeTransportError, match="redirect"):
        transport.fetch_sessions({
            "base_url": config.base_url, "username": config.username,
            "password_file": str(config.password_file), "ca_file": None,
            "timeout_seconds": config.timeout_seconds, "parameters": parameters,
        })


def test_transport_builds_digest_https_without_proxy_inheritance(configured, monkeypatch):
    captured = []
    class Response:
        headers = {"Content-Encoding": "identity"}
        def __enter__(self): return self
        def __exit__(self, *_args): return False
        def read(self, _size): return b""
    class Opener:
        def open(self, *_args, **_kwargs): return Response()
    def build(*handlers):
        captured.extend(handlers)
        return Opener()
    monkeypatch.setattr(transport.request, "build_opener", build)
    config = ArkimeConnectorConfig.from_environment()
    transport.fetch_sessions({
        "base_url": config.base_url, "username": config.username,
        "password_file": str(config.password_file), "ca_file": None,
        "timeout_seconds": config.timeout_seconds,
        "parameters": {"startTime":"1","stopTime":"2"},
    })
    assert any(isinstance(item, transport.request.HTTPDigestAuthHandler) for item in captured)
    proxy = next(item for item in captured if isinstance(item, transport.request.ProxyHandler))
    assert proxy.proxies == {}
    assert any(isinstance(item, transport.request.HTTPSHandler) for item in captured)
    monkeypatch.setenv("NCT_ARKIME_API_URL", "https://user:pass@arkime.invalid:8005")
    with pytest.raises(ArkimeConnectorUnavailable, match="credentials"):
        ArkimeConnectorConfig.from_environment()


def test_profile_validation_and_read_only_listing(configured, tmp_path):
    db = tmp_path / "nct.db"
    scope = create_network_scope(db, label="Range", created_by="admin")
    profile = _profile(db, scope["scope_id"])
    assert profile["scope_label"] == "Range"
    assert profile["enabled"] is False
    assert list_pull_profiles(db)["items"][0]["profile_id"] == profile["profile_id"]
    with pytest.raises(ArkimeConnectorError):
        _profile(db, scope["scope_id"], overlap_minutes=60)


def test_profile_creation_pause_and_enable_are_attributed(configured, tmp_path):
    db = tmp_path / "nct.db"
    scope = create_network_scope(db, label="Range", created_by="admin")
    profile = _profile(db, scope["scope_id"])
    set_pull_profile_enabled(db, profile["profile_id"], enabled=True, actor="supervisor")
    set_pull_profile_enabled(db, profile["profile_id"], enabled=False, actor="operator")
    with connect_database(db, read_only=True) as connection:
        events = connection.execute(
            "SELECT event_type, actor FROM arkime_pull_profile_events "
            "WHERE profile_id=? ORDER BY created_at, rowid", (profile["profile_id"],),
        ).fetchall()
    assert events == [("created", "admin"), ("enabled", "supervisor"), ("paused", "operator")]


def test_pausing_prevents_a_waiting_scheduled_pull_from_being_claimed(configured, tmp_path):
    db = tmp_path / "nct.db"
    scope = create_network_scope(db, label="Range", created_by="admin")
    profile = _profile(db, scope["scope_id"], enabled=True)
    connector._queue_due(db)
    runs = connector.list_pull_runs(db)["items"]
    assert runs[0]["request_kind"] == "scheduled"
    set_pull_profile_enabled(db, profile["profile_id"], enabled=False, actor="admin")
    assert get_pull_run(db, runs[0]["run_id"])["state"] == "cancelled"
    assert connector._claim(db) is None


def test_pull_retains_exact_response_and_completes_atomically(configured, tmp_path):
    db = tmp_path / "nct.db"
    scope = create_network_scope(db, label="Range", created_by="admin")
    profile = _profile(db, scope["scope_id"])
    queued = enqueue_pull_now(db, profile["profile_id"], actor="analyst")
    captured = {}
    def fetch(_config, parameters):
        captured.update(parameters)
        return _response(parameters)
    assert execute_one_pull(db, fetcher=fetch)
    completed = get_pull_run(db, queued["run_id"])
    assert completed["state"] == "complete"
    assert completed["import_id"]
    assert captured["length"] == "1000"
    assert captured["start"] == "0"
    assert "password" not in json.dumps(completed).lower()
    with connect_database(db, read_only=True) as connection:
        assert connection.execute("SELECT COUNT(*) FROM arkime_imports").fetchone()[0] == 1
        assert connection.execute("SELECT COUNT(*) FROM artifact_observations").fetchone()[0] == 1


def test_partial_response_is_retained_and_stops_schedule(configured, tmp_path):
    db = tmp_path / "nct.db"
    scope = create_network_scope(db, label="Range", created_by="admin")
    profile = _profile(db, scope["scope_id"])
    queued = enqueue_pull_now(db, profile["profile_id"], actor="analyst")
    execute_one_pull(db, fetcher=lambda _config, params: _response(params, filtered=7, rows=1))
    assert get_pull_run(db, queued["run_id"])["state"] == "partial"
    current = list_pull_profiles(db)["items"][0]
    assert current["state"] == "attention"
    assert "more matching sessions" in current["attention_detail"]


def test_missing_match_count_is_retained_as_unknown_and_stops_schedule(configured, tmp_path):
    db = tmp_path / "nct.db"
    scope = create_network_scope(db, label="Range", created_by="admin")
    profile = _profile(db, scope["scope_id"])
    queued = enqueue_pull_now(db, profile["profile_id"], actor="analyst")

    def response_without_counts(_config, parameters):
        body = json.loads(_response(parameters))
        body.pop("recordsFiltered")
        body.pop("recordsTotal")
        return json.dumps(body, separators=(",", ":")).encode()

    execute_one_pull(db, fetcher=response_without_counts)
    run = get_pull_run(db, queued["run_id"])
    assert run["state"] == "partial"
    current = list_pull_profiles(db)["items"][0]
    assert current["state"] == "attention"
    assert "did not report" in current["attention_detail"]
    with connect_database(db, read_only=True) as connection:
        saved = connection.execute(
            "SELECT calculated_export_completeness, capture_coverage FROM arkime_imports"
        ).fetchone()
    assert saved == ("unknown", "unknown")


def test_identical_api_responses_share_content_but_keep_two_encounters(configured, tmp_path):
    db = tmp_path / "nct.db"
    scope = create_network_scope(db, label="Range", created_by="admin")
    profile = _profile(db, scope["scope_id"])
    first = enqueue_pull_now(db, profile["profile_id"], actor="analyst")
    saved_content = None

    def first_fetch(_config, parameters):
        nonlocal saved_content
        saved_content = _response(parameters)
        return saved_content

    execute_one_pull(db, fetcher=first_fetch)
    second = enqueue_pull_now(db, profile["profile_id"], actor="analyst")
    execute_one_pull(db, fetcher=lambda _config, _parameters: saved_content)
    assert get_pull_run(db, first["run_id"])["state"] == "complete"
    assert get_pull_run(db, second["run_id"])["state"] == "complete"
    with connect_database(db, read_only=True) as connection:
        artifact_count = connection.execute("SELECT COUNT(*) FROM artifact_registry").fetchone()[0]
        observation_count = connection.execute("SELECT COUNT(*) FROM artifact_observations").fetchone()[0]
        import_count = connection.execute("SELECT COUNT(*) FROM arkime_imports").fetchone()[0]
    assert artifact_count == 1
    assert observation_count == 2
    assert import_count == 2


def test_failure_redacts_credentials_and_explicit_retry_keeps_window(configured, tmp_path):
    db = tmp_path / "nct.db"
    scope = create_network_scope(db, label="Range", created_by="admin")
    profile = _profile(db, scope["scope_id"])
    queued = enqueue_pull_now(db, profile["profile_id"], actor="analyst")
    def fail(_config, _parameters):
        raise ArkimeConnectorUnavailable("Arkime rejected the read-only account credentials")
    execute_one_pull(db, fetcher=fail)
    failed = get_pull_run(db, queued["run_id"])
    assert failed["state"] == "failed"
    assert "test-only-password" not in json.dumps(failed)
    retried = retry_pull_run(db, failed["run_id"], actor="analyst")
    assert retried["query_start"] == failed["query_start"]
    assert retried["query_end"] == failed["query_end"]
    assert retried["retry_of_run_id"] == failed["run_id"]


def test_cancelled_run_never_publishes(configured, tmp_path):
    db = tmp_path / "nct.db"
    scope = create_network_scope(db, label="Range", created_by="admin")
    profile = _profile(db, scope["scope_id"])
    queued = enqueue_pull_now(db, profile["profile_id"], actor="analyst")
    cancelled = cancel_pull_run(db, queued["run_id"])
    assert cancelled["state"] == "cancelled"
    assert list_pull_profiles(db)["items"][0]["state"] == "attention"
    with pytest.raises(ArkimeConnectorConflict, match="attention-required"):
        enqueue_pull_now(db, profile["profile_id"], actor="analyst")
    assert execute_one_pull(db, fetcher=lambda _config, params: _response(params)) is False
    with connect_database(db, read_only=True) as connection:
        assert connection.execute("SELECT COUNT(*) FROM arkime_imports").fetchone()[0] == 0


def test_scope_change_after_queue_blocks_publication(configured, tmp_path):
    db = tmp_path / "nct.db"
    scope = create_network_scope(db, label="Range", created_by="admin")
    profile = _profile(db, scope["scope_id"])
    queued = enqueue_pull_now(db, profile["profile_id"], actor="analyst")
    update_network_scope(
        db, scope["scope_id"], expected_version=1, label="Renamed Range",
        description="", reason="test", updated_by="admin",
    )
    contacted = False

    def fetch(_config, params):
        nonlocal contacted
        contacted = True
        return _response(params)

    execute_one_pull(db, fetcher=fetch)
    failed = get_pull_run(db, queued["run_id"])
    assert failed["state"] == "failed"
    assert "Network Scope changed" in failed["error"]
    assert contacted is False
    with connect_database(db, read_only=True) as connection:
        assert connection.execute("SELECT COUNT(*) FROM arkime_imports").fetchone()[0] == 0


def test_restart_marks_running_attempt_interrupted(configured, tmp_path):
    db = tmp_path / "nct.db"
    scope = create_network_scope(db, label="Range", created_by="admin")
    profile = _profile(db, scope["scope_id"])
    queued = enqueue_pull_now(db, profile["profile_id"], actor="analyst")
    with connect_database(db) as connection:
        connection.execute(
            "UPDATE arkime_pull_runs SET state='running',claim_token='lost',started_at=? WHERE run_id=?",
            (datetime.now(timezone.utc).isoformat(), queued["run_id"]),
        )
    assert recover_interrupted_pulls(db) == 1
    assert get_pull_run(db, queued["run_id"])["state"] == "interrupted"


def test_frozen_run_authority_and_single_claim(configured, tmp_path):
    db = tmp_path / "nct.db"
    scope = create_network_scope(db, label="Range", created_by="admin")
    profile = _profile(db, scope["scope_id"])
    queued = enqueue_pull_now(db, profile["profile_id"], actor="analyst")
    first = connector._claim(db)
    assert first is not None
    assert connector._claim(db) is None
    with connect_database(db) as connection, pytest.raises(Exception, match="authority is immutable"):
        connection.execute(
            "UPDATE arkime_pull_runs SET query_expression='changed' WHERE run_id=?",
            (queued["run_id"],),
        )
    for field, value in (
        ("connector_contract", "changed"),
        ("parser_version", "changed"),
        ("advances_schedule", 1),
    ):
        with connect_database(db) as connection, pytest.raises(
            Exception, match="authority is immutable",
        ):
            connection.execute(
                f"UPDATE arkime_pull_runs SET {field}=? WHERE run_id=?",
                (value, queued["run_id"]),
            )


def test_connector_routes_create_list_queue_cancel_and_report_status(configured, tmp_path, monkeypatch):
    import app.main as main

    db = tmp_path / "routes.db"
    monkeypatch.setattr(main, "DB_PATH", db)
    monkeypatch.setattr(main, "start_arkime_pull_worker", lambda _db: True)
    monkeypatch.setattr(main, "stop_arkime_pull_worker", lambda: True)
    scope = create_network_scope(db, label="Route range", created_by="admin")
    payload = {
        "name": "Route pull",
        "scope_id": scope["scope_id"],
        "operator_sensor": "range Arkime",
        "query_expression": "vlan == 10",
        "bounding_mode": "both",
        "cadence_minutes": 60,
        "lookback_minutes": 60,
        "overlap_minutes": 5,
        "collection_delay_seconds": 60,
        "enabled": False,
    }
    with TestClient(main.app) as client:
        status = client.get("/api/arkime/connector")
        created = client.post("/api/arkime/pull-profiles", json=payload)
        profiles = client.get("/api/arkime/pull-profiles?limit=1&offset=0")
        queued = client.post(
            f"/api/arkime/pull-profiles/{created.json()['profile_id']}/pull-now"
        )
        cancelled = client.post(f"/api/arkime/pull-runs/{queued.json()['run_id']}/cancel")
        runs = client.get("/api/arkime/pull-runs")

    assert status.status_code == 200
    assert status.json()["configured"] is True
    assert created.status_code == 201
    assert profiles.status_code == 200
    assert profiles.json()["items"][0]["name"] == "Route pull"
    assert profiles.json()["pagination"] == {
        "limit": 1, "offset": 0, "total": 1, "has_more": False,
    }
    assert queued.status_code == 202
    assert cancelled.status_code == 202
    assert cancelled.json()["state"] == "cancelled"
    assert runs.status_code == 200
    assert runs.json()["items"][0]["run_id"] == queued.json()["run_id"]


def test_connector_routes_keep_profile_control_admin_only(configured, tmp_path, monkeypatch):
    import app.main as main

    db = tmp_path / "auth-routes.db"
    monkeypatch.setattr(main, "DB_PATH", db)
    monkeypatch.setattr(main, "start_arkime_pull_worker", lambda _db: True)
    monkeypatch.setattr(main, "stop_arkime_pull_worker", lambda: True)
    monkeypatch.setattr(main, "auth_enabled", lambda: True)
    identity = {"username": "analyst-a", "display_name": "Analyst", "role": "analyst"}
    monkeypatch.setattr(main, "session_identity", lambda *_args: identity)
    scope = create_network_scope(db, label="Authorized range", created_by="admin")
    profile = _profile(db, scope["scope_id"])
    payload = {
        "name": "Forbidden analyst definition", "scope_id": scope["scope_id"],
        "operator_sensor": "sensor", "query_expression": "", "bounding_mode": "both",
        "cadence_minutes": 60, "lookback_minutes": 60, "overlap_minutes": 5,
        "collection_delay_seconds": 60, "enabled": False,
    }

    with TestClient(main.app) as client:
        assert client.get("/api/arkime/pull-profiles").status_code == 200
        assert client.post("/api/arkime/pull-profiles", json=payload).status_code == 403
        queued = client.post(f"/api/arkime/pull-profiles/{profile['profile_id']}/pull-now")
        assert queued.status_code == 202

        identity["role"] = "viewer"
        assert client.get("/api/arkime/pull-runs").status_code == 200
        assert client.post(f"/api/arkime/pull-runs/{queued.json()['run_id']}/cancel").status_code == 403


def test_manual_retry_resolves_attention_without_advancing_schedule(configured, tmp_path):
    db = tmp_path / "manual-retry.db"
    scope = create_network_scope(db, label="Range", created_by="admin")
    profile = _profile(db, scope["scope_id"])
    before = list_pull_profiles(db)["items"][0]
    queued = enqueue_pull_now(db, profile["profile_id"], actor="analyst")
    execute_one_pull(
        db, fetcher=lambda *_args: (_ for _ in ()).throw(
            ArkimeConnectorUnavailable("temporary failure")
        ),
    )
    retried = retry_pull_run(db, queued["run_id"], actor="analyst")
    execute_one_pull(db, fetcher=lambda _config, params: _response(params))
    after = list_pull_profiles(db)["items"][0]
    assert retried["advances_schedule"] is False
    assert after["state"] == "ready"
    assert (after["next_window_start"], after["next_window_end"], after["next_due_at"]) == (
        before["next_window_start"], before["next_window_end"], before["next_due_at"],
    )


def test_scheduled_retry_advances_once_and_obsolete_attempt_is_rejected(configured, tmp_path):
    db = tmp_path / "scheduled-retry.db"
    scope = create_network_scope(db, label="Range", created_by="admin")
    profile = _profile(db, scope["scope_id"], enabled=True)
    before = list_pull_profiles(db)["items"][0]
    connector._queue_due(db)
    scheduled = connector.list_pull_runs(db)["items"][0]
    execute_one_pull(
        db, fetcher=lambda *_args: (_ for _ in ()).throw(
            ArkimeConnectorUnavailable("temporary failure")
        ),
    )
    retried = retry_pull_run(db, scheduled["run_id"], actor="analyst")
    assert retried["advances_schedule"] is True
    execute_one_pull(db, fetcher=lambda _config, params: _response(params))
    after = list_pull_profiles(db)["items"][0]
    assert after["state"] == "ready"
    assert after["next_window_end"] != before["next_window_end"]
    with pytest.raises(ArkimeConnectorConflict, match="already resolved"):
        retry_pull_run(db, scheduled["run_id"], actor="analyst")


def test_pull_profiles_are_fully_reachable_through_pagination(configured, tmp_path):
    db = tmp_path / "profile-pages.db"
    scope = create_network_scope(db, label="Range", created_by="admin")
    for index in range(101):
        _profile(db, scope["scope_id"], name=f"Pull {index:03d}")
    first = list_pull_profiles(db, limit=100, offset=0)
    second = list_pull_profiles(db, limit=100, offset=100)
    assert first["pagination"] == {
        "limit": 100, "offset": 0, "total": 101, "has_more": True,
    }
    assert len(first["items"]) == 100
    assert second["pagination"]["has_more"] is False
    assert len(second["items"]) == 1
    assert {item["name"] for item in first["items"] + second["items"]} == {
        f"Pull {index:03d}" for index in range(101)
    }


@pytest.mark.parametrize("mode", ["body", "headers"])
def test_whole_request_deadline_stops_real_slow_stream(
    configured, monkeypatch, mode,
):
    base = ArkimeConnectorConfig.from_environment()
    config = ArkimeConnectorConfig(
        enabled=True, base_url=base.base_url, username=base.username,
        password_file=base.password_file, timeout_seconds=0.1,
        connector_id=base.connector_id,
    )

    fixture = os.path.join(os.getcwd(), "tests", "arkime_slow_transport.py")
    monkeypatch.setattr(
        connector, "_transport_command", lambda: [sys.executable, fixture, mode],
    )
    started = time.monotonic()
    with pytest.raises(ArkimeConnectorUnavailable, match="whole-request deadline"):
        connector._fetch_sessions(config, {"startTime": "1", "stopTime": "2"})
    assert time.monotonic() - started < 0.3
    assert connector._ACTIVE_TRANSPORT is None


def test_worker_shutdown_interrupts_an_active_response_within_its_bound(configured, monkeypatch):
    config = ArkimeConnectorConfig.from_environment()
    fixture = os.path.join(os.getcwd(), "tests", "arkime_slow_transport.py")
    monkeypatch.setattr(
        connector, "_transport_command", lambda: [sys.executable, fixture, "body"],
    )
    errors = []
    def fetch():
        try:
            connector._fetch_sessions(config, {"startTime": "1", "stopTime": "2"})
        except Exception as exc:
            errors.append(exc)

    worker = connector.threading.Thread(target=fetch, name="arkime-test-worker")
    connector._WORKER_STOP.clear()
    connector._WORKER_THREAD = worker
    worker.start()
    wait_until = time.monotonic() + 1
    while connector._ACTIVE_TRANSPORT is None and time.monotonic() < wait_until:
        time.sleep(0.01)
    assert connector._ACTIVE_TRANSPORT is not None
    started = time.monotonic()
    assert connector.stop_arkime_pull_worker() is True
    assert time.monotonic() - started < 0.5
    assert errors and "stopped" in str(errors[0]).lower()
    connector._WORKER_STOP.clear()


def test_connector_rejects_more_than_one_thousand_rows_before_publication(configured, tmp_path):
    db = tmp_path / "row-limit.db"
    scope = create_network_scope(db, label="Range", created_by="admin")
    profile = _profile(db, scope["scope_id"])
    queued = enqueue_pull_now(db, profile["profile_id"], actor="analyst")

    def too_many(_config, parameters):
        start = int(parameters["startTime"])
        row = {
            "id": "same", "rootId": "root", "node": "sensor",
            "firstPacket": (start + 120) * 1000, "lastPacket": (start + 180) * 1000,
            "source.ip": "192.0.2.10", "source.port": 50000,
            "destination.ip": "198.51.100.20", "destination.port": 443,
            "ipProtocol": 6, "network.packets": 10, "network.bytes": 4096,
            "protocol": ["tls"], "vlan": [10],
        }
        return json.dumps({
            "recordsFiltered": 1001, "recordsTotal": 1001, "data": [row] * 1001,
        }, separators=(",", ":")).encode()

    execute_one_pull(db, fetcher=too_many)
    failed = get_pull_run(db, queued["run_id"])
    assert failed["state"] == "failed"
    assert "1,000-session connector limit" in failed["error"]
    with connect_database(db, read_only=True) as connection:
        assert connection.execute("SELECT COUNT(*) FROM arkime_imports").fetchone()[0] == 0


@pytest.mark.parametrize("field,value", [
    ("connector_contract", "old-contract"),
    ("parser_version", "old-parser"),
])
def test_incompatible_queued_contract_is_rejected_before_contact(
    configured, tmp_path, field, value,
):
    db = tmp_path / f"contract-{field}.db"
    scope = create_network_scope(db, label="Range", created_by="admin")
    profile = _profile(db, scope["scope_id"])
    queued = enqueue_pull_now(db, profile["profile_id"], actor="analyst")
    with connect_database(db) as connection:
        connection.execute("DROP TRIGGER arkime_pull_runs_frozen_authority")
        connection.execute(
            f"UPDATE arkime_pull_runs SET {field}=? WHERE run_id=?", (value, queued["run_id"]),
        )
    contacted = False
    def fetch(*_args):
        nonlocal contacted
        contacted = True
        return b"{}"
    execute_one_pull(db, fetcher=fetch)
    assert contacted is False
    assert get_pull_run(db, queued["run_id"])["state"] == "failed"
