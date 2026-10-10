from __future__ import annotations

import asyncio
import inspect
import json

import pytest
from fastapi.testclient import TestClient

import app.lifecycle_health as lifecycle
import app.main as main


def _body(response) -> dict:
    return json.loads(response.body)


def test_probe_states_are_fixed_and_resettable() -> None:
    lifecycle.begin_startup()
    startup = lifecycle.probe_result("startup")
    readiness = lifecycle.probe_result("readiness")
    liveness = lifecycle.probe_result("liveness")
    assert startup[0] == readiness[0] == 503
    assert liveness[0] == 200
    assert startup[1] == {
        "schema_version": 1,
        "check": "startup",
        "status": "not_started",
        "healthy": False,
        "meaning": "Required initialization and recovery safety checks have completed.",
    }

    lifecycle.mark_ready()
    assert lifecycle.probe_result("startup")[0] == 200
    assert lifecycle.probe_result("readiness")[0] == 200

    lifecycle.begin_shutdown()
    assert lifecycle.probe_result("startup")[0] == 200
    assert lifecycle.probe_result("readiness")[0] == 503
    lifecycle.mark_failed()
    assert lifecycle.probe_result("startup")[0] == 503

    lifecycle.begin_startup()
    assert lifecycle.lifecycle_phase() == "starting"
    assert lifecycle.probe_result("readiness")[0] == 503
    lifecycle.mark_stopped()


def test_probe_routes_are_no_store_and_keep_legacy_health_contract(monkeypatch) -> None:
    monkeypatch.setattr(main, "auth_enabled", lambda: True)

    def unexpected_session_lookup(*_args, **_kwargs):
        raise AssertionError("public health probes must not read an authentication session")

    monkeypatch.setattr(main, "session_identity", unexpected_session_lookup)
    with TestClient(main.app) as client:
        for path, check in (
            ("/health/startup", "startup"),
            ("/health/readiness", "readiness"),
            ("/health/liveness", "liveness"),
        ):
            response = client.get(path)
            assert response.status_code == 200
            assert response.headers["cache-control"] == "no-store"
            assert response.json()["check"] == check
            assert set(response.json()) == {
                "schema_version", "check", "status", "healthy", "meaning",
            }

        legacy = client.get("/health")
        assert legacy.status_code == 200
        assert legacy.json() == {
            "status": "ok",
            "version": main.APP_VERSION,
            "build_id": main.BUILD_ID,
            "build_commit": main.BUILD_COMMIT,
        }


def test_readiness_returns_503_before_shutdown_cleanup(monkeypatch) -> None:
    stopped_while_not_ready = []

    def record_stop(*_args, **_kwargs):
        stopped_while_not_ready.append(lifecycle.probe_result("readiness")[0] == 503)

    monkeypatch.setattr(main, "stop_derived_job_worker", record_stop)
    with TestClient(main.app) as client:
        assert client.get("/health/readiness").status_code == 200
    assert stopped_while_not_ready == [True]
    assert lifecycle.lifecycle_phase() == "stopped"


def test_safely_fenced_compaction_recovery_still_allows_http_readiness(monkeypatch) -> None:
    monkeypatch.setattr(
        main,
        "recover_incomplete_compactions",
        lambda *_args: {"resolved": 0, "recovery_required": 1},
    )

    def unexpected_worker_start(*_args, **_kwargs):
        raise AssertionError("workers must stay fenced while compaction recovery is unresolved")

    monkeypatch.setattr(main, "start_derived_job_worker", unexpected_worker_start)
    with TestClient(main.app) as client:
        assert client.get("/health/startup").status_code == 200
        assert client.get("/health/readiness").status_code == 200


def test_fatal_startup_failure_is_not_reported_as_started(monkeypatch) -> None:
    def fail_startup(*_args, **_kwargs):
        raise RuntimeError("fatal initialization failure")

    monkeypatch.setattr(main, "configure_database", fail_startup)

    async def run_failed_lifespan() -> None:
        async with main.lifespan(main.app):
            raise AssertionError("failed startup must not yield")

    with pytest.raises(RuntimeError, match="fatal initialization failure"):
        asyncio.run(run_failed_lifespan())
    assert lifecycle.lifecycle_phase() == "failed"
    assert lifecycle.probe_result("startup")[0] == 503
    assert lifecycle.probe_result("readiness")[0] == 503

    lifecycle.begin_startup()
    assert lifecycle.lifecycle_phase() == "starting"
    lifecycle.mark_stopped()


def test_probe_route_functions_do_not_touch_database_disk_workers_or_network(monkeypatch) -> None:
    forbidden = (
        "configure_database",
        "connect_database",
        "storage_status",
        "start_storage_job",
        "start_derived_job_worker",
        "schedule_worker",
    )

    def fail(*_args, **_kwargs):
        raise AssertionError("probe performed a forbidden external check")

    for name in forbidden:
        monkeypatch.setattr(main, name, fail)

    lifecycle.mark_ready()

    async def exercise_routes() -> None:
        for route, check in (
            (main.startup_health, "startup"),
            (main.readiness_health, "readiness"),
            (main.liveness_health, "liveness"),
        ):
            assert inspect.iscoroutinefunction(route)
            response = await route()
            assert response.status_code == 200
            assert response.headers["cache-control"] == "no-store"
            assert _body(response)["check"] == check

    asyncio.run(exercise_routes())
    lifecycle.mark_stopped()
