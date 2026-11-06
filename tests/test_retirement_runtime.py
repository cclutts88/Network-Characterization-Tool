from pathlib import Path

import pytest
from starlette.requests import Request

from app.database import connect_database
from app.evidence_retirement import init_evidence_retirement_storage
from app.retirement_guard import provision_retirement_guard
import app.retirement_runtime as runtime
import app.main as main


def _foundation(tmp_path: Path):
    data = tmp_path / "mission-data"
    guard = tmp_path / "retirement-guard"
    data.mkdir()
    db_path = data / "analyzer.db"
    with connect_database(db_path) as db:
        db.execute("CREATE TABLE source(id TEXT PRIMARY KEY)")
    init_evidence_retirement_storage(db_path)
    return db_path, data, guard


def test_disabled_runtime_keeps_operator_controls_fail_closed(tmp_path, monkeypatch):
    db_path, data, _guard = _foundation(tmp_path)
    monkeypatch.setenv("NCT_RETIREMENT_GUARD_MODE", "disabled")
    status = runtime.require_retirement_startup_ready(db_path, data)
    assert not status.ready
    with pytest.raises(runtime.RetirementRuntimeError, match="disabled"):
        runtime.require_retirement_controls_ready()


def test_unconfigured_production_default_is_required_and_refused(monkeypatch):
    monkeypatch.delenv("NCT_RETIREMENT_GUARD_MODE", raising=False)
    monkeypatch.delenv("NCT_RETIREMENT_GUARD_DIR", raising=False)
    monkeypatch.delenv("NCT_RETIREMENT_DATA_IDENTITY", raising=False)
    with pytest.raises(runtime.RetirementRuntimeError, match="not configured"):
        runtime.runtime_config()


def test_required_runtime_binds_and_admits_protected_fresh_data(tmp_path, monkeypatch):
    db_path, data, guard = _foundation(tmp_path)
    provision_retirement_guard(
        guard, installation_id="installation-a", data_identity="volume:a",
    )
    monkeypatch.setenv("NCT_RETIREMENT_GUARD_MODE", "required")
    monkeypatch.setenv("NCT_RETIREMENT_GUARD_DIR", str(guard))
    monkeypatch.setenv("NCT_RETIREMENT_DATA_IDENTITY", "volume:a")
    status = runtime.require_retirement_startup_ready(db_path, data)
    assert status.ready and status.revision == 0
    controls = runtime.require_retirement_controls_ready()
    assert controls.ready and controls.revision == 0


def test_required_runtime_refuses_unprovisioned_or_wrong_authority(
    tmp_path, monkeypatch,
):
    db_path, data, guard = _foundation(tmp_path)
    guard.mkdir()
    monkeypatch.setenv("NCT_RETIREMENT_GUARD_MODE", "required")
    monkeypatch.setenv("NCT_RETIREMENT_GUARD_DIR", str(guard))
    monkeypatch.setenv("NCT_RETIREMENT_DATA_IDENTITY", "volume:a")
    with pytest.raises(runtime.RetirementRuntimeError, match="blocked startup"):
        runtime.require_retirement_startup_ready(db_path, data)
    with pytest.raises(runtime.RetirementRuntimeError):
        runtime.require_retirement_controls_ready()


@pytest.mark.parametrize("value", ["", "maybe", "enabled"])
def test_invalid_runtime_mode_is_rejected(monkeypatch, value):
    monkeypatch.setenv("NCT_RETIREMENT_GUARD_MODE", value)
    with pytest.raises(runtime.RetirementRuntimeError, match="invalid"):
        runtime.runtime_config()


def test_ordinary_api_requests_revalidate_guard_instead_of_trusting_startup_cache(
    tmp_path, monkeypatch,
):
    db_path, data, guard = _foundation(tmp_path)
    provision_retirement_guard(
        guard, installation_id="installation-a", data_identity="volume:a",
    )
    monkeypatch.setenv("NCT_RETIREMENT_GUARD_MODE", "required")
    monkeypatch.setenv("NCT_RETIREMENT_GUARD_DIR", str(guard))
    monkeypatch.setenv("NCT_RETIREMENT_DATA_IDENTITY", "volume:a")
    monkeypatch.setattr(main, "DB_PATH", db_path)
    monkeypatch.setattr(main, "DATA_DIR", data)
    assert runtime.require_retirement_startup_ready(db_path, data).ready
    request = Request({
        "type": "http",
        "method": "GET",
        "path": "/api/analysis/network",
        "headers": [],
        "query_string": b"",
        "scheme": "http",
        "server": ("test", 80),
        "client": ("test", 1),
    })
    assert main._retirement_projection_hold(request) is None

    (guard / "lineage-binding.json").write_text("{}", encoding="utf-8")
    held = main._retirement_projection_hold(request)
    assert held is not None
    assert held.status_code == 503


def test_retirement_requires_an_attributable_analyst_or_administrator(monkeypatch):
    request = Request({
        "type": "http", "method": "POST", "path": "/api/evidence-retirements",
        "headers": [], "query_string": b"", "scheme": "http",
        "server": ("test", 80), "client": ("test", 1),
    })
    monkeypatch.setattr(main, "auth_enabled", lambda: True)
    request.state.analyst = {"username": "viewer", "role": "viewer"}
    with pytest.raises(main.HTTPException) as viewer:
        main.require_retirement_operator(request)
    assert viewer.value.status_code == 403

    request.state.analyst = {"username": "alice", "role": "analyst"}
    assert main.require_retirement_operator(request) == "alice"
    request.state.analyst = {"username": "admin", "role": "admin"}
    assert main.require_retirement_operator(request) == "admin"

    monkeypatch.setattr(main, "auth_enabled", lambda: False)
    with pytest.raises(main.HTTPException) as unauthenticated:
        main.require_retirement_operator(request)
    assert unauthenticated.value.status_code == 403
