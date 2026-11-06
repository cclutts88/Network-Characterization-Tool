from __future__ import annotations

import pytest
from fastapi import HTTPException

import app.main as main


def _changing_token(monkeypatch):
    values = iter(("authority-before", "authority-after"))
    monkeypatch.setattr(main, "_hunting_retirement_token", lambda: next(values))


def test_reach_context_fails_closed_when_retirement_changes_mid_route(monkeypatch):
    _changing_token(monkeypatch)
    monkeypatch.setattr(main, "_latest_network_evidence", lambda: {
        "hosts": [{"ip": "10.0.0.10"}], "findings": [],
    })
    monkeypatch.setattr(main, "_latest_device_reachability_evidence", lambda: [])
    monkeypatch.setattr(main, "list_saved_networks", lambda _path: [])
    monkeypatch.setattr(main, "get_external_wan_gateway", lambda _path: None)

    with pytest.raises(HTTPException) as raised:
        main.reachability_context()

    assert raised.value.status_code == 409
    assert "Reach" in str(raised.value.detail)


def test_reach_evaluation_fails_closed_when_retirement_changes_mid_route(monkeypatch):
    _changing_token(monkeypatch)
    monkeypatch.setattr(main, "_latest_network_evidence", lambda: {
        "hosts": [], "findings": [],
    })
    monkeypatch.setattr(main, "_latest_device_reachability_evidence", lambda: [])
    monkeypatch.setattr(main, "list_saved_networks", lambda _path: [])

    with pytest.raises(HTTPException) as raised:
        main.evaluate_retained_reachability(main.ReachabilityQuery(
            source="10.0.0.10", destination="10.0.0.20",
            protocol="tcp", port=443,
        ))

    assert raised.value.status_code == 409
    assert "Reach" in str(raised.value.detail)


def test_changes_over_time_fails_closed_when_retirement_changes_mid_route(monkeypatch):
    _changing_token(monkeypatch)
    monkeypatch.setattr(main, "list_prepared_scan_group_metadata", lambda _path: [])

    with pytest.raises(HTTPException) as raised:
        main.analyze_current_network_changes(limit=5, offset=0, revision=None)

    assert raised.value.status_code == 409
    assert "Changes Over Time" in str(raised.value.detail)
