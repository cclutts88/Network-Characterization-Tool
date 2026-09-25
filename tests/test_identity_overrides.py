from __future__ import annotations

from fastapi.testclient import TestClient

from app.identity_overrides import (
    apply_analysis_os_overrides,
    delete_os_override,
    inference_review_history,
    list_os_overrides,
    os_override_history,
    set_os_override,
    set_inference_review,
)
from app.main import app
from app.os_inference import authoritative_os, infer_os_identity


def test_override_preserves_scanner_os_and_becomes_authoritative(tmp_path):
    db_path = tmp_path / "analyzer.db"
    saved = set_os_override(
        db_path,
        ip="10.0.0.20",
        mac="00-11-22-33-44-55",
        os_name="Windows Server 2022",
        analyst="Casey",
        reason="Confirmed in the virtualization console",
        scanner_os="Linux 5.x",
    )
    analysis = {
        "hosts": [{
            "ip": "10.0.0.20",
            "mac": "00:11:22:33:44:55",
            "os": "Linux 5.x",
            "ports": [{"port": 445, "protocol": "tcp", "service": "microsoft-ds"}],
        }]
    }

    apply_analysis_os_overrides(analysis, db_path)
    host = analysis["hosts"][0]

    assert saved["identity_key"] == "mac:00:11:22:33:44:55"
    assert host["scanner_os"] == "Linux 5.x"
    assert host["effective_os"] == "Windows Server 2022"
    assert host["os"] == "Linux 5.x"
    assert host["os_disagreement"] is True
    assert authoritative_os(host) == "Windows Server 2022"
    assert infer_os_identity(host) is None


def test_override_can_follow_an_ip_when_no_mac_is_known(tmp_path):
    db_path = tmp_path / "analyzer.db"
    set_os_override(
        db_path,
        ip="10.0.0.21",
        os_name="Ubuntu 24.04",
        analyst="Jordan",
        reason="Authenticated console observation",
    )
    analysis = {"hosts": [{"ip": "10.0.0.21", "os": "", "ports": []}]}

    apply_analysis_os_overrides(analysis, db_path)

    assert analysis["hosts"][0]["effective_os"] == "Ubuntu 24.04"
    assert analysis["hosts"][0]["os_disagreement"] is False


def test_update_and_delete_are_retained_in_audit_history(tmp_path):
    db_path = tmp_path / "analyzer.db"
    first = set_os_override(
        db_path,
        ip="10.0.0.22",
        os_name="Windows 10",
        analyst="Morgan",
        reason="Operator confirmed",
    )
    set_os_override(
        db_path,
        ip="10.0.0.22",
        os_name="Windows 11",
        analyst="Morgan",
        reason="Corrected after local login",
    )
    delete_os_override(
        db_path,
        first["identity_key"],
        analyst="Morgan",
        reason="Host was reimaged",
    )

    assert list_os_overrides(db_path) == []
    history = os_override_history(db_path, first["identity_key"])
    assert [item["action"] for item in history] == ["delete", "set", "set"]
    assert history[0]["reason"] == "Host was reimaged"


def test_os_override_api_validates_and_audits(monkeypatch, tmp_path):
    db_path = tmp_path / "analyzer.db"
    monkeypatch.setattr("app.main.DB_PATH", db_path)

    with TestClient(app) as client:
        response = client.post("/api/os-overrides", json={
            "ip": "10.0.0.23",
            "os_name": "Rocky Linux 9",
            "analyst": "Taylor",
            "reason": "Console banner",
            "scanner_os": "Linux",
        })
        assert response.status_code == 200
        key = response.json()["identity_key"]
        assert client.get("/api/os-overrides").json()[0]["os_name"] == "Rocky Linux 9"
        assert len(client.get(
            "/api/os-overrides/history", params={"identity_key": key}
        ).json()) == 1
        deleted = client.request("DELETE", f"/api/os-overrides/{key}", json={
            "analyst": "Taylor", "reason": "Correction no longer applies",
        })
        assert deleted.status_code == 200
        assert client.get("/api/os-overrides").json() == []


def test_inference_review_tracks_exact_evidence_and_stales_on_change(tmp_path):
    db_path = tmp_path / "analyzer.db"
    inference = {
        "family": "Windows",
        "display": "Windows (inferred)",
        "confidence": "medium",
        "evidence": ["445/tcp · microsoft-ds"],
        "source": "service_and_device_evidence",
    }
    review = set_inference_review(
        db_path,
        ip="10.0.0.30",
        inference=inference,
        status="investigate",
        analyst="Riley",
        reason="Need console confirmation",
    )
    analysis = {"hosts": [{
        "ip": "10.0.0.30", "os": "", "os_inference": inference, "ports": [],
    }]}

    apply_analysis_os_overrides(analysis, db_path)
    assert analysis["hosts"][0]["os_inference_review"]["current"] is True
    assert review["status"] == "investigate"

    analysis["hosts"][0]["os_inference"] = {
        **inference, "evidence": ["445/tcp · microsoft-ds", "135/tcp · msrpc"],
    }
    apply_analysis_os_overrides(analysis, db_path)
    assert analysis["hosts"][0]["os_inference_review"]["current"] is False
    assert len(inference_review_history(db_path, review["identity_key"])) == 1


def test_inference_review_api_retains_decision(monkeypatch, tmp_path):
    db_path = tmp_path / "analyzer.db"
    monkeypatch.setattr("app.main.DB_PATH", db_path)
    payload = {
        "ip": "10.0.0.31",
        "inference": {
            "family": "Linux / Unix-like", "confidence": "high",
            "evidence": ["Linux fingerprint: 22/tcp OpenSSH"],
        },
        "status": "confirmed",
        "analyst": "Avery",
        "reason": "Banner agrees with managed host inventory",
    }

    with TestClient(app) as client:
        response = client.post("/api/os-inference-reviews", json=payload)
        assert response.status_code == 200
        key = response.json()["identity_key"]
        history = client.get(
            "/api/os-inference-reviews/history", params={"identity_key": key}
        )
        assert history.status_code == 200
        assert history.json()[0]["status"] == "confirmed"
