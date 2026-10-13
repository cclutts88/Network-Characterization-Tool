from __future__ import annotations

import json

from fastapi.testclient import TestClient

from app.main import app
from app.shell_ui import SHELL_SCRIPT
from app.storage_ui import storage_page
from app.shared_storage_contract import (
    shared_storage_contract,
    shared_storage_status,
    validate_shared_storage_contract,
)


def test_contract_preserves_standalone_and_blocks_multiple_replicas() -> None:
    contract = shared_storage_contract()

    assert contract["standalone_profile"] == {
        "profile_id": "standalone-sqlite-local-artifacts-v1",
        "database": "embedded-sqlite",
        "artifact_store": "local-content-addressed-filesystem",
        "application_replicas": 1,
        "required_for_core_offline_use": True,
    }
    assert contract["multiple_replica_target"]["database"] == "postgresql"
    assert contract["multiple_replica_target"]["implementation_status"] == (
        "selected-not-implemented"
    )
    assert contract["multiple_replica_enabled"] is False
    assert contract["migration"]["dual_write"] is False
    assert contract["migration"]["full_artifact_inventory_required"] is True
    assert contract["rollback"]["post_write_export_required"] is True
    assert contract["rollback"]["post_write_reconciliation_required"] is True
    assert contract["rollback"]["attributed_decision_receipt_required"] is True
    assert contract["rollback"]["automatic_reverse_migration"] is False
    assert validate_shared_storage_contract(contract) is True


def test_contract_digest_detects_architecture_drift() -> None:
    changed = json.loads(json.dumps(shared_storage_contract()))
    changed["multiple_replica_enabled"] = True

    assert validate_shared_storage_contract(changed) is False


def test_contract_rejects_removing_post_write_recovery_requirements() -> None:
    for requirement in (
        "post_write_export_required",
        "post_write_reconciliation_required",
        "attributed_decision_receipt_required",
    ):
        changed = json.loads(json.dumps(shared_storage_contract()))
        changed["rollback"].pop(requirement)

        assert validate_shared_storage_contract(changed) is False


def test_contract_contains_no_secret_or_endpoint_material() -> None:
    serialized = json.dumps(shared_storage_contract(), sort_keys=True).lower()

    assert "password" not in serialized
    assert "secret" not in serialized
    assert "postgresql://" not in serialized
    assert "access_key" not in serialized


def test_status_reports_current_runtime_without_claiming_gate_eight() -> None:
    status = shared_storage_status()

    assert status["active_database"] == "SQLite"
    assert status["multiple_replica_enabled"] is False
    assert "Gate 8" in status["gate"]
    assert len(status["contract_digest"]) == 64


def test_storage_architecture_status_is_available_to_system_health() -> None:
    response = TestClient(app).get("/api/system/storage-architecture")

    assert response.status_code == 200
    assert response.json()["active_database"] == "SQLite"
    assert response.json()["multiple_replica_enabled"] is False


def test_system_health_explains_storage_architecture_and_guide() -> None:
    html = storage_page().body.decode()

    assert 'id="storageArchitecturePanel"' in html
    assert "PostgreSQL + shared immutable object storage" in html
    assert "Multiple application instances" in html
    assert 'id="storageArchitectureMeaningSummary"' in html
    assert "storageArchitecturePanel:['Storage deployment architecture'" in SHELL_SCRIPT
    assert "storageArchitectureMeaningSummary:['Why multiple instances are still disabled'" in SHELL_SCRIPT
    assert "It does not enable PostgreSQL or shared object storage" in SHELL_SCRIPT
