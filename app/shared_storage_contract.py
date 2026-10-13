from __future__ import annotations

import hashlib
import json


CONTRACT_VERSION = 1


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def shared_storage_contract() -> dict[str, object]:
    """Return the reviewed Gate 7 decision without deployment credentials."""
    body: dict[str, object] = {
        "contract_version": CONTRACT_VERSION,
        "standalone_profile": {
            "profile_id": "standalone-sqlite-local-artifacts-v1",
            "database": "embedded-sqlite",
            "artifact_store": "local-content-addressed-filesystem",
            "application_replicas": 1,
            "required_for_core_offline_use": True,
        },
        "multiple_replica_target": {
            "profile_id": "postgresql-shared-artifacts-v1",
            "database": "postgresql",
            "artifact_store": "s3-compatible-immutable-content-addressed-objects",
            "artifact_key_template": "sha256/{prefix}/{sha256}",
            "database_is_evidence_authority": True,
            "filesystem_paths_are_shared_identity": False,
            "implementation_status": "selected-not-implemented",
        },
        "artifact_invariants": [
            "sha256-and-size-verified-before-publication",
            "conditional-create-without-overwrite",
            "incomplete-uploads-remain-private",
            "listing-is-never-evidence-authority",
            "deletion-requires-fenced-maintenance-and-dry-run",
            "credentials-never-enter-receipts",
        ],
        "transaction_invariants": [
            "database-time-leases",
            "monotonic-fencing-epochs",
            "exact-claim-rechecked-in-publication-transaction",
            "network-contact-never-transfers-on-expiry",
            "singleton-migration-backfill-and-compaction",
        ],
        "migration": {
            "mode": "offline-versioned-cutover",
            "dual_write": False,
            "source_backup_required": True,
            "fresh_target_generation_required": True,
            "full_artifact_inventory_required": True,
            "cutover_receipt_required": True,
        },
        "rollback": {
            "before_target_write": "restart-unchanged-verified-sqlite-source",
            "after_target_write": "preserve-target-and-restore-to-separate-generation",
            "post_write_export_required": True,
            "post_write_reconciliation_required": True,
            "attributed_decision_receipt_required": True,
            "automatic_reverse_migration": False,
        },
        "multiple_replica_enabled": False,
        "next_gate": "gate-8-concurrency-failure-and-load-testing",
    }
    return {
        **body,
        "contract_digest": hashlib.sha256(_canonical(body)).hexdigest(),
    }


def validate_shared_storage_contract(value: object) -> bool:
    if not isinstance(value, dict):
        return False
    expected = shared_storage_contract()
    if value != expected:
        return False
    supplied = value.get("contract_digest")
    body = {key: item for key, item in value.items() if key != "contract_digest"}
    return supplied == hashlib.sha256(_canonical(body)).hexdigest()


def shared_storage_status() -> dict[str, object]:
    contract = shared_storage_contract()
    target = contract["multiple_replica_target"]
    return {
        "active_profile": contract["standalone_profile"]["profile_id"],
        "active_database": "SQLite",
        "active_artifact_store": "Local content-addressed files",
        "multiple_replica_target": target["profile_id"],
        "multiple_replica_enabled": False,
        "gate": "Gate 7 architecture selected; implementation and Gate 8 remain open",
        "contract_version": CONTRACT_VERSION,
        "contract_digest": contract["contract_digest"],
    }
