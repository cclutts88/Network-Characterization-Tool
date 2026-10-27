from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
import uuid
from typing import Any

from app.database import connect_database
from app.schema_compatibility import (
    MIGRATION_PLAN,
    SCHEMA_CONTRACT_VERSION,
    WRITABLE_SCHEMA_VERSION,
    migration_plan_digest,
    schema_fingerprint,
)
from app.scan_history_index import sync_scan_history_manifest


PAUSE_FOLDER = "recovery"
PAUSE_FILE = "scan-work-paused.json"
UPDATE_PAUSE_CONTRACT = "nct-update-pause-v1"
PAUSE_CONTRACT = "nct-unfinished-work-recovery-pause-v2"
LEGACY_PAUSE_CONTRACT = "nct-scan-work-recovery-pause-v1"
ACTIVE_SCAN_STATES = {
    "queued", "dispatching", "running", "awaiting_fallback_approval"
}
TERMINAL_SCAN_STATES = {
    "completed", "completed_without_nmap", "failed", "cancelled",
    "interrupted", "blocked_mission_environment", "stopped_no_targets", "timed_out",
}
SCAN_CAPACITY_LEASE_KEY = "scan-capacity:primary"
OPEN_OCCURRENCE_STATES = {"waiting", "preparing", "active", "needs_attention"}
KNOWN_OCCURRENCE_STATES = OPEN_OCCURRENCE_STATES | {"complete", "cancelled", "missed"}
KNOWN_CHUNK_STATES = {
    "waiting", "preparing", "active", "complete", "cancelled", "needs_attention"
}
KNOWN_CONTACT_PHASES = {
    "not_started", "preparing", "contact_starting", "contact_active",
    "contact_stopped", "complete", "uncertain",
}


class ScanWorkRecoveryError(RuntimeError):
    pass


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def content_digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def pause_path(data_dir: Path) -> Path:
    return data_dir / PAUSE_FOLDER / PAUSE_FILE


def recovery_pause(data_dir: Path) -> dict[str, Any] | None:
    update_path = Path(data_dir) / PAUSE_FOLDER / "update-maintenance.json"
    if update_path.exists() or update_path.is_symlink():
        # A malformed marker also fences work. Only the independent host helper
        # clears this marker after runtime/account/evidence verification.
        return {"contract": UPDATE_PAUSE_CONTRACT, "state": "update_in_progress",
            "reason": "The independent recovery console is verifying this NCT version",
            "scan_contact_paused": True, "passive_contact_paused": True,
            "device_contact_paused": True, "local_processing_paused": True,
            "storage_maintenance_paused": True, "path": str(update_path)}
    path = pause_path(data_dir)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, ValueError, TypeError):
        return {
            "state": "invalid",
            "reason": "The scan recovery pause record cannot be read safely.",
            "scan_contact_paused": True,
            "passive_contact_paused": True,
            "device_contact_paused": True,
            "local_processing_paused": True,
            "storage_maintenance_paused": True,
            "path": str(path),
        }
    if not isinstance(value, dict) or value.get("state") not in {
        "diagnosis_required", "review_required"
    }:
        return {
            "state": "invalid",
            "reason": "The scan recovery pause record has an unsupported format.",
            "scan_contact_paused": True,
            "passive_contact_paused": True,
            "device_contact_paused": True,
            "local_processing_paused": True,
            "storage_maintenance_paused": True,
            "path": str(path),
        }
    contract = value.get("contract")
    modern = contract == PAUSE_CONTRACT
    if contract not in {LEGACY_PAUSE_CONTRACT, PAUSE_CONTRACT}:
        return {
            "state": "invalid",
            "reason": "The scan recovery pause record uses an unsupported contract.",
            "scan_contact_paused": True,
            "passive_contact_paused": True,
            "device_contact_paused": True,
            "local_processing_paused": True,
            "storage_maintenance_paused": True,
            "path": str(path),
        }
    required_gates = (
        "scan_contact_paused", "passive_contact_paused",
        "device_contact_paused", "local_processing_paused",
        "storage_maintenance_paused",
    ) if modern else ("scan_contact_paused", "passive_contact_paused")
    if any(name in value and not isinstance(value[name], bool) for name in required_gates) or (
        modern and any(name not in value for name in required_gates)
    ):
        return {
            "state": "invalid",
            "reason": "The scan recovery pause record has invalid hold fields.",
            "scan_contact_paused": True,
            "passive_contact_paused": True,
            "device_contact_paused": True,
            "local_processing_paused": True,
            "storage_maintenance_paused": True,
            "path": str(path),
        }
    return {
        **value,
        "scan_contact_paused": bool(value.get("scan_contact_paused", True)),
        "passive_contact_paused": bool(value.get("passive_contact_paused", True)),
        "device_contact_paused": bool(value.get("device_contact_paused", modern)),
        "local_processing_paused": bool(value.get("local_processing_paused", modern)),
        "storage_maintenance_paused": bool(value.get("storage_maintenance_paused", modern)),
        "path": str(path),
    }


def scan_contact_paused(data_dir: Path) -> bool:
    current = recovery_pause(data_dir)
    return bool(current and current.get("scan_contact_paused", True))


def passive_contact_paused(data_dir: Path) -> bool:
    current = recovery_pause(data_dir)
    return bool(current and current.get("passive_contact_paused", True))


def device_contact_paused(data_dir: Path) -> bool:
    current = recovery_pause(data_dir)
    return bool(current and current.get("device_contact_paused", False))


def local_processing_paused(data_dir: Path) -> bool:
    current = recovery_pause(data_dir)
    return bool(current and current.get("local_processing_paused", False))


def storage_maintenance_paused(data_dir: Path) -> bool:
    current = recovery_pause(data_dir)
    return bool(current and current.get("storage_maintenance_paused", False))


def _save_or_remove_pause(data_dir: Path, current: dict[str, Any]) -> None:
    current.pop("path", None)
    gates = (
        "scan_contact_paused", "passive_contact_paused", "device_contact_paused",
        "local_processing_paused", "storage_maintenance_paused",
    )
    if any(bool(current.get(name, False)) for name in gates):
        write_recovery_pause(data_dir, current)
    else:
        pause_path(data_dir).unlink(missing_ok=True)


def write_recovery_pause(data_dir: Path, value: dict[str, Any]) -> Path:
    folder = data_dir / PAUSE_FOLDER
    folder.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = pause_path(data_dir)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.chmod(0o600)
    temporary.replace(path)
    return path


def _remaining_gate_names(current: dict[str, Any]) -> list[str]:
    labels = {
        "scan_contact_paused": "Nmap scans",
        "passive_contact_paused": "Arkime pulls",
        "device_contact_paused": "device contact",
        "local_processing_paused": "local processing",
        "storage_maintenance_paused": "storage maintenance",
    }
    return [label for gate, label in labels.items() if current.get(gate, False)]


def _review_reason(current: dict[str, Any], resumed: str) -> str:
    remaining = _remaining_gate_names(current)
    if not remaining:
        return f"{resumed} was reviewed; all recovery holds were cleared"
    return f"{resumed} was reviewed; still paused: {', '.join(remaining)}"


def clear_recovery_pause(data_dir: Path, expected_plan_digest: str) -> bool:
    current = recovery_pause(data_dir)
    if current is None:
        return False
    if current.get("state") != "review_required":
        raise ScanWorkRecoveryError("Recovery has not reached administrator review")
    if current.get("plan_digest") != expected_plan_digest:
        raise ScanWorkRecoveryError("The saved recovery plan changed")
    if not current.get("scan_contact_paused", True):
        return False
    current["scan_contact_paused"] = False
    current["scan_resumed_at"] = utc_now()
    current["reason"] = _review_reason(current, "Nmap scan work")
    _save_or_remove_pause(data_dir, current)
    return True


def clear_passive_recovery_pause(data_dir: Path, expected_plan_digest: str) -> bool:
    current = recovery_pause(data_dir)
    if current is None:
        return False
    if current.get("state") != "review_required":
        raise ScanWorkRecoveryError("Recovery has not reached administrator review")
    if current.get("plan_digest") != expected_plan_digest:
        raise ScanWorkRecoveryError("The saved recovery plan changed")
    if not current.get("passive_contact_paused", True):
        return False
    current["passive_contact_paused"] = False
    current["passive_resumed_at"] = utc_now()
    current["reason"] = _review_reason(current, "Arkime pull work")
    _save_or_remove_pause(data_dir, current)
    return True


def clear_recovery_gate(
    data_dir: Path, expected_plan_digest: str, gate: str,
) -> bool:
    current = validate_recovery_gate(data_dir, expected_plan_digest, gate)
    if current is None:
        return False
    current[gate] = False
    current[f"{gate.removesuffix('_paused')}_resumed_at"] = utc_now()
    resumed = {
        "device_contact_paused": "Device contact",
        "local_processing_paused": "Local processing",
        "storage_maintenance_paused": "Storage maintenance",
    }[gate]
    current["reason"] = _review_reason(current, resumed)
    _save_or_remove_pause(data_dir, current)
    return True


def validate_recovery_gate(
    data_dir: Path, expected_plan_digest: str, gate: str,
) -> dict[str, Any] | None:
    """Validate one reviewed hold without changing the durable pause record."""
    allowed = {
        "device_contact_paused", "local_processing_paused",
        "storage_maintenance_paused",
    }
    if gate not in allowed:
        raise ScanWorkRecoveryError("Unknown recovery gate")
    current = recovery_pause(data_dir)
    if current is None:
        return None
    if current.get("state") != "review_required":
        raise ScanWorkRecoveryError("Recovery has not reached administrator review")
    if current.get("plan_digest") != expected_plan_digest:
        raise ScanWorkRecoveryError("The saved recovery plan changed")
    if not current.get(gate, False):
        return None
    return current


def _tables(connection: sqlite3.Connection) -> set[str]:
    return {str(row[0]) for row in connection.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    )}


def _snapshot_rows(
    connection: sqlite3.Connection,
    statement: str,
    parameters: tuple[Any, ...] = (),
) -> list[dict[str, Any]]:
    cursor = connection.execute(statement, parameters)
    columns = [str(item[0]) for item in cursor.description or ()]
    return [dict(zip(columns, row)) for row in cursor.fetchall()]


def _write_external_receipt(path: Path, receipt: dict[str, Any]) -> None:
    """Write the human-portable copy after the atomic database receipt exists."""
    path.write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    path.chmod(0o600)


def _validate_schema(connection: sqlite3.Connection) -> list[str]:
    blockers: list[str] = []
    tables = _tables(connection)
    required = {
        "nct_schema_state", "nct_schema_migrations", "scan_runs", "work_leases",
        "scan_schedule_occurrences", "scan_schedule_chunks", "scan_schedules",
        "scan_schedule_definitions", "scan_run_audit",
    }
    missing = sorted(required - tables)
    if missing:
        return ["Required recovery tables are missing: " + ", ".join(missing)]
    state = connection.execute(
        """SELECT schema_contract_version, schema_version, data_layout_contract,
                  migration_plan_digest, schema_fingerprint
             FROM nct_schema_state WHERE singleton=1"""
    ).fetchone()
    if state is None:
        return ["The saved schema authority record is missing"]
    contract, version, layout, plan, recorded = state
    if int(contract) != SCHEMA_CONTRACT_VERSION or int(version) != WRITABLE_SCHEMA_VERSION:
        blockers.append("The saved schema version is not the exact recovery-tool version")
    if str(layout) != "nct-data-layout-v1":
        blockers.append("The saved evidence layout is unfamiliar")
    if str(plan) != migration_plan_digest(MIGRATION_PLAN):
        blockers.append("The saved migration plan is unfamiliar")
    migrations = connection.execute(
        "SELECT migration_id, target_schema_version, status FROM nct_schema_migrations"
    ).fetchall()
    by_id = {str(row[0]): (int(row[1]), str(row[2])) for row in migrations}
    expected = {item: (index, "completed") for index, item in enumerate(MIGRATION_PLAN, 1)}
    if by_id != expected:
        blockers.append("The migration ledger is incomplete or contains unfamiliar work")
    if not blockers and str(recorded) != schema_fingerprint(connection):
        blockers.append("The live schema fingerprint does not match its saved authority")
    if "artifact_compaction_journal" in tables:
        unresolved = connection.execute(
            """SELECT COUNT(*) FROM artifact_compaction_journal
                 WHERE state IN ('preparing','prepared','replaced','recovery-required')"""
        ).fetchone()[0]
        if unresolved:
            blockers.append("Artifact compaction recovery is unresolved")
    return blockers


def _storage_status_record(data_dir: Path | None) -> dict[str, Any] | None:
    if data_dir is None:
        return None
    path = data_dir / "storage-health.json"
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        return {"state": "missing", "sha256": None, "size_bytes": 0}
    except OSError as exc:
        return {"state": "unreadable", "error": type(exc).__name__}
    try:
        value = json.loads(raw)
    except (ValueError, TypeError):
        value = None
    return {
        "state": "saved",
        "sha256": hashlib.sha256(raw).hexdigest(),
        "size_bytes": len(raw),
        "reported_status": value.get("status") if isinstance(value, dict) else "invalid",
    }


def _diagnose(
    connection: sqlite3.Connection, data_dir: Path | None = None,
) -> dict[str, Any]:
    blockers = _validate_schema(connection)
    available_tables = _tables(connection)
    quick = str(connection.execute("PRAGMA quick_check(1)").fetchone()[0])
    foreign = connection.execute("PRAGMA foreign_key_check").fetchmany(101)
    if quick != "ok":
        blockers.append("The saved database failed its quick integrity check")
    if foreign:
        blockers.append("The saved database has foreign-key errors")

    query_tables = {
        "scan_runs", "work_leases", "scan_schedule_occurrences",
        "scan_schedule_chunks", "scan_schedules", "scan_schedule_definitions",
    }
    if not query_tables.issubset(available_tables):
        result = {
            "contract": "nct-unfinished-work-recovery-v2",
            "safe_to_apply": False,
            "blockers": sorted(set(blockers)),
            "scans": [],
            "schedule_chunks": [],
            "schedule_occurrences": [],
            "schedules": [], "arkime_pulls": [], "device_contacts": [],
            "pipeline_attempts": [], "pipeline_intake": [],
            "device_vlan_intake": [], "storage_maintenance": [], "leases": [],
            "storage_status_record": _storage_status_record(data_dir),
            "affected_count": 0,
            "completed_evidence_action": "preserve",
            "automatic_contact_after_recovery": False,
        }
        result["plan_digest"] = content_digest(result)
        return result

    scans: list[dict[str, Any]] = []
    for rowid, run_id, status, manifest_json, created_at in connection.execute(
        "SELECT rowid,run_id,status,manifest_json,created_at FROM scan_runs ORDER BY rowid"
    ):
        try:
            manifest = json.loads(manifest_json)
        except (TypeError, ValueError):
            blockers.append(f"Scan {run_id} has malformed saved metadata")
            continue
        manifest_status = str(manifest.get("status") or "")
        if status != manifest_status:
            blockers.append(f"Scan {run_id} has conflicting saved status values")
        if status not in ACTIVE_SCAN_STATES | TERMINAL_SCAN_STATES:
            blockers.append(f"Scan {run_id} has unsupported state {status}")
        if status not in ACTIVE_SCAN_STATES:
            continue
        started = bool(manifest.get("started_at"))
        claim = manifest.get("execution_claim")
        action = "preserve_queue"
        reason = "Unstarted queued work keeps its original queue position"
        if status == "queued" and not started and not isinstance(claim, dict):
            action = "preserve_queue"
        elif status in {"queued", "dispatching"} and not started:
            action = "requeue_precontact"
            reason = "No network-contact start was recorded; stale ownership can be removed"
        else:
            action = "interrupt_for_review"
            reason = "Network contact may have begun; the original record must not resume"
        item = {
            "run_id": str(run_id), "rowid": int(rowid), "status": str(status),
            "created_at": str(created_at), "scheduled": bool(manifest.get("scheduled")),
            "started_at": manifest.get("started_at"), "action": action, "reason": reason,
            "manifest_digest": content_digest(manifest),
            "owner": manifest.get("owner") or manifest.get("created_by") or manifest.get("operator"),
            "scope": manifest.get("network_scope_context"),
            "targets": list(manifest.get("targets") or []),
            "profile": manifest.get("profile") or manifest.get("profile_name"),
        }
        scans.append(item)

    arkime_pulls: list[dict[str, Any]] = []
    for row in (_snapshot_rows(
        connection,
        """SELECT * FROM arkime_pull_runs
             WHERE state IN ('queued','running') ORDER BY queued_at,run_id""",
    ) if {"arkime_pull_runs", "arkime_pull_profiles"}.issubset(available_tables) else []):
        action = "preserve_queue" if row["state"] == "queued" else "interrupt_for_review"
        arkime_pulls.append({
            "run_id": row["run_id"], "profile_id": row["profile_id"],
            "state": row["state"], "window_start": row["query_start"],
            "window_end": row["query_end"], "action": action,
            "reason": (
                "The saved pull window remains queued" if action == "preserve_queue"
                else "Arkime contact began; retry must reuse this exact saved window"
            ),
            "record_digest": content_digest(row),
        })

    device_contacts: list[dict[str, Any]] = []
    device_lease_bindings: dict[str, tuple[Any, ...]] = {}
    for run in (_snapshot_rows(
        connection,
        """SELECT * FROM device_contact_runs
             WHERE state IN ('waiting','preparing','contact_starting','contact_active','needs_attention')
                OR active_attempt_number IS NOT NULL
             ORDER BY created_at,run_id""",
    ) if {"device_contact_runs", "device_contact_attempts", "device_contact_publications"}.issubset(available_tables) else []):
        attempts = _snapshot_rows(
            connection,
            "SELECT * FROM device_contact_attempts WHERE run_id=? ORDER BY attempt_number",
            (run["run_id"],),
        )
        publications = _snapshot_rows(
            connection,
            "SELECT * FROM device_contact_publications WHERE run_id=? ORDER BY prepared_at",
            (run["run_id"],),
        )
        active = next(
            (item for item in attempts if item["attempt_number"] == run["active_attempt_number"]),
            None,
        )
        if active is None and run["state"] == "needs_attention":
            active = next(
                (item for item in reversed(attempts) if item["state"] == "needs_attention"),
                None,
            )
        if run["active_attempt_number"] is not None and active is None:
            blockers.append(f"Device contact {run['run_id']} is missing its active attempt")
        force_review = bool(publications) or run["contact_phase"] not in {"not_started", "preparing"}
        action = (
            "preserve_review" if run["state"] == "needs_attention" else
            "interrupt_for_review" if force_review else "close_precontact"
        )
        if active:
            for prefix in ("run", "capacity"):
                device_lease_bindings[str(active[f"{prefix}_lease_key"])] = (
                    active[f"{prefix}_lease_id"], active["owner_id"],
                    int(active[f"{prefix}_lease_epoch"]),
                )
        device_contacts.append({
            "run_id": run["run_id"], "state": run["state"],
            "contact_phase": run["contact_phase"], "action": action,
            "reason": (
                "This contact is already retained for administrator review"
                if action == "preserve_review" else
                "Contact or file publication may have begun; administrator review is required"
                if force_review else
                "No contact start or publication was recorded; close the abandoned attempt"
            ),
            "run_record": run, "attempt_records": attempts,
            "publication_records": publications,
        })

    pipeline_attempts: list[dict[str, Any]] = []
    derived_lease_bindings: dict[str, tuple[Any, ...]] = {}
    for attempt in (_snapshot_rows(
        connection,
        """SELECT * FROM pipeline_job_attempts
             WHERE state IN ('queued','running') ORDER BY requested_at,attempt_id""",
    ) if {"pipeline_jobs", "pipeline_job_attempts", "pipeline_job_requests"}.issubset(available_tables) else []):
        job_rows = _snapshot_rows(
            connection, "SELECT * FROM pipeline_jobs WHERE job_id=?", (attempt["job_id"],),
        )
        if len(job_rows) != 1:
            blockers.append(f"Pipeline attempt {attempt['attempt_id']} has no exact saved job")
        action = "preserve_queue" if attempt["state"] == "queued" else "interrupt_and_requeue"
        if attempt["state"] == "running":
            derived_lease_bindings[f"derived-attempt:{attempt['attempt_id']}"] = (
                attempt["claim_token"], attempt["lease_owner"],
                int(attempt["lease_epoch"] or 0),
            )
        pipeline_attempts.append({
            "attempt_id": attempt["attempt_id"], "job_id": attempt["job_id"],
            "attempt_number": int(attempt["attempt_number"]), "state": attempt["state"],
            "action": action,
            "reason": (
                "The local analysis attempt remains queued" if action == "preserve_queue"
                else "The former local worker stopped; retain this attempt and queue one replacement"
            ),
            "attempt_record": attempt, "job_record": job_rows[0] if job_rows else None,
        })

    pipeline_intake = _snapshot_rows(
        connection,
        """SELECT * FROM pipeline_admission_intents
             WHERE state='pending' ORDER BY created_at,intent_id""",
    ) if "pipeline_admission_intents" in available_tables else []
    device_vlan_intake = _snapshot_rows(
        connection,
        """SELECT * FROM device_vlan_admission_intents
             WHERE state='pending' ORDER BY created_at,intent_id""",
    ) if "device_vlan_admission_intents" in available_tables else []

    leases = _snapshot_rows(
        connection,
        """SELECT * FROM work_leases
             WHERE state IN ('active','recovery_required') ORDER BY lease_key""",
    )
    storage_maintenance: list[dict[str, Any]] = []
    for item in leases:
        key = str(item["lease_key"])
        binding = device_lease_bindings.get(key) or derived_lease_bindings.get(key)
        if key == SCAN_CAPACITY_LEASE_KEY:
            continue
        if key == "storage-maintenance" and str(item["work_kind"]).startswith("storage-"):
            storage_maintenance.append({
                "lease_key": key, "state": item["state"],
                "action": (
                    "mark_recovery_required" if item["state"] == "active"
                    else "preserve_safety_stop"
                ),
                "reason": "Storage ownership must be reviewed before maintenance resumes",
                "lease_record": item,
            })
            continue
        if binding is None:
            blockers.append(f"Unsupported active work lease {key} ({item['work_kind']})")
            continue
        expected_id, expected_owner, expected_epoch = binding
        if item["state"] == "recovery_required":
            matches = (
                item["lease_id"] is None and item["owner_id"] is None
                and int(item["fencing_epoch"]) == int(expected_epoch)
            )
        else:
            matches = (
                item["lease_id"] == expected_id and item["owner_id"] == expected_owner
                and int(item["fencing_epoch"]) == int(expected_epoch)
            )
        if not matches:
            blockers.append(f"Work lease {key} does not match its saved attempt ownership")

    chunks: list[dict[str, Any]] = []
    affected_occurrences: set[str] = set()
    for row in connection.execute(
        """SELECT occurrence_id,chunk_number,state,contact_phase,scan_run_id,
                  target_count,attempt_count,status_reason,targets_digest,targets_json,
                  last_fencing_epoch,created_at,started_at,completed_at
             FROM scan_schedule_chunks
            WHERE state IN ('waiting','preparing','active','needs_attention')
            ORDER BY occurrence_id,chunk_number"""
    ):
        (occurrence_id, number, state, phase, run_id, target_count, attempts, reason,
         targets_digest, targets_json, fencing_epoch, created_at, started_at,
         completed_at) = row
        if state not in KNOWN_CHUNK_STATES or phase not in KNOWN_CONTACT_PHASES:
            blockers.append(f"Schedule chunk {occurrence_id}/{number} has unfamiliar state")
        action = "preserve_waiting"
        explanation = "This scheduled chunk has not started"
        if state == "waiting" and phase == "not_started" and not run_id:
            pass
        elif state in {"waiting", "preparing"} and phase in {"not_started", "preparing"}:
            action = "hold_for_review"
            explanation = "The frozen targets are preserved, but stale scheduled ownership needs review"
            affected_occurrences.add(str(occurrence_id))
        else:
            action = "hold_for_review"
            explanation = "Scheduled contact may have begun; completed chunks remain untouched"
            affected_occurrences.add(str(occurrence_id))
        chunks.append({
            "occurrence_id": str(occurrence_id), "chunk_number": int(number),
            "state": str(state), "contact_phase": str(phase),
            "scan_run_id": run_id, "target_count": int(target_count),
            "attempt_count": int(attempts), "status_reason": reason,
            "targets_digest": str(targets_digest),
            "targets_record_digest": hashlib.sha256(
                str(targets_json).encode("utf-8")
            ).hexdigest(),
            "last_fencing_epoch": fencing_epoch, "created_at": str(created_at),
            "started_at": started_at, "completed_at": completed_at,
            "action": action, "reason": explanation,
        })

    # If one chunk may have contacted the network, every unfinished sibling in
    # that frozen occurrence is held. The preview must describe every row that
    # apply will change rather than showing a sibling as preserved.
    for item in chunks:
        if (
            item["occurrence_id"] in affected_occurrences
            and item["action"] == "preserve_waiting"
        ):
            item["action"] = "hold_for_review"
            item["reason"] = (
                "Another chunk in this frozen occurrence needs review; this waiting "
                "sibling is preserved and held with it"
            )

    occurrences = []
    for row in connection.execute(
        """SELECT occurrence_id,schedule_id,state,due_at,trigger_kind,actor,status_reason,
                  definition_version,definition_digest,frozen_digest,frozen_json,
                  trigger_key,created_at,started_at,completed_at
             FROM scan_schedule_occurrences
            WHERE state IN ('waiting','preparing','active','needs_attention')
            ORDER BY created_at,occurrence_id"""
    ):
        (occurrence_id, schedule_id, state, due_at, trigger, actor, reason,
         definition_version, definition_digest, frozen_digest, frozen_json,
         trigger_key, created_at, started_at, completed_at) = row
        if state not in KNOWN_OCCURRENCE_STATES:
            blockers.append(f"Schedule occurrence {occurrence_id} has unfamiliar state {state}")
        action = "hold_for_review" if str(occurrence_id) in affected_occurrences or state != "waiting" else "preserve_waiting"
        occurrences.append({
            "occurrence_id": str(occurrence_id), "schedule_id": str(schedule_id),
            "state": str(state), "due_at": str(due_at), "trigger_kind": str(trigger),
            "actor": str(actor), "status_reason": reason, "action": action,
            "definition_version": int(definition_version),
            "definition_digest": str(definition_digest),
            "frozen_digest": str(frozen_digest),
            "frozen_record_digest": hashlib.sha256(
                str(frozen_json).encode("utf-8")
            ).hexdigest(),
            "trigger_key": str(trigger_key), "created_at": str(created_at),
            "started_at": started_at, "completed_at": completed_at,
        })

    # Applying recovery disables each schedule that owns an occurrence held for
    # review. Include the complete mutable schedule row and the immutable
    # definition row in the reviewed plan so any stopped-copy change invalidates
    # the preview digest before a write can begin.
    schedule_refs = sorted({
        (item["schedule_id"], item["definition_version"])
        for item in occurrences if item["action"] == "hold_for_review"
    })
    schedules: list[dict[str, Any]] = []
    for schedule_id, definition_version in schedule_refs:
        schedule_rows = _snapshot_rows(
            connection,
            "SELECT * FROM scan_schedules WHERE schedule_id=?",
            (schedule_id,),
        )
        definition_rows = _snapshot_rows(
            connection,
            """SELECT * FROM scan_schedule_definitions
                 WHERE schedule_id=? AND definition_version=?""",
            (schedule_id, definition_version),
        )
        if len(schedule_rows) != 1:
            blockers.append(f"Schedule {schedule_id} does not have one saved schedule record")
        if len(definition_rows) != 1:
            blockers.append(
                f"Schedule {schedule_id} version {definition_version} does not have one definition record"
            )
        schedules.append({
            "schedule_id": schedule_id,
            "definition_version": definition_version,
            "action": "disable_for_review",
            "reason": "An unfinished occurrence requires review before this schedule can dispatch again",
            "schedule_record": schedule_rows[0] if schedule_rows else None,
            "definition_record": definition_rows[0] if definition_rows else None,
        })

    changes = [item for item in scans if item["action"] != "preserve_queue"]
    changes += [item for item in chunks if item["action"] != "preserve_waiting"]
    changes += [item for item in occurrences if item["action"] != "preserve_waiting"]
    changes += schedules
    changes += [item for item in arkime_pulls if item["action"] != "preserve_queue"]
    changes += [item for item in device_contacts if item["action"] != "preserve_review"]
    changes += [item for item in pipeline_attempts if item["action"] != "preserve_queue"]
    changes += [item for item in storage_maintenance if item["action"] == "mark_recovery_required"]
    result = {
        "contract": "nct-unfinished-work-recovery-v2",
        "safe_to_apply": not blockers,
        "blockers": sorted(set(blockers)),
        "scans": scans,
        "schedule_chunks": chunks,
        "schedule_occurrences": occurrences,
        "schedules": schedules,
        "arkime_pulls": arkime_pulls,
        "device_contacts": device_contacts,
        "pipeline_attempts": pipeline_attempts,
        "pipeline_intake": pipeline_intake,
        "device_vlan_intake": device_vlan_intake,
        "storage_maintenance": storage_maintenance,
        "storage_status_record": _storage_status_record(data_dir),
        "leases": leases,
        "affected_count": len(changes),
        "completed_evidence_action": "preserve",
        "automatic_contact_after_recovery": False,
    }
    result["plan_digest"] = content_digest(result)
    return result


def diagnose_scan_work(db_path: Path) -> dict[str, Any]:
    if not db_path.is_file():
        return {
            "contract": "nct-unfinished-work-recovery-v2", "safe_to_apply": False,
            "blockers": ["The saved NCT database was not found"], "scans": [],
            "schedule_chunks": [], "schedule_occurrences": [], "schedules": [],
            "arkime_pulls": [], "device_contacts": [], "pipeline_attempts": [],
            "pipeline_intake": [], "device_vlan_intake": [],
            "storage_maintenance": [], "leases": [],
            "affected_count": 0, "completed_evidence_action": "preserve",
            "automatic_contact_after_recovery": False,
            "plan_digest": None,
        }
    with connect_database(db_path, read_only=True) as connection:
        connection.execute("BEGIN")
        return _diagnose(connection, db_path.parent)


def pause_for_diagnosis(data_dir: Path, plan: dict[str, Any], reason: str) -> dict[str, Any]:
    value = {
        "contract": PAUSE_CONTRACT,
        "state": "diagnosis_required",
        "recorded_at": utc_now(),
        "reason": reason[:500],
        "plan_digest": plan.get("plan_digest"),
        "scan_contact_paused": True,
        "passive_contact_paused": True,
        "device_contact_paused": True,
        "local_processing_paused": True,
        "storage_maintenance_paused": True,
        "affected_count": int(plan.get("affected_count") or 0),
        "blockers": list(plan.get("blockers") or []),
    }
    write_recovery_pause(data_dir, value)
    return value


def apply_scan_work_recovery(
    db_path: Path,
    data_dir: Path,
    *,
    expected_plan_digest: str,
    actor: str,
    backup_path: str,
    backup_sha256: str,
) -> dict[str, Any]:
    if not actor.strip() or len(actor) > 100:
        raise ScanWorkRecoveryError("A valid administrator identity is required")
    if not backup_path.strip() or len(backup_path) > 4096:
        raise ScanWorkRecoveryError("A verified cold-backup path is required")
    if len(backup_sha256) != 64 or any(ch not in "0123456789abcdef" for ch in backup_sha256.lower()):
        raise ScanWorkRecoveryError("A verified cold-backup SHA-256 is required")
    recovery_id = uuid.uuid4().hex
    now = utc_now()
    # Fail closed before opening the database for mutation. Startup will remain paused
    # even if the transaction or later receipt write is interrupted.
    write_recovery_pause(data_dir, {
        "contract": PAUSE_CONTRACT,
        "state": "diagnosis_required",
        "recorded_at": now,
        "reason": "A stopped-container recovery is being applied",
        "plan_digest": expected_plan_digest,
        "recovery_id": recovery_id,
        "scan_contact_paused": True,
        "passive_contact_paused": True,
        "device_contact_paused": True,
        "local_processing_paused": True,
        "storage_maintenance_paused": True,
        "affected_count": 0,
        "blockers": [],
    })
    with connect_database(db_path) as connection:
        connection.execute("BEGIN IMMEDIATE")
        plan = _diagnose(connection, data_dir)
        if not plan["safe_to_apply"]:
            raise ScanWorkRecoveryError("Recovery is blocked: " + "; ".join(plan["blockers"]))
        if plan["plan_digest"] != expected_plan_digest:
            raise ScanWorkRecoveryError("The stopped saved-work plan changed; create a new preview")

        changed_runs: list[str] = []
        change_records: list[dict[str, Any]] = []
        for item in plan["scans"]:
            if item["action"] == "preserve_queue":
                continue
            before = _snapshot_rows(
                connection, "SELECT * FROM scan_runs WHERE run_id=?", (item["run_id"],)
            )
            row = connection.execute(
                "SELECT manifest_json FROM scan_runs WHERE run_id=?", (item["run_id"],)
            ).fetchone()
            manifest = json.loads(row[0])
            manifest.pop("execution_claim", None)
            if item["action"] == "requeue_precontact" and not item["scheduled"]:
                manifest["status"] = "queued"
                manifest.pop("dispatching_at", None)
                event = "recovery_requeued_precontact"
                detail = "Verified cold recovery removed stale pre-contact ownership; original queue position retained"
            else:
                manifest["status"] = "interrupted"
                manifest["success"] = False
                manifest["completed_at"] = now
                manifest["recovery_required"] = True
                manifest["recovery_id"] = recovery_id
                manifest["error"] = "Saved work was interrupted and requires review before a separately traceable retry"
                if isinstance(manifest.get("progress"), dict):
                    manifest["progress"]["phase"] = "interrupted"
                    manifest["progress"]["updated_at"] = now
                event = "recovery_interrupted"
                detail = manifest["error"]
            connection.execute(
                "UPDATE scan_runs SET status=?,manifest_json=? WHERE run_id=?",
                (manifest["status"], json.dumps(manifest, sort_keys=True), item["run_id"]),
            )
            sync_scan_history_manifest(
                connection,
                manifest,
                run_id=item["run_id"],
                created_at=item["created_at"],
            )
            connection.execute(
                "INSERT INTO scan_run_audit(run_id,event,actor,changed_at,details) VALUES(?,?,?,?,?)",
                (item["run_id"], event, actor.strip(), now, detail),
            )
            after = _snapshot_rows(
                connection, "SELECT * FROM scan_runs WHERE run_id=?", (item["run_id"],)
            )
            change_records.append({
                "record_type": "scan_run", "record_id": item["run_id"],
                "action": item["action"], "before": before, "after": after,
            })
            changed_runs.append(item["run_id"])

        affected_occurrences = {
            item["occurrence_id"] for item in plan["schedule_chunks"]
            if item["action"] == "hold_for_review"
        } | {
            item["occurrence_id"] for item in plan["schedule_occurrences"]
            if item["action"] == "hold_for_review"
        }
        for occurrence_id in affected_occurrences:
            occurrence_before = _snapshot_rows(
                connection,
                "SELECT * FROM scan_schedule_occurrences WHERE occurrence_id=?",
                (occurrence_id,),
            )
            chunks_before = _snapshot_rows(
                connection,
                "SELECT * FROM scan_schedule_chunks WHERE occurrence_id=? ORDER BY chunk_number",
                (occurrence_id,),
            )
            schedule_id = occurrence_before[0]["schedule_id"]
            schedule_before = _snapshot_rows(
                connection, "SELECT * FROM scan_schedules WHERE schedule_id=?", (schedule_id,)
            )
            connection.execute(
                """UPDATE scan_schedule_chunks
                      SET state='needs_attention', contact_phase=CASE
                          WHEN contact_phase IN ('not_started','preparing') THEN 'not_started'
                          ELSE 'uncertain' END,
                          completed_at=COALESCE(completed_at,?),
                          status_reason=?
                    WHERE occurrence_id=? AND state NOT IN ('complete','cancelled')""",
                (now, "Stopped recovery preserved frozen work for administrator review", occurrence_id),
            )
            connection.execute(
                """UPDATE scan_schedule_occurrences
                      SET state='needs_attention', completed_at=COALESCE(completed_at,?),
                          status_reason=? WHERE occurrence_id=?""",
                (now, "Stopped recovery requires review before any new occurrence", occurrence_id),
            )
            connection.execute(
                """UPDATE scan_schedules SET definition_json=json_set(
                       definition_json,'$.enabled',0,'$.batch_status','needs_attention',
                       '$.last_dispatch_note','Stopped recovery requires administrator review')
                    WHERE schedule_id=(SELECT schedule_id FROM scan_schedule_occurrences WHERE occurrence_id=?)""",
                (occurrence_id,),
            )
            change_records.extend((
                {
                    "record_type": "schedule_chunks", "record_id": occurrence_id,
                    "action": "hold_for_review", "before": chunks_before,
                    "after": _snapshot_rows(
                        connection,
                        "SELECT * FROM scan_schedule_chunks WHERE occurrence_id=? ORDER BY chunk_number",
                        (occurrence_id,),
                    ),
                },
                {
                    "record_type": "schedule_occurrence", "record_id": occurrence_id,
                    "action": "hold_for_review", "before": occurrence_before,
                    "after": _snapshot_rows(
                        connection,
                        "SELECT * FROM scan_schedule_occurrences WHERE occurrence_id=?",
                        (occurrence_id,),
                    ),
                },
                {
                    "record_type": "scan_schedule", "record_id": str(schedule_id),
                    "action": "disable_for_review", "before": schedule_before,
                    "after": _snapshot_rows(
                        connection, "SELECT * FROM scan_schedules WHERE schedule_id=?",
                        (schedule_id,),
                    ),
                },
            ))

        for item in plan["arkime_pulls"]:
            if item["action"] == "preserve_queue":
                continue
            before = _snapshot_rows(
                connection, "SELECT * FROM arkime_pull_runs WHERE run_id=?", (item["run_id"],)
            )
            connection.execute(
                """UPDATE arkime_pull_runs
                      SET state='interrupted',completed_at=?,claim_token=NULL,
                          error='NCT stopped after Arkime contact began; retry explicitly with the same saved window'
                    WHERE run_id=? AND state='running'""",
                (now, item["run_id"]),
            )
            connection.execute(
                "UPDATE arkime_pull_profiles SET state='attention',updated_at=? WHERE profile_id=?",
                (now, item["profile_id"]),
            )
            change_records.append({
                "record_type": "arkime_pull", "record_id": item["run_id"],
                "action": item["action"], "before": before,
                "after": _snapshot_rows(
                    connection, "SELECT * FROM arkime_pull_runs WHERE run_id=?", (item["run_id"],)
                ),
            })

        for item in plan["device_contacts"]:
            if item["action"] == "preserve_review":
                continue
            run_id = item["run_id"]
            before = _snapshot_rows(
                connection, "SELECT * FROM device_contact_runs WHERE run_id=?", (run_id,)
            )
            active_number = item["run_record"].get("active_attempt_number")
            needs_review = item["action"] == "interrupt_for_review"
            reason = (
                "Former process may have contacted the device or moved files; administrator review is required."
                if needs_review else
                "NCT stopped before device contact; start a new collection with fresh settings and credentials."
            )
            if active_number is not None:
                connection.execute(
                    """UPDATE device_contact_attempts
                          SET state=?,contact_phase=?,completed_at=?,status_reason=?
                        WHERE run_id=? AND attempt_number=?""",
                    (
                        "needs_attention" if needs_review else "failed",
                        "uncertain" if needs_review else "contact_stopped",
                        now, reason, run_id, int(active_number),
                    ),
                )
                attempt = next(
                    row for row in item["attempt_records"]
                    if row["attempt_number"] == active_number
                )
                for prefix in ("run", "capacity"):
                    key = attempt[f"{prefix}_lease_key"]
                    epoch = int(attempt[f"{prefix}_lease_epoch"])
                    connection.execute(
                        """UPDATE work_leases SET state=?,renewed_at=?,released_at=?,
                                  expires_at=NULL,recovery_reason=?,lease_id=NULL,owner_id=NULL
                             WHERE lease_key=? AND fencing_epoch=?
                               AND lease_id=? AND owner_id=?""",
                        (
                            "recovery_required" if needs_review else "released", now,
                            None if needs_review else now, reason if needs_review else None,
                            key, epoch, attempt[f"{prefix}_lease_id"], attempt["owner_id"],
                        ),
                    )
                    connection.execute(
                        """INSERT INTO work_lease_events(
                               event_id,lease_key,fencing_epoch,lease_id,owner_id,event_kind,
                               recorded_at,detail) VALUES(?,?,?,?,?,?,?,?)""",
                        (
                            uuid.uuid4().hex, key, epoch,
                            attempt[f"{prefix}_lease_id"] if needs_review else None,
                            attempt["owner_id"] if needs_review else None,
                            "recovery_required" if needs_review else "released", now, reason,
                        ),
                    )
            connection.execute(
                """UPDATE device_contact_runs
                      SET state=?,contact_phase=?,active_attempt_number=NULL,
                          completed_at=?,updated_at=?,status_reason=?
                    WHERE run_id=?""",
                (
                    "needs_attention" if needs_review else "failed",
                    "uncertain" if needs_review else "contact_stopped",
                    None if needs_review else now, now, reason, run_id,
                ),
            )
            change_records.append({
                "record_type": "device_contact", "record_id": run_id,
                "action": item["action"], "before": before,
                "after": _snapshot_rows(
                    connection, "SELECT * FROM device_contact_runs WHERE run_id=?", (run_id,)
                ),
            })

        for item in plan["pipeline_attempts"]:
            if item["action"] == "preserve_queue":
                continue
            attempt_id = item["attempt_id"]
            before = _snapshot_rows(
                connection, "SELECT * FROM pipeline_job_attempts WHERE attempt_id=?", (attempt_id,)
            )
            connection.execute(
                """UPDATE pipeline_job_attempts
                      SET state='interrupted',finished_at=?,
                          error='The former local worker stopped; a reviewed replacement was queued from retained evidence'
                    WHERE attempt_id=? AND state='running'""",
                (now, attempt_id),
            )
            attempt = item["attempt_record"]
            lease_key = f"derived-attempt:{attempt_id}"
            connection.execute(
                """UPDATE work_leases SET lease_id=NULL,owner_id=NULL,state='released',
                           expires_at=NULL,released_at=?,renewed_at=?,recovery_reason=NULL
                     WHERE lease_key=? AND fencing_epoch=? AND lease_id IS ?
                       AND owner_id IS ? AND state IN ('active','recovery_required')""",
                (
                    now, now, lease_key, int(attempt["lease_epoch"] or 0),
                    attempt["claim_token"], attempt["lease_owner"],
                ),
            )
            replacement_id = uuid.uuid4().hex
            connection.execute(
                """INSERT INTO pipeline_job_attempts(
                       attempt_id,job_id,attempt_number,state,claim_token,lease_owner,
                       lease_epoch,lease_expires_at,requested_by,requested_at
                   ) VALUES(?,?,?,'queued',NULL,NULL,0,NULL,'system-recovery',?)""",
                (
                    replacement_id, item["job_id"], int(item["attempt_number"]) + 1, now,
                ),
            )
            connection.execute(
                """INSERT INTO pipeline_job_requests(
                       request_token,job_id,request_kind,requested_by,requested_at
                   ) VALUES(?,?,'retry','system-recovery',?)""",
                (f"recovery-{attempt_id}-{int(attempt['lease_epoch'] or 0)}", item["job_id"], now),
            )
            change_records.append({
                "record_type": "pipeline_attempt", "record_id": attempt_id,
                "action": item["action"], "replacement_attempt_id": replacement_id,
                "before": before,
                "after": _snapshot_rows(
                    connection,
                    "SELECT * FROM pipeline_job_attempts WHERE job_id=? ORDER BY attempt_number",
                    (item["job_id"],),
                ),
            })

        for item in plan["storage_maintenance"]:
            if item["action"] != "mark_recovery_required":
                continue
            before = _snapshot_rows(
                connection, "SELECT * FROM work_leases WHERE lease_key='storage-maintenance'"
            )
            lease = item["lease_record"]
            reason = "Former storage-maintenance ownership ended; verify retained evidence before resuming."
            connection.execute(
                """UPDATE work_leases SET state='recovery_required',expires_at=NULL,
                           lease_id=NULL,owner_id=NULL,renewed_at=?,recovery_reason=?
                     WHERE lease_key='storage-maintenance' AND fencing_epoch=?
                       AND lease_id=? AND owner_id=? AND state='active'""",
                (now, reason, int(lease["fencing_epoch"]), lease["lease_id"], lease["owner_id"]),
            )
            connection.execute(
                """INSERT INTO work_lease_events(
                       event_id,lease_key,fencing_epoch,lease_id,owner_id,event_kind,
                       recorded_at,detail) VALUES(?,?,?,?,?,'recovery_required',?,?)""",
                (
                    uuid.uuid4().hex, "storage-maintenance", int(lease["fencing_epoch"]),
                    lease["lease_id"], lease["owner_id"], now, reason,
                ),
            )
            change_records.append({
                "record_type": "storage_maintenance", "record_id": "storage-maintenance",
                "action": item["action"], "before": before,
                "after": _snapshot_rows(
                    connection, "SELECT * FROM work_leases WHERE lease_key='storage-maintenance'"
                ),
            })

        lease_before = _snapshot_rows(
            connection, "SELECT * FROM work_leases WHERE lease_key=?",
            (SCAN_CAPACITY_LEASE_KEY,),
        )
        if lease_before and lease_before[0]["state"] in {"active", "recovery_required"}:
            lease = lease_before[0]
            connection.execute(
                """UPDATE work_leases SET lease_id=NULL,owner_id=NULL,state='released',
                       expires_at=NULL,released_at=?,renewed_at=?,recovery_reason=NULL
                    WHERE lease_key=? AND fencing_epoch=?""",
                (now, now, SCAN_CAPACITY_LEASE_KEY, int(lease["fencing_epoch"])),
            )
            connection.execute(
                """INSERT INTO work_lease_events(
                       event_id,lease_key,fencing_epoch,lease_id,owner_id,event_kind,
                       recorded_at,detail) VALUES(?,?,?,?,?,?,?,?)""",
                (uuid.uuid4().hex, SCAN_CAPACITY_LEASE_KEY, int(lease["fencing_epoch"]), None, None,
                 "recovery_cleared", now, "Verified stopped-container scan recovery"),
            )
            change_records.append({
                "record_type": "work_lease", "record_id": SCAN_CAPACITY_LEASE_KEY,
                "action": "release", "before": lease_before,
                "after": _snapshot_rows(
                    connection, "SELECT * FROM work_leases WHERE lease_key=?",
                    (SCAN_CAPACITY_LEASE_KEY,),
                ),
            })

        receipt = {
            "contract": "nct-unfinished-work-recovery-receipt-v2",
            "recovery_id": recovery_id,
            "applied_at": now,
            "actor": actor.strip(),
            "plan_digest": expected_plan_digest,
            "backup_path": backup_path,
            "backup_sha256": backup_sha256.lower(),
            "changed_run_ids": changed_runs,
            "held_occurrence_ids": sorted(affected_occurrences),
            "interrupted_arkime_run_ids": [
                item["run_id"] for item in plan["arkime_pulls"]
                if item["action"] == "interrupt_for_review"
            ],
            "reconciled_device_contact_ids": [
                item["run_id"] for item in plan["device_contacts"]
            ],
            "requeued_pipeline_attempt_ids": [
                item["attempt_id"] for item in plan["pipeline_attempts"]
                if item["action"] == "interrupt_and_requeue"
            ],
            "preserved_queue_run_ids": [
                item["run_id"] for item in plan["scans"]
                if item["action"] in {"preserve_queue", "requeue_precontact"}
            ],
            "completed_evidence_action": "preserved",
            "automatic_contact_after_recovery": False,
            "change_record_count": len(change_records),
            "database_receipt": True,
        }
        connection.execute(
            """INSERT INTO scan_run_audit(run_id,event,actor,changed_at,details)
               VALUES(?,?,?,?,?)""",
            (
                f"recovery:{recovery_id}", "scan_work_recovery_receipt",
                actor.strip(), now, canonical_json({
                    "plan": plan,
                    "changes": change_records,
                    "receipt": receipt,
                }),
            ),
        )

    receipt_dir = data_dir / PAUSE_FOLDER / "receipts"
    receipt_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    receipt_path = receipt_dir / f"scan-work-recovery-{recovery_id}.json"
    _write_external_receipt(receipt_path, receipt)
    write_recovery_pause(data_dir, {
        "contract": PAUSE_CONTRACT,
        "state": "review_required",
        "recorded_at": now,
        "reason": "Recovered work remains paused until an administrator reviews it",
        "plan_digest": expected_plan_digest,
        "recovery_id": recovery_id,
        "scan_contact_paused": True,
        "passive_contact_paused": True,
        "device_contact_paused": True,
        "local_processing_paused": True,
        "storage_maintenance_paused": True,
        "affected_count": plan["affected_count"],
        "blockers": [],
        "receipt": str(receipt_path),
    })
    return receipt
