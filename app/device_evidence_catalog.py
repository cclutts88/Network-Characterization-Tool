"""Disposable selector catalog for current device evidence.

The catalog is an acceleration structure. Device collection authority, immutable
derived results, and retained files remain the source of truth.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import sqlite3
from pathlib import Path

from app.database import connect_database
from app.derived_contracts import (
    DEVICE_SUMMARY_FAMILY,
    DEVICE_SUMMARY_PARAMETERS,
    DEVICE_SUMMARY_SCHEMA_VERSION,
    DEVICE_SUMMARY_VERSION,
)
from app.pipeline_intake import DEVICE_SUMMARY_JOB_TYPE


CATALOG_SCHEMA_VERSION = 1
_SUPPORTED_STATUS = {"completed", "uploaded"}
_SUPPORTED_OPERATION = {
    "configuration_pull",
    "interactive_configuration_pull",
    "manual_upload",
}


class DeviceEvidenceCatalogError(ValueError):
    """The disposable selector cannot prove a safe current selection."""


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _digest_text(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _table_exists(db: sqlite3.Connection, name: str) -> bool:
    return db.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (name,)
    ).fetchone() is not None


def ensure_device_evidence_catalog_schema(db: sqlite3.Connection) -> None:
    """Create the rebuildable selector and pure-SQL rollback dirty markers."""
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS device_evidence_catalog (
            run_id TEXT PRIMARY KEY,
            device_key TEXT NOT NULL,
            completed_at TEXT,
            created_at TEXT,
            status TEXT NOT NULL,
            operation TEXT NOT NULL,
            manifest_json TEXT NOT NULL,
            manifest_sha256 TEXT NOT NULL,
            authority_revision INTEGER NOT NULL,
            selection_contract TEXT NOT NULL,
            semantic_manifest_sha256 TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS device_evidence_catalog_order
            ON device_evidence_catalog(completed_at DESC, created_at DESC, run_id DESC);
        CREATE INDEX IF NOT EXISTS device_evidence_catalog_device
            ON device_evidence_catalog(device_key, completed_at DESC, created_at DESC);
        CREATE TABLE IF NOT EXISTS device_evidence_catalog_dirty (
            run_id TEXT PRIMARY KEY,
            reason TEXT NOT NULL,
            marked_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS device_evidence_catalog_meta (
            singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
            schema_version INTEGER NOT NULL,
            reconciled_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        DROP TRIGGER IF EXISTS device_evidence_catalog_authority_insert;
        DROP TRIGGER IF EXISTS device_evidence_catalog_authority_update;
        CREATE TRIGGER device_evidence_catalog_authority_insert
            AFTER INSERT ON device_collection_authority
            WHEN NEW.state = 'active'
            BEGIN
                INSERT INTO device_evidence_catalog_dirty(run_id, reason)
                VALUES (NEW.run_id, 'authority_insert')
                ON CONFLICT(run_id) DO UPDATE SET
                    reason = excluded.reason,
                    marked_at = CURRENT_TIMESTAMP;
            END;
        CREATE TRIGGER device_evidence_catalog_authority_update
            AFTER UPDATE ON device_collection_authority
            WHEN OLD.state = 'active' OR NEW.state = 'active'
            BEGIN
                INSERT INTO device_evidence_catalog_dirty(run_id, reason)
                VALUES (NEW.run_id, 'authority_update')
                ON CONFLICT(run_id) DO UPDATE SET
                    reason = excluded.reason,
                    marked_at = CURRENT_TIMESTAMP;
            END;
        """
    )


def _device_key(manifest: dict) -> str:
    value = str(manifest.get("device_address") or manifest.get("device_name") or "").strip()
    if not value:
        return ""
    try:
        return f"ip:{ipaddress.ip_address(value)}"
    except ValueError:
        return f"name:{value.rstrip('.').casefold()}"


def _catalog_value(manifest: dict, authority: dict) -> dict | None:
    if authority.get("state") != "active":
        return None
    status = str(manifest.get("status") or "").casefold()
    operation = str(manifest.get("operation") or "")
    if status not in _SUPPORTED_STATUS or operation not in _SUPPORTED_OPERATION:
        return None
    marker = manifest.get("summary_authority") or {}
    if (
        not isinstance(marker, dict)
        or marker.get("required") is not True
        or marker.get("selection_contract") != authority.get("selection_contract")
    ):
        raise DeviceEvidenceCatalogError(
            f"Device collection {authority.get('run_id')} has inconsistent authority metadata"
        )
    run_id = str(manifest.get("run_id") or "")
    if not run_id or run_id != authority.get("run_id"):
        raise DeviceEvidenceCatalogError("Device collection manifest identity is inconsistent")
    manifest_json = _canonical_json(manifest)
    return {
        "run_id": run_id,
        "device_key": _device_key(manifest),
        "completed_at": str(manifest.get("completed_at") or "") or None,
        "created_at": str(manifest.get("created_at") or "") or None,
        "status": status,
        "operation": operation,
        "manifest_json": manifest_json,
        "manifest_sha256": _digest_text(manifest_json),
        "authority_revision": int(authority.get("revision") or 0),
        "selection_contract": str(authority.get("selection_contract") or ""),
        "semantic_manifest_sha256": str(
            authority.get("semantic_manifest_sha256") or ""
        ),
    }


def record_device_evidence_activation(
    db: sqlite3.Connection, manifest: dict, authority: dict,
) -> None:
    """Synchronize one current activation inside its authority transaction."""
    value = _catalog_value(manifest, authority)
    if value is None:
        db.execute("DELETE FROM device_evidence_catalog WHERE run_id = ?", (authority["run_id"],))
    elif value["device_key"]:
        db.execute(
            """INSERT INTO device_evidence_catalog (
                   run_id, device_key, completed_at, created_at, status, operation,
                   manifest_json, manifest_sha256, authority_revision,
                   selection_contract, semantic_manifest_sha256
               ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(run_id) DO UPDATE SET
                   device_key = excluded.device_key,
                   completed_at = excluded.completed_at,
                   created_at = excluded.created_at,
                   status = excluded.status,
                   operation = excluded.operation,
                   manifest_json = excluded.manifest_json,
                   manifest_sha256 = excluded.manifest_sha256,
                   authority_revision = excluded.authority_revision,
                   selection_contract = excluded.selection_contract,
                   semantic_manifest_sha256 = excluded.semantic_manifest_sha256""",
            tuple(value[key] for key in (
                "run_id", "device_key", "completed_at", "created_at", "status",
                "operation", "manifest_json", "manifest_sha256", "authority_revision",
                "selection_contract", "semantic_manifest_sha256",
            )),
        )
    else:
        db.execute("DELETE FROM device_evidence_catalog WHERE run_id = ?", (value["run_id"],))
    db.execute("DELETE FROM device_evidence_catalog_dirty WHERE run_id = ?", (authority["run_id"],))


def record_device_evidence_deletion(db: sqlite3.Connection, run_id: str) -> None:
    """Remove a disposable selector row inside the deletion transaction."""
    db.execute("DELETE FROM device_evidence_catalog WHERE run_id = ?", (run_id,))
    db.execute("DELETE FROM device_evidence_catalog_dirty WHERE run_id = ?", (run_id,))


def _authority_rows(db: sqlite3.Connection) -> list[dict]:
    if not _table_exists(db, "device_collection_authority"):
        return []
    rows = db.execute(
        """SELECT run_id, state, revision, selection_contract,
                  semantic_manifest_json, semantic_manifest_sha256,
                  artifact_observation_id, artifact_sha256, retained_filename,
                  created_at, activated_at, deleted_at
           FROM device_collection_authority ORDER BY run_id"""
    ).fetchall()
    keys = (
        "run_id", "state", "revision", "selection_contract",
        "semantic_manifest_json", "semantic_manifest_sha256",
        "artifact_observation_id", "artifact_sha256", "retained_filename",
        "created_at", "activated_at", "deleted_at",
    )
    return [dict(zip(keys, row)) for row in rows]


def _safe_manifest(config_dir: Path, run_id: str) -> tuple[dict, str]:
    """Return parsed content and its canonical semantic JSON digest."""
    root = Path(config_dir).resolve()
    run_dir = root / run_id
    path = run_dir / "manifest.json"
    if (
        not run_id
        or Path(run_id).name != run_id
        or run_dir.parent != root
        or run_dir.is_symlink()
        or path.is_symlink()
    ):
        raise DeviceEvidenceCatalogError(f"Device collection {run_id!r} has an unsafe path")
    try:
        raw = path.read_bytes()
        manifest = json.loads(raw)
    except (OSError, ValueError) as exc:
        raise DeviceEvidenceCatalogError(
            f"Device collection {run_id} has no readable manifest"
        ) from exc
    if not isinstance(manifest, dict):
        raise DeviceEvidenceCatalogError(f"Device collection {run_id} manifest is invalid")
    canonical = _canonical_json(manifest)
    return manifest, _digest_text(canonical)


def reconcile_device_evidence_catalog(db_path: Path, config_dir: Path) -> dict:
    """Rebuild the disposable selector from current authority and manifests."""
    issues: list[str] = []
    with connect_database(db_path, read_only=True) as db:
        before = _authority_rows(db)
    values: list[dict] = []
    for authority in before:
        if authority["state"] != "active":
            continue
        try:
            manifest, manifest_sha256 = _safe_manifest(config_dir, authority["run_id"])
            value = _catalog_value(manifest, authority)
            if value is not None and value["manifest_sha256"] == manifest_sha256:
                if value["device_key"]:
                    values.append(value)
        except DeviceEvidenceCatalogError as exc:
            issues.append(str(exc))
    # Reject a rebuild that crossed an authority or manifest change.
    with connect_database(db_path, read_only=True) as db:
        if _authority_rows(db) != before:
            raise DeviceEvidenceCatalogError(
                "Device authority changed while rebuilding its selector catalog"
            )
    for value in values:
        _manifest, current = _safe_manifest(config_dir, value["run_id"])
        if current != value["manifest_sha256"]:
            raise DeviceEvidenceCatalogError(
                "Device manifest changed while rebuilding its selector catalog"
            )
    with connect_database(db_path) as db:
        db.execute("BEGIN IMMEDIATE")
        if _authority_rows(db) != before:
            raise DeviceEvidenceCatalogError(
                "Device authority changed before selector publication"
            )
        active_ids = {value["run_id"] for value in values}
        if active_ids:
            placeholders = ",".join("?" for _ in active_ids)
            db.execute(
                f"DELETE FROM device_evidence_catalog WHERE run_id NOT IN ({placeholders})",
                tuple(sorted(active_ids)),
            )
        else:
            db.execute("DELETE FROM device_evidence_catalog")
        for value in values:
            authority = next(item for item in before if item["run_id"] == value["run_id"])
            record_device_evidence_activation(db, json.loads(value["manifest_json"]), authority)
        valid_ids = {value["run_id"] for value in values}
        db.execute("DELETE FROM device_evidence_catalog_meta WHERE singleton = 1")
        db.execute(
            """INSERT INTO device_evidence_catalog_meta(singleton, schema_version)
               VALUES (1, ?)""",
            (CATALOG_SCHEMA_VERSION,),
        )
        db.execute("DELETE FROM device_evidence_catalog_dirty")
        # Keep unresolved active collections explicitly dirty so reads cannot hide them.
        for authority in before:
            if authority["state"] == "active" and authority["run_id"] not in valid_ids:
                db.execute(
                    """INSERT INTO device_evidence_catalog_dirty(run_id, reason)
                       VALUES (?, 'reconcile_issue')""",
                    (authority["run_id"],),
                )
    return {"indexed": len(values), "issues": issues}


def _selected_dependency_rows(
    db: sqlite3.Connection, result_ids: list[str],
) -> tuple[dict[str, list[list]], dict[str, list[list]]]:
    """Read immutable dependencies only for the already selected results."""
    inputs: dict[str, list[list]] = {}
    links: dict[str, list[list]] = {}
    # Keep each statement below SQLite's common host-parameter limit while still
    # supporting installations with more than one thousand distinct devices.
    for offset in range(0, len(result_ids), 400):
        batch = result_ids[offset:offset + 400]
        placeholders = ",".join("?" for _ in batch)
        for row in db.execute(
            f"""SELECT result_id, input_role, input_kind, input_identity,
                       input_metadata_json
                FROM derived_result_inputs
                WHERE result_id IN ({placeholders})
                ORDER BY result_id, input_role""",
            batch,
        ).fetchall():
            inputs.setdefault(str(row[0]), []).append(list(row))
        for row in db.execute(
            f"""SELECT result_id, input_role, observation_id, linked_at
                FROM derived_result_observation_links
                WHERE result_id IN ({placeholders})
                ORDER BY result_id, input_role, observation_id""",
            batch,
        ).fetchall():
            links.setdefault(str(row[0]), []).append(list(row))
    return inputs, links


def select_latest_device_evidence(
    db_path: Path, config_dir: Path,
) -> tuple[list[dict], dict]:
    """Select every device's newest completed supported evidence without writes."""
    with connect_database(db_path, read_only=True) as db:
        required_tables = (
            "device_evidence_catalog", "device_evidence_catalog_dirty",
            "device_collection_authority", "pipeline_jobs",
            "pipeline_job_attempts", "derived_results", "derived_result_inputs",
            "derived_result_observation_links",
        )
        if not all(_table_exists(db, name) for name in required_tables):
            return [], {"catalog_available": False, "rows": []}
        dirty = db.execute(
            "SELECT run_id, reason, marked_at FROM device_evidence_catalog_dirty ORDER BY run_id"
        ).fetchall()
        if dirty:
            raise DeviceEvidenceCatalogError(
                "Device evidence selection changed outside the current catalog; restart NCT "
                "to reconcile the disposable selector"
            )
        expected_parameters = _canonical_json(dict(DEVICE_SUMMARY_PARAMETERS))
        rows = db.execute(
            """WITH latest_jobs AS (
                   SELECT jobs.*,
                          ROW_NUMBER() OVER (
                              PARTITION BY jobs.source_run_id
                              ORDER BY jobs.requested_at DESC, jobs.job_id DESC
                          ) AS job_rank
                   FROM pipeline_jobs jobs
                   WHERE jobs.job_type = ?
               ), latest_attempts AS (
                   SELECT attempts.*,
                          ROW_NUMBER() OVER (
                              PARTITION BY attempts.job_id
                              ORDER BY attempts.attempt_number DESC
                          ) AS attempt_rank
                   FROM pipeline_job_attempts attempts
                   JOIN latest_jobs current_jobs
                     ON current_jobs.job_id = attempts.job_id
                    AND current_jobs.job_rank = 1
               ), eligible AS (
                   SELECT catalog.run_id, catalog.device_key,
                          catalog.completed_at, catalog.created_at,
                          catalog.status, catalog.operation,
                          catalog.manifest_json, catalog.manifest_sha256,
                          catalog.authority_revision, catalog.selection_contract,
                          catalog.semantic_manifest_sha256,
                          authority.state, authority.revision,
                          authority.selection_contract,
                          authority.semantic_manifest_json,
                          authority.semantic_manifest_sha256,
                          authority.artifact_observation_id,
                          authority.artifact_sha256,
                          authority.retained_filename, authority.activated_at,
                          jobs.job_id, jobs.source_run_id,
                          jobs.source_observation_id, jobs.source_status,
                          jobs.source_sha256, jobs.source_size_bytes,
                          jobs.target_family, jobs.target_analysis_version,
                          jobs.target_payload_schema_version,
                          jobs.target_parameters_json,
                          jobs.target_computation_key, jobs.target_result_id,
                          jobs.requested_at,
                          attempts.attempt_id, attempts.attempt_number,
                          attempts.state AS attempt_state, attempts.result_id,
                          attempts.output_kind, attempts.output_id, attempts.error,
                          results.result_id AS verified_result_id,
                          results.computation_key, results.family,
                          results.analysis_version,
                          results.payload_schema_version,
                          results.parameters_json, results.inputs_json,
                          results.result_sha256, results.generated_at,
                          ROW_NUMBER() OVER (
                              PARTITION BY catalog.device_key
                              ORDER BY COALESCE(
                                  catalog.completed_at, catalog.created_at, ''
                              ) DESC, catalog.run_id DESC
                          ) AS device_rank,
                          COUNT(*) OVER () AS eligible_count
                   FROM device_evidence_catalog catalog
                   JOIN device_collection_authority authority
                     ON authority.run_id = catalog.run_id
                    AND authority.state = 'active'
                    AND authority.revision = catalog.authority_revision
                    AND authority.selection_contract = catalog.selection_contract
                    AND authority.semantic_manifest_sha256 =
                        catalog.semantic_manifest_sha256
                   JOIN latest_jobs jobs
                     ON jobs.source_run_id = catalog.run_id
                    AND jobs.job_rank = 1
                   JOIN latest_attempts attempts
                     ON attempts.job_id = jobs.job_id
                    AND attempts.attempt_rank = 1
                    AND attempts.state = 'completed'
                    AND attempts.output_kind = 'derived_result'
                    AND attempts.output_id IS NOT NULL
                    AND (attempts.result_id IS NULL OR
                         attempts.result_id = attempts.output_id)
                   JOIN derived_results results
                     ON results.result_id = attempts.output_id
                    AND (jobs.target_result_id IS NULL OR
                         jobs.target_result_id = results.result_id)
                   WHERE jobs.target_family = ?
                     AND jobs.target_analysis_version = ?
                     AND jobs.target_payload_schema_version = ?
                     AND jobs.target_parameters_json = ?
                     AND results.family = ?
                     AND results.analysis_version = ?
                     AND results.payload_schema_version = ?
                     AND results.parameters_json = ?
               )
               SELECT * FROM eligible WHERE device_rank = 1
               ORDER BY COALESCE(completed_at, created_at, '') DESC, run_id DESC""",
            (
                DEVICE_SUMMARY_JOB_TYPE,
                DEVICE_SUMMARY_FAMILY, str(DEVICE_SUMMARY_VERSION),
                int(DEVICE_SUMMARY_SCHEMA_VERSION), expected_parameters,
                DEVICE_SUMMARY_FAMILY, str(DEVICE_SUMMARY_VERSION),
                int(DEVICE_SUMMARY_SCHEMA_VERSION), expected_parameters,
            ),
        ).fetchall()
        result_ids = [str(row[40]) for row in rows]
        input_rows, link_rows = _selected_dependency_rows(db, result_ids)

    selected = []
    for row in rows:
        run_id = str(row[0])
        manifest, current_manifest_sha = _safe_manifest(config_dir, run_id)
        if current_manifest_sha != row[7]:
            raise DeviceEvidenceCatalogError(
                f"Device collection {run_id} changed after selector indexing; restart NCT "
                "to reconcile the disposable selector"
            )
        authority = {
            "run_id": run_id,
            "state": row[11],
            "revision": row[12],
            "selection_contract": row[13],
            "semantic_manifest_json": row[14],
            "semantic_manifest_sha256": row[15],
            "artifact_observation_id": row[16],
            "artifact_sha256": row[17],
            "retained_filename": row[18],
            "activated_at": row[19],
        }
        current = _catalog_value(manifest, authority)
        if current is None or any(
            current[key] != expected
            for key, expected in (
                ("device_key", row[1]),
                ("completed_at", row[2]),
                ("created_at", row[3]),
                ("status", row[4]),
                ("operation", row[5]),
                ("manifest_json", row[6]),
                ("manifest_sha256", row[7]),
                ("authority_revision", row[8]),
                ("selection_contract", row[9]),
                ("semantic_manifest_sha256", row[10]),
            )
        ):
            raise DeviceEvidenceCatalogError(
                f"Device collection {run_id} no longer matches its selector catalog; "
                "restart NCT to reconcile it"
            )
        result_id = str(row[40])
        current["job_dependency"] = {
            "job": list(row[20:33]),
            "attempt": [
                row[33], row[20], row[34], row[35], row[36], row[37], row[38],
                row[39],
            ],
            "result": list(row[40:49]),
            "inputs": input_rows.get(result_id, []),
            "observation_links": link_rows.get(result_id, []),
        }
        current["catalog_manifest_sha256"] = row[7]
        current["manifest_sha256"] = current_manifest_sha
        selected.append(current)
    descriptor = {
        "catalog_available": True,
        "schema_version": CATALOG_SCHEMA_VERSION,
        "dirty": [list(row) for row in dirty],
        "eligible_count": int(rows[0][50]) if rows else 0,
        "rows": selected,
        "selected_run_ids": [value["run_id"] for value in selected],
    }
    return selected, descriptor
