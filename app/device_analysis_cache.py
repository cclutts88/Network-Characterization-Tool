"""Exact-source process cache boundary for current device analyses."""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import stat
from pathlib import Path
from typing import Any

from app.database import connect_database
from app.device_analysis import DEVICE_SUMMARY_VERSION
from app.device_collection_authority import (
    COLLECTED_DEVICE_SELECTION_CONTRACT,
    MANUAL_UPLOAD_SELECTION_CONTRACT,
)
from app.device_configs import COLLECTION_ARTIFACT_RE, UPLOADED_ARTIFACT_RE
from app.device_evidence_catalog import select_latest_device_evidence
from app.device_observations import DEVICE_INTERFACE_JOB_TYPE
from app.network_evidence_cache import NetworkEvidenceSnapshot, stable_path_identity
from app.network_semantics import EXTERNAL_WAN_ROLES
from app.pipeline_intake import COLLECTED_DEVICE_INTENT, MANUAL_DEVICE_INTENT


DEVICE_ANALYSIS_VIEW_CONTRACT_VERSION = 1
_WAN_ROLE_ORDER = tuple(EXTERNAL_WAN_ROLES.values())


class DeviceAnalysisSnapshotError(RuntimeError):
    """Current verified device inputs cannot be fingerprinted safely."""


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _table_exists(db: sqlite3.Connection, name: str) -> bool:
    return db.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
    ).fetchone() is not None


def _batches(values: list[str], size: int = 400):
    for offset in range(0, len(values), size):
        yield values[offset:offset + size]


def _query_for_values(
    db: sqlite3.Connection, query: str, values: list[str],
) -> list[list]:
    rows: list[list] = []
    for batch in _batches(values):
        placeholders = ",".join("?" for _ in batch)
        rows.extend(list(row) for row in db.execute(query.format(placeholders), batch))
    return rows


def _has_symlink_component(path: Path) -> bool:
    candidate = Path(path)
    return any(item.is_symlink() for item in (candidate, *candidate.parents))


def _stable_regular_identity(path: Path, label: str) -> dict:
    """Hash a regular file through one no-follow descriptor and prove path stability."""
    path = Path(path)
    if _has_symlink_component(path):
        raise DeviceAnalysisSnapshotError(f"{label} uses a symbolic link")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        before_path = path.stat(follow_symlinks=False)
        descriptor = os.open(path, flags)
    except (OSError, ValueError) as exc:
        raise DeviceAnalysisSnapshotError(f"{label} cannot be opened safely: {exc}") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise DeviceAnalysisSnapshotError(f"{label} is not a regular file")
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    try:
        after_path = path.stat(follow_symlinks=False)
    except OSError as exc:
        raise DeviceAnalysisSnapshotError(f"{label} changed after reading: {exc}") from exc
    before_identity = (
        before.st_dev, before.st_ino, before.st_size,
        before.st_mtime_ns, before.st_ctime_ns,
    )
    after_identity = (
        after.st_dev, after.st_ino, after.st_size,
        after.st_mtime_ns, after.st_ctime_ns,
    )
    path_before_identity = (before_path.st_dev, before_path.st_ino, before_path.st_size)
    path_after_identity = (after_path.st_dev, after_path.st_ino, after_path.st_size)
    if before_identity != after_identity or path_before_identity != path_after_identity:
        raise DeviceAnalysisSnapshotError(f"{label} changed while it was read")
    return {
        "path": str(path.resolve(strict=True)),
        "device": int(after.st_dev),
        "inode": int(after.st_ino),
        "size": int(after.st_size),
        "sha256": digest.hexdigest(),
    }


def _safe_run_directory(config_dir: Path, run_id: str) -> Path:
    root = Path(config_dir).resolve(strict=True)
    run_dir = root / run_id
    if (
        not run_id
        or Path(run_id).name != run_id
        or run_dir.parent != root
        or _has_symlink_component(run_dir)
        or not run_dir.is_dir()
    ):
        raise DeviceAnalysisSnapshotError(
            f"Device collection {run_id!r} has an unsafe or unavailable directory"
        )
    return run_dir


def _directory_shape(run_dir: Path) -> list[dict]:
    shape = []
    for path in sorted(run_dir.iterdir(), key=lambda item: item.name.casefold()):
        if path.is_symlink():
            raise DeviceAnalysisSnapshotError(
                f"Device collection {run_dir.name} contains a linked path: {path.name}"
            )
        relevant = (
            path.name in {"manifest.json", "stdout.txt", "command-history.txt"}
            or UPLOADED_ARTIFACT_RE.fullmatch(path.name) is not None
            or COLLECTION_ARTIFACT_RE.fullmatch(path.name) is not None
        )
        if not relevant:
            continue
        info = path.stat(follow_symlinks=False)
        identity = (
            _stable_regular_identity(path, f"Device candidate {run_dir.name}/{path.name}")
            if path.is_file() else None
        )
        shape.append({
            "name": path.name,
            "kind": "file" if path.is_file() else "directory" if path.is_dir() else "other",
            "size": int(info.st_size),
            "identity": identity,
        })
    return shape


def _verified_identity(path: Path, *, expected_sha256: str, expected_size: int, label: str) -> dict:
    identity = _stable_regular_identity(path, label)
    if identity["sha256"] != expected_sha256 or identity["size"] != expected_size:
        raise DeviceAnalysisSnapshotError(f"{label} does not match its exact authority")
    return identity


def _selected_database_rows(
    db: sqlite3.Connection, run_ids: list[str], result_ids: list[str],
) -> dict:
    required = (
        "device_collection_authority_inputs", "artifact_observations",
        "artifact_registry", "derived_results", "derived_result_inputs",
        "derived_result_observation_links", "device_scope_assignments",
        "device_interface_assessments", "network_scopes", "pipeline_jobs",
        "pipeline_job_attempts", "pipeline_admission_intents",
        "network_semantics", "network_wan_interfaces",
    )
    missing = [name for name in required if not _table_exists(db, name)]
    if missing:
        raise DeviceAnalysisSnapshotError(
            f"Device analysis dependencies are unavailable: {', '.join(missing)}"
        )

    authority_evidence = _query_for_values(
        db,
        """SELECT authority.run_id, authority.state, authority.revision,
                  authority.artifact_observation_id, authority.artifact_sha256,
                  authority.retained_filename, authority.selection_contract,
                  authority.semantic_manifest_json,
                  authority.semantic_manifest_sha256, authority.created_at,
                  authority.activated_at, authority.deleted_at,
                  observation.sha256, observation.source_kind,
                  observation.source_ref, observation.observed_at,
                  observation.original_filename, observation.actor,
                  observation.metadata_json, artifact.size_bytes,
                  artifact.media_type, artifact.canonical_path,
                  artifact.first_seen_at, artifact.last_seen_at
           FROM device_collection_authority authority
           LEFT JOIN artifact_observations observation
             ON observation.observation_id = authority.artifact_observation_id
           LEFT JOIN artifact_registry artifact
             ON artifact.sha256 = observation.sha256
           WHERE authority.run_id IN ({}) ORDER BY authority.run_id""",
        run_ids,
    ) if run_ids else []
    authority_inputs = _query_for_values(
        db,
        """SELECT input.run_id, input.input_role, input.position,
                  input.source_kind, input.identity, input.filename,
                  input.artifact_observation_id, input.artifact_sha256,
                  input.size_bytes, input.metadata_json,
                  observation.sha256, observation.source_kind,
                  observation.source_ref, observation.observed_at,
                  observation.original_filename, observation.actor,
                  observation.metadata_json, artifact.size_bytes,
                  artifact.media_type, artifact.canonical_path,
                  artifact.first_seen_at, artifact.last_seen_at
           FROM device_collection_authority_inputs input
           LEFT JOIN artifact_observations observation
             ON observation.observation_id = input.artifact_observation_id
           LEFT JOIN artifact_registry artifact
             ON artifact.sha256 = observation.sha256
           WHERE input.run_id IN ({})
           ORDER BY input.run_id, input.input_role, input.position""",
        run_ids,
    ) if run_ids else []
    results = _query_for_values(
        db,
        """SELECT result_id, computation_key, family, analysis_version,
                  payload_schema_version, parameters_json, inputs_json,
                  result_json, result_sha256, generated_at
           FROM derived_results WHERE result_id IN ({}) ORDER BY result_id""",
        result_ids,
    ) if result_ids else []
    intents = _query_for_values(
        db,
        """SELECT intent_id, intent_kind, source_kind, source_id, policy_version,
                  observation_id, assignment_id, scope_id, actor, request_token,
                  contract_json, state, created_at, updated_at, admitted_job_id,
                  resolved_assignment_id, activity_state, last_error
           FROM pipeline_admission_intents
           WHERE source_id IN ({})
             AND intent_kind IN ('manual_device_summary', 'collected_device_summary')
           ORDER BY source_id, intent_kind, intent_id""",
        run_ids,
    ) if run_ids else []
    result_inputs = _query_for_values(
        db,
        """SELECT result_id, input_role, input_kind, input_identity,
                  input_metadata_json
           FROM derived_result_inputs WHERE result_id IN ({})
           ORDER BY result_id, input_role""",
        result_ids,
    ) if result_ids else []
    result_links = _query_for_values(
        db,
        """SELECT result_id, input_role, observation_id, linked_at
           FROM derived_result_observation_links WHERE result_id IN ({})
           ORDER BY result_id, input_role, observation_id""",
        result_ids,
    ) if result_ids else []
    assignments = _query_for_values(
        db,
        """SELECT assignment_id, run_id, authority_revision, scope_id, revision,
                  event_kind, supersedes_assignment_id, actor, reason, assigned_at
           FROM device_scope_assignments WHERE run_id IN ({})
           ORDER BY run_id, authority_revision, revision, assignment_id""",
        run_ids,
    ) if run_ids else []
    assignment_ids = [str(row[0]) for row in assignments]
    scope_ids = sorted({str(row[3]) for row in assignments})
    scopes = _query_for_values(
        db,
        """SELECT scope_id, label, description, version, active, created_at,
                  updated_at, archived_at
           FROM network_scopes WHERE scope_id IN ({}) ORDER BY scope_id""",
        scope_ids,
    ) if scope_ids else []
    assessments = _query_for_values(
        db,
        """SELECT assessment_id, assignment_id, run_id, authority_revision,
                  scope_id, configuration_observation_id, configuration_sha256,
                  configuration_size_bytes, configuration_filename,
                  summary_result_id, extractor_version, coverage_json, recorded_at
           FROM device_interface_assessments WHERE assignment_id IN ({})
           ORDER BY assignment_id, assessment_id""",
        assignment_ids,
    ) if assignment_ids else []
    observation_jobs = _query_for_values(
        db,
        """SELECT job_id, job_key, job_type, source_run_id,
                  source_observation_id, source_status, source_sha256,
                  source_size_bytes, target_family, target_analysis_version,
                  target_payload_schema_version, target_parameters_json,
                  target_computation_key, target_result_id, source_kind,
                  source_ref, definition_json, requested_by, requested_at
           FROM pipeline_jobs WHERE job_type = 'device_interface_observations'
             AND source_ref IN ({}) ORDER BY source_ref, requested_at, job_id""",
        assignment_ids,
    ) if assignment_ids else []
    observation_job_ids = [str(row[0]) for row in observation_jobs]
    observation_attempts = _query_for_values(
        db,
        """SELECT attempt_id, job_id, attempt_number, state, claim_token,
                  requested_by, requested_at, started_at, finished_at, outcome,
                  result_id, output_kind, output_id, error
           FROM pipeline_job_attempts WHERE job_id IN ({})
           ORDER BY job_id, attempt_number, attempt_id""",
        observation_job_ids,
    ) if observation_job_ids else []
    wan_parent_rows = [
        list(row) for row in db.execute(
            """SELECT role, node_id, device_name, device_address, interface_name,
                      changed_at, changed_by
               FROM network_semantics
               WHERE role IN ('external_wan_gateway',
                              'external_wan_gateway_secondary')
               ORDER BY CASE role WHEN 'external_wan_gateway' THEN 0 ELSE 1 END"""
        )
    ]
    wan_interface_rows = [
        list(row) for row in db.execute(
            """SELECT role, node_id, interface_name, position
               FROM network_wan_interfaces
               WHERE role IN ('external_wan_gateway',
                              'external_wan_gateway_secondary')
               ORDER BY role, position, interface_name COLLATE NOCASE"""
        )
    ]
    return {
        "authority_evidence": authority_evidence,
        "authority_inputs": authority_inputs,
        "admission_intents": intents,
        "results": results,
        "result_inputs": result_inputs,
        "result_links": result_links,
        "scope_assignments": assignments,
        "scopes": scopes,
        "interface_assessments": assessments,
        "observation_jobs": observation_jobs,
        "observation_attempts": observation_attempts,
        "wan_parent_rows": wan_parent_rows,
        "wan_interface_rows": wan_interface_rows,
    }


def _gateway_values(parent_rows: list[list], interface_rows: list[list]) -> list[dict]:
    child_by_role: dict[str, list[list]] = {}
    for row in interface_rows:
        child_by_role.setdefault(str(row[0]), []).append(row)
    values = []
    for role in _WAN_ROLE_ORDER:
        row = next((item for item in parent_rows if item[0] == role), None)
        if row is None:
            continue
        legacy = str(row[4] or "").strip()
        names = [
            str(item[2]).strip()
            for item in child_by_role.get(role, [])
            if item[1] == row[1] and str(item[2]).strip()
        ]
        if names and legacy and legacy not in names:
            names = [legacy]
        elif not names and legacy:
            names = [legacy]
        values.append({
            "role": role,
            "slot": "primary" if role == "external_wan_gateway" else "secondary",
            "node_id": row[1],
            "device_name": row[2],
            "device_address": row[3],
            "interface_name": row[4],
            "interface_names": names,
            "changed_at": row[5],
            "changed_by": row[6],
        })
    return values


def _validate_durable_selection(selected: list[dict], rows: dict) -> None:
    authority_by_run = {str(row[0]): row for row in rows["authority_evidence"]}
    inputs_by_run: dict[str, list[list]] = {}
    for row in rows["authority_inputs"]:
        inputs_by_run.setdefault(str(row[0]), []).append(row)
    intents_by_run: dict[str, list[list]] = {}
    for row in rows["admission_intents"]:
        intents_by_run.setdefault(str(row[3]), []).append(row)
    results_by_id = {str(row[0]): row for row in rows["results"]}
    result_inputs: dict[str, list[list]] = {}
    for row in rows["result_inputs"]:
        result_inputs.setdefault(str(row[0]), []).append(row)
    result_links: dict[str, list[list]] = {}
    for row in rows["result_links"]:
        result_links.setdefault(str(row[0]), []).append(row)

    for record in selected:
        run_id = str(record["run_id"])
        dependency = record["job_dependency"]
        job = dependency["job"]
        result_id = str(dependency["result"][0])
        authority = authority_by_run.get(run_id)
        if authority is None or authority[1] != "active":
            raise DeviceAnalysisSnapshotError(
                f"Device collection {run_id} has no active evidence authority"
            )
        contract = str(record["selection_contract"])
        expected_intent = {
            MANUAL_UPLOAD_SELECTION_CONTRACT: MANUAL_DEVICE_INTENT,
            COLLECTED_DEVICE_SELECTION_CONTRACT: COLLECTED_DEVICE_INTENT,
        }.get(contract)
        intent_rows = intents_by_run.get(run_id, [])
        if expected_intent is None or len(intent_rows) != 1:
            raise DeviceAnalysisSnapshotError(
                f"Device collection {run_id} has no single durable admission intent"
            )
        intent = intent_rows[0]
        if (
            intent[1] != expected_intent
            or intent[5] != authority[3]
            or intent[11] != "admitted"
            or intent[14] != job[0]
            or intent[16] != "complete"
        ):
            raise DeviceAnalysisSnapshotError(
                f"Device collection {run_id} admission intent is incomplete or inconsistent"
            )
        result = results_by_id.get(result_id)
        if result is None or hashlib.sha256(str(result[7]).encode()).hexdigest() != result[8]:
            raise DeviceAnalysisSnapshotError(
                f"Device collection {run_id} has an invalid completed result"
            )
        if result_inputs.get(result_id, []) != dependency["inputs"]:
            raise DeviceAnalysisSnapshotError(
                f"Device collection {run_id} result inputs are incomplete or changed"
            )
        if result_links.get(result_id, []) != dependency["observation_links"]:
            raise DeviceAnalysisSnapshotError(
                f"Device collection {run_id} result links changed during selection"
            )
        if contract == MANUAL_UPLOAD_SELECTION_CONTRACT:
            expected_links = {
                (result_id, "configuration", str(authority[3])),
                (result_id, "raw_output", str(authority[3])),
            }
        else:
            expected_links = {
                (result_id, str(item[1]), str(item[6]))
                for item in inputs_by_run.get(run_id, [])
                if item[3] == "artifact_file"
            }
        actual_links = {
            (str(item[0]), str(item[1]), str(item[2]))
            for item in result_links.get(result_id, [])
        }
        if not expected_links or not expected_links.issubset(actual_links):
            raise DeviceAnalysisSnapshotError(
                f"Device collection {run_id} completed result links are incomplete"
            )


def _selected_file_rows(
    config_dir: Path, run_ids: list[str], authority_evidence: list[list],
    authority_inputs: list[list],
) -> list[dict]:
    authority_by_run = {str(row[0]): row for row in authority_evidence}
    inputs_by_run: dict[str, list[list]] = {}
    for row in authority_inputs:
        inputs_by_run.setdefault(str(row[0]), []).append(row)
    described = []
    for run_id in run_ids:
        run_dir = _safe_run_directory(config_dir, run_id)
        manifest_path = run_dir / "manifest.json"
        if _has_symlink_component(manifest_path):
            raise DeviceAnalysisSnapshotError(
                f"Device collection {run_id} manifest uses a symbolic link"
            )
        try:
            manifest = _stable_regular_identity(
                manifest_path, f"Device collection {run_id} manifest"
            )
        except (OSError, DeviceAnalysisSnapshotError) as exc:
            raise DeviceAnalysisSnapshotError(
                f"Device collection {run_id} manifest is not stable: {exc}"
            ) from exc
        files = []
        authority = authority_by_run.get(run_id)
        if (
            authority is None
            or authority[1] != "active"
            or authority[4] != authority[12]
            or authority[13] not in {"device_collection", "device_config_upload"}
            or authority[14] != run_id
            or int(authority[19] if authority[19] is not None else -1) < 0
            or not authority[5]
            or not authority[21]
        ):
            raise DeviceAnalysisSnapshotError(
                f"Device collection {run_id} evidence authority is inconsistent"
            )
        top_sha = str(authority[4])
        top_size = int(authority[19])
        top_filename = str(authority[5])
        if Path(top_filename).name != top_filename:
            raise DeviceAnalysisSnapshotError(
                f"Device collection {run_id} has an unsafe retained filename"
            )
        files.append({
            "role": "collection_authority", "position": 0,
            "filename": top_filename, "sha256": top_sha, "size": top_size,
            "local": _verified_identity(
                run_dir / top_filename, expected_sha256=top_sha,
                expected_size=top_size,
                label=f"Run-local device authority {run_id}/{top_filename}",
            ),
            "canonical": _verified_identity(
                Path(str(authority[21])), expected_sha256=top_sha,
                expected_size=top_size,
                label=f"Canonical device authority {top_sha}",
            ),
        })
        for row in inputs_by_run.get(run_id, []):
            if row[3] != "artifact_file":
                continue
            filename = str(row[5] or "")
            if not filename or Path(filename).name != filename:
                raise DeviceAnalysisSnapshotError(
                    f"Device collection {run_id} has an unsafe authority filename"
                )
            expected_sha = str(row[7] or "")
            expected_size = int(row[8] if row[8] is not None else -1)
            if (
                row[10] != expected_sha
                or row[11] not in {"device_collection", "device_config_upload"}
                or row[12] != run_id
                or int(row[17] if row[17] is not None else -1) != expected_size
                or not row[19]
            ):
                raise DeviceAnalysisSnapshotError(
                    f"Device collection {run_id} authority input is inconsistent"
                )
            local = _verified_identity(
                run_dir / filename,
                expected_sha256=expected_sha,
                expected_size=expected_size,
                label=f"Run-local device evidence {run_id}/{filename}",
            )
            canonical = _verified_identity(
                Path(str(row[19])),
                expected_sha256=expected_sha,
                expected_size=expected_size,
                label=f"Canonical device evidence {expected_sha}",
            )
            files.append({
                "role": row[1], "position": row[2], "filename": filename,
                "sha256": expected_sha, "size": expected_size,
                "local": local, "canonical": canonical,
            })
        described.append({
            "run_id": run_id,
            "manifest": manifest,
            "directory_shape": _directory_shape(run_dir),
            "authority_files": files,
        })
    return described


def capture_device_analysis_snapshot(
    *, db_path: Path, config_dir: Path,
) -> NetworkEvidenceSnapshot:
    """Capture exact selected device inputs without mutating retained state."""
    try:
        database = stable_path_identity(db_path)
        selected, selector = select_latest_device_evidence(db_path, config_dir)
        if not selector.get("catalog_available"):
            raise DeviceAnalysisSnapshotError("Current device selector is unavailable")
        run_ids = [str(item["run_id"]) for item in selected]
        result_ids = [
            str(item["job_dependency"]["result"][0]) for item in selected
        ]
        with connect_database(db_path, read_only=True) as db:
            db.execute("BEGIN")
            database_rows = _selected_database_rows(db, run_ids, result_ids)
        confirmed_selected, confirmed_selector = select_latest_device_evidence(
            db_path, config_dir
        )
        confirmed_database = stable_path_identity(db_path)
        if (
            database != confirmed_database
            or selected != confirmed_selected
            or selector != confirmed_selector
        ):
            raise DeviceAnalysisSnapshotError(
                "Current device selection changed while its dependencies were captured"
            )
        _validate_durable_selection(selected, database_rows)
        file_rows = _selected_file_rows(
            config_dir, run_ids, database_rows["authority_evidence"],
            database_rows["authority_inputs"],
        )
        if stable_path_identity(db_path) != database:
            raise DeviceAnalysisSnapshotError(
                "The analysis database changed while device files were verified"
            )
    except (OSError, sqlite3.Error, KeyError, TypeError, ValueError) as exc:
        if isinstance(exc, DeviceAnalysisSnapshotError):
            raise
        raise DeviceAnalysisSnapshotError(
            f"Current device analysis inputs could not be verified: {exc}"
        ) from exc

    descriptor = {
        "cache_contract": DEVICE_ANALYSIS_VIEW_CONTRACT_VERSION,
        "device_summary_version": DEVICE_SUMMARY_VERSION,
        "device_interface_job_type": DEVICE_INTERFACE_JOB_TYPE,
        "database": database,
        "selector": selector,
        "database_rows": database_rows,
        "files": file_rows,
    }
    return NetworkEvidenceSnapshot(
        _digest(descriptor),
        {
            "selected_run_ids": run_ids,
            "gateways": _gateway_values(
                database_rows["wan_parent_rows"],
                database_rows["wan_interface_rows"],
            ),
        },
    )
