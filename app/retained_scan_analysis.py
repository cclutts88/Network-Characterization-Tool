"""Read-only reopening of prepared automated Nmap analysis."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sqlite3

from app.comparison import describe_run_group, group_run_manifests, merge_analyses
from app.database import connect_database
from app.derived_contracts import (
    NMAP_BASE_ANALYSIS_FAMILY,
    NMAP_BASE_ANALYSIS_VERSION,
    NMAP_BASE_PARAMETERS,
    NMAP_BASE_PAYLOAD_SCHEMA_VERSION,
)
from app.derived_results import _load_derived_result, derived_result_identity


GROUP_COMPOSITION_VERSION = "nmap-group-composition:1"
TERMINAL_SAVED_STATES = {"completed"}
MAX_PREPARED_HISTORY_GROUPS = 5_000
MAX_PREPARED_HISTORY_RUNS = 5_000


class RetainedScanAnalysisUnavailable(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _stable_verified_bytes(path: Path, digest: str, size_bytes: int, label: str) -> None:
    if not path.is_file() or path.is_symlink():
        raise RetainedScanAnalysisUnavailable("evidence_unavailable", f"{label} is unavailable")
    before = path.stat()
    content = path.read_bytes()
    after = path.stat()
    identity = (before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
    if identity != (after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
        raise RetainedScanAnalysisUnavailable("evidence_changed", f"{label} changed during verification")
    if len(content) != size_bytes or hashlib.sha256(content).hexdigest() != digest:
        raise RetainedScanAnalysisUnavailable("evidence_changed", f"{label} failed exact-content verification")


def _group_manifests(db: sqlite3.Connection, run_id: str) -> list[dict]:
    row = db.execute(
        "SELECT run_id, status, manifest_json FROM scan_runs WHERE run_id = ?", (run_id,),
    ).fetchone()
    if row is None:
        raise KeyError("Scan run not found")
    selected_row_id, selected_status, selected_json = row
    selected = json.loads(selected_json)
    if str(selected.get("run_id") or "") != str(selected_row_id):
        raise RetainedScanAnalysisUnavailable(
            "source_conflict", "The saved scan row and its manifest disagree about the run identity",
        )
    batch_id = str(selected.get("schedule_batch_id") or "").strip()
    if batch_id:
        rows = db.execute(
            """SELECT run_id, status, manifest_json FROM scan_runs
               WHERE json_extract(manifest_json, '$.schedule_batch_id') = ?
               ORDER BY CAST(json_extract(manifest_json, '$.chunk_number') AS INTEGER),
                        created_at, rowid""",
            (batch_id,),
        ).fetchall()
        row_ids = [str(item[0] or "") for item in rows]
        database_statuses = [str(item[1] or "") for item in rows]
        manifests = [json.loads(item[2]) for item in rows]
    else:
        row_ids = [str(selected_row_id)]
        database_statuses = [str(selected_status or "")]
        manifests = [selected]
    if not manifests:
        raise RetainedScanAnalysisUnavailable("group_incomplete", "The saved scan group is unavailable")
    if any(str(item.get("run_id") or "") != row_id for row_id, item in zip(row_ids, manifests)):
        raise RetainedScanAnalysisUnavailable(
            "source_conflict", "A saved scan chunk row and its manifest disagree about the run identity",
        )
    expected_values = {int(item.get("chunk_count") or 1) for item in manifests}
    if len(expected_values) != 1:
        raise RetainedScanAnalysisUnavailable("group_incomplete", "The saved scan group has conflicting chunk counts")
    expected = expected_values.pop()
    numbers = [int(item.get("chunk_number") or 1) for item in manifests]
    if expected != len(manifests) or sorted(numbers) != list(range(1, expected + 1)):
        raise RetainedScanAnalysisUnavailable(
            "group_incomplete",
            f"The saved scan group is incomplete: expected {expected} ordered chunks and found {len(manifests)}",
        )
    if len(set(numbers)) != len(numbers):
        raise RetainedScanAnalysisUnavailable("group_incomplete", "The saved scan group contains duplicate chunks")
    if any(status != "completed" for status in database_statuses) or any(
        item.get("status") != "completed" for item in manifests
    ):
        raise RetainedScanAnalysisUnavailable(
            "source_incomplete", "Every scan chunk must be completed in both saved status records before analysis can be reopened",
        )
    return manifests


def _unavailable_job_state(db: sqlite3.Connection, run_id: str) -> RetainedScanAnalysisUnavailable:
    job_storage = db.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'pipeline_jobs'",
    ).fetchone()
    authority = db.execute(
        """SELECT observation.observation_id, observation.sha256, artifact.size_bytes
           FROM artifact_observations observation
           JOIN artifact_registry artifact ON artifact.sha256 = observation.sha256
           WHERE observation.source_kind = 'nmap_scan' AND observation.source_ref = ?
             AND observation.original_filename = 'scan.xml'""",
        (run_id,),
    ).fetchall()
    if not authority:
        return RetainedScanAnalysisUnavailable(
            "conversion_required",
            "This historical scan must be registered by the storage backfill before saved analysis can be prepared",
        )
    if len(authority) != 1:
        return RetainedScanAnalysisUnavailable(
            "analysis_conflict", "The saved scan does not have exactly one authoritative scan.xml observation",
        )
    if job_storage is None:
        return RetainedScanAnalysisUnavailable(
            "prepare_required", "Saved analysis is not prepared. Use Prepare from saved scan in Scan History",
        )
    observation_id, digest, size_bytes = authority[0]
    identity = derived_result_identity(
        family=NMAP_BASE_ANALYSIS_FAMILY,
        analysis_version=NMAP_BASE_ANALYSIS_VERSION,
        payload_schema_version=NMAP_BASE_PAYLOAD_SCHEMA_VERSION,
        parameters=dict(NMAP_BASE_PARAMETERS),
        inputs=[{
            "role": "nmap_xml", "kind": "artifact_sha256", "identity": digest,
            "metadata": {"media_family": "nmap_xml"},
        }],
    )
    jobs = db.execute(
        """SELECT job_id FROM pipeline_jobs
           WHERE job_type = 'nmap_base_analysis' AND source_run_id = ?
             AND source_observation_id = ? AND source_status = 'completed'
             AND source_sha256 = ? AND source_size_bytes = ?
             AND target_family = ? AND target_analysis_version = ?
             AND target_payload_schema_version = ? AND target_parameters_json = ?
             AND target_computation_key = ? AND target_result_id = ?""",
        (
            run_id, observation_id, digest, int(size_bytes),
            NMAP_BASE_ANALYSIS_FAMILY, NMAP_BASE_ANALYSIS_VERSION,
            NMAP_BASE_PAYLOAD_SCHEMA_VERSION, _canonical_json(dict(NMAP_BASE_PARAMETERS)),
            identity.computation_key, identity.result_id,
        ),
    ).fetchall()
    if not jobs:
        return RetainedScanAnalysisUnavailable(
            "prepare_required", "Saved analysis is not prepared. Use Prepare from saved scan in Scan History",
        )
    if len(jobs) != 1:
        return RetainedScanAnalysisUnavailable(
            "analysis_conflict", "More than one current saved-analysis job claims the authoritative source",
        )
    row = db.execute(
        """SELECT state, error FROM pipeline_job_attempts
           WHERE job_id = ? ORDER BY attempt_number DESC LIMIT 1""",
        (jobs[0][0],),
    ).fetchone()
    if row is None:
        return RetainedScanAnalysisUnavailable(
            "prepare_required", "Saved analysis is not prepared. Use Prepare from saved scan in Scan History",
        )
    state, error = row
    if state in {"queued", "running"}:
        return RetainedScanAnalysisUnavailable(
            "preparing", "Saved analysis is still being prepared. Its status is available in Scan History",
        )
    if state in {"failed", "interrupted"}:
        detail = f": {error}" if error else ""
        return RetainedScanAnalysisUnavailable(
            "retry_required", f"Saved analysis needs attention. Use Retry saved analysis in Scan History{detail}",
        )
    return RetainedScanAnalysisUnavailable(
        "prepare_required", "A completed current saved-analysis result is not available",
    )


def _prepared_child(db: sqlite3.Connection, manifest: dict) -> tuple[dict, dict]:
    run_id = manifest["run_id"]
    job_storage = db.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'pipeline_jobs'",
    ).fetchone()
    if job_storage is None:
        raise _unavailable_job_state(db, run_id)
    authority = db.execute(
        """SELECT observation.observation_id, observation.sha256,
                  artifact.size_bytes, artifact.canonical_path
           FROM artifact_observations observation
           JOIN artifact_registry artifact ON artifact.sha256 = observation.sha256
           WHERE observation.source_kind = 'nmap_scan'
             AND observation.source_ref = ?
             AND observation.original_filename = 'scan.xml'""",
        (run_id,),
    ).fetchall()
    if len(authority) != 1:
        raise RetainedScanAnalysisUnavailable(
            "analysis_conflict",
            "The saved scan does not have exactly one authoritative registered scan.xml observation",
        )
    observation_id, digest, size_bytes, canonical_path = authority[0]
    expected_parameters = _canonical_json(dict(NMAP_BASE_PARAMETERS))
    identity = derived_result_identity(
        family=NMAP_BASE_ANALYSIS_FAMILY,
        analysis_version=NMAP_BASE_ANALYSIS_VERSION,
        payload_schema_version=NMAP_BASE_PAYLOAD_SCHEMA_VERSION,
        parameters=dict(NMAP_BASE_PARAMETERS),
        inputs=[{
            "role": "nmap_xml", "kind": "artifact_sha256", "identity": digest,
            "metadata": {"media_family": "nmap_xml"},
        }],
    )
    jobs = db.execute(
        """SELECT job_id, target_result_id
           FROM pipeline_jobs
           WHERE job_type = 'nmap_base_analysis' AND source_run_id = ?
             AND source_observation_id = ? AND source_status = 'completed'
             AND source_sha256 = ? AND source_size_bytes = ?
             AND target_family = ? AND target_analysis_version = ?
             AND target_payload_schema_version = ? AND target_parameters_json = ?
             AND target_computation_key = ? AND target_result_id = ?""",
        (
            run_id, observation_id, digest, int(size_bytes),
            NMAP_BASE_ANALYSIS_FAMILY, NMAP_BASE_ANALYSIS_VERSION,
            NMAP_BASE_PAYLOAD_SCHEMA_VERSION, expected_parameters,
            identity.computation_key, identity.result_id,
        ),
    ).fetchall()
    if not jobs:
        raise _unavailable_job_state(db, run_id)
    if len(jobs) != 1:
        raise RetainedScanAnalysisUnavailable("analysis_conflict", "More than one current saved-analysis job claims the authoritative source")
    job_id, result_id = jobs[0]
    attempt = db.execute(
        """SELECT state, result_id, output_kind, output_id, finished_at
           FROM pipeline_job_attempts WHERE job_id = ?
           ORDER BY attempt_number DESC LIMIT 1""",
        (job_id,),
    ).fetchone()
    if attempt is None or attempt[0] != "completed":
        raise _unavailable_job_state(db, run_id)
    _, attempt_result_id, output_kind, output_id, finished_at = attempt
    if (
        result_id != identity.result_id
        or attempt_result_id != result_id
        or output_kind != "derived_result"
        or output_id != result_id
    ):
        raise RetainedScanAnalysisUnavailable("analysis_conflict", "The completed saved-analysis result identifiers do not agree")
    retained = _load_derived_result(db, identity)
    if retained is None:
        raise RetainedScanAnalysisUnavailable("analysis_missing", "The saved analysis result is missing")
    provenance = db.execute(
        """SELECT observation.sha256, artifact.size_bytes, artifact.canonical_path
           FROM artifact_observations observation
           JOIN artifact_registry artifact ON artifact.sha256 = observation.sha256
           JOIN derived_result_observation_links link
             ON link.observation_id = observation.observation_id
            AND link.result_id = ? AND link.input_role = 'nmap_xml'
           WHERE observation.observation_id = ?
             AND observation.source_kind = 'nmap_scan'
             AND observation.source_ref = ?
             AND observation.original_filename = 'scan.xml'""",
        (result_id, observation_id, run_id),
    ).fetchall()
    if len(provenance) != 1 or provenance[0][0] != digest or int(provenance[0][1]) != int(size_bytes):
        raise RetainedScanAnalysisUnavailable("analysis_conflict", "Saved analysis provenance is incomplete or inconsistent")
    return retained, {
        "run_id": run_id,
        "observation_id": observation_id,
        "sha256": digest,
        "size_bytes": int(size_bytes),
        "canonical_path": canonical_path,
        "result_id": result_id,
        "family": NMAP_BASE_ANALYSIS_FAMILY,
        "analysis_version": NMAP_BASE_ANALYSIS_VERSION,
        "payload_schema_version": NMAP_BASE_PAYLOAD_SCHEMA_VERSION,
        "generated_at": retained["generated_at"],
        "job_finished_at": finished_at,
    }


def load_prepared_scan_group(db_path: Path, data_dir: Path, run_id: str) -> dict:
    """Load one exact saved scan group without parsing, queuing, or writing."""
    if not Path(db_path).is_file():
        raise KeyError("Scan run not found")
    with connect_database(db_path, read_only=True) as db:
        db.execute("BEGIN")
        manifests = _group_manifests(db, run_id)
        children = [_prepared_child(db, item) for item in manifests]
        for manifest, (_, receipt) in zip(manifests, children):
            local_path = Path(data_dir) / "scan-runs" / manifest["run_id"] / "scan.xml"
            _stable_verified_bytes(local_path, receipt["sha256"], receipt["size_bytes"], "Run-local Nmap evidence")
            _stable_verified_bytes(Path(receipt["canonical_path"]), receipt["sha256"], receipt["size_bytes"], "Canonical Nmap evidence")
    description = describe_run_group(manifests)
    return {
        "manifests": manifests,
        "group": description,
        "analysis": merge_analyses([item[0]["payload"] for item in children]),
        "provenance": {
            "composition_version": GROUP_COMPOSITION_VERSION,
            "composition": "deterministic read-only merge of exact prepared child results",
            "children": [item[1] for item in children],
        },
    }


def list_prepared_scan_group_metadata(db_path: Path) -> list[dict]:
    """List bounded prepared-group metadata without opening results or evidence files."""
    if not Path(db_path).is_file():
        return []
    with connect_database(db_path, read_only=True) as db:
        db.execute("BEGIN")
        if db.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'pipeline_jobs'",
        ).fetchone() is None:
            return []
        count = int(db.execute("SELECT COUNT(*) FROM scan_runs").fetchone()[0])
        if count > MAX_PREPARED_HISTORY_RUNS:
            raise RetainedScanAnalysisUnavailable(
                "history_limit",
                f"Saved scan history exceeds the reviewed {MAX_PREPARED_HISTORY_RUNS:,}-run metadata limit",
            )
        rows = db.execute(
            """SELECT scan.run_id, scan.manifest_json,
                      observation.sha256, artifact.size_bytes,
                      job.target_computation_key, job.target_result_id,
                      attempt.result_id, attempt.output_kind, attempt.output_id
               FROM scan_runs scan
               JOIN artifact_observations observation
                 ON observation.source_kind = 'nmap_scan'
                AND observation.source_ref = scan.run_id
                AND observation.original_filename = 'scan.xml'
               JOIN artifact_registry artifact ON artifact.sha256 = observation.sha256
               JOIN pipeline_jobs job
                 ON job.job_type = 'nmap_base_analysis'
                AND job.source_run_id = scan.run_id
                AND job.source_observation_id = observation.observation_id
                AND job.source_status = 'completed'
                AND job.source_sha256 = observation.sha256
                AND job.source_size_bytes = artifact.size_bytes
                AND job.target_family = ?
                AND job.target_analysis_version = ?
                AND job.target_payload_schema_version = ?
                AND job.target_parameters_json = ?
               JOIN pipeline_job_attempts attempt
                 ON attempt.job_id = job.job_id
                AND attempt.attempt_number = (
                    SELECT MAX(latest.attempt_number)
                    FROM pipeline_job_attempts latest WHERE latest.job_id = job.job_id
                )
                AND attempt.state = 'completed'
                AND attempt.result_id = job.target_result_id
                AND attempt.output_kind = 'derived_result'
                AND attempt.output_id = job.target_result_id
               WHERE scan.status = 'completed'
                 AND CASE WHEN json_valid(scan.manifest_json)
                          THEN json_extract(scan.manifest_json, '$.status') END = 'completed'
                 AND (
                    SELECT COUNT(*) FROM artifact_observations authority
                    WHERE authority.source_kind = 'nmap_scan'
                      AND authority.source_ref = scan.run_id
                      AND authority.original_filename = 'scan.xml'
                 ) = 1
               ORDER BY scan.created_at DESC, scan.run_id DESC""",
            (
                NMAP_BASE_ANALYSIS_FAMILY,
                NMAP_BASE_ANALYSIS_VERSION,
                NMAP_BASE_PAYLOAD_SCHEMA_VERSION,
                _canonical_json(dict(NMAP_BASE_PARAMETERS)),
            ),
        ).fetchall()
        eligible_by_run: dict[str, list[dict]] = {}
        for (
            row_id, manifest_json, digest, size_bytes,
            computation_key, target_result_id, attempt_result_id,
            output_kind, output_id,
        ) in rows:
            try:
                manifest = json.loads(manifest_json)
            except (TypeError, json.JSONDecodeError):
                continue
            if str(manifest.get("run_id") or "") != str(row_id):
                continue
            identity = derived_result_identity(
                family=NMAP_BASE_ANALYSIS_FAMILY,
                analysis_version=NMAP_BASE_ANALYSIS_VERSION,
                payload_schema_version=NMAP_BASE_PAYLOAD_SCHEMA_VERSION,
                parameters=dict(NMAP_BASE_PARAMETERS),
                inputs=[{
                    "role": "nmap_xml", "kind": "artifact_sha256", "identity": digest,
                    "metadata": {"media_family": "nmap_xml"},
                }],
            )
            if (
                int(size_bytes) < 0
                or computation_key != identity.computation_key
                or target_result_id != identity.result_id
                or attempt_result_id != identity.result_id
                or output_kind != "derived_result"
                or output_id != identity.result_id
            ):
                continue
            eligible_by_run.setdefault(str(row_id), []).append(manifest)
        eligible = [items[0] for items in eligible_by_run.values() if len(items) == 1]
        groups = group_run_manifests(eligible)
        prepared = []
        for manifests in groups:
            expected = {int(item.get("chunk_count") or 1) for item in manifests}
            numbers = [int(item.get("chunk_number") or 1) for item in manifests]
            if (
                len(expected) != 1
                or expected.pop() != len(manifests)
                or sorted(numbers) != list(range(1, len(manifests) + 1))
                or len(set(numbers)) != len(numbers)
            ):
                continue
            description = describe_run_group(manifests)
            prepared.append({
                "manifests": manifests,
                "group": description,
                "selection_run_id": description["run_ids"][-1],
            })
    prepared.sort(
        key=lambda item: (
            item["group"].get("completed_at") or item["group"].get("created_at") or "",
            item["group"].get("group_id") or "",
        ),
        reverse=True,
    )
    if len(prepared) > MAX_PREPARED_HISTORY_GROUPS:
        raise RetainedScanAnalysisUnavailable(
            "history_limit",
            f"Prepared scan history exceeds the reviewed {MAX_PREPARED_HISTORY_GROUPS:,}-group metadata limit",
        )
    return prepared


def list_prepared_scan_groups(
    db_path: Path, data_dir: Path, *, limit: int = 25, offset: int = 0,
) -> dict:
    """Return one bounded page of exact prepared groups in stable newest-first order."""
    if limit < 1 or limit > 100 or offset < 0:
        raise ValueError("Prepared scan page is out of range")
    if not Path(db_path).is_file():
        return {"items": [], "pagination": {"limit": limit, "offset": offset, "total": 0, "has_more": False}}
    with connect_database(db_path, read_only=True) as db:
        db.execute("BEGIN")
        if db.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'pipeline_jobs'",
        ).fetchone() is None:
            return {"items": [], "pagination": {"limit": limit, "offset": offset, "total": 0, "has_more": False}}
        cte = """
            WITH prepared_runs AS (
                SELECT DISTINCT job.source_run_id AS run_id
                FROM pipeline_jobs job
                JOIN pipeline_job_attempts attempt ON attempt.job_id = job.job_id
                WHERE job.job_type = 'nmap_base_analysis'
                  AND attempt.state = 'completed'
                  AND attempt.output_kind = 'derived_result'
                  AND attempt.output_id = job.target_result_id
            ), grouped AS (
                SELECT scan.run_id, scan.created_at,
                       CASE
                         WHEN COALESCE(json_extract(scan.manifest_json, '$.schedule_batch_id'), '') <> ''
                         THEN 'schedule-batch:' || json_extract(scan.manifest_json, '$.schedule_batch_id')
                         ELSE 'run:' || scan.run_id
                       END AS group_key
                FROM scan_runs scan
                JOIN prepared_runs prepared ON prepared.run_id = scan.run_id
                WHERE json_extract(scan.manifest_json, '$.status') = 'completed'
            ), leaders AS (
                SELECT group_key, MAX(created_at) AS sort_time, MIN(run_id) AS representative_run_id
                FROM grouped GROUP BY group_key
            )
        """
        total = int(db.execute(cte + " SELECT COUNT(*) FROM leaders").fetchone()[0])
        rows = db.execute(
            cte + """ SELECT representative_run_id FROM leaders
                       ORDER BY sort_time DESC, group_key DESC LIMIT ? OFFSET ?""",
            (limit, offset),
        ).fetchall()
    items = []
    unavailable = []
    for row in rows:
        try:
            items.append(load_prepared_scan_group(db_path, data_dir, row[0]))
        except (KeyError, RetainedScanAnalysisUnavailable) as exc:
            unavailable.append({"run_id": row[0], "reason": str(exc)})
    return {
        "items": items,
        "unavailable": unavailable,
        "pagination": {
            "limit": limit, "offset": offset, "total": total,
            "has_more": offset + len(rows) < total,
        },
    }
