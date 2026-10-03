"""Internal content-addressed adapter for one Nmap XML base analysis."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sqlite3
from typing import Callable

from app.database import connect_database, initialize_once_per_database
from app.derived_results import (
    derived_result_identity,
    init_derived_result_storage,
    load_derived_result,
    load_linked_derived_result,
    prepare_derived_result,
    publish_derived_result,
)


NMAP_BASE_ANALYSIS_FAMILY = "nmap_base_analysis"
NMAP_BASE_ANALYSIS_VERSION = "nmap-base-analysis:1"
NMAP_BASE_PAYLOAD_SCHEMA_VERSION = 1
NMAP_ANALYSIS_TERMINAL_STATES = {
    "completed",
    "completed_without_nmap",
    "failed",
    "cancelled",
    "timed_out",
}
NMAP_BASE_PARAMETERS = {
    "parser": "nct.parse_xml",
    "coverage_presence_os_inference_contract": 1,
}


@initialize_once_per_database
def retire_legacy_scan_analysis_cache(db_path: Path) -> None:
    """Remove disposable legacy results during startup, never from a page read."""
    with connect_database(db_path) as db:
        db.execute("BEGIN IMMEDIATE")
        db.execute("DROP TABLE IF EXISTS scan_analysis_cache")


def _parse_nmap_xml(content: bytes):
    from app.main import parse_xml
    return parse_xml(content)


def _stable_file_bytes(path: Path, label: str) -> bytes:
    if not path.is_file() or path.is_symlink():
        raise ValueError(f"{label} is unavailable")
    before = path.stat()
    content = path.read_bytes()
    after = path.stat()
    if (before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
        after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns,
    ):
        raise ValueError(f"{label} changed during verification")
    return content


def _verified_observation_bytes(db_path: Path, observation_id: str) -> tuple[bytes, dict]:
    with connect_database(db_path, read_only=True) as db:
        row = db.execute(
            """SELECT observation.observation_id, observation.sha256,
                      observation.source_kind, observation.source_ref,
                      observation.original_filename, artifact.size_bytes,
                      artifact.canonical_path
               FROM artifact_observations observation
               JOIN artifact_registry artifact ON artifact.sha256 = observation.sha256
               WHERE observation.observation_id = ?""",
            (observation_id,),
        ).fetchone()
    if row is None:
        raise KeyError("Artifact observation is not available")
    if row[2] not in {"nmap_import", "nmap_scan"}:
        raise ValueError("Nmap base analysis requires a registered Nmap observation")
    content = _stable_file_bytes(Path(row[6]), "Canonical Nmap evidence")
    digest = hashlib.sha256(content).hexdigest()
    if digest != row[1] or len(content) != int(row[5]):
        raise ValueError("Canonical Nmap evidence failed exact-content verification")
    return content, {
        "observation_id": row[0],
        "sha256": row[1],
        "source_kind": row[2],
        "source_ref": row[3],
        "original_filename": row[4],
    }


def analyze_registered_nmap_base(
    db_path: Path, observation_id: str, *,
    analysis_version: str | None = None,
    parameters: dict | None = None,
    authority_guard: Callable[[sqlite3.Connection], None] | None = None,
) -> dict:
    """Reuse or publish base parsing for verified bytes without run/scope provenance."""
    init_derived_result_storage(db_path)
    analysis_version = analysis_version or NMAP_BASE_ANALYSIS_VERSION
    content, observation = _verified_observation_bytes(db_path, observation_id)
    requested_parameters = dict(parameters or {})
    for key, value in NMAP_BASE_PARAMETERS.items():
        if key in requested_parameters and requested_parameters[key] != value:
            raise ValueError(f"{key} is fixed by the Nmap base-analysis contract")
    parameters = {**NMAP_BASE_PARAMETERS, **requested_parameters}
    inputs = [{
        "role": "nmap_xml",
        "kind": "artifact_sha256",
        "identity": observation["sha256"],
        "metadata": {"media_family": "nmap_xml"},
    }]
    identity = derived_result_identity(
        family=NMAP_BASE_ANALYSIS_FAMILY,
        analysis_version=analysis_version,
        payload_schema_version=NMAP_BASE_PAYLOAD_SCHEMA_VERSION,
        parameters=parameters,
        inputs=inputs,
    )
    linked = load_linked_derived_result(
        db_path,
        identity,
        role="nmap_xml",
        observation_id=observation_id,
        read_guard=authority_guard,
    )
    if linked is not None:
        return {**linked, "reused": True, "observation": observation}
    retained = load_derived_result(db_path, identity)
    if retained is None:
        parsed = _parse_nmap_xml(content)
        reused = False
    else:
        parsed = retained["payload"]
        reused = True
    prepared = prepare_derived_result(
        family=NMAP_BASE_ANALYSIS_FAMILY,
        analysis_version=analysis_version,
        payload_schema_version=NMAP_BASE_PAYLOAD_SCHEMA_VERSION,
        parameters=parameters,
        inputs=inputs,
        payload=parsed,
    )
    publication = publish_derived_result(
        db_path,
        prepared,
        observation_links=[{"role": "nmap_xml", "observation_id": observation_id}],
        transaction_guard=authority_guard,
    )
    if reused or not publication["created"]:
        retained = load_linked_derived_result(
            db_path,
            identity,
            role="nmap_xml",
            observation_id=observation_id,
            read_guard=authority_guard,
        )
        if retained is None:
            raise RuntimeError("Published derived result and provenance could not be reloaded")
        return {**retained, "reused": True, "observation": observation}
    return {
        "result_id": publication["result_id"],
        "family": NMAP_BASE_ANALYSIS_FAMILY,
        "analysis_version": analysis_version,
        "payload_schema_version": NMAP_BASE_PAYLOAD_SCHEMA_VERSION,
        "generated_at": prepared.generated_at,
        "payload": json.loads(prepared.result_json),
        "reused": False,
        "observation": observation,
    }


def _scan_xml_rows(db: sqlite3.Connection, run_id: str) -> list[tuple]:
    return db.execute(
        """SELECT observation.observation_id, observation.sha256, artifact.size_bytes
           FROM artifact_observations observation
           JOIN artifact_registry artifact ON artifact.sha256 = observation.sha256
           WHERE observation.source_kind = 'nmap_scan'
             AND observation.source_ref = ?
             AND observation.original_filename = 'scan.xml'
           ORDER BY observation.observation_id""",
        (run_id,),
    ).fetchall()


def _require_scan_run(
    db: sqlite3.Connection, run_id: str, *, finalized: bool = False,
) -> str:
    row = db.execute(
        "SELECT status FROM scan_runs WHERE run_id = ?", (run_id,),
    ).fetchone()
    if row is None:
        raise ValueError("Scan run is no longer available")
    status = str(row[0] or "")
    if finalized and status not in NMAP_ANALYSIS_TERMINAL_STATES:
        raise ValueError("Scan run is not finalized for reusable analysis")
    return status


def _scan_authority_guard(run_id: str, observation_id: str):
    def require_authority(db: sqlite3.Connection) -> None:
        _require_scan_run(db, run_id, finalized=True)
        rows = _scan_xml_rows(db, run_id)
        if len(rows) != 1:
            raise ValueError("Scan run does not have one authoritative registered scan.xml")
        if rows[0][0] != observation_id:
            raise ValueError("Registered scan.xml authority changed during analysis")
    return require_authority


def _verify_run_local_artifact(path: Path, expected_sha256: str, expected_size: int) -> bytes:
    content = _stable_file_bytes(path, "Run-local Nmap evidence")
    if len(content) != expected_size or hashlib.sha256(content).hexdigest() != expected_sha256:
        raise ValueError("Run-local Nmap evidence does not match its registered artifact")
    return content


def analyze_scan_run_nmap_base(
    db_path: Path,
    run_id: str,
    run_local_path: Path,
    *,
    registration_expected: bool = False,
    analysis_version: str | None = None,
) -> dict:
    """Analyze one run's exact aggregate XML without doing evidence work on page reads."""
    init_derived_result_storage(db_path)
    with connect_database(db_path, read_only=True) as db:
        db.execute("BEGIN")
        status = _require_scan_run(db, run_id)
        rows = _scan_xml_rows(db, run_id)
    if len(rows) > 1:
        raise ValueError("Scan run has ambiguous registered scan.xml observations")
    if not rows:
        if registration_expected:
            raise ValueError("The registered scan.xml observation is missing")
        content = _stable_file_bytes(run_local_path, "Historical run-local Nmap evidence")
        parsed = _parse_nmap_xml(content)
        with connect_database(db_path, read_only=True) as db:
            db.execute("BEGIN")
            _require_scan_run(db, run_id)
        return {
            "payload": parsed,
            "registered": False,
            "reused": False,
            "observation": None,
        }

    if status not in NMAP_ANALYSIS_TERMINAL_STATES:
        content = _stable_file_bytes(run_local_path, "In-progress run-local Nmap evidence")
        parsed = _parse_nmap_xml(content)
        with connect_database(db_path, read_only=True) as db:
            db.execute("BEGIN")
            _require_scan_run(db, run_id)
        return {
            "payload": parsed,
            "registered": True,
            "reused": False,
            "observation": None,
        }

    observation_id, digest, size_bytes = rows[0]
    _verify_run_local_artifact(run_local_path, digest, int(size_bytes))
    guard = _scan_authority_guard(run_id, observation_id)
    result = analyze_registered_nmap_base(
        db_path,
        observation_id,
        analysis_version=analysis_version,
        authority_guard=guard,
    )
    _verify_run_local_artifact(run_local_path, digest, int(size_bytes))
    return {**result, "registered": True}
