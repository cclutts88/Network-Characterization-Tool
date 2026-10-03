"""Internal content-addressed adapter for one Nmap XML base analysis."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from app.database import connect_database
from app.derived_results import (
    associate_derived_result_observation,
    derived_result_identity,
    init_derived_result_storage,
    load_derived_result,
    prepare_derived_result,
    publish_derived_result,
)


NMAP_BASE_ANALYSIS_FAMILY = "nmap_base_analysis"
NMAP_BASE_ANALYSIS_VERSION = "nmap-base-analysis:1"
NMAP_BASE_PAYLOAD_SCHEMA_VERSION = 1
NMAP_BASE_PARAMETERS = {
    "parser": "nct.parse_xml",
    "coverage_presence_os_inference_contract": 1,
}


def _parse_nmap_xml(content: bytes):
    from app.main import parse_xml
    return parse_xml(content)


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
    path = Path(row[6])
    if not path.is_file() or path.is_symlink():
        raise ValueError("Canonical Nmap evidence is unavailable")
    before = path.stat()
    content = path.read_bytes()
    after = path.stat()
    if (before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
        after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns,
    ):
        raise ValueError("Canonical Nmap evidence changed during verification")
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
    analysis_version: str = NMAP_BASE_ANALYSIS_VERSION,
    parameters: dict | None = None,
) -> dict:
    """Reuse or publish base parsing for verified bytes without run/scope provenance."""
    init_derived_result_storage(db_path)
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
    retained = load_derived_result(db_path, identity)
    if retained is not None:
        associate_derived_result_observation(
            db_path, identity, role="nmap_xml", observation_id=observation_id,
        )
        return {**retained, "reused": True, "observation": observation}
    parsed = _parse_nmap_xml(content)
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
    )
    if not publication["created"]:
        retained = load_derived_result(db_path, identity)
        if retained is None:
            raise RuntimeError("Published derived result could not be reloaded")
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
