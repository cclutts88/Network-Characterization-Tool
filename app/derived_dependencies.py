"""Read-only direct-input and provenance views for supported derived results."""
from __future__ import annotations

import json
from pathlib import Path
import sqlite3

from app.database import connect_database
from app.derived_contracts import SUPPORTED_DERIVED_RESULT_CONTRACTS
from app.derived_result_status import classify_calculation_contract
from app.derived_results import derived_result_identity


MAX_INPUTS_PER_RESULT = 25
MAX_MANIFEST_JSON_CHARS = 262_144


class DerivedDependencyIntegrityError(ValueError):
    """Saved dependency records conflict or cannot be verified."""


class UnsupportedDerivedDependency(ValueError):
    """This build has no reviewed input contract for the saved result."""


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _strict_json(raw: object, expected_type: type, field: str):
    if not isinstance(raw, str) or len(raw) > MAX_MANIFEST_JSON_CHARS:
        raise DerivedDependencyIntegrityError(f"Saved {field} is unreadable or too large.")
    try:
        value = json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
        canonical = _canonical_json(value)
    except (json.JSONDecodeError, RecursionError, TypeError, ValueError) as exc:
        raise DerivedDependencyIntegrityError(f"Saved {field} is unreadable.") from exc
    if not isinstance(value, expected_type) or canonical != raw:
        raise DerivedDependencyIntegrityError(f"Saved {field} is inconsistent.")
    return value


def _tables_available(db: sqlite3.Connection) -> bool:
    required = {
        "derived_results", "derived_result_inputs",
        "derived_result_observation_links", "artifact_observations", "artifact_registry",
    }
    rows = db.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table'"
    ).fetchall()
    return required.issubset({row[0] for row in rows})


def _load_verified_manifest(db: sqlite3.Connection, result_id: str) -> dict:
    if not _tables_available(db):
        raise KeyError("Saved calculation is not available.")
    row = db.execute(
        """SELECT result_id, computation_key, family, analysis_version,
                  payload_schema_version, parameters_json, inputs_json
           FROM derived_results WHERE result_id = ?""",
        (result_id,),
    ).fetchone()
    if row is None:
        raise KeyError("Saved calculation is not available.")
    contract = SUPPORTED_DERIVED_RESULT_CONTRACTS.get(row[2])
    if contract is None:
        raise UnsupportedDerivedDependency(
            "This build has no reviewed input contract for that calculation type."
        )
    compatibility = classify_calculation_contract(
        family=row[2],
        analysis_version=row[3],
        payload_schema_version=row[4],
        parameters_json=row[5],
    )
    if compatibility["state"] != "CURRENT":
        raise UnsupportedDerivedDependency(
            "This build has not reviewed the saved calculation version, output format, "
            "and settings as an input contract."
        )
    parameters = _strict_json(row[5], dict, "calculation settings")
    inputs = _strict_json(row[6], list, "input manifest")
    if len(inputs) > MAX_INPUTS_PER_RESULT:
        raise DerivedDependencyIntegrityError("Saved input manifest has too many roles.")
    try:
        identity = derived_result_identity(
            family=row[2],
            analysis_version=row[3],
            payload_schema_version=row[4],
            parameters=parameters,
            inputs=inputs,
        )
    except (RecursionError, TypeError, ValueError) as exc:
        raise DerivedDependencyIntegrityError(
            "Saved calculation identity is unreadable."
        ) from exc
    if (
        identity.result_id != row[0]
        or identity.computation_key != row[1]
        or identity.parameters_json != row[5]
        or identity.inputs_json != row[6]
    ):
        raise DerivedDependencyIntegrityError(
            "Saved calculation identity does not match its input manifest."
        )
    declared = {item["role"]: item for item in inputs}
    if set(declared) != set(contract.input_kinds):
        raise UnsupportedDerivedDependency(
            "The saved calculation uses an unsupported set of input roles."
        )
    for role, item in declared.items():
        if item["kind"] not in contract.input_kinds[role]:
            raise UnsupportedDerivedDependency(
                f"The saved {role} input type is not supported by this build."
            )

    count = int(db.execute(
        "SELECT COUNT(*) FROM derived_result_inputs WHERE result_id = ?",
        (result_id,),
    ).fetchone()[0])
    if count > MAX_INPUTS_PER_RESULT:
        raise DerivedDependencyIntegrityError("Saved input rows exceed the supported limit.")
    rows = db.execute(
        """SELECT input_role, input_kind, input_identity, input_metadata_json
           FROM derived_result_inputs WHERE result_id = ? ORDER BY input_role""",
        (result_id,),
    ).fetchall()
    retained = []
    for input_row in rows:
        metadata = _strict_json(input_row[3], dict, "input metadata")
        retained.append({
            "role": input_row[0], "kind": input_row[1],
            "identity": input_row[2], "metadata": metadata,
        })
    if retained != sorted(inputs, key=lambda item: item["role"]):
        raise DerivedDependencyIntegrityError(
            "Saved input rows do not match the immutable input manifest."
        )
    observation_counts = {
        item["role"]: _verified_observation_count(db, result_id, item)
        for item in retained
    }
    return {
        "result_id": row[0], "family": row[2], "label": contract.label,
        "analysis_version": row[3], "inputs": retained,
        "observation_counts": observation_counts,
    }


def _input_explanation(item: dict) -> tuple[str, str]:
    kind = item["kind"]
    metadata = item["metadata"]
    if kind == "artifact_sha256":
        detail = "Registered evidence bytes."
        if item["role"] == "command_history":
            detail = "Dedicated command-history file; its source record shows whether it was empty."
        return "Registered evidence file", detail
    if kind == "embedded_config_section":
        if metadata.get("present") is False:
            return "Embedded history descriptor", "No embedded history section was present."
        return "Embedded history descriptor", "Command history was embedded in configuration evidence."
    if kind == "absence_descriptor":
        return "Missing history descriptor", "No dedicated or embedded command history was recorded."
    if kind == "canonical_json_sha256":
        return (
            "Saved calculation descriptor",
            f"Recorded descriptor with {len(metadata)} fields; full values are not shown here.",
        )
    raise UnsupportedDerivedDependency("The saved input type is not supported by this build.")


def _verified_observation_count(
    db: sqlite3.Connection, result_id: str, item: dict,
) -> int:
    total = int(db.execute(
        """SELECT COUNT(*) FROM derived_result_observation_links
           WHERE result_id = ? AND input_role = ?""",
        (result_id, item["role"]),
    ).fetchone()[0])
    if item["kind"] != "artifact_sha256":
        if total:
            raise DerivedDependencyIntegrityError(
                "A descriptor input has conflicting source-record links."
            )
        return 0
    invalid = int(db.execute(
        """SELECT COUNT(*)
           FROM derived_result_observation_links link
           LEFT JOIN artifact_observations observation
             ON observation.observation_id = link.observation_id
           LEFT JOIN artifact_registry artifact
             ON artifact.sha256 = observation.sha256
           WHERE link.result_id = ? AND link.input_role = ?
             AND (observation.observation_id IS NULL
                  OR observation.sha256 <> ?
                  OR artifact.sha256 IS NULL)""",
        (result_id, item["role"], item["identity"]),
    ).fetchone()[0])
    if invalid:
        raise DerivedDependencyIntegrityError(
            "Saved source records conflict with the declared input identity."
        )
    return total


def _validated_limit_offset(limit: int, offset: int) -> None:
    if not isinstance(limit, int) or not 1 <= limit <= 100:
        raise ValueError("limit must be between 1 and 100")
    if not isinstance(offset, int) or offset < 0:
        raise ValueError("offset must be zero or greater")


def list_result_inputs(
    db_path: Path, result_id: str, *, limit: int = 25, offset: int = 0,
) -> dict:
    """Return one verified, bounded page of direct calculation inputs."""
    _validated_limit_offset(limit, offset)
    if not db_path.is_file():
        raise KeyError("Saved calculation is not available.")
    with connect_database(db_path, read_only=True) as db:
        db.execute("BEGIN")
        manifest = _load_verified_manifest(db, result_id)
        inputs = manifest.pop("inputs")
        observation_counts = manifest.pop("observation_counts")
        page = inputs[offset:offset + limit]
        items = []
        for item in page:
            label, explanation = _input_explanation(item)
            items.append({
                "role": item["role"], "kind": item["kind"],
                "type_label": label, "explanation": explanation,
                "identity": item["identity"],
                "metadata_field_count": len(item["metadata"]),
                "source_record_count": observation_counts[item["role"]],
                "source_records_supported": item["kind"] == "artifact_sha256",
            })
    total = len(inputs)
    return {
        **manifest, "items": items, "total": total, "limit": limit,
        "offset": offset, "has_more": offset + len(items) < total,
    }


def list_input_observations(
    db_path: Path, result_id: str, role: str, *, limit: int = 25, offset: int = 0,
) -> dict:
    """Return separately paged provenance links for one verified artifact input role."""
    _validated_limit_offset(limit, offset)
    if not db_path.is_file():
        raise KeyError("Saved calculation is not available.")
    with connect_database(db_path, read_only=True) as db:
        db.execute("BEGIN")
        manifest = _load_verified_manifest(db, result_id)
        inputs = {item["role"]: item for item in manifest.pop("inputs")}
        observation_counts = manifest.pop("observation_counts")
        selected = inputs.get(role)
        if selected is None:
            raise KeyError("Saved calculation input is not available.")
        total = observation_counts[role]
        if selected["kind"] != "artifact_sha256":
            raise UnsupportedDerivedDependency(
                "This descriptor input does not have Artifact Registry source records."
            )
        rows = db.execute(
            """SELECT observation.observation_id, observation.source_kind,
                      observation.source_ref, observation.observed_at,
                      observation.original_filename, observation.actor,
                      artifact.size_bytes
               FROM derived_result_observation_links link
               JOIN artifact_observations observation
                 ON observation.observation_id = link.observation_id
               JOIN artifact_registry artifact ON artifact.sha256 = observation.sha256
               WHERE link.result_id = ? AND link.input_role = ?
               ORDER BY observation.observed_at DESC, observation.observation_id
               LIMIT ? OFFSET ?""",
            (result_id, role, limit, offset),
        ).fetchall()
        items = [{
            "observation_id": row[0], "source_kind": row[1], "source_ref": row[2],
            "observed_at": row[3], "original_filename": row[4], "actor": row[5],
            "size_bytes": int(row[6]),
        } for row in rows]
    return {
        **manifest, "role": role, "input_identity": selected["identity"],
        "items": items, "total": total, "limit": limit, "offset": offset,
        "has_more": offset + len(items) < total,
    }
