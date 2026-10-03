"""Immutable reusable computations with explicit version and input identity."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import sqlite3
from typing import Callable

from app.artifacts import init_artifact_storage, utc_now
from app.database import connect_database, initialize_once_per_database


class DerivedResultConflict(ValueError):
    """An exact computation identity was reused with different content."""


@dataclass(frozen=True)
class DerivedResultIdentity:
    family: str
    analysis_version: str
    payload_schema_version: int
    parameters_json: str
    inputs_json: str
    computation_key: str
    result_id: str


@dataclass(frozen=True)
class PreparedDerivedResult:
    identity: DerivedResultIdentity
    result_json: str
    result_sha256: str
    generated_at: str


def _text(value, field: str, maximum: int = 200) -> str:
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise ValueError(f"{field} must be nonblank trimmed text")
    if len(value) > maximum:
        raise ValueError(f"{field} exceeds {maximum} characters")
    return value


def _json(value) -> str:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise ValueError("Derived-result data must be finite JSON") from exc


def _normalized_inputs(inputs: list[dict]) -> list[dict]:
    if not isinstance(inputs, list) or not inputs:
        raise ValueError("At least one derived-result input is required")
    normalized = []
    roles = set()
    for item in inputs:
        if not isinstance(item, dict):
            raise ValueError("Derived-result inputs must be objects")
        role = _text(item.get("role"), "input role", 100)
        if role in roles:
            raise ValueError("Derived-result input roles must be unique")
        roles.add(role)
        metadata = item.get("metadata") or {}
        if not isinstance(metadata, dict):
            raise ValueError("Derived-result input metadata must be an object")
        normalized.append({
            "role": role,
            "kind": _text(item.get("kind"), "input kind", 100),
            "identity": _text(item.get("identity"), "input identity", 500),
            "metadata": json.loads(_json(metadata)),
        })
    return sorted(normalized, key=lambda item: item["role"])


def derived_result_identity(
    *, family: str, analysis_version: str, payload_schema_version: int,
    parameters: dict, inputs: list[dict],
) -> DerivedResultIdentity:
    family = _text(family, "family", 100)
    analysis_version = _text(analysis_version, "analysis_version", 100)
    if not isinstance(payload_schema_version, int) or payload_schema_version < 1:
        raise ValueError("payload_schema_version must be a positive integer")
    if not isinstance(parameters, dict):
        raise ValueError("parameters must be an object")
    parameters_json = _json(parameters)
    inputs_json = _json(_normalized_inputs(inputs))
    computation_key = hashlib.sha256(_json({
        "family": family,
        "analysis_version": analysis_version,
        "payload_schema_version": payload_schema_version,
        "parameters": json.loads(parameters_json),
        "inputs": json.loads(inputs_json),
    }).encode()).hexdigest()
    return DerivedResultIdentity(
        family=family,
        analysis_version=analysis_version,
        payload_schema_version=payload_schema_version,
        parameters_json=parameters_json,
        inputs_json=inputs_json,
        computation_key=computation_key,
        result_id=f"derived_{computation_key}",
    )


def prepare_derived_result(
    *, family: str, analysis_version: str, payload_schema_version: int,
    parameters: dict, inputs: list[dict], payload,
    generated_at: str | None = None,
) -> PreparedDerivedResult:
    identity = derived_result_identity(
        family=family,
        analysis_version=analysis_version,
        payload_schema_version=payload_schema_version,
        parameters=parameters,
        inputs=inputs,
    )
    result_json = _json(payload)
    return PreparedDerivedResult(
        identity=identity,
        result_json=result_json,
        result_sha256=hashlib.sha256(result_json.encode()).hexdigest(),
        generated_at=generated_at or utc_now(),
    )


def _validated_identity(identity: DerivedResultIdentity) -> DerivedResultIdentity:
    if not isinstance(identity, DerivedResultIdentity):
        raise DerivedResultConflict("Derived-result identity has an invalid type")
    try:
        parameters = json.loads(identity.parameters_json)
        inputs = json.loads(identity.inputs_json)
        canonical = derived_result_identity(
            family=identity.family,
            analysis_version=identity.analysis_version,
            payload_schema_version=identity.payload_schema_version,
            parameters=parameters,
            inputs=inputs,
        )
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        raise DerivedResultConflict("Derived-result identity is invalid") from exc
    if canonical != identity:
        raise DerivedResultConflict("Derived-result identity does not match its computation key")
    return canonical


def _validated_prepared(prepared: PreparedDerivedResult) -> PreparedDerivedResult:
    if not isinstance(prepared, PreparedDerivedResult):
        raise DerivedResultConflict("Prepared derived result has an invalid type")
    _validated_identity(prepared.identity)
    try:
        payload = json.loads(prepared.result_json)
        canonical_payload = _json(payload)
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        raise DerivedResultConflict("Prepared derived-result payload is unreadable") from exc
    if canonical_payload != prepared.result_json:
        raise DerivedResultConflict("Prepared derived-result payload is not canonical")
    if hashlib.sha256(prepared.result_json.encode()).hexdigest() != prepared.result_sha256:
        raise DerivedResultConflict("Prepared derived-result payload hash is inconsistent")
    _text(prepared.generated_at, "generated_at", 100)
    return prepared


@initialize_once_per_database
def init_derived_result_storage(db_path: Path) -> None:
    init_artifact_storage(db_path)
    with connect_database(db_path) as db:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS derived_results (
                result_id TEXT PRIMARY KEY,
                computation_key TEXT NOT NULL UNIQUE,
                family TEXT NOT NULL,
                analysis_version TEXT NOT NULL,
                payload_schema_version INTEGER NOT NULL
                    CHECK(payload_schema_version >= 1),
                parameters_json TEXT NOT NULL,
                inputs_json TEXT NOT NULL,
                result_json TEXT NOT NULL,
                result_sha256 TEXT NOT NULL,
                generated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS derived_result_inputs (
                result_id TEXT NOT NULL REFERENCES derived_results(result_id)
                    ON DELETE CASCADE,
                input_role TEXT NOT NULL,
                input_kind TEXT NOT NULL,
                input_identity TEXT NOT NULL,
                input_metadata_json TEXT NOT NULL,
                PRIMARY KEY(result_id, input_role)
            );
            CREATE TABLE IF NOT EXISTS derived_result_observation_links (
                result_id TEXT NOT NULL,
                input_role TEXT NOT NULL,
                observation_id TEXT NOT NULL REFERENCES artifact_observations(observation_id)
                    ON DELETE CASCADE,
                linked_at TEXT NOT NULL,
                PRIMARY KEY(result_id, input_role, observation_id),
                FOREIGN KEY(result_id, input_role)
                    REFERENCES derived_result_inputs(result_id, input_role)
                    ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS derived_results_family_generated
                ON derived_results(family, generated_at DESC);
            CREATE INDEX IF NOT EXISTS derived_result_observation_lookup
                ON derived_result_observation_links(observation_id, result_id);
            CREATE TRIGGER IF NOT EXISTS derived_results_no_update
                BEFORE UPDATE ON derived_results
                BEGIN SELECT RAISE(ABORT, 'derived results are immutable'); END;
            CREATE TRIGGER IF NOT EXISTS derived_result_inputs_no_update
                BEFORE UPDATE ON derived_result_inputs
                BEGIN SELECT RAISE(ABORT, 'derived result inputs are immutable'); END;
            CREATE TRIGGER IF NOT EXISTS derived_result_links_no_update
                BEFORE UPDATE ON derived_result_observation_links
                BEGIN SELECT RAISE(ABORT, 'derived result links are immutable'); END;
            """
        )


def _input_rows(identity: DerivedResultIdentity) -> list[tuple]:
    return [
        (
            identity.result_id,
            item["role"],
            item["kind"],
            item["identity"],
            _json(item["metadata"]),
        )
        for item in json.loads(identity.inputs_json)
    ]


def _validate_observation_links(
    db: sqlite3.Connection, *, result_id: str, inputs: dict[str, dict], links: list[dict],
) -> list[tuple]:
    normalized = []
    for link in links:
        if not isinstance(link, dict):
            raise ValueError("Derived-result observation links must be objects")
        role = _text(link.get("role"), "link role", 100)
        observation_id = _text(link.get("observation_id"), "observation_id", 200)
        declared = inputs.get(role)
        if declared is None or declared["kind"] != "artifact_sha256":
            raise ValueError("Observation links require a matching artifact_sha256 input role")
        row = db.execute(
            "SELECT sha256 FROM artifact_observations WHERE observation_id = ?",
            (observation_id,),
        ).fetchone()
        if row is None:
            raise KeyError("Artifact observation is no longer available")
        if row[0] != declared["identity"]:
            raise DerivedResultConflict("Artifact observation does not match the declared input")
        normalized.append((result_id, role, observation_id, utc_now()))
    return normalized


def publish_derived_result(
    db_path: Path, prepared: PreparedDerivedResult, *, observation_links: list[dict] | None = None,
    transaction_guard: Callable[[sqlite3.Connection], None] | None = None,
) -> dict:
    init_derived_result_storage(db_path)
    _validated_prepared(prepared)
    identity = prepared.identity
    row_values = (
        identity.result_id,
        identity.computation_key,
        identity.family,
        identity.analysis_version,
        identity.payload_schema_version,
        identity.parameters_json,
        identity.inputs_json,
        prepared.result_json,
        prepared.result_sha256,
        prepared.generated_at,
    )
    with connect_database(db_path) as db:
        db.execute("BEGIN IMMEDIATE")
        if transaction_guard is not None:
            transaction_guard(db)
        declared_inputs = {
            item["role"]: item for item in json.loads(identity.inputs_json)
        }
        links = _validate_observation_links(
            db,
            result_id=identity.result_id,
            inputs=declared_inputs,
            links=observation_links or [],
        )
        created = bool(db.execute(
            """INSERT OR IGNORE INTO derived_results (
                   result_id, computation_key, family, analysis_version,
                   payload_schema_version, parameters_json, inputs_json,
                   result_json, result_sha256, generated_at
               ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            row_values,
        ).rowcount)
        retained = db.execute(
            """SELECT result_id, computation_key, family, analysis_version,
                      payload_schema_version, parameters_json, inputs_json,
                      result_json, result_sha256
               FROM derived_results WHERE computation_key = ?""",
            (identity.computation_key,),
        ).fetchone()
        expected = row_values[:-1]
        if retained is None or tuple(retained) != expected:
            raise DerivedResultConflict(
                "Exact derived-result identity produced different retained content"
            )
        for input_row in _input_rows(identity):
            db.execute(
                """INSERT OR IGNORE INTO derived_result_inputs (
                       result_id, input_role, input_kind, input_identity,
                       input_metadata_json
                   ) VALUES (?, ?, ?, ?, ?)""",
                input_row,
            )
            retained_input = db.execute(
                """SELECT result_id, input_role, input_kind, input_identity,
                          input_metadata_json
                   FROM derived_result_inputs
                   WHERE result_id = ? AND input_role = ?""",
                input_row[:2],
            ).fetchone()
            if retained_input is None or tuple(retained_input) != input_row:
                raise DerivedResultConflict("Derived-result input manifest conflict")
        db.executemany(
            """INSERT OR IGNORE INTO derived_result_observation_links (
                   result_id, input_role, observation_id, linked_at
               ) VALUES (?, ?, ?, ?)""",
            links,
        )
    return {
        "result_id": identity.result_id,
        "computation_key": identity.computation_key,
        "created": created,
    }


def associate_derived_result_observation(
    db_path: Path, identity: DerivedResultIdentity, *, role: str, observation_id: str,
) -> None:
    init_derived_result_storage(db_path)
    _validated_identity(identity)
    with connect_database(db_path) as db:
        db.execute("BEGIN IMMEDIATE")
        retained = db.execute(
            """SELECT family, analysis_version, payload_schema_version,
                      parameters_json, inputs_json
               FROM derived_results WHERE result_id = ? AND computation_key = ?""",
            (identity.result_id, identity.computation_key),
        ).fetchone()
        if retained is None:
            raise KeyError("Derived result is not available")
        if tuple(retained) != (
            identity.family,
            identity.analysis_version,
            identity.payload_schema_version,
            identity.parameters_json,
            identity.inputs_json,
        ):
            raise DerivedResultConflict("Stored derived-result identity is inconsistent")
        stored_rows = db.execute(
            """SELECT input_role, input_kind, input_identity, input_metadata_json
               FROM derived_result_inputs WHERE result_id = ? ORDER BY input_role""",
            (identity.result_id,),
        ).fetchall()
        expected_rows = [item[1:] for item in _input_rows(identity)]
        if [tuple(row) for row in stored_rows] != expected_rows:
            raise DerivedResultConflict("Stored derived-result inputs are inconsistent")
        stored_inputs = {
            row[0]: {"role": row[0], "kind": row[1], "identity": row[2]}
            for row in stored_rows
        }
        links = _validate_observation_links(
            db,
            result_id=identity.result_id,
            inputs=stored_inputs,
            links=[{"role": role, "observation_id": observation_id}],
        )
        db.executemany(
            """INSERT OR IGNORE INTO derived_result_observation_links (
                   result_id, input_role, observation_id, linked_at
               ) VALUES (?, ?, ?, ?)""",
            links,
        )


def _load_derived_result(
    db: sqlite3.Connection, identity: DerivedResultIdentity,
) -> dict | None:
    row = db.execute(
        """SELECT result_id, family, analysis_version, payload_schema_version,
                  parameters_json, inputs_json, result_json, result_sha256,
                  generated_at
           FROM derived_results WHERE computation_key = ?""",
        (identity.computation_key,),
    ).fetchone()
    if row is None:
        return None
    inputs = db.execute(
        """SELECT input_role, input_kind, input_identity, input_metadata_json
           FROM derived_result_inputs WHERE result_id = ? ORDER BY input_role""",
        (identity.result_id,),
    ).fetchall()
    if tuple(row[:6]) != (
        identity.result_id,
        identity.family,
        identity.analysis_version,
        identity.payload_schema_version,
        identity.parameters_json,
        identity.inputs_json,
    ):
        raise DerivedResultConflict("Stored derived-result identity is inconsistent")
    expected_inputs = [item[1:] for item in _input_rows(identity)]
    if [tuple(item) for item in inputs] != expected_inputs:
        raise DerivedResultConflict("Stored derived-result inputs are inconsistent")
    result_json, result_sha256 = row[6], row[7]
    if hashlib.sha256(result_json.encode()).hexdigest() != result_sha256:
        raise DerivedResultConflict("Stored derived-result payload failed integrity verification")
    try:
        payload = json.loads(result_json)
    except json.JSONDecodeError as exc:
        raise DerivedResultConflict("Stored derived-result payload is unreadable") from exc
    if _json(payload) != result_json:
        raise DerivedResultConflict("Stored derived-result payload is not canonical")
    return {
        "result_id": row[0],
        "family": row[1],
        "analysis_version": row[2],
        "payload_schema_version": int(row[3]),
        "generated_at": row[8],
        "payload": payload,
    }


def load_derived_result(db_path: Path, identity: DerivedResultIdentity) -> dict | None:
    _validated_identity(identity)
    with connect_database(db_path, read_only=True) as db:
        db.execute("BEGIN")
        return _load_derived_result(db, identity)


def load_linked_derived_result(
    db_path: Path,
    identity: DerivedResultIdentity,
    *,
    role: str,
    observation_id: str,
    read_guard: Callable[[sqlite3.Connection], None] | None = None,
) -> dict | None:
    """Read one result and its provenance link from the same read-only snapshot."""
    _validated_identity(identity)
    role = _text(role, "link role", 100)
    observation_id = _text(observation_id, "observation_id", 200)
    with connect_database(db_path, read_only=True) as db:
        db.execute("BEGIN")
        if read_guard is not None:
            read_guard(db)
        retained = _load_derived_result(db, identity)
        if retained is None:
            return None
        linked = db.execute(
            """SELECT 1 FROM derived_result_observation_links
               WHERE result_id = ? AND input_role = ? AND observation_id = ?""",
            (identity.result_id, role, observation_id),
        ).fetchone()
        return retained if linked is not None else None
