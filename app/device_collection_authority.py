"""Durable lifecycle authority for retained device collections."""
from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path

from app.artifacts import init_artifact_storage, utc_now
from app.database import connect_database, initialize_once_per_database


AUTHORITY_MARKER = "summary_authority"
AUTHORITY_SCHEMA_VERSION = 1
MANUAL_UPLOAD_SELECTION_CONTRACT = "manual-upload-single-file:1"
COLLECTED_DEVICE_SELECTION_CONTRACT = "collected-device-multi-file:1"


class DeviceCollectionAuthorityError(ValueError):
    """Base class for collection lifecycle conflicts."""


class DeviceCollectionIncomplete(DeviceCollectionAuthorityError):
    """The collection has not completed authority activation."""


class DeviceCollectionDeleted(FileNotFoundError):
    """The collection was deliberately deleted and must not be recreated."""


class DeviceCollectionIntegrityError(DeviceCollectionAuthorityError):
    """Retained evidence no longer matches its durable authority."""


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _digest_text(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def manual_upload_manifest_semantics(manifest: dict, *, history_exists: bool) -> dict:
    commands = manifest.get("commands") or []
    if not isinstance(commands, list):
        raise DeviceCollectionIntegrityError("Device upload commands must be a list")
    return {
        "vendor": str(manifest.get("vendor") or "").lower(),
        "commands": [str(value) for value in commands],
        "history_command": str(manifest.get("history_command") or "show history"),
        "history_attempted": bool(
            history_exists
            or manifest.get("command_history_status")
            or manifest.get("history_command")
        ),
        "output_complete_is_false": manifest.get("output_complete") is False,
    }


def authority_manifest_marker(
    selection_contract: str = MANUAL_UPLOAD_SELECTION_CONTRACT,
) -> dict:
    return {
        "required": True,
        "schema_version": AUTHORITY_SCHEMA_VERSION,
        "revision": 1,
        "selection_contract": selection_contract,
    }


def manifest_requires_authority(manifest: dict | None) -> bool:
    marker = (manifest or {}).get(AUTHORITY_MARKER)
    return isinstance(marker, dict) and marker.get("required") is True


@initialize_once_per_database
def init_device_collection_authority_storage(db_path: Path) -> None:
    init_artifact_storage(db_path)
    with connect_database(db_path) as db:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS device_collection_authority (
                run_id TEXT PRIMARY KEY,
                state TEXT NOT NULL CHECK(state IN ('preparing', 'active', 'deleted')),
                revision INTEGER NOT NULL CHECK(revision >= 1),
                artifact_observation_id TEXT
                    REFERENCES artifact_observations(observation_id) ON DELETE RESTRICT,
                artifact_sha256 TEXT,
                retained_filename TEXT,
                selection_contract TEXT,
                semantic_manifest_json TEXT,
                semantic_manifest_sha256 TEXT,
                created_at TEXT NOT NULL,
                activated_at TEXT,
                deleted_at TEXT,
                CHECK(
                    state != 'active' OR (
                        artifact_observation_id IS NOT NULL
                        AND artifact_sha256 IS NOT NULL
                        AND retained_filename IS NOT NULL
                        AND selection_contract IS NOT NULL
                        AND semantic_manifest_json IS NOT NULL
                        AND semantic_manifest_sha256 IS NOT NULL
                        AND activated_at IS NOT NULL
                    )
                ),
                CHECK(state != 'deleted' OR deleted_at IS NOT NULL)
            );
            CREATE INDEX IF NOT EXISTS device_collection_authority_state
                ON device_collection_authority(state, created_at DESC);
            CREATE TABLE IF NOT EXISTS device_collection_authority_inputs (
                run_id TEXT NOT NULL REFERENCES device_collection_authority(run_id),
                input_role TEXT NOT NULL,
                position INTEGER NOT NULL CHECK(position >= 0),
                source_kind TEXT NOT NULL CHECK(
                    source_kind IN ('artifact_file', 'embedded_section', 'absent')
                ),
                identity TEXT NOT NULL,
                filename TEXT,
                artifact_observation_id TEXT
                    REFERENCES artifact_observations(observation_id) ON DELETE RESTRICT,
                artifact_sha256 TEXT,
                size_bytes INTEGER CHECK(size_bytes IS NULL OR size_bytes >= 0),
                metadata_json TEXT NOT NULL,
                PRIMARY KEY(run_id, input_role, position),
                CHECK(
                    source_kind != 'artifact_file' OR (
                        filename IS NOT NULL
                        AND artifact_observation_id IS NOT NULL
                        AND artifact_sha256 IS NOT NULL
                        AND size_bytes IS NOT NULL
                    )
                )
            );
            CREATE INDEX IF NOT EXISTS device_collection_authority_input_observation
                ON device_collection_authority_inputs(artifact_observation_id, run_id);
            DROP TRIGGER IF EXISTS device_collection_authority_identity_immutable;
            DROP TRIGGER IF EXISTS device_collection_authority_legal_transition;
            DROP TRIGGER IF EXISTS device_collection_authority_inputs_no_update;
            DROP TRIGGER IF EXISTS device_collection_authority_inputs_no_delete;
            CREATE TRIGGER IF NOT EXISTS device_collection_authority_no_delete
                BEFORE DELETE ON device_collection_authority
                BEGIN SELECT RAISE(ABORT, 'device collection authority is permanent'); END;
            CREATE TRIGGER IF NOT EXISTS device_collection_authority_no_reactivate
                BEFORE UPDATE ON device_collection_authority
                WHEN OLD.state = 'deleted'
                BEGIN SELECT RAISE(ABORT, 'deleted device collection cannot be reactivated'); END;
            CREATE TRIGGER IF NOT EXISTS device_collection_authority_identity_immutable
                BEFORE UPDATE ON device_collection_authority
                WHEN OLD.state = 'active' AND (
                    NEW.artifact_observation_id IS NOT OLD.artifact_observation_id
                    OR NEW.artifact_sha256 IS NOT OLD.artifact_sha256
                    OR NEW.retained_filename IS NOT OLD.retained_filename
                    OR NEW.selection_contract IS NOT OLD.selection_contract
                    OR NEW.semantic_manifest_json IS NOT OLD.semantic_manifest_json
                    OR NEW.semantic_manifest_sha256 IS NOT OLD.semantic_manifest_sha256
                )
                BEGIN SELECT RAISE(ABORT, 'active device collection authority is immutable'); END;
            CREATE TRIGGER device_collection_authority_legal_transition
                BEFORE UPDATE ON device_collection_authority
                WHEN NOT (
                    (OLD.state = 'preparing' AND NEW.state IN ('active', 'deleted'))
                    OR (OLD.state = 'active' AND NEW.state = 'deleted')
                )
                BEGIN SELECT RAISE(ABORT, 'illegal device collection authority transition'); END;
            CREATE TRIGGER device_collection_authority_inputs_no_update
                BEFORE UPDATE ON device_collection_authority_inputs
                BEGIN SELECT RAISE(ABORT, 'device collection authority inputs are immutable'); END;
            CREATE TRIGGER device_collection_authority_inputs_no_delete
                BEFORE DELETE ON device_collection_authority_inputs
                BEGIN SELECT RAISE(ABORT, 'device collection authority inputs are permanent'); END;
            """
        )


def begin_manual_upload_authority(db_path: Path, run_id: str) -> dict:
    init_device_collection_authority_storage(db_path)
    created_at = utc_now()
    try:
        with connect_database(db_path) as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute(
                """INSERT INTO device_collection_authority (
                       run_id, state, revision, created_at
                   ) VALUES (?, 'preparing', 1, ?)""",
                (run_id, created_at),
            )
    except sqlite3.IntegrityError as exc:
        raise DeviceCollectionIntegrityError(
            "Device collection identity is already in use"
        ) from exc
    return {"run_id": run_id, "state": "preparing", "revision": 1}


def begin_collected_device_authority(db_path: Path, run_id: str) -> dict:
    """Create or resume the preparation record for one successful collection."""
    init_device_collection_authority_storage(db_path)
    created_at = utc_now()
    with connect_database(db_path) as db:
        db.execute("BEGIN IMMEDIATE")
        authority = _authority_record(_authority_row(db, run_id))
        if authority is None:
            db.execute(
                """INSERT INTO device_collection_authority (
                       run_id, state, revision, created_at
                   ) VALUES (?, 'preparing', 1, ?)""",
                (run_id, created_at),
            )
        elif authority["state"] == "deleted":
            raise DeviceCollectionDeleted("Device collection was deleted")
        elif authority["state"] == "active":
            if authority["selection_contract"] != COLLECTED_DEVICE_SELECTION_CONTRACT:
                raise DeviceCollectionIntegrityError(
                    "Device collection authority uses a different selection contract"
                )
            return authority
        elif authority["revision"] != 1:
            raise DeviceCollectionIntegrityError(
                "Preparing device collection authority has an unsupported revision"
            )
    return get_device_collection_authority(db_path, run_id) or {}


def _authority_row(db: sqlite3.Connection, run_id: str):
    return db.execute(
        """SELECT run_id, state, revision, artifact_observation_id,
                  artifact_sha256, retained_filename, selection_contract,
                  semantic_manifest_json, semantic_manifest_sha256,
                  created_at, activated_at, deleted_at
           FROM device_collection_authority WHERE run_id = ?""",
        (run_id,),
    ).fetchone()


def _authority_record(row) -> dict | None:
    if row is None:
        return None
    keys = (
        "run_id", "state", "revision", "artifact_observation_id",
        "artifact_sha256", "retained_filename", "selection_contract",
        "semantic_manifest_json", "semantic_manifest_sha256", "created_at",
        "activated_at", "deleted_at",
    )
    return dict(zip(keys, row))


def get_device_collection_authority(db_path: Path, run_id: str) -> dict | None:
    """Read lifecycle state without performing request-path schema writes."""
    if not Path(db_path).is_file():
        return None
    try:
        with connect_database(db_path, read_only=True) as db:
            return _authority_record(_authority_row(db, run_id))
    except sqlite3.OperationalError as exc:
        if "no such table" in str(exc).lower():
            return None
        raise


def _normalized_authority_inputs(inputs: list[dict]) -> list[dict]:
    if not isinstance(inputs, list) or not inputs:
        raise DeviceCollectionIntegrityError("Device collection authority inputs are missing")
    normalized = []
    keys = set()
    for item in inputs:
        if not isinstance(item, dict):
            raise DeviceCollectionIntegrityError("Device collection authority inputs are invalid")
        role = str(item.get("role") or "").strip()
        position = item.get("position", 0)
        source_kind = str(item.get("source_kind") or "").strip()
        identity = str(item.get("identity") or "").strip()
        metadata = item.get("metadata") or {}
        if (
            not role or not isinstance(position, int) or position < 0
            or source_kind not in {"artifact_file", "embedded_section", "absent"}
            or not identity or not isinstance(metadata, dict)
            or (role, position) in keys
        ):
            raise DeviceCollectionIntegrityError("Device collection authority inputs are invalid")
        keys.add((role, position))
        record = {
            "role": role,
            "position": position,
            "source_kind": source_kind,
            "identity": identity,
            "filename": item.get("filename"),
            "observation_id": item.get("observation_id"),
            "sha256": item.get("sha256"),
            "size_bytes": item.get("size_bytes"),
            "metadata": json.loads(_canonical_json(metadata)),
        }
        if source_kind == "artifact_file" and (
            not isinstance(record["filename"], str) or not record["filename"]
            or not isinstance(record["observation_id"], str) or not record["observation_id"]
            or not isinstance(record["sha256"], str) or not record["sha256"]
            or not isinstance(record["size_bytes"], int) or record["size_bytes"] < 0
            or record["identity"] != record["sha256"]
        ):
            raise DeviceCollectionIntegrityError("File-backed collection authority input is invalid")
        if source_kind != "artifact_file" and any(
            record[key] is not None
            for key in ("filename", "observation_id", "sha256", "size_bytes")
        ):
            raise DeviceCollectionIntegrityError("Descriptor authority input cannot name a file")
        normalized.append(record)
    return sorted(normalized, key=lambda item: (item["role"], item["position"]))


def _authority_input_rows(db: sqlite3.Connection, run_id: str) -> list[dict]:
    rows = db.execute(
        """SELECT input_role, position, source_kind, identity, filename,
                  artifact_observation_id, artifact_sha256, size_bytes, metadata_json
           FROM device_collection_authority_inputs
           WHERE run_id = ? ORDER BY input_role, position""",
        (run_id,),
    ).fetchall()
    return [
        {
            "role": row[0], "position": int(row[1]), "source_kind": row[2],
            "identity": row[3], "filename": row[4], "observation_id": row[5],
            "sha256": row[6], "size_bytes": row[7],
            "metadata": json.loads(row[8]),
        }
        for row in rows
    ]


def _insert_authority_inputs(
    db: sqlite3.Connection, run_id: str, inputs: list[dict], source_kind: str,
) -> None:
    for item in _normalized_authority_inputs(inputs):
        if item["source_kind"] == "artifact_file":
            observation = db.execute(
                """SELECT observation.sha256, observation.source_kind,
                          observation.source_ref, artifact.size_bytes
                   FROM artifact_observations observation
                   JOIN artifact_registry artifact ON artifact.sha256 = observation.sha256
                   WHERE observation.observation_id = ?""",
                (item["observation_id"],),
            ).fetchone()
            if observation is None or tuple(observation) != (
                item["sha256"], source_kind, run_id, item["size_bytes"],
            ):
                raise DeviceCollectionIntegrityError(
                    "Device collection input observation does not match its authority"
                )
        db.execute(
            """INSERT INTO device_collection_authority_inputs (
                   run_id, input_role, position, source_kind, identity, filename,
                   artifact_observation_id, artifact_sha256, size_bytes, metadata_json
               ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                run_id, item["role"], item["position"], item["source_kind"],
                item["identity"], item["filename"], item["observation_id"],
                item["sha256"], item["size_bytes"], _canonical_json(item["metadata"]),
            ),
        )


def activate_manual_upload_authority(
    db_path: Path,
    run_id: str,
    *,
    observation_id: str,
    artifact_sha256: str,
    retained_filename: str,
    manifest: dict,
) -> dict:
    init_device_collection_authority_storage(db_path)
    marker = manifest.get(AUTHORITY_MARKER)
    if marker != authority_manifest_marker():
        raise DeviceCollectionIntegrityError("Device upload authority marker is invalid")
    if manifest.get("run_id") != run_id:
        raise DeviceCollectionIntegrityError("Device upload manifest does not match its collection")
    if manifest.get("operation") != "manual_upload" or manifest.get("status") != "uploaded":
        raise DeviceCollectionIntegrityError("Only finalized manual uploads can be activated")
    if manifest.get("artifact_observation_id") != observation_id:
        raise DeviceCollectionIntegrityError("Device upload observation changed before activation")
    if manifest.get("artifact_sha256") != artifact_sha256:
        raise DeviceCollectionIntegrityError("Device upload digest changed before activation")
    if manifest.get("retained_filename") != retained_filename:
        raise DeviceCollectionIntegrityError("Device upload filename changed before activation")
    semantics_json = _canonical_json(
        manual_upload_manifest_semantics(manifest, history_exists=False)
    )
    semantics_sha256 = _digest_text(semantics_json)
    activated_at = utc_now()
    with connect_database(db_path) as db:
        db.execute("BEGIN IMMEDIATE")
        authority = _authority_record(_authority_row(db, run_id))
        if authority is None:
            raise DeviceCollectionIntegrityError("Device upload authority is missing")
        if authority["state"] == "deleted":
            raise DeviceCollectionDeleted("Device collection was deleted")
        if authority["state"] != "preparing" or authority["revision"] != 1:
            raise DeviceCollectionIntegrityError("Device upload authority is not preparing")
        observation = db.execute(
            """SELECT observation.sha256, observation.source_kind,
                      observation.source_ref, artifact.size_bytes
               FROM artifact_observations observation
               JOIN artifact_registry artifact ON artifact.sha256 = observation.sha256
               WHERE observation.observation_id = ?""",
            (observation_id,),
        ).fetchone()
        if observation is None or tuple(observation[:3]) != (
            artifact_sha256, "device_config_upload", run_id,
        ):
            raise DeviceCollectionIntegrityError(
                "Device upload observation does not match the retained evidence"
            )
        db.execute(
            """UPDATE device_collection_authority
               SET state = 'active', artifact_observation_id = ?,
                   artifact_sha256 = ?, retained_filename = ?,
                   selection_contract = ?, semantic_manifest_json = ?,
                   semantic_manifest_sha256 = ?, activated_at = ?
               WHERE run_id = ? AND state = 'preparing' AND revision = 1""",
            (
                observation_id, artifact_sha256, retained_filename,
                MANUAL_UPLOAD_SELECTION_CONTRACT, semantics_json,
                semantics_sha256, activated_at, run_id,
            ),
        )
    return get_device_collection_authority(db_path, run_id) or {}


def collected_device_manifest_semantics(manifest: dict) -> dict:
    commands = manifest.get("commands") or []
    if not isinstance(commands, list):
        raise DeviceCollectionIntegrityError("Device collection commands must be a list")
    return {
        "vendor": str(manifest.get("vendor") or "").lower(),
        "commands": [str(value) for value in commands],
        "history_command": str(manifest.get("history_command") or "show history"),
        "history_attempted": bool(
            manifest.get("command_history_artifact")
            or manifest.get("command_history_status")
            or manifest.get("history_command")
        ),
        "command_history_status": str(manifest.get("command_history_status") or ""),
        "operation": str(manifest.get("operation") or ""),
        "output_complete": manifest.get("output_complete") is True,
        "output_truncated": bool(manifest.get("output_truncated")),
        "command_history_truncated": bool(manifest.get("command_history_truncated")),
    }


def activate_collected_device_authority(
    db_path: Path,
    run_id: str,
    *,
    manifest: dict,
    inputs: list[dict],
) -> dict:
    """Activate exact multi-file authority for one completed SSH collection."""
    init_device_collection_authority_storage(db_path)
    marker = authority_manifest_marker(COLLECTED_DEVICE_SELECTION_CONTRACT)
    if manifest.get(AUTHORITY_MARKER) != marker:
        raise DeviceCollectionIntegrityError("Device collection authority marker is invalid")
    if manifest.get("run_id") != run_id:
        raise DeviceCollectionIntegrityError("Device collection manifest does not match its collection")
    semantics = collected_device_manifest_semantics(manifest)
    if (
        manifest.get("status") != "completed"
        or manifest.get("operation") not in {
            "configuration_pull", "interactive_configuration_pull",
        }
        or not semantics["output_complete"]
        or semantics["output_truncated"]
        or semantics["command_history_truncated"]
    ):
        raise DeviceCollectionIntegrityError(
            "Only complete, untruncated SSH collections can be activated"
        )
    normalized_inputs = _normalized_authority_inputs(inputs)
    required_roles = {"configuration", "raw_output", "command_history"}
    if {item["role"] for item in normalized_inputs} != required_roles:
        raise DeviceCollectionIntegrityError("Device collection authority roles are incomplete")
    configuration = next(
        item for item in normalized_inputs if item["role"] == "configuration"
    )
    if configuration["source_kind"] != "artifact_file":
        raise DeviceCollectionIntegrityError("Device configuration evidence is missing")
    semantics_json = _canonical_json(semantics)
    semantics_sha256 = _digest_text(semantics_json)
    activated_at = utc_now()
    with connect_database(db_path) as db:
        db.execute("BEGIN IMMEDIATE")
        authority = _authority_record(_authority_row(db, run_id))
        if authority is None:
            raise DeviceCollectionIntegrityError("Device collection authority is missing")
        if authority["state"] == "deleted":
            raise DeviceCollectionDeleted("Device collection was deleted")
        if authority["state"] == "active":
            if (
                authority["selection_contract"] == COLLECTED_DEVICE_SELECTION_CONTRACT
                and _authority_input_rows(db, run_id) == normalized_inputs
                and authority["semantic_manifest_sha256"] == semantics_sha256
            ):
                return authority
            raise DeviceCollectionIntegrityError("Active device collection authority does not match")
        if authority["state"] != "preparing" or authority["revision"] != 1:
            raise DeviceCollectionIntegrityError("Device collection authority is not preparing")
        if _authority_input_rows(db, run_id):
            raise DeviceCollectionIntegrityError("Preparing device collection already has frozen inputs")
        _insert_authority_inputs(db, run_id, normalized_inputs, "device_collection")
        updated = db.execute(
            """UPDATE device_collection_authority
               SET state = 'active', artifact_observation_id = ?,
                   artifact_sha256 = ?, retained_filename = ?,
                   selection_contract = ?, semantic_manifest_json = ?,
                   semantic_manifest_sha256 = ?, activated_at = ?
               WHERE run_id = ? AND state = 'preparing' AND revision = 1""",
            (
                configuration["observation_id"], configuration["sha256"],
                configuration["filename"], COLLECTED_DEVICE_SELECTION_CONTRACT,
                semantics_json, semantics_sha256, activated_at, run_id,
            ),
        )
        if updated.rowcount != 1:
            raise DeviceCollectionIntegrityError("Device collection activation lost its authority")
    return get_device_collection_authority(db_path, run_id) or {}


def require_available_collection(
    db_path: Path, run_id: str, *, manifest: dict | None = None,
) -> dict | None:
    authority = get_device_collection_authority(db_path, run_id)
    if authority is None:
        if manifest_requires_authority(manifest):
            raise DeviceCollectionIntegrityError(
                "This device upload expects verified authority, but its lifecycle record is missing"
            )
        return None
    if authority["state"] == "deleted":
        raise DeviceCollectionDeleted("Device collection was deleted")
    if authority["state"] == "preparing":
        raise DeviceCollectionIncomplete("Device upload did not finish activation")
    expected_marker = authority_manifest_marker(str(authority.get("selection_contract") or ""))
    if (manifest or {}).get(AUTHORITY_MARKER) != expected_marker:
        raise DeviceCollectionIntegrityError(
            "Verified device authority exists, but the collection manifest marker does not match"
        )
    semantics_json = authority.get("semantic_manifest_json")
    if (
        not isinstance(semantics_json, str)
        or _digest_text(semantics_json) != authority.get("semantic_manifest_sha256")
    ):
        raise DeviceCollectionIntegrityError(
            "Stored device collection authority failed integrity verification"
        )
    return authority


def require_active_snapshot(
    db: sqlite3.Connection,
    *,
    run_id: str,
    revision: int,
    observation_id: str,
    artifact_sha256: str,
    retained_filename: str,
    semantic_manifest_sha256: str,
    selection_contract: str = MANUAL_UPLOAD_SELECTION_CONTRACT,
    authority_inputs: list[dict] | None = None,
) -> None:
    authority = _authority_record(_authority_row(db, run_id))
    expected = {
        "state": "active",
        "revision": revision,
        "artifact_observation_id": observation_id,
        "artifact_sha256": artifact_sha256,
        "retained_filename": retained_filename,
        "selection_contract": selection_contract,
        "semantic_manifest_sha256": semantic_manifest_sha256,
    }
    authority_json = authority.get("semantic_manifest_json") if authority else None
    if (
        authority is None
        or any(authority.get(key) != value for key, value in expected.items())
        or not isinstance(authority_json, str)
        or _digest_text(authority_json) != authority.get("semantic_manifest_sha256")
        or (
            authority_inputs is not None
            and _authority_input_rows(db, run_id) != _normalized_authority_inputs(authority_inputs)
        )
    ):
        raise DeviceCollectionIntegrityError(
            "Device collection authority changed during verified analysis"
        )


def require_not_deleted_in_transaction(db: sqlite3.Connection, run_id: str) -> None:
    try:
        row = db.execute(
            "SELECT state FROM device_collection_authority WHERE run_id = ?",
            (run_id,),
        ).fetchone()
    except sqlite3.OperationalError as exc:
        if "no such table" in str(exc).lower():
            return
        raise
    if row is not None and row[0] == "deleted":
        raise DeviceCollectionDeleted("Device collection was deleted during analysis")


def tombstone_device_collection(db_path: Path, run_id: str) -> dict:
    """Permanently mark a collection deleted and remove disposable analysis rows."""
    init_device_collection_authority_storage(db_path)
    deleted_at = utc_now()
    with connect_database(db_path) as db:
        db.execute("BEGIN IMMEDIATE")
        authority = _authority_record(_authority_row(db, run_id))
        if authority is None:
            db.execute(
                """INSERT INTO device_collection_authority (
                       run_id, state, revision, created_at, deleted_at
                   ) VALUES (?, 'deleted', 1, ?, ?)""",
                (run_id, deleted_at, deleted_at),
            )
        elif authority["state"] != "deleted":
            db.execute(
                """UPDATE device_collection_authority
                   SET state = 'deleted', revision = revision + 1, deleted_at = ?
                   WHERE run_id = ?""",
                (deleted_at, run_id),
            )
        table = db.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'device_collections'"
        ).fetchone()
        if table is not None:
            db.execute("DELETE FROM device_collections WHERE run_id = ?", (run_id,))
    return get_device_collection_authority(db_path, run_id) or {}
