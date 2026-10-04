"""Verified reusable summaries for finalized manual device uploads."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sqlite3

from app.database import connect_database
from app.derived_results import (
    derived_result_identity,
    init_derived_result_storage,
    load_derived_result,
    load_linked_derived_result,
    prepare_derived_result,
    publish_derived_result,
)
from app.device_configs import (
    MAX_RESPONSE_OUTPUT_CHARS,
    MAX_SUMMARY_ITEMS,
    MAX_SUMMARY_TEXT_BYTES,
    _configuration_source_names,
    _labeled_command_sections,
    active_configuration_text,
    calculate_device_collection_summary,
)
from app.device_collection_authority import (
    COLLECTED_DEVICE_SELECTION_CONTRACT,
    DeviceCollectionIntegrityError,
    MANUAL_UPLOAD_SELECTION_CONTRACT,
    collected_device_manifest_semantics,
    manual_upload_manifest_semantics,
    require_active_snapshot,
    require_available_collection,
)


DEVICE_SUMMARY_FAMILY = "device_collection_summary"
DEVICE_SUMMARY_VERSION = "device-collection-summary:1"
DEVICE_SUMMARY_SCHEMA_VERSION = 1
DEVICE_SUMMARY_PARAMETERS = {
    "snapshot_contract": 1,
    "configuration_selection": "sorted-uploaded_then_sorted-collected_then-stdout",
    "raw_selection": "stdout_then_configuration-order",
    "utf8_errors": "replace",
    "max_summary_text_bytes": MAX_SUMMARY_TEXT_BYTES,
    "max_history_text_chars": MAX_RESPONSE_OUTPUT_CHARS,
    "max_summary_items": MAX_SUMMARY_ITEMS,
    "parser_bundle": "device-summary-parsers:1",
}


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _json_digest(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode()).hexdigest()


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


def _manual_upload_observation(
    db_path: Path, run_id: str, observation_id: str,
) -> dict:
    with connect_database(db_path, read_only=True) as db:
        row = db.execute(
            """SELECT observation.observation_id, observation.sha256,
                      observation.source_kind, observation.source_ref,
                      artifact.size_bytes, artifact.canonical_path
               FROM artifact_observations observation
               JOIN artifact_registry artifact ON artifact.sha256 = observation.sha256
               WHERE observation.observation_id = ?""",
            (observation_id,),
        ).fetchone()
    if row is None:
        raise KeyError("Device upload artifact observation is unavailable")
    if row[2] != "device_config_upload" or row[3] != run_id:
        raise ValueError("Device upload observation does not belong to this collection")
    canonical = _stable_file_bytes(Path(row[5]), "Canonical device evidence")
    if len(canonical) != int(row[4]) or hashlib.sha256(canonical).hexdigest() != row[1]:
        raise ValueError("Canonical device evidence failed exact-content verification")
    return {
        "observation_id": row[0],
        "sha256": row[1],
        "size_bytes": int(row[4]),
        "canonical_bytes": canonical,
    }


def capture_manual_upload_snapshot(db_path: Path, run_id: str, run_dir: Path) -> dict:
    """Freeze and verify the reviewed single-file manual-upload selection shape."""
    manifest_path = run_dir / "manifest.json"
    manifest_bytes = _stable_file_bytes(manifest_path, "Device upload manifest")
    try:
        manifest = json.loads(manifest_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Device upload manifest is unreadable") from exc
    if manifest.get("run_id") != run_id:
        raise ValueError("Device upload manifest does not match its collection")
    if manifest.get("operation") != "manual_upload" or manifest.get("status") != "uploaded":
        raise ValueError("Only finalized manual device uploads use this adapter")
    retained_filename = manifest.get("retained_filename")
    observation_id = manifest.get("artifact_observation_id")
    if not isinstance(retained_filename, str) or not retained_filename:
        raise ValueError("Device upload manifest has no retained evidence filename")
    if not isinstance(observation_id, str) or not observation_id:
        raise ValueError("Device upload manifest has no artifact observation")

    ordered = _configuration_source_names(run_dir)
    existing_configuration = [
        name for name in ordered if (run_dir / name).is_file()
    ]
    raw_order = list(dict.fromkeys(["stdout.txt", *ordered]))
    existing_raw = [name for name in raw_order if (run_dir / name).is_file()]
    history_exists = (run_dir / "command-history.txt").is_file()
    if (
        existing_configuration != [retained_filename]
        or existing_raw != [retained_filename]
        or history_exists
    ):
        raise ValueError(
            "Manual device upload does not match the reviewed single-file selection shape"
        )

    evidence_path = run_dir / retained_filename
    run_local = _stable_file_bytes(evidence_path, "Run-local device evidence")
    observation = _manual_upload_observation(db_path, run_id, observation_id)
    if (
        len(run_local) != observation["size_bytes"]
        or hashlib.sha256(run_local).hexdigest() != observation["sha256"]
        or run_local != observation["canonical_bytes"]
    ):
        raise ValueError("Run-local device evidence does not match its registered artifact")

    prefix = run_local[:MAX_SUMMARY_TEXT_BYTES]
    configuration_text = prefix.decode("utf-8", errors="replace")
    configuration_truncated = len(run_local) > MAX_SUMMARY_TEXT_BYTES
    semantics = manual_upload_manifest_semantics(manifest, history_exists=False)
    sections = _labeled_command_sections(configuration_text)
    history_present = semantics["history_command"] in sections
    history_text = sections.get(semantics["history_command"], "")
    selection_shape = {
        "configuration": "single_uploaded_file",
        "raw_output": "same_as_configuration",
        "command_history": "embedded_configuration_section",
        "embedded_history_present": history_present,
    }
    if _stable_file_bytes(manifest_path, "Device upload manifest") != manifest_bytes:
        raise ValueError("Device upload manifest changed during verification")
    return {
        "run_id": run_id,
        "source_filename": retained_filename,
        "raw_filename": retained_filename,
        "configuration_text": configuration_text,
        "configuration_truncated": configuration_truncated,
        "raw_output": configuration_text,
        "raw_truncated": configuration_truncated,
        "history_text": history_text,
        "manifest_semantics": semantics,
        "manifest_presentation": {
            key: manifest.get(key)
            for key in (
                "run_id", "created_at", "completed_at", "operator", "reason",
                "originating_host", "vendor", "device_type", "device_types",
                "device_name", "device_address", "operation", "status",
                "output_truncated", "retained_filename", "artifact_sha256",
                "artifact_observation_id", "summary_authority",
            )
        },
        "authority_manifest": manifest,
        "selection_shape": selection_shape,
        "observation_id": observation_id,
        "sha256": observation["sha256"],
        "size_bytes": observation["size_bytes"],
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
    }


def _inputs(snapshot: dict) -> list[dict]:
    artifact_input = {
        "kind": "artifact_sha256",
        "identity": snapshot["sha256"],
        "metadata": {"media_family": "device_configuration"},
    }
    history_identity = _json_digest({
        "configuration_sha256": snapshot["sha256"],
        "history_command": snapshot["manifest_semantics"]["history_command"],
        "present": snapshot["selection_shape"]["embedded_history_present"],
    })
    return [
        {"role": "configuration", **artifact_input},
        {"role": "raw_output", **artifact_input},
        {
            "role": "command_history",
            "kind": "embedded_config_section",
            "identity": history_identity,
            "metadata": {
                "present": snapshot["selection_shape"]["embedded_history_present"]
            },
        },
        {
            "role": "manifest_semantics",
            "kind": "canonical_json_sha256",
            "identity": _json_digest(snapshot["manifest_semantics"]),
            "metadata": snapshot["manifest_semantics"],
        },
        {
            "role": "selection_shape",
            "kind": "canonical_json_sha256",
            "identity": _json_digest(snapshot["selection_shape"]),
            "metadata": snapshot["selection_shape"],
        },
    ]


def _authority_guard(run_id: str, snapshot: dict, authority: dict):
    def require_observation(db: sqlite3.Connection) -> None:
        row = db.execute(
            """SELECT sha256, source_kind, source_ref
               FROM artifact_observations WHERE observation_id = ?""",
            (snapshot["observation_id"],),
        ).fetchone()
        if row is None or tuple(row) != (
            snapshot["sha256"], "device_config_upload", run_id,
        ):
            raise ValueError("Device upload artifact authority changed during analysis")
        require_active_snapshot(
            db,
            run_id=run_id,
            revision=authority["revision"],
            observation_id=snapshot["observation_id"],
            artifact_sha256=snapshot["sha256"],
            retained_filename=snapshot["source_filename"],
            semantic_manifest_sha256=_json_digest(snapshot["manifest_semantics"]),
        )
    return require_observation


def _summary_payload(snapshot: dict) -> dict:
    semantics = snapshot["manifest_semantics"]
    summary = calculate_device_collection_summary(
        run_id=snapshot["run_id"],
        configuration_text=snapshot["configuration_text"],
        source_filename=snapshot["source_filename"],
        configuration_truncated=snapshot["configuration_truncated"],
        raw_output=snapshot["raw_output"],
        raw_filename=snapshot["raw_filename"],
        raw_truncated=snapshot["raw_truncated"],
        history_text=snapshot["history_text"],
        history_attempted=semantics["history_attempted"],
        vendor=semantics["vendor"],
        commands=semantics["commands"],
        output_complete=(
            False
            if semantics.get("output_complete_is_false")
            or semantics.get("output_complete") is False
            else None
        ),
    )
    summary.pop("run_id", None)
    summary.pop("source_filename", None)
    summary.pop("raw_filename", None)
    summary.pop("configuration_text", None)
    summary.pop("raw_output", None)
    return summary


def _attach_context(payload: dict, snapshot: dict, **metadata: object) -> dict:
    return {
        **metadata,
        "payload": {
            **payload,
            "run_id": snapshot["run_id"],
            "source_filename": snapshot["source_filename"],
            "raw_filename": snapshot["raw_filename"],
        },
        "observation_id": snapshot["observation_id"],
        "manifest": dict(snapshot["manifest_presentation"]),
        "source_content": {
            "configuration_text": active_configuration_text(snapshot["configuration_text"]),
            "raw_output": snapshot["raw_output"],
        },
    }


def analyze_manual_upload_summary(
    db_path: Path, run_id: str, run_dir: Path,
    *, analysis_version: str = DEVICE_SUMMARY_VERSION,
) -> dict:
    """Reuse one immutable result only while upload authority remains active."""
    init_derived_result_storage(db_path)
    snapshot = capture_manual_upload_snapshot(db_path, run_id, run_dir)
    authority = require_available_collection(
        db_path, run_id, manifest=snapshot["authority_manifest"]
    )
    if authority is None:
        raise DeviceCollectionIntegrityError(
            "Manual upload has no verified collection authority"
        )
    if authority.get("selection_contract") != MANUAL_UPLOAD_SELECTION_CONTRACT:
        raise DeviceCollectionIntegrityError(
            "Manual upload selection contract is not supported"
        )
    inputs = _inputs(snapshot)
    identity = derived_result_identity(
        family=DEVICE_SUMMARY_FAMILY,
        analysis_version=analysis_version,
        payload_schema_version=DEVICE_SUMMARY_SCHEMA_VERSION,
        parameters=dict(DEVICE_SUMMARY_PARAMETERS),
        inputs=inputs,
    )
    guard = _authority_guard(run_id, snapshot, authority)
    linked_configuration = load_linked_derived_result(
        db_path,
        identity,
        role="configuration",
        observation_id=snapshot["observation_id"],
        read_guard=guard,
    )
    linked_raw = load_linked_derived_result(
        db_path,
        identity,
        role="raw_output",
        observation_id=snapshot["observation_id"],
        read_guard=guard,
    )
    if linked_configuration is not None and linked_raw is not None:
        if linked_configuration["result_id"] != linked_raw["result_id"]:
            raise RuntimeError("Device summary provenance links disagree")
        verified = capture_manual_upload_snapshot(db_path, run_id, run_dir)
        if verified != snapshot:
            raise ValueError("Device upload snapshot changed during analysis")
        return _attach_context(
            linked_configuration["payload"], snapshot,
            result_id=linked_configuration["result_id"],
            family=DEVICE_SUMMARY_FAMILY,
            analysis_version=analysis_version,
            reused=True,
        )

    retained = load_derived_result(db_path, identity)
    payload = retained["payload"] if retained is not None else _summary_payload(snapshot)
    if capture_manual_upload_snapshot(db_path, run_id, run_dir) != snapshot:
        raise ValueError("Device upload snapshot changed during analysis")
    prepared = prepare_derived_result(
        family=DEVICE_SUMMARY_FAMILY,
        analysis_version=analysis_version,
        payload_schema_version=DEVICE_SUMMARY_SCHEMA_VERSION,
        parameters=dict(DEVICE_SUMMARY_PARAMETERS),
        inputs=inputs,
        payload=payload,
    )
    publication = publish_derived_result(
        db_path,
        prepared,
        observation_links=[
            {"role": "configuration", "observation_id": snapshot["observation_id"]},
            {"role": "raw_output", "observation_id": snapshot["observation_id"]},
        ],
        transaction_guard=guard,
    )
    if capture_manual_upload_snapshot(db_path, run_id, run_dir) != snapshot:
        raise ValueError("Device upload snapshot changed during analysis")
    return _attach_context(
        payload,
        snapshot,
        result_id=publication["result_id"],
        family=DEVICE_SUMMARY_FAMILY,
        analysis_version=analysis_version,
        reused=bool(retained is not None or not publication["created"]),
    )


def _registered_collection_file(
    db_path: Path, run_id: str, run_dir: Path, record: dict, label: str,
) -> dict:
    filename = record.get("filename")
    observation_id = record.get("observation_id")
    expected_sha256 = record.get("sha256")
    expected_size = record.get("size_bytes")
    if (
        not isinstance(filename, str) or not filename
        or not isinstance(observation_id, str) or not observation_id
        or not isinstance(expected_sha256, str) or not expected_sha256
        or not isinstance(expected_size, int) or expected_size < 0
    ):
        raise ValueError(f"{label} registration is incomplete")
    with connect_database(db_path, read_only=True) as db:
        row = db.execute(
            """SELECT observation.sha256, observation.source_kind,
                      observation.source_ref, artifact.size_bytes,
                      artifact.canonical_path
               FROM artifact_observations observation
               JOIN artifact_registry artifact ON artifact.sha256 = observation.sha256
               WHERE observation.observation_id = ?""",
            (observation_id,),
        ).fetchone()
    if row is None or tuple(row[:4]) != (
        expected_sha256, "device_collection", run_id, expected_size,
    ):
        raise ValueError(f"{label} observation does not match this collection")
    local_bytes = _stable_file_bytes(run_dir / filename, f"Run-local {label.lower()}")
    canonical_bytes = _stable_file_bytes(Path(row[4]), f"Canonical {label.lower()}")
    if (
        len(local_bytes) != expected_size
        or len(canonical_bytes) != expected_size
        or hashlib.sha256(local_bytes).hexdigest() != expected_sha256
        or hashlib.sha256(canonical_bytes).hexdigest() != expected_sha256
        or local_bytes != canonical_bytes
    ):
        raise ValueError(f"{label} failed exact-content verification")
    return {
        "filename": filename,
        "observation_id": observation_id,
        "sha256": expected_sha256,
        "size_bytes": expected_size,
        "bytes": local_bytes,
    }


def capture_collected_device_snapshot(db_path: Path, run_id: str, run_dir: Path) -> dict:
    """Freeze the exact files and selection rules for one completed SSH collection."""
    manifest_path = run_dir / "manifest.json"
    manifest_bytes = _stable_file_bytes(manifest_path, "Device collection manifest")
    try:
        manifest = json.loads(manifest_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Device collection manifest is unreadable") from exc
    if manifest.get("run_id") != run_id:
        raise ValueError("Device collection manifest does not match its collection")
    semantics = collected_device_manifest_semantics(manifest)
    if (
        manifest.get("operation") not in {
            "configuration_pull", "interactive_configuration_pull",
        }
        or manifest.get("status") != "completed"
        or not semantics["output_complete"]
        or semantics["output_truncated"]
        or semantics["command_history_truncated"]
    ):
        raise ValueError("Only complete, untruncated SSH collections use this adapter")
    registry = manifest.get("artifact_registry") or {}
    if registry.get("status") != "complete" or registry.get("errors"):
        raise ValueError("Device collection artifact registration is incomplete")
    registered = {}
    for item in registry.get("files") or []:
        if not isinstance(item, dict) or not isinstance(item.get("filename"), str):
            raise ValueError("Device collection artifact registration is invalid")
        if item["filename"] in registered:
            raise ValueError("Device collection artifact registration contains duplicates")
        registered[item["filename"]] = item

    configuration_candidates = [
        name for name in _configuration_source_names(run_dir)
        if (run_dir / name).is_file()
    ]
    raw_candidates = [
        name for name in dict.fromkeys(["stdout.txt", *_configuration_source_names(run_dir)])
        if (run_dir / name).is_file()
    ]
    if not configuration_candidates or not raw_candidates:
        raise ValueError("Device collection has no retained configuration evidence")
    configuration = _registered_collection_file(
        db_path, run_id, run_dir,
        registered.get(configuration_candidates[0]) or {}, "Configuration evidence",
    )
    raw = _registered_collection_file(
        db_path, run_id, run_dir,
        registered.get(raw_candidates[0]) or {}, "Raw output evidence",
    )
    configuration_prefix = configuration["bytes"][:MAX_SUMMARY_TEXT_BYTES]
    raw_prefix = raw["bytes"][:MAX_SUMMARY_TEXT_BYTES]
    configuration_text = configuration_prefix.decode("utf-8", errors="replace")
    raw_output = raw_prefix.decode("utf-8", errors="replace")
    history_path = run_dir / "command-history.txt"
    if history_path.is_file():
        history = _registered_collection_file(
            db_path, run_id, run_dir,
            registered.get("command-history.txt") or {}, "Command history evidence",
        )
        history_text = history["bytes"][:MAX_RESPONSE_OUTPUT_CHARS].decode(
            "utf-8", errors="replace"
        )
        history_input = {
            "role": "command_history", "position": 0,
            "source_kind": "artifact_file", "identity": history["sha256"],
            "filename": history["filename"],
            "observation_id": history["observation_id"],
            "sha256": history["sha256"], "size_bytes": history["size_bytes"],
            "metadata": {"selection_rule": "dedicated_history_file"},
        }
    else:
        sections = _labeled_command_sections(configuration_text)
        history_present = semantics["history_command"] in sections
        history_text = sections.get(semantics["history_command"], "")
        descriptor = {
            "configuration_sha256": configuration["sha256"],
            "history_command": semantics["history_command"],
            "present": history_present,
        }
        history_input = {
            "role": "command_history", "position": 0,
            "source_kind": "embedded_section" if history_present else "absent",
            "identity": _json_digest(descriptor),
            "filename": None, "observation_id": None, "sha256": None,
            "size_bytes": None, "metadata": descriptor,
        }
    authority_inputs = [
        {
            "role": "configuration", "position": 0,
            "source_kind": "artifact_file", "identity": configuration["sha256"],
            "filename": configuration["filename"],
            "observation_id": configuration["observation_id"],
            "sha256": configuration["sha256"], "size_bytes": configuration["size_bytes"],
            "metadata": {
                "selection_rule": "sorted_uploaded_then_sorted_collected_then_stdout",
                "candidates": configuration_candidates,
            },
        },
        {
            "role": "raw_output", "position": 0,
            "source_kind": "artifact_file", "identity": raw["sha256"],
            "filename": raw["filename"], "observation_id": raw["observation_id"],
            "sha256": raw["sha256"], "size_bytes": raw["size_bytes"],
            "metadata": {
                "selection_rule": "stdout_then_configuration_order",
                "candidates": raw_candidates,
            },
        },
        history_input,
    ]
    selection_shape = {
        item["role"]: {
            "source_kind": item["source_kind"],
            "identity": item["identity"],
            "filename": item["filename"],
            "metadata": item["metadata"],
        }
        for item in authority_inputs
    }
    if _stable_file_bytes(manifest_path, "Device collection manifest") != manifest_bytes:
        raise ValueError("Device collection manifest changed during verification")
    return {
        "run_id": run_id,
        "source_filename": configuration["filename"],
        "raw_filename": raw["filename"],
        "configuration_text": configuration_text,
        "configuration_truncated": len(configuration["bytes"]) > MAX_SUMMARY_TEXT_BYTES,
        "raw_output": raw_output,
        "raw_truncated": len(raw["bytes"]) > MAX_SUMMARY_TEXT_BYTES,
        "history_text": history_text,
        "manifest_semantics": semantics,
        "manifest_presentation": {
            key: manifest.get(key)
            for key in (
                "run_id", "created_at", "completed_at", "operator", "reason",
                "originating_host", "vendor", "device_type", "device_types",
                "device_name", "device_address", "operation", "status",
                "authentication_mode", "output_truncated", "local_output_name",
                "command_history_status", "summary_verification_status",
                "summary_authority",
            )
        },
        "authority_manifest": manifest,
        "selection_shape": selection_shape,
        "authority_inputs": authority_inputs,
        "observation_id": configuration["observation_id"],
        "sha256": configuration["sha256"],
        "size_bytes": configuration["size_bytes"],
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
    }


def _collected_inputs(snapshot: dict) -> list[dict]:
    inputs = []
    for item in snapshot["authority_inputs"]:
        inputs.append({
            "role": item["role"],
            "kind": (
                "artifact_sha256" if item["source_kind"] == "artifact_file"
                else "embedded_config_section" if item["source_kind"] == "embedded_section"
                else "absence_descriptor"
            ),
            "identity": item["identity"],
            "metadata": item["metadata"],
        })
    inputs.extend([
        {
            "role": "manifest_semantics", "kind": "canonical_json_sha256",
            "identity": _json_digest(snapshot["manifest_semantics"]),
            "metadata": snapshot["manifest_semantics"],
        },
        {
            "role": "selection_shape", "kind": "canonical_json_sha256",
            "identity": _json_digest(snapshot["selection_shape"]),
            "metadata": snapshot["selection_shape"],
        },
    ])
    return inputs


def _collected_authority_guard(run_id: str, snapshot: dict, authority: dict):
    def require_inputs(db: sqlite3.Connection) -> None:
        require_active_snapshot(
            db,
            run_id=run_id,
            revision=authority["revision"],
            observation_id=snapshot["observation_id"],
            artifact_sha256=snapshot["sha256"],
            retained_filename=snapshot["source_filename"],
            semantic_manifest_sha256=_json_digest(snapshot["manifest_semantics"]),
            selection_contract=COLLECTED_DEVICE_SELECTION_CONTRACT,
            authority_inputs=snapshot["authority_inputs"],
        )
    return require_inputs


def analyze_collected_device_summary(
    db_path: Path, run_id: str, run_dir: Path,
    *, analysis_version: str = DEVICE_SUMMARY_VERSION,
) -> dict:
    """Analyze a finalized SSH collection only through its verified frozen inputs."""
    init_derived_result_storage(db_path)
    snapshot = capture_collected_device_snapshot(db_path, run_id, run_dir)
    authority = require_available_collection(
        db_path, run_id, manifest=snapshot["authority_manifest"]
    )
    if authority is None or authority.get("selection_contract") != COLLECTED_DEVICE_SELECTION_CONTRACT:
        raise DeviceCollectionIntegrityError("SSH collection has no supported verified authority")
    inputs = _collected_inputs(snapshot)
    identity = derived_result_identity(
        family=DEVICE_SUMMARY_FAMILY,
        analysis_version=analysis_version,
        payload_schema_version=DEVICE_SUMMARY_SCHEMA_VERSION,
        parameters=dict(DEVICE_SUMMARY_PARAMETERS),
        inputs=inputs,
    )
    guard = _collected_authority_guard(run_id, snapshot, authority)
    file_inputs = [
        item for item in snapshot["authority_inputs"]
        if item["source_kind"] == "artifact_file"
    ]
    linked = [
        load_linked_derived_result(
            db_path, identity, role=item["role"],
            observation_id=item["observation_id"], read_guard=guard,
        )
        for item in file_inputs
    ]
    if linked and all(value is not None for value in linked):
        if len({value["result_id"] for value in linked}) != 1:
            raise RuntimeError("Device summary provenance links disagree")
        if capture_collected_device_snapshot(db_path, run_id, run_dir) != snapshot:
            raise ValueError("Device collection snapshot changed during analysis")
        return _attach_context(
            linked[0]["payload"], snapshot,
            result_id=linked[0]["result_id"], family=DEVICE_SUMMARY_FAMILY,
            analysis_version=analysis_version, reused=True,
        )
    retained = load_derived_result(db_path, identity)
    payload = retained["payload"] if retained is not None else _summary_payload(snapshot)
    if capture_collected_device_snapshot(db_path, run_id, run_dir) != snapshot:
        raise ValueError("Device collection snapshot changed during analysis")
    prepared = prepare_derived_result(
        family=DEVICE_SUMMARY_FAMILY,
        analysis_version=analysis_version,
        payload_schema_version=DEVICE_SUMMARY_SCHEMA_VERSION,
        parameters=dict(DEVICE_SUMMARY_PARAMETERS), inputs=inputs, payload=payload,
    )
    publication = publish_derived_result(
        db_path, prepared,
        observation_links=[
            {"role": item["role"], "observation_id": item["observation_id"]}
            for item in file_inputs
        ],
        transaction_guard=guard,
    )
    if capture_collected_device_snapshot(db_path, run_id, run_dir) != snapshot:
        raise ValueError("Device collection snapshot changed during analysis")
    return _attach_context(
        payload, snapshot, result_id=publication["result_id"],
        family=DEVICE_SUMMARY_FAMILY, analysis_version=analysis_version,
        reused=bool(retained is not None or not publication["created"]),
    )
