"""Internal verified adapter for frozen manual device-upload summaries.

This module is intentionally not wired into production reads yet. Publication and
collection deletion need a durable shared authority record before the legacy cache can
be replaced safely.
"""
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
    calculate_device_collection_summary,
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


def _manifest_semantics(manifest: dict, *, history_exists: bool) -> dict:
    commands = manifest.get("commands") or []
    if not isinstance(commands, list):
        raise ValueError("Device upload commands must be a list")
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
    semantics = _manifest_semantics(manifest, history_exists=False)
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


def _authority_guard(run_id: str, observation_id: str, digest: str):
    def require_observation(db: sqlite3.Connection) -> None:
        row = db.execute(
            """SELECT sha256, source_kind, source_ref
               FROM artifact_observations WHERE observation_id = ?""",
            (observation_id,),
        ).fetchone()
        if row is None or tuple(row) != (digest, "device_config_upload", run_id):
            raise ValueError("Device upload artifact authority changed during analysis")
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
        output_complete=False if semantics["output_complete_is_false"] else None,
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
    }


def analyze_manual_upload_summary(
    db_path: Path, run_id: str, run_dir: Path,
    *, analysis_version: str = DEVICE_SUMMARY_VERSION,
) -> dict:
    """Exercise verified reuse internally; production reads are not wired to this yet."""
    init_derived_result_storage(db_path)
    snapshot = capture_manual_upload_snapshot(db_path, run_id, run_dir)
    inputs = _inputs(snapshot)
    identity = derived_result_identity(
        family=DEVICE_SUMMARY_FAMILY,
        analysis_version=analysis_version,
        payload_schema_version=DEVICE_SUMMARY_SCHEMA_VERSION,
        parameters=dict(DEVICE_SUMMARY_PARAMETERS),
        inputs=inputs,
    )
    guard = _authority_guard(run_id, snapshot["observation_id"], snapshot["sha256"])
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
