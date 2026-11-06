"""Exact encounter adapters for every supported evidence source family."""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import sqlite3
import stat

from app.evidence_retirement import (
    EvidenceDependency,
    EvidenceRetirementAdapter,
    EvidenceRetirementBlocked,
    EvidenceRetirementError,
)


NMAP_SCAN_RUN = "nmap_scan_run"
NMAP_IMPORT = "nmap_import"
DEVICE_COLLECTION = "device_collection"
ARKIME_SESSIONS_IMPORT = "arkime_sessions_import"
ARKIME_SUMMARY_IMPORT = "arkime_summary_import"
HOSTNAME_EVIDENCE_UPLOAD = "hostname_evidence_upload"

ACTIVE_SCAN_STATES = frozenset({
    "queued", "dispatching", "running", "awaiting_fallback_approval",
})
HOSTNAME_EVIDENCE_ID = re.compile(r"[a-f0-9]{32}")
MAX_HOSTNAME_MANIFEST_BYTES = 100 * 1024 * 1024


def artifact_observation_namespace(observation_id: str) -> str:
    value = str(observation_id or "")
    namespace = f"artifact_observation:{value}"
    if not value or value != value.strip() or len(namespace) > 100:
        raise EvidenceRetirementError("Artifact observation identity is not canonical")
    return namespace


def artifact_observation_dependency(
    source_family: str, observation_id: str,
) -> EvidenceDependency:
    return EvidenceDependency(
        source_family=source_family,
        identity_namespace=artifact_observation_namespace(observation_id),
        identity_value=observation_id,
    )


def _bounded_regular_json(path: Path, maximum: int) -> dict:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    descriptor = os.open(path, flags)
    try:
        status = os.fstat(descriptor)
        if not stat.S_ISREG(status.st_mode) or status.st_size > maximum:
            raise EvidenceRetirementError("Hostname evidence manifest is invalid")
        chunks: list[bytes] = []
        length = 0
        while length <= maximum:
            chunk = os.read(descriptor, min(1024 * 1024, maximum + 1 - length))
            if not chunk:
                break
            chunks.append(chunk)
            length += len(chunk)
        if length > maximum:
            raise EvidenceRetirementError("Hostname evidence manifest is too large")
        value = json.loads(b"".join(chunks).decode("utf-8"))
    finally:
        os.close(descriptor)
    if not isinstance(value, dict):
        raise EvidenceRetirementError("Hostname evidence manifest must be an object")
    return value


def _one(db: sqlite3.Connection, statement: str, values: tuple, label: str):
    try:
        row = db.execute(statement, values).fetchone()
    except sqlite3.OperationalError as exc:
        if "no such table" in str(exc).casefold():
            raise EvidenceRetirementError(f"{label} storage is unavailable") from exc
        raise
    if row is None:
        raise EvidenceRetirementError(f"{label} does not exist")
    return row


def _artifact_identities(
    db: sqlite3.Connection, *, source_kinds: tuple[str, ...], source_ref: str,
) -> dict[str, str]:
    marks = ",".join("?" for _ in source_kinds)
    try:
        rows = db.execute(
            f"""SELECT observation_id,source_kind,original_filename
                  FROM artifact_observations
                 WHERE source_kind IN ({marks}) AND source_ref=?
                 ORDER BY source_kind,original_filename,observation_id""",
            (*source_kinds, source_ref),
        ).fetchall()
    except sqlite3.OperationalError as exc:
        if "no such table" in str(exc).casefold():
            raise EvidenceRetirementError("Artifact Registry storage is unavailable") from exc
        raise
    return {
        artifact_observation_namespace(str(row[0])): str(row[0])
        for row in rows
    }


def nmap_scan_run_adapter() -> EvidenceRetirementAdapter:
    def identities(db: sqlite3.Connection, run_id: str) -> dict[str, str]:
        row = _one(
            db, "SELECT status FROM scan_runs WHERE run_id=?", (run_id,), "Nmap scan run",
        )
        if str(row[0]) != "completed":
            raise EvidenceRetirementBlocked(
                "Only completed retained Nmap scan evidence can be retired"
            )
        artifacts = _artifact_identities(
            db, source_kinds=("nmap_scan", "nmap_run"), source_ref=run_id,
        )
        if not artifacts:
            raise EvidenceRetirementError(
                "This historical scan must complete Artifact Registry backfill before retirement"
            )
        return {"encounter_id": run_id, "run_id": run_id, **artifacts}

    def active(db: sqlite3.Connection, run_id: str) -> str | None:
        row = _one(
            db, "SELECT status FROM scan_runs WHERE run_id=?", (run_id,), "Nmap scan run",
        )
        state = str(row[0] or "")
        return f"Nmap scan run is still {state}" if state in ACTIVE_SCAN_STATES else None

    return EvidenceRetirementAdapter(identities, active)


def nmap_import_adapter() -> EvidenceRetirementAdapter:
    def identities(db: sqlite3.Connection, observation_id: str) -> dict[str, str]:
        row = _one(
            db,
            """SELECT source_ref FROM artifact_observations
                WHERE observation_id=? AND source_kind='nmap_import'""",
            (observation_id,),
            "Nmap import observation",
        )
        return {
            "encounter_id": observation_id,
            "observation_id": observation_id,
            "source_ref": str(row[0]),
        }

    return EvidenceRetirementAdapter(identities, lambda _db, _id: None)


def device_collection_adapter() -> EvidenceRetirementAdapter:
    def authority(db: sqlite3.Connection, run_id: str):
        return _one(
            db,
            "SELECT state,artifact_observation_id FROM device_collection_authority WHERE run_id=?",
            (run_id,),
            "Device collection",
        )

    def identities(db: sqlite3.Connection, run_id: str) -> dict[str, str]:
        state, primary = authority(db, run_id)
        if state != "active":
            raise EvidenceRetirementBlocked(
                "Only complete active device evidence can be retired"
            )
        try:
            rows = db.execute(
                """SELECT input_role,position,artifact_observation_id
                     FROM device_collection_authority_inputs
                    WHERE run_id=? AND artifact_observation_id IS NOT NULL
                    ORDER BY input_role,position""",
                (run_id,),
            ).fetchall()
        except sqlite3.OperationalError as exc:
            if "no such table" in str(exc).casefold():
                raise EvidenceRetirementError("Device collection inputs are unavailable") from exc
            raise
        observation_ids = []
        if primary:
            observation_ids.append(str(primary))
        observation_ids.extend(str(row[2]) for row in rows)
        observation_ids.extend(_artifact_identities(
            db,
            source_kinds=("device_config_upload", "device_config", "device_collection"),
            source_ref=run_id,
        ).values())
        unique = list(dict.fromkeys(observation_ids))
        if not unique:
            raise EvidenceRetirementError(
                "This device collection must complete evidence backfill before retirement"
            )
        return {
            "encounter_id": run_id,
            "run_id": run_id,
            **{
                artifact_observation_namespace(observation_id): observation_id
                for observation_id in unique
            },
        }

    def active(db: sqlite3.Connection, run_id: str) -> str | None:
        state, _primary = authority(db, run_id)
        return (
            "Device collection is still preparing"
            if state == "preparing" else
            "Device collection was physically deleted and cannot be retired"
            if state == "deleted" else None
        )

    return EvidenceRetirementAdapter(identities, active)


def _arkime_adapter(
    *, table: str, family_label: str,
) -> EvidenceRetirementAdapter:
    def identities(db: sqlite3.Connection, import_id: str) -> dict[str, str]:
        row = _one(
            db, f"SELECT observation_id FROM {table} WHERE import_id=?",
            (import_id,), family_label,
        )
        return {
            "encounter_id": import_id,
            "import_id": import_id,
            "observation_id": str(row[0]),
        }

    return EvidenceRetirementAdapter(identities, lambda _db, _id: None)


def arkime_sessions_import_adapter() -> EvidenceRetirementAdapter:
    return _arkime_adapter(table="arkime_imports", family_label="Arkime Sessions import")


def arkime_summary_import_adapter() -> EvidenceRetirementAdapter:
    return _arkime_adapter(
        table="arkime_summary_imports", family_label="Arkime Summary import",
    )


def hostname_evidence_upload_adapter(evidence_dir: Path) -> EvidenceRetirementAdapter:
    evidence_root = Path(evidence_dir)

    def identities(_db: sqlite3.Connection, evidence_id: str) -> dict[str, str]:
        if not HOSTNAME_EVIDENCE_ID.fullmatch(evidence_id):
            raise EvidenceRetirementError("Hostname evidence identity is invalid")
        run_dir = evidence_root.absolute() / evidence_id
        manifest_path = run_dir / "manifest.json"
        try:
            directory_status = run_dir.lstat()
            if stat.S_ISLNK(directory_status.st_mode) or not stat.S_ISDIR(directory_status.st_mode):
                raise EvidenceRetirementError("Hostname evidence directory is invalid")
            manifest = _bounded_regular_json(
                manifest_path, MAX_HOSTNAME_MANIFEST_BYTES,
            )
        except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise EvidenceRetirementError("Hostname evidence manifest is unavailable") from exc
        if str(manifest.get("evidence_id") or "") != evidence_id:
            raise EvidenceRetirementError("Hostname evidence manifest identity changed")
        stored_name = str(manifest.get("stored_name") or "")
        if not stored_name or Path(stored_name).name != stored_name:
            raise EvidenceRetirementError("Hostname evidence source name is invalid")
        source_path = run_dir / stored_name
        try:
            source_status = source_path.lstat()
        except OSError as exc:
            raise EvidenceRetirementError("Hostname evidence source is unavailable") from exc
        if stat.S_ISLNK(source_status.st_mode) or not stat.S_ISREG(source_status.st_mode):
            raise EvidenceRetirementError("Hostname evidence source is unavailable")
        return {
            "encounter_id": evidence_id,
            "evidence_id": evidence_id,
            "manifest_relative_path": f"{evidence_id}/manifest.json",
        }

    return EvidenceRetirementAdapter(identities, lambda _db, _id: None)


def adapter_for_source(
    source_family: str, *, hostname_evidence_dir: Path | None = None,
) -> EvidenceRetirementAdapter:
    if source_family == NMAP_SCAN_RUN:
        return nmap_scan_run_adapter()
    if source_family == NMAP_IMPORT:
        return nmap_import_adapter()
    if source_family == DEVICE_COLLECTION:
        return device_collection_adapter()
    if source_family == ARKIME_SESSIONS_IMPORT:
        return arkime_sessions_import_adapter()
    if source_family == ARKIME_SUMMARY_IMPORT:
        return arkime_summary_import_adapter()
    if source_family == HOSTNAME_EVIDENCE_UPLOAD:
        if hostname_evidence_dir is None:
            raise EvidenceRetirementError("Hostname evidence storage is required")
        return hostname_evidence_upload_adapter(hostname_evidence_dir)
    raise EvidenceRetirementError(f"Unsupported evidence source family: {source_family}")

