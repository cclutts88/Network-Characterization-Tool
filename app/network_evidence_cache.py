"""Exact-source, process-local reuse for the assembled current-network model."""
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from app.database import connect_database
from app.derived_contracts import (
    NMAP_BASE_ANALYSIS_FAMILY,
    NMAP_BASE_ANALYSIS_VERSION,
    NMAP_BASE_PARAMETERS,
    NMAP_BASE_PAYLOAD_SCHEMA_VERSION,
    NMAP_TOPOLOGY_FAMILY,
    NMAP_TOPOLOGY_PARAMETERS,
    NMAP_TOPOLOGY_PAYLOAD_SCHEMA_VERSION,
    NMAP_TOPOLOGY_VERSION,
)
from app.mac_enrichment import oui_search_paths


NETWORK_MODEL_CONTRACT_VERSION = 1
MAX_MAP_CONFIG_BYTES = 100 * 1024 * 1024


class NetworkEvidenceSourceChanged(RuntimeError):
    """The source set did not remain stable long enough to publish a cache entry."""


@dataclass(frozen=True)
class NetworkEvidenceSnapshot:
    key: str | None
    context: Any
    reason: str | None = None


@dataclass
class _Flight:
    event: threading.Event
    error: BaseException | None = None


def _serialize(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _digest_json(value: Any) -> str:
    return hashlib.sha256(_serialize(value)).hexdigest()


def stable_file_identity(path: Path) -> dict:
    """Hash one regular file while proving it did not change during the read."""
    if not path.is_file() or path.is_symlink():
        raise OSError(f"Stable regular file is unavailable: {path}")
    resolved = path.resolve(strict=True)
    before = resolved.stat()
    digest = hashlib.sha256()
    with resolved.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    after = resolved.stat()
    before_identity = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )
    after_identity = (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )
    if before_identity != after_identity:
        raise OSError(f"File changed during fingerprinting: {path}")
    return {
        "path": str(resolved),
        "device": int(after.st_dev),
        "inode": int(after.st_ino),
        "size": int(after.st_size),
        "sha256": digest.hexdigest(),
    }


def stable_path_identity(path: Path) -> dict:
    """Identify a path replacement without reading the mutable SQLite file bytes."""
    if path.is_symlink():
        raise OSError(f"Database path must not be a symbolic link: {path}")
    resolved = path.resolve(strict=True)
    info = resolved.stat()
    if not resolved.is_file():
        raise OSError(f"Regular file is unavailable: {path}")
    return {
        "path": str(resolved),
        "device": int(info.st_dev),
        "inode": int(info.st_ino),
    }


class NetworkEvidenceCache:
    """One-entry serialized cache with per-descriptor single-flight builds."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._entry_key: str | None = None
        self._entry_json: bytes | None = None
        self._flights: dict[str, _Flight] = {}
        self._hits = 0
        self._misses = 0

    def clear(self) -> None:
        with self._lock:
            self._entry_key = None
            self._entry_json = None
            self._hits = 0
            self._misses = 0

    def status(self) -> dict:
        with self._lock:
            return {
                "entry_count": int(self._entry_json is not None),
                "entry_bytes": len(self._entry_json or b""),
                "in_flight": len(self._flights),
                "hits": self._hits,
                "misses": self._misses,
            }

    def get(
        self,
        snapshot_provider: Callable[[], NetworkEvidenceSnapshot],
        builder: Callable[[Any], Any],
        *,
        retry_on_change: int = 1,
    ) -> Any:
        attempts = 0
        while True:
            snapshot = snapshot_provider()
            if snapshot.key is None:
                # Unverifiable legacy or changing inputs retain the existing behavior,
                # but never create or consume a weak cache entry.
                return json.loads(_serialize(builder(snapshot.context)))

            with self._lock:
                if self._entry_key == snapshot.key and self._entry_json is not None:
                    self._hits += 1
                    return json.loads(self._entry_json)
                flight = self._flights.get(snapshot.key)
                if flight is None:
                    flight = _Flight(threading.Event())
                    self._flights[snapshot.key] = flight
                    owner = True
                    self._misses += 1
                else:
                    owner = False

            if not owner:
                flight.event.wait()
                if flight.error is not None:
                    raise flight.error
                continue

            try:
                result_json = _serialize(builder(snapshot.context))
                after = snapshot_provider()
                stable = after.key is not None and after.key == snapshot.key
                attempts += int(not stable)
                source_error = (
                    NetworkEvidenceSourceChanged(
                        "Retained network evidence changed while the current view was built; retry the request"
                    )
                    if not stable and attempts > retry_on_change
                    else None
                )
                with self._lock:
                    if stable:
                        self._entry_key = snapshot.key
                        self._entry_json = result_json
                    self._flights.pop(snapshot.key, None)
                    flight.error = source_error
                    flight.event.set()
                if stable:
                    return json.loads(result_json)
                if source_error is not None:
                    raise source_error
            except BaseException as exc:
                with self._lock:
                    if not flight.event.is_set():
                        self._flights.pop(snapshot.key, None)
                        flight.error = exc
                        flight.event.set()
                raise


def _table_rows(
    db: sqlite3.Connection,
    table: str,
    *,
    where: str = "",
    order_by: str = "",
    limit: int | None = None,
) -> dict:
    columns = [row[1] for row in db.execute(f"PRAGMA table_info({table})").fetchall()]
    if not columns:
        raise sqlite3.OperationalError(f"Required table is unavailable: {table}")
    query = f"SELECT rowid, * FROM {table}"
    if where:
        query += f" WHERE {where}"
    if order_by:
        query += f" ORDER BY {order_by}"
    if limit is not None:
        query += f" LIMIT {int(limit)}"
    return {
        "columns": ["rowid", *columns],
        "rows": [list(row) for row in db.execute(query).fetchall()],
    }


def select_map_scan_rows(db: sqlite3.Connection, limit: int = 200) -> dict:
    """Select the exact automated scan rows consumed by Map."""
    return _table_rows(
        db, "scan_runs", order_by="created_at DESC, rowid DESC", limit=limit,
    )


def select_map_import_rows(db: sqlite3.Connection, limit: int = 200) -> dict:
    """Select the exact manual import rows consumed by Map."""
    return _table_rows(
        db, "imports", order_by="imported_at DESC, rowid DESC", limit=limit,
    )


def _scan_artifact_rows(db: sqlite3.Connection, run_ids: set[str]) -> list[list]:
    if not run_ids:
        return []
    rows: list[list] = []
    ordered = sorted(run_ids)
    for start in range(0, len(ordered), 400):
        chunk = ordered[start:start + 400]
        placeholders = ",".join("?" for _ in chunk)
        rows.extend(
            list(row)
            for row in db.execute(
                f"""SELECT observation.observation_id, observation.sha256,
                           observation.source_ref, observation.original_filename,
                           artifact.size_bytes, artifact.canonical_path
                    FROM artifact_observations observation
                    JOIN artifact_registry artifact
                      ON artifact.sha256 = observation.sha256
                    WHERE observation.source_kind = 'nmap_scan'
                      AND observation.source_ref IN ({placeholders})
                    ORDER BY observation.source_ref, observation.observation_id""",
                chunk,
            ).fetchall()
        )
    return rows


def select_map_configuration_file(run_dir: Path) -> Path | None:
    candidates = [run_dir / "stdout.txt"]
    candidates.extend(
        path for path in sorted(
            run_dir.glob("uploaded-*"),
            key=lambda item: (item.name.casefold(), item.name),
        )
        if path.is_file()
    )
    for path in candidates:
        if path.is_file() and path.stat().st_size <= MAX_MAP_CONFIG_BYTES:
            return path
    return None


def select_map_configuration_records(
    config_dir: Path, limit: int = 300,
) -> tuple[list[tuple[Path, dict]], str | None]:
    """Select Map manifests with one deterministic order shared by build and cache."""
    if not config_dir.exists():
        return [], None
    records: list[tuple[Path, dict]] = []
    error: str | None = None
    for path in config_dir.glob("*/manifest.json"):
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            error = error or f"Device manifest is not stable and readable: {exc}"
            continue
        records.append((path, value))
    records.sort(
        key=lambda item: (
            str(item[1].get("completed_at") or item[1].get("created_at") or ""),
            str(item[1].get("run_id") or item[0].parent.name),
            item[0].parent.name.casefold(),
        ),
        reverse=True,
    )
    return records[:limit], error


def _configuration_inputs(config_dir: Path) -> tuple[list[dict], str | None]:
    selected, error = select_map_configuration_records(config_dir)
    records: list[tuple[Path, dict, dict]] = []
    for path, value in selected:
        try:
            identity = stable_file_identity(path)
        except OSError as exc:
            return [], f"Device manifest is not stable and readable: {exc}"
        records.append((path, value, identity))
    if error:
        return [], error
    described: list[dict] = []
    for path, manifest, manifest_identity in records:
        operation = manifest.get("operation")
        legacy_pull = operation is None and manifest.get("vendor") and manifest.get("device_type")
        if operation not in {
            "configuration_pull",
            "interactive_configuration_pull",
            "manual_upload",
        } and not legacy_pull:
            described.append({"manifest": manifest_identity, "eligible": False})
            continue
        if str(manifest.get("status") or "").casefold() not in {
            "completed", "uploaded", "failed",
        }:
            return [], f"Device collection {path.parent.name} is still changing"
        evidence_path = select_map_configuration_file(path.parent)
        if evidence_path is None:
            return [], f"Device collection {path.parent.name} has no stable selected evidence"
        try:
            selected_identity = stable_file_identity(evidence_path)
        except OSError as exc:
            return [], str(exc)
        described.append({
            "manifest": manifest_identity,
            "eligible": True,
            "selected_evidence": selected_identity,
        })
    return described, None


def capture_network_evidence_snapshot(
    *,
    db_path: Path,
    config_dir: Path,
    run_directory: Callable[[str], Path],
    prepare_manifests: Callable[[list[dict], list[str]], list[dict]],
    select_groups: Callable[[list[dict]], list[list[dict]]],
    map_only: bool = False,
) -> NetworkEvidenceSnapshot:
    """Capture the exact dependencies and the group context built from that snapshot."""
    try:
        database = stable_path_identity(db_path)
    except OSError as exc:
        return NetworkEvidenceSnapshot(None, [], str(exc))

    scan_rows = None
    manifest_index = None
    if map_only:
        groups: list[list[dict]] = []
    else:
        try:
            with connect_database(db_path, read_only=True) as db:
                db.execute("BEGIN")
                scan_rows = _table_rows(
                    db, "scan_runs", order_by="created_at DESC, rowid DESC", limit=5000
                )
                scan_columns = scan_rows["columns"]
                manifest_index = scan_columns.index("manifest_json")
                raw_manifests = [
                    json.loads(row[manifest_index]) for row in scan_rows["rows"]
                ]
                queued_ids = [
                    str(row[0])
                    for row in db.execute(
                        "SELECT run_id FROM scan_runs WHERE status = 'queued' ORDER BY rowid"
                    ).fetchall()
                ]
        except (sqlite3.Error, ValueError, json.JSONDecodeError) as exc:
            return NetworkEvidenceSnapshot(
                None, [], f"Scan selection cannot be fingerprinted: {exc}"
            )

        manifests = prepare_manifests(raw_manifests, queued_ids)
        groups = select_groups(manifests)
    selected_ids = {
        str(manifest.get("run_id"))
        for group in groups
        for manifest in group
        if manifest.get("run_id")
    }
    try:
        with connect_database(db_path, read_only=True) as db:
            db.execute("BEGIN")
            topology_scan_rows = select_map_scan_rows(db)
        topology_manifest_index = topology_scan_rows["columns"].index("manifest_json")
        topology_manifests = [
            json.loads(row[topology_manifest_index])
            for row in topology_scan_rows["rows"]
        ]
    except (sqlite3.Error, ValueError, json.JSONDecodeError) as exc:
        return NetworkEvidenceSnapshot(
            None, groups, f"Map scan selection cannot be fingerprinted: {exc}"
        )
    topology_ids = {
        str(manifest.get("run_id")) for manifest in topology_manifests
        if manifest.get("run_id")
    }
    relevant_run_ids = selected_ids | topology_ids

    try:
        with connect_database(db_path, read_only=True) as db:
            db.execute("BEGIN")
            artifact_rows = _scan_artifact_rows(db, relevant_run_ids)
            imports = select_map_import_rows(db)
            mutable = {
                "host_identities": _table_rows(
                    db, "analyst_host_identities", order_by="length(ip), ip"
                ),
                "os_overrides": _table_rows(
                    db, "host_os_overrides", order_by="identity_key"
                ),
                "os_reviews": _table_rows(
                    db, "host_os_inference_reviews", order_by="identity_key"
                ),
                "saved_networks": _table_rows(
                    db, "saved_networks", where="active = 1", order_by="saved_network_id"
                ),
            }
    except sqlite3.Error as exc:
        return NetworkEvidenceSnapshot(None, groups, f"Mutable context cannot be fingerprinted: {exc}")

    artifact_by_run: dict[str, list[list]] = {}
    canonical_by_digest: dict[str, dict] = {}
    for row in artifact_rows:
        artifact_by_run.setdefault(str(row[2]), []).append(row)
        digest, size_bytes, canonical_path = str(row[1]), int(row[4]), Path(row[5])
        if digest in canonical_by_digest:
            continue
        try:
            identity = stable_file_identity(canonical_path)
        except OSError as exc:
            return NetworkEvidenceSnapshot(None, groups, str(exc))
        if identity["sha256"] != digest or identity["size"] != size_bytes:
            return NetworkEvidenceSnapshot(
                None, groups, f"Canonical Nmap artifact does not match registry: {digest}"
            )
        canonical_by_digest[digest] = identity

    nmap_inputs: list[dict] = []
    for run_id in sorted(relevant_run_ids):
        rows = artifact_by_run.get(run_id, [])
        if len(rows) > 1:
            return NetworkEvidenceSnapshot(
                None, groups, f"Scan {run_id} has ambiguous registered XML"
            )
        path = run_directory(run_id) / "scan.xml"
        if not path.is_file():
            nmap_inputs.append({"run_id": run_id, "present": False, "registry": rows})
            continue
        try:
            local = stable_file_identity(path)
        except OSError as exc:
            return NetworkEvidenceSnapshot(None, groups, str(exc))
        if rows and (local["sha256"], local["size"]) != (str(rows[0][1]), int(rows[0][4])):
            return NetworkEvidenceSnapshot(
                None, groups, f"Run-local Nmap XML does not match registry: {run_id}"
            )
        nmap_inputs.append({
            "run_id": run_id,
            "present": True,
            "local": local,
            "registry": rows,
        })

    configuration_inputs, config_error = _configuration_inputs(config_dir)
    if config_error:
        return NetworkEvidenceSnapshot(None, groups, config_error)

    oui_identities: list[dict] = []
    for path in oui_search_paths():
        if not path.is_file():
            continue
        try:
            oui_identities.append(stable_file_identity(path))
        except OSError as exc:
            return NetworkEvidenceSnapshot(None, groups, str(exc))
    oui_identity = {
        "available": bool(oui_identities),
        "paths": oui_identities,
    }

    contract = {
        "network_model": NETWORK_MODEL_CONTRACT_VERSION,
        "nmap_base": {
            "family": NMAP_BASE_ANALYSIS_FAMILY,
            "version": NMAP_BASE_ANALYSIS_VERSION,
            "schema": NMAP_BASE_PAYLOAD_SCHEMA_VERSION,
            "parameters": dict(NMAP_BASE_PARAMETERS),
        },
        "nmap_topology": {
            "family": NMAP_TOPOLOGY_FAMILY,
            "version": NMAP_TOPOLOGY_VERSION,
            "schema": NMAP_TOPOLOGY_PAYLOAD_SCHEMA_VERSION,
            "parameters": dict(NMAP_TOPOLOGY_PARAMETERS),
        },
    }
    descriptor = {
        "contract": contract,
        "database": {
            "path": database["path"],
            "device": database["device"],
            "inode": database["inode"],
        },
        "scan_rows": None if scan_rows is None else {
            "columns": scan_rows["columns"],
            "rows": [
                [*row[:manifest_index], _digest_json(row[manifest_index]), *row[manifest_index + 1:]]
                for row in scan_rows["rows"]
            ],
        },
        "selected_groups": [
            [str(manifest.get("run_id") or "") for manifest in group]
            for group in groups
        ],
        "topology_scan_rows": topology_scan_rows,
        "nmap_inputs": nmap_inputs,
        "imports": {
            "columns": imports["columns"],
            "rows": [
                [
                    _digest_json(value) if imports["columns"][index] == "analysis_json" else value
                    for index, value in enumerate(row)
                ]
                for row in imports["rows"]
            ],
        },
        "configuration_inputs": configuration_inputs,
        "mutable_context": mutable,
        "oui": oui_identity,
    }
    context = {"groups": groups, "oui": oui_identity}
    return NetworkEvidenceSnapshot(_digest_json(descriptor), context)
