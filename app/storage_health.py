"""Explicit storage inventory and non-destructive, restart-safe registry backfill.

Evidence is never deleted or rewritten here. Reports are snapshots, not permission
to compact. Only known finalized source files are candidates for deduplication.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import sqlite3
import stat
import threading
import uuid

from app.artifacts import (artifact_root_for, canonical_artifact_path,
                           register_artifact_file, sha256_file, utc_now)
from app.database import connect_database

_LOCK = threading.Lock()
_ACTIVE: set[str] = set()
TERMINAL = {"completed", "completed_without_nmap", "failed", "cancelled", "interrupted", "uploaded"}


def _read_db(db_path: Path):
    return connect_database(db_path, read_only=True)


def _safe_file(path: Path, root: Path) -> bool:
    try:
        relative = path.absolute().relative_to(root.absolute())
        current = root
        for part in relative.parts:
            current = current / part
            if current.is_symlink():
                return False
        return stat.S_ISREG(path.stat().st_mode)
    except (OSError, ValueError):
        return False


def _fingerprint(path: Path) -> list[int]:
    value = path.stat()
    return [value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns]


def evidence_references(db_path: Path) -> tuple[list[dict], list[str], int]:
    # Import lazily to avoid changing the existing collection module dependency graph.
    from app.poc import ARTIFACT_FILES
    from app.device_configs import ARTIFACT_NAMES, UPLOADED_ARTIFACT_RE, COLLECTION_ARTIFACT_RE

    root = db_path.parent
    references, issues = [], []
    active = 0
    scan_manifests = {}
    imports = []
    if db_path.exists():
        db = _read_db(db_path)
        try:
            tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if "scan_runs" in tables:
                for run_id, manifest_json in db.execute("SELECT run_id, manifest_json FROM scan_runs"):
                    try:
                        stored = json.loads(manifest_json)
                        if not isinstance(stored, dict):
                            raise ValueError("invalid manifest")
                        scan_manifests[run_id] = stored
                    except (ValueError, TypeError):
                        issues.append(f"Unreadable scan history: {run_id}")
            if "imports" in tables:
                imports = db.execute("SELECT sha256, filename, stored_path, imported_at FROM imports").fetchall()
        finally:
            db.close()
    for folder, kind in (("scan-runs", "nmap_scan"), ("device-configs", "device_collection")):
        base = root / folder
        directories = {p.name: p for p in base.iterdir()} if base.is_dir() and not base.is_symlink() else {}
        if kind == "nmap_scan":
            directories.update({key: base / key for key in scan_manifests})
        for run_id, directory in sorted(directories.items()):
            if directory.is_symlink() or directory.parent != base or not directory.is_dir():
                issues.append(f"Missing or unsafe collection directory: {folder}/{run_id}")
                continue
            try:
                manifest_path = directory / "manifest.json"
                if not _safe_file(manifest_path, root):
                    raise ValueError("missing manifest")
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                if not isinstance(manifest, dict):
                    raise ValueError("invalid manifest")
            except (OSError, ValueError):
                issues.append(f"Unreadable manifest: {folder}/{run_id}")
                continue
            stored = scan_manifests.get(run_id, manifest)
            if manifest.get("status") not in TERMINAL or stored.get("status") not in TERMINAL:
                active += 1
                continue
            if kind == "nmap_scan":
                names = {v[0] for v in ARTIFACT_FILES.values()} - {"manifest.json"}
                expected = {v.get("filename") for v in stored.get("artifacts", []) if isinstance(v, dict)} - {None, "manifest.json"}
                if stored.get("status") == "completed":
                    expected.add("scan.xml")
            else:
                names = set(ARTIFACT_NAMES) - {"manifest.json"}
                names.update(p.name for p in directory.iterdir()
                             if UPLOADED_ARTIFACT_RE.fullmatch(p.name) or COLLECTION_ARTIFACT_RE.fullmatch(p.name))
                expected = {manifest.get("local_output_name")} - {None, ""}
            registered = {item["filename"]: item["sha256"]
                          for item in manifest.get("artifact_registry", {}).get("files", [])}
            expected.update(registered)
            for filename in sorted(names | expected):
                path = directory / filename
                if filename not in names or not _safe_file(path, root):
                    if filename in expected or path.is_symlink():
                        issues.append(f"Missing or unsafe evidence: {folder}/{run_id}/{filename}")
                    continue
                references.append({"path": path, "kind": kind, "ref": run_id,
                                   "filename": filename, "actor": manifest.get("owner") or manifest.get("operator"),
                                   "observed_at": manifest.get("completed_at") or manifest.get("created_at"),
                                   **({"expected_hash": registered[filename]} if filename in registered else {})})
    for digest, filename, stored_path, imported_at in imports:
        path = Path(stored_path)
        if not _safe_file(path, root):
            issues.append(f"Missing or unsafe imported evidence: {digest}")
            continue
        references.append({"path": path, "kind": "nmap_import", "ref": digest,
                           "filename": filename, "observed_at": imported_at, "expected_hash": digest})
    return references, issues, active


def analyze_storage(db_path: Path) -> dict:
    """Read-only inventory, including no schema initialization or cache writes."""
    root = db_path.parent
    references, issues, active = evidence_references(db_path)
    used = logical = files = 0
    seen = set()
    categories = {}
    for directory, dirs, names in os.walk(root, followlinks=False, onerror=lambda _: issues.append("Unreadable storage directory")):
        if any((Path(directory) / name).is_symlink() for name in dirs):
            issues.append("Skipped unsafe storage directory")
        dirs[:] = [name for name in dirs if not (Path(directory) / name).is_symlink()]
        for name in names:
            path = Path(directory) / name
            if not _safe_file(path, root):
                issues.append("Skipped unsafe storage entry")
                continue
            try:
                st = path.stat()
                identity = (st.st_dev, st.st_ino)
                files += 1
                logical += st.st_size
                if identity not in seen:
                    seen.add(identity)
                    used += st.st_size
                    category = path.relative_to(root).parts[0]
                    categories[category] = categories.get(category, 0) + st.st_size
            except OSError:
                issues.append("Storage entry changed during inventory")
    registry = []
    observations = 0
    if db_path.exists():
        db = _read_db(db_path)
        try:
            tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if "artifact_registry" in tables:
                registry = db.execute("SELECT sha256, size_bytes, canonical_path FROM artifact_registry").fetchall()
                observations = db.execute("SELECT COUNT(*) FROM artifact_observations").fetchone()[0]
        finally:
            db.close()
    hashes, groups = {}, {}

    def inspect(path):
        key = str(path)
        if key not in hashes:
            before = _fingerprint(path)
            digest, size = sha256_file(path)
            if _fingerprint(path) != before:
                raise ValueError("Evidence changed during inspection")
            hashes[key] = (digest, size, tuple(before[:2]))
        return hashes[key]

    verified = set()
    for digest, size, name in registry:
        path = Path(name)
        try:
            if path != canonical_artifact_path(artifact_root_for(db_path), digest) or not _safe_file(path, root):
                raise ValueError("Unsafe canonical path")
            actual, actual_size, identity = inspect(path)
            if (actual, actual_size) != (digest, size):
                raise ValueError("Canonical content mismatch")
            verified.add(digest)
            groups.setdefault(digest, {})[identity] = size
        except (OSError, ValueError):
            issues.append(f"Canonical verification failed: {digest}")
    valid_refs = 0
    for ref in references:
        try:
            digest, size, identity = inspect(ref["path"])
            if ref.get("expected_hash", digest) != digest:
                raise ValueError("Import hash mismatch")
            groups.setdefault(digest, {})[identity] = size
            valid_refs += 1
        except (OSError, ValueError):
            issues.append(f"Evidence verification failed: {ref['kind']}/{ref['ref']}/{ref['filename']}")
    duplicate_bytes = sum(sum(copies.values()) - max(copies.values()) for copies in groups.values())
    candidate_bytes = sum(sum(copies.values()) - max(copies.values()) for digest, copies in groups.items() if digest in verified)
    return {"generated_at": utc_now(), "used_bytes": used, "logical_bytes": logical,
            "measurement": "File lengths counted once per physical file; filesystem overhead and compression excluded.",
            "files_inspected": files, "categories": categories,
            "unique_artifact_count": len(groups), "unique_artifact_bytes": sum(max(c.values()) for c in groups.values()),
            "registered_artifact_count": len(registry), "observation_count": observations,
            "duplicate_file_count": sum(len(c) - 1 for c in groups.values()),
            "duplicate_bytes": duplicate_bytes, "reclaimable_bytes": candidate_bytes if not issues and not active else 0,
            "verified_references": valid_refs, "active_collections_skipped": active,
            "issues": issues[:100], "issue_count": len(issues),
            "compaction": {"enabled": False, "status": "blocked" if issues or active else "dry_run_only",
                           "detail": "No files removed. Compaction execution is not enabled; backup, reference recheck and rollback gates remain required."},
            "passive_telemetry": {"status": "not_implemented", "bytes": None},
            "pinned_evidence": {"status": "not_implemented", "bytes": None},
            "retention": "Automatic artifact pruning is disabled. All evidence is retained."}


def backfill_storage(db_path: Path) -> dict:
    references, issues, active = evidence_references(db_path)
    with connect_database(db_path) as db:
        db.execute("CREATE TABLE IF NOT EXISTS artifact_backfill (source_key TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, sha256 TEXT NOT NULL)")
    completed = skipped = 0
    for ref in references:
        path = ref["path"]
        key = f"{ref['kind']}:{ref['ref']}:{path.name}"
        try:
            fingerprint = json.dumps(_fingerprint(path))
            with connect_database(db_path) as db:
                checkpoint = db.execute("SELECT fingerprint, sha256 FROM artifact_backfill WHERE source_key=?", (key,)).fetchone()
            canonical = canonical_artifact_path(artifact_root_for(db_path), checkpoint[1]) if checkpoint else None
            if checkpoint and checkpoint[0] == fingerprint and _safe_file(canonical, db_path.parent) and sha256_file(canonical)[0] == checkpoint[1]:
                skipped += 1
                continue
            if ref.get("expected_hash") and sha256_file(path)[0] != ref["expected_hash"]:
                raise ValueError("Import content does not match its retained hash")
            record = register_artifact_file(
                db_path=db_path, source_path=path, source_kind=ref["kind"], source_ref=ref["ref"],
                original_filename=ref["filename"], actor=ref.get("actor"), observed_at=ref.get("observed_at"),
                observation_key=key, metadata={"relative_path": str(path.relative_to(db_path.parent)), "backfill": True})
            if ref.get("expected_hash", record["sha256"]) != record["sha256"]:
                raise ValueError("Import content does not match its retained hash")
            if json.dumps(_fingerprint(path)) != fingerprint:
                raise ValueError("Evidence changed during backfill")
            with connect_database(db_path) as db:
                db.execute("INSERT OR REPLACE INTO artifact_backfill VALUES (?, ?, ?)", (key, fingerprint, record["sha256"]))
            completed += 1
        except (OSError, ValueError, sqlite3.Error):
            issues.append(f"Backfill failed: {ref['kind']}/{ref['ref']}/{ref['filename']}")
    return {"completed": completed, "resumed_unchanged": skipped, "issues": issues[:100],
            "issue_count": len(issues), "active_collections_skipped": active,
            "evidence_removed": 0}


def _status_path(db_path):
    return db_path.parent / "storage-health.json"


def _save_status(db_path, value):
    path = _status_path(db_path)
    temporary = path.with_suffix(f".{uuid.uuid4().hex}.tmp")
    try:
        temporary.write_text(json.dumps(value), encoding="utf-8")
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def storage_status(db_path: Path) -> dict:
    try:
        value = json.loads(_status_path(db_path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"status": "not_run", "report": None}
    if value.get("status") == "running" and str(db_path) not in _ACTIVE:
        value["status"] = "interrupted"
    return value


def start_storage_job(db_path: Path, mode: str) -> dict:
    if mode not in {"dry-run", "backfill"}:
        raise ValueError("Unknown storage operation")
    with _LOCK:
        if str(db_path) in _ACTIVE:
            raise ValueError("A storage operation is already running")
        previous = storage_status(db_path)
        value = {"status": "running", "mode": mode, "started_at": utc_now(), "report": previous.get("report")}
        _save_status(db_path, value)
        _ACTIVE.add(str(db_path))

    def work():
        try:
            if mode == "backfill":
                value["backfill"] = backfill_storage(db_path)
            value["report"] = analyze_storage(db_path)
            value["status"] = "complete"
        except Exception:
            value["status"] = "failed"
            value["error"] = "Storage inspection failed. Retained evidence has not been removed; retry after checking storage access."
        finally:
            value["finished_at"] = utc_now()
            try:
                _save_status(db_path, value)
            finally:
                with _LOCK:
                    _ACTIVE.discard(str(db_path))
    threading.Thread(target=work, daemon=True, name="storage-health").start()
    return value.copy()
