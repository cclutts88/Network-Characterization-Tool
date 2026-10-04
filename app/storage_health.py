"""Storage inventory, registry backfill, and confirmed exact-content compaction."""
from __future__ import annotations

import json
import hashlib
import os
import re
from pathlib import Path
import sqlite3
import stat
import shutil
import threading
import uuid

from app.artifacts import (artifact_root_for, canonical_artifact_path,
                           register_artifact_file, sha256_file, utc_now)
from app.database import connect_database
from app.evidence_maintenance import (
    EvidenceMaintenanceBlocked,
    clear_recovery_required,
    evidence_maintenance,
    evidence_mutation,
    guarded_evidence_mutation,
    mark_recovery_required,
    recovery_required,
    recovery_root,
)

_LOCK = threading.Lock()
_ACTIVE: set[str] = set()
TERMINAL = {"completed", "completed_without_nmap", "failed", "cancelled", "interrupted", "uploaded", "timed_out"}
COMPACTION_CONFIRMATION = "REMOVE VERIFIED DUPLICATE COPIES"
MIN_COMPACTION_FREE_BYTES = 1024 * 1024


def _read_db(db_path: Path):
    return connect_database(db_path, read_only=True)


def _safe_file(path: Path, root: Path) -> bool:
    try:
        relative = path.absolute().relative_to(root.absolute())
        if ".." in relative.parts or root.is_symlink():
            return False
        path.resolve().relative_to(root.resolve())
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
    observations = []
    import_observations = []
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
            if "artifact_observations" in tables:
                observations = db.execute("SELECT source_kind, source_ref, original_filename, sha256, observation_id, metadata_json FROM artifact_observations").fetchall()
                import_observations = db.execute("SELECT sha256, observed_at, observation_id FROM artifact_observations WHERE source_kind='nmap_import'").fetchall()
        finally:
            db.close()
    for folder, kind in (("scan-runs", "nmap_scan"), ("device-configs", "device_collection")):
        base = root / folder
        directories = {p.name: p for p in base.iterdir()} if base.is_dir() and not base.is_symlink() else {}
        if kind == "nmap_scan":
            directories.update({key: base / key for key in scan_manifests})
        source_kinds = {kind, "device_config_upload"} if kind == "device_collection" else {kind}
        for obs in observations:
            if obs[0] in source_kinds:
                directories.setdefault(obs[1], base / obs[1])
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
            manual = kind == "device_collection" and manifest.get("operation") == "manual_upload"
            upload_name = None
            if manual:
                original = manifest.get("source_filename") or "configuration-result.txt"
                safe = re.sub(r"[^A-Za-z0-9_.-]+", "-", original.strip()).strip(".-")[:80] or "configuration-result.txt"
                upload_name = manifest.get("retained_filename") or f"uploaded-{safe}"
                names.add(upload_name)
                expected.add(upload_name)
                if manifest.get("artifact_sha256"):
                    registered[upload_name] = manifest["artifact_sha256"]
            existing_observations = {}
            for obs_kind, obs_ref, obs_name, digest, obs_id, raw_metadata in observations:
                if obs_kind not in source_kinds or obs_ref != run_id:
                    continue
                try:
                    metadata = json.loads(raw_metadata)
                    relative_path = metadata.get("relative_path")
                    filename = upload_name if obs_kind == "device_config_upload" else obs_name
                    if relative_path:
                        observed_path = root / relative_path
                        if observed_path.parent != directory:
                            raise ValueError("Observation outside collection")
                        filename = observed_path.name
                    if not filename:
                        raise ValueError("Missing observation filename")
                    if filename in registered and registered[filename] != digest:
                        raise ValueError("Conflicting retained hashes")
                    registered[filename] = digest
                    expected.add(filename)
                    if obs_kind == ("device_config_upload" if manual and filename == upload_name else kind):
                        existing_observations[filename] = obs_id
                except (ValueError, TypeError, AttributeError):
                    issues.append(f"Unresolved observation: {obs_id}")
            expected.update(registered)
            for filename in sorted(names | expected):
                path = directory / filename
                if filename not in names or not _safe_file(path, root):
                    if filename in expected or path.is_symlink():
                        issues.append(f"Missing or unsafe evidence: {folder}/{run_id}/{filename}")
                    continue
                references.append({"path": path, "kind": "device_config_upload" if manual and filename == upload_name else kind, "ref": run_id,
                                   "filename": manifest.get("source_filename", filename) if manual and filename == upload_name else filename,
                                   "existing_observation": existing_observations.get(filename),
                                   "actor": manifest.get("owner") or manifest.get("operator"),
                                   "observed_at": manifest.get("completed_at") or manifest.get("created_at"),
                                   **({"expected_hash": registered[filename]} if filename in registered else {})})
    for digest, filename, stored_path, imported_at in imports:
        path = Path(stored_path)
        if not _safe_file(path, root):
            issues.append(f"Missing or unsafe imported evidence: {digest}")
            continue
        references.append({"path": path, "kind": "nmap_import", "ref": digest,
                           "existing_observation": next((o[2] for o in import_observations if o[0] == digest and o[1] == imported_at), None),
                           "filename": filename, "observed_at": imported_at, "expected_hash": digest})
    return references, issues, active


def _security_metadata(path: Path) -> dict | None:
    """Return metadata that will become shared by a hard link, or None if unsupported."""
    if os.name != "posix" or not hasattr(os, "listxattr"):
        return None
    try:
        value = path.stat()
        attributes = {
            name: os.getxattr(path, name).hex()
            for name in sorted(os.listxattr(path))
        }
        return {
            "mode": stat.S_IMODE(value.st_mode),
            "uid": value.st_uid,
            "gid": value.st_gid,
            "xattrs": attributes,
        }
    except (OSError, ValueError):
        return None


def _plan_fingerprint(path: Path) -> dict:
    value = path.stat()
    security = _security_metadata(path)
    if security is None:
        raise ValueError("Security metadata cannot be compared on this filesystem")
    return {
        "device": value.st_dev,
        "inode": value.st_ino,
        "size": value.st_size,
        "mtime_ns": value.st_mtime_ns,
        "security": security,
    }


def _plan_id(candidates: list[dict]) -> str:
    frozen = []
    for item in candidates:
        value = {key: item[key] for key in (
            "source_path", "canonical_path", "sha256", "size_bytes",
            "source_fingerprint", "canonical_fingerprint",
        )}
        value["references"] = sorted(
            item["references"], key=lambda ref: json.dumps(ref, sort_keys=True)
        )
        frozen.append(value)
    payload = json.dumps(frozen, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest()


def _fsync_path(path: Path) -> None:
    try:
        descriptor = os.open(path, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError:
        if os.name == "posix":
            raise


def _fsync_journal(db_path: Path) -> None:
    for path in (db_path, Path(str(db_path) + "-wal")):
        if path.is_file():
            _fsync_path(path)


def _init_compaction_journal(db_path: Path) -> None:
    with connect_database(db_path) as db:
        db.execute("PRAGMA synchronous=FULL")
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS artifact_compaction_journal (
                compaction_id TEXT NOT NULL,
                item_id TEXT PRIMARY KEY,
                source_path TEXT NOT NULL,
                canonical_path TEXT NOT NULL,
                recovery_path TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                size_bytes INTEGER NOT NULL,
                source_fingerprint_json TEXT NOT NULL,
                canonical_fingerprint_json TEXT NOT NULL,
                state TEXT NOT NULL,
                detail TEXT,
                updated_at TEXT NOT NULL
            )
            """
        )
    _fsync_journal(db_path)


def _journal_item(db_path: Path, item: dict, state: str, detail: str | None = None) -> None:
    with connect_database(db_path) as db:
        db.execute("PRAGMA synchronous=FULL")
        db.execute(
            """
            INSERT INTO artifact_compaction_journal (
                compaction_id, item_id, source_path, canonical_path, recovery_path,
                sha256, size_bytes, source_fingerprint_json,
                canonical_fingerprint_json, state, detail, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(item_id) DO UPDATE SET
                state=excluded.state, detail=excluded.detail,
                updated_at=excluded.updated_at
            """,
            (
                item["compaction_id"], item["item_id"], item["source_path"],
                item["canonical_path"], item["recovery_path"], item["sha256"],
                item["size_bytes"], json.dumps(item["source_fingerprint"], sort_keys=True),
                json.dumps(item["canonical_fingerprint"], sort_keys=True), state,
                detail, utc_now(),
            ),
        )
    _fsync_journal(db_path)


def _analyze_storage(db_path: Path) -> dict:
    """Read-only inventory, including no schema initialization or cache writes."""
    root = db_path.parent
    references, issues, active = evidence_references(db_path)
    if recovery_required(db_path):
        issues.append("Interrupted compaction recovery requires administrator repair")
    used = logical = files = 0
    seen = set()
    categories = {}
    for directory, dirs, names in os.walk(root, followlinks=False, onerror=lambda _: issues.append("Unreadable storage directory")):
        if Path(directory) == root:
            dirs[:] = [name for name in dirs if name != recovery_root(db_path).name]
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
    verified_registry = {}
    for digest, size, name in registry:
        path = Path(name)
        try:
            if path != canonical_artifact_path(artifact_root_for(db_path), digest) or not _safe_file(path, root):
                raise ValueError("Unsafe canonical path")
            actual, actual_size, identity = inspect(path)
            if (actual, actual_size) != (digest, size):
                raise ValueError("Canonical content mismatch")
            verified.add(digest)
            verified_registry[digest] = {
                "path": path,
                "identity": identity,
                "fingerprint": _plan_fingerprint(path),
            }
            groups.setdefault(digest, {})[identity] = size
        except (OSError, ValueError):
            issues.append(f"Canonical verification failed: {digest}")
    valid_refs = 0
    candidates_by_path = {}
    skipped = []
    for ref in references:
        try:
            digest, size, identity = inspect(ref["path"])
            if ref.get("expected_hash", digest) != digest:
                raise ValueError("Import hash mismatch")
            groups.setdefault(digest, {})[identity] = size
            valid_refs += 1
            canonical = verified_registry.get(digest)
            if canonical is not None and identity != canonical["identity"]:
                source = ref["path"]
                reason = None
                source_stat = source.stat()
                try:
                    source_fingerprint = _plan_fingerprint(source)
                except ValueError:
                    source_fingerprint = None
                    reason = "security_metadata_unsupported"
                if reason is None and source_stat.st_nlink != 1:
                    reason = "unexplained_existing_hard_links"
                if reason is None and source_stat.st_dev != canonical["path"].stat().st_dev:
                    reason = "different_filesystem"
                if (
                    reason is None
                    and source_fingerprint["security"]
                    != canonical["fingerprint"]["security"]
                ):
                    reason = "security_metadata_mismatch"
                relative_source = str(source.relative_to(root))
                if reason:
                    skipped.append({
                        "source_path": relative_source,
                        "sha256": digest,
                        "size_bytes": size,
                        "reason": reason,
                    })
                else:
                    candidate = candidates_by_path.setdefault(relative_source, {
                        "source_path": relative_source,
                        "canonical_path": str(canonical["path"].relative_to(root)),
                        "sha256": digest,
                        "size_bytes": size,
                        "source_fingerprint": source_fingerprint,
                        "canonical_fingerprint": canonical["fingerprint"],
                        "references": [],
                    })
                    reference = {
                        "kind": ref["kind"],
                        "ref": ref["ref"],
                        "filename": ref["filename"],
                        "observation": ref.get("existing_observation"),
                        "expected_hash": ref.get("expected_hash"),
                    }
                    if reference not in candidate["references"]:
                        candidate["references"].append(reference)
        except (OSError, ValueError):
            issues.append(f"Evidence verification failed: {ref['kind']}/{ref['ref']}/{ref['filename']}")
    candidates = sorted(candidates_by_path.values(), key=lambda item: item["source_path"])
    duplicate_bytes = sum(sum(copies.values()) - max(copies.values()) for copies in groups.values())
    candidate_bytes = sum(item["size_bytes"] for item in candidates)
    ready = not issues and not active and bool(candidates)
    status = "blocked" if issues or active else "ready" if candidates else "nothing_to_compact"
    return {"generated_at": utc_now(), "used_bytes": used, "logical_bytes": logical,
            "measurement": "File lengths counted once per physical file; filesystem overhead and compression excluded.",
            "files_inspected": files, "categories": categories,
            "unique_artifact_count": len(groups), "unique_artifact_bytes": sum(max(c.values()) for c in groups.values()),
            "registered_artifact_count": len(registry), "observation_count": observations,
            "duplicate_file_count": sum(len(c) - 1 for c in groups.values()),
            "duplicate_bytes": duplicate_bytes, "reclaimable_bytes": candidate_bytes if not issues and not active else 0,
            "verified_references": valid_refs, "active_collections_skipped": active,
            "issues": issues[:100], "issue_count": len(issues),
            "compaction": {
                "enabled": ready,
                "status": status,
                "plan_id": _plan_id(candidates) if ready else None,
                "eligible_file_count": len(candidates) if not issues and not active else 0,
                "estimated_file_length_savings": candidate_bytes if not issues and not active else 0,
                "eligible_files": candidates[:100] if not issues and not active else [],
                "eligible_files_truncated": max(0, len(candidates) - 100) if not issues and not active else 0,
                "skipped_files": skipped[:100],
                "skipped_files_truncated": max(0, len(skipped) - 100),
                "detail": (
                    "Fresh verification passed. Only the listed byte-for-byte exact copies are eligible."
                    if ready else
                    "Compaction is blocked until every reference and canonical file verifies and no collection is active."
                    if status == "blocked" else
                    "No separate verified duplicate copies are eligible for compaction."
                ),
            },
            "_compaction_candidates": candidates,
            "passive_telemetry": {"status": "not_implemented", "bytes": None},
            "pinned_evidence": {"status": "not_implemented", "bytes": None},
            "retention": "Automatic artifact pruning is disabled. All evidence is retained."}


def analyze_storage(db_path: Path) -> dict:
    report = _analyze_storage(db_path)
    report.pop("_compaction_candidates", None)
    return report


def _journal_rows(db_path: Path) -> list[dict]:
    if not db_path.is_file():
        return []
    with _read_db(db_path) as db:
        tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if "artifact_compaction_journal" not in tables:
            return []
        rows = db.execute(
            """
            SELECT compaction_id, item_id, source_path, canonical_path,
                   recovery_path, sha256, size_bytes, source_fingerprint_json,
                   canonical_fingerprint_json, state, detail
            FROM artifact_compaction_journal
            WHERE state IN ('preparing','prepared','replaced','verified','recovery-required')
            ORDER BY updated_at, item_id
            """
        ).fetchall()
    keys = (
        "compaction_id", "item_id", "source_path", "canonical_path",
        "recovery_path", "sha256", "size_bytes", "source_fingerprint_json",
        "canonical_fingerprint_json", "state", "detail",
    )
    return [dict(zip(keys, row)) for row in rows]


def _validated_recovery_paths(db_path: Path, row: dict) -> tuple[Path, Path, Path]:
    root = db_path.parent.absolute()
    if root.is_symlink():
        raise ValueError("Evidence storage root cannot be a symbolic link")
    source = Path(row["source_path"]).absolute()
    canonical = Path(row["canonical_path"]).absolute()
    recovery = Path(row["recovery_path"]).absolute()
    source_relative = source.relative_to(root)
    if not source_relative.parts or source_relative.parts[0] not in {
        "scan-runs", "device-configs", "imports",
    }:
        raise ValueError("Compaction source is outside a recognized evidence area")
    expected_canonical = canonical_artifact_path(
        artifact_root_for(db_path), row["sha256"]
    ).absolute()
    if canonical != expected_canonical:
        raise ValueError("Compaction canonical path does not match its content identity")
    expected_recovery = (
        recovery_root(db_path) / row["compaction_id"] / f"{row['item_id']}.recovery"
    ).absolute()
    if recovery != expected_recovery:
        raise ValueError("Compaction recovery path does not match its journal owner")
    for path, allowed_root in (
        (source, root),
        (canonical, root),
        (recovery, recovery_root(db_path).absolute()),
    ):
        relative = path.relative_to(allowed_root)
        current = allowed_root
        for part in relative.parts:
            current = current / part
            if current.is_symlink():
                raise ValueError("Compaction journal path contains a symbolic link")
    if source == canonical or recovery in {source, canonical}:
        raise ValueError("Compaction journal paths conflict")
    return source, canonical, recovery


def _validate_recovery_original(item: dict, recovery: Path) -> None:
    if _plan_fingerprint(recovery) != item["source_fingerprint"]:
        raise ValueError("Recovery link no longer matches the prepared original")
    if sha256_file(recovery) != (item["sha256"], item["size_bytes"]):
        raise ValueError("Recovery link content no longer matches the prepared original")


def recover_incomplete_compactions(db_path: Path) -> dict:
    """Restore an original inode after an interrupted replacement, or block mutations."""
    rows = _journal_rows(db_path)
    recovery_directory = recovery_root(db_path)
    if not rows:
        stray = list(recovery_directory.glob("**/*.recovery")) if recovery_directory.exists() else []
        if stray:
            mark_recovery_required(db_path, "Unjournaled compaction recovery files require review")
            return {"resolved": 0, "recovery_required": len(stray)}
        clear_recovery_required(db_path)
        return {"resolved": 0, "recovery_required": 0}
    mark_recovery_required(db_path, "Interrupted exact-content compaction is being recovered")
    resolved = 0
    for row in rows:
        item = {
            **row,
            "source_fingerprint": json.loads(row["source_fingerprint_json"]),
            "canonical_fingerprint": json.loads(row["canonical_fingerprint_json"]),
        }
        try:
            source, canonical, recovery = _validated_recovery_paths(db_path, row)
            recovery_exists = _safe_file(recovery, recovery_root(db_path))
            source_exists = _safe_file(source, db_path.parent)
            if row["state"] == "preparing" and not recovery_exists:
                if not source_exists or _plan_fingerprint(source) != item["source_fingerprint"]:
                    raise ValueError("Preparing item no longer has its original source")
                if sha256_file(source) != (row["sha256"], row["size_bytes"]):
                    raise ValueError("Preparing item original failed content verification")
                _journal_item(db_path, item, "restored", "No replacement had occurred")
                resolved += 1
                continue
            if row["state"] == "verified":
                if not source_exists or not _safe_file(canonical, db_path.parent):
                    raise ValueError("Verified replacement is unavailable during cleanup")
                source_stat, canonical_stat = source.stat(), canonical.stat()
                if (source_stat.st_dev, source_stat.st_ino) != (
                    canonical_stat.st_dev, canonical_stat.st_ino,
                ):
                    raise ValueError("Verified retained path no longer names canonical content")
                if sha256_file(source) != (row["sha256"], row["size_bytes"]):
                    if not recovery_exists:
                        raise ValueError(
                            "Verified retained content changed and its original recovery link is unavailable"
                        )
                    _validate_recovery_original(item, recovery)
                    os.replace(recovery, source)
                    _fsync_path(source.parent)
                    if _plan_fingerprint(source) != item["source_fingerprint"]:
                        raise ValueError("Restored original failed verification")
                    _journal_item(
                        db_path, item, "restored",
                        "Original inode restored because verified retained content changed",
                    )
                    resolved += 1
                    continue
                if recovery_exists:
                    _validate_recovery_original(item, recovery)
                    recovery.unlink()
                    _fsync_path(recovery.parent)
                _journal_item(db_path, item, "completed", "Verified recovery link cleanup completed")
                resolved += 1
                continue
            if not recovery_exists or not source_exists or not _safe_file(canonical, db_path.parent):
                raise ValueError("Recovery source, retained path, or canonical file is unavailable")
            _validate_recovery_original(item, recovery)
            recovery_stat = recovery.stat()
            source_stat = source.stat()
            canonical_stat = canonical.stat()
            original_inode = item["source_fingerprint"]["inode"]
            if (recovery_stat.st_dev, recovery_stat.st_ino) != (
                item["source_fingerprint"]["device"], original_inode,
            ):
                raise ValueError("Recovery link no longer names the original inode")
            source_is_original = (source_stat.st_dev, source_stat.st_ino) == (
                recovery_stat.st_dev, recovery_stat.st_ino,
            )
            source_is_canonical = (source_stat.st_dev, source_stat.st_ino) == (
                canonical_stat.st_dev, canonical_stat.st_ino,
            )
            if source_is_original:
                if sha256_file(source) != (row["sha256"], row["size_bytes"]):
                    raise ValueError("Original retained source failed content verification")
                recovery.unlink()
                _fsync_path(recovery.parent)
            elif source_is_canonical:
                os.replace(recovery, source)
                _fsync_path(source.parent)
                if _plan_fingerprint(source) != item["source_fingerprint"]:
                    raise ValueError("Restored original does not match its prepared fingerprint")
            else:
                raise ValueError("Retained path was replaced by an unrelated file")
            if sha256_file(source) != (row["sha256"], row["size_bytes"]):
                raise ValueError("Recovered retained source failed content verification")
            _journal_item(db_path, item, "restored", "Original inode restored after interruption")
            resolved += 1
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            try:
                _journal_item(db_path, item, "recovery-required", str(exc))
            finally:
                mark_recovery_required(db_path, str(exc))
            return {"resolved": resolved, "recovery_required": 1, "detail": str(exc)}
    clear_recovery_required(db_path)
    return {"resolved": resolved, "recovery_required": 0}


def _restore_original(db_path: Path, item: dict, detail: str) -> None:
    source = Path(item["source_path"])
    canonical = Path(item["canonical_path"])
    recovery = Path(item["recovery_path"])
    if not (_safe_file(source, db_path.parent) and _safe_file(canonical, db_path.parent)
            and _safe_file(recovery, recovery_root(db_path))):
        raise ValueError("Recovery cannot verify all retained paths")
    _validate_recovery_original(item, recovery)
    source_stat, canonical_stat, recovery_stat = source.stat(), canonical.stat(), recovery.stat()
    if (source_stat.st_dev, source_stat.st_ino) != (canonical_stat.st_dev, canonical_stat.st_ino):
        raise ValueError("Recovery will not overwrite an unrelated retained file")
    if (recovery_stat.st_dev, recovery_stat.st_ino) != (
        item["source_fingerprint"]["device"], item["source_fingerprint"]["inode"],
    ):
        raise ValueError("Recovery link no longer names the original inode")
    os.replace(recovery, source)
    _fsync_path(source.parent)
    if _plan_fingerprint(source) != item["source_fingerprint"]:
        raise ValueError("Restored original failed verification")
    if sha256_file(source) != (item["sha256"], item["size_bytes"]):
        raise ValueError("Restored original failed content verification")
    _journal_item(db_path, item, "restored", detail)


def _compact_storage_locked(db_path: Path, expected_plan_id: str) -> dict:
    report = _analyze_storage(db_path)
    plan = report["compaction"]
    candidates = report.pop("_compaction_candidates")
    if not plan["enabled"] or plan["plan_id"] != expected_plan_id:
        raise ValueError("Storage changed since the dry run. Run a new dry run and review the updated plan.")
    if shutil.disk_usage(db_path.parent).free < MIN_COMPACTION_FREE_BYTES:
        raise ValueError("At least 1 MiB of free space is required for the recovery journal")
    _init_compaction_journal(db_path)
    compaction_id = uuid.uuid4().hex
    before_free = shutil.disk_usage(db_path.parent).free
    replaced = estimated = 0
    issues = []
    for candidate in candidates:
        item_id = hashlib.sha256(
            f"{compaction_id}:{candidate['source_path']}".encode()
        ).hexdigest()
        source = db_path.parent / candidate["source_path"]
        canonical = db_path.parent / candidate["canonical_path"]
        recovery_dir = recovery_root(db_path) / compaction_id
        recovery_dir.mkdir(parents=True, exist_ok=True)
        _fsync_path(recovery_dir.parent)
        recovery_path = recovery_dir / f"{item_id}.recovery"
        item = {
            **candidate,
            "compaction_id": compaction_id,
            "item_id": item_id,
            "source_path": str(source),
            "canonical_path": str(canonical),
            "recovery_path": str(recovery_path),
        }
        replacement = source.with_name(f".{source.name}.{item_id}.compact")
        was_replaced = False
        try:
            if not (_safe_file(source, db_path.parent) and _safe_file(canonical, db_path.parent)):
                raise ValueError("A retained path became unavailable")
            if _plan_fingerprint(source) != candidate["source_fingerprint"]:
                raise ValueError("The duplicate source changed after confirmation")
            if _plan_fingerprint(canonical) != candidate["canonical_fingerprint"]:
                raise ValueError("The canonical file changed after confirmation")
            if source.stat().st_nlink != 1:
                raise ValueError("The duplicate source acquired another hard link")
            _journal_item(db_path, item, "preparing")
            os.link(source, recovery_path)
            _fsync_path(recovery_dir)
            _journal_item(db_path, item, "prepared")
            if (source.stat().st_dev, source.stat().st_ino) != (
                recovery_path.stat().st_dev, recovery_path.stat().st_ino,
            ):
                raise ValueError("Recovery link does not name the original inode")
            if sha256_file(source) != (candidate["sha256"], candidate["size_bytes"]):
                raise ValueError("The duplicate source changed during preparation")
            if sha256_file(canonical) != (candidate["sha256"], candidate["size_bytes"]):
                raise ValueError("The canonical file changed during preparation")
            if _security_metadata(source) != _security_metadata(canonical):
                raise ValueError("Security metadata no longer matches")
            os.link(canonical, replacement)
            _fsync_path(source.parent)
            mark_recovery_required(
                db_path,
                f"Exact-content replacement in progress for {candidate['source_path']}",
            )
            os.replace(replacement, source)
            _fsync_path(source.parent)
            was_replaced = True
            _journal_item(db_path, item, "replaced")
            if (source.stat().st_dev, source.stat().st_ino) != (
                canonical.stat().st_dev, canonical.stat().st_ino,
            ) or sha256_file(source) != (candidate["sha256"], candidate["size_bytes"]):
                raise ValueError("The shared retained path failed post-replacement verification")
            _journal_item(db_path, item, "verified")
            recovery_path.unlink()
            _fsync_path(recovery_dir)
            _journal_item(db_path, item, "completed", "Exact-content replacement verified")
            clear_recovery_required(db_path)
            replaced += 1
            estimated += candidate["size_bytes"]
        except Exception as exc:
            try:
                replacement.unlink(missing_ok=True)
            except OSError:
                pass
            try:
                if was_replaced:
                    _restore_original(db_path, item, str(exc))
                elif recovery_path.exists():
                    if source.exists() and (source.stat().st_dev, source.stat().st_ino) == (
                        recovery_path.stat().st_dev, recovery_path.stat().st_ino,
                    ):
                        recovery_path.unlink()
                        _fsync_path(recovery_dir)
                        _journal_item(db_path, item, "restored", str(exc))
                    else:
                        raise ValueError("Prepared original cannot be safely restored")
                else:
                    _journal_item(db_path, item, "restored", str(exc))
                clear_recovery_required(db_path)
            except Exception as recovery_error:
                try:
                    _journal_item(db_path, item, "recovery-required", str(recovery_error))
                except Exception:
                    pass
                try:
                    mark_recovery_required(db_path, str(recovery_error))
                except Exception:
                    pass
                raise EvidenceMaintenanceBlocked(
                    "Compaction stopped because the original file requires recovery"
                ) from recovery_error
            issues.append({"source_path": candidate["source_path"], "detail": str(exc)})
    after_free = shutil.disk_usage(db_path.parent).free
    final_report = analyze_storage(db_path)
    return {
        "compaction_id": compaction_id,
        "replaced_file_count": replaced,
        "estimated_file_length_savings": estimated,
        "measured_free_space_change": after_free - before_free,
        "issue_count": len(issues),
        "issues": issues[:100],
        "references_removed": 0,
        "automatic_pruning": False,
        "report": final_report,
    }


def compact_storage(db_path: Path, expected_plan_id: str) -> dict:
    with evidence_maintenance(db_path, allow_recovery=True):
        recovery = recover_incomplete_compactions(db_path)
        if recovery["recovery_required"]:
            raise EvidenceMaintenanceBlocked("Interrupted compaction recovery requires repair")
        return _compact_storage_locked(db_path, expected_plan_id)


@guarded_evidence_mutation(lambda db_path, *args, **kwargs: db_path)
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
            if (checkpoint and ref.get("existing_observation") and checkpoint[0] == fingerprint
                    and ref.get("expected_hash") == checkpoint[1]
                    and _safe_file(canonical, db_path.parent) and sha256_file(canonical)[0] == checkpoint[1]):
                skipped += 1
                continue
            if ref.get("expected_hash") and sha256_file(path)[0] != ref["expected_hash"]:
                raise ValueError("Import content does not match its retained hash")
            if ref.get("existing_observation"):
                digest = ref["expected_hash"]
                canonical = canonical_artifact_path(artifact_root_for(db_path), digest)
                if not _safe_file(canonical, db_path.parent) or sha256_file(canonical)[0] != digest:
                    raise ValueError("Existing observation has no verified canonical content")
                if json.dumps(_fingerprint(path)) != fingerprint:
                    raise ValueError("Evidence changed during backfill")
                with connect_database(db_path) as db:
                    db.execute("INSERT OR REPLACE INTO artifact_backfill VALUES (?, ?, ?)", (key, fingerprint, digest))
                skipped += 1
                continue
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


def start_storage_job(
    db_path: Path,
    mode: str,
    *,
    plan_id: str | None = None,
    confirmation: str | None = None,
) -> dict:
    if mode not in {"dry-run", "backfill", "compact"}:
        raise ValueError("Unknown storage operation")
    if mode == "compact":
        if confirmation != COMPACTION_CONFIRMATION:
            raise ValueError("Enter the exact compaction confirmation phrase")
        previous_report = storage_status(db_path).get("report") or {}
        previous_plan = previous_report.get("compaction") or {}
        if not plan_id or not previous_plan.get("enabled") or previous_plan.get("plan_id") != plan_id:
            raise ValueError("Run and review a current storage dry run before compaction")
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
            elif mode == "compact":
                value["compaction_result"] = compact_storage(db_path, plan_id)
                value["report"] = value["compaction_result"].pop("report")
            else:
                value["report"] = analyze_storage(db_path)
            if mode == "backfill":
                value["report"] = analyze_storage(db_path)
            value["status"] = "complete"
        except Exception as exc:
            value["status"] = "failed"
            value["error"] = str(exc) if isinstance(exc, (ValueError, EvidenceMaintenanceBlocked)) else (
                "Storage operation failed. Retained evidence records were preserved; retry after checking storage access."
            )
        finally:
            value["finished_at"] = utc_now()
            try:
                _save_status(db_path, value)
            finally:
                with _LOCK:
                    _ACTIVE.discard(str(db_path))
    threading.Thread(target=work, daemon=True, name="storage-health").start()
    return value.copy()
