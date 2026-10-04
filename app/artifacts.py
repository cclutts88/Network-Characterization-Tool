from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import threading
import uuid

from app.database import configure_database, connect_database
from app.evidence_maintenance import guarded_evidence_mutation
from app.saved_network_scope_associations import (
    get_run_scope_context,
    insert_artifact_observation_scope_context,
)


_ARTIFACT_STORAGE_READY: set[tuple[str, str, int, int]] = set()
_ARTIFACT_STORAGE_LOCK = threading.RLock()
COPY_CHUNK_BYTES = 1024 * 1024


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def artifact_root_for(db_path: Path) -> Path:
    return db_path.parent / "artifacts" / "sha256"


def canonical_artifact_path(artifact_root: Path, digest: str) -> Path:
    return artifact_root / digest[:2] / digest


def sha256_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(COPY_CHUNK_BYTES), b""):
            size += len(chunk)
            digest.update(chunk)
    return digest.hexdigest(), size


def init_artifact_storage(db_path: Path, artifact_root: Path | None = None) -> None:
    artifact_root = artifact_root or artifact_root_for(db_path)
    def storage_key():
        try:
            info = db_path.stat()
        except FileNotFoundError:
            return None
        return (str(db_path.resolve()), str(artifact_root.resolve()), info.st_dev, info.st_ino)

    if storage_key() in _ARTIFACT_STORAGE_READY:
        return
    with _ARTIFACT_STORAGE_LOCK:
        if storage_key() in _ARTIFACT_STORAGE_READY:
            return
        configure_database(db_path)
        artifact_root.mkdir(parents=True, exist_ok=True)
        with connect_database(db_path) as db:
            db.execute(
                """
                CREATE TABLE IF NOT EXISTS artifact_registry (
                    sha256 TEXT PRIMARY KEY,
                    size_bytes INTEGER NOT NULL,
                    media_type TEXT NOT NULL DEFAULT 'application/octet-stream',
                    canonical_path TEXT NOT NULL,
                    first_seen_at TEXT NOT NULL,
                    last_seen_at TEXT NOT NULL
                )
                """
            )
            db.execute(
                """
                CREATE TABLE IF NOT EXISTS artifact_observations (
                    observation_id TEXT PRIMARY KEY,
                    sha256 TEXT NOT NULL,
                    source_kind TEXT NOT NULL,
                    source_ref TEXT NOT NULL,
                    observed_at TEXT NOT NULL,
                    original_filename TEXT,
                    actor TEXT,
                    metadata_json TEXT NOT NULL DEFAULT '{}',
                    FOREIGN KEY (sha256) REFERENCES artifact_registry(sha256)
                        ON DELETE CASCADE
                )
                """
            )
            db.execute(
                "CREATE INDEX IF NOT EXISTS artifact_observations_sha "
                "ON artifact_observations(sha256, observed_at)"
            )
            db.execute(
                "CREATE INDEX IF NOT EXISTS artifact_observations_source "
                "ON artifact_observations(source_kind, source_ref)"
            )
        _ARTIFACT_STORAGE_READY.add(storage_key())


def _register_record(
    *,
    db_path: Path,
    artifact_root: Path,
    digest: str,
    size_bytes: int,
    media_type: str,
    source_kind: str,
    source_ref: str,
    original_filename: str | None,
    actor: str | None,
    metadata: dict | None,
    observed_at: str | None,
    observation_key: str | None = None,
    run_id: str | None = None,
    scope_context: dict | None = None,
    pipeline_policy_version: int | None = None,
) -> dict:
    init_artifact_storage(db_path, artifact_root)
    if pipeline_policy_version is not None:
        from app.pipeline_intake import init_pipeline_intake_storage

        init_pipeline_intake_storage(db_path)
    observed_at = observed_at or utc_now()
    canonical_path = canonical_artifact_path(artifact_root, digest)
    observation_id = hashlib.sha256(f"{observation_key}:{digest}".encode()).hexdigest() if observation_key else uuid.uuid4().hex
    with connect_database(db_path) as db:
        inserted = db.execute(
            """
            INSERT OR IGNORE INTO artifact_registry (
                sha256, size_bytes, media_type, canonical_path,
                first_seen_at, last_seen_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                digest,
                int(size_bytes),
                media_type or "application/octet-stream",
                str(canonical_path),
                observed_at,
                observed_at,
            ),
        ).rowcount
        duplicate = not bool(inserted)
        db.execute(
            """
            UPDATE artifact_registry
            SET first_seen_at = MIN(first_seen_at, ?), last_seen_at = MAX(last_seen_at, ?),
                media_type = CASE
                    WHEN media_type = 'application/octet-stream' AND ? != ''
                    THEN ? ELSE media_type END
            WHERE sha256 = ?
            """,
            (observed_at, observed_at, media_type or "", media_type or "", digest),
        )
        observation_values = (
            observation_id,
            digest,
            source_kind,
            source_ref,
            observed_at,
            original_filename,
            actor,
            json.dumps(metadata or {}, sort_keys=True),
        )
        observation_inserted = db.execute(
            """
            INSERT OR IGNORE INTO artifact_observations (
                observation_id, sha256, source_kind, source_ref, observed_at,
                original_filename, actor, metadata_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            observation_values,
        ).rowcount
        if not observation_inserted:
            existing_observation = db.execute(
                """
                SELECT observation_id, sha256, source_kind, source_ref, observed_at,
                       original_filename, actor, metadata_json
                FROM artifact_observations WHERE observation_id = ?
                """,
                (observation_id,),
            ).fetchone()
            if existing_observation is None or tuple(existing_observation) != observation_values:
                raise ValueError("Artifact observation replay does not match retained provenance")
        if scope_context is not None:
            if not run_id:
                raise ValueError("Scoped artifact observations require a scan run")
            insert_artifact_observation_scope_context(
                db,
                observation_id=observation_id,
                run_id=run_id,
                context=scope_context,
            )
        if pipeline_policy_version is not None:
            from app.pipeline_intake import MANUAL_NMAP_SOURCE, mark_pipeline_source

            if source_kind != "nmap_import":
                raise ValueError("Pipeline upload policy applies only to manual Nmap evidence")
            mark_pipeline_source(
                db,
                source_kind=MANUAL_NMAP_SOURCE,
                source_id=observation_id,
                marked_by=actor or "local-operator",
                marked_at=observed_at,
                policy_version=pipeline_policy_version,
            )
        first_seen_at, last_seen_at = db.execute(
            "SELECT first_seen_at, last_seen_at FROM artifact_registry WHERE sha256 = ?", (digest,)
        ).fetchone()
    return {
        "sha256": digest,
        "size_bytes": int(size_bytes),
        "media_type": media_type or "application/octet-stream",
        "canonical_path": str(canonical_path),
        "duplicate": duplicate,
        "first_seen_at": first_seen_at,
        "last_seen_at": last_seen_at,
        "observation_id": observation_id,
        "source_kind": source_kind,
        "source_ref": source_ref,
    }


@guarded_evidence_mutation(lambda *args, **kwargs: kwargs["db_path"])
def register_artifact_bytes(
    *,
    db_path: Path,
    content: bytes,
    source_kind: str,
    source_ref: str,
    original_filename: str | None = None,
    media_type: str = "application/octet-stream",
    actor: str | None = None,
    metadata: dict | None = None,
    observed_at: str | None = None,
    artifact_root: Path | None = None,
    pipeline_policy_version: int | None = None,
) -> dict:
    artifact_root = artifact_root or artifact_root_for(db_path)
    digest = hashlib.sha256(content).hexdigest()
    canonical_path = canonical_artifact_path(artifact_root, digest)
    canonical_path.parent.mkdir(parents=True, exist_ok=True)
    if not canonical_path.exists():
        temporary = canonical_path.with_name(f".{digest}.{uuid.uuid4().hex}.tmp")
        temporary.write_bytes(content)
        try:
            os.replace(temporary, canonical_path)
        finally:
            temporary.unlink(missing_ok=True)
    if sha256_file(canonical_path) != (digest, len(content)):
        raise ValueError("Canonical artifact failed content verification")
    record = _register_record(
        db_path=db_path,
        artifact_root=artifact_root,
        digest=digest,
        size_bytes=len(content),
        media_type=media_type,
        source_kind=source_kind,
        source_ref=source_ref,
        original_filename=original_filename,
        actor=actor,
        metadata=metadata,
        observed_at=observed_at,
        pipeline_policy_version=pipeline_policy_version,
    )
    record["physical_created"] = not record["duplicate"]
    return record


@guarded_evidence_mutation(lambda *args, **kwargs: kwargs["db_path"])
def register_artifact_file(
    *,
    db_path: Path,
    source_path: Path,
    source_kind: str,
    source_ref: str,
    original_filename: str | None = None,
    media_type: str = "application/octet-stream",
    actor: str | None = None,
    metadata: dict | None = None,
    observed_at: str | None = None,
    artifact_root: Path | None = None,
    observation_key: str | None = None,
    run_id: str | None = None,
    scope_context: dict | None = None,
    expected_sha256: str | None = None,
    expected_size_bytes: int | None = None,
    pipeline_policy_version: int | None = None,
) -> dict:
    artifact_root = artifact_root or artifact_root_for(db_path)
    before = source_path.stat()
    digest, size_bytes = sha256_file(source_path)
    if (
        expected_sha256 is not None
        and (digest != expected_sha256 or size_bytes != expected_size_bytes)
    ):
        raise ValueError("Evidence does not match the frozen verification contract")
    canonical_path = canonical_artifact_path(artifact_root, digest)
    canonical_path.parent.mkdir(parents=True, exist_ok=True)
    physical_created = False
    if not canonical_path.exists():
        temporary = canonical_path.with_name(f".{digest}.{uuid.uuid4().hex}.tmp")
        try:
            with source_path.open("rb") as source, temporary.open("wb") as target:
                shutil.copyfileobj(source, target, COPY_CHUNK_BYTES)
            if sha256_file(temporary) != (digest, size_bytes):
                raise ValueError("Evidence changed while being registered")
            os.replace(temporary, canonical_path)
            physical_created = True
        finally:
            temporary.unlink(missing_ok=True)
    if sha256_file(canonical_path) != (digest, size_bytes):
        raise ValueError("Canonical artifact failed content verification")
    after = source_path.stat()
    if (before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
        raise ValueError("Evidence changed while being registered")
    record = _register_record(
        db_path=db_path,
        artifact_root=artifact_root,
        digest=digest,
        size_bytes=size_bytes,
        media_type=media_type,
        source_kind=source_kind,
        source_ref=source_ref,
        original_filename=original_filename,
        actor=actor,
        metadata=metadata,
        observed_at=observed_at,
        observation_key=observation_key,
        run_id=run_id,
        scope_context=scope_context,
        pipeline_policy_version=pipeline_policy_version,
    )
    record["physical_created"] = physical_created
    return record


def link_artifact(record: dict, destination: Path) -> str:
    """Materialize one retained run-local reference without duplicating blocks when possible."""
    source = Path(record["canonical_path"])
    destination.parent.mkdir(parents=True, exist_ok=True)
    if source.resolve() == destination.resolve():
        return "canonical"
    temporary = destination.with_name(f".{destination.name}.{uuid.uuid4().hex}.tmp")
    try:
        try:
            os.link(source, temporary)
            mode = "hardlink"
        except OSError:
            shutil.copyfile(source, temporary)
            mode = "copy"
        os.replace(temporary, destination)
        return mode
    finally:
        temporary.unlink(missing_ok=True)


@guarded_evidence_mutation(lambda db_path, *args, **kwargs: db_path)
def register_finalized_files(db_path: Path, run_dir: Path, manifest: dict,
                             source_kind: str, filenames,
                             expected_files: dict[str, dict] | None = None) -> None:
    """Called after writers close, never from history/read endpoints."""
    records, errors = [], []
    scope_context = get_run_scope_context(db_path, manifest["run_id"])
    for filename in dict.fromkeys(filenames):
        path = run_dir / filename
        if filename == "manifest.json" or not path.is_file() or path.is_symlink():
            if expected_files is not None and filename != "manifest.json":
                errors.append({
                    "filename": filename,
                    "error": "Expected retained evidence is unavailable",
                })
            continue
        expected = (expected_files or {}).get(filename)
        if expected_files is not None and expected is None:
            errors.append({
                "filename": filename,
                "error": "Retained evidence is outside the frozen verification contract",
            })
            continue
        try:
            record = register_artifact_file(
                db_path=db_path, source_path=path, source_kind=source_kind,
                source_ref=manifest["run_id"], original_filename=filename,
                actor=manifest.get("owner") or manifest.get("operator"),
                observed_at=manifest.get("completed_at") or manifest.get("created_at"),
                observation_key=f"{source_kind}:{manifest['run_id']}:{filename}",
                metadata={"relative_path": str(path.relative_to(db_path.parent))},
                run_id=manifest["run_id"], scope_context=scope_context,
                expected_sha256=(expected or {}).get("sha256"),
                expected_size_bytes=(expected or {}).get("size_bytes"),
            )
            record["storage_mode"] = link_artifact(record, path)
            records.append({
                "filename": filename,
                "sha256": record["sha256"],
                "size_bytes": record["size_bytes"],
                "observation_id": record["observation_id"],
                "storage_mode": record["storage_mode"],
            })
        except (OSError, ValueError, sqlite3.Error) as exc:
            errors.append({"filename": filename, "error": str(exc)})
    if expected_files is not None:
        attempted = {name for name in dict.fromkeys(filenames) if name != "manifest.json"}
        for filename in sorted(set(expected_files) - attempted):
            errors.append({
                "filename": filename,
                "error": "Frozen retained evidence was not selected for registration",
            })
    manifest["artifact_registry"] = {"files": records, "errors": errors,
                                     "status": "partial" if errors else "complete"}


def get_artifact(db_path: Path, digest: str) -> dict | None:
    init_artifact_storage(db_path)
    with connect_database(db_path) as db:
        row = db.execute(
            """
            SELECT sha256, size_bytes, media_type, canonical_path,
                   first_seen_at, last_seen_at
            FROM artifact_registry WHERE sha256 = ?
            """,
            (digest,),
        ).fetchone()
        if row is None:
            return None
        observations = db.execute(
            """
            SELECT observation_id, source_kind, source_ref, observed_at,
                   original_filename, actor, metadata_json
            FROM artifact_observations
            WHERE sha256 = ?
            ORDER BY observed_at, observation_id
            """,
            (digest,),
        ).fetchall()
    return {
        "sha256": row[0],
        "size_bytes": int(row[1]),
        "media_type": row[2],
        "canonical_path": row[3],
        "first_seen_at": row[4],
        "last_seen_at": row[5],
        "observations": [
            {
                "observation_id": item[0],
                "source_kind": item[1],
                "source_ref": item[2],
                "observed_at": item[3],
                "original_filename": item[4],
                "actor": item[5],
                "metadata": json.loads(item[6] or "{}"),
            }
            for item in observations
        ],
    }


def get_artifact_observation(db_path: Path, observation_id: str) -> dict | None:
    """Return one source encounter together with its canonical artifact record."""
    init_artifact_storage(db_path)
    with connect_database(db_path) as db:
        row = db.execute(
            """
            SELECT o.observation_id, o.sha256, o.source_kind, o.source_ref,
                   o.observed_at, o.original_filename, o.actor, o.metadata_json,
                   a.size_bytes, a.media_type, a.canonical_path,
                   a.first_seen_at, a.last_seen_at
            FROM artifact_observations o
            JOIN artifact_registry a ON a.sha256 = o.sha256
            WHERE o.observation_id = ?
            """,
            (observation_id,),
        ).fetchone()
    if row is None:
        return None
    return {
        "observation_id": row[0], "sha256": row[1], "source_kind": row[2],
        "source_ref": row[3], "observed_at": row[4], "original_filename": row[5],
        "actor": row[6], "metadata": json.loads(row[7] or "{}"),
        "size_bytes": int(row[8]), "media_type": row[9], "canonical_path": row[10],
        "first_seen_at": row[11], "last_seen_at": row[12],
    }


def artifact_storage_summary(db_path: Path) -> dict:
    init_artifact_storage(db_path)
    with connect_database(db_path) as db:
        unique_count, unique_bytes = db.execute(
            "SELECT COUNT(*), COALESCE(SUM(size_bytes), 0) FROM artifact_registry"
        ).fetchone()
        observation_count = db.execute(
            "SELECT COUNT(*) FROM artifact_observations"
        ).fetchone()[0]
    return {
        "unique_artifact_count": int(unique_count),
        "unique_artifact_bytes": int(unique_bytes),
        "observation_count": int(observation_count),
    }
