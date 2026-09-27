from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import threading
import uuid

from app.database import configure_database, connect_database


_ARTIFACT_STORAGE_READY: set[tuple[str, str]] = set()
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
    storage_key = (str(db_path.resolve()), str(artifact_root.resolve()))
    if storage_key in _ARTIFACT_STORAGE_READY and db_path.is_file():
        return
    with _ARTIFACT_STORAGE_LOCK:
        if storage_key in _ARTIFACT_STORAGE_READY and db_path.is_file():
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
        _ARTIFACT_STORAGE_READY.add(storage_key)


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
) -> dict:
    init_artifact_storage(db_path, artifact_root)
    observed_at = observed_at or utc_now()
    canonical_path = canonical_artifact_path(artifact_root, digest)
    observation_id = uuid.uuid4().hex
    with connect_database(db_path) as db:
        existing = db.execute(
            "SELECT first_seen_at FROM artifact_registry WHERE sha256 = ?",
            (digest,),
        ).fetchone()
        if existing is None:
            db.execute(
                """
                INSERT INTO artifact_registry (
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
            )
            duplicate = False
            first_seen_at = observed_at
        else:
            db.execute(
                """
                UPDATE artifact_registry
                SET last_seen_at = ?,
                    media_type = CASE
                        WHEN media_type = 'application/octet-stream' AND ? != ''
                        THEN ? ELSE media_type END
                WHERE sha256 = ?
                """,
                (observed_at, media_type or "", media_type or "", digest),
            )
            duplicate = True
            first_seen_at = existing[0]
        db.execute(
            """
            INSERT INTO artifact_observations (
                observation_id, sha256, source_kind, source_ref, observed_at,
                original_filename, actor, metadata_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                observation_id,
                digest,
                source_kind,
                source_ref,
                observed_at,
                original_filename,
                actor,
                json.dumps(metadata or {}, sort_keys=True),
            ),
        )
    return {
        "sha256": digest,
        "size_bytes": int(size_bytes),
        "media_type": media_type or "application/octet-stream",
        "canonical_path": str(canonical_path),
        "duplicate": duplicate,
        "first_seen_at": first_seen_at,
        "last_seen_at": observed_at,
        "observation_id": observation_id,
        "source_kind": source_kind,
        "source_ref": source_ref,
    }


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
    )
    record["physical_created"] = not record["duplicate"]
    return record


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
) -> dict:
    artifact_root = artifact_root or artifact_root_for(db_path)
    digest, size_bytes = sha256_file(source_path)
    canonical_path = canonical_artifact_path(artifact_root, digest)
    canonical_path.parent.mkdir(parents=True, exist_ok=True)
    physical_created = False
    if not canonical_path.exists():
        temporary = canonical_path.with_name(f".{digest}.{uuid.uuid4().hex}.tmp")
        with source_path.open("rb") as source, temporary.open("wb") as target:
            shutil.copyfileobj(source, target, COPY_CHUNK_BYTES)
        try:
            os.replace(temporary, canonical_path)
            physical_created = True
        finally:
            temporary.unlink(missing_ok=True)
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
    )
    record["physical_created"] = physical_created
    return record


def link_artifact(record: dict, destination: Path) -> str:
    """Materialize one retained run-local reference without duplicating blocks when possible."""
    source = Path(record["canonical_path"])
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.unlink(missing_ok=True)
    try:
        os.link(source, destination)
        return "hardlink"
    except OSError:
        shutil.copyfile(source, destination)
        return "copy"


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
