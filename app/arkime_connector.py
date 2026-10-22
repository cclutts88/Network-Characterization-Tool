"""Bounded, restart-aware read-only Arkime Sessions API connector.

The connector keeps credentials in deployment-owned files, freezes every query before
contact, retains the exact HTTP entity, and reuses the manual Arkime evidence parser.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
import sqlite3
import ssl
import stat
import subprocess
import sys
import threading
from typing import Callable
from urllib import parse
import uuid

from app.arkime_evidence import (
    ARKIME_PARSER_VERSION,
    ArkimeEvidenceError,
    MAX_ARKIME_JSON_BYTES,
    import_arkime_sessions_json,
    init_arkime_evidence_storage,
    parse_arkime_sessions_json,
)
from app.database import connect_database, initialize_once_per_database
from app.evidence_maintenance import evidence_mutation
from app.network_scopes import init_network_scope_storage


PROFILE_STATES = {"ready", "attention"}
RUN_STATES = {"queued", "running", "complete", "partial", "failed", "interrupted", "cancelled"}
FINAL_RUN_STATES = {"complete", "partial", "failed", "interrupted", "cancelled"}
MAX_PULL_SESSIONS = 1_000
MAX_PROFILE_PAGE = 100
ARKIME_CONNECTOR_CONTRACT = "arkime-sessions-api:1"
ARKIME_FIELDS = ",".join((
    "ipProtocol", "rootId", "firstPacket", "lastPacket", "source.ip", "source.port",
    "destination.ip", "destination.port", "network.packets", "network.bytes", "node",
    "protocol", "vlan", "srcPackets", "dstPackets", "srcBytes", "dstBytes",
    "totDataBytes",
))


class ArkimeConnectorError(ValueError):
    pass


class ArkimeConnectorConflict(ArkimeConnectorError):
    pass


class ArkimeConnectorUnavailable(ArkimeConnectorError):
    pass


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def _time_text(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat()


def _parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def _text(value, field: str, maximum: int, *, blank: bool = False) -> str:
    if not isinstance(value, str):
        raise ArkimeConnectorError(f"{field} must be text")
    result = value.strip()
    if not result and not blank:
        raise ArkimeConnectorError(f"{field} cannot be blank")
    if len(result) > maximum:
        raise ArkimeConnectorError(f"{field} exceeds {maximum} characters")
    if any(ord(character) < 32 or ord(character) == 127 for character in result):
        raise ArkimeConnectorError(f"{field} contains unsupported control characters")
    return result


def _integer(value, field: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ArkimeConnectorError(f"{field} must be between {minimum} and {maximum}")
    return value


@dataclass(frozen=True)
class ArkimeConnectorConfig:
    enabled: bool
    base_url: str | None = None
    username: str | None = None
    password_file: Path | None = None
    ca_file: Path | None = None
    timeout_seconds: int = 30
    connector_id: str | None = None
    dataset_identity: str | None = None

    @classmethod
    def from_environment(cls) -> "ArkimeConnectorConfig":
        enabled = os.getenv("NCT_ARKIME_API_ENABLED", "").strip().lower() in {"1", "true", "yes"}
        if not enabled:
            return cls(enabled=False)
        raw_url = os.getenv("NCT_ARKIME_API_URL", "").strip()
        username = os.getenv("NCT_ARKIME_API_USERNAME", "").strip()
        password_path = os.getenv("NCT_ARKIME_API_PASSWORD_FILE", "").strip()
        if not raw_url or not username or not password_path:
            raise ArkimeConnectorUnavailable(
                "Arkime automatic pulls require URL, username, and password-file deployment settings"
            )
        parsed = parse.urlsplit(raw_url)
        if parsed.scheme.lower() != "https" or not parsed.hostname:
            raise ArkimeConnectorUnavailable("Arkime automatic pulls require an HTTPS URL")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ArkimeConnectorUnavailable(
                "The Arkime URL cannot contain credentials, a query, or a fragment"
            )
        base_url = parse.urlunsplit(("https", parsed.netloc, parsed.path.rstrip("/"), "", ""))
        username = _text(username, "Arkime API username", 200)
        timeout_raw = os.getenv("NCT_ARKIME_API_TIMEOUT_SECONDS", "30").strip()
        try:
            timeout = int(timeout_raw)
        except ValueError as exc:
            raise ArkimeConnectorUnavailable("Arkime API timeout must be a whole number") from exc
        if not 3 <= timeout <= 120:
            raise ArkimeConnectorUnavailable("Arkime API timeout must be between 3 and 120 seconds")
        ca_raw = os.getenv("NCT_ARKIME_API_CA_FILE", "").strip()
        dataset_raw = os.getenv("NCT_ARKIME_DATASET_ID", "").strip()
        dataset_identity = (
            _text(dataset_raw, "Arkime dataset identity", 200) if dataset_raw else None
        )
        identity = hashlib.sha256(f"{base_url}\0{username}".encode()).hexdigest()[:16]
        return cls(
            enabled=True, base_url=base_url, username=username,
            password_file=Path(password_path), ca_file=Path(ca_raw) if ca_raw else None,
            timeout_seconds=timeout, connector_id=identity,
            dataset_identity=dataset_identity,
        )

    @property
    def sessions_url(self) -> str:
        if not self.base_url:
            raise ArkimeConnectorUnavailable("Arkime automatic pulls are not configured")
        return f"{self.base_url}/api/sessions"

    def read_password(self) -> str:
        if self.password_file is None:
            raise ArkimeConnectorUnavailable("Arkime password file is not configured")
        try:
            info = self.password_file.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                raise ArkimeConnectorUnavailable("Arkime password file must be a regular file")
            if info.st_size > 4096:
                raise ArkimeConnectorUnavailable("Arkime password file exceeds 4 KiB")
            password = self.password_file.read_text(encoding="utf-8").strip()
        except ArkimeConnectorUnavailable:
            raise
        except (OSError, UnicodeError) as exc:
            raise ArkimeConnectorUnavailable("Arkime password file could not be read") from exc
        if not password:
            raise ArkimeConnectorUnavailable("Arkime password file is empty")
        return password


def connector_status() -> dict:
    try:
        config = ArkimeConnectorConfig.from_environment()
    except ArkimeConnectorError as exc:
        return {"configured": False, "available": False, "detail": str(exc)}
    if not config.enabled:
        return {
            "configured": False, "available": False,
            "detail": "Automatic Arkime pulls are not enabled for this deployment",
        }
    password = ""
    try:
        password = config.read_password()
        ssl.create_default_context(cafile=str(config.ca_file) if config.ca_file else None)
    except (ArkimeConnectorError, OSError, ssl.SSLError) as exc:
        return {"configured": False, "available": False, "detail": str(exc)}
    finally:
        password = ""
    return {
        "configured": True, "available": True, "connector_id": config.connector_id,
        "endpoint": parse.urlsplit(config.base_url or "").netloc,
        "authentication": "Digest", "tls_verified": True,
        "connector_contract": ARKIME_CONNECTOR_CONTRACT,
        "parser_version": ARKIME_PARSER_VERSION,
        "max_sessions_per_pull": MAX_PULL_SESSIONS,
        "max_response_bytes": MAX_ARKIME_JSON_BYTES,
        "dataset_identity": config.dataset_identity,
        "history_identity_configured": bool(config.dataset_identity),
        "detail": "Ready for bounded read-only Sessions API pulls",
    }


def _transport_command() -> list[str]:
    return [sys.executable, "-m", "app.arkime_transport"]


_ACTIVE_TRANSPORT_LOCK = threading.Lock()
_ACTIVE_TRANSPORT: subprocess.Popen | None = None


def _stop_active_transport() -> None:
    with _ACTIVE_TRANSPORT_LOCK:
        process = _ACTIVE_TRANSPORT
    if process is not None and process.poll() is None:
        try:
            process.kill()
        except OSError:
            pass


def _fetch_sessions(config: ArkimeConnectorConfig, parameters: dict[str, str]) -> bytes:
    global _ACTIVE_TRANSPORT
    caller_is_worker = threading.current_thread() is _WORKER_THREAD
    if caller_is_worker and _WORKER_STOP.is_set():
        raise ArkimeConnectorUnavailable(
            "NCT stopped the Arkime pull before network contact began"
        )
    password = config.read_password()
    password = ""
    payload = json.dumps({
        "base_url": config.base_url,
        "username": config.username,
        "password_file": str(config.password_file),
        "ca_file": str(config.ca_file) if config.ca_file else None,
        "timeout_seconds": config.timeout_seconds,
        "parameters": parameters,
    }, sort_keys=True, separators=(",", ":")).encode("utf-8")
    process = subprocess.Popen(
        _transport_command(), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, cwd=str(Path(__file__).resolve().parents[1]),
    )
    with _ACTIVE_TRANSPORT_LOCK:
        if _ACTIVE_TRANSPORT is not None and _ACTIVE_TRANSPORT.poll() is None:
            process.kill()
            process.wait(timeout=1)
            raise ArkimeConnectorConflict("Another Arkime network transfer is already active")
        _ACTIVE_TRANSPORT = process
    if caller_is_worker and _WORKER_STOP.is_set():
        process.kill()
    try:
        try:
            content, stderr = process.communicate(input=payload, timeout=config.timeout_seconds)
        except subprocess.TimeoutExpired as exc:
            process.kill()
            content, stderr = process.communicate(timeout=1)
            raise ArkimeConnectorUnavailable(
                "Arkime exceeded the whole-request deadline; no evidence was published"
            ) from exc
        if process.returncode != 0:
            if caller_is_worker and _WORKER_STOP.is_set():
                raise ArkimeConnectorUnavailable(
                    "NCT stopped the Arkime pull before the response completed"
                )
            detail = stderr.decode("utf-8", errors="replace").strip()[:500]
            raise ArkimeConnectorUnavailable(detail or "Arkime transport failed")
        if len(content) > MAX_ARKIME_JSON_BYTES:
            raise ArkimeConnectorUnavailable(
                "Arkime response exceeded the 10 MiB pull limit; no evidence was published"
            )
        return content
    finally:
        with _ACTIVE_TRANSPORT_LOCK:
            if _ACTIVE_TRANSPORT is process:
                _ACTIVE_TRANSPORT = None


@initialize_once_per_database
def init_arkime_connector_storage(db_path: Path) -> None:
    init_network_scope_storage(db_path)
    init_arkime_evidence_storage(db_path)
    with connect_database(db_path) as db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS arkime_pull_profiles (
                profile_id TEXT PRIMARY KEY,
                current_version INTEGER NOT NULL CHECK(current_version >= 1),
                enabled INTEGER NOT NULL CHECK(enabled IN (0,1)),
                state TEXT NOT NULL CHECK(state IN ('ready','attention')),
                next_window_start TEXT NOT NULL,
                next_window_end TEXT NOT NULL,
                next_due_at TEXT NOT NULL,
                last_run_id TEXT,
                attention_detail TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS arkime_pull_profile_versions (
                profile_id TEXT NOT NULL REFERENCES arkime_pull_profiles(profile_id),
                version INTEGER NOT NULL CHECK(version >= 1),
                name TEXT NOT NULL,
                scope_id TEXT NOT NULL REFERENCES network_scopes(scope_id),
                scope_label TEXT NOT NULL,
                scope_version INTEGER NOT NULL CHECK(scope_version >= 1),
                operator_sensor TEXT NOT NULL,
                query_expression TEXT NOT NULL DEFAULT '',
                bounding_mode TEXT NOT NULL CHECK(bounding_mode IN ('first','last','both','either')),
                cadence_minutes INTEGER NOT NULL,
                lookback_minutes INTEGER NOT NULL,
                overlap_minutes INTEGER NOT NULL,
                collection_delay_seconds INTEGER NOT NULL,
                actor TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY(profile_id, version)
            );
            CREATE TABLE IF NOT EXISTS arkime_pull_profile_events (
                event_id TEXT PRIMARY KEY,
                profile_id TEXT NOT NULL REFERENCES arkime_pull_profiles(profile_id),
                event_type TEXT NOT NULL CHECK(event_type IN ('created','enabled','paused')),
                actor TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS arkime_pull_runs (
                run_id TEXT PRIMARY KEY,
                profile_id TEXT NOT NULL REFERENCES arkime_pull_profiles(profile_id),
                profile_version INTEGER NOT NULL,
                request_kind TEXT NOT NULL CHECK(request_kind IN ('scheduled','manual','retry')),
                retry_of_run_id TEXT REFERENCES arkime_pull_runs(run_id),
                state TEXT NOT NULL CHECK(state IN ('queued','running','complete','partial','failed','interrupted','cancelled')),
                scope_id TEXT NOT NULL,
                scope_label TEXT NOT NULL,
                scope_version INTEGER NOT NULL,
                operator_sensor TEXT NOT NULL,
                query_expression TEXT NOT NULL,
                bounding_mode TEXT NOT NULL,
                query_start TEXT NOT NULL,
                query_end TEXT NOT NULL,
                connector_id TEXT NOT NULL,
                dataset_identity TEXT NOT NULL DEFAULT 'legacy-unverified',
                connector_contract TEXT NOT NULL,
                parser_version TEXT NOT NULL,
                advances_schedule INTEGER NOT NULL CHECK(advances_schedule IN (0,1)),
                request_parameters_json TEXT NOT NULL,
                actor TEXT NOT NULL,
                queued_at TEXT NOT NULL,
                started_at TEXT,
                completed_at TEXT,
                claim_token TEXT,
                cancel_requested INTEGER NOT NULL DEFAULT 0 CHECK(cancel_requested IN (0,1)),
                import_id TEXT REFERENCES arkime_imports(import_id),
                error TEXT,
                FOREIGN KEY(profile_id, profile_version)
                    REFERENCES arkime_pull_profile_versions(profile_id, version)
            );
            CREATE INDEX IF NOT EXISTS arkime_pull_runs_profile_time
                ON arkime_pull_runs(profile_id, queued_at DESC, run_id DESC);
            CREATE INDEX IF NOT EXISTS arkime_pull_runs_claim
                ON arkime_pull_runs(state, queued_at, run_id);
            CREATE TRIGGER IF NOT EXISTS arkime_pull_profile_versions_no_update
                BEFORE UPDATE ON arkime_pull_profile_versions
                BEGIN SELECT RAISE(ABORT, 'Arkime pull profile versions are immutable'); END;
            CREATE TRIGGER IF NOT EXISTS arkime_pull_profile_versions_no_delete
                BEFORE DELETE ON arkime_pull_profile_versions
                BEGIN SELECT RAISE(ABORT, 'Arkime pull profile versions are immutable'); END;
            CREATE TRIGGER IF NOT EXISTS arkime_pull_profile_events_no_update
                BEFORE UPDATE ON arkime_pull_profile_events
                BEGIN SELECT RAISE(ABORT, 'Arkime pull profile events are immutable'); END;
            CREATE TRIGGER IF NOT EXISTS arkime_pull_profile_events_no_delete
                BEFORE DELETE ON arkime_pull_profile_events
                BEGIN SELECT RAISE(ABORT, 'Arkime pull profile events are immutable'); END;
            CREATE TRIGGER IF NOT EXISTS arkime_pull_runs_no_delete
                BEFORE DELETE ON arkime_pull_runs
                BEGIN SELECT RAISE(ABORT, 'Arkime pull runs cannot be deleted'); END;
        """)
        columns = {
            row[1] for row in db.execute("PRAGMA table_info(arkime_pull_runs)").fetchall()
        }
        if "connector_contract" not in columns:
            db.execute(
                "ALTER TABLE arkime_pull_runs ADD COLUMN connector_contract TEXT "
                "NOT NULL DEFAULT 'legacy-unfrozen'"
            )
        if "dataset_identity" not in columns:
            db.execute(
                "ALTER TABLE arkime_pull_runs ADD COLUMN dataset_identity TEXT "
                "NOT NULL DEFAULT 'legacy-unverified'"
            )
        if "parser_version" not in columns:
            db.execute(
                "ALTER TABLE arkime_pull_runs ADD COLUMN parser_version TEXT "
                "NOT NULL DEFAULT 'legacy-unfrozen'"
            )
        if "advances_schedule" not in columns:
            db.execute(
                "ALTER TABLE arkime_pull_runs ADD COLUMN advances_schedule INTEGER "
                "NOT NULL DEFAULT 0 CHECK(advances_schedule IN (0,1))"
            )
            db.execute(
                "UPDATE arkime_pull_runs SET advances_schedule=1 "
                "WHERE request_kind='scheduled'"
            )
            db.execute("""
                WITH RECURSIVE scheduled_retries(run_id) AS (
                    SELECT run_id FROM arkime_pull_runs WHERE request_kind='scheduled'
                    UNION ALL
                    SELECT child.run_id
                    FROM arkime_pull_runs child
                    JOIN scheduled_retries parent
                      ON child.retry_of_run_id=parent.run_id
                )
                UPDATE arkime_pull_runs SET advances_schedule=1
                WHERE run_id IN (SELECT run_id FROM scheduled_retries)
            """)
        db.executescript("""
            DROP TRIGGER IF EXISTS arkime_pull_runs_frozen_authority;
            CREATE TRIGGER arkime_pull_runs_frozen_authority
                BEFORE UPDATE ON arkime_pull_runs
                WHEN OLD.profile_id != NEW.profile_id
                  OR OLD.profile_version != NEW.profile_version
                  OR OLD.request_kind != NEW.request_kind
                  OR COALESCE(OLD.retry_of_run_id,'') != COALESCE(NEW.retry_of_run_id,'')
                  OR OLD.scope_id != NEW.scope_id OR OLD.scope_label != NEW.scope_label
                  OR OLD.scope_version != NEW.scope_version
                  OR OLD.operator_sensor != NEW.operator_sensor
                  OR OLD.query_expression != NEW.query_expression
                  OR OLD.bounding_mode != NEW.bounding_mode
                  OR OLD.query_start != NEW.query_start OR OLD.query_end != NEW.query_end
                  OR OLD.connector_id != NEW.connector_id
                  OR OLD.dataset_identity != NEW.dataset_identity
                  OR OLD.connector_contract != NEW.connector_contract
                  OR OLD.parser_version != NEW.parser_version
                  OR OLD.advances_schedule != NEW.advances_schedule
                  OR OLD.request_parameters_json != NEW.request_parameters_json
                  OR OLD.actor != NEW.actor OR OLD.queued_at != NEW.queued_at
                BEGIN SELECT RAISE(ABORT, 'Arkime pull authority is immutable'); END;
        """)


def _scope(db: sqlite3.Connection, scope_id: str) -> dict:
    db.row_factory = sqlite3.Row
    row = db.execute(
        "SELECT scope_id, label, version, active FROM network_scopes WHERE scope_id = ?",
        (scope_id,),
    ).fetchone()
    if row is None:
        raise KeyError("Network Scope not found")
    if not row["active"]:
        raise ArkimeConnectorConflict("The selected Network Scope is archived")
    return dict(row)


def _validated_profile(payload: dict) -> dict:
    name = _text(payload.get("name"), "name", 120)
    scope_id = _text(payload.get("scope_id"), "scope_id", 200)
    sensor = _text(payload.get("operator_sensor"), "operator_sensor", 200)
    expression = _text(payload.get("query_expression", ""), "query_expression", 2000, blank=True)
    bounding = _text(payload.get("bounding_mode", "both"), "bounding_mode", 20).lower()
    if bounding not in {"first", "last", "both", "either"}:
        raise ArkimeConnectorError("bounding_mode must be first, last, both, or either")
    cadence = _integer(payload.get("cadence_minutes"), "cadence_minutes", 5, 1440)
    lookback = _integer(payload.get("lookback_minutes"), "lookback_minutes", 5, 10080)
    overlap = _integer(payload.get("overlap_minutes", 0), "overlap_minutes", 0, 1439)
    delay = _integer(payload.get("collection_delay_seconds", 60), "collection_delay_seconds", 0, 3600)
    if overlap >= cadence or overlap >= lookback:
        raise ArkimeConnectorError("overlap_minutes must be smaller than cadence and lookback")
    enabled = payload.get("enabled", False)
    if not isinstance(enabled, bool):
        raise ArkimeConnectorError("enabled must be true or false")
    return {
        "name": name, "scope_id": scope_id, "operator_sensor": sensor,
        "query_expression": expression, "bounding_mode": bounding,
        "cadence_minutes": cadence, "lookback_minutes": lookback,
        "overlap_minutes": overlap, "collection_delay_seconds": delay,
        "enabled": enabled,
    }


def create_pull_profile(db_path: Path, payload: dict, *, actor: str) -> dict:
    init_arkime_connector_storage(db_path)
    values = _validated_profile(payload)
    status = connector_status()
    if values["enabled"] and not status["configured"]:
        raise ArkimeConnectorUnavailable(status["detail"])
    profile_id = f"arkime_profile_{uuid.uuid4().hex}"
    now = _now()
    end = now - timedelta(seconds=values["collection_delay_seconds"])
    start = end - timedelta(minutes=values["lookback_minutes"])
    actor = _text(actor, "actor", 100)
    with connect_database(db_path) as db:
        db.execute("BEGIN IMMEDIATE")
        scope = _scope(db, values["scope_id"])
        db.execute(
            """INSERT INTO arkime_pull_profiles
               (profile_id,current_version,enabled,state,next_window_start,next_window_end,
                next_due_at,last_run_id,attention_detail,created_at,updated_at)
               VALUES (?,1,?,'ready',?,?,?,NULL,NULL,?,?)""",
            (profile_id, int(values["enabled"]), _time_text(start), _time_text(end),
             _time_text(now), _time_text(now), _time_text(now)),
        )
        db.execute(
            """INSERT INTO arkime_pull_profile_versions
               (profile_id,version,name,scope_id,scope_label,scope_version,operator_sensor,
                query_expression,bounding_mode,cadence_minutes,lookback_minutes,
                overlap_minutes,collection_delay_seconds,actor,created_at)
               VALUES (?,1,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (profile_id, values["name"], values["scope_id"], scope["label"], scope["version"],
             values["operator_sensor"], values["query_expression"], values["bounding_mode"],
             values["cadence_minutes"], values["lookback_minutes"], values["overlap_minutes"],
             values["collection_delay_seconds"], actor, _time_text(now)),
        )
        db.execute(
            "INSERT INTO arkime_pull_profile_events VALUES (?,?,?,?,?)",
            (f"arkime_profile_event_{uuid.uuid4().hex}", profile_id, "created", actor, _time_text(now)),
        )
    return get_pull_profile(db_path, profile_id)


def _profile_row(db: sqlite3.Connection, profile_id: str) -> sqlite3.Row:
    db.row_factory = sqlite3.Row
    row = db.execute(
        """SELECT p.*, v.* FROM arkime_pull_profiles p
           JOIN arkime_pull_profile_versions v
             ON v.profile_id=p.profile_id AND v.version=p.current_version
           WHERE p.profile_id=?""", (profile_id,),
    ).fetchone()
    if row is None:
        raise KeyError("Arkime pull profile not found")
    return row


def _profile_dict(row: sqlite3.Row) -> dict:
    return {
        "profile_id": row["profile_id"], "version": int(row["current_version"]),
        "name": row["name"], "scope_id": row["scope_id"], "scope_label": row["scope_label"],
        "scope_version": int(row["scope_version"]), "operator_sensor": row["operator_sensor"],
        "query_expression": row["query_expression"], "bounding_mode": row["bounding_mode"],
        "cadence_minutes": int(row["cadence_minutes"]),
        "lookback_minutes": int(row["lookback_minutes"]),
        "overlap_minutes": int(row["overlap_minutes"]),
        "collection_delay_seconds": int(row["collection_delay_seconds"]),
        "enabled": bool(row["enabled"]), "state": row["state"],
        "attention_detail": row["attention_detail"], "next_window_start": row["next_window_start"],
        "next_window_end": row["next_window_end"], "next_due_at": row["next_due_at"],
        "last_run_id": row["last_run_id"], "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def get_pull_profile(db_path: Path, profile_id: str) -> dict:
    with connect_database(db_path, read_only=True) as db:
        return _profile_dict(_profile_row(db, profile_id))


def list_pull_profiles(db_path: Path, *, limit: int = 25, offset: int = 0) -> dict:
    limit = _integer(limit, "limit", 1, MAX_PROFILE_PAGE)
    offset = _integer(offset, "offset", 0, 1_000_000_000)
    with connect_database(db_path, read_only=True) as db:
        db.row_factory = sqlite3.Row
        db.execute("BEGIN")
        total = int(db.execute("SELECT COUNT(*) FROM arkime_pull_profiles").fetchone()[0])
        rows = db.execute(
            """SELECT p.*,v.* FROM arkime_pull_profiles p JOIN arkime_pull_profile_versions v
               ON v.profile_id=p.profile_id AND v.version=p.current_version
               ORDER BY p.created_at,p.profile_id LIMIT ? OFFSET ?""", (limit, offset),
        ).fetchall()
    return {
        "items": [_profile_dict(row) for row in rows],
        "pagination": {
            "limit": limit, "offset": offset, "total": total,
            "has_more": offset + len(rows) < total,
        },
        "connector": connector_status(), "read_only": True,
    }


def set_pull_profile_enabled(db_path: Path, profile_id: str, *, enabled: bool, actor: str) -> dict:
    if not isinstance(enabled, bool):
        raise ArkimeConnectorError("enabled must be true or false")
    if enabled:
        status = connector_status()
        if not status["configured"]:
            raise ArkimeConnectorUnavailable(status["detail"])
    now = _time_text(_now())
    actor = _text(actor, "actor", 100)
    with connect_database(db_path) as db:
        db.execute("BEGIN IMMEDIATE")
        row = _profile_row(db, profile_id)
        if enabled and row["state"] == "attention":
            raise ArkimeConnectorConflict("Resolve or retry the attention-required window before resuming")
        db.execute(
            "UPDATE arkime_pull_profiles SET enabled=?,updated_at=? WHERE profile_id=?",
            (int(enabled), now, profile_id),
        )
        db.execute(
            "INSERT INTO arkime_pull_profile_events VALUES (?,?,?,?,?)",
            (
                f"arkime_profile_event_{uuid.uuid4().hex}", profile_id,
                "enabled" if enabled else "paused", actor, now,
            ),
        )
        if not enabled:
            db.execute(
                """UPDATE arkime_pull_runs
                   SET state='cancelled',cancel_requested=1,completed_at=?
                   WHERE profile_id=? AND request_kind='scheduled' AND state='queued'""",
                (now, profile_id),
            )
    return get_pull_profile(db_path, profile_id)


def _parameters(row: sqlite3.Row, start: str, end: str) -> dict[str, str]:
    return {
        "startTime": str(int(_parse_time(start).timestamp())),
        "stopTime": str(int(_parse_time(end).timestamp())),
        "bounding": row["bounding_mode"], "expression": row["query_expression"],
        "facets": "0", "length": str(MAX_PULL_SESSIONS), "start": "0",
        "fields": ARKIME_FIELDS, "order": "firstPacket:asc,rootId:asc",
    }


def _enqueue(db: sqlite3.Connection, row: sqlite3.Row, *, kind: str, actor: str,
             start: str, end: str, retry_of: str | None = None,
             advances_schedule: bool | None = None) -> str:
    config = ArkimeConnectorConfig.from_environment()
    if not config.enabled or not config.connector_id:
        raise ArkimeConnectorUnavailable("Arkime automatic pulls are not configured")
    scope = db.execute(
        "SELECT label, version, active FROM network_scopes WHERE scope_id=?",
        (row["scope_id"],),
    ).fetchone()
    if (
        scope is None or not scope[2] or scope[0] != row["scope_label"]
        or int(scope[1]) != int(row["scope_version"])
    ):
        raise ArkimeConnectorConflict(
            "The pull definition's frozen Network Scope changed; no Arkime contact was started"
        )
    active = db.execute(
        "SELECT 1 FROM arkime_pull_runs WHERE profile_id=? AND state IN ('queued','running') LIMIT 1",
        (row["profile_id"],),
    ).fetchone()
    if active:
        raise ArkimeConnectorConflict("This Arkime pull already has queued or running work")
    parameters = _parameters(row, start, end)
    if advances_schedule is None:
        advances_schedule = kind == "scheduled"
    run_id = f"arkime_pull_{uuid.uuid4().hex}"
    now = _time_text(_now())
    db.execute(
        """INSERT INTO arkime_pull_runs
           (run_id,profile_id,profile_version,request_kind,retry_of_run_id,state,scope_id,
            scope_label,scope_version,operator_sensor,query_expression,bounding_mode,
             query_start,query_end,connector_id,dataset_identity,connector_contract,parser_version,
             advances_schedule,request_parameters_json,actor,queued_at)
           VALUES (?,?,?,?,?,'queued',?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (run_id,row["profile_id"],row["current_version"],kind,retry_of,row["scope_id"],
         row["scope_label"],row["scope_version"],row["operator_sensor"],row["query_expression"],
         row["bounding_mode"],start,end,config.connector_id,
         config.dataset_identity or "unverified",ARKIME_CONNECTOR_CONTRACT,
         ARKIME_PARSER_VERSION,int(advances_schedule),
         json.dumps(parameters,sort_keys=True,separators=(",",":")),_text(actor,"actor",100),now),
    )
    db.execute(
        "UPDATE arkime_pull_profiles SET last_run_id=?,updated_at=? WHERE profile_id=?",
        (run_id, now, row["profile_id"]),
    )
    return run_id


def enqueue_pull_now(db_path: Path, profile_id: str, *, actor: str) -> dict:
    status = connector_status()
    if not status["configured"]:
        raise ArkimeConnectorUnavailable(status["detail"])
    with connect_database(db_path) as db:
        db.execute("BEGIN IMMEDIATE")
        row = _profile_row(db, profile_id)
        if row["state"] == "attention":
            raise ArkimeConnectorConflict(
                "Retry or resolve the saved attention-required window before starting a new pull"
            )
        end = _now() - timedelta(seconds=int(row["collection_delay_seconds"]))
        start = end - timedelta(minutes=int(row["lookback_minutes"]))
        run_id = _enqueue(db,row,kind="manual",actor=actor,start=_time_text(start),end=_time_text(end))
    _WORKER_WAKE.set()
    return get_pull_run(db_path, run_id)


def retry_pull_run(db_path: Path, run_id: str, *, actor: str) -> dict:
    with connect_database(db_path) as db:
        db.row_factory = sqlite3.Row
        db.execute("BEGIN IMMEDIATE")
        old = db.execute("SELECT * FROM arkime_pull_runs WHERE run_id=?",(run_id,)).fetchone()
        if old is None:
            raise KeyError("Arkime pull run not found")
        if old["state"] not in {"partial","failed","interrupted","cancelled"}:
            raise ArkimeConnectorConflict("Only incomplete or failed pulls can be retried")
        row = _profile_row(db, old["profile_id"])
        if old["advances_schedule"] and (
            row["next_window_start"] != old["query_start"]
            or row["next_window_end"] != old["query_end"]
        ):
            raise ArkimeConnectorConflict(
                "This scheduled window was already resolved; its older attempt cannot be retried"
            )
        new_id = _enqueue(
            db,row,kind="retry",actor=actor,start=old["query_start"],end=old["query_end"],
            retry_of=run_id,advances_schedule=bool(old["advances_schedule"]),
        )
    _WORKER_WAKE.set()
    return get_pull_run(db_path,new_id)


def cancel_pull_run(db_path: Path, run_id: str) -> dict:
    with connect_database(db_path) as db:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute(
            "SELECT state,profile_id FROM arkime_pull_runs WHERE run_id=?", (run_id,),
        ).fetchone()
        if row is None:
            raise KeyError("Arkime pull run not found")
        if row[0] == "queued":
            db.execute("UPDATE arkime_pull_runs SET state='cancelled',cancel_requested=1,completed_at=? WHERE run_id=?",(_time_text(_now()),run_id))
            db.execute(
                "UPDATE arkime_pull_profiles SET state='attention',attention_detail=?,updated_at=? "
                "WHERE profile_id=?",
                ("The latest window was cancelled; retry it before resuming", _time_text(_now()), row[1]),
            )
        elif row[0] == "running":
            db.execute("UPDATE arkime_pull_runs SET cancel_requested=1 WHERE run_id=?",(run_id,))
        elif row[0] not in FINAL_RUN_STATES:
            raise ArkimeConnectorConflict("The pull cannot be cancelled in its current state")
    _WORKER_WAKE.set()
    return get_pull_run(db_path,run_id)


def _run_dict(row: sqlite3.Row) -> dict:
    return {
        "run_id":row["run_id"],"profile_id":row["profile_id"],"profile_version":row["profile_version"],
        "request_kind":row["request_kind"],"retry_of_run_id":row["retry_of_run_id"],
        "state":row["state"],"scope_id":row["scope_id"],"scope_label":row["scope_label"],
        "scope_version":row["scope_version"],"operator_sensor":row["operator_sensor"],
        "query_expression":row["query_expression"],"bounding_mode":row["bounding_mode"],
        "query_start":row["query_start"],"query_end":row["query_end"],
        "connector_id":row["connector_id"],
        "dataset_identity":row["dataset_identity"],
        "connector_contract":row["connector_contract"],"parser_version":row["parser_version"],
        "advances_schedule":bool(row["advances_schedule"]),
        "request_parameters":json.loads(row["request_parameters_json"]),
        "actor":row["actor"],"queued_at":row["queued_at"],"started_at":row["started_at"],
        "completed_at":row["completed_at"],"cancel_requested":bool(row["cancel_requested"]),
        "import_id":row["import_id"],"error":row["error"],
    }


def get_pull_run(db_path: Path, run_id: str) -> dict:
    with connect_database(db_path,read_only=True) as db:
        db.row_factory=sqlite3.Row
        row=db.execute("SELECT * FROM arkime_pull_runs WHERE run_id=?",(run_id,)).fetchone()
    if row is None:
        raise KeyError("Arkime pull run not found")
    return _run_dict(row)


def list_pull_runs(db_path: Path, *, profile_id: str | None = None, limit: int = 50) -> dict:
    limit=_integer(limit,"limit",1,100)
    where=" WHERE profile_id=?" if profile_id else ""
    params=(profile_id,) if profile_id else ()
    with connect_database(db_path,read_only=True) as db:
        db.row_factory=sqlite3.Row
        rows=db.execute("SELECT * FROM arkime_pull_runs"+where+" ORDER BY queued_at DESC,run_id DESC LIMIT ?",(*params,limit)).fetchall()
    return {"items":[_run_dict(row) for row in rows],"read_only":True}


def recover_interrupted_pulls(db_path: Path) -> int:
    now=_time_text(_now())
    with connect_database(db_path) as db:
        db.execute("BEGIN IMMEDIATE")
        rows=db.execute("SELECT run_id,profile_id FROM arkime_pull_runs WHERE state='running'").fetchall()
        for run_id,profile_id in rows:
            db.execute("UPDATE arkime_pull_runs SET state='interrupted',completed_at=?,claim_token=NULL,error=? WHERE run_id=?",(now,"NCT stopped after Arkime contact began; retry explicitly with the same saved window",run_id))
            db.execute("UPDATE arkime_pull_profiles SET state='attention',attention_detail=?,updated_at=? WHERE profile_id=?",("A pull was interrupted; retry its saved window before resuming",now,profile_id))
    return len(rows)


def _queue_due(db_path: Path) -> None:
    now=_time_text(_now())
    with connect_database(db_path) as db:
        db.execute("BEGIN IMMEDIATE")
        db.row_factory=sqlite3.Row
        row=db.execute("""SELECT p.*,v.* FROM arkime_pull_profiles p
            JOIN arkime_pull_profile_versions v ON v.profile_id=p.profile_id AND v.version=p.current_version
            WHERE p.enabled=1 AND p.state='ready' AND p.next_due_at<=?
              AND NOT EXISTS(SELECT 1 FROM arkime_pull_runs r WHERE r.profile_id=p.profile_id AND r.state IN ('queued','running'))
            ORDER BY p.next_due_at,p.profile_id LIMIT 1""",(now,)).fetchone()
        if row is not None:
            try:
                _enqueue(
                    db, row, kind="scheduled", actor="arkime-scheduler",
                    start=row["next_window_start"], end=row["next_window_end"],
                )
            except ArkimeConnectorError as exc:
                db.execute(
                    "UPDATE arkime_pull_profiles SET state='attention',attention_detail=?,updated_at=? "
                    "WHERE profile_id=?", (str(exc), now, row["profile_id"]),
                )


def _claim(db_path: Path) -> tuple[dict,str] | None:
    token=secrets.token_hex(16); now=_time_text(_now())
    with connect_database(db_path) as db:
        db.row_factory=sqlite3.Row; db.execute("BEGIN IMMEDIATE")
        row=db.execute("""SELECT r.* FROM arkime_pull_runs r
            JOIN arkime_pull_profiles p ON p.profile_id=r.profile_id
            WHERE r.state='queued'
              AND (r.request_kind!='scheduled' OR (p.enabled=1 AND p.state='ready'))
            ORDER BY r.queued_at,r.run_id LIMIT 1""").fetchone()
        if row is None:return None
        if row["cancel_requested"]:
            db.execute("UPDATE arkime_pull_runs SET state='cancelled',completed_at=? WHERE run_id=?",(now,row["run_id"]));return None
        changed=db.execute("UPDATE arkime_pull_runs SET state='running',claim_token=?,started_at=? WHERE run_id=? AND state='queued'",(token,now,row["run_id"])).rowcount
        if changed!=1:return None
        result=dict(row);result["state"]="running";result["claim_token"]=token;result["started_at"]=now
        return result,token


def _finish_failure(db_path: Path, run: dict, token: str, message: str) -> None:
    detail=_text(message,"error",500)
    now=_time_text(_now())
    with connect_database(db_path) as db:
        db.execute("BEGIN IMMEDIATE")
        current=db.execute("SELECT state,claim_token,cancel_requested FROM arkime_pull_runs WHERE run_id=?",(run["run_id"],)).fetchone()
        if current is None or current[0]!="running" or current[1]!=token:return
        state="cancelled" if current[2] else "failed"
        db.execute("UPDATE arkime_pull_runs SET state=?,completed_at=?,claim_token=NULL,error=? WHERE run_id=?",(state,now,None if state=="cancelled" else detail,run["run_id"]))
        db.execute("UPDATE arkime_pull_profiles SET state='attention',attention_detail=?,updated_at=? WHERE profile_id=?",("The latest window was cancelled" if state=="cancelled" else detail,now,run["profile_id"]))


def _publish(db_path: Path, run: dict, token: str, content: bytes) -> None:
    parsed=parse_arkime_sessions_json(content,query_start=run["query_start"],query_end=run["query_end"],bounding_mode=run["bounding_mode"])
    if len(parsed["sessions"]) > MAX_PULL_SESSIONS:
        raise ArkimeConnectorConflict(
            "Arkime returned more than the 1,000-session connector limit; no evidence was published"
        )
    completeness=parsed["calculated_export_completeness"]
    assessment=completeness if completeness in {"complete","partial"} else "unknown"
    now=_now();now_text=_time_text(now)
    with evidence_mutation(db_path):
        with connect_database(db_path) as db:
            db.execute("BEGIN IMMEDIATE")
            current=db.execute("SELECT state,claim_token,cancel_requested FROM arkime_pull_runs WHERE run_id=?",(run["run_id"],)).fetchone()
            if current is None or current[0]!="running" or current[1]!=token:
                raise ArkimeConnectorConflict("Arkime pull claim changed before evidence publication")
            if current[2]:
                db.execute("UPDATE arkime_pull_runs SET state='cancelled',completed_at=?,claim_token=NULL WHERE run_id=?",(now_text,run["run_id"]))
                db.execute("UPDATE arkime_pull_profiles SET state='attention',attention_detail=?,updated_at=? WHERE profile_id=?",("The latest window was cancelled",now_text,run["profile_id"]))
                return
            scope=db.execute("SELECT label,version,active FROM network_scopes WHERE scope_id=?",(run["scope_id"],)).fetchone()
            if scope is None or not scope[2] or scope[0]!=run["scope_label"] or int(scope[1])!=int(run["scope_version"]):
                raise ArkimeConnectorConflict("The frozen Network Scope changed before evidence publication")
            result=import_arkime_sessions_json(
                db_path,content=content,original_filename=f"arkime-api-{run['run_id']}.json",media_type="application/json",
                scope_id=run["scope_id"],operator_sensor=run["operator_sensor"],query_start=run["query_start"],query_end=run["query_end"],
                bounding_mode=run["bounding_mode"],operator_export_assessment=assessment,capture_coverage="unknown",
                query_expression=run["query_expression"],actor=run["actor"],connection=db,
                source_metadata={"import_tier":"tier_e_sessions_api","pull_run_id":run["run_id"],"connector_id":run["connector_id"],"dataset_identity":run["dataset_identity"],"connector_contract":run["connector_contract"],"parser_version":run["parser_version"],"request_parameters":json.loads(run["request_parameters_json"]),"exact_bytes":"decoded HTTP entity; transfer framing removed; content encoding identity"},
            )
            final="complete" if completeness=="complete" else "partial"
            db.execute("UPDATE arkime_pull_runs SET state=?,completed_at=?,claim_token=NULL,import_id=? WHERE run_id=?",(final,now_text,result["import_id"],run["run_id"]))
            profile=db.execute(
                "SELECT next_window_start,next_window_end FROM arkime_pull_profiles WHERE profile_id=?",
                (run["profile_id"],),
            ).fetchone()
            if (
                final=="complete" and run["advances_schedule"]
                and profile is not None and profile[0] == run["query_start"]
                and profile[1] == run["query_end"]
            ):
                end=_parse_time(run["query_end"]); cadence=int(db.execute("SELECT cadence_minutes FROM arkime_pull_profile_versions WHERE profile_id=? AND version=?",(run["profile_id"],run["profile_version"])).fetchone()[0]); overlap=int(db.execute("SELECT overlap_minutes FROM arkime_pull_profile_versions WHERE profile_id=? AND version=?",(run["profile_id"],run["profile_version"])).fetchone()[0]); delay=int(db.execute("SELECT collection_delay_seconds FROM arkime_pull_profile_versions WHERE profile_id=? AND version=?",(run["profile_id"],run["profile_version"])).fetchone()[0]); next_start=end-timedelta(minutes=overlap); next_end=end+timedelta(minutes=cadence); due=max(now+timedelta(minutes=cadence),next_end+timedelta(seconds=delay));db.execute("UPDATE arkime_pull_profiles SET state='ready',attention_detail=NULL,next_window_start=?,next_window_end=?,next_due_at=?,updated_at=? WHERE profile_id=? AND next_window_start=? AND next_window_end=?",(_time_text(next_start),_time_text(next_end),_time_text(due),now_text,run["profile_id"],run["query_start"],run["query_end"]))
            elif final=="complete":
                db.execute(
                    "UPDATE arkime_pull_profiles SET state='ready',attention_detail=NULL,updated_at=? "
                    "WHERE profile_id=?", (now_text, run["profile_id"]),
                )
            elif final=="partial":
                detail = (
                    "Arkime reported more matching sessions than the bounded response contained; "
                    "retry or review before continuing"
                    if completeness == "partial"
                    else "Arkime did not report the total matching-session count; review this retained "
                    "window before continuing"
                )
                db.execute(
                    "UPDATE arkime_pull_profiles SET state='attention',attention_detail=?,updated_at=? "
                    "WHERE profile_id=?", (detail, now_text, run["profile_id"]),
                )


def _verify_scope_before_contact(db_path: Path, run: dict) -> None:
    with connect_database(db_path, read_only=True) as db:
        scope = db.execute(
            "SELECT label, version, active FROM network_scopes WHERE scope_id=?",
            (run["scope_id"],),
        ).fetchone()
    if (
        scope is None or not scope[2] or scope[0] != run["scope_label"]
        or int(scope[1]) != int(run["scope_version"])
    ):
        raise ArkimeConnectorConflict(
            "The frozen Network Scope changed before Arkime contact; no request was sent"
        )


def execute_one_pull(db_path: Path, *, fetcher: Callable[[ArkimeConnectorConfig,dict[str,str]],bytes]=_fetch_sessions) -> bool:
    claimed=_claim(db_path)
    if claimed is None:return False
    run,token=claimed
    try:
        config=ArkimeConnectorConfig.from_environment()
        if config.connector_id!=run["connector_id"]:
            raise ArkimeConnectorConflict("Connector deployment identity changed after this pull was queued")
        if (config.dataset_identity or "unverified") != run["dataset_identity"]:
            raise ArkimeConnectorConflict("Arkime dataset identity changed after this pull was queued")
        if run["connector_contract"] != ARKIME_CONNECTOR_CONTRACT:
            raise ArkimeConnectorConflict(
                "The queued Arkime connector contract is not supported; no request was sent"
            )
        if run["parser_version"] != ARKIME_PARSER_VERSION:
            raise ArkimeConnectorConflict(
                "The queued Arkime parser version is not supported; no request was sent"
            )
        _verify_scope_before_contact(db_path, run)
        content=fetcher(config,json.loads(run["request_parameters_json"]))
        _publish(db_path,run,token,content)
    except Exception as exc:
        _finish_failure(db_path,run,token,str(exc) or exc.__class__.__name__)
    return True


_WORKER_THREAD: threading.Thread | None=None
_WORKER_STOP=threading.Event()
_WORKER_WAKE=threading.Event()
_WORKER_LOCK=threading.Lock()


def _worker(db_path: Path) -> None:
    while not _WORKER_STOP.is_set():
        try:
            _queue_due(db_path)
            worked=execute_one_pull(db_path)
        except Exception:
            worked=False
        if not worked:
            _WORKER_WAKE.wait(5)
            _WORKER_WAKE.clear()


def start_arkime_pull_worker(db_path: Path) -> bool:
    global _WORKER_THREAD
    with _WORKER_LOCK:
        if _WORKER_THREAD is not None and _WORKER_THREAD.is_alive():return False
        _WORKER_STOP.clear();_WORKER_WAKE.clear()
        _WORKER_THREAD=threading.Thread(target=_worker,args=(db_path,),daemon=True,name="arkime-pull-worker")
        _WORKER_THREAD.start();return True


def stop_arkime_pull_worker() -> bool:
    global _WORKER_THREAD
    with _WORKER_LOCK:
        thread=_WORKER_THREAD
        if thread is None:return True
        _WORKER_STOP.set();_WORKER_WAKE.set();_stop_active_transport();thread.join(timeout=5)
        stopped=not thread.is_alive()
        if stopped:_WORKER_THREAD=None
        return stopped
