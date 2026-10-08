from __future__ import annotations

import json
import re
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path

from app.database import connect_database, initialize_once_per_database
from app.network_scopes import init_network_scope_storage


PROFILE_SETTING_KEYS = {
    "vendor", "device_type", "device_types", "device_address", "device_name",
    "username", "ssh_port", "additional_commands", "preferred_scope_id",
}
DEVICE_TYPES_BY_VENDOR = {
    "vyos": {"router", "firewall"}, "cisco": {"router", "firewall", "switch"},
    "juniper": {"router", "firewall", "switch"}, "pfsense": {"router", "firewall"},
    "unifi": {"router", "firewall", "switch"},
}
HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,254}$")
USER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
SCOPE_RE = re.compile(r"^[A-Za-z0-9._:-]+$")
COMMAND_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._:/,=|?*+-]{0,199}$")
READ_ONLY_COMMAND_PREFIXES = {
    "show", "display", "get", "ping", "traceroute", "mtr", "cat",
    "netstat", "sockstat", "uptime", "uname", "dmesg",
}
READ_ONLY_FILTER_PREFIXES = {
    "include", "exclude", "match", "display", "grep", "egrep", "head",
    "tail", "count", "no-more",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


@initialize_once_per_database
def init_device_collection_profile_storage(db_path: Path) -> None:
    init_network_scope_storage(db_path)
    with connect_database(db_path) as db:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS device_collection_profile_roots (
                profile_id TEXT PRIMARY KEY,
                active_name TEXT NOT NULL,
                name_key TEXT NOT NULL,
                active_version INTEGER NOT NULL CHECK(active_version >= 1),
                created_at TEXT NOT NULL,
                created_by TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                updated_by TEXT NOT NULL,
                archived_at TEXT,
                archived_by TEXT
            );
            CREATE UNIQUE INDEX IF NOT EXISTS device_collection_profile_active_name
                ON device_collection_profile_roots(name_key)
                WHERE archived_at IS NULL;
            CREATE TABLE IF NOT EXISTS device_collection_profile_versions (
                profile_id TEXT NOT NULL,
                version INTEGER NOT NULL CHECK(version >= 1),
                name TEXT NOT NULL,
                description TEXT NOT NULL,
                created_at TEXT NOT NULL,
                created_by TEXT NOT NULL,
                settings_json TEXT NOT NULL,
                PRIMARY KEY(profile_id, version),
                FOREIGN KEY(profile_id) REFERENCES device_collection_profile_roots(profile_id)
            );
            CREATE TRIGGER IF NOT EXISTS device_collection_profile_versions_no_update
            BEFORE UPDATE ON device_collection_profile_versions
            BEGIN SELECT RAISE(ABORT, 'device collection profile versions are immutable'); END;
            CREATE TRIGGER IF NOT EXISTS device_collection_profile_versions_no_delete
            BEFORE DELETE ON device_collection_profile_versions
            BEGIN SELECT RAISE(ABORT, 'device collection profile versions are immutable'); END;
            CREATE TRIGGER IF NOT EXISTS device_collection_profile_roots_no_delete
            BEFORE DELETE ON device_collection_profile_roots
            BEGIN SELECT RAISE(ABORT, 'device collection profiles must be archived, not deleted'); END;
            CREATE TRIGGER IF NOT EXISTS device_collection_profile_roots_no_reactivate
            BEFORE UPDATE OF archived_at ON device_collection_profile_roots
            WHEN OLD.archived_at IS NOT NULL AND NEW.archived_at IS NULL
            BEGIN SELECT RAISE(ABORT, 'archived device collection profiles cannot be reactivated'); END;
            CREATE TRIGGER IF NOT EXISTS device_collection_profile_roots_identity_immutable
            BEFORE UPDATE OF profile_id, created_at, created_by ON device_collection_profile_roots
            BEGIN SELECT RAISE(ABORT, 'device collection profile identity is immutable'); END;
            CREATE TRIGGER IF NOT EXISTS device_collection_profile_roots_version_forward_only
            BEFORE UPDATE OF active_version ON device_collection_profile_roots
            WHEN NEW.active_version != OLD.active_version + 1
              OR NOT EXISTS (
                  SELECT 1 FROM device_collection_profile_versions v
                  WHERE v.profile_id = OLD.profile_id
                    AND v.version = NEW.active_version
                    AND v.name = NEW.active_name
                    AND v.created_at = NEW.updated_at
                    AND v.created_by = NEW.updated_by
              )
            BEGIN SELECT RAISE(ABORT, 'device collection profile version pointer must advance to its matching immutable version'); END;
            CREATE TRIGGER IF NOT EXISTS device_collection_profile_roots_metadata_requires_version
            BEFORE UPDATE OF active_name, name_key, updated_at, updated_by
            ON device_collection_profile_roots
            WHEN NEW.active_version = OLD.active_version
              AND NEW.archived_at IS OLD.archived_at
            BEGIN SELECT RAISE(ABORT, 'device collection profile metadata changes require a new version'); END;
            CREATE TRIGGER IF NOT EXISTS device_collection_profile_roots_archive_once
            BEFORE UPDATE OF archived_at, archived_by ON device_collection_profile_roots
            WHEN OLD.archived_at IS NOT NULL
              OR NEW.archived_at IS NULL OR NEW.archived_by IS NULL
              OR NEW.active_version != OLD.active_version
              OR NEW.active_name != OLD.active_name OR NEW.name_key != OLD.name_key
            BEGIN SELECT RAISE(ABORT, 'device collection profile archive metadata is immutable'); END;
            CREATE TRIGGER IF NOT EXISTS device_collection_profile_roots_archived_immutable
            BEFORE UPDATE ON device_collection_profile_roots
            WHEN OLD.archived_at IS NOT NULL
            BEGIN SELECT RAISE(ABORT, 'archived device collection profiles are immutable'); END;
            """
        )


def _snapshot(row) -> dict | None:
    if row is None:
        return None
    return {
        "profile_id": row["profile_id"], "version": int(row["version"]),
        "current_version": int(row["active_version"]),
        "name": row["name"], "description": row["description"],
        "created_at": row["version_created_at"], "created_by": row["version_created_by"],
        "updated_at": row["updated_at"], "updated_by": row["updated_by"],
        "active": row["archived_at"] is None,
        "archived_at": row["archived_at"], "archived_by": row["archived_by"],
        "settings": json.loads(row["settings_json"]),
    }


def _select_sql(version_clause: str) -> str:
    return f"""SELECT r.profile_id, r.active_version, r.updated_at, r.updated_by, r.archived_at,
                      r.archived_by, v.version, v.name, v.description,
                      v.created_at AS version_created_at,
                      v.created_by AS version_created_by, v.settings_json
               FROM device_collection_profile_roots r
               JOIN device_collection_profile_versions v
                 ON v.profile_id = r.profile_id AND {version_clause}"""


def _validated_settings_payload(settings: dict) -> dict:
    if not isinstance(settings, dict):
        raise ValueError("Device collection profile settings must be an object")
    unknown = set(settings) - PROFILE_SETTING_KEYS
    missing = PROFILE_SETTING_KEYS - set(settings)
    if unknown or missing:
        raise ValueError("Device collection profiles accept only the approved non-secret settings")
    value = dict(settings)
    vendor, device_type = value["vendor"], value["device_type"]
    roles = value["device_types"]
    if vendor not in DEVICE_TYPES_BY_VENDOR or device_type not in DEVICE_TYPES_BY_VENDOR[vendor]:
        raise ValueError("Choose a supported vendor and device type")
    if not isinstance(roles, list) or not 1 <= len(roles) <= 2 or len(set(roles)) != len(roles):
        raise ValueError("Choose one or two unique supported device roles")
    if any(role not in DEVICE_TYPES_BY_VENDOR[vendor] for role in roles):
        raise ValueError("Choose supported device roles for this vendor")
    if "switch" in roles and len(roles) > 1:
        raise ValueError("Switch collection cannot be combined with Router or Firewall")
    if device_type != ("firewall" if set(roles) == {"router", "firewall"} else roles[0]):
        raise ValueError("The primary device type does not match the selected roles")
    if not isinstance(value["device_address"], str) or not HOST_RE.fullmatch(value["device_address"]):
        raise ValueError("Use a valid hostname or IP address")
    device_name = value["device_name"]
    if device_name is not None and (not isinstance(device_name, str) or len(device_name) > 100):
        raise ValueError("Device name is limited to 100 characters")
    if not isinstance(value["username"], str) or not USER_RE.fullmatch(value["username"]):
        raise ValueError("Use a valid SSH username")
    if isinstance(value["ssh_port"], bool) or not isinstance(value["ssh_port"], int) or not 1 <= value["ssh_port"] <= 65535:
        raise ValueError("SSH port must be between 1 and 65535")
    commands = value["additional_commands"]
    if not isinstance(commands, list) or len(commands) > 20:
        raise ValueError("Additional commands must be a list of at most 20 commands")
    cleaned_commands = []
    for command in commands:
        if not isinstance(command, str) or not COMMAND_RE.fullmatch(command):
            raise ValueError("Additional commands must use safe read-only syntax")
        pipeline = [segment.strip() for segment in command.split("|")]
        if any(not segment for segment in pipeline):
            raise ValueError("Additional command pipelines cannot contain an empty step")
        if pipeline[0].split(maxsplit=1)[0].lower() not in READ_ONLY_COMMAND_PREFIXES:
            raise ValueError("Additional commands must start with a supported read-only command")
        if any(
            step.split(maxsplit=1)[0].lower() not in READ_ONLY_FILTER_PREFIXES
            for step in pipeline[1:]
        ):
            raise ValueError("Additional command pipelines must use supported read-only filters")
        if command not in cleaned_commands:
            cleaned_commands.append(command)
    value["additional_commands"] = cleaned_commands
    scope_id = value["preferred_scope_id"]
    if scope_id is not None and (not isinstance(scope_id, str) or not SCOPE_RE.fullmatch(scope_id)):
        raise ValueError("Choose a valid Network Scope")
    return value


def _validated_settings_in_db(db, settings: dict) -> dict:
    settings = _validated_settings_payload(settings)
    scope_id = settings.get("preferred_scope_id")
    if not scope_id:
        settings["preferred_scope_label"] = None
        return settings
    row = db.execute(
        "SELECT label, active FROM network_scopes WHERE scope_id = ?", (scope_id,)
    ).fetchone()
    if row is None or not bool(row[1]):
        raise ValueError("The preferred Network Scope does not exist or is archived")
    settings["preferred_scope_label"] = str(row[0])
    return settings


def get_device_collection_profile(
    db_path: Path, profile_id: str, version: int | None = None,
) -> dict | None:
    init_device_collection_profile_storage(db_path)
    with connect_database(db_path, read_only=True) as db:
        db.row_factory = sqlite3.Row
        if version is None:
            row = db.execute(
                _select_sql("v.version = r.active_version") + " WHERE r.profile_id = ?",
                (profile_id,),
            ).fetchone()
        else:
            row = db.execute(
                _select_sql("v.version = ?") + " WHERE r.profile_id = ?",
                (version, profile_id),
            ).fetchone()
    return _snapshot(row)


def list_device_collection_profiles(
    db_path: Path, *, include_archived: bool = False,
) -> list[dict]:
    init_device_collection_profile_storage(db_path)
    with connect_database(db_path, read_only=True) as db:
        db.row_factory = sqlite3.Row
        where = "" if include_archived else " WHERE r.archived_at IS NULL"
        rows = db.execute(
            _select_sql("v.version = r.active_version") + where
            + " ORDER BY r.archived_at IS NOT NULL, r.name_key, r.profile_id"
        ).fetchall()
    return [_snapshot(row) for row in rows]


def create_device_collection_profile(
    db_path: Path, *, name: str, description: str, created_by: str, settings: dict,
) -> dict:
    init_device_collection_profile_storage(db_path)
    profile_id, timestamp = f"device_profile_{uuid.uuid4().hex}", utc_now()
    try:
        with connect_database(db_path) as db:
            db.execute("BEGIN IMMEDIATE")
            settings = _validated_settings_in_db(db, settings)
            db.execute(
                """INSERT INTO device_collection_profile_roots (
                       profile_id, active_name, name_key, active_version,
                       created_at, created_by, updated_at, updated_by
                   ) VALUES (?, ?, ?, 1, ?, ?, ?, ?)""",
                (profile_id, name, name.casefold(), timestamp, created_by, timestamp, created_by),
            )
            db.execute(
                """INSERT INTO device_collection_profile_versions (
                       profile_id, version, name, description, created_at,
                       created_by, settings_json
                   ) VALUES (?, 1, ?, ?, ?, ?, ?)""",
                (profile_id, name, description, timestamp, created_by,
                 json.dumps(settings, sort_keys=True)),
            )
    except sqlite3.IntegrityError as exc:
        if "device_collection_profile" in str(exc):
            raise ValueError("An active device collection profile already uses this name") from exc
        raise
    return get_device_collection_profile(db_path, profile_id, 1)


def create_device_collection_profile_version(
    db_path: Path, *, profile_id: str, expected_version: int, name: str,
    description: str, created_by: str, settings: dict,
) -> dict:
    init_device_collection_profile_storage(db_path)
    timestamp, next_version = utc_now(), expected_version + 1
    try:
        with connect_database(db_path) as db:
            db.execute("BEGIN IMMEDIATE")
            root = db.execute(
                "SELECT active_version, archived_at FROM device_collection_profile_roots WHERE profile_id = ?",
                (profile_id,),
            ).fetchone()
            if root is None:
                raise KeyError("Device collection profile not found")
            if root[1] is not None:
                raise ValueError("Archived device collection profiles cannot be changed")
            if int(root[0]) != expected_version:
                raise ValueError("The device collection profile changed in another session")
            settings = _validated_settings_in_db(db, settings)
            db.execute(
                """INSERT INTO device_collection_profile_versions (
                       profile_id, version, name, description, created_at,
                       created_by, settings_json
                   ) VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (profile_id, next_version, name, description, timestamp, created_by,
                 json.dumps(settings, sort_keys=True)),
            )
            changed = db.execute(
                """UPDATE device_collection_profile_roots
                   SET active_name = ?, name_key = ?, active_version = ?,
                       updated_at = ?, updated_by = ?
                   WHERE profile_id = ? AND active_version = ? AND archived_at IS NULL""",
                (name, name.casefold(), next_version, timestamp, created_by,
                 profile_id, expected_version),
            ).rowcount
            if changed != 1:
                raise ValueError("The device collection profile changed in another session")
    except sqlite3.IntegrityError as exc:
        if "device_collection_profile" in str(exc):
            raise ValueError("An active device collection profile already uses this name") from exc
        raise
    return get_device_collection_profile(db_path, profile_id, next_version)


def archive_device_collection_profile(
    db_path: Path, *, profile_id: str, expected_version: int, archived_by: str,
) -> dict:
    init_device_collection_profile_storage(db_path)
    timestamp = utc_now()
    with connect_database(db_path) as db:
        db.execute("BEGIN IMMEDIATE")
        changed = db.execute(
            """UPDATE device_collection_profile_roots
               SET archived_at = ?, archived_by = ?, updated_at = ?, updated_by = ?
               WHERE profile_id = ? AND active_version = ? AND archived_at IS NULL""",
            (timestamp, archived_by, timestamp, archived_by, profile_id, expected_version),
        ).rowcount
        if changed != 1:
            row = db.execute(
                "SELECT active_version, archived_at FROM device_collection_profile_roots WHERE profile_id = ?",
                (profile_id,),
            ).fetchone()
            if row is None:
                raise KeyError("Device collection profile not found")
            if row[1] is not None:
                raise ValueError("Device collection profile is already archived")
            raise ValueError("The device collection profile changed in another session")
    return get_device_collection_profile(db_path, profile_id, expected_version)
