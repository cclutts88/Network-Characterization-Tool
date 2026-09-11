from __future__ import annotations

import ipaddress
import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, field_validator


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def normalize_cidr(value: str) -> tuple[str, bool]:
    token = value.strip()
    try:
        network = ipaddress.ip_network(token, strict=False)
    except ValueError as exc:
        raise ValueError(f"Invalid IPv4 CIDR: {token}") from exc
    if network.version != 4:
        raise ValueError("Saved Networks currently support IPv4 only")
    normalized = str(network)
    return normalized, normalized != token


def _clean_tags(values: list[str]) -> list[str]:
    cleaned: list[str] = []
    seen: set[str] = set()
    for value in values:
        tag = value.strip()
        key = tag.casefold()
        if tag and key not in seen:
            cleaned.append(tag)
            seen.add(key)
    return cleaned


class SavedNetworkCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=100)
    cidr: str = Field(min_length=1, max_length=64)
    description: str = Field(default="", max_length=500)
    category: str = Field(default="", max_length=100)
    tags: list[str] = Field(default_factory=list, max_length=30)
    created_by: str = Field(min_length=1, max_length=100)

    @field_validator("name", "cidr", "created_by")
    @classmethod
    def clean_required_text(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("Value cannot be blank")
        return cleaned

    @field_validator("description", "category")
    @classmethod
    def clean_text(cls, value: str) -> str:
        return value.strip()

    @field_validator("tags")
    @classmethod
    def clean_tags(cls, value: list[str]) -> list[str]:
        return _clean_tags(value)


class SavedNetworkUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, min_length=1, max_length=100)
    cidr: str | None = Field(default=None, min_length=1, max_length=64)
    description: str | None = Field(default=None, max_length=500)
    category: str | None = Field(default=None, max_length=100)
    tags: list[str] | None = Field(default=None, max_length=30)
    updated_by: str = Field(min_length=1, max_length=100)

    @field_validator("name", "cidr", "updated_by")
    @classmethod
    def clean_required_optional_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("Value cannot be blank")
        return cleaned

    @field_validator("description", "category")
    @classmethod
    def clean_optional_text(cls, value: str | None) -> str | None:
        return value.strip() if value is not None else None

    @field_validator("tags")
    @classmethod
    def clean_optional_tags(cls, value: list[str] | None) -> list[str] | None:
        return _clean_tags(value) if value is not None else None


class SavedNetworkArchive(BaseModel):
    model_config = ConfigDict(extra="forbid")

    changed_by: str = Field(min_length=1, max_length=100)

    @field_validator("changed_by")
    @classmethod
    def clean_actor(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("Value cannot be blank")
        return cleaned


def init_saved_network_storage(db_path: Path) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(db_path) as db:
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS saved_networks (
                saved_network_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                cidr TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                category TEXT NOT NULL DEFAULT '',
                tags_json TEXT NOT NULL DEFAULT '[]',
                created_at TEXT NOT NULL,
                created_by TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                updated_by TEXT NOT NULL,
                active INTEGER NOT NULL DEFAULT 1
            )
            """
        )
        db.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS saved_networks_name_unique "
            "ON saved_networks(lower(name))"
        )
        db.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS saved_networks_cidr_unique "
            "ON saved_networks(cidr)"
        )


def _row_record(row: tuple | None) -> dict | None:
    if row is None:
        return None
    return {
        "saved_network_id": row[0],
        "name": row[1],
        "cidr": row[2],
        "description": row[3],
        "category": row[4],
        "tags": json.loads(row[5] or "[]"),
        "created_at": row[6],
        "created_by": row[7],
        "updated_at": row[8],
        "updated_by": row[9],
        "active": bool(row[10]),
    }


def _select_sql() -> str:
    return (
        "SELECT saved_network_id, name, cidr, description, category, tags_json, "
        "created_at, created_by, updated_at, updated_by, active FROM saved_networks"
    )


def get_saved_network(saved_network_id: str, db_path: Path) -> dict | None:
    init_saved_network_storage(db_path)
    with sqlite3.connect(db_path) as db:
        row = db.execute(
            f"{_select_sql()} WHERE saved_network_id = ?", (saved_network_id,)
        ).fetchone()
    return _row_record(row)


def _overlap_warnings(cidr: str, saved_network_id: str | None, db_path: Path) -> list[dict]:
    candidate = ipaddress.ip_network(cidr)
    with sqlite3.connect(db_path) as db:
        rows = db.execute(
            "SELECT saved_network_id, name, cidr FROM saved_networks WHERE active = 1"
        ).fetchall()
    return [
        {"saved_network_id": row[0], "name": row[1], "cidr": row[2]}
        for row in rows
        if row[0] != saved_network_id and candidate.overlaps(ipaddress.ip_network(row[2]))
    ]


def _with_warnings(record: dict, db_path: Path, *, normalized_from: str | None = None) -> dict:
    result = dict(record)
    warnings: list[dict] = []
    if normalized_from is not None and normalized_from != record["cidr"]:
        warnings.append(
            {
                "type": "normalized",
                "message": f"Host bits were normalized to {record['cidr']}",
                "entered_cidr": normalized_from,
            }
        )
    for overlap in _overlap_warnings(record["cidr"], record["saved_network_id"], db_path):
        warnings.append(
            {
                "type": "overlap",
                "message": f"Overlaps {overlap['name']} ({overlap['cidr']})",
                **overlap,
            }
        )
    result["warnings"] = warnings
    return result


def list_saved_networks(db_path: Path, *, include_archived: bool = False) -> list[dict]:
    init_saved_network_storage(db_path)
    where = "" if include_archived else " WHERE active = 1"
    with sqlite3.connect(db_path) as db:
        rows = db.execute(
            f"{_select_sql()}{where} ORDER BY active DESC, lower(name)"
        ).fetchall()
    return [_with_warnings(_row_record(row), db_path) for row in rows]


def _duplicate_message(exc: sqlite3.IntegrityError) -> str:
    message = str(exc).lower()
    if "cidr" in message:
        return "A Saved Network already uses this normalized CIDR"
    return "A Saved Network already uses this name"


def create_saved_network(request: SavedNetworkCreate, db_path: Path) -> dict:
    init_saved_network_storage(db_path)
    cidr, was_normalized = normalize_cidr(request.cidr)
    timestamp = utc_now()
    saved_network_id = uuid.uuid4().hex
    try:
        with sqlite3.connect(db_path) as db:
            db.execute(
                """
                INSERT INTO saved_networks (
                    saved_network_id, name, cidr, description, category, tags_json,
                    created_at, created_by, updated_at, updated_by, active
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
                """,
                (
                    saved_network_id,
                    request.name,
                    cidr,
                    request.description,
                    request.category,
                    json.dumps(request.tags),
                    timestamp,
                    request.created_by,
                    timestamp,
                    request.created_by,
                ),
            )
    except sqlite3.IntegrityError as exc:
        raise ValueError(_duplicate_message(exc)) from exc
    record = get_saved_network(saved_network_id, db_path)
    return _with_warnings(
        record,
        db_path,
        normalized_from=request.cidr if was_normalized else None,
    )


def update_saved_network(
    saved_network_id: str, request: SavedNetworkUpdate, db_path: Path
) -> dict:
    current = get_saved_network(saved_network_id, db_path)
    if current is None:
        raise KeyError("Saved Network not found")
    values = request.model_dump(exclude_unset=True)
    values.pop("updated_by", None)
    normalized_from: str | None = None
    if "cidr" in values:
        entered = values["cidr"]
        values["cidr"], changed = normalize_cidr(entered)
        if changed:
            normalized_from = entered
    updated = {**current, **values}
    updated["tags"] = _clean_tags(updated.get("tags") or [])
    timestamp = utc_now()
    try:
        with sqlite3.connect(db_path) as db:
            db.execute(
                """
                UPDATE saved_networks
                SET name = ?, cidr = ?, description = ?, category = ?, tags_json = ?,
                    updated_at = ?, updated_by = ?
                WHERE saved_network_id = ?
                """,
                (
                    updated["name"],
                    updated["cidr"],
                    updated["description"],
                    updated["category"],
                    json.dumps(updated["tags"]),
                    timestamp,
                    request.updated_by,
                    saved_network_id,
                ),
            )
    except sqlite3.IntegrityError as exc:
        raise ValueError(_duplicate_message(exc)) from exc
    return _with_warnings(
        get_saved_network(saved_network_id, db_path),
        db_path,
        normalized_from=normalized_from,
    )


def archive_saved_network(
    saved_network_id: str, request: SavedNetworkArchive, db_path: Path
) -> dict:
    current = get_saved_network(saved_network_id, db_path)
    if current is None:
        raise KeyError("Saved Network not found")
    timestamp = utc_now()
    with sqlite3.connect(db_path) as db:
        db.execute(
            """
            UPDATE saved_networks
            SET active = 0, updated_at = ?, updated_by = ?
            WHERE saved_network_id = ?
            """,
            (timestamp, request.changed_by, saved_network_id),
        )
    return _with_warnings(get_saved_network(saved_network_id, db_path), db_path)


def resolve_saved_network_targets(
    saved_network_ids: list[str],
    manual_targets: list[str],
    db_path: Path,
    *,
    max_addresses: int,
) -> tuple[list[str], list[dict], list[str]]:
    init_saved_network_storage(db_path)
    snapshots: list[dict] = []
    selected_cidrs: list[str] = []
    seen_ids: set[str] = set()
    for saved_network_id in saved_network_ids:
        if saved_network_id in seen_ids:
            continue
        seen_ids.add(saved_network_id)
        record = get_saved_network(saved_network_id, db_path)
        if record is None:
            raise ValueError(f"Saved Network not found: {saved_network_id}")
        if not record["active"]:
            raise ValueError(f"Saved Network is archived: {record['name']}")
        selected_cidrs.append(record["cidr"])
        snapshots.append(
            {
                "saved_network_id": record["saved_network_id"],
                "name": record["name"],
                "cidr": record["cidr"],
                "description": record["description"],
                "category": record["category"],
                "tags": list(record["tags"]),
            }
        )
    normalized_manual = [normalize_cidr(value)[0] for value in manual_targets if value.strip()]
    networks = [ipaddress.ip_network(value) for value in selected_cidrs + normalized_manual]
    collapsed = list(ipaddress.collapse_addresses(networks))
    if not collapsed:
        raise ValueError("Select a Saved Network or enter at least one manual target")
    if sum(network.num_addresses for network in collapsed) > max_addresses:
        raise ValueError(f"Target scope exceeds the {max_addresses}-address safety limit")
    return [str(network) for network in collapsed], snapshots, normalized_manual
