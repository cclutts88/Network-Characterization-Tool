"""Read-only inventory of exact saved calculation contract groups."""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Mapping

from app.database import connect_database
from app.derived_contracts import (
    DerivedResultContract,
    SUPPORTED_DERIVED_RESULT_CONTRACTS,
)
from app.derived_result_status import classify_calculation_contract


def _validated_limit_offset(limit: int, offset: int) -> None:
    if not isinstance(limit, int) or not 1 <= limit <= 100:
        raise ValueError("limit must be between 1 and 100")
    if not isinstance(offset, int) or offset < 0:
        raise ValueError("offset must be zero or greater")


def _typed_value(value: object) -> list[object]:
    if value is None:
        return ["null", None]
    if isinstance(value, bytes):
        return ["blob", base64.b64encode(value).decode("ascii")]
    if isinstance(value, str):
        return ["text", value]
    if isinstance(value, int):
        return ["integer", value]
    if isinstance(value, float):
        return ["real", value.hex()]
    return [type(value).__name__, repr(value)]


def _group_identity(values: tuple[object, object, object, object]) -> str:
    encoded = json.dumps(
        [_typed_value(value) for value in values],
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def _display_text(value: object, fallback: str) -> str:
    if isinstance(value, str) and value:
        return value
    return fallback


def _empty_page(limit: int, offset: int) -> dict:
    return {
        "items": [], "total_groups": 0, "limit": limit, "offset": offset,
        "has_more": False,
        "page_counts": {"CURRENT": 0, "STALE": 0, "UNKNOWN": 0},
    }


def list_version_groups(
    db_path: Path,
    *,
    limit: int = 25,
    offset: int = 0,
    contracts: Mapping[str, DerivedResultContract] = SUPPORTED_DERIVED_RESULT_CONTRACTS,
) -> dict:
    """Return one bounded page of exact retained contract groups."""
    _validated_limit_offset(limit, offset)
    if not db_path.is_file():
        return _empty_page(limit, offset)
    with connect_database(db_path, read_only=True) as db:
        db.execute("BEGIN")
        available = db.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'derived_results'"
        ).fetchone()
        if available is None:
            return _empty_page(limit, offset)
        total = int(db.execute(
            """SELECT COUNT(*) FROM (
                   SELECT 1 FROM derived_results
                   GROUP BY family, analysis_version,
                            payload_schema_version, parameters_json
               )"""
        ).fetchone()[0])
        rows = db.execute(
            """SELECT family, analysis_version, payload_schema_version,
                      parameters_json, COUNT(*), MIN(generated_at),
                      MAX(generated_at), MIN(result_id)
               FROM derived_results
               GROUP BY family, analysis_version,
                        payload_schema_version, parameters_json
               ORDER BY MAX(generated_at) DESC, family, analysis_version,
                        payload_schema_version, parameters_json, MIN(result_id)
               LIMIT ? OFFSET ?""",
            (limit, offset),
        ).fetchall()

    items = []
    counts = {"CURRENT": 0, "STALE": 0, "UNKNOWN": 0}
    for row in rows:
        values = (row[0], row[1], row[2], row[3])
        status = classify_calculation_contract(
            family=row[0],
            analysis_version=row[1],
            payload_schema_version=row[2],
            parameters_json=row[3],
            contracts=contracts,
        )
        counts[status["state"]] += 1
        settings_identity = hashlib.sha256(
            json.dumps(_typed_value(row[3]), separators=(",", ":")).encode()
        ).hexdigest()
        items.append({
            "group_id": _group_identity(values),
            "representative_result_id": row[7],
            "family": _display_text(row[0], "Unreadable calculation family"),
            "label": _display_text(status["label"], "Unknown calculation"),
            "analysis_version": _display_text(row[1], "Unreadable saved version"),
            "payload_schema_version": row[2] if isinstance(row[2], int) else None,
            "settings_fingerprint": settings_identity,
            "state": status["state"],
            "reasons": status["reasons"],
            "result_count": int(row[4]),
            "earliest_generated_at": row[5],
            "latest_generated_at": row[6],
        })
    return {
        "items": items,
        "total_groups": total,
        "limit": limit,
        "offset": offset,
        "has_more": offset + len(items) < total,
        "page_counts": counts,
    }


def list_version_group_results(
    db_path: Path,
    group_id: str,
    representative_result_id: str,
    *,
    limit: int = 25,
    offset: int = 0,
    contracts: Mapping[str, DerivedResultContract] = SUPPORTED_DERIVED_RESULT_CONTRACTS,
) -> dict:
    """Resolve an exact group from one retained member and page only that group."""
    _validated_limit_offset(limit, offset)
    if not isinstance(group_id, str) or len(group_id) != 64 or any(
        character not in "0123456789abcdef" for character in group_id
    ):
        raise ValueError("group_id must be a lowercase SHA-256 identity")
    if not isinstance(representative_result_id, str) or not representative_result_id:
        raise ValueError("representative_result_id is required")
    if not db_path.is_file():
        raise KeyError("Saved calculation version group is not available.")
    with connect_database(db_path, read_only=True) as db:
        db.execute("BEGIN")
        representative = db.execute(
            """SELECT family, analysis_version, payload_schema_version, parameters_json
               FROM derived_results WHERE result_id = ?""",
            (representative_result_id,),
        ).fetchone()
        if representative is None or _group_identity(tuple(representative)) != group_id:
            raise KeyError("Saved calculation version group is not available.")
        values = tuple(representative)
        total = int(db.execute(
            """SELECT COUNT(*) FROM derived_results
               WHERE family IS ? AND analysis_version IS ?
                 AND payload_schema_version IS ? AND parameters_json IS ?""",
            values,
        ).fetchone()[0])
        rows = db.execute(
            """SELECT result_id, generated_at FROM derived_results
               WHERE family IS ? AND analysis_version IS ?
                 AND payload_schema_version IS ? AND parameters_json IS ?
               ORDER BY generated_at DESC, result_id
               LIMIT ? OFFSET ?""",
            (*values, limit, offset),
        ).fetchall()

    status = classify_calculation_contract(
        family=values[0],
        analysis_version=values[1],
        payload_schema_version=values[2],
        parameters_json=values[3],
        contracts=contracts,
    )
    return {
        "group_id": group_id,
        "label": _display_text(status["label"], "Unknown calculation"),
        "state": status["state"],
        "reasons": status["reasons"],
        "items": [{"result_id": row[0], "generated_at": row[1]} for row in rows],
        "total": total,
        "limit": limit,
        "offset": offset,
        "has_more": offset + len(rows) < total,
    }
