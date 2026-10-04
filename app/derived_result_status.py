"""Read-only calculation-contract status for retained reusable results."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Mapping

from app.database import connect_database
from app.derived_contracts import (
    DerivedResultContract,
    SUPPORTED_DERIVED_RESULT_CONTRACTS,
)


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate calculation setting")
        result[key] = value
    return result


def classify_calculation_contract(
    *,
    family: object,
    analysis_version: object,
    payload_schema_version: object,
    parameters_json: object,
    contracts: Mapping[str, DerivedResultContract] = SUPPORTED_DERIVED_RESULT_CONTRACTS,
) -> dict:
    """Classify only compatibility with the running calculation contract."""
    contract = contracts.get(family) if isinstance(family, str) else None
    if contract is None:
        return {
            "state": "UNKNOWN",
            "label": family or "Unknown calculation",
            "reasons": ["This build does not recognize the saved calculation family."],
            "expected": None,
        }
    expected = {
        "analysis_version": contract.analysis_version,
        "payload_schema_version": contract.payload_schema_version,
        "parameters": dict(contract.parameters),
    }
    if (
        not isinstance(analysis_version, str)
        or not analysis_version
        or isinstance(payload_schema_version, bool)
        or not isinstance(payload_schema_version, int)
        or not isinstance(parameters_json, str)
    ):
        return {
            "state": "UNKNOWN",
            "label": contract.label,
            "reasons": ["The saved calculation contract is unreadable."],
            "expected": expected,
        }
    try:
        parameters = json.loads(parameters_json, object_pairs_hook=_reject_duplicate_keys)
        if not isinstance(parameters, dict):
            raise ValueError("settings are not an object")
        canonical_parameters = _canonical_json(parameters)
    except (json.JSONDecodeError, RecursionError, TypeError, ValueError):
        return {
            "state": "UNKNOWN",
            "label": contract.label,
            "reasons": ["The saved calculation settings are unreadable."],
            "expected": expected,
        }

    reasons = []
    if analysis_version != contract.analysis_version:
        reasons.append(
            f"Saved rule version {analysis_version} differs from "
            f"{contract.analysis_version}."
        )
    if payload_schema_version != contract.payload_schema_version:
        reasons.append(
            f"Saved output format {payload_schema_version} differs from "
            f"{contract.payload_schema_version}."
        )
    if canonical_parameters != _canonical_json(dict(contract.parameters)):
        reasons.append("Saved calculation settings differ from this build.")
    return {
        "state": "STALE" if reasons else "CURRENT",
        "label": contract.label,
        "reasons": reasons or ["Saved calculation rules match this build."],
        "expected": expected,
    }


def list_derived_result_status(
    db_path: Path,
    *,
    limit: int = 25,
    offset: int = 0,
    contracts: Mapping[str, DerivedResultContract] = SUPPORTED_DERIVED_RESULT_CONTRACTS,
) -> dict:
    """Return one bounded page without initializing storage or writing status flags."""
    if not isinstance(limit, int) or not 1 <= limit <= 100:
        raise ValueError("limit must be between 1 and 100")
    if not isinstance(offset, int) or offset < 0:
        raise ValueError("offset must be zero or greater")
    if not db_path.is_file():
        return {
            "items": [], "total": 0, "limit": limit, "offset": offset,
            "has_more": False, "page_counts": {"CURRENT": 0, "STALE": 0, "UNKNOWN": 0},
        }
    with connect_database(db_path, read_only=True) as db:
        db.execute("BEGIN")
        available = db.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'derived_results'"
        ).fetchone()
        if available is None:
            return {
                "items": [], "total": 0, "limit": limit, "offset": offset,
                "has_more": False,
                "page_counts": {"CURRENT": 0, "STALE": 0, "UNKNOWN": 0},
            }
        total = int(db.execute("SELECT COUNT(*) FROM derived_results").fetchone()[0])
        rows = db.execute(
            """SELECT result_id, family, analysis_version, payload_schema_version,
                      parameters_json, generated_at
               FROM derived_results
               ORDER BY generated_at DESC, result_id
               LIMIT ? OFFSET ?""",
            (limit, offset),
        ).fetchall()

    items = []
    counts = {"CURRENT": 0, "STALE": 0, "UNKNOWN": 0}
    for row in rows:
        status = classify_calculation_contract(
            family=row[1],
            analysis_version=row[2],
            payload_schema_version=row[3],
            parameters_json=row[4],
            contracts=contracts,
        )
        counts[status["state"]] += 1
        items.append({
            "result_id": row[0],
            "family": row[1],
            "label": status["label"],
            "state": status["state"],
            "reasons": status["reasons"],
            "analysis_version": row[2],
            "payload_schema_version": row[3],
            "generated_at": row[5],
            "expected": status["expected"],
        })
    return {
        "items": items,
        "total": total,
        "limit": limit,
        "offset": offset,
        "has_more": offset + len(items) < total,
        "page_counts": counts,
    }
