from __future__ import annotations

import json
import sqlite3
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path

from app.database import connect_database
from app.device_configs import normalize_command_for_attribution


ATTRIBUTION_ASSESSMENT_VERSION = 1
TIMESTAMP_WINDOW_SECONDS = 10 * 60
UNTIMED_LOOKBACK_SECONDS = 7 * 24 * 60 * 60


def _instant(value: object) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def _active_semantics(db_path: Path) -> list[dict]:
    try:
        with connect_database(db_path) as db:
            rows = db.execute(
                """SELECT run_id, semantic_manifest_json, semantic_manifest_sha256
                   FROM device_collection_authority
                   WHERE state = 'active' AND semantic_manifest_json IS NOT NULL"""
            ).fetchall()
    except sqlite3.OperationalError:
        return []
    result = []
    for run_id, raw, semantic_sha256 in rows:
        try:
            semantics = json.loads(raw)
        except (TypeError, json.JSONDecodeError):
            continue
        if isinstance(semantics, dict):
            result.append({
                "run_id": str(run_id),
                "semantic_sha256": str(semantic_sha256 or ""),
                "semantics": semantics,
            })
    return result


def _receipt_ref(source: dict, receipt: dict) -> dict:
    return {
        "receipt_id": str(receipt.get("receipt_id") or ""),
        "run_id": source["run_id"],
        "semantic_sha256": source["semantic_sha256"],
        "sequence": receipt.get("sequence"),
        "contact_started_at": receipt.get("contact_started_at"),
        "contact_completed_at": receipt.get("contact_completed_at"),
        "execution_status": receipt.get("execution_status"),
        "acknowledgement": receipt.get("acknowledgement"),
        "device_identity": receipt.get("device_identity"),
    }


def _candidate_receipts(
    sources: list[dict], current: dict, entry: dict, used: set[str]
) -> list[tuple[float, dict, dict, str]]:
    semantics = current["semantics"]
    identity = semantics.get("device_identity")
    current_start = _instant(semantics.get("contact_started_at"))
    if not isinstance(identity, dict) or current_start is None:
        return []
    command = normalize_command_for_attribution(entry.get("command") or "")
    observed = (
        _instant(entry.get("observed_at"))
        if entry.get("timestamp_assumption") == "absolute"
        else None
    )
    candidates = []
    for source in sources:
        source_semantics = source["semantics"]
        if source["run_id"] == current["run_id"]:
            continue
        if source_semantics.get("device_identity") != identity:
            continue
        for receipt in source_semantics.get("command_execution_receipts") or []:
            if not isinstance(receipt, dict):
                continue
            receipt_id = str(receipt.get("receipt_id") or "")
            if not receipt_id or receipt_id in used:
                continue
            if receipt.get("execution_status") != "sent_in_completed_authenticated_session":
                continue
            if normalize_command_for_attribution(
                receipt.get("command") or ""
            ) != command:
                continue
            completed = _instant(receipt.get("contact_completed_at"))
            if completed is None or completed > current_start:
                continue
            if observed is not None:
                distance = abs((observed - completed).total_seconds())
                if distance > TIMESTAMP_WINDOW_SECONDS:
                    continue
                timing = "absolute_history_time_within_10_minutes"
            else:
                distance = (current_start - completed).total_seconds()
                if distance < 0 or distance > UNTIMED_LOOKBACK_SECONDS:
                    continue
                timing = "untimed_history_within_7_day_review_window"
            candidates.append((distance, source, receipt, timing))
    return sorted(candidates, key=lambda item: (item[0], item[1]["run_id"], item[2].get("sequence") or 0))


def assess_command_attribution(
    history: dict,
    *,
    run_id: str,
    db_path: Path,
    history_truncated: bool = False,
) -> dict:
    """Add a current, read-only attribution assessment to immutable history facts."""
    result = deepcopy(history or {})
    sources = _active_semantics(db_path)
    current = next((item for item in sources if item["run_id"] == run_id), None)
    used: set[str] = set()
    linked_receipts = 0
    for entry in result.get("entries") or []:
        candidates = _candidate_receipts(sources, current, entry, used) if current else []
        explicit = str(entry.get("occurrence_receipt_id") or "")
        selected = next(
            (
                candidate for candidate in candidates
                if explicit and candidate[2].get("receipt_id") == explicit
            ),
            candidates[0] if candidates else None,
        )
        if selected:
            _distance, source, receipt, timing = selected
            receipt_id = str(receipt["receipt_id"])
            used.add(receipt_id)
            linked_receipts += 1
            entry["receipt_refs"] = [_receipt_ref(source, receipt)]
            if explicit == receipt_id:
                entry.update({
                    "classification": "confirmed_nct",
                    "label": "Confirmed NCT · occurrence is directly linked to the retained session receipt",
                    "attribution_basis": "occurrence_receipt_id",
                })
            else:
                label = (
                    "Possible NCT · verified session receipt matches this device, "
                    "command, and retained timing"
                    if timing == "absolute_history_time_within_10_minutes"
                    else "Possible NCT · verified session receipt matches this device and "
                    "command; history lacks an occurrence time"
                )
                entry.update({
                    "classification": "possible_nct",
                    "label": label,
                    "attribution_basis": timing,
                })
        elif entry.get("classification") not in {"confirmed_nct", "possible_nct"}:
            entry.update({
                "classification": "unmatched",
                "label": "Unmatched · no defensible retained NCT link was found",
                "attribution_basis": "none",
                "receipt_refs": [],
            })
    entries = result.get("entries") or []
    confirmed = sum(item.get("classification") == "confirmed_nct" for item in entries)
    possible = sum(item.get("classification") == "possible_nct" for item in entries)
    unmatched = sum(item.get("classification") == "unmatched" for item in entries)
    limitations = []
    if current is None or not isinstance(current["semantics"].get("device_identity"), dict):
        limitations.append(
            "This collection predates verified scoped device-identity receipts; command text can support only a weak possible match."
        )
    if any(item.get("timestamp_assumption") != "absolute" for item in entries):
        limitations.append(
            "One or more history entries lack an absolute timestamp, so timing cannot identify a unique command occurrence."
        )
    if history_truncated:
        limitations.append(
            "The retained history reached its collection limit; missing entries remain unknown."
        )
    if result.get("parse_errors"):
        error_count = len(result["parse_errors"])
        limitations.append(
            f"The device returned {error_count} history error line"
            f"{'s' if error_count != 1 else ''} alongside usable entries; valid entries "
            "were preserved and the errors remain visible."
        )
    result.update({
        "assessment_version": ATTRIBUTION_ASSESSMENT_VERSION,
        "confirmed_nct_count": confirmed,
        "possible_nct_count": possible,
        "unmatched_count": unmatched,
        "nct_command_count": confirmed + possible,
        "other_command_count": unmatched,
        "linked_receipt_count": linked_receipts,
        "history_truncated": bool(history_truncated),
        "limitations": limitations,
        "scope_note": (
            "Assessment basis: exact scoped device identity, preserved command text, "
            "retained session receipts, and available timing."
        ),
    })
    return result
