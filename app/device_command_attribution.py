from __future__ import annotations

import hashlib
import json
import sqlite3
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app.database import connect_database
from app.device_command_receipt_contract import (
    COMMAND_RECEIPT_SCHEMA_VERSION,
    command_receipt_is_valid,
    normalize_command_for_attribution,
)


ATTRIBUTION_ASSESSMENT_VERSION = 1
TIMESTAMP_WINDOW_SECONDS = 10 * 60
UNTIMED_LOOKBACK_SECONDS = 7 * 24 * 60 * 60
MAX_CANDIDATE_COLLECTIONS = 256


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


def _decoded_source(row: tuple, *, require_receipts: bool) -> dict | None:
    run_id, raw, semantic_sha256 = row
    if not isinstance(raw, str) or hashlib.sha256(raw.encode()).hexdigest() != str(
        semantic_sha256 or ""
    ):
        return None
    try:
        semantics = json.loads(raw)
    except json.JSONDecodeError:
        return None
    if not isinstance(semantics, dict):
        return None
    if require_receipts:
        identity = semantics.get("device_identity")
        started_at = str(semantics.get("contact_started_at") or "")
        completed_at = str(semantics.get("contact_completed_at") or "")
        receipts = semantics.get("command_execution_receipts")
        if (
            semantics.get("command_receipt_schema_version")
            != COMMAND_RECEIPT_SCHEMA_VERSION
            or not isinstance(identity, dict)
            or not isinstance(receipts, list)
            or not receipts
        ):
            return None
        receipt_ids: set[str] = set()
        for sequence, receipt in enumerate(receipts, start=1):
            receipt_id = str(receipt.get("receipt_id") or "") if isinstance(receipt, dict) else ""
            if (
                not receipt_id
                or receipt_id in receipt_ids
                or not isinstance(receipt, dict)
                or receipt.get("sequence") != sequence
                or not command_receipt_is_valid(
                    receipt,
                    run_id=str(run_id),
                    device_identity=identity,
                    contact_started_at=started_at,
                    contact_completed_at=completed_at,
                )
            ):
                return None
            receipt_ids.add(receipt_id)
    return {
        "run_id": str(run_id),
        "semantic_sha256": str(semantic_sha256 or ""),
        "semantics": semantics,
    }


def _attribution_sources(db_path: Path, run_id: str) -> tuple[list[dict], list[str]]:
    limitations: list[str] = []
    try:
        with connect_database(db_path, read_only=True) as db:
            current_row = db.execute(
                """SELECT run_id, semantic_manifest_json, semantic_manifest_sha256
                   FROM device_collection_authority
                   WHERE state = 'active' AND run_id = ?""",
                (run_id,),
            ).fetchone()
            current = _decoded_source(tuple(current_row), require_receipts=False) if current_row else None
            if current is None:
                if current_row is not None:
                    limitations.append(
                        "The current collection's retained semantic record failed integrity validation; receipt matching was not used."
                    )
                return [], limitations
            semantics = current["semantics"]
            identity = semantics.get("device_identity")
            current_start = _instant(semantics.get("contact_started_at"))
            if not isinstance(identity, dict) or current_start is None:
                return [current], limitations
            oldest = current_start - timedelta(seconds=UNTIMED_LOOKBACK_SECONDS)
            iso = lambda value: value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
            rows = db.execute(
                """SELECT run_id, semantic_manifest_json, semantic_manifest_sha256
                   FROM device_collection_authority
                   WHERE state = 'active' AND run_id != ?
                     AND json_valid(semantic_manifest_json)
                     AND json_extract(semantic_manifest_json, '$.command_receipt_schema_version') = ?
                     AND json_extract(semantic_manifest_json, '$.device_identity.scope_id') = ?
                     AND json_extract(semantic_manifest_json, '$.device_identity.device_address') = ?
                     AND json_extract(semantic_manifest_json, '$.device_identity.ssh_port') = ?
                     AND json_extract(semantic_manifest_json, '$.device_identity.username') = ?
                     AND json_extract(semantic_manifest_json, '$.device_identity.vendor') = ?
                     AND julianday(json_extract(semantic_manifest_json, '$.contact_completed_at'))
                         >= julianday(?)
                     AND julianday(json_extract(semantic_manifest_json, '$.contact_completed_at'))
                         <= julianday(?)
                   ORDER BY julianday(json_extract(semantic_manifest_json, '$.contact_completed_at')) DESC,
                            activated_at DESC, run_id DESC
                   LIMIT ?""",
                (
                    run_id, COMMAND_RECEIPT_SCHEMA_VERSION,
                    str(identity.get("scope_id") or ""),
                    str(identity.get("device_address") or ""),
                    int(identity.get("ssh_port") or 22),
                    str(identity.get("username") or ""),
                    str(identity.get("vendor") or ""),
                    iso(oldest), iso(current_start), MAX_CANDIDATE_COLLECTIONS + 1,
                ),
            ).fetchall()
    except (sqlite3.OperationalError, ValueError, TypeError):
        limitations.append(
            "Retained command-receipt candidates could not be read safely; no receipt match was asserted."
        )
        return [], limitations
    if len(rows) > MAX_CANDIDATE_COLLECTIONS:
        rows = rows[:MAX_CANDIDATE_COLLECTIONS]
        limitations.append(
            f"Receipt matching reviewed the newest {MAX_CANDIDATE_COLLECTIONS} eligible collections; older candidates remain unassessed."
        )
    invalid = 0
    sources = [current]
    for row in rows:
        source = _decoded_source(tuple(row), require_receipts=True)
        if source is None:
            invalid += 1
        else:
            sources.append(source)
    if invalid:
        limitations.append(
            f"{invalid} retained receipt-bearing collection{'s' if invalid != 1 else ''} failed integrity or receipt-contract validation and were not used."
        )
    return sources, limitations


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
    sources, source_limitations = _attribution_sources(db_path, run_id)
    current = next((item for item in sources if item["run_id"] == run_id), None)
    used: set[str] = set()
    linked_receipts = 0
    for entry in result.get("entries") or []:
        legacy_classification = entry.get("classification")
        if legacy_classification == "nct_collection":
            entry.update({
                "classification": "possible_nct",
                "label": (
                    "Possible NCT · retained legacy summary matched a known collection "
                    "command; no occurrence receipt exists"
                ),
                "attribution_basis": "legacy_summary_template_match",
                "receipt_refs": [],
            })
        elif legacy_classification == "other":
            entry.update({
                "classification": "unmatched",
                "label": "Unmatched · retained legacy summary found no known collection-command match",
                "attribution_basis": "legacy_summary_unmatched",
                "receipt_refs": [],
            })
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
    limitations = list(source_limitations)
    if any(
        item.get("attribution_basis", "").startswith("legacy_summary_")
        for item in entries
    ):
        limitations.append(
            "This retained summary uses the earlier command-history contract; its original template matches were preserved as Possible NCT and were not upgraded to receipt-backed attribution."
        )
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
