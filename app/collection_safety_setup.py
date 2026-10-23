"""Reviewed installation-wide scope and No-Strike collection boundary."""
from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3

from app.database import connect_database


REVIEW_KEY_PREFIX = "collection_safety_setup_review:"


class CollectionSafetySetupIncomplete(RuntimeError):
    """Raised when active network contact is not allowed by shared setup."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _clean_text(value: str, field: str, maximum: int) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be text")
    cleaned = value.strip()
    if not cleaned:
        raise ValueError(f"{field} cannot be blank")
    if len(cleaned) > maximum:
        raise ValueError(f"{field} exceeds {maximum} characters")
    return cleaned


def _latest_no_strike(db: sqlite3.Connection) -> dict:
    if not db.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='global_no_strike_history'"
    ).fetchone():
        return {"entries": [], "revision": 0, "updated_at": None, "updated_by": None}
    row = db.execute(
        """SELECT revision, entries_json, changed_at, changed_by
             FROM global_no_strike_history ORDER BY revision DESC LIMIT 1"""
    ).fetchone()
    if row is None:
        return {"entries": [], "revision": 0, "updated_at": None, "updated_by": None}
    return {
        "entries": json.loads(row[1]),
        "revision": int(row[0]),
        "updated_at": row[2],
        "updated_by": row[3],
    }


def _latest_review(db: sqlite3.Connection) -> dict | None:
    if not db.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='app_settings'"
    ).fetchone():
        return None
    row = db.execute(
        """SELECT value_json FROM app_settings
             WHERE key LIKE ? ORDER BY key DESC LIMIT 1""",
        (f"{REVIEW_KEY_PREFIX}%",),
    ).fetchone()
    if row is None:
        return None
    try:
        value = json.loads(row[0])
    except (TypeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def collection_safety_status_on_connection(db: sqlite3.Connection) -> dict:
    """Return readiness against the current scope and No-Strike revisions."""
    no_strike = _latest_no_strike(db)
    review = _latest_review(db)
    scope = None
    reasons: list[str] = []
    if review is None:
        reasons.append("Mission Environment scope and Global No-Strike have not been reviewed")
    else:
        scope_id = str(review.get("scope_id") or "")
        if db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='network_scopes'"
        ).fetchone():
            row = db.execute(
                """SELECT scope_id, label, description, version, active,
                          updated_at, updated_by
                     FROM network_scopes WHERE scope_id = ?""",
                (scope_id,),
            ).fetchone()
        else:
            row = None
        if row is None:
            reasons.append("The reviewed Network Scope no longer exists")
        else:
            scope = {
                "scope_id": row[0], "label": row[1], "description": row[2],
                "version": int(row[3]), "active": bool(row[4]),
                "updated_at": row[5], "updated_by": row[6],
            }
            if not scope["active"]:
                reasons.append("The reviewed Network Scope is archived")
            if int(review.get("scope_version") or 0) != scope["version"]:
                reasons.append("The Network Scope changed after the setup review")
        if int(review.get("no_strike_revision") or 0) != no_strike["revision"]:
            reasons.append("The Global No-Strike list changed after the setup review")
        if not no_strike["entries"] and not bool(review.get("empty_no_strike_reviewed")):
            reasons.append("The empty Global No-Strike list has not been explicitly reviewed")
    return {
        "ready": not reasons,
        "message": (
            "Ready for collection planning. Network contact is not authorized by this setup."
            if not reasons else "Complete the missing checks before NCT can contact a network."
        ),
        "missing_checks": reasons,
        "scope": scope,
        "no_strike": no_strike,
        "review": review,
    }


def get_collection_safety_status(db_path: Path) -> dict:
    with connect_database(db_path) as db:
        return collection_safety_status_on_connection(db)


def record_collection_safety_review(
    db_path: Path,
    *,
    scope_id: str,
    expected_scope_version: int,
    expected_no_strike_revision: int,
    empty_no_strike_reviewed: bool,
    reviewed_by: str,
    reason: str,
) -> dict:
    """Append a review bound to the exact current scope and safety revisions."""
    scope_id = _clean_text(scope_id, "scope_id", 200)
    actor = _clean_text(reviewed_by, "reviewed_by", 100)
    reason = _clean_text(reason, "reason", 500)
    with connect_database(db_path) as db:
        db.execute("BEGIN IMMEDIATE")
        scope = db.execute(
            "SELECT version, active FROM network_scopes WHERE scope_id = ?",
            (scope_id,),
        ).fetchone()
        if scope is None:
            raise KeyError("Network Scope not found")
        if not bool(scope[1]):
            raise ValueError("Archived Network Scopes cannot be selected")
        if int(scope[0]) != int(expected_scope_version):
            raise CollectionSafetySetupIncomplete(
                "The Network Scope changed while this setup was being reviewed"
            )
        no_strike = _latest_no_strike(db)
        if no_strike["revision"] != int(expected_no_strike_revision):
            raise CollectionSafetySetupIncomplete(
                "The Global No-Strike list changed while this setup was being reviewed"
            )
        if not no_strike["entries"] and not empty_no_strike_reviewed:
            raise ValueError(
                "Confirm that no Global No-Strike exclusions are currently required"
            )
        previous = _latest_review(db)
        revision = int(previous.get("revision") or 0) + 1 if previous else 1
        reviewed_at = _utc_now()
        record = {
            "revision": revision,
            "scope_id": scope_id,
            "scope_version": int(scope[0]),
            "no_strike_revision": no_strike["revision"],
            "empty_no_strike_reviewed": bool(empty_no_strike_reviewed),
            "reviewed_by": actor,
            "reviewed_at": reviewed_at,
            "reason": reason,
        }
        db.execute(
            """INSERT INTO app_settings(key, value_json, updated_at, updated_by)
                 VALUES (?, ?, ?, ?)""",
            (
                f"{REVIEW_KEY_PREFIX}{revision:012d}",
                json.dumps(record, sort_keys=True),
                reviewed_at,
                actor,
            ),
        )
        return collection_safety_status_on_connection(db)


def require_collection_safety_ready(
    db_path: Path,
    *,
    expected_scope_id: str | None = None,
) -> dict:
    status = get_collection_safety_status(db_path)
    if not status["ready"]:
        raise CollectionSafetySetupIncomplete("; ".join(status["missing_checks"]))
    selected_scope_id = status["scope"]["scope_id"]
    if not expected_scope_id:
        raise CollectionSafetySetupIncomplete(
            "Choose evidence assigned to the active Mission Environment Network Scope"
        )
    if expected_scope_id != selected_scope_id:
        raise CollectionSafetySetupIncomplete(
            "The selected evidence belongs to a different Network Scope than Mission Environment"
        )
    return status


def require_collection_safety_ready_on_connection(
    db: sqlite3.Connection,
    *,
    expected_scope_id: str | None = None,
) -> dict:
    status = collection_safety_status_on_connection(db)
    if not status["ready"]:
        raise CollectionSafetySetupIncomplete("; ".join(status["missing_checks"]))
    selected_scope_id = status["scope"]["scope_id"]
    if not expected_scope_id:
        raise CollectionSafetySetupIncomplete(
            "Choose evidence assigned to the active Mission Environment Network Scope"
        )
    if expected_scope_id != selected_scope_id:
        raise CollectionSafetySetupIncomplete(
            "The selected evidence belongs to a different Network Scope than Mission Environment"
        )
    return status


def bind_collection_scope_context_on_connection(
    db: sqlite3.Connection,
    *,
    context: dict | None,
    saved_network_ids: list[str] | None = None,
) -> tuple[dict, dict]:
    """Bind unscoped/manual collection to the explicitly reviewed active scope."""
    status = collection_safety_status_on_connection(db)
    if not status["ready"]:
        raise CollectionSafetySetupIncomplete("; ".join(status["missing_checks"]))
    scope = status["scope"]
    if context is not None and context.get("scope_id") != scope["scope_id"]:
        raise CollectionSafetySetupIncomplete(
            "The selected evidence belongs to a different Network Scope than Mission Environment"
        )
    sources: list[dict] = []
    for saved_network_id in dict.fromkeys(saved_network_ids or []):
        row = db.execute(
            """SELECT association_id, revision, scope_id
                 FROM saved_network_scope_associations
                WHERE saved_network_id = ? ORDER BY revision DESC LIMIT 1""",
            (saved_network_id,),
        ).fetchone()
        if row is None or row[2] is None:
            continue
        if str(row[2]) != scope["scope_id"]:
            raise CollectionSafetySetupIncomplete(
                "A selected Saved Network belongs to a different Network Scope than Mission Environment"
            )
        sources.append({
            "saved_network_id": saved_network_id,
            "association_id": row[0],
            "association_revision": int(row[1]),
        })
    if context is None:
        context = {
            "scope_id": scope["scope_id"],
            "scope_label": scope["label"],
            "scope_version": int(scope["version"]),
            "recorded_at": _utc_now(),
            "sources": sources,
            "context_source": "collection_safety_setup",
        }
    return status, context
