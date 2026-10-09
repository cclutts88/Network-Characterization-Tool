"""Read-only, correction-aware views over processed scoped Nmap evidence."""
from __future__ import annotations

import json
import hashlib
from pathlib import Path
import re
import sqlite3
from decimal import Decimal, InvalidOperation

from app.database import connect_database
from app.nmap_evidence import NMAP_ENDPOINT_PARSER


MAX_SCOPE_PAGE = 100
MAX_ENDPOINT_PAGE = 100
MAX_RECEIPT_PAGE = 25
MAX_SERVICE_PAGE = 250
MAX_LATEST_SELECTION_CANDIDATES = 5000
MAX_MAC_ASSOCIATION_CANDIDATES = 5000
MAX_MAC_ASSOCIATION_PAGE = 100
LATEST_OBSERVATION_SELECTION_CONTRACT = "latest-supported-nmap-observations:1"
MAC_ASSOCIATION_SELECTION_CONTRACT = "source-reported-mac-address-associations:1"


class FoundationEvidenceConflict(ValueError):
    pass


def _page(limit: int, offset: int, maximum: int) -> tuple[int, int]:
    if type(limit) is not int or not 1 <= limit <= maximum:
        raise ValueError(f"limit must be between 1 and {maximum}")
    if type(offset) is not int or offset < 0:
        raise ValueError("offset must be zero or greater")
    return limit, offset


def _json(raw: str | None) -> dict:
    try:
        value = json.loads(raw or "{}")
    except json.JSONDecodeError:
        return {"unreadable": True}
    return value if isinstance(value, dict) else {"unreadable": True}


def _source(row: sqlite3.Row) -> dict:
    source_kind = row["source_kind"]
    source_ref = row["source_ref"]
    digest = row["sha256"]
    filename = row["original_filename"] or "Retained Nmap XML"
    if source_kind == "nmap_scan":
        source_url = f"/api/scan-runs/{source_ref}/artifacts/xml"
        analysis_url = f"/analysis?run={source_ref}"
        label = f"Automated scan · {filename}"
    elif source_kind == "nmap_import":
        source_url = f"/api/imports/{digest}/raw"
        analysis_url = "/analysis#xmlImport"
        label = f"Imported Nmap evidence · {filename}"
    else:
        source_url = None
        analysis_url = None
        label = f"{source_kind} · {filename}"
    return {
        "observation_id": row["observation_id"],
        "sha256": digest,
        "source_kind": source_kind,
        "source_ref": source_ref,
        "original_filename": row["original_filename"],
        "encountered_at": row["observed_at"],
        "actor": row["observation_actor"],
        "label": label,
        "source_url": source_url,
        "analysis_url": analysis_url,
    }


def _scope(row: sqlite3.Row) -> dict:
    return {
        "scope_id": row["scope_id"],
        "label": row["label"],
        "description": row["description"],
        "version": int(row["version"]),
        "active": bool(row["active"]),
    }


_SCOPE_STATS_SQL = """
WITH assignments AS (
    SELECT assignment.*,
           CASE WHEN successor.assignment_id IS NULL THEN 1 ELSE 0 END AS is_current
    FROM artifact_scope_assignments assignment
    LEFT JOIN artifact_scope_assignments successor
      ON successor.supersedes_assignment_id = assignment.assignment_id
), linked AS (
    SELECT assignment.scope_id, assignment.assignment_id,
           assessment.assessment_id, assessment.parser_version,
           assignment.is_current,
           CASE WHEN assignment.is_current = 1 AND assessment.parser_version = ?
                THEN 1 ELSE 0 END AS is_primary
    FROM assignments assignment
    JOIN assessment_scope_assignment_links link
      ON link.assignment_id = assignment.assignment_id
    JOIN entity_assessments assessment
      ON assessment.assessment_id = link.assessment_id
     AND assessment.scope_id = assignment.scope_id
), primary_assessments AS (
    SELECT DISTINCT scope_id, assessment_id
    FROM linked WHERE is_primary = 1
), assessment_counts AS (
    SELECT scope_id, COUNT(*) AS assessment_count
    FROM primary_assessments GROUP BY scope_id
), endpoint_counts AS (
    SELECT primary_assessments.scope_id,
           COUNT(DISTINCT receipt.host_id) AS endpoint_count
    FROM primary_assessments
    JOIN endpoint_receipts receipt
      ON receipt.assessment_id = primary_assessments.assessment_id
    GROUP BY primary_assessments.scope_id
), service_counts AS (
    SELECT primary_assessments.scope_id,
           COUNT(DISTINCT receipt.service_id) AS service_count
    FROM primary_assessments
    JOIN service_receipts receipt
      ON receipt.assessment_id = primary_assessments.assessment_id
    GROUP BY primary_assessments.scope_id
), history_counts AS (
    SELECT scope_id,
           COUNT(DISTINCT assignment_id || ':' || assessment_id) AS historical_link_count
    FROM linked WHERE is_primary = 0 GROUP BY scope_id
), pending AS (
    SELECT assignment.scope_id,
           SUM(CASE WHEN EXISTS (
                 SELECT 1 FROM artifact_scope_assignments older
                 JOIN assessment_scope_assignment_links older_link
                   ON older_link.assignment_id = older.assignment_id
                 WHERE older.artifact_observation_id = assignment.artifact_observation_id
                   AND older.assignment_id != assignment.assignment_id
               ) THEN 1 ELSE 0 END) AS pending_corrections,
           SUM(CASE WHEN NOT EXISTS (
                 SELECT 1 FROM artifact_scope_assignments older
                 JOIN assessment_scope_assignment_links older_link
                   ON older_link.assignment_id = older.assignment_id
                 WHERE older.artifact_observation_id = assignment.artifact_observation_id
                   AND older.assignment_id != assignment.assignment_id
               ) THEN 1 ELSE 0 END) AS pending_processing
    FROM assignments assignment
    WHERE assignment.is_current = 1
      AND NOT EXISTS (
        SELECT 1 FROM assessment_scope_assignment_links current_link
        JOIN entity_assessments current_assessment
          ON current_assessment.assessment_id = current_link.assessment_id
        WHERE current_link.assignment_id = assignment.assignment_id
          AND current_assessment.parser_version = ?
      )
    GROUP BY assignment.scope_id
), stats AS (
    SELECT scope.scope_id, scope.label, scope.description, scope.version, scope.active,
           COALESCE(assessment_counts.assessment_count, 0) AS assessment_count,
           COALESCE(endpoint_counts.endpoint_count, 0) AS endpoint_count,
           COALESCE(service_counts.service_count, 0) AS service_count,
           COALESCE(history_counts.historical_link_count, 0) AS historical_link_count,
           COALESCE(pending.pending_corrections, 0) AS pending_corrections,
           COALESCE(pending.pending_processing, 0) AS pending_processing
    FROM network_scopes scope
    LEFT JOIN assessment_counts ON assessment_counts.scope_id = scope.scope_id
    LEFT JOIN endpoint_counts ON endpoint_counts.scope_id = scope.scope_id
    LEFT JOIN service_counts ON service_counts.scope_id = scope.scope_id
    LEFT JOIN history_counts ON history_counts.scope_id = scope.scope_id
    LEFT JOIN pending ON pending.scope_id = scope.scope_id
), visible AS (
    SELECT * FROM stats
    WHERE assessment_count > 0 OR historical_link_count > 0
       OR pending_corrections > 0 OR pending_processing > 0
)
SELECT *, COUNT(*) OVER() AS total_count
FROM visible
ORDER BY active DESC, lower(label), scope_id
LIMIT ? OFFSET ?
"""


def list_foundation_evidence_scopes(
    db_path: Path, *, limit: int = 50, offset: int = 0,
) -> dict:
    """List bounded scope summaries without parsing, hashing, or schema work."""
    limit, offset = _page(limit, offset, MAX_SCOPE_PAGE)
    with connect_database(db_path, read_only=True) as db:
        db.row_factory = sqlite3.Row
        db.execute("BEGIN")
        rows = db.execute(
            _SCOPE_STATS_SQL,
            (NMAP_ENDPOINT_PARSER, NMAP_ENDPOINT_PARSER, limit, offset),
        ).fetchall()
        if rows:
            total = int(rows[0]["total_count"])
        elif offset:
            first = db.execute(
                _SCOPE_STATS_SQL,
                (NMAP_ENDPOINT_PARSER, NMAP_ENDPOINT_PARSER, 1, 0),
            ).fetchone()
            total = int(first["total_count"]) if first else 0
        else:
            total = 0
    return {
        "items": [
            {
                **_scope(row),
                "assessment_count": int(row["assessment_count"]),
                "endpoint_count": int(row["endpoint_count"]),
                "service_count": int(row["service_count"]),
                "historical_link_count": int(row["historical_link_count"]),
                "pending_correction_count": int(row["pending_corrections"]),
                "pending_processing_count": int(row["pending_processing"]),
            }
            for row in rows
        ],
        "pagination": {
            "limit": limit, "offset": offset, "total": total,
            "has_more": offset + len(rows) < total,
        },
        "parser_version": NMAP_ENDPOINT_PARSER,
        "read_only": True,
    }


_PRIMARY_CTE = """
WITH assignments AS (
    SELECT assignment.*
    FROM artifact_scope_assignments assignment
    WHERE assignment.scope_id = ?
      AND NOT EXISTS (
        SELECT 1 FROM artifact_scope_assignments successor
        WHERE successor.supersedes_assignment_id = assignment.assignment_id
      )
), primary_links AS (
    SELECT DISTINCT assignment.assignment_id, assignment.revision,
           assessment.assessment_id
    FROM assignments assignment
    JOIN assessment_scope_assignment_links link
      ON link.assignment_id = assignment.assignment_id
    JOIN entity_assessments assessment
      ON assessment.assessment_id = link.assessment_id
     AND assessment.scope_id = assignment.scope_id
     AND assessment.parser_version = ?
)
"""


_ENDPOINT_PAGE_SQL = _PRIMARY_CTE + """
, endpoint_grouped AS (
    SELECT endpoint.entity_id, endpoint.address,
           COUNT(DISTINCT primary_links.assessment_id) AS receipt_count
    FROM primary_links
    JOIN endpoint_receipts receipt
      ON receipt.assessment_id = primary_links.assessment_id
    JOIN endpoint_entities endpoint ON endpoint.entity_id = receipt.host_id
    GROUP BY endpoint.entity_id, endpoint.address
), service_grouped AS (
    SELECT entity.host_id AS entity_id,
           COUNT(DISTINCT receipt.service_id) AS service_count
    FROM primary_links
    JOIN service_receipts receipt
      ON receipt.assessment_id = primary_links.assessment_id
    JOIN service_entities entity ON entity.entity_id = receipt.service_id
    GROUP BY entity.host_id
), grouped AS (
    SELECT endpoint_grouped.*,
           COALESCE(service_grouped.service_count, 0) AS service_count
    FROM endpoint_grouped
    LEFT JOIN service_grouped
      ON service_grouped.entity_id = endpoint_grouped.entity_id
)
SELECT *, COUNT(*) OVER() AS total_count
FROM grouped
ORDER BY address, entity_id
LIMIT ? OFFSET ?
"""


_HISTORICAL_ENDPOINT_PAGE_SQL = """
WITH assignments AS (
    SELECT assignment.*,
           CASE WHEN successor.assignment_id IS NULL THEN 1 ELSE 0 END AS is_current
    FROM artifact_scope_assignments assignment
    LEFT JOIN artifact_scope_assignments successor
      ON successor.supersedes_assignment_id = assignment.assignment_id
    WHERE assignment.scope_id = ?
), historical_links AS (
    SELECT DISTINCT assignment.assignment_id, assessment.assessment_id
    FROM assignments assignment
    JOIN assessment_scope_assignment_links link
      ON link.assignment_id = assignment.assignment_id
    JOIN entity_assessments assessment
      ON assessment.assessment_id = link.assessment_id
     AND assessment.scope_id = assignment.scope_id
    WHERE NOT (assignment.is_current = 1 AND assessment.parser_version = ?)
), endpoint_grouped AS (
    SELECT endpoint.entity_id, endpoint.address,
           COUNT(DISTINCT historical_links.assignment_id || ':' ||
                 historical_links.assessment_id) AS receipt_count
    FROM historical_links
    JOIN endpoint_receipts receipt
      ON receipt.assessment_id = historical_links.assessment_id
    JOIN endpoint_entities endpoint ON endpoint.entity_id = receipt.host_id
    GROUP BY endpoint.entity_id, endpoint.address
), service_grouped AS (
    SELECT entity.host_id AS entity_id,
           COUNT(DISTINCT receipt.service_id) AS service_count
    FROM historical_links
    JOIN service_receipts receipt
      ON receipt.assessment_id = historical_links.assessment_id
    JOIN service_entities entity ON entity.entity_id = receipt.service_id
    GROUP BY entity.host_id
), grouped AS (
    SELECT endpoint_grouped.*,
           COALESCE(service_grouped.service_count, 0) AS service_count
    FROM endpoint_grouped
    LEFT JOIN service_grouped
      ON service_grouped.entity_id = endpoint_grouped.entity_id
)
SELECT *, COUNT(*) OVER() AS total_count
FROM grouped
ORDER BY address, entity_id
LIMIT ? OFFSET ?
"""


_PENDING_SQL = """
WITH assignments AS (
    SELECT assignment.*
    FROM artifact_scope_assignments assignment
    WHERE assignment.scope_id = ?
      AND NOT EXISTS (
        SELECT 1 FROM artifact_scope_assignments successor
        WHERE successor.supersedes_assignment_id = assignment.assignment_id
      )
)
SELECT assignment.assignment_id, assignment.revision, assignment.assigned_at,
       assignment.actor AS assignment_actor, assignment.reason,
       observation.observation_id, observation.sha256, observation.source_kind,
       observation.source_ref, observation.observed_at, observation.original_filename,
       observation.actor AS observation_actor,
       CASE WHEN EXISTS (
           SELECT 1 FROM artifact_scope_assignments older
           JOIN assessment_scope_assignment_links older_link
             ON older_link.assignment_id = older.assignment_id
           WHERE older.artifact_observation_id = assignment.artifact_observation_id
             AND older.assignment_id != assignment.assignment_id
       ) THEN 'correction_pending' ELSE 'processing_pending' END AS pending_kind,
       COUNT(*) OVER() AS total_count
FROM assignments assignment
JOIN artifact_observations observation
  ON observation.observation_id = assignment.artifact_observation_id
WHERE NOT EXISTS (
    SELECT 1 FROM assessment_scope_assignment_links link
    JOIN entity_assessments assessment ON assessment.assessment_id = link.assessment_id
    WHERE link.assignment_id = assignment.assignment_id
      AND assessment.parser_version = ?
)
ORDER BY assignment.assigned_at DESC, assignment.assignment_id
LIMIT ? OFFSET ?
"""


_HISTORY_SQL = """
WITH assignments AS (
    SELECT assignment.*,
           CASE WHEN successor.assignment_id IS NULL THEN 1 ELSE 0 END AS is_current
    FROM artifact_scope_assignments assignment
    LEFT JOIN artifact_scope_assignments successor
      ON successor.supersedes_assignment_id = assignment.assignment_id
    WHERE assignment.scope_id = ?
)
SELECT assignment.assignment_id, assignment.revision, assignment.event_kind,
       assignment.assigned_at, assignment.actor AS assignment_actor, assignment.reason,
       assignment.is_current, assessment.assessment_id, assessment.parser_version,
       assessment.assessed_at, assessment.recorded_at,
       observation.observation_id, observation.sha256, observation.source_kind,
       observation.source_ref, observation.observed_at, observation.original_filename,
       observation.actor AS observation_actor,
       (SELECT COUNT(*) FROM endpoint_receipts endpoint
        WHERE endpoint.assessment_id = assessment.assessment_id) AS endpoint_count,
       (SELECT COUNT(*) FROM service_receipts service
        WHERE service.assessment_id = assessment.assessment_id) AS service_count,
       COUNT(*) OVER() AS total_count
FROM assignments assignment
JOIN assessment_scope_assignment_links link
  ON link.assignment_id = assignment.assignment_id
JOIN entity_assessments assessment ON assessment.assessment_id = link.assessment_id
JOIN artifact_observations observation
  ON observation.observation_id = assessment.artifact_observation_id
WHERE NOT (assignment.is_current = 1 AND assessment.parser_version = ?)
ORDER BY assignment.assigned_at DESC, assignment.revision DESC,
         assessment.recorded_at DESC, assessment.assessment_id
LIMIT ? OFFSET ?
"""


def get_foundation_scope_evidence(
    db_path: Path, scope_id: str, *, limit: int = 25, offset: int = 0,
    pending_limit: int = 25, pending_offset: int = 0,
    history_limit: int = 25, history_offset: int = 0,
    historical_endpoint_limit: int = 25, historical_endpoint_offset: int = 0,
) -> dict:
    """Return one consistent, bounded snapshot for a selected scope."""
    limit, offset = _page(limit, offset, MAX_ENDPOINT_PAGE)
    pending_limit, pending_offset = _page(
        pending_limit, pending_offset, MAX_RECEIPT_PAGE,
    )
    history_limit, history_offset = _page(
        history_limit, history_offset, MAX_RECEIPT_PAGE,
    )
    historical_endpoint_limit, historical_endpoint_offset = _page(
        historical_endpoint_limit, historical_endpoint_offset, MAX_ENDPOINT_PAGE,
    )
    with connect_database(db_path, read_only=True) as db:
        db.row_factory = sqlite3.Row
        db.execute("BEGIN")
        scope_row = db.execute(
            """SELECT scope_id, label, description, version, active
               FROM network_scopes WHERE scope_id = ?""",
            (scope_id,),
        ).fetchone()
        if scope_row is None:
            raise KeyError("Network Scope not found")
        endpoints = db.execute(
            _ENDPOINT_PAGE_SQL,
            (scope_id, NMAP_ENDPOINT_PARSER, limit, offset),
        ).fetchall()
        historical_endpoints = db.execute(
            _HISTORICAL_ENDPOINT_PAGE_SQL,
            (scope_id, NMAP_ENDPOINT_PARSER,
             historical_endpoint_limit, historical_endpoint_offset),
        ).fetchall()
        pending = db.execute(
            _PENDING_SQL,
            (scope_id, NMAP_ENDPOINT_PARSER, pending_limit, pending_offset),
        ).fetchall()
        history = db.execute(
            _HISTORY_SQL,
            (scope_id, NMAP_ENDPOINT_PARSER, history_limit, history_offset),
        ).fetchall()
        if endpoints:
            total = int(endpoints[0]["total_count"])
        elif offset:
            first = db.execute(
                _ENDPOINT_PAGE_SQL,
                (scope_id, NMAP_ENDPOINT_PARSER, 1, 0),
            ).fetchone()
            total = int(first["total_count"]) if first else 0
        else:
            total = 0
        if historical_endpoints:
            historical_total = int(historical_endpoints[0]["total_count"])
        elif historical_endpoint_offset:
            first = db.execute(
                _HISTORICAL_ENDPOINT_PAGE_SQL,
                (scope_id, NMAP_ENDPOINT_PARSER, 1, 0),
            ).fetchone()
            historical_total = int(first["total_count"]) if first else 0
        else:
            historical_total = 0
        if pending:
            pending_total = int(pending[0]["total_count"])
        elif pending_offset:
            first = db.execute(
                _PENDING_SQL,
                (scope_id, NMAP_ENDPOINT_PARSER, 1, 0),
            ).fetchone()
            pending_total = int(first["total_count"]) if first else 0
        else:
            pending_total = 0
        if history:
            history_total = int(history[0]["total_count"])
        elif history_offset:
            first = db.execute(
                _HISTORY_SQL,
                (scope_id, NMAP_ENDPOINT_PARSER, 1, 0),
            ).fetchone()
            history_total = int(first["total_count"]) if first else 0
        else:
            history_total = 0
    return {
        "scope": _scope(scope_row),
        "endpoints": [
            {
                "entity_id": row["entity_id"],
                "address": row["address"],
                "receipt_count": int(row["receipt_count"]),
                "service_count": int(row["service_count"]),
            }
            for row in endpoints
        ],
        "pagination": {
            "limit": limit, "offset": offset, "total": total,
            "has_more": offset + len(endpoints) < total,
        },
        "historical_endpoints": [
            {
                "entity_id": row["entity_id"],
                "address": row["address"],
                "receipt_count": int(row["receipt_count"]),
                "service_count": int(row["service_count"]),
            }
            for row in historical_endpoints
        ],
        "historical_endpoint_pagination": {
            "limit": historical_endpoint_limit,
            "offset": historical_endpoint_offset,
            "total": historical_total,
            "has_more": (
                historical_endpoint_offset + len(historical_endpoints) < historical_total
            ),
        },
        "pending": [
            {
                "kind": row["pending_kind"],
                "assignment_id": row["assignment_id"],
                "assignment_revision": int(row["revision"]),
                "assigned_at": row["assigned_at"],
                "assigned_by": row["assignment_actor"],
                "reason": row["reason"],
                "source": _source(row),
            }
            for row in pending
        ],
        "pending_pagination": {
            "limit": pending_limit, "offset": pending_offset,
            "total": pending_total,
            "has_more": pending_offset + len(pending) < pending_total,
        },
        "separate_history": [
            {
                "assignment_id": row["assignment_id"],
                "assignment_revision": int(row["revision"]),
                "assignment_current": bool(row["is_current"]),
                "assignment_event": row["event_kind"],
                "assigned_at": row["assigned_at"],
                "assigned_by": row["assignment_actor"],
                "reason": row["reason"],
                "assessment_id": row["assessment_id"],
                "parser_version": row["parser_version"],
                "assessed_at": row["assessed_at"],
                "processed_at": row["recorded_at"],
                "endpoint_count": int(row["endpoint_count"]),
                "service_count": int(row["service_count"]),
                "source": _source(row),
            }
            for row in history
        ],
        "history_pagination": {
            "limit": history_limit, "offset": history_offset,
            "total": history_total,
            "has_more": history_offset + len(history) < history_total,
        },
        "parser_version": NMAP_ENDPOINT_PARSER,
        "read_only": True,
        "claims": {
            "current_truth": False,
            "physical_device_identity": False,
            "last_seen": False,
            "absence_or_disappearance": False,
        },
    }


_ENDPOINT_DETAIL_SQL = """
WITH assignments AS (
    SELECT assignment.*,
           CASE WHEN successor.assignment_id IS NULL THEN 1 ELSE 0 END AS is_current
    FROM artifact_scope_assignments assignment
    LEFT JOIN artifact_scope_assignments successor
      ON successor.supersedes_assignment_id = assignment.assignment_id
    WHERE assignment.scope_id = ?
)
SELECT assignment.assignment_id, assignment.revision, assignment.event_kind,
       assignment.assigned_at, assignment.actor AS assignment_actor, assignment.reason,
       assignment.is_current, assessment.assessment_id, assessment.parser_version,
       assessment.assessed_at, assessment.recorded_at,
       json_extract(assessment.payload_json, '$.time_basis') AS time_basis,
       json_extract(assessment.payload_json, '$.facts.scan_start') AS scan_start_json,
       json_extract(assessment.payload_json, '$.facts.scan_end') AS scan_end_json,
       json_extract(assessment.payload_json, '$.facts.coverage') AS coverage_json,
       receipt.facts_json AS endpoint_facts_json,
       observation.observation_id, observation.sha256, observation.source_kind,
       observation.source_ref, observation.observed_at, observation.original_filename,
       observation.actor AS observation_actor,
       CASE WHEN assignment.is_current = 1 AND assessment.parser_version = ?
            THEN 1 ELSE 0 END AS is_primary,
       (SELECT COUNT(*) FROM service_receipts service
        JOIN service_entities entity ON entity.entity_id = service.service_id
        WHERE service.assessment_id = assessment.assessment_id
          AND entity.host_id = receipt.host_id) AS service_count,
       COUNT(*) OVER() AS total_count
FROM assignments assignment
JOIN assessment_scope_assignment_links link
  ON link.assignment_id = assignment.assignment_id
JOIN entity_assessments assessment ON assessment.assessment_id = link.assessment_id
JOIN endpoint_receipts receipt
  ON receipt.assessment_id = assessment.assessment_id AND receipt.host_id = ?
JOIN artifact_observations observation
  ON observation.observation_id = assessment.artifact_observation_id
ORDER BY is_primary DESC, assignment.assigned_at DESC, assignment.revision DESC,
         assessment.recorded_at DESC, assessment.assessment_id
LIMIT ? OFFSET ?
"""


def get_foundation_endpoint_evidence(
    db_path: Path, scope_id: str, entity_id: str, *,
    limit: int = 10, offset: int = 0,
) -> dict:
    """Load a bounded page of one endpoint's current and historical receipts."""
    limit, offset = _page(limit, offset, MAX_RECEIPT_PAGE)
    with connect_database(db_path, read_only=True) as db:
        db.row_factory = sqlite3.Row
        db.execute("BEGIN")
        scope_row = db.execute(
            """SELECT scope_id, label, description, version, active
               FROM network_scopes WHERE scope_id = ?""",
            (scope_id,),
        ).fetchone()
        endpoint = db.execute(
            """SELECT entity_id, address FROM endpoint_entities
               WHERE entity_id = ? AND scope_id = ?""",
            (entity_id, scope_id),
        ).fetchone()
        if scope_row is None or endpoint is None:
            raise KeyError("Processed endpoint not found in this Network Scope")
        rows = db.execute(
            _ENDPOINT_DETAIL_SQL,
            (scope_id, NMAP_ENDPOINT_PARSER, entity_id, limit, offset),
        ).fetchall()
        if not rows and offset == 0:
            raise KeyError("Processed endpoint not found in this Network Scope")
        if rows:
            total = int(rows[0]["total_count"])
        else:
            first = db.execute(
                _ENDPOINT_DETAIL_SQL,
                (scope_id, NMAP_ENDPOINT_PARSER, entity_id, 1, 0),
            ).fetchone()
            if first is None:
                raise KeyError("Processed endpoint not found in this Network Scope")
            total = int(first["total_count"])
        receipts = []
        for row in rows:
            receipts.append({
                "primary": bool(row["is_primary"]),
                "assessment": {
                    "assessment_id": row["assessment_id"],
                    "parser_version": row["parser_version"],
                    "assessed_at": row["assessed_at"],
                    "time_basis": row["time_basis"],
                    "processed_at": row["recorded_at"],
                    "collection_window": {
                        "start": _json(row["scan_start_json"]),
                        "end": _json(row["scan_end_json"]),
                    },
                    "coverage": _json(row["coverage_json"]),
                },
                "assignment": {
                    "assignment_id": row["assignment_id"],
                    "revision": int(row["revision"]),
                    "event": row["event_kind"],
                    "current": bool(row["is_current"]),
                    "assigned_at": row["assigned_at"],
                    "actor": row["assignment_actor"],
                    "reason": row["reason"],
                },
                "source": _source(row),
                "endpoint_facts": _json(row["endpoint_facts_json"]),
                "service_count": int(row["service_count"]),
            })
    primary = [item for item in receipts if item["primary"]]
    history = [item for item in receipts if not item["primary"]]
    return {
        "scope": _scope(scope_row),
        "endpoint": {"entity_id": endpoint["entity_id"], "address": endpoint["address"]},
        "current_assignment_receipts": primary,
        "separate_history_receipts": history,
        "pagination": {
            "limit": limit, "offset": offset, "total": total,
            "has_more": offset + len(rows) < total,
        },
        "read_only": True,
        "claims": {
            "current_truth": False,
            "physical_device_identity": False,
            "last_seen": False,
            "absence_or_disappearance": False,
        },
    }


_RECEIPT_SERVICES_SQL = """
SELECT entity.entity_id, entity.protocol, entity.port, receipt.facts_json,
       COUNT(*) OVER() AS total_count
FROM service_receipts receipt
JOIN service_entities entity ON entity.entity_id = receipt.service_id
WHERE receipt.assessment_id = ? AND entity.host_id = ?
ORDER BY entity.protocol, entity.port, entity.entity_id
LIMIT ? OFFSET ?
"""


def get_foundation_receipt_services(
    db_path: Path, scope_id: str, entity_id: str,
    assignment_id: str, assessment_id: str, *,
    limit: int = 100, offset: int = 0,
) -> dict:
    """Load one bounded service-receipt page for an exact endpoint receipt."""
    limit, offset = _page(limit, offset, MAX_SERVICE_PAGE)
    with connect_database(db_path, read_only=True) as db:
        db.row_factory = sqlite3.Row
        db.execute("BEGIN")
        endpoint = db.execute(
            """SELECT entity_id, address FROM endpoint_entities
               WHERE entity_id = ? AND scope_id = ?""",
            (entity_id, scope_id),
        ).fetchone()
        valid = db.execute(
            """SELECT 1
               FROM artifact_scope_assignments assignment
               JOIN assessment_scope_assignment_links link
                 ON link.assignment_id = assignment.assignment_id
               JOIN entity_assessments assessment
                 ON assessment.assessment_id = link.assessment_id
               JOIN endpoint_receipts receipt
                 ON receipt.assessment_id = assessment.assessment_id
               WHERE assignment.assignment_id = ?
                 AND assessment.assessment_id = ?
                 AND assignment.scope_id = ?
                 AND assessment.scope_id = ?
                 AND receipt.host_id = ?""",
            (assignment_id, assessment_id, scope_id, scope_id, entity_id),
        ).fetchone()
        if endpoint is None or valid is None:
            raise KeyError("Processed endpoint receipt not found in this Network Scope")
        rows = db.execute(
            _RECEIPT_SERVICES_SQL,
            (assessment_id, entity_id, limit, offset),
        ).fetchall()
        if rows:
            total = int(rows[0]["total_count"])
        elif offset:
            first = db.execute(
                _RECEIPT_SERVICES_SQL,
                (assessment_id, entity_id, 1, 0),
            ).fetchone()
            total = int(first["total_count"]) if first else 0
        else:
            total = 0
    return {
        "endpoint": {"entity_id": endpoint["entity_id"], "address": endpoint["address"]},
        "receipt": {"assignment_id": assignment_id, "assessment_id": assessment_id},
        "services": [
            {
                "service_id": row["entity_id"],
                "protocol": row["protocol"],
                "port": int(row["port"]),
                "facts": _json(row["facts_json"]),
            }
            for row in rows
        ],
        "pagination": {
            "limit": limit, "offset": offset, "total": total,
            "has_more": offset + len(rows) < total,
        },
        "read_only": True,
    }


_LATEST_OBSERVATION_CANDIDATES_SQL = """
WITH current_assignments AS (
    SELECT assignment.*
    FROM artifact_scope_assignments assignment
    WHERE assignment.scope_id = ?
      AND NOT EXISTS (
          SELECT 1 FROM artifact_scope_assignments successor
          WHERE successor.supersedes_assignment_id = assignment.assignment_id
      )
)
SELECT assignment.assignment_id, assignment.revision, assignment.event_kind,
       assignment.assigned_at, assignment.actor AS assignment_actor, assignment.reason,
       assessment.assessment_id, assessment.parser_version, assessment.assessed_at,
       assessment.recorded_at,
       CASE
           WHEN json_valid(assessment.payload_json)
           THEN CASE
               WHEN json_type(
                   assessment.payload_json,
                   '$.facts.coverage.completion.successful'
               ) = 'true'
               THEN 1
               ELSE 0
           END
           ELSE NULL
       END AS completion_successful,
       receipt.facts_json AS endpoint_facts_json,
       observation.observation_id, observation.sha256, observation.source_kind,
       observation.source_ref, observation.observed_at, observation.original_filename,
       observation.actor AS observation_actor,
       (SELECT COUNT(*) FROM service_receipts service
        JOIN service_entities entity ON entity.entity_id = service.service_id
        WHERE service.assessment_id = assessment.assessment_id
          AND entity.host_id = receipt.host_id) AS service_count
FROM current_assignments assignment
JOIN assessment_scope_assignment_links link
  ON link.assignment_id = assignment.assignment_id
JOIN entity_assessments assessment
  ON assessment.assessment_id = link.assessment_id
 AND assessment.scope_id = assignment.scope_id
JOIN endpoint_receipts receipt
  ON receipt.assessment_id = assessment.assessment_id AND receipt.host_id = ?
JOIN artifact_observations observation
  ON observation.observation_id = assessment.artifact_observation_id
WHERE assessment.parser_version = ?
ORDER BY assessment.assessment_id, assignment.assignment_id
LIMIT ?
"""


def _supported_observation_candidate(row: sqlite3.Row) -> tuple[dict, tuple[Decimal, Decimal] | None, bool]:
    completed = row["completion_successful"] == 1
    endpoint_facts = _json(row["endpoint_facts_json"])
    presence = endpoint_facts.get("presence")
    presence = presence if isinstance(presence, dict) else {}
    port_coverage = endpoint_facts.get("port_coverage")
    port_coverage = port_coverage if isinstance(port_coverage, dict) else {}
    interval = port_coverage.get("collection_interval")
    interval = interval if isinstance(interval, dict) else {}
    start = interval.get("start") if isinstance(interval.get("start"), dict) else {}
    end = interval.get("end") if isinstance(interval.get("end"), dict) else {}
    numeric_interval = None
    if completed and interval.get("eligible") is True:
        try:
            start_value, end_value = Decimal(start["raw"]), Decimal(end["raw"])
            if (start_value.is_finite() and end_value.is_finite()
                    and start_value >= 0 and start_value < end_value
                    and start.get("valid") is True and end.get("valid") is True
                    and isinstance(start.get("utc"), str) and isinstance(end.get("utc"), str)):
                numeric_interval = (start_value, end_value)
        except (InvalidOperation, KeyError, TypeError):
            pass
    record = {
        "assignment": {
            "assignment_id": row["assignment_id"],
            "revision": int(row["revision"]),
            "event": row["event_kind"],
            "assigned_at": row["assigned_at"],
            "actor": row["assignment_actor"],
            "reason": row["reason"],
        },
        "assessment": {
            "assessment_id": row["assessment_id"],
            "parser_version": row["parser_version"],
            "assessed_at": row["assessed_at"],
            "processed_at": row["recorded_at"],
        },
        "source": _source(row),
        "presence": {
            "classification": presence.get("classification") or "unknown",
            "detail": presence.get("detail"),
        },
        "collection_window": {"start": start, "end": end},
        "service_count": int(row["service_count"]),
    }
    return record, numeric_interval, completed


def _latest_observation_group(candidates: list[dict], unknown_count: int) -> dict:
    if not candidates:
        if unknown_count:
            return {
                "status": "time_uncertain",
                "reason": (
                    "Successful current records exist, but none has a valid source "
                    "collection window, so NCT cannot claim which is latest overall"
                ),
                "records": [],
                "record_count": 0,
            }
        return {
            "status": "unavailable",
            "reason": "No successful record has a valid host collection window",
            "records": [],
            "record_count": 0,
        }
    max_end = max(item["interval"][1] for item in candidates)
    anchors = [item for item in candidates if item["interval"][1] == max_end]
    anchor_start = min(item["interval"][0] for item in anchors)
    while True:
        group = [
            item for item in candidates
            if item["interval"][0] <= max_end and item["interval"][1] >= anchor_start
        ]
        expanded_start = min(item["interval"][0] for item in group)
        if expanded_start == anchor_start:
            break
        anchor_start = expanded_start
    group.sort(key=lambda item: (
        -item["interval"][1], -item["interval"][0],
        item["record"]["assessment"]["assessment_id"],
        item["record"]["assignment"]["assignment_id"],
    ))
    if unknown_count:
        status = "time_uncertain"
        reason = (
            "A successful current record has no valid source collection window, so "
            "NCT cannot claim which supported observation is latest overall"
        )
    elif len(group) > 1:
        status = "overlapping"
        reason = (
            "The latest-ending supported observations overlap or share the same source "
            "collection time; NCT keeps them together"
        )
    else:
        status = "ordered"
        reason = "This supported observation has the latest non-overlapping source window"
    return {
        "status": status,
        "reason": reason,
        "records": [item["record"] for item in group],
        "record_count": len(group),
    }


def _slice_observation_group(group: dict, *, limit: int, offset: int) -> dict:
    records = group.pop("records")
    group["records"] = records[offset:offset + limit]
    group["pagination"] = {
        "limit": limit,
        "offset": offset,
        "total": len(records),
        "has_more": offset + len(group["records"]) < len(records),
    }
    return group


def get_foundation_latest_observations(
    db_path: Path, scope_id: str, entity_id: str, *,
    limit: int = 10, latest_offset: int = 0,
    confirmed_offset: int = 0, unknown_offset: int = 0,
) -> dict:
    """Derive latest supported and last-confirmed Nmap evidence without current-truth claims."""
    limit, latest_offset = _page(limit, latest_offset, MAX_RECEIPT_PAGE)
    _, confirmed_offset = _page(limit, confirmed_offset, MAX_RECEIPT_PAGE)
    _, unknown_offset = _page(limit, unknown_offset, MAX_RECEIPT_PAGE)
    with connect_database(db_path, read_only=True) as db:
        db.row_factory = sqlite3.Row
        db.execute("BEGIN")
        scope_row = db.execute(
            """SELECT scope_id, label, description, version, active
               FROM network_scopes WHERE scope_id = ?""",
            (scope_id,),
        ).fetchone()
        endpoint = db.execute(
            """SELECT entity_id, address FROM endpoint_entities
               WHERE entity_id = ? AND scope_id = ?""",
            (entity_id, scope_id),
        ).fetchone()
        if scope_row is None or endpoint is None:
            raise KeyError("Processed endpoint not found in this Network Scope")
        rows = db.execute(
            _LATEST_OBSERVATION_CANDIDATES_SQL,
            (scope_id, entity_id, NMAP_ENDPOINT_PARSER,
             MAX_LATEST_SELECTION_CANDIDATES + 1),
        ).fetchall()
    if len(rows) > MAX_LATEST_SELECTION_CANDIDATES:
        raise ValueError(
            "Latest-observation selection exceeds the reviewed per-address safety bound"
        )
    timed = []
    confirmed = []
    unknown_records = []
    incomplete_count = 0
    confirmed_unknown_count = 0
    for row in rows:
        record, interval, completed = _supported_observation_candidate(row)
        if not completed:
            incomplete_count += 1
            continue
        if interval is None:
            unknown_records.append(record)
            if record["presence"]["classification"] == "confirmed":
                confirmed_unknown_count += 1
            continue
        candidate = {"record": record, "interval": interval}
        timed.append(candidate)
        if record["presence"]["classification"] == "confirmed":
            confirmed.append(candidate)
    unknown_records.sort(key=lambda item: (
        item["assessment"]["assessment_id"], item["assignment"]["assignment_id"],
    ))
    latest = _slice_observation_group(
        _latest_observation_group(timed, len(unknown_records)),
        limit=limit, offset=latest_offset,
    )
    last_confirmed = _slice_observation_group(
        _latest_observation_group(confirmed, confirmed_unknown_count),
        limit=limit, offset=confirmed_offset,
    )
    unknown_page = unknown_records[unknown_offset:unknown_offset + limit]
    return {
        "contract": LATEST_OBSERVATION_SELECTION_CONTRACT,
        "scope": _scope(scope_row),
        "endpoint": {"entity_id": endpoint["entity_id"], "address": endpoint["address"]},
        "latest_supported_observations": latest,
        "last_confirmed_observations": last_confirmed,
        "unknown_time_records": unknown_page,
        "unknown_time_pagination": {
            "limit": limit,
            "offset": unknown_offset,
            "total": len(unknown_records),
            "has_more": unknown_offset + len(unknown_page) < len(unknown_records),
        },
        "incomplete_record_count": incomplete_count,
        "read_only": True,
        "claims": {
            "live_or_current_truth": False,
            "physical_device_identity": False,
            "exact_last_seen_timestamp": False,
            "last_confirmed_source_window": bool(
                last_confirmed["record_count"]
                and last_confirmed["status"] in {"ordered", "overlapping"}
            ),
            "service_disappearance": False,
        },
    }


_MAC_ASSOCIATION_CANDIDATES_SQL = _PRIMARY_CTE + """
SELECT assignment.assignment_id, assignment.revision, assignment.event_kind,
       assignment.assigned_at, assignment.actor AS assignment_actor, assignment.reason,
       assessment.assessment_id, assessment.parser_version, assessment.assessed_at,
       assessment.recorded_at,
       CASE
           WHEN json_valid(assessment.payload_json)
           THEN CASE
               WHEN json_type(
                   assessment.payload_json,
                   '$.facts.coverage.completion.successful'
               ) = 'true'
               THEN 1 ELSE 0
           END
           ELSE NULL
       END AS completion_successful,
       endpoint.entity_id, endpoint.address,
       receipt.facts_json AS endpoint_facts_json,
       observation.observation_id, observation.sha256, observation.source_kind,
       observation.source_ref, observation.observed_at, observation.original_filename,
       observation.actor AS observation_actor,
       (SELECT COUNT(*) FROM service_receipts service
        JOIN service_entities entity ON entity.entity_id = service.service_id
        WHERE service.assessment_id = assessment.assessment_id
          AND entity.host_id = receipt.host_id) AS service_count
FROM primary_links
JOIN artifact_scope_assignments assignment
  ON assignment.assignment_id = primary_links.assignment_id
JOIN entity_assessments assessment
  ON assessment.assessment_id = primary_links.assessment_id
JOIN endpoint_receipts receipt
  ON receipt.assessment_id = assessment.assessment_id
JOIN endpoint_entities endpoint
  ON endpoint.entity_id = receipt.host_id AND endpoint.scope_id = assignment.scope_id
JOIN artifact_observations observation
  ON observation.observation_id = assessment.artifact_observation_id
ORDER BY assignment.assignment_id, assessment.assessment_id,
         endpoint.address, endpoint.entity_id
LIMIT ?
"""


def _normalize_source_mac(value: object) -> tuple[str, bool] | None:
    if not isinstance(value, str):
        return None
    candidate = value.strip()
    if re.fullmatch(r"[0-9a-fA-F]{12}", candidate):
        compact = candidate
    elif re.fullmatch(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", candidate):
        compact = candidate.replace(":", "")
    elif re.fullmatch(r"(?:[0-9a-fA-F]{2}-){5}[0-9a-fA-F]{2}", candidate):
        compact = candidate.replace("-", "")
    elif re.fullmatch(r"[0-9a-fA-F]{4}(?:\.[0-9a-fA-F]{4}){2}", candidate):
        compact = candidate.replace(".", "")
    else:
        return None
    try:
        octets = bytes.fromhex(compact)
    except ValueError:
        return None
    if octets == b"\x00" * 6 or octets[0] & 1:
        return None
    normalized = ":".join(f"{part:02x}" for part in octets)
    return normalized, bool(octets[0] & 2)


def _reported_macs(endpoint_facts: dict) -> list[dict]:
    addresses = endpoint_facts.get("addresses")
    if not isinstance(addresses, list):
        return []
    found = {}
    for address in addresses:
        if not isinstance(address, dict):
            continue
        if str(address.get("addrtype") or "").strip().lower() != "mac":
            continue
        normalized = _normalize_source_mac(address.get("addr"))
        if normalized is None:
            continue
        mac, locally_administered = normalized
        found.setdefault(mac, {
            "mac": mac,
            "locally_administered": locally_administered,
            "vendor": str(address.get("vendor") or "").strip() or None,
        })
    return [found[key] for key in sorted(found)]


def _assignment_set_revision(rows: list[sqlite3.Row]) -> str:
    identities = sorted({
        (str(row["assignment_id"]), int(row["revision"]), str(row["assessment_id"]))
        for row in rows
    })
    encoded = json.dumps(identities, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _mark_interval_groups(items: list[dict]) -> None:
    timed = [item for item in items if item["_interval"] is not None]
    timed.sort(key=lambda item: (
        item["_interval"][0], item["_interval"][1], item["address"],
        item["assessment"]["assessment_id"], item["assignment"]["assignment_id"],
    ))
    groups: list[list[dict]] = []
    group_end = None
    for item in timed:
        start, end = item["_interval"]
        if not groups or start > group_end:
            groups.append([item])
            group_end = end
        else:
            groups[-1].append(item)
            group_end = max(group_end, end)
    for group_index, group in enumerate(groups, start=1):
        status = "overlapping_or_tied" if len(group) > 1 else "distinct_window"
        for item in group:
            item["source_window_group"] = group_index
            item["source_window_status"] = status
    for item in items:
        if item["_interval"] is None:
            item["source_window_group"] = None
            item["source_window_status"] = "unknown"
        item.pop("_interval", None)


def get_foundation_mac_associations(
    db_path: Path,
    scope_id: str,
    mac: str,
    *,
    limit: int = 25,
    offset: int = 0,
    expected_revision: str | None = None,
) -> dict:
    """List bounded source-reported MAC/address associations without device merging."""
    limit, offset = _page(limit, offset, MAX_MAC_ASSOCIATION_PAGE)
    normalized = _normalize_source_mac(mac)
    if normalized is None:
        raise ValueError("Use a valid unicast MAC address reported by Nmap")
    normalized_mac, locally_administered = normalized
    with connect_database(db_path, read_only=True) as db:
        db.row_factory = sqlite3.Row
        db.execute("BEGIN")
        scope_row = db.execute(
            """SELECT scope_id, label, description, version, active
               FROM network_scopes WHERE scope_id = ?""",
            (scope_id,),
        ).fetchone()
        if scope_row is None:
            raise KeyError("Network Scope not found")
        rows = db.execute(
            _MAC_ASSOCIATION_CANDIDATES_SQL,
            (scope_id, NMAP_ENDPOINT_PARSER, MAX_MAC_ASSOCIATION_CANDIDATES + 1),
        ).fetchall()
    if len(rows) > MAX_MAC_ASSOCIATION_CANDIDATES:
        raise ValueError(
            "This view cannot safely review more than 5,000 candidate source records "
            "at once. No result was produced and nothing changed. Use a smaller "
            "Network Scope"
        )
    selection_revision = _assignment_set_revision(rows)
    if expected_revision is not None and expected_revision != selection_revision:
        raise FoundationEvidenceConflict(
            "The current scope assignments changed; refresh address-association evidence"
        )

    associations = []
    excluded_unsuccessful = 0
    for row in rows:
        if row["completion_successful"] != 1:
            excluded_unsuccessful += 1
            continue
        endpoint_facts = _json(row["endpoint_facts_json"])
        reported = next(
            (item for item in _reported_macs(endpoint_facts)
             if item["mac"] == normalized_mac),
            None,
        )
        if reported is None:
            continue
        record, interval, completed = _supported_observation_candidate(row)
        if not completed:
            excluded_unsuccessful += 1
            continue
        associations.append({
            "address": row["address"],
            "entity_id": row["entity_id"],
            "mac": reported,
            "assignment": record["assignment"],
            "assessment": record["assessment"],
            "source": record["source"],
            "presence": record["presence"],
            "collection_window": record["collection_window"],
            "service_count": record["service_count"],
            "_interval": interval,
        })
    _mark_interval_groups(associations)
    associations.sort(key=lambda item: (
        item["source_window_group"] is None,
        item["source_window_group"] or 0,
        item["address"], item["assessment"]["assessment_id"],
        item["assignment"]["assignment_id"],
    ))
    page = associations[offset:offset + limit]
    return {
        "contract": MAC_ASSOCIATION_SELECTION_CONTRACT,
        "scope": _scope(scope_row),
        "mac": {
            "normalized": normalized_mac,
            "locally_administered": locally_administered,
            "warning": (
                "This MAC is locally administered and may be private, randomized, "
                "or reused by different systems"
                if locally_administered else None
            ),
        },
        "associations": page,
        "pagination": {
            "limit": limit,
            "offset": offset,
            "total": len(associations),
            "has_more": offset + len(page) < len(associations),
            "selection_revision": selection_revision,
        },
        "candidate_receipts_reviewed": len(rows),
        "excluded_unsuccessful_receipts": excluded_unsuccessful,
        "read_only": True,
        "claims": {
            "physical_device_identity": False,
            "address_move": False,
            "dhcp_cause": False,
            "live_or_current_truth": False,
            "exact_last_seen_timestamp": False,
            "cross_scope_identity": False,
        },
    }


_COMPARISON_RECORD_SQL = """
SELECT assignment.assignment_id, assignment.revision, assignment.event_kind,
       assignment.assigned_at, assignment.actor AS assignment_actor, assignment.reason,
       assessment.assessment_id, assessment.parser_version, assessment.assessed_at,
       assessment.recorded_at,
       json_extract(assessment.payload_json, '$.time_basis') AS time_basis,
       json_extract(assessment.payload_json, '$.facts.scan_start') AS scan_start_json,
       json_extract(assessment.payload_json, '$.facts.scan_end') AS scan_end_json,
       json_extract(assessment.payload_json, '$.facts.coverage') AS coverage_json,
       receipt.facts_json AS endpoint_facts_json,
       observation.observation_id, observation.sha256, observation.source_kind,
       observation.source_ref, observation.observed_at, observation.original_filename,
       observation.actor AS observation_actor,
       (SELECT COUNT(*) FROM service_receipts service
        JOIN service_entities entity ON entity.entity_id = service.service_id
        WHERE service.assessment_id = assessment.assessment_id
          AND entity.host_id = receipt.host_id) AS service_count
FROM artifact_scope_assignments assignment
JOIN assessment_scope_assignment_links link
  ON link.assignment_id = assignment.assignment_id
JOIN entity_assessments assessment ON assessment.assessment_id = link.assessment_id
JOIN endpoint_receipts receipt
  ON receipt.assessment_id = assessment.assessment_id AND receipt.host_id = ?
JOIN artifact_observations observation
  ON observation.observation_id = assessment.artifact_observation_id
WHERE assignment.assignment_id = ?
  AND assessment.assessment_id = ?
  AND assignment.scope_id = ?
  AND assessment.scope_id = ?
  AND assessment.parser_version = ?
  AND NOT EXISTS (
      SELECT 1 FROM artifact_scope_assignments successor
      WHERE successor.supersedes_assignment_id = assignment.assignment_id
  )
"""


_SERVICE_COMPARISON_SQL = """
WITH record_a AS (
    SELECT entity.entity_id AS service_id, entity.protocol, entity.port,
           receipt.facts_json
    FROM service_receipts receipt
    JOIN service_entities entity ON entity.entity_id = receipt.service_id
    WHERE receipt.assessment_id = ? AND entity.host_id = ?
), record_b AS (
    SELECT entity.entity_id AS service_id, entity.protocol, entity.port,
           receipt.facts_json
    FROM service_receipts receipt
    JOIN service_entities entity ON entity.entity_id = receipt.service_id
    WHERE receipt.assessment_id = ? AND entity.host_id = ?
), service_keys AS (
    SELECT protocol, port FROM record_a
    UNION
    SELECT protocol, port FROM record_b
), compared AS (
    SELECT service_keys.protocol, service_keys.port,
           record_a.service_id AS record_a_service_id,
           record_a.facts_json AS record_a_facts_json,
           record_b.service_id AS record_b_service_id,
           record_b.facts_json AS record_b_facts_json
    FROM service_keys
    LEFT JOIN record_a
      ON record_a.protocol = service_keys.protocol AND record_a.port = service_keys.port
    LEFT JOIN record_b
      ON record_b.protocol = service_keys.protocol AND record_b.port = service_keys.port
)
SELECT *, COUNT(*) OVER() AS total_count
FROM compared
ORDER BY protocol, port
LIMIT ? OFFSET ?
"""


def _comparison_record(row: sqlite3.Row) -> dict:
    return {
        "assignment": {
            "assignment_id": row["assignment_id"],
            "revision": int(row["revision"]),
            "event": row["event_kind"],
            "assigned_at": row["assigned_at"],
            "actor": row["assignment_actor"],
            "reason": row["reason"],
        },
        "assessment": {
            "assessment_id": row["assessment_id"],
            "parser_version": row["parser_version"],
            "assessed_at": row["assessed_at"],
            "time_basis": row["time_basis"],
            "processed_at": row["recorded_at"],
            "collection_window": {
                "start": _json(row["scan_start_json"]),
                "end": _json(row["scan_end_json"]),
            },
            "coverage": _json(row["coverage_json"]),
        },
        "source": _source(row),
        "endpoint_facts": _json(row["endpoint_facts_json"]),
        "service_count": int(row["service_count"]),
    }


def _reported_state(facts: dict | None) -> str | None:
    if not isinstance(facts, dict):
        return None
    state = facts.get("state")
    if not isinstance(state, dict):
        return None
    value = state.get("state")
    return value if isinstance(value, str) and value.strip() else None


def _service_side(service_id: str | None, facts_raw: str | None) -> dict | None:
    if service_id is None:
        return None
    facts = _json(facts_raw)
    service = facts.get("service") if isinstance(facts.get("service"), dict) else {}
    return {
        "service_id": service_id,
        "reported_state": _reported_state(facts),
        "service_name": service.get("name"),
        "extraction_locator": facts.get("extraction_locator"),
    }


def _comparison_kind(record_a: dict | None, record_b: dict | None) -> str:
    if record_a is None:
        return "recorded_only_in_b"
    if record_b is None:
        return "recorded_only_in_a"
    state_a, state_b = record_a["reported_state"], record_b["reported_state"]
    if state_a is None or state_b is None:
        return "comparison_unavailable"
    if state_a == state_b:
        return "same_reported_state"
    return "different_reported_state"


def _interval_values(record: dict, label: str) -> tuple[Decimal, Decimal] | tuple[None, str]:
    completion = record.get("assessment", {}).get("coverage", {}).get("completion", {})
    if not completion.get("successful"):
        return None, f"{label} source did not prove successful completion"
    interval = (
        record.get("endpoint_facts", {}).get("port_coverage", {})
        .get("collection_interval", {})
    )
    if not interval.get("eligible"):
        detail = "; ".join(interval.get("reasons") or []) or "interval proof is unavailable"
        return None, f"{label} collection interval is not eligible: {detail}"
    start, end = interval.get("start") or {}, interval.get("end") or {}
    try:
        start_value, end_value = Decimal(start["raw"]), Decimal(end["raw"])
    except (InvalidOperation, KeyError, TypeError):
        return None, f"{label} collection interval is unreadable"
    if not start_value.is_finite() or not end_value.is_finite() or start_value >= end_value:
        return None, f"{label} collection interval is invalid"
    return start_value, end_value


def _comparison_chronology(record_a: dict, record_b: dict) -> dict:
    interval_a = _interval_values(record_a, "Record A")
    interval_b = _interval_values(record_b, "Record B")
    reasons = [value[1] for value in (interval_a, interval_b) if value[0] is None]
    if reasons:
        return {"status": "unresolved", "earlier": None, "later": None,
                "reason": "; ".join(reasons)}
    start_a, end_a = interval_a
    start_b, end_b = interval_b
    if end_a < start_b:
        return {
            "status": "ordered", "earlier": "record_a", "later": "record_b",
            "reason": "Record A host collection ended before Record B began",
        }
    if end_b < start_a:
        return {
            "status": "ordered", "earlier": "record_b", "later": "record_a",
            "reason": "Record B host collection ended before Record A began",
        }
    return {
        "status": "unresolved", "earlier": None, "later": None,
        "reason": "Host collection intervals overlap or touch; chronological order is unresolved",
    }


def _coverage_for_omission(
    record: dict, label: str, protocol: str, port: int,
) -> tuple[bool, str, str | None]:
    receipt = record.get("endpoint_facts", {}).get("port_coverage", {})
    if receipt.get("contract") != "nmap-coverage:1":
        return False, f"{label} record has no supported versioned coverage receipt", None
    protocol_receipt = (receipt.get("protocols") or {}).get(protocol)
    if not isinstance(protocol_receipt, dict):
        return False, f"{label} record has no exact {protocol.upper()} coverage receipt", None
    if not protocol_receipt.get("omission_coverage_eligible"):
        detail = "; ".join(protocol_receipt.get("reasons") or []) or "coverage proof is incomplete"
        return False, f"{label} record cannot support a missing-service conclusion: {detail}", None
    intervals = protocol_receipt.get("requested_intervals") or []
    if not any(int(item.get("start", 1)) <= port <= int(item.get("end", -1))
               for item in intervals):
        return False, (
            f"Port {port} was not included in the {label.lower()} record's selected "
            f"{protocol.upper()} ports, so its {label.lower()} state is unknown"
        ), None
    if not protocol_receipt.get("omitted_state_eligible"):
        detail = "; ".join(protocol_receipt.get("omitted_state_reasons") or [])
        return False, f"{label} omitted-port state is not attributable: {detail}", None
    state = protocol_receipt.get("omitted_reported_state")
    return True, (
        f"The {label.lower()} record successfully covered {protocol.upper()} port {port} "
        f"and reported omitted ports as {state}"
    ), state


def _coverage_for_explicit(record: dict, label: str, protocol: str, port: int) -> tuple[bool, str]:
    receipt = record.get("endpoint_facts", {}).get("port_coverage", {})
    if receipt.get("contract") != "nmap-coverage:1":
        return False, f"{label} record has no supported versioned coverage receipt"
    protocol_receipt = (receipt.get("protocols") or {}).get(protocol)
    if not isinstance(protocol_receipt, dict):
        return False, f"{label} record has no exact {protocol.upper()} coverage receipt"
    if not protocol_receipt.get("explicit_observation_eligible"):
        detail = "; ".join(protocol_receipt.get("explicit_observation_reasons") or [])
        return False, f"{label} explicit service is not coverage-eligible: {detail or 'coverage proof is incomplete'}"
    intervals = protocol_receipt.get("requested_intervals") or []
    if not any(int(item.get("start", 1)) <= port <= int(item.get("end", -1))
               for item in intervals):
        return False, (
            f"Port {port} was not included in the {label.lower()} record's selected "
            f"{protocol.upper()} ports, so its {label.lower()} state is unknown"
        )
    return True, f"The {label.lower()} record explicitly and validly covered {protocol.upper()} port {port}"


def _lifecycle_result(
    chronology: dict, record_a_metadata: dict, record_b_metadata: dict,
    record_a: dict | None, record_b: dict | None, protocol: str, port: int,
) -> dict:
    if chronology["status"] != "ordered":
        return {"classification": "not_assessed", "reason": chronology["reason"]}
    if chronology["earlier"] == "record_a":
        earlier, later = record_a, record_b
        earlier_metadata, later_metadata = record_a_metadata, record_b_metadata
    else:
        earlier, later = record_b, record_a
        earlier_metadata, later_metadata = record_b_metadata, record_a_metadata

    def resolve_state(record_metadata, record, label):
        if record is not None:
            eligible, reason = _coverage_for_explicit(
                record_metadata, label, protocol, port,
            )
            state = record.get("reported_state")
            if not eligible:
                return None, None, reason
            if state is None:
                return None, None, f"The {label.lower()} explicit service receipt has no reported state"
            return state, "explicit", reason
        eligible, reason, state = _coverage_for_omission(
            record_metadata, label, protocol, port,
        )
        if not eligible:
            return None, None, reason
        if state not in {"open", "closed"}:
            return None, None, f"Aggregate {state} does not establish an exact service state"
        return state, "aggregate", reason

    earlier_state, earlier_basis, earlier_reason = resolve_state(
        earlier_metadata, earlier, "Earlier",
    )
    later_state, later_basis, later_reason = resolve_state(
        later_metadata, later, "Later",
    )
    unresolved = [
        reason for state, reason in (
            (earlier_state, earlier_reason), (later_state, later_reason),
        ) if state is None
    ]
    if unresolved:
        return {"classification": "not_assessed", "reason": "; ".join(unresolved)}

    basis_note = (
        f"earlier {earlier_basis} evidence and later {later_basis} evidence"
    )
    if earlier_state == later_state:
        return {
            "classification": "unchanged",
            "reason": f"Both ordered records reported {earlier_state} using {basis_note}",
        }
    if earlier_state == "closed" and later_state == "open":
        return {
            "classification": "new",
            "reason": f"State moved from closed to open using {basis_note}",
        }
    if earlier_state == "open" and later_state == "closed":
        return {
            "classification": "no_longer_observed",
            "reason": f"State moved from open to closed using {basis_note}",
        }
    return {
        "classification": "changed",
        "reason": f"Reported state changed from {earlier_state} to {later_state} using {basis_note}",
    }


def compare_foundation_receipt_services(
    db_path: Path, scope_id: str, entity_id: str, *,
    record_a_assignment_id: str, record_a_assessment_id: str,
    record_b_assignment_id: str, record_b_assessment_id: str,
    limit: int = 100, offset: int = 0,
) -> dict:
    """Compare service states in two selected saved source records."""
    limit, offset = _page(limit, offset, MAX_SERVICE_PAGE)
    if (record_a_assignment_id, record_a_assessment_id) == (
        record_b_assignment_id, record_b_assessment_id,
    ):
        raise ValueError("Record A and Record B must be different source records")
    with connect_database(db_path, read_only=True) as db:
        db.row_factory = sqlite3.Row
        db.execute("BEGIN")
        scope_row = db.execute(
            """SELECT scope_id, label, description, version, active
               FROM network_scopes WHERE scope_id = ?""",
            (scope_id,),
        ).fetchone()
        endpoint = db.execute(
            """SELECT entity_id, address FROM endpoint_entities
               WHERE entity_id = ? AND scope_id = ?""",
            (entity_id, scope_id),
        ).fetchone()
        if scope_row is None or endpoint is None:
            raise KeyError("Processed endpoint not found in this Network Scope")
        record_a_row = db.execute(
            _COMPARISON_RECORD_SQL,
            (entity_id, record_a_assignment_id, record_a_assessment_id,
             scope_id, scope_id, NMAP_ENDPOINT_PARSER),
        ).fetchone()
        record_b_row = db.execute(
            _COMPARISON_RECORD_SQL,
            (entity_id, record_b_assignment_id, record_b_assessment_id,
             scope_id, scope_id, NMAP_ENDPOINT_PARSER),
        ).fetchone()
        if record_a_row is None or record_b_row is None:
            raise KeyError(
                "A selected source record is unavailable, superseded, or uses an unsupported parser"
            )
        record_a_metadata = _comparison_record(record_a_row)
        record_b_metadata = _comparison_record(record_b_row)
        chronology = _comparison_chronology(record_a_metadata, record_b_metadata)
        rows = db.execute(
            _SERVICE_COMPARISON_SQL,
            (record_a_assessment_id, entity_id,
             record_b_assessment_id, entity_id, limit, offset),
        ).fetchall()
        if rows:
            total = int(rows[0]["total_count"])
        elif offset:
            first = db.execute(
                _SERVICE_COMPARISON_SQL,
                (record_a_assessment_id, entity_id,
                 record_b_assessment_id, entity_id, 1, 0),
            ).fetchone()
            total = int(first["total_count"]) if first else 0
        else:
            total = 0
        comparisons = []
        for row in rows:
            record_a = _service_side(
                row["record_a_service_id"], row["record_a_facts_json"],
            )
            record_b = _service_side(
                row["record_b_service_id"], row["record_b_facts_json"],
            )
            comparisons.append({
                "protocol": row["protocol"],
                "port": int(row["port"]),
                "comparison": _comparison_kind(record_a, record_b),
                "record_a": record_a,
                "record_b": record_b,
                "lifecycle": _lifecycle_result(
                    chronology, record_a_metadata, record_b_metadata,
                    record_a, record_b, row["protocol"], int(row["port"]),
                ),
            })
    return {
        "scope": _scope(scope_row),
        "endpoint": {"entity_id": endpoint["entity_id"], "address": endpoint["address"]},
        "record_a": record_a_metadata,
        "record_b": record_b_metadata,
        "chronology": chronology,
        "services": comparisons,
        "pagination": {
            "limit": limit, "offset": offset, "total": total,
            "has_more": offset + len(rows) < total,
        },
        "read_only": True,
        "claims": {
            "record_order_from_non_overlapping_host_intervals": chronology["status"] == "ordered",
            "coverage_aware_lifecycle": True,
            "current_truth": False,
            "last_seen": False,
            "absence_or_disappearance": False,
        },
    }
