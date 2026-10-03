"""Read-only, correction-aware views over processed scoped Nmap evidence."""
from __future__ import annotations

import json
from pathlib import Path
import sqlite3

from app.database import connect_database
from app.nmap_evidence import NMAP_ENDPOINT_PARSER


MAX_SCOPE_PAGE = 100
MAX_ENDPOINT_PAGE = 100
MAX_RECEIPT_PAGE = 25
MAX_SERVICE_PAGE = 250


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
