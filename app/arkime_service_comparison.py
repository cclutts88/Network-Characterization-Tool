"""Read-only inverse comparison against one entire retained Sessions import."""
from __future__ import annotations

import ipaddress
import hashlib
import json
from pathlib import Path
import sqlite3

from app.arkime_analytics import ArkimeAnalyticsError, _window_context
from app.arkime_evidence import MAX_ARKIME_SESSIONS
from app.database import connect_database
from app.foundation_evidence import get_foundation_exact_service_states_snapshot

MAX_CANDIDATE_SERVICES = 10_000

NOTE = (
    "No destination traffic in this selected source means no exact destination address, "
    "transport and port receipt exists in the entire selected import. Traffic filters "
    "and path pages are ignored. It does not mean unused, closed, currently open or "
    "outside sensor coverage. Export and capture declarations may be incomplete or unknown."
)


class ArkimeComparisonChanged(ArkimeAnalyticsError):
    pass


def compare_unobserved_services(db_path: Path, import_id: str, *, limit=25, offset=0, candidate_revision=None):
    if not isinstance(import_id, str) or not import_id.strip():
        raise ArkimeAnalyticsError("Select one retained Sessions import")
    if type(limit) is not int or not 1 <= limit <= 100 or type(offset) is not int or offset < 0:
        raise ArkimeAnalyticsError("Comparison needs a page size of 1–100 and a nonnegative offset")
    try:
        with connect_database(db_path, read_only=True) as db:
            db.row_factory = sqlite3.Row
            db.execute("BEGIN")
            record = db.execute("SELECT * FROM arkime_imports WHERE import_id=?", (import_id,)).fetchone()
            if record is None:
                raise ArkimeAnalyticsError("This comparison requires a retained Sessions import; summary groups are unsupported")
            receipts = db.execute("SELECT source_ordinal, destination_ip, transport, destination_port FROM arkime_session_receipts WHERE import_id=? ORDER BY source_ordinal LIMIT ?", (import_id, MAX_ARKIME_SESSIONS + 1)).fetchall()
            if len(receipts) > MAX_ARKIME_SESSIONS or len(receipts) != record["returned_count"] or any(row["source_ordinal"] != index for index, row in enumerate(receipts)):
                raise ArkimeAnalyticsError("Retained receipt inventory is incomplete or exceeds the comparison bound")
            if any(row["transport"] not in {"tcp", "udp", "sctp"} or row["destination_port"] is None for row in receipts):
                raise ArkimeAnalyticsError("Destination transport or port is unknown or unsupported in this source; no missing-traffic comparison was produced")
            observed = {(row["destination_ip"], row["transport"], row["destination_port"]) for row in receipts}
            scope = db.execute("SELECT scope_id FROM network_scopes WHERE scope_id=?", (record["scope_id"],)).fetchone()
            if scope is None:
                raise ArkimeAnalyticsError("The retained Network Scope is unavailable")
            candidates_sql = "FROM service_entities s JOIN endpoint_entities e ON e.entity_id=s.host_id WHERE e.scope_id=?"
            membership = db.execute("SELECT s.entity_id, e.address, s.protocol, s.port " + candidates_sql + " ORDER BY s.entity_id LIMIT ?", (record["scope_id"], MAX_CANDIDATE_SERVICES + 1)).fetchall()
            total = len(membership)
            if total > MAX_CANDIDATE_SERVICES:
                raise ArkimeAnalyticsError("Scope exceeds the reviewed 10,000 candidate-service bound; no partial comparison was produced")
            revision = hashlib.sha256(json.dumps([record["scope_id"], [tuple(row) for row in membership]]).encode()).hexdigest()
            if (offset and not candidate_revision) or (candidate_revision is not None and candidate_revision != revision):
                raise ArkimeComparisonChanged("The candidate list changed or its page reference is missing. Choose Check saved services to start again")
            def address_key(value):
                address = ipaddress.ip_address(value)
                return bytes([address.version]) + address.packed
            db.create_function("nct_comparison_address_key", 1, address_key)
            candidates = db.execute("SELECT e.entity_id, e.address, s.protocol, s.port " + candidates_sql + " ORDER BY nct_comparison_address_key(e.address), s.protocol, s.port LIMIT ? OFFSET ?", (record["scope_id"], limit, offset)).fetchall()
            grouped = {}
            for row in candidates:
                grouped.setdefault(row["entity_id"], []).append((row["protocol"], row["port"]))
            selections = {entity_id: get_foundation_exact_service_states_snapshot(db, record["scope_id"], entity_id, services) for entity_id, services in grouped.items()}
            result = []
            for row in candidates:
                selection = selections[row["entity_id"]]
                service = next(value for value in selection["services"] if (value["protocol"], value["port"]) == (row["protocol"], row["port"]))
                if selection["selection"]["status"] != "ordered" or service["status"] != "reported" or service["reported_state"] != "open":
                    continue
                if (row["address"], row["protocol"], row["port"]) in observed:
                    continue
                evidence = service["evidence"][0]
                result.append({"address": row["address"], "entity_id": row["entity_id"], "protocol": row["protocol"], "port": row["port"], "label": "No destination traffic in this selected source", "active_source": evidence["source"], "evidence_windows": _window_context(record, evidence), "selection_revision": selection["selection_revision"]})
            return {"contract": "arkime-unobserved-services:1", "import_id": import_id, "candidate_revision": revision, "scope": {"scope_id": record["scope_id"], "label": record["scope_label"], "version": record["scope_version"]}, "operator_sensor": record["operator_sensor"], "query_start": record["query_start"], "query_end": record["query_end"], "export_completeness": record["calculated_export_completeness"], "capture_coverage": record["capture_coverage"], "raw_url": f"/api/arkime/imports/{import_id}/raw", "note": NOTE, "rows": result, "checked_candidates": len(candidates), "pagination": {"offset": offset, "limit": limit, "candidate_total": total, "has_more": offset + len(candidates) < total}, "read_only": True}
    except (sqlite3.Error, ValueError) as exc:
        if isinstance(exc, ArkimeAnalyticsError):
            raise
        raise ArkimeAnalyticsError("Retained comparison is unavailable: " + str(exc)) from exc
