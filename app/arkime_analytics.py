"""Bounded descriptive traffic analytics for one exact retained Arkime import."""
from __future__ import annotations

import hashlib
import ipaddress
import json
from pathlib import Path
import sqlite3

from app.database import connect_database


MAX_RESULTS = 100
MAX_RECEIPT_REFS = 100
MAX_FILTERS = 20
FILTER_FIELDS = {"ip.src", "ip.dst", "port.dst", "ipProtocol", "protocols", "vlan"}


class ArkimeAnalyticsError(ValueError):
    pass


def _known_sum(rows: list[sqlite3.Row], field: str) -> tuple[str, int]:
    values = [row[field] for row in rows if row[field] is not None]
    return str(sum(int(value) for value in values)), len(rows) - len(values)


def _metric(
    key: str, rows: list[sqlite3.Row], label: str | None = None,
    *, filter_field: str | None = None, filter_value=None,
    filter_clauses: list[dict] | None = None,
) -> dict:
    packets, missing_packets = _known_sum(rows, "packet_count")
    byte_count, missing_bytes = _known_sum(rows, "byte_count")
    ordinals = sorted(int(row["source_ordinal"]) for row in rows)
    return {
        "key": key,
        "label": label or key,
        "retained_session_rows": len(rows),
        "known_packet_total": packets,
        "packet_rows_missing": missing_packets,
        "known_byte_total": byte_count,
        "byte_rows_missing": missing_bytes,
        "receipt_ordinals": ordinals[:MAX_RECEIPT_REFS],
        "receipt_count": len(ordinals),
        "receipt_references_truncated": len(ordinals) > MAX_RECEIPT_REFS,
        "filter_clauses": filter_clauses if filter_clauses is not None else (
            [{"field": filter_field, "operator": "==", "value": filter_value}]
            if filter_field else []
        ),
    }


def _rank(
    groups: dict[str, list[sqlite3.Row]], labels: dict[str, str], limit: int,
    *, filter_field: str | None = None, filter_values: dict | None = None,
    filter_clause_groups: dict | None = None, result_keys: dict | None = None,
) -> list[dict]:
    values = filter_values or {}
    clause_groups = filter_clause_groups or {}
    output_keys = result_keys or {}
    items = [
        _metric(
            output_keys.get(key, key), rows, labels.get(key), filter_field=filter_field,
            filter_value=values.get(key, key),
            filter_clauses=clause_groups.get(key),
        )
        for key, rows in groups.items()
    ]
    items.sort(key=lambda item: (-item["retained_session_rows"], item["label"], item["key"]))
    return items[:limit]


def _group(rows: list[sqlite3.Row], key_function) -> tuple[dict, dict]:
    groups: dict[str, list[sqlite3.Row]] = {}
    labels: dict[str, str] = {}
    for row in rows:
        key, label = key_function(row)
        groups.setdefault(key, []).append(row)
        labels[key] = label
    return groups, labels


def _public_destination(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


def _json_values(value: str | None) -> list:
    try:
        decoded = json.loads(value or "[]")
    except json.JSONDecodeError:
        return []
    return decoded if isinstance(decoded, list) else []


def _filter_value(row: sqlite3.Row, source_kind: str, field: str) -> list:
    if field == "ip.src":
        value = row["source_ip"]
        return [] if value is None else [str(value)]
    if field == "ip.dst":
        value = row["destination_ip"]
        return [] if value is None else [str(value)]
    if field == "port.dst":
        value = row["destination_port"]
        return [] if value is None else [int(value)]
    if field == "ipProtocol":
        value = row["transport"]
        return [] if value is None else [str(value)]
    if field == "protocols":
        if source_kind == "sessions_json":
            return [str(value) for value in _json_values(row["applications_json"]) if value is not None]
        value = row["detected_protocol"]
        return [] if value is None else [str(value)]
    if field == "vlan":
        if source_kind == "sessions_json":
            return [int(value) for value in _json_values(row["vlan_json"]) if value is not None]
        value = row["vlan"]
        return [] if value is None else [int(value)]
    raise ArkimeAnalyticsError(f"Unsupported Arkime filter field: {field}")


def _normalize_clause(clause) -> dict:
    if not isinstance(clause, dict):
        raise ArkimeAnalyticsError("Each Arkime filter clause must be an object")
    field = clause.get("field")
    operator = clause.get("operator")
    value = clause.get("value")
    if not isinstance(field, str) or field not in FILTER_FIELDS:
        raise ArkimeAnalyticsError("Arkime filter field is unsupported or malformed")
    if not isinstance(operator, str) or operator not in {"==", "!="}:
        raise ArkimeAnalyticsError("Arkime filter operator must be == or !=")
    if value is not None and not isinstance(value, (str, int)):
        raise ArkimeAnalyticsError("Arkime filter values must be text, an integer, or Unknown")
    if isinstance(value, bool):
        raise ArkimeAnalyticsError("Arkime filter values must not be true or false")
    if isinstance(value, str) and (not value or len(value) > 200):
        raise ArkimeAnalyticsError("Arkime text filter values must contain 1 to 200 characters")
    if field in {"port.dst", "vlan"} and value is not None:
        numeric_value = str(value)
        if not numeric_value.isascii() or not numeric_value.isdecimal():
            raise ArkimeAnalyticsError(f"{field} requires a non-negative integer or Unknown")
        try:
            value = int(numeric_value)
        except (TypeError, ValueError, OverflowError) as exc:
            raise ArkimeAnalyticsError(
                f"{field} requires a non-negative integer or Unknown"
            ) from exc
    elif value is not None:
        value = str(value)
    return {"field": field, "operator": operator, "value": value}


def _normalize_filters(filters) -> list[dict]:
    if filters is None:
        return []
    if not isinstance(filters, list) or len(filters) > MAX_FILTERS:
        raise ArkimeAnalyticsError(f"filters must be a list with at most {MAX_FILTERS} clauses")
    normalized = []
    clause_count = 0
    for predicate in filters:
        if not isinstance(predicate, dict):
            raise ArkimeAnalyticsError("Each Arkime filter must be an object")
        if "clauses" not in predicate:
            normalized.append(_normalize_clause(predicate))
            clause_count += 1
            continue
        clauses = predicate.get("clauses")
        group_mode = predicate.get("match_mode", "all")
        negated = predicate.get("negated", False)
        if not isinstance(clauses, list) or not clauses:
            raise ArkimeAnalyticsError("Grouped Arkime filters require one or more clauses")
        if not isinstance(group_mode, str) or group_mode not in {"all", "any"}:
            raise ArkimeAnalyticsError("Grouped Arkime filter match_mode must be all or any")
        if type(negated) is not bool:
            raise ArkimeAnalyticsError("Grouped Arkime filter negated must be true or false")
        normalized_clauses = [_normalize_clause(clause) for clause in clauses]
        clause_count += len(normalized_clauses)
        normalized.append({
            "clauses": normalized_clauses,
            "match_mode": group_mode,
            "negated": negated,
        })
    if clause_count > MAX_FILTERS:
        raise ArkimeAnalyticsError(f"filters may contain at most {MAX_FILTERS} total clauses")
    return normalized


def _row_matches(row: sqlite3.Row, source_kind: str, clause: dict) -> bool:
    values = _filter_value(row, source_kind, clause["field"])
    wanted = clause["value"]
    matched = (not values) if wanted is None else wanted in values
    return matched if clause["operator"] == "==" else not matched


def _predicate_matches(row: sqlite3.Row, source_kind: str, predicate: dict) -> bool:
    if "clauses" not in predicate:
        return _row_matches(row, source_kind, predicate)
    matcher = all if predicate["match_mode"] == "all" else any
    matched = matcher(
        _row_matches(row, source_kind, clause) for clause in predicate["clauses"]
    )
    return not matched if predicate["negated"] else matched


def _apply_filters(
    rows: list[sqlite3.Row], source_kind: str, filters: list[dict], match_mode: str,
) -> list[sqlite3.Row]:
    if not isinstance(match_mode, str) or match_mode not in {"all", "any"}:
        raise ArkimeAnalyticsError("match_mode must be all or any")
    if not filters:
        return rows
    matcher = all if match_mode == "all" else any
    return [
        row for row in rows
        if matcher(_predicate_matches(row, source_kind, predicate) for predicate in filters)
    ]


def _expression_value(value) -> str:
    if value is None:
        return "EXISTS!"
    text = str(value)
    if all(character.isalnum() or character in ".:_-" for character in text):
        return text
    return json.dumps(text, ensure_ascii=False)


def _clause_expression(clause: dict) -> str:
    operator = clause["operator"]
    if clause["value"] is None:
        operator = "!=" if operator == "==" else "=="
    return f"({clause['field']} {operator} {_expression_value(clause['value'])})"


def _filter_expression(filters: list[dict], match_mode: str) -> str:
    parts = []
    for predicate in filters:
        if "clauses" not in predicate:
            parts.append(_clause_expression(predicate))
            continue
        grouped = (
            " && " if predicate["match_mode"] == "all" else " || "
        ).join(_clause_expression(clause) for clause in predicate["clauses"])
        expression = f"({grouped})"
        parts.append(f"!{expression}" if predicate["negated"] else expression)
    return (" && " if match_mode == "all" else " || ").join(parts)


def _session_analysis(record: sqlite3.Row, rows: list[sqlite3.Row], limit: int) -> dict:
    sources, source_labels = _group(
        rows, lambda row: (
            row["source_ip"] or "unknown", row["source_ip"] or "Unknown source address",
        ),
    )
    destinations, destination_labels = _group(
        rows, lambda row: (
            row["destination_ip"] or "unknown",
            row["destination_ip"] or "Unknown destination address",
        ),
    )
    ports, port_labels = _group(
        rows,
        lambda row: (
            f"{row['transport'] or 'unknown'}:{row['destination_port'] if row['destination_port'] is not None else 'unknown'}",
            f"{row['destination_port'] if row['destination_port'] is not None else 'Unknown port'} / {row['transport'] or 'unknown transport'}",
        ),
    )
    applications: dict[str, list[sqlite3.Row]] = {}
    application_labels: dict[str, str] = {}
    application_filter_values: dict[str, str | None] = {}
    application_result_keys: dict[str, str] = {}
    vlans: dict[str, list[sqlite3.Row]] = {}
    vlan_labels: dict[str, str] = {}
    transports, transport_labels = _group(
        rows, lambda row: (
            row["transport"] or "unknown", row["transport"] or "Unknown transport",
        ),
    )
    for row in rows:
        try:
            application_values = _json_values(row["applications_json"])
        except (TypeError, ValueError):
            application_values = []
        if not application_values:
            application_values = [None]
        for application in sorted(set(application_values), key=lambda value: str(value)):
            key = (
                f"reported:{json.dumps(str(application), ensure_ascii=True)}"
                if application is not None else "missing"
            )
            applications.setdefault(key, []).append(row)
            application_labels[key] = str(application) if application is not None else "Unknown application"
            application_filter_values[key] = None if application is None else str(application)
            application_result_keys[key] = str(application) if application is not None else "<missing>"
        try:
            vlan_values = _json_values(row["vlan_json"])
        except (TypeError, ValueError):
            vlan_values = []
        if not vlan_values:
            vlan_values = [None]
        for vlan in sorted(set(vlan_values), key=lambda value: (-1 if value is None else int(value))):
            key = str(vlan) if vlan is not None else "unknown"
            vlans.setdefault(key, []).append(row)
            vlan_labels[key] = f"VLAN {vlan}" if vlan is not None else "VLAN unknown"
    public = {
        key: group for key, group in destinations.items() if _public_destination(key)
    }
    return {
        "analysis_mode": "individual_session_rows",
        "metric_definition": (
            "Rankings count retained session rows. Packet and byte totals are associated "
            "with each reported address or category and may include both traffic directions."
        ),
        "retained_row_count": len(rows),
        "top_source_addresses": _rank(
            sources, source_labels, limit, filter_field="ip.src",
            filter_values={key: None if key == "unknown" else key for key in sources},
        ),
        "top_destination_addresses": _rank(
            destinations, destination_labels, limit, filter_field="ip.dst",
            filter_values={key: None if key == "unknown" else key for key in destinations},
        ),
        "public_destination_addresses": _rank(
            public, destination_labels, limit, filter_field="ip.dst",
        ),
        "destination_port_activity": _rank(
            ports, port_labels, limit,
            filter_clause_groups={
                key: [
                    {
                        "field": "ipProtocol", "operator": "==",
                        "value": None if key.rsplit(":", 1)[0] == "unknown" else key.rsplit(":", 1)[0],
                    },
                    {
                        "field": "port.dst", "operator": "==",
                        "value": None if key.endswith(":unknown") else int(key.rsplit(":", 1)[1]),
                    },
                ]
                for key in ports
            },
        ),
        "transport_activity": _rank(
            transports, transport_labels, limit, filter_field="ipProtocol",
            filter_values={key: None if key == "unknown" else key for key in transports},
        ),
        "application_activity": _rank(
            applications, application_labels, limit, filter_field="protocols",
            filter_values=application_filter_values, result_keys=application_result_keys,
        ),
        "vlan_activity": _rank(
            vlans, vlan_labels, limit, filter_field="vlan",
            filter_values={key: None if key == "unknown" else int(key) for key in vlans},
        ),
        "reported_groups": [],
        "category_note": (
            "Application and VLAN categories can overlap because one retained session row "
            "may report several applications or VLAN values."
        ),
        "public_address_note": (
            "Public destinations are addresses classified as globally routable by the IP "
            "address standard. This is not a reviewed mission-boundary or threat label."
        ),
    }


def _summary_analysis(record: sqlite3.Row, rows: list[sqlite3.Row], limit: int) -> dict:
    groups = []
    for row in rows:
        groups.append({
            "source_ordinal": int(row["source_ordinal"]),
            "source_line": int(row["source_line"]),
            "source_ip": row["source_ip"],
            "destination_ip": row["destination_ip"],
            "destination_port": row["destination_port"],
            "transport": row["transport"],
            "detected_protocol": row["detected_protocol"],
            "vlan": row["vlan"],
            "session_count": None if row["session_count"] is None else str(row["session_count"]),
            "packet_count": None if row["packet_count"] is None else str(row["packet_count"]),
            "byte_count": None if row["byte_count"] is None else str(row["byte_count"]),
            "public_destination": _public_destination(row["destination_ip"]),
            "filter_values": {
                "ip.src": row["source_ip"],
                "ip.dst": row["destination_ip"],
                "port.dst": row["destination_port"],
                "ipProtocol": row["transport"],
                "protocols": row["detected_protocol"],
                "vlan": row["vlan"],
            },
        })
    def order(item: dict):
        values = [item["session_count"], item["packet_count"], item["byte_count"]]
        strongest = max((int(value) for value in values if value is not None), default=-1)
        return (-strongest, item["source_line"])
    groups.sort(key=order)
    return {
        "analysis_mode": "reported_summary_groups",
        "metric_definition": (
            "Each row is one reported grouping from the exact retained summary. NCT does "
            "not add groups because different group fields can overlap."
        ),
        "retained_row_count": len(rows),
        "top_source_addresses": [],
        "top_destination_addresses": [],
        "public_destination_addresses": [],
        "destination_port_activity": [],
        "transport_activity": [],
        "application_activity": [],
        "vlan_activity": [],
        "reported_groups": groups[:limit],
        "reported_group_count": len(groups),
        "reported_groups_truncated": len(groups) > limit,
        "category_note": (
            "Summary groups stay separate; missing counts remain Unknown and numeric zero "
            "remains a measured zero."
        ),
        "public_address_note": (
            "Public-destination flags use globally routable address classification only. "
            "They do not establish mission-boundary direction or maliciousness."
        ),
    }


def analyze_arkime_import(
    db_path: Path, import_id: str, *, limit: int = 25,
    filters=None, match_mode: str = "all",
) -> dict:
    if not isinstance(import_id, str) or not import_id.strip():
        raise ArkimeAnalyticsError("import_id is required")
    if type(limit) is not int or not 1 <= limit <= MAX_RESULTS:
        raise ArkimeAnalyticsError(f"limit must be between 1 and {MAX_RESULTS}")
    normalized_filters = _normalize_filters(filters)
    if not isinstance(match_mode, str) or match_mode not in {"all", "any"}:
        raise ArkimeAnalyticsError("match_mode must be all or any")
    try:
        with connect_database(Path(db_path), read_only=True) as db:
            db.row_factory = sqlite3.Row
            db.execute("BEGIN")
            tables = {
                row[0] for row in db.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            }
            session = None
            summary = None
            if "arkime_imports" in tables:
                session = db.execute(
                    "SELECT * FROM arkime_imports WHERE import_id=?", (import_id,),
                ).fetchone()
            if "arkime_summary_imports" in tables:
                summary = db.execute(
                    "SELECT * FROM arkime_summary_imports WHERE import_id=?", (import_id,),
                ).fetchone()
            if session is None and summary is None:
                raise KeyError("Arkime import not found")
            if session is not None:
                rows = db.execute(
                    "SELECT * FROM arkime_session_receipts WHERE import_id=? "
                    "ORDER BY source_ordinal", (import_id,),
                ).fetchall()
                unfiltered_row_count = len(rows)
                rows = _apply_filters(rows, "sessions_json", normalized_filters, match_mode)
                analysis = _session_analysis(session, rows, limit)
                source_kind = "sessions_json"
                source_url = f"/api/arkime/imports/{import_id}/raw"
                detail_url = f"/api/arkime/imports/{import_id}"
                completeness = session["calculated_export_completeness"]
                record = session
            else:
                rows = db.execute(
                    "SELECT * FROM arkime_summary_receipts WHERE import_id=? "
                    "ORDER BY source_ordinal", (import_id,),
                ).fetchall()
                unfiltered_row_count = len(rows)
                rows = _apply_filters(rows, "summary_csv", normalized_filters, match_mode)
                analysis = _summary_analysis(summary, rows, limit)
                source_kind = "summary_csv"
                source_url = f"/api/arkime/summary-imports/{import_id}/raw"
                detail_url = f"/api/arkime/summary-imports/{import_id}"
                completeness = summary["recorded_export_completeness"]
                record = summary
            revision_material = (
                f"{source_kind}:{record['import_id']}:{record['observation_id']}:"
                f"{record['returned_count']}:{record['imported_at']}"
            )
    except (ArkimeAnalyticsError, KeyError):
        raise
    except sqlite3.Error as exc:
        raise ArkimeAnalyticsError("Arkime analytics storage is unavailable") from exc
    return {
        "import_id": import_id,
        "source_kind": source_kind,
        "source_revision": hashlib.sha256(revision_material.encode()).hexdigest(),
        "scope": {
            "scope_id": record["scope_id"], "label": record["scope_label"],
            "version": int(record["scope_version"]),
        },
        "operator_sensor": record["operator_sensor"],
        "query_start": record["query_start"],
        "query_end": record["query_end"],
        "export_completeness": completeness,
        "capture_coverage": record["capture_coverage"],
        "raw_url": source_url,
        "detail_url": detail_url,
        "read_only": True,
        "unfiltered_row_count": unfiltered_row_count,
        "filtered_row_count": len(rows),
        "active_filters": normalized_filters,
        "filter_match_mode": match_mode,
        "filter_expression": _filter_expression(normalized_filters, match_mode),
        "filter_note": (
            "This Arkime-style expression filters only the exact retained NCT source. "
            "It does not contact Arkime or run a new live query."
        ),
        **analysis,
    }
