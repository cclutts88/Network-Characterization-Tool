"""Bounded descriptive traffic analytics for one exact retained Arkime import."""
from __future__ import annotations

import hashlib
import ipaddress
import json
from datetime import datetime, timezone
from pathlib import Path
import re
import sqlite3

from app.database import connect_database
from app.foundation_evidence import get_foundation_exact_service_states_snapshot


MAX_RESULTS = 100
MAX_RECEIPT_REFS = 100
MAX_FILTERS = 20
MAX_EXPRESSION_LENGTH = 8192
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


def _scan_expression_level(expression: str) -> tuple[list[str], str | None]:
    parts: list[str] = []
    connectors: list[str] = []
    start = 0
    depth = 0
    quoted = False
    escaped = False
    index = 0
    while index < len(expression):
        character = expression[index]
        if quoted:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                quoted = False
            index += 1
            continue
        if character == '"':
            quoted = True
            index += 1
            continue
        if character == "(":
            depth += 1
            index += 1
            continue
        if character == ")":
            depth -= 1
            if depth < 0:
                raise ArkimeAnalyticsError("Typed expression has an unmatched closing parenthesis")
            index += 1
            continue
        connector = expression[index:index + 2]
        if depth == 0 and connector in {"&&", "||"}:
            part = expression[start:index].strip()
            if not part:
                raise ArkimeAnalyticsError("Typed expression has an empty clause")
            parts.append(part)
            connectors.append(connector)
            index += 2
            start = index
            continue
        index += 1
    if quoted:
        raise ArkimeAnalyticsError("Typed expression has an unterminated quoted value")
    if depth:
        raise ArkimeAnalyticsError("Typed expression has an unmatched opening parenthesis")
    if not connectors:
        return [expression.strip()], None
    final = expression[start:].strip()
    if not final:
        raise ArkimeAnalyticsError("Typed expression has an empty clause")
    parts.append(final)
    if len(set(connectors)) != 1:
        raise ArkimeAnalyticsError(
            "Use one connector at each level: group mixed AND and OR clauses with parentheses"
        )
    return parts, connectors[0]


def _is_wrapped_expression(expression: str) -> bool:
    if len(expression) < 2 or expression[0] != "(" or expression[-1] != ")":
        return False
    depth = 0
    quoted = False
    escaped = False
    for index, character in enumerate(expression):
        if quoted:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                quoted = False
            continue
        if character == '"':
            quoted = True
        elif character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
            if depth == 0 and index != len(expression) - 1:
                return False
            if depth < 0:
                return False
    return depth == 0 and not quoted


def _strip_expression_wrapper(expression: str) -> str:
    value = expression.strip()
    while _is_wrapped_expression(value):
        value = value[1:-1].strip()
    return value


def _parse_expression_value(value: str):
    value = value.strip()
    if not value:
        raise ArkimeAnalyticsError("Typed expression requires a value after == or !=")
    if value == "EXISTS!":
        return None
    if value.startswith('"'):
        try:
            decoded = json.loads(value)
        except json.JSONDecodeError as exc:
            raise ArkimeAnalyticsError("Typed expression contains an invalid quoted value") from exc
        if not isinstance(decoded, str):
            raise ArkimeAnalyticsError("Quoted Arkime filter values must be text")
        return decoded
    if any(character.isspace() for character in value):
        raise ArkimeAnalyticsError("Put double quotes around filter values that contain spaces")
    if any(token in value for token in ("(", ")", "&&", "||", "==", "!=")):
        raise ArkimeAnalyticsError("Typed expression contains unsupported syntax in a value")
    return value


def _parse_expression_clause(expression: str) -> dict:
    value = _strip_expression_wrapper(expression)
    match = re.fullmatch(r"([A-Za-z][A-Za-z0-9.]*)\s*(==|!=)\s*(.+)", value)
    if not match:
        raise ArkimeAnalyticsError(
            "Use a supported field followed by == or != and one exact value"
        )
    field, operator, raw_value = match.groups()
    parsed_value = _parse_expression_value(raw_value)
    if parsed_value is None:
        operator = "!=" if operator == "==" else "=="
    return _normalize_clause({"field": field, "operator": operator, "value": parsed_value})


def _parse_expression_predicate(expression: str) -> dict:
    value = expression.strip()
    negated = value.startswith("!")
    if negated:
        value = value[1:].strip()
        if not _is_wrapped_expression(value):
            raise ArkimeAnalyticsError("NOT must be followed by a parenthesized clause group")
    if _is_wrapped_expression(value):
        inner = value[1:-1].strip()
        parts, connector = _scan_expression_level(inner)
        if connector:
            clauses = []
            for part in parts:
                nested = _strip_expression_wrapper(part)
                _, nested_connector = _scan_expression_level(nested)
                if nested_connector:
                    raise ArkimeAnalyticsError(
                        "Typed expression nesting is too deep; split it into simpler grouped clauses"
                    )
                clauses.append(_parse_expression_clause(part))
            return {
                "clauses": clauses,
                "match_mode": "all" if connector == "&&" else "any",
                "negated": negated,
            }
        value = inner
    clause = _parse_expression_clause(value)
    if negated:
        clause["operator"] = "!=" if clause["operator"] == "==" else "=="
    return clause


def parse_arkime_filter_expression(expression: str | None) -> tuple[list[dict], str]:
    if expression is None:
        return [], "all"
    if not isinstance(expression, str):
        raise ArkimeAnalyticsError("Typed expression must be text")
    if not expression.strip():
        return [], "all"
    if len(expression) > MAX_EXPRESSION_LENGTH:
        raise ArkimeAnalyticsError(
            f"Typed expression must contain no more than {MAX_EXPRESSION_LENGTH} characters"
        )
    value = expression.strip()
    while _is_wrapped_expression(value):
        value = value[1:-1].strip()
    parts, connector = _scan_expression_level(value)
    predicates = [_parse_expression_predicate(part) for part in parts]
    match_mode = "any" if connector == "||" else "all"
    return _normalize_filters(predicates), match_mode


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


def _correlated_paths(rows: list[sqlite3.Row], limit: int) -> list[dict]:
    groups: dict[tuple, list[sqlite3.Row]] = {}
    for row in rows:
        key = (
            row["source_ip"], row["destination_ip"], row["transport"],
            row["destination_port"],
        )
        groups.setdefault(key, []).append(row)
    paths = []
    for (source_ip, destination_ip, transport, destination_port), grouped_rows in groups.items():
        packets, missing_packets = _known_sum(grouped_rows, "packet_count")
        byte_count, missing_bytes = _known_sum(grouped_rows, "byte_count")
        ordinals = sorted(int(row["source_ordinal"]) for row in grouped_rows)
        paths.append({
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "transport": transport,
            "destination_port": destination_port,
            "retained_session_rows": len(grouped_rows),
            "known_packet_total": packets,
            "packet_rows_missing": missing_packets,
            "known_byte_total": byte_count,
            "byte_rows_missing": missing_bytes,
            "receipt_ordinals": ordinals[:MAX_RECEIPT_REFS],
            "receipt_count": len(ordinals),
            "receipt_references_truncated": len(ordinals) > MAX_RECEIPT_REFS,
            "filter_clauses": [
                {"field": "ip.src", "operator": "==", "value": source_ip},
                {"field": "ip.dst", "operator": "==", "value": destination_ip},
                {"field": "ipProtocol", "operator": "==", "value": transport},
                {"field": "port.dst", "operator": "==", "value": destination_port},
            ],
        })
    paths.sort(key=lambda item: (
        -item["retained_session_rows"], item["source_ip"] or "",
        item["destination_ip"] or "", item["transport"] or "",
        -1 if item["destination_port"] is None else item["destination_port"],
    ))
    return paths[:limit]


def _parse_utc(value: object) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _window_context(record: sqlite3.Row, evidence: dict | None) -> dict:
    passive = {"start": record["query_start"], "end": record["query_end"]}
    active = evidence.get("collection_window") if evidence else None
    active_start = _parse_utc((active or {}).get("start", {}).get("utc"))
    active_end = _parse_utc((active or {}).get("end", {}).get("utc"))
    passive_start = _parse_utc(record["query_start"])
    passive_end = _parse_utc(record["query_end"])
    if None in {active_start, active_end, passive_start, passive_end}:
        relationship = "unknown"
        note = (
            "The retained Arkime and Nmap windows are shown separately; their time "
            "relationship cannot be established."
        )
    elif active_end < passive_start:
        relationship = "active_before_passive"
        note = (
            "The Nmap collection ended before this retained Arkime window began. "
            "These are reports from different times."
        )
    elif passive_end < active_start:
        relationship = "passive_before_active"
        note = (
            "This retained Arkime window ended before the Nmap collection began. "
            "These are reports from different times."
        )
    else:
        relationship = "overlapping"
        note = (
            "The retained Arkime and Nmap collection windows overlap. This still does "
            "not prove both tools observed the same packet or service event."
        )
    return {
        "passive": passive,
        "active": active,
        "relationship": relationship,
        "note": note,
    }


def _endpoint_link(scope_id: str, row: sqlite3.Row | None) -> dict | None:
    if row is None:
        return None
    entity_id = str(row["entity_id"])
    return {
        "entity_id": entity_id,
        "address": str(row["address"]),
        "detail_url": (
            f"/api/foundation-evidence/scopes/{scope_id}/endpoints/{entity_id}"
        ),
        "workspace_url": "/analysis#networkChangesPanel",
    }


def _active_label(service: dict, selection: dict) -> tuple[str, str, str]:
    if selection["status"] == "unresolved" or service["status"] == "unresolved":
        return (
            "active_state_unresolved",
            "Active state unresolved",
            selection["reason"],
        )
    if service["status"] != "reported":
        return (
            "not_actively_assessed",
            "Not actively assessed",
            service["reason"],
        )
    state = str(service.get("reported_state") or "").strip().lower()
    if state == "open":
        return (
            "reported_open_and_observed",
            "Reported open + observed",
            "Nmap reported this exact destination protocol and port open, and this "
            "retained Arkime source reports traffic to it.",
        )
    if state == "closed":
        detail = "reported closed"
    elif state == "filtered":
        detail = "reported filtered"
    else:
        detail = f"reported an ambiguous state ({state or 'Unknown'})"
    return (
        "observed_scan_mismatch",
        "Observed / Scan Mismatch",
        f"Nmap {detail}, while this retained Arkime source reports traffic to the "
        "same destination protocol and port. The reports may cover different times, "
        "and observed packets do not prove that a connection succeeded or a listener "
        "was open.",
    )


def _path_characterization(status: str, reason: str) -> dict:
    result = {
        "passive_observation": {
            "status": "passively_observed",
            "label": "Passively observed",
            "reason": (
                "This exact retained Arkime source reported one or more individual "
                "session rows for this communication path."
            ),
        },
        "active_validation": None,
    }
    if status in {
        "passive_only_in_scope",
        "insufficient_path_fields",
        "not_actively_assessed",
        "active_state_unresolved",
    }:
        result["active_validation"] = {
            "status": "not_actively_validated",
            "label": "Not actively validated",
            "reason": reason,
        }
    return result


def _attach_active_context(
    db: sqlite3.Connection,
    record: sqlite3.Row,
    paths: list[dict],
) -> None:
    """Attach exact-scope Nmap context using the caller's Arkime read snapshot."""
    addresses = sorted({
        value
        for path in paths
        for value in (path.get("source_ip"), path.get("destination_ip"))
        if isinstance(value, str) and value
    })
    if not addresses:
        return
    marks = ",".join("?" for _ in addresses)
    endpoint_table = db.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='endpoint_entities'"
    ).fetchone()
    endpoint_rows = [] if endpoint_table is None else db.execute(
        f"""SELECT entity_id, address FROM endpoint_entities
             WHERE scope_id = ? AND address IN ({marks})
             ORDER BY address, entity_id""",
        [record["scope_id"], *addresses],
    ).fetchall()
    endpoints = {str(row["address"]): row for row in endpoint_rows}
    grouped: dict[str, set[tuple[str, int]]] = {}
    for path in paths:
        destination = path.get("destination_ip")
        endpoint = endpoints.get(destination)
        protocol = str(path.get("transport") or "").lower()
        port = path.get("destination_port")
        if endpoint is not None and protocol in {"tcp", "udp", "sctp"} \
                and type(port) is int and 0 <= port <= 65535:
            grouped.setdefault(str(endpoint["entity_id"]), set()).add((protocol, port))
    selections = {}
    for entity_id, services in grouped.items():
        try:
            selections[entity_id] = get_foundation_exact_service_states_snapshot(
                db, str(record["scope_id"]), entity_id, sorted(services),
            )
        except ValueError as exc:
            raise ArkimeAnalyticsError(
                f"Active Nmap context is unavailable: {exc}"
            ) from exc
    for path in paths:
        source_endpoint = endpoints.get(path.get("source_ip"))
        destination_endpoint = endpoints.get(path.get("destination_ip"))
        base = {
            "contract": "arkime-active-context:1",
            "scope_id": record["scope_id"],
            "scope_version": int(record["scope_version"]),
            "source_endpoint": _endpoint_link(record["scope_id"], source_endpoint),
            "destination_endpoint": _endpoint_link(
                record["scope_id"], destination_endpoint,
            ),
            "read_only": True,
            "claims": {
                "live_or_current_network_truth": False,
                "physical_device_identity": False,
                "connection_succeeded": False,
                "listener_open": False,
                "same_event": False,
            },
        }
        if destination_endpoint is None:
            reason = (
                "No supported processed Nmap endpoint exists for this destination "
                "address in the same Network Scope. This does not mean it was never scanned."
            )
            path["active_context"] = {
                **base,
                "status": "passive_only_in_scope",
                "label": "Passive only in this scope",
                "reason": reason,
                **_path_characterization("passive_only_in_scope", reason),
                "reported_state": None,
                "selection_revision": None,
                "active_source": None,
                "active_sources": [],
                "evidence_windows": _window_context(record, None),
            }
            continue
        protocol = str(path.get("transport") or "").lower()
        port = path.get("destination_port")
        if (
            protocol not in {"tcp", "udp", "sctp"}
            or type(port) is not int
            or not 0 <= port <= 65535
        ):
            reason = (
                "This retained path has no supported exact transport and destination "
                "port, so NCT cannot compare it with Nmap service coverage."
            )
            path["active_context"] = {
                **base,
                "status": "insufficient_path_fields",
                "label": "Not actively assessed",
                "reason": reason,
                **_path_characterization("insufficient_path_fields", reason),
                "reported_state": None,
                "selection_revision": None,
                "active_source": None,
                "active_sources": [],
                "evidence_windows": _window_context(record, None),
            }
            continue
        selection = selections[str(destination_endpoint["entity_id"])]
        service = next(
            item for item in selection["services"]
            if item["protocol"] == protocol and item["port"] == port
        )
        status, label, reason = _active_label(service, selection["selection"])
        active_evidence = (
            service["evidence"][0]
            if selection["selection"]["status"] == "ordered"
            and len(service["evidence"]) == 1
            else None
        )
        active_sources = [
            item["source"] for item in service["evidence"]
            if isinstance(item.get("source"), dict)
        ]
        path["active_context"] = {
            **base,
            "status": status,
            "label": label,
            "reason": reason,
            **_path_characterization(status, reason),
            "reported_state": service.get("reported_state"),
            "reported_basis": service.get("basis"),
            "selection_revision": selection["selection_revision"],
            "active_source": active_evidence.get("source") if active_evidence else None,
            "active_sources": active_sources,
            "evidence_windows": _window_context(record, active_evidence),
        }


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
        "correlated_paths": _correlated_paths(rows, limit),
        "correlated_path_count": len({
            (row["source_ip"], row["destination_ip"], row["transport"], row["destination_port"])
            for row in rows
        }),
        "correlated_paths_truncated": len({
            (row["source_ip"], row["destination_ip"], row["transport"], row["destination_port"])
            for row in rows
        }) > limit,
        "correlation_note": (
            "Each path groups individual retained session rows by source address, "
            "destination address, transport and destination port."
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
        "correlated_paths": [],
        "correlated_path_count": 0,
        "correlated_paths_truncated": False,
        "correlation_note": (
            "Communication-summary rows remain separate below because their reported "
            "groups can overlap; NCT does not add them into correlated path totals."
        ),
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
                _attach_active_context(db, session, analysis["correlated_paths"])
                analysis["active_context_contract"] = "arkime-active-context:1"
                analysis["active_context_note"] = (
                    "Active context uses the same database read snapshot, exact Network "
                    "Scope, destination address, transport and destination port. It "
                    "compares retained reports; it does not claim live truth or that a "
                    "connection succeeded."
                )
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
                analysis["active_context_contract"] = None
                analysis["active_context_note"] = (
                    "Active Nmap context is not calculated for communication-summary "
                    "groups because their reported rows may overlap."
                )
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


def build_hunt_arkime_context(
    db_path: Path, import_id: str, *, limit: int = 25,
) -> dict:
    """Return one exact retained Sessions source for the separate Hunt context panel."""
    analysis = analyze_arkime_import(db_path, import_id, limit=limit)
    if analysis["source_kind"] != "sessions_json":
        raise ArkimeAnalyticsError(
            "Hunt passive context accepts one retained Sessions JSON/API source. "
            "Communication-summary groups can overlap and remain available only in "
            "the Arkime workspace."
        )
    return {
        "contract": "arkime-hunt-context:1",
        "import_id": analysis["import_id"],
        "source_kind": analysis["source_kind"],
        "source_revision": analysis["source_revision"],
        "scope": analysis["scope"],
        "operator_sensor": analysis["operator_sensor"],
        "query_start": analysis["query_start"],
        "query_end": analysis["query_end"],
        "export_completeness": analysis["export_completeness"],
        "capture_coverage": analysis["capture_coverage"],
        "raw_url": analysis["raw_url"],
        "detail_url": analysis["detail_url"],
        "read_only": True,
        "retained_row_count": analysis["retained_row_count"],
        "correlated_paths": analysis["correlated_paths"],
        "correlated_path_count": analysis["correlated_path_count"],
        "correlated_paths_truncated": analysis["correlated_paths_truncated"],
        "correlation_note": analysis["correlation_note"],
        "active_context_contract": analysis["active_context_contract"],
        "active_context_note": analysis["active_context_note"],
        "claims": {
            "creates_current_hosts": False,
            "changes_candidate_matching": False,
            "changes_hunt_filters": False,
            "included_in_hunt_exports": False,
            "proves_live_service": False,
            "proves_connection_success": False,
            "changes_reach_or_map": False,
        },
        "boundary_note": (
            "This is separately selected retained passive context. It does not change "
            "the network-wide Hunt inventory, CVE candidates, filters, exports, Reach "
            "or Map. Nmap labels use exact same-scope retained sources and may differ "
            "from the scans displayed elsewhere in Hunt."
        ),
    }
