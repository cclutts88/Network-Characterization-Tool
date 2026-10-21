"""Bounded read-only projection of current scoped device VLAN evidence."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sqlite3
import time

from app.database import connect_database
from app.device_observations import DeviceObservationConflict, assignment_contract_on_connection
from app.device_vlan_observations import (
    DEVICE_VLAN_CLAIMS,
    DEVICE_VLAN_EVIDENCE_LABELS,
    DEVICE_VLAN_EXTRACTOR,
    DEVICE_VLAN_STATUS_MEANING,
    current_device_vlan_assessment_on_connection,
)


MAX_VLAN_PROJECTION_ASSIGNMENTS = 2_000
MAX_VLAN_PROJECTION_PAGE = 100
MAX_VLAN_PROJECTION_SECONDS = 3.0
MAX_VLAN_SUMMARIES_PER_ASSIGNMENT = 200
MAX_VLAN_EXPORT_ROWS = 20_000
MAX_VLAN_EXPORT_BYTES = 10 * 1024 * 1024
VLAN_PROJECTION_VERSION = "device-vlan-projection:1"
VLAN_COVERAGE_STATES = frozenset({"supported", "partial", "unsupported", "unknown"})
VLAN_EXPORT_COLUMNS = (
    "projection_revision", "scope_id", "scope_label", "scope_active",
    "assignment_id", "assignment_revision", "run_id", "assigned_at",
    "device_name", "device_address", "device_vendor", "device_type",
    "coverage_state", "coverage_label", "coverage_reason", "assessment_id",
    "extractor_version", "collection_contract", "source_sha256",
    "source_filename", "source_url", "device_context", "bridge_context",
    "vlan_id", "vlan_name", "interface", "relation", "evidence_state",
    "evidence_state_label", "receipt_id", "source_line_number", "source_line",
    "receipts_url",
)


class DeviceVlanProjectionChanged(RuntimeError):
    """The caller's retained projection revision is no longer current."""


class DeviceVlanProjectionTooLarge(ValueError):
    """The requested projection cannot be expanded within the export bounds."""


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _manifest(value: object) -> dict:
    if not isinstance(value, str):
        return {}
    try:
        result = json.loads(value)
    except (TypeError, ValueError):
        return {}
    return result if isinstance(result, dict) else {}


def _device_identity(manifest: dict, run_id: str, row: sqlite3.Row | None = None) -> dict:
    address = str(
        manifest.get("device_address") or (row["device_address"] if row else "") or ""
    ).strip() or None
    name = str(
        manifest.get("device_name") or (row["device_name"] if row else "") or ""
    ).strip() or None
    return {
        "name": name,
        "address": address,
        "vendor": str(
            manifest.get("vendor") or (row["device_vendor"] if row else "") or ""
        ).strip() or None,
        "device_type": str(
            manifest.get("device_type") or (row["device_type"] if row else "") or ""
        ).strip() or None,
        "label": name or address or run_id,
    }


def _unknown_entry(row: sqlite3.Row, *, reason: str, manifest: dict) -> dict:
    return {
        "assignment_id": row["assignment_id"],
        "run_id": row["run_id"],
        "assignment_revision": int(row["revision"]),
        "authority_revision": int(row["authority_revision"]),
        "assigned_at": row["assigned_at"],
        "scope": {
            "scope_id": row["scope_id"],
            "label": row["scope_label"],
            "active": bool(row["scope_active"]) if row["scope_active"] is not None else False,
        },
        "device": _device_identity(manifest, row["run_id"], row),
        "state": "unknown",
        "state_label": "VLAN evidence unknown",
        "reason": reason,
        "assessment": None,
        "vlans": [],
    }


def _group_receipts(rows: list[sqlite3.Row], run_id: str, filename: str) -> list[dict]:
    groups: dict[tuple, dict] = {}
    for row in rows:
        key = (
            row["assessment_id"], row["device_context"], row["bridge_context"],
            int(row["vlan_id"]),
        )
        group = groups.setdefault(key, {
            "assessment_id": row["assessment_id"],
            "device_context": row["device_context"],
            "bridge_context": row["bridge_context"],
            "vlan_id": int(row["vlan_id"]),
            "vlan_name": None,
            "vlan_names": set(),
            "interfaces": set(),
            "relations": set(),
            "evidence_states": set(),
            "evidence_state_labels": set(),
            "receipt_ids": [],
            "source_lines": [],
            "receipt_count": 0,
            "receipts_url": f"/api/device-configs/{run_id}/scope-vlans/receipts",
            "source_url": f"/api/device-configs/{run_id}/files/{filename}",
        })
        if row["interface_name"]:
            group["interfaces"].add(row["interface_name"])
        if row["vlan_name"]:
            group["vlan_names"].add(row["vlan_name"])
        group["relations"].add(row["membership_relation"])
        group["evidence_states"].add(row["evidence_state"])
        group["evidence_state_labels"].add(
            DEVICE_VLAN_EVIDENCE_LABELS[row["evidence_state"]]
        )
        group["receipt_ids"].append(row["receipt_id"])
        group["source_lines"].append({
            "receipt_id": row["receipt_id"],
            "line_number": int(row["source_line_number"]),
            "source_line": row["source_line"],
            "interface": row["interface_name"],
            "relation": row["membership_relation"],
            "state": row["evidence_state"],
            "state_label": DEVICE_VLAN_EVIDENCE_LABELS[row["evidence_state"]],
        })
        group["receipt_count"] += 1
    result = []
    for group in groups.values():
        for key in (
            "interfaces", "relations", "evidence_states", "evidence_state_labels",
            "vlan_names",
        ):
            group[key] = sorted(group[key], key=lambda value: str(value).casefold())
        group["vlan_name"] = " / ".join(group["vlan_names"]) or None
        group["receipt_ids"].sort()
        group["source_lines"].sort(key=lambda item: (item["line_number"], item["receipt_id"]))
        result.append(group)
    result.sort(key=lambda item: (
        item["vlan_id"], str(item["vlan_name"] or "").casefold(),
        str(item["device_context"] or "").casefold(),
        str(item["bridge_context"] or "").casefold(), item["assessment_id"],
    ))
    return result


def _receipt_search_clause(search: str, alias: str = "receipt") -> str:
    if search.isdigit():
        return f"CAST({alias}.vlan_id AS TEXT) = ?"
    return " OR ".join(
        f"instr(lower(COALESCE(CAST({alias}.{field} AS TEXT), '')), ?) > 0"
        for field in (
            "vlan_id", "vlan_name", "device_context", "bridge_context",
            "interface_name", "membership_relation",
        )
    )


def _receipt_search_values(search: str) -> tuple[str, ...]:
    return (search,) if search.isdigit() else (search,) * 6


def _receipt_group_search_clause(search: str, alias: str = "receipt") -> str:
    match = "matched"
    return (
        f"EXISTS (SELECT 1 FROM device_vlan_receipts {match} "
        f"WHERE {match}.assessment_id = {alias}.assessment_id "
        f"AND {match}.device_context = {alias}.device_context "
        f"AND COALESCE({match}.bridge_context, '') = COALESCE({alias}.bridge_context, '') "
        f"AND {match}.vlan_id = {alias}.vlan_id "
        f"AND ({_receipt_search_clause(search, match)}))"
    )


def _summarize_receipts(
    db: sqlite3.Connection, entry: dict, receipt_search: str | None,
) -> tuple[list[dict], bool]:
    assessment = entry.get("assessment")
    if not assessment:
        return [], False
    where = "receipt.assessment_id = ?"
    values: list[object] = [assessment["assessment_id"]]
    if receipt_search:
        where += f" AND {_receipt_group_search_clause(receipt_search)}"
        values.extend(_receipt_search_values(receipt_search))
    rows = db.execute(
        f"""SELECT receipt.device_context, receipt.bridge_context, receipt.vlan_id,
                    MIN(NULLIF(receipt.vlan_name, '')) AS vlan_name,
                    COUNT(DISTINCT NULLIF(receipt.vlan_name, '')) AS vlan_name_count,
                    MIN(NULLIF(receipt.interface_name, '')) AS sample_interface,
                    COUNT(DISTINCT NULLIF(receipt.interface_name, '')) AS interface_count,
                    GROUP_CONCAT(DISTINCT receipt.membership_relation) AS relations,
                    GROUP_CONCAT(DISTINCT receipt.evidence_state) AS evidence_states,
                    COUNT(*) AS receipt_count
               FROM device_vlan_receipts receipt
              WHERE {where}
              GROUP BY receipt.device_context, receipt.bridge_context, receipt.vlan_id
              ORDER BY receipt.vlan_id, lower(COALESCE(vlan_name, '')),
                       lower(receipt.device_context), lower(COALESCE(receipt.bridge_context, ''))
              LIMIT ?""",
        (*values, MAX_VLAN_SUMMARIES_PER_ASSIGNMENT + 1),
    ).fetchall()
    truncated = len(rows) > MAX_VLAN_SUMMARIES_PER_ASSIGNMENT
    result = []
    for row in rows[:MAX_VLAN_SUMMARIES_PER_ASSIGNMENT]:
        states = sorted(filter(None, str(row["evidence_states"] or "").split(",")))
        sample_interface = row["sample_interface"]
        result.append({
            "assessment_id": assessment["assessment_id"],
            "device_context": row["device_context"],
            "bridge_context": row["bridge_context"],
            "vlan_id": int(row["vlan_id"]),
            "vlan_name": row["vlan_name"],
            "vlan_name_count": int(row["vlan_name_count"]),
            "interfaces": [sample_interface] if sample_interface else [],
            "interface_count": int(row["interface_count"]),
            "relations": sorted(filter(None, str(row["relations"] or "").split(","))),
            "evidence_states": states,
            "evidence_state_labels": [DEVICE_VLAN_EVIDENCE_LABELS[value] for value in states],
            "receipt_count": int(row["receipt_count"]),
            "receipts_url": f"/api/device-configs/{entry['run_id']}/scope-vlans/receipts",
            "source_url": assessment["source_url"],
        })
    return result, truncated


def _empty_projection(
    *, revision: str, run_id: str | None, scope_id: str | None,
    requested_state: str | None, clean_search: str, limit: int, offset: int,
) -> dict:
    return {
        "projection_version": VLAN_PROJECTION_VERSION,
        "source_revision": revision,
        "meaning": DEVICE_VLAN_STATUS_MEANING,
        "claims": dict(DEVICE_VLAN_CLAIMS),
        "filters": {
            "run_id": run_id, "scope_id": scope_id, "state": requested_state,
            "search": clean_search or None,
        },
        "assignments": [],
        "facets": {"scopes": [], "vlans": [], "states": ["unknown"]},
        "pagination": {"limit": limit, "offset": offset, "total": 0, "has_more": False},
    }


def build_device_vlan_projection(
    db_path: Path, *, run_id: str | None = None, scope_id: str | None = None,
    state: str | None = None, search: str | None = None,
    limit: int = 50, offset: int = 0, expected_revision: str | None = None,
    _page_cap: int = MAX_VLAN_PROJECTION_PAGE, _export_full: bool = False,
) -> dict:
    """Return a bounded page from one coherent read-only database snapshot."""
    requested_state = state
    if not 1 <= limit <= _page_cap or offset < 0:
        raise ValueError("Invalid device VLAN projection page")
    if requested_state and requested_state not in VLAN_COVERAGE_STATES:
        raise ValueError("Invalid scoped VLAN evidence state")
    clean_search = str(search or "").strip().casefold()
    started = time.monotonic()
    if not Path(db_path).is_file():
        result = _empty_projection(
            revision=hashlib.sha256(b"missing-device-vlan-storage").hexdigest(),
            run_id=run_id, scope_id=scope_id, requested_state=requested_state,
            clean_search=clean_search, limit=limit, offset=offset,
        )
        if expected_revision and expected_revision != result["source_revision"]:
            raise DeviceVlanProjectionChanged("Scoped VLAN evidence changed")
        return result

    try:
        with connect_database(db_path, read_only=True) as db:
            db.row_factory = sqlite3.Row
            db.execute("BEGIN")
            db.set_progress_handler(
                lambda: int(time.monotonic() - started > MAX_VLAN_PROJECTION_SECONDS),
                1_000,
            )
            required = {
                "device_scope_assignments", "network_scopes", "device_collection_authority",
                "device_vlan_assessments", "device_vlan_receipts",
            }
            available = {
                row[0] for row in db.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                ).fetchall()
            }
            if not required.issubset(available):
                result = _empty_projection(
                    revision=hashlib.sha256(b"unavailable-device-vlan-storage").hexdigest(),
                    run_id=run_id, scope_id=scope_id, requested_state=requested_state,
                    clean_search=clean_search, limit=limit, offset=offset,
                )
                if expected_revision and expected_revision != result["source_revision"]:
                    raise DeviceVlanProjectionChanged("Scoped VLAN evidence changed")
                return result

            clauses = [
                "NOT EXISTS (SELECT 1 FROM device_scope_assignments successor "
                "WHERE successor.supersedes_assignment_id = assignment.assignment_id)"
            ]
            values: list[object] = []
            if run_id:
                clauses.append("assignment.run_id = ?")
                values.append(run_id)
            if scope_id:
                clauses.append("assignment.scope_id = ?")
                values.append(scope_id)
            collection_columns = (
                "collection.device_name AS device_name, "
                "collection.device_address AS device_address, "
                "collection.vendor AS device_vendor, collection.device_type AS device_type"
                if "device_collections" in available
                else "NULL AS device_name, NULL AS device_address, "
                     "NULL AS device_vendor, NULL AS device_type"
            )
            collection_join = (
                "LEFT JOIN device_collections collection ON collection.run_id = assignment.run_id"
                if "device_collections" in available else ""
            )
            catalog_columns = (
                "catalog.manifest_json AS catalog_manifest_json"
                if "device_evidence_catalog" in available
                else "NULL AS catalog_manifest_json"
            )
            catalog_join = (
                "LEFT JOIN device_evidence_catalog catalog "
                "ON catalog.run_id = assignment.run_id "
                "AND catalog.authority_revision = authority.revision "
                "AND catalog.selection_contract = authority.selection_contract "
                "AND catalog.semantic_manifest_sha256 = authority.semantic_manifest_sha256"
                if "device_evidence_catalog" in available else ""
            )
            candidates = db.execute(
                f"""SELECT assignment.*, scope.label AS scope_label,
                           scope.active AS scope_active, authority.semantic_manifest_json,
                           {collection_columns}, {catalog_columns}
                      FROM device_scope_assignments assignment
                      LEFT JOIN network_scopes scope ON scope.scope_id = assignment.scope_id
                      LEFT JOIN device_collection_authority authority
                        ON authority.run_id = assignment.run_id
                      {collection_join}
                      {catalog_join}
                     WHERE {' AND '.join(clauses)}
                     ORDER BY lower(COALESCE(scope.label, '')), assignment.scope_id,
                              assignment.run_id, assignment.assignment_id
                     LIMIT ?""",
                (*values, MAX_VLAN_PROJECTION_ASSIGNMENTS + 1),
            ).fetchall()
            if len(candidates) > MAX_VLAN_PROJECTION_ASSIGNMENTS:
                raise ValueError("Scoped VLAN projection exceeds its assignment limit")

            entries: list[dict] = []
            revision_items: list[dict] = []
            for row in candidates:
                if time.monotonic() - started > MAX_VLAN_PROJECTION_SECONDS:
                    raise ValueError("Scoped VLAN projection exceeded its processing-time limit")
                manifest = (
                    _manifest(row["catalog_manifest_json"])
                    or _manifest(row["semantic_manifest_json"])
                )
                if not bool(row["scope_active"]):
                    entry = _unknown_entry(
                        row, reason="Assigned Network Scope is archived", manifest=manifest,
                    )
                    entries.append(entry)
                    revision_items.append(entry)
                    continue
                try:
                    contract = assignment_contract_on_connection(db, row["assignment_id"])
                except (DeviceObservationConflict, KeyError, ValueError) as exc:
                    entry = _unknown_entry(row, reason=str(exc), manifest=manifest)
                    entries.append(entry)
                    revision_items.append(entry)
                    continue
                collection_contract = contract["authority"]["selection_contract"]
                assessment = current_device_vlan_assessment_on_connection(
                    db, assignment_id=row["assignment_id"],
                    collection_contract=collection_contract,
                )
                if assessment is None:
                    entry = _unknown_entry(
                        row, reason="No current supported VLAN assessment is available",
                        manifest=manifest,
                    )
                    entries.append(entry)
                    revision_items.append(entry)
                    continue
                try:
                    coverage = json.loads(assessment["coverage_json"])
                    if not isinstance(coverage, dict):
                        raise ValueError
                except (TypeError, ValueError, json.JSONDecodeError):
                    entry = _unknown_entry(
                        row, reason="Retained VLAN coverage is malformed", manifest=manifest,
                    )
                    entries.append(entry)
                    revision_items.append(entry | {"assessment_id": assessment["assessment_id"]})
                    continue
                coverage_state = coverage.get("collection_state")
                if coverage_state not in VLAN_COVERAGE_STATES:
                    entry = _unknown_entry(
                        row, reason="Retained VLAN coverage state is unsupported", manifest=manifest,
                    )
                    entries.append(entry)
                    revision_items.append(entry | {"assessment_id": assessment["assessment_id"]})
                    continue
                entry = {
                    "assignment_id": row["assignment_id"],
                    "run_id": row["run_id"],
                    "assignment_revision": int(row["revision"]),
                    "authority_revision": int(row["authority_revision"]),
                    "assigned_at": row["assigned_at"],
                    "scope": {
                        "scope_id": row["scope_id"], "label": row["scope_label"], "active": True,
                    },
                    "device": _device_identity(manifest, row["run_id"], row),
                    "state": coverage_state,
                    "state_label": coverage.get("collection_state_label") or coverage_state.title(),
                    "reason": None,
                    "assessment": {
                        "assessment_id": assessment["assessment_id"],
                        "extractor_version": assessment["extractor_version"],
                        "collection_contract": assessment["collection_contract"],
                        "recorded_at": assessment["recorded_at"],
                        "source_sha256": assessment["configuration_sha256"],
                        "source_filename": assessment["configuration_filename"],
                        "source_url": (
                            f"/api/device-configs/{row['run_id']}/files/"
                            f"{assessment['configuration_filename']}"
                        ),
                        "coverage": coverage,
                    },
                    "vlans": [],
                }
                receipt_count = int(db.execute(
                    "SELECT COUNT(*) FROM device_vlan_receipts WHERE assessment_id = ?",
                    (assessment["assessment_id"],),
                ).fetchone()[0])
                entries.append(entry)
                revision_items.append({
                    "assignment_id": entry["assignment_id"],
                    "assignment_revision": entry["assignment_revision"],
                    "authority_revision": entry["authority_revision"],
                    "scope": entry["scope"],
                    "device": entry["device"],
                    "assessment_id": assessment["assessment_id"],
                    "extractor_version": assessment["extractor_version"],
                    "collection_contract": assessment["collection_contract"],
                    "configuration_sha256": assessment["configuration_sha256"],
                    "configuration_filename": assessment["configuration_filename"],
                    "receipt_count": receipt_count,
                    "coverage_sha256": hashlib.sha256(
                        str(assessment["coverage_json"]).encode()
                    ).hexdigest(),
                })

            entries.sort(key=lambda item: (
                str(item["scope"].get("label") or "").casefold(), item["scope"]["scope_id"],
                str(item["device"].get("label") or "").casefold(), item["run_id"],
                item["assignment_id"],
            ))
            all_entries = entries
            if requested_state:
                entries = [entry for entry in entries if entry["state"] == requested_state]
            filtered: list[dict] = []
            for entry in entries:
                receipt_search = None
                if clean_search:
                    entry_values = [
                        entry["scope"].get("label"), entry.get("state_label"),
                        entry.get("reason"),
                        *entry["device"].values(),
                    ]
                    entry_matches = not clean_search.isdigit() and any(
                        clean_search in str(value or "").casefold() for value in entry_values
                    )
                    if not entry_matches:
                        assessment = entry.get("assessment")
                        if not assessment:
                            continue
                        found = db.execute(
                            f"""SELECT 1 FROM device_vlan_receipts receipt
                                  WHERE receipt.assessment_id = ?
                                    AND ({_receipt_search_clause(clean_search)}) LIMIT 1""",
                            (assessment["assessment_id"], *_receipt_search_values(clean_search)),
                        ).fetchone()
                        if not found:
                            continue
                        receipt_search = clean_search
                filtered.append(entry | {"_receipt_search": receipt_search})

            revision = hashlib.sha256(_canonical({
                "version": VLAN_PROJECTION_VERSION,
                "filters": {
                    "run_id": run_id, "scope_id": scope_id, "state": requested_state,
                    "search": clean_search or None,
                },
                "items": revision_items,
            }).encode()).hexdigest()
            if expected_revision and expected_revision != revision:
                raise DeviceVlanProjectionChanged("Scoped VLAN evidence changed")

            total = len(filtered)
            selected = filtered if _export_full else filtered[offset:offset + limit]
            if _export_full:
                export_rows = 0
                export_estimate = 0
                for entry in selected:
                    assessment = entry.get("assessment")
                    if not assessment:
                        export_rows += 1
                        export_estimate += len(_canonical(entry).encode()) + 2_048
                        continue
                    where = "receipt.assessment_id = ?"
                    query_values: list[object] = [assessment["assessment_id"]]
                    if entry["_receipt_search"]:
                        where += f" AND {_receipt_group_search_clause(entry['_receipt_search'])}"
                        query_values.extend(_receipt_search_values(entry["_receipt_search"]))
                    count, variable_bytes = db.execute(
                        f"""SELECT COUNT(*), COALESCE(SUM(
                                length(CAST(receipt.receipt_id AS BLOB)) +
                                length(CAST(receipt.source_filename AS BLOB)) +
                                length(CAST(receipt.device_context AS BLOB)) +
                                length(CAST(COALESCE(receipt.bridge_context, '') AS BLOB)) +
                                length(CAST(COALESCE(receipt.vlan_name, '') AS BLOB)) +
                                length(CAST(COALESCE(receipt.interface_name, '') AS BLOB)) +
                                length(CAST(receipt.membership_relation AS BLOB)) +
                                length(CAST(receipt.evidence_state AS BLOB)) +
                                length(CAST(receipt.source_line AS BLOB))
                            ), 0)
                              FROM device_vlan_receipts receipt WHERE {where}""",
                        tuple(query_values),
                    ).fetchone()
                    count = max(1, int(count))
                    export_rows += count
                    export_estimate += int(variable_bytes) + count * 2_048
                    if export_rows > MAX_VLAN_EXPORT_ROWS or export_estimate > MAX_VLAN_EXPORT_BYTES:
                        raise DeviceVlanProjectionTooLarge(
                            "Scoped VLAN export is too large; narrow it by Network Scope or search"
                        )
                for entry in selected:
                    assessment = entry.get("assessment")
                    if not assessment:
                        continue
                    where = "assessment_id = ?"
                    query_values = [assessment["assessment_id"]]
                    if entry["_receipt_search"]:
                        where += f" AND {_receipt_group_search_clause(entry['_receipt_search'])}"
                        query_values.extend(_receipt_search_values(entry["_receipt_search"]))
                    receipts = db.execute(
                        f"""SELECT * FROM device_vlan_receipts receipt WHERE {where}
                              ORDER BY vlan_id, source_line_number,
                                       membership_relation, receipt_id""",
                        tuple(query_values),
                    ).fetchall()
                    entry["vlans"] = _group_receipts(
                        receipts, entry["run_id"], assessment["source_filename"],
                    )
            else:
                for entry in selected:
                    summaries, truncated = _summarize_receipts(
                        db, entry, entry["_receipt_search"],
                    )
                    entry["vlans"] = summaries
                    entry["vlan_summaries_truncated"] = truncated

            scopes = {}
            states = set()
            for entry in all_entries:
                scope = entry["scope"]
                scopes[scope["scope_id"]] = {
                    "scope_id": scope["scope_id"], "label": scope.get("label"),
                    "active": scope["active"],
                }
                states.add(entry["state"])
            vlans = {}
            for entry in selected:
                scope = entry["scope"]
                for vlan in entry["vlans"]:
                    key = (
                        f"{scope['scope_id']}:{entry['assignment_id']}:"
                        f"{vlan['device_context']}:{vlan['bridge_context'] or ''}:{vlan['vlan_id']}"
                    )
                    vlans[key] = {
                        "key": key, "scope_id": scope["scope_id"],
                        "assignment_id": entry["assignment_id"],
                        "device_context": vlan["device_context"],
                        "bridge_context": vlan["bridge_context"],
                        "vlan_id": vlan["vlan_id"], "vlan_name": vlan["vlan_name"],
                    }
            for entry in selected:
                entry.pop("_receipt_search", None)
            return {
                "projection_version": VLAN_PROJECTION_VERSION,
                "source_revision": revision,
                "meaning": DEVICE_VLAN_STATUS_MEANING,
                "claims": dict(DEVICE_VLAN_CLAIMS),
                "filters": {
                    "run_id": run_id, "scope_id": scope_id, "state": requested_state,
                    "search": clean_search or None,
                },
                "assignments": selected,
                "facets": {
                    "scopes": sorted(scopes.values(), key=lambda item: (
                        str(item.get("label") or "").casefold(), item["scope_id"],
                    )),
                    "vlans": sorted(vlans.values(), key=lambda item: (
                        item["scope_id"], item["assignment_id"], item["device_context"],
                        str(item["bridge_context"] or ""), item["vlan_id"],
                    )),
                    "states": sorted(states),
                },
                "pagination": {
                    "limit": limit, "offset": offset, "total": total,
                    "has_more": False if _export_full else offset + len(selected) < total,
                },
            }
    except sqlite3.OperationalError as exc:
        if "interrupted" in str(exc).casefold():
            raise ValueError("Scoped VLAN projection exceeded its processing-time limit") from exc
        raise


def build_device_vlan_export_projection(
    db_path: Path, *, revision: str, run_id: str | None = None,
    scope_id: str | None = None, state: str | None = None,
    search: str | None = None,
) -> dict:
    """Return a preflight-bounded full export tied to the displayed revision."""
    return build_device_vlan_projection(
        db_path, run_id=run_id, scope_id=scope_id, state=state, search=search,
        limit=MAX_VLAN_PROJECTION_ASSIGNMENTS, offset=0,
        expected_revision=revision, _page_cap=MAX_VLAN_PROJECTION_ASSIGNMENTS,
        _export_full=True,
    )


def device_vlan_export_rows(projection: dict):
    """Yield bounded export rows without creating a second full row list."""
    revision = projection["source_revision"]
    for entry in projection["assignments"]:
        base = {
            "projection_revision": revision,
            "scope_id": entry["scope"]["scope_id"],
            "scope_label": entry["scope"].get("label"),
            "scope_active": entry["scope"].get("active"),
            "assignment_id": entry["assignment_id"],
            "assignment_revision": entry["assignment_revision"],
            "run_id": entry["run_id"],
            "assigned_at": entry["assigned_at"],
            "device_name": entry["device"].get("name"),
            "device_address": entry["device"].get("address"),
            "device_vendor": entry["device"].get("vendor"),
            "device_type": entry["device"].get("device_type"),
            "coverage_state": entry["state"],
            "coverage_label": entry.get("state_label"),
            "coverage_reason": entry.get("reason"),
        }
        assessment = entry.get("assessment") or {}
        base.update({
            "assessment_id": assessment.get("assessment_id"),
            "extractor_version": assessment.get("extractor_version"),
            "collection_contract": assessment.get("collection_contract"),
            "source_sha256": assessment.get("source_sha256"),
            "source_filename": assessment.get("source_filename"),
            "source_url": assessment.get("source_url"),
        })
        if not entry["vlans"]:
            yield base | {
                "device_context": None, "bridge_context": None,
                "vlan_id": None, "vlan_name": None, "interface": None,
                "relation": None, "evidence_state": None,
                "evidence_state_label": None, "receipt_id": None,
                "source_line_number": None, "source_line": None,
                "receipts_url": None,
            }
            continue
        for vlan in entry["vlans"]:
            for line in vlan["source_lines"]:
                yield base | {
                    "device_context": vlan.get("device_context"),
                    "bridge_context": vlan.get("bridge_context"),
                    "vlan_id": vlan.get("vlan_id"),
                    "vlan_name": vlan.get("vlan_name"),
                    "interface": line.get("interface"),
                    "relation": line.get("relation"),
                    "evidence_state": line.get("state"),
                    "evidence_state_label": line.get("state_label"),
                    "receipt_id": line.get("receipt_id"),
                    "source_line_number": line.get("line_number"),
                    "source_line": line.get("source_line"),
                    "receipts_url": vlan.get("receipts_url"),
                }
