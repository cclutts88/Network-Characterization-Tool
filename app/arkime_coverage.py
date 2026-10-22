"""Read-only retained-window inventory for Arkime evidence.

The inventory unifies manual Sessions JSON imports, NCT summary CSV imports, and
successful API pull publications.  A retained-window gap means only that NCT has
no comparable retained window for the same declared API stream.  It is not proof
of a sensor outage or an absence of traffic.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import sqlite3

from app.database import connect_database
from app.arkime_evidence import ARKIME_SOURCE_KIND


MAX_PAGE = 100
MAX_WINDOWS = 20_000
MAX_RECOMMENDATION_STREAMS = 1_000
MAX_OVERLAP_MINUTES = 1_439
MAX_COLLECTION_DELAY_SECONDS = 3_600
ARKIME_PULL_ROW_LIMIT = 1_000


class ArkimeCoverageError(ValueError):
    pass


class ArkimeCoverageConflict(ArkimeCoverageError):
    pass


def _time(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError) as exc:
        raise ArkimeCoverageError("A retained Arkime window has invalid time metadata") from exc
    if parsed.tzinfo is None:
        raise ArkimeCoverageError("A retained Arkime window has time metadata without a timezone")
    return parsed


def _identity(parts: dict) -> str:
    encoded = json.dumps(parts, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _source_url(kind: str, import_id: str) -> str:
    if kind == "summary":
        return f"/api/arkime/summary-imports/{import_id}/raw"
    return f"/api/arkime/imports/{import_id}/raw"


def _manual_session(row: sqlite3.Row) -> dict:
    stream = {
        "source_kind": "manual_sessions_json",
        "scope_id": row["scope_id"],
        "scope_version": int(row["scope_version"]),
        "operator_sensor": row["operator_sensor"],
        "bounding_mode": row["bounding_mode"],
        "query_expression": row["query_expression"],
        "parser_version": row["parser_version"],
    }
    return {
        "import_id": row["import_id"],
        "observation_id": row["observation_id"],
        "source_kind": "sessions_json",
        "source_method": "manual_import",
        "scope": {
            "scope_id": row["scope_id"], "label": row["scope_label"],
            "version": int(row["scope_version"]),
        },
        "operator_sensor": row["operator_sensor"],
        "query_start": row["query_start"],
        "query_end": row["query_end"],
        "bounding_mode": row["bounding_mode"],
        "query_expression": row["query_expression"],
        "parser_version": row["parser_version"],
        "imported_at": row["imported_at"],
        "actor": row["actor"],
        "returned_count": int(row["returned_count"]),
        "export_completeness": row["calculated_export_completeness"],
        "operator_export_assessment": row["operator_export_assessment"],
        "capture_coverage": row["capture_coverage"],
        "summary_basis": None,
        "top_n_limit": None,
        "connector_id": None,
        "dataset_identity": None,
        "connector_contract": None,
        "pull_run_id": None,
        "pull_state": None,
        "provenance_state": "manual_source",
        "stream_identity": _identity(stream),
        "stream_basis": "Manual Sessions JSON label; observation point is not independently verified",
        "raw_url": _source_url("sessions", row["import_id"]),
        "continuity": "not_comparable",
        "gap_seconds": None,
        "continuity_detail": (
            "Manual import retained. Its observation-point label does not establish "
            "a stable comparable API stream."
        ),
        "eligible_for_continuity": False,
    }


def _summary(row: sqlite3.Row) -> dict:
    stream = {
        "source_kind": "summary_csv",
        "scope_id": row["scope_id"],
        "scope_version": int(row["scope_version"]),
        "operator_sensor": row["operator_sensor"],
        "bounding_mode": row["bounding_mode"],
        "query_expression": row["query_expression"],
        "parser_version": row["parser_version"],
        "summary_basis": row["summary_basis"],
        "top_n_limit": row["top_n_limit"],
    }
    basis = row["summary_basis"].replace("_", " ")
    if row["top_n_limit"] is not None:
        basis = f"{basis} ({int(row['top_n_limit'])})"
    return {
        "import_id": row["import_id"],
        "observation_id": row["observation_id"],
        "source_kind": "summary_csv",
        "source_method": "manual_summary",
        "scope": {
            "scope_id": row["scope_id"], "label": row["scope_label"],
            "version": int(row["scope_version"]),
        },
        "operator_sensor": row["operator_sensor"],
        "query_start": row["query_start"],
        "query_end": row["query_end"],
        "bounding_mode": row["bounding_mode"],
        "query_expression": row["query_expression"],
        "parser_version": row["parser_version"],
        "imported_at": row["imported_at"],
        "actor": row["actor"],
        "returned_count": int(row["returned_count"]),
        "export_completeness": row["recorded_export_completeness"],
        "operator_export_assessment": row["operator_export_assessment"],
        "capture_coverage": row["capture_coverage"],
        "summary_basis": row["summary_basis"],
        "top_n_limit": row["top_n_limit"],
        "connector_id": None,
        "dataset_identity": None,
        "connector_contract": None,
        "pull_run_id": None,
        "pull_state": None,
        "provenance_state": "manual_summary",
        "stream_identity": _identity(stream),
        "stream_basis": f"Summary grouping: {basis}; observation point is not independently verified",
        "raw_url": _source_url("summary", row["import_id"]),
        "continuity": "not_comparable",
        "gap_seconds": None,
        "continuity_detail": (
            "Summary retained. Operator declarations and a sensor label cannot independently "
            "establish a comparable observation stream."
        ),
        "eligible_for_continuity": False,
    }


def _api_provenance_matches(item: dict, run: sqlite3.Row) -> bool:
    comparisons = (
        (item["scope"]["scope_id"], run["scope_id"]),
        (item["scope"]["version"], int(run["scope_version"])),
        (item["operator_sensor"], run["operator_sensor"]),
        (item["query_start"], run["query_start"]),
        (item["query_end"], run["query_end"]),
        (item["bounding_mode"], run["bounding_mode"]),
        (item["query_expression"], run["query_expression"]),
        (item["parser_version"], run["parser_version"]),
    )
    return all(left == right for left, right in comparisons)


def _api_observation_matches(
    item: dict, run: sqlite3.Row, observation: sqlite3.Row | None,
) -> bool:
    if observation is None:
        return False
    try:
        metadata = json.loads(observation["metadata_json"])
        request_parameters = json.loads(run["request_parameters_json"])
    except (json.JSONDecodeError, TypeError):
        return False
    if not isinstance(metadata, dict) or not isinstance(request_parameters, dict):
        return False
    comparisons = (
        (observation["observation_id"], item["observation_id"]),
        (observation["source_kind"], ARKIME_SOURCE_KIND),
        (observation["source_ref"], item["import_id"]),
        (observation["observed_at"], item["imported_at"]),
        (observation["actor"], item["actor"]),
        (observation["original_filename"], f"arkime-api-{run['run_id']}.json"),
        (metadata.get("import_tier"), "tier_e_sessions_api"),
        (metadata.get("pull_run_id"), run["run_id"]),
        (metadata.get("connector_id"), run["connector_id"]),
        (metadata.get("connector_contract"), run["connector_contract"]),
        (metadata.get("parser_version"), run["parser_version"]),
        (metadata.get("request_parameters"), request_parameters),
        (metadata.get("scope_id"), item["scope"]["scope_id"]),
        (metadata.get("operator_sensor"), item["operator_sensor"]),
        (metadata.get("query_start"), item["query_start"]),
        (metadata.get("query_end"), item["query_end"]),
        (metadata.get("bounding_mode"), item["bounding_mode"]),
        (metadata.get("returned_count"), item["returned_count"]),
    )
    if run["dataset_identity"] not in {"unverified", "legacy-unverified"}:
        comparisons += ((metadata.get("dataset_identity"), run["dataset_identity"]),)
    return all(left == right for left, right in comparisons)


def _apply_api_provenance(
    item: dict, runs: list[sqlite3.Row], observation: sqlite3.Row | None,
) -> None:
    if not runs:
        return
    if len(runs) != 1:
        item["source_method"] = "api_pull"
        item["provenance_state"] = "ambiguous_api_runs"
        item["continuity_detail"] = (
            "Multiple pull attempts point to this retained import, so its API stream "
            "provenance is ambiguous."
        )
        return
    run = runs[0]
    item["source_method"] = "api_pull"
    item["pull_run_id"] = run["run_id"]
    item["pull_state"] = run["state"]
    item["connector_id"] = run["connector_id"]
    item["dataset_identity"] = run["dataset_identity"]
    item["connector_contract"] = run["connector_contract"]
    if not _api_provenance_matches(item, run):
        item["provenance_state"] = "api_provenance_mismatch"
        item["continuity_detail"] = (
            "The retained import and its pull record disagree, so this window cannot "
            "be compared."
        )
        return
    if not _api_observation_matches(item, run, observation):
        item["provenance_state"] = "api_observation_mismatch"
        item["continuity_detail"] = (
            "The pull record is linked, but the retained artifact observation does not "
            "carry the same API publication identity. This window cannot be compared."
        )
        return
    stream = {
        "source_kind": "sessions_api",
        "scope_id": item["scope"]["scope_id"],
        "scope_version": item["scope"]["version"],
        "operator_sensor": item["operator_sensor"],
        "bounding_mode": item["bounding_mode"],
        "query_expression": item["query_expression"],
        "parser_version": item["parser_version"],
        "connector_id": run["connector_id"],
        "dataset_identity": run["dataset_identity"],
        "connector_contract": run["connector_contract"],
    }
    item["stream_identity"] = _identity(stream)
    item["stream_basis"] = (
        f"Declared API stream {run['connector_id']} · {run['connector_contract']} · "
        f"scope v{item['scope']['version']} · exact query and parser contract"
    )
    item["provenance_state"] = "exact_api_run"
    complete = (
        run["state"] == "complete"
        and item["export_completeness"] == "complete"
        and item["operator_export_assessment"] == "complete"
        and item["capture_coverage"] == "complete"
    )
    item["eligible_for_continuity"] = complete
    item["continuity_detail"] = (
        "Comparable complete API window."
        if complete else
        "API source retained, but incomplete or unknown calculated export, operator "
        "export-assessment, or capture declarations "
        "prevent continuity comparison."
    )


def _classify(items: list[dict]) -> None:
    eligible: dict[str, list[dict]] = {}
    for item in items:
        if item["eligible_for_continuity"]:
            eligible.setdefault(item["stream_identity"], []).append(item)
    for stream in eligible.values():
        stream.sort(key=lambda item: (
            _time(item["query_start"]), _time(item["query_end"]),
            item["imported_at"], item["import_id"],
        ))
        maximum_end: datetime | None = None
        for item in stream:
            start = _time(item["query_start"])
            end = _time(item["query_end"])
            if maximum_end is None:
                item["continuity"] = "first_retained_comparable_window"
                item["continuity_detail"] = (
                    "First retained comparable window for this exact declared API stream."
                )
            elif start <= maximum_end:
                item["continuity"] = "continuous_or_overlapping"
                item["gap_seconds"] = 0
                item["continuity_detail"] = (
                    "Touches or overlaps a preceding comparable retained window."
                )
            else:
                item["continuity"] = "retained_window_gap"
                item["gap_seconds"] = int((start - maximum_end).total_seconds())
                item["continuity_detail"] = (
                    "No comparable retained NCT window covers this interval. This does "
                    "not prove a sensor outage or an absence of traffic."
                )
            if maximum_end is None or end > maximum_end:
                maximum_end = end


def _revision(items: list[dict]) -> str:
    stable = [
        [item["source_kind"], item["import_id"], item["observation_id"],
         item["query_start"], item["query_end"], item["imported_at"],
         item["provenance_state"], item["stream_identity"]]
        for item in items
    ]
    return hashlib.sha256(
        json.dumps(stable, separators=(",", ":"), ensure_ascii=True).encode()
    ).hexdigest()


def _stream_summaries(items: list[dict]) -> list[dict]:
    streams: dict[str, list[dict]] = {}
    for item in items:
        if item["provenance_state"] == "exact_api_run":
            streams.setdefault(item["stream_identity"], []).append(item)
    if len(streams) > MAX_RECOMMENDATION_STREAMS:
        raise ArkimeCoverageError(
            f"The coverage inventory contains more than {MAX_RECOMMENDATION_STREAMS} "
            "exact API streams; choose one Network Scope"
        )
    result = []
    for identity, stream in streams.items():
        ordered = sorted(stream, key=lambda item: (
            _time(item["query_end"]), _time(item["query_start"]),
            item["imported_at"], item["import_id"],
        ))
        latest = ordered[-1]
        eligible = [item for item in ordered if item["eligible_for_continuity"]]
        result.append({
            "stream_identity": identity,
            "scope": latest["scope"],
            "operator_sensor": latest["operator_sensor"],
            "connector_id": latest["connector_id"],
            "connector_contract": latest["connector_contract"],
            "query_expression": latest["query_expression"],
            "bounding_mode": latest["bounding_mode"],
            "parser_version": latest["parser_version"],
            "retained_window_count": len(ordered),
            "eligible_window_count": len(eligible),
            "latest_eligible_end": (
                max(eligible, key=lambda item: _time(item["query_end"]))["query_end"]
                if eligible else None
            ),
        })
    result.sort(key=lambda item: (
        item["scope"]["label"].casefold(), item["operator_sensor"].casefold(),
        item["connector_id"] or "", item["stream_identity"],
    ))
    return result


def _recommend_next_forward_window(
    items: list[dict], *, stream_identity: str, overlap_minutes: int,
    cutoff: str | None, collection_delay_seconds: int,
    frozen_now: datetime | None = None,
) -> dict:
    if not isinstance(stream_identity, str) or not stream_identity.strip():
        raise ArkimeCoverageError("stream_identity cannot be blank")
    if (
        isinstance(overlap_minutes, bool) or not isinstance(overlap_minutes, int)
        or not 0 <= overlap_minutes <= MAX_OVERLAP_MINUTES
    ):
        raise ArkimeCoverageError(
            f"overlap_minutes must be between 0 and {MAX_OVERLAP_MINUTES}"
        )
    if (
        isinstance(collection_delay_seconds, bool)
        or not isinstance(collection_delay_seconds, int)
        or not 0 <= collection_delay_seconds <= MAX_COLLECTION_DELAY_SECONDS
    ):
        raise ArkimeCoverageError(
            "collection_delay_seconds must be between 0 and "
            f"{MAX_COLLECTION_DELAY_SECONDS}"
        )
    now = frozen_now or datetime.now(timezone.utc).replace(microsecond=0)
    if now.tzinfo is None:
        raise ArkimeCoverageError("The frozen server time must include a timezone")
    now = now.astimezone(timezone.utc).replace(microsecond=0)
    exact = [
        item for item in items
        if item["provenance_state"] == "exact_api_run"
        and item["stream_identity"] == stream_identity
    ]
    if not exact:
        return {
            "status": "unavailable", "reason": "stream_not_found",
            "detail": "The selected exact API stream is no longer retained.",
            "read_only": True,
        }
    eligible = [item for item in exact if item["eligible_for_continuity"]]
    if not eligible:
        return {
            "status": "unavailable", "reason": "no_eligible_anchor",
            "detail": (
                "No retained window for this exact API stream has Complete calculated "
                "export, operator assessment, and capture declarations."
            ),
            "stream_identity": stream_identity, "read_only": True,
        }
    eligible.sort(key=lambda item: (
        _time(item["query_start"]), _time(item["query_end"]),
        item["imported_at"], item["import_id"],
    ))
    terminal_segment: list[dict] = []
    terminal_end: datetime | None = None
    for item in eligible:
        start = _time(item["query_start"])
        end = _time(item["query_end"])
        if terminal_end is None or start > terminal_end:
            terminal_segment = [item]
            terminal_end = end
        else:
            terminal_segment.append(item)
            if end > terminal_end:
                terminal_end = end
    assert terminal_end is not None
    if cutoff is None:
        selected_cutoff = now - timedelta(seconds=collection_delay_seconds)
        cutoff_basis = "frozen_server_time_minus_collection_delay"
    else:
        selected_cutoff = _time(cutoff).astimezone(timezone.utc).replace(microsecond=0)
        cutoff_basis = "operator_selected_utc_cutoff"
    later_noncomparable = [
        item for item in exact
        if not item["eligible_for_continuity"] and _time(item["query_end"]) > terminal_end
    ]
    common = {
        "stream_identity": stream_identity,
        "generated_at": now.isoformat(),
        "cutoff": selected_cutoff.isoformat(),
        "cutoff_basis": cutoff_basis,
        "collection_delay_seconds": collection_delay_seconds if cutoff is None else 0,
        "overlap_minutes": overlap_minutes,
        "anchor_end": terminal_end.isoformat(),
        "anchor_sources": [
            {
                "import_id": item["import_id"],
                "observation_id": item["observation_id"],
                "pull_run_id": item["pull_run_id"],
                "query_start": item["query_start"],
                "query_end": item["query_end"],
                "raw_url": item["raw_url"],
            }
            for item in terminal_segment
        ],
        "later_noncomparable_sources": [
            {
                "import_id": item["import_id"],
                "query_start": item["query_start"],
                "query_end": item["query_end"],
                "provenance_state": item["provenance_state"],
                "raw_url": item["raw_url"],
            }
            for item in later_noncomparable
        ],
        "row_limit_warning": (
            f"Arkime may report more than the {ARKIME_PULL_ROW_LIMIT:,}-session connector "
            "limit. A recommended time window cannot guarantee a complete API result."
        ),
        "repairs_historical_gaps": False,
        "deduplicates_observations": False,
        "contacts_arkime": False,
        "read_only": True,
    }
    if selected_cutoff > now:
        return {
            **common, "status": "unavailable", "window": None,
            "reason": "cutoff_after_frozen_server_time",
            "detail": (
                "The selected cutoff is later than the frozen server time. Choose a "
                "current or historical UTC cutoff."
            ),
        }
    if selected_cutoff <= terminal_end:
        return {
            **common, "status": "nothing_due", "window": None,
            "reason": "cutoff_not_after_anchor",
            "detail": (
                "The selected cutoff is not later than the latest eligible retained "
                "window, so there is no forward interval to recommend."
            ),
        }
    start = terminal_end - timedelta(minutes=overlap_minutes)
    return {
        **common, "status": "recommended",
        "window": {"start": start.isoformat(), "end": selected_cutoff.isoformat()},
        "detail": (
            "This is the next forward collection window from the latest comparable "
            "retained interval. It does not repair earlier gaps or authorize a pull."
        ),
        "recollects_later_noncomparable_time": bool(later_noncomparable),
    }


def list_arkime_coverage_windows(
    db_path: Path, *, scope_id: str | None = None, limit: int = 25,
    offset: int = 0, revision: str | None = None,
    recommend_stream_identity: str | None = None, overlap_minutes: int = 5,
    cutoff: str | None = None, collection_delay_seconds: int = 60,
    frozen_now: datetime | None = None,
) -> dict:
    """Return a revision-bound page from one read-only database snapshot."""
    if type(limit) is not int or not 1 <= limit <= MAX_PAGE:
        raise ArkimeCoverageError(f"limit must be between 1 and {MAX_PAGE}")
    if type(offset) is not int or offset < 0:
        raise ArkimeCoverageError("offset must be zero or greater")
    where = " WHERE scope_id = ?" if scope_id else ""
    parameters = (scope_id,) if scope_id else ()
    try:
        with connect_database(Path(db_path), read_only=True) as db:
            db.row_factory = sqlite3.Row
            db.execute("BEGIN")
            tables = {
                row[0] for row in db.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            }
            if not {"arkime_imports", "arkime_summary_imports"} & tables:
                raise ArkimeCoverageError(
                    "Arkime coverage storage is unavailable; finish Arkime storage setup first"
                )
            session_count = 0 if "arkime_imports" not in tables else int(db.execute(
                "SELECT COUNT(*) FROM arkime_imports" + where, parameters,
            ).fetchone()[0])
            summary_count = 0 if "arkime_summary_imports" not in tables else int(db.execute(
                "SELECT COUNT(*) FROM arkime_summary_imports" + where, parameters,
            ).fetchone()[0])
            if session_count + summary_count > MAX_WINDOWS:
                raise ArkimeCoverageError(
                    f"The filtered Arkime coverage inventory exceeds {MAX_WINDOWS} windows; "
                    "choose one Network Scope"
                )
            sessions = [] if "arkime_imports" not in tables else db.execute(
                "SELECT * FROM arkime_imports" + where, parameters,
            ).fetchall()
            summaries = [] if "arkime_summary_imports" not in tables else db.execute(
                "SELECT * FROM arkime_summary_imports" + where, parameters,
            ).fetchall()
            import_ids = [row["import_id"] for row in sessions]
            observation_ids = [row["observation_id"] for row in sessions]
            runs_by_import: dict[str, list[sqlite3.Row]] = {}
            observations_by_id: dict[str, sqlite3.Row] = {}
            if import_ids and "arkime_pull_runs" in tables:
                for start in range(0, len(import_ids), 500):
                    batch = import_ids[start:start + 500]
                    marks = ",".join("?" for _ in batch)
                    rows = db.execute(
                        f"SELECT * FROM arkime_pull_runs WHERE import_id IN ({marks}) "
                        "ORDER BY queued_at, run_id", batch,
                    ).fetchall()
                    for row in rows:
                        runs_by_import.setdefault(row["import_id"], []).append(row)
            if observation_ids and "artifact_observations" in tables:
                for start in range(0, len(observation_ids), 500):
                    batch = observation_ids[start:start + 500]
                    marks = ",".join("?" for _ in batch)
                    rows = db.execute(
                        f"SELECT observation_id,source_kind,source_ref,observed_at,"
                        f"original_filename,actor,metadata_json FROM artifact_observations "
                        f"WHERE observation_id IN ({marks})", batch,
                    ).fetchall()
                    observations_by_id.update({row["observation_id"]: row for row in rows})
            items = [_manual_session(row) for row in sessions]
            items.extend(_summary(row) for row in summaries)
            for item in items:
                if item["source_kind"] == "sessions_json":
                    _apply_api_provenance(
                        item, runs_by_import.get(item["import_id"], []),
                        observations_by_id.get(item["observation_id"]),
                    )
            _classify(items)
            items.sort(key=lambda item: (
                _time(item["query_start"]), _time(item["query_end"]),
                item["imported_at"], item["source_kind"], item["import_id"],
            ), reverse=True)
            source_revision = _revision(items)
            if revision is not None and revision != source_revision:
                raise ArkimeCoverageConflict(
                    "Arkime coverage history changed while paging"
                )
            page = items[offset:offset + limit]
    except ArkimeCoverageError:
        raise
    except sqlite3.Error as exc:
        raise ArkimeCoverageError(
            "Arkime coverage storage is unavailable; finish Arkime storage setup first"
        ) from exc
    total = len(items)
    states: dict[str, int] = {}
    for item in items:
        states[item["continuity"]] = states.get(item["continuity"], 0) + 1
    exact_api_streams = _stream_summaries(items)
    recommendation = None
    if recommend_stream_identity is not None:
        recommendation = _recommend_next_forward_window(
            items, stream_identity=recommend_stream_identity,
            overlap_minutes=overlap_minutes, cutoff=cutoff,
            collection_delay_seconds=collection_delay_seconds,
            frozen_now=frozen_now,
        )
    return {
        "items": page,
        "source_revision": source_revision,
        "pagination": {
            "limit": limit, "offset": offset, "total": total,
            "has_more": offset + len(page) < total,
        },
        "continuity_counts": states,
        "exact_api_streams": exact_api_streams,
        "recommendation": recommendation,
        "read_only": True,
        "meaning": (
            "A retained-window gap means only that NCT has no comparable retained "
            "window for the same exact declared API stream."
        ),
    }
