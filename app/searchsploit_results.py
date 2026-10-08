"""Immutable offline-candidate assessments for retained Nmap evidence."""
from __future__ import annotations

from collections import defaultdict
import json
from pathlib import Path
import sqlite3
from typing import Callable

from app.derived_contracts import (
    SEARCHSPLOIT_CANDIDATES_FAMILY,
    SEARCHSPLOIT_CANDIDATES_PARAMETERS,
    SEARCHSPLOIT_CANDIDATES_SCHEMA_VERSION,
    SEARCHSPLOIT_CANDIDATES_VERSION,
)
from app.derived_results import (
    derived_result_identity,
    init_derived_result_storage,
    load_derived_result,
    load_linked_derived_result,
    prepare_derived_result,
    publish_derived_result,
)
from app.database import connect_database
from app.hunting import build_hunting_analysis
from app.nmap_base_analysis import _parse_nmap_xml, _verified_observation_bytes
from app.searchsploit import (
    enrich_hunting_with_searchsploit,
    searchsploit_provider_snapshot,
)


SEARCHSPLOIT_CANDIDATE_JOB_TYPE = "nmap_searchsploit_candidates"


def _provider_identity(provider: dict) -> str:
    value = str(provider.get("provider_key") or "").strip()
    if not provider.get("available") or len(value) != 64:
        raise ValueError("A ready, identified offline Exploit-DB dataset is required")
    return value


def candidate_result_identity(source_sha256: str, provider: dict):
    provider_key = _provider_identity(provider)
    return derived_result_identity(
        family=SEARCHSPLOIT_CANDIDATES_FAMILY,
        analysis_version=SEARCHSPLOIT_CANDIDATES_VERSION,
        payload_schema_version=SEARCHSPLOIT_CANDIDATES_SCHEMA_VERSION,
        parameters=dict(SEARCHSPLOIT_CANDIDATES_PARAMETERS),
        inputs=[
            {
                "role": "nmap_xml",
                "kind": "artifact_sha256",
                "identity": source_sha256,
                "metadata": {"media_family": "nmap_xml"},
            },
            {
                "role": "offline_dataset",
                "kind": "searchsploit_dataset_sha256",
                "identity": provider_key,
                "metadata": {
                    key: provider.get(key)
                    for key in (
                        "active_version", "archive_sha256", "database_updated_epoch",
                        "installed_at", "source", "command_sha256",
                    )
                    if provider.get(key) is not None
                },
            },
        ],
    )


def generate_searchsploit_candidate_result(
    db_path: Path,
    observation_id: str,
    *,
    provider: dict,
    transaction_guard: Callable[[sqlite3.Connection], None] | None = None,
    transaction_finalize: Callable[[sqlite3.Connection, bool], None] | None = None,
) -> dict:
    """Calculate once from exact Nmap bytes and one frozen offline dataset."""
    provider_key = _provider_identity(provider)
    init_derived_result_storage(db_path)
    content, observation = _verified_observation_bytes(db_path, observation_id)
    identity = candidate_result_identity(observation["sha256"], provider)
    current = searchsploit_provider_snapshot()
    if _provider_identity(current) != provider_key:
        raise ValueError("The offline Exploit-DB dataset changed before assessment began")
    retained = load_derived_result(db_path, identity)
    if retained is not None:
        prepared = prepare_derived_result(
            family=SEARCHSPLOIT_CANDIDATES_FAMILY,
            analysis_version=SEARCHSPLOIT_CANDIDATES_VERSION,
            payload_schema_version=SEARCHSPLOIT_CANDIDATES_SCHEMA_VERSION,
            parameters=dict(SEARCHSPLOIT_CANDIDATES_PARAMETERS),
            inputs=json.loads(identity.inputs_json),
            payload=retained["payload"],
            generated_at=retained["generated_at"],
        )
        publication = publish_derived_result(
            db_path,
            prepared,
            observation_links=[{"role": "nmap_xml", "observation_id": observation_id}],
            transaction_guard=transaction_guard,
            transaction_finalize=transaction_finalize,
        )
        return {
            **publication,
            "payload": retained["payload"],
            "observation": observation,
            "execution": {"reused_retained_result": True},
        }
    hunting = build_hunting_analysis(_parse_nmap_xml(content))
    payload = enrich_hunting_with_searchsploit(hunting, provider_status=provider)
    repeated = searchsploit_provider_snapshot()
    if _provider_identity(repeated) != provider_key:
        raise ValueError("The offline Exploit-DB dataset changed during assessment")
    if int(payload.get("failed_query_count") or 0):
        raise RuntimeError(
            "Offline candidate assessment could not complete every product/version query; "
            "retry after checking the local Exploit-DB installation"
        )
    execution = {
        "reused_retained_result": False,
        "cache_hit_count": int(payload.pop("cache_hit_count", 0) or 0),
        "cache_miss_count": int(payload.pop("cache_miss_count", 0) or 0),
    }
    payload = {
        **payload,
        "status": "retained_candidate_assessment_complete",
        "provider": {
            key: provider.get(key)
            for key in (
                "provider", "provider_key", "active_version", "archive_sha256",
                "database_updated_epoch", "installed_at", "source", "command_sha256",
            )
        },
    }
    prepared = prepare_derived_result(
        family=SEARCHSPLOIT_CANDIDATES_FAMILY,
        analysis_version=SEARCHSPLOIT_CANDIDATES_VERSION,
        payload_schema_version=SEARCHSPLOIT_CANDIDATES_SCHEMA_VERSION,
        parameters=dict(SEARCHSPLOIT_CANDIDATES_PARAMETERS),
        inputs=json.loads(identity.inputs_json),
        payload=payload,
    )
    publication = publish_derived_result(
        db_path,
        prepared,
        observation_links=[{"role": "nmap_xml", "observation_id": observation_id}],
        transaction_guard=transaction_guard,
        transaction_finalize=transaction_finalize,
    )
    return {
        **publication,
        "payload": payload,
        "observation": observation,
        "execution": execution,
    }


def _load_linked_result(db_path: Path, result_id: str, observation_id: str) -> dict | None:
    with connect_database(db_path, read_only=True) as db:
        row = db.execute(
            """SELECT family, analysis_version, payload_schema_version,
                      parameters_json, inputs_json
               FROM derived_results WHERE result_id = ?""",
            (result_id,),
        ).fetchone()
    if row is None or row[0] != SEARCHSPLOIT_CANDIDATES_FAMILY:
        return None
    identity = derived_result_identity(
        family=row[0],
        analysis_version=row[1],
        payload_schema_version=int(row[2]),
        parameters=json.loads(row[3]),
        inputs=json.loads(row[4]),
    )
    if identity.result_id != result_id:
        raise ValueError("Retained candidate-result identity is inconsistent")
    return load_linked_derived_result(
        db_path, identity, role="nmap_xml", observation_id=observation_id,
    )


def _candidate_key(candidate: dict) -> str:
    return "|".join(str(candidate.get(key) or "") for key in (
        "edb_id", "title", "path", "url",
    ))


def _merge_payloads(results: list[dict]) -> dict:
    matches: dict[str, dict] = {}
    for result in results:
        for item in result["payload"].get("matches") or []:
            key = str(item.get("match_key") or "")
            if not key:
                continue
            if key not in matches:
                matches[key] = {**item, "candidates": []}
            known = {_candidate_key(candidate) for candidate in matches[key]["candidates"]}
            for candidate in item.get("candidates") or []:
                candidate_key = _candidate_key(candidate)
                if candidate_key not in known:
                    matches[key]["candidates"].append(candidate)
                    known.add(candidate_key)
            matches[key]["candidate_count"] = len(matches[key]["candidates"])
            matches[key]["cves"] = sorted({
                cve
                for candidate in matches[key]["candidates"]
                for cve in (candidate.get("cves") or [])
            })
    merged_matches = list(matches.values())
    cve_hosts: dict[str, set[str]] = defaultdict(set)
    cve_candidates: dict[str, int] = defaultdict(int)
    cve_names: dict[str, set[str]] = defaultdict(set)
    cve_candidate_count = 0
    non_cve_candidate_count = 0
    for match in merged_matches:
        for candidate in match.get("candidates") or []:
            cves = candidate.get("cves") or []
            if cves:
                cve_candidate_count += 1
            else:
                non_cve_candidate_count += 1
            for cve in cves:
                cve_candidates[cve] += 1
                if match.get("host_key"):
                    cve_hosts[cve].add(str(match["host_key"]))
                if candidate.get("title"):
                    cve_names[cve].add(str(candidate["title"]))
    return {
        "matches": merged_matches,
        "match_count": sum(item.get("candidate_count", 0) for item in merged_matches),
        "matched_host_count": len({
            item.get("host_key") for item in merged_matches if item.get("host_key")
        }),
        "cve_count": len(cve_candidates),
        "cve_candidate_count": cve_candidate_count,
        "non_cve_candidate_count": non_cve_candidate_count,
        "cve_facets": [
            {
                "cve": cve,
                "year": cve.split("-")[1],
                "candidate_count": cve_candidates[cve],
                "matched_host_count": len(cve_hosts[cve]),
                "common_names": sorted(cve_names[cve]),
            }
            for cve in sorted(cve_candidates, reverse=True)
        ],
    }


def load_retained_searchsploit_candidates(db_path: Path, run_ids: list[str]) -> dict:
    """Load saved candidates and processing states without launching a lookup."""
    run_ids = list(dict.fromkeys(str(value) for value in run_ids if value))
    if not run_ids:
        return {
            "status": "retained_candidates_no_evidence",
            "query_count": 0,
            "matches": [],
            "warnings": [],
            "disclaimer": "Potential product/version matches require analyst validation.",
        }
    placeholders = ",".join("?" for _ in run_ids)
    with connect_database(db_path, read_only=True) as db:
        observations = db.execute(
            f"""SELECT source_ref, observation_id
                 FROM artifact_observations
                 WHERE source_kind = 'nmap_scan' AND source_ref IN ({placeholders})
                   AND original_filename = 'scan.xml'
                 ORDER BY observation_id""",
            tuple(run_ids),
        ).fetchall()
        jobs = db.execute(
            f"""SELECT job.source_run_id, job.source_observation_id, job.job_id,
                       attempt.state, attempt.output_id, attempt.error,
                       attempt.finished_at, job.requested_at
                FROM pipeline_jobs job
                JOIN pipeline_job_attempts attempt ON attempt.job_id = job.job_id
                WHERE job.job_type = ?
                  AND job.source_run_id IN ({placeholders})
                  AND attempt.attempt_number = (
                      SELECT MAX(newer.attempt_number)
                      FROM pipeline_job_attempts newer WHERE newer.job_id = job.job_id
                  )
                ORDER BY job.requested_at DESC""",
            (SEARCHSPLOIT_CANDIDATE_JOB_TYPE, *run_ids),
        ).fetchall()
    jobs_by_observation: dict[str, tuple] = {}
    for job in jobs:
        jobs_by_observation.setdefault(str(job[1]), job)
    loaded_by_result: dict[str, dict] = {}
    encounters = []
    source_states = []
    for run_id, observation_id in observations:
        job = jobs_by_observation.get(str(observation_id))
        if job is None:
            source_states.append({
                "run_id": run_id, "observation_id": observation_id,
                "state": "historical_unassessed",
                "detail": "This evidence predates automatic offline-candidate assessment.",
            })
            continue
        state, output_id, error = str(job[3]), job[4], job[5]
        source_states.append({
            "run_id": run_id, "observation_id": observation_id,
            "job_id": job[2], "state": state, "detail": error,
        })
        if state != "completed" or not output_id:
            continue
        retained = _load_linked_result(db_path, str(output_id), str(observation_id))
        if retained is None:
            source_states[-1]["state"] = "integrity_conflict"
            source_states[-1]["detail"] = "The retained candidate result could not be verified."
            continue
        loaded_by_result.setdefault(str(output_id), retained)
        encounters.append({
            "run_id": run_id,
            "observation_id": observation_id,
            "result_id": output_id,
            "prepared_at": retained["generated_at"],
        })
    retained_results = list(loaded_by_result.values())
    observed_run_ids = {str(row[0]) for row in observations}
    for run_id in run_ids:
        if run_id not in observed_run_ids:
            source_states.append({
                "run_id": run_id,
                "observation_id": None,
                "state": "historical_unassessed",
                "detail": (
                    "This retained scan has not been registered for automatic "
                    "offline-candidate assessment."
                ),
            })
    merged = _merge_payloads(retained_results)
    complete = bool(source_states) and all(item["state"] == "completed" for item in source_states)
    status = (
        "retained_candidates_complete" if complete
        else "retained_candidates_partial" if retained_results
        else "retained_candidates_not_available"
    )
    warnings = [
        str(warning)
        for result in retained_results
        for warning in (result["payload"].get("warnings") or [])
    ]
    incomplete = [item for item in source_states if item["state"] != "completed"]
    if incomplete:
        warnings.append(
            f"Saved candidate assessment is unavailable for {len(incomplete)} of "
            f"{len(source_states)} retained scan source(s)."
        )
    providers = {
        json.dumps(result["payload"].get("provider") or {}, sort_keys=True):
        result["payload"].get("provider") or {}
        for result in retained_results
    }
    query_count = sum(int(result["payload"].get("query_count") or 0) for result in retained_results)
    coverage_complete = complete and all(
        bool(result["payload"].get("coverage_complete")) for result in retained_results
    )
    return {
        "status": status,
        **merged,
        "query_count": query_count,
        "searched_finding_count": sum(
            int(result["payload"].get("searched_finding_count") or 0)
            for result in retained_results
        ),
        "skipped_no_product_count": sum(
            int(result["payload"].get("skipped_no_product_count") or 0)
            for result in retained_results
        ),
        "coverage_complete": coverage_complete,
        "query_limit": SEARCHSPLOIT_CANDIDATES_PARAMETERS["max_distinct_queries"],
        "candidate_limit_per_query": SEARCHSPLOIT_CANDIDATES_PARAMETERS[
            "max_candidates_per_query"
        ],
        "provider": next(iter(providers.values()), {}),
        "provider_datasets": list(providers.values()),
        "mixed_provider_datasets": len(providers) > 1,
        "prepared_at": max(
            (result["generated_at"] for result in retained_results), default=None,
        ),
        "encounters": encounters,
        "source_states": source_states,
        "warnings": list(dict.fromkeys(warnings)),
        "disclaimer": "Potential product/version matches require analyst validation.",
    }
