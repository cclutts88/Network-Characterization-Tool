from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import os
from pathlib import Path
import re
import shutil
import subprocess


MAX_QUERIES = 40
MAX_RESULTS_PER_QUERY = 25
GENERIC_PRODUCTS = {
    "", "unknown", "http", "https", "ssh", "ftp", "smtp", "dns", "domain",
    "microsoft", "windows", "linux", "network", "server",
}


def _configured_command() -> str:
    return str(os.environ.get("NCT_SEARCHSPLOIT_COMMAND") or "searchsploit").strip()


def _command_path() -> str | None:
    command = _configured_command()
    candidates = [
        Path(command),
        Path("/data/searchsploit/current/searchsploit"),
        Path("/opt/exploit-database/searchsploit"),
    ]
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)
    return shutil.which(command)


def _database_path(command_path: str | None) -> Path | None:
    configured = str(os.environ.get("NCT_SEARCHSPLOIT_DB") or "").strip()
    candidates = [
        Path(configured) if configured else None,
        Path("/data/searchsploit/current"),
        Path(command_path).resolve().parent if command_path else None,
        Path("/opt/exploit-database"),
        Path("/usr/share/exploitdb"),
    ]
    for candidate in candidates:
        if candidate and candidate.is_dir() and list(candidate.glob("files_*.csv")):
            return candidate
    return None


def searchsploit_status() -> dict:
    command_path = _command_path()
    database_path = _database_path(command_path)
    csv_files = list(database_path.glob("files_*.csv")) if database_path else []
    updated_at = None
    if csv_files:
        updated_at = max(path.stat().st_mtime for path in csv_files)
    available = bool(command_path and database_path)
    return {
        "status": "ready" if available else "unavailable",
        "available": available,
        "provider": "SearchSploit / Exploit-DB",
        "command_path": command_path,
        "database_path": str(database_path) if database_path else None,
        "database_files": len(csv_files),
        "database_updated_epoch": updated_at,
        "mode": "offline_read_only",
        "message": (
            "Offline SearchSploit database is ready."
            if available else
            "SearchSploit and its offline Exploit-DB data have not been staged in this build."
        ),
    }


def _safe_term(value: object) -> str:
    value = re.sub(r"[^A-Za-z0-9._+ -]+", " ", str(value or ""))
    return re.sub(r"\s+", " ", value).strip(" -")[:120]


def _query_for_finding(finding: dict) -> str | None:
    product = _safe_term(finding.get("product"))
    version = _safe_term(finding.get("version"))
    if product.lower() in GENERIC_PRODUCTS:
        return None
    return " ".join(value for value in (product, version) if value).strip() or None


def _candidate(item: dict) -> dict:
    edb_id = str(item.get("EDB-ID") or "").strip()
    return {
        "edb_id": edb_id or None,
        "title": item.get("Title"),
        "platform": item.get("Platform"),
        "type": item.get("Type"),
        "codes": item.get("Codes"),
        "verified": str(item.get("Verified") or "").strip() in {"1", "true", "True"},
        "date_published": item.get("Date_Published"),
        "path": item.get("Path"),
        "url": f"https://www.exploit-db.com/exploits/{edb_id}" if edb_id else None,
    }


def _search(command_path: str, query: str) -> tuple[list[dict], str | None]:
    try:
        completed = subprocess.run(
            [command_path, "--json", "--title", "--disable-colour", query],
            capture_output=True,
            check=False,
            text=True,
            timeout=12,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return [], f"SearchSploit query failed for {query}: {exc}"
    if completed.returncode not in {0, 1}:
        detail = _safe_term(completed.stderr) or f"exit code {completed.returncode}"
        return [], f"SearchSploit query failed for {query}: {detail}"
    try:
        payload = json.loads(completed.stdout or "{}")
    except json.JSONDecodeError:
        return [], f"SearchSploit returned unreadable JSON for {query}."
    results = [
        _candidate(item) for item in (payload.get("RESULTS_EXPLOITS") or [])
        if isinstance(item, dict)
    ]
    return results[:MAX_RESULTS_PER_QUERY], None


def enrich_hunting_with_searchsploit(hunting: dict) -> dict:
    status = searchsploit_status()
    if not status["available"]:
        return {
            "status": "searchsploit_unavailable",
            "provider": status,
            "query_count": 0,
            "matched_host_count": 0,
            "match_count": 0,
            "matches": [],
            "warnings": [status["message"]],
            "disclaimer": "Potential product/version matches require analyst validation.",
        }

    query_findings: dict[str, list[dict]] = {}
    for finding in hunting.get("findings") or []:
        if finding.get("evidence_kind") == "device_configuration":
            continue
        query = _query_for_finding(finding)
        if not query:
            continue
        query_findings.setdefault(query, []).append(finding)
        if len(query_findings) >= MAX_QUERIES:
            break

    query_results: dict[str, list[dict]] = {}
    warnings = []
    if query_findings:
        workers = min(4, len(query_findings))
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {
                executor.submit(_search, status["command_path"], query): query
                for query in query_findings
            }
            for future in as_completed(futures):
                query = futures[future]
                candidates, warning = future.result()
                query_results[query] = candidates
                if warning:
                    warnings.append(warning)

    matches = []
    for query, findings in query_findings.items():
        candidates = query_results.get(query, [])
        if not candidates:
            continue
        for finding in findings:
            matches.append({
                "host_key": finding.get("host_key"),
                "ip": finding.get("ip"),
                "hostname": finding.get("hostname"),
                "port": finding.get("port"),
                "protocol": finding.get("protocol"),
                "service": finding.get("service"),
                "product": finding.get("product"),
                "version": finding.get("version"),
                "query": query,
                "candidate_count": len(candidates),
                "candidates": candidates,
            })
    matched_hosts = {item.get("host_key") for item in matches if item.get("host_key")}
    return {
        "status": "searchsploit_complete",
        "provider": status,
        "query_count": len(query_findings),
        "matched_host_count": len(matched_hosts),
        "match_count": sum(item["candidate_count"] for item in matches),
        "matches": matches,
        "warnings": warnings,
        "disclaimer": "Potential product/version matches require analyst validation.",
    }
