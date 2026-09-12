from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
from pathlib import PurePosixPath
import re
import shutil
import subprocess
import tarfile
import threading
import urllib.request
import uuid
import zipfile


MAX_QUERIES = 40
MAX_RESULTS_PER_QUERY = 25
MAX_ARCHIVE_BYTES = 1_500_000_000
MAX_EXTRACTED_BYTES = 4_000_000_000
MAX_ARCHIVE_FILES = 120_000
OFFICIAL_ARCHIVE_URL = (
    "https://gitlab.com/exploit-database/exploitdb/-/archive/main/"
    "exploitdb-main.tar.gz"
)
_UPDATE_LOCK = threading.Lock()
GENERIC_PRODUCTS = {
    "", "unknown", "http", "https", "ssh", "ftp", "smtp", "dns", "domain",
    "microsoft", "windows", "linux", "network", "server",
}


def _configured_command() -> str:
    return str(os.environ.get("NCT_SEARCHSPLOIT_COMMAND") or "searchsploit").strip()


def _storage_root() -> Path:
    data_root = Path(os.environ.get("ANALYZER_DATA_DIR") or "/data")
    return data_root / "searchsploit"


def _active_database_path() -> Path | None:
    root = _storage_root()
    pointer = root / "active.json"
    try:
        payload = json.loads(pointer.read_text(encoding="utf-8"))
        candidate = (root / str(payload.get("directory") or "")).resolve()
        versions = (root / "versions").resolve()
        if candidate.is_relative_to(versions) and candidate.is_dir():
            return candidate
    except (OSError, ValueError, json.JSONDecodeError):
        pass
    legacy = root / "current"
    return legacy if legacy.is_dir() else None


def _command_path() -> str | None:
    command = _configured_command()
    active = _active_database_path()
    candidates = [
        Path(command),
        active / "searchsploit" if active else None,
        Path("/opt/exploit-database/searchsploit"),
    ]
    for candidate in candidates:
        if candidate and candidate.is_file():
            return str(candidate)
    return shutil.which(command)


def _database_path(command_path: str | None) -> Path | None:
    configured = str(os.environ.get("NCT_SEARCHSPLOIT_DB") or "").strip()
    active = _active_database_path()
    candidates = [
        Path(configured) if configured else None,
        active,
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
    active_metadata = {}
    if database_path:
        try:
            active_metadata = json.loads(
                (database_path / "nct-database.json").read_text(encoding="utf-8")
            )
        except (OSError, json.JSONDecodeError):
            pass
    return {
        "status": "ready" if available else "unavailable",
        "available": available,
        "provider": "SearchSploit / Exploit-DB",
        "command_path": command_path,
        "database_path": str(database_path) if database_path else None,
        "database_files": len(csv_files),
        "database_updated_epoch": updated_at,
        "active_version": active_metadata.get("version_id"),
        "installed_at": active_metadata.get("installed_at"),
        "source": active_metadata.get("source"),
        "archive_sha256": active_metadata.get("archive_sha256"),
        "versions": list_searchsploit_versions(),
        "mode": "offline_read_only",
        "message": (
            "Offline SearchSploit database is ready."
            if available else
            "SearchSploit and its offline Exploit-DB data have not been staged in this build."
        ),
    }


def list_searchsploit_versions() -> list[dict]:
    root = _storage_root()
    active = _active_database_path()
    versions = []
    versions_root = root / "versions"
    if not versions_root.is_dir():
        return versions
    for path in versions_root.iterdir():
        if not path.is_dir():
            continue
        try:
            metadata = json.loads(
                (path / "nct-database.json").read_text(encoding="utf-8")
            )
        except (OSError, json.JSONDecodeError):
            continue
        versions.append({
            **metadata,
            "active": bool(active and path.resolve() == active.resolve()),
        })
    versions.sort(key=lambda item: str(item.get("installed_at") or ""), reverse=True)
    return versions


def _safe_archive_name(name: str) -> PurePosixPath:
    normalized = PurePosixPath(str(name or "").replace("\\", "/"))
    if normalized.is_absolute() or ".." in normalized.parts:
        raise ValueError("The update archive contains an unsafe path.")
    return normalized


def _extract_archive(archive_path: Path, destination: Path) -> None:
    if zipfile.is_zipfile(archive_path):
        with zipfile.ZipFile(archive_path) as archive:
            members = archive.infolist()
            if len(members) > MAX_ARCHIVE_FILES:
                raise ValueError("The update archive contains too many files.")
            if sum(item.file_size for item in members) > MAX_EXTRACTED_BYTES:
                raise ValueError("The expanded update archive is too large.")
            for member in members:
                relative = _safe_archive_name(member.filename)
                mode = member.external_attr >> 16
                if mode and (mode & 0o170000) == 0o120000:
                    raise ValueError("Symbolic links are not allowed in update archives.")
                target = destination.joinpath(*relative.parts)
                if member.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(member) as source, target.open("wb") as output:
                    shutil.copyfileobj(source, output)
        return
    if not tarfile.is_tarfile(archive_path):
        raise ValueError("Upload a ZIP, TAR, TAR.GZ, or TGZ Exploit-DB package.")
    with tarfile.open(archive_path, mode="r:*") as archive:
        members = archive.getmembers()
        regular = [item for item in members if item.isfile()]
        if len(members) > MAX_ARCHIVE_FILES:
            raise ValueError("The update archive contains too many files.")
        if sum(item.size for item in regular) > MAX_EXTRACTED_BYTES:
            raise ValueError("The expanded update archive is too large.")
        if any(not (item.isfile() or item.isdir()) for item in members):
            raise ValueError("Links and special files are not allowed in update archives.")
        for member in members:
            relative = _safe_archive_name(member.name)
            target = destination.joinpath(*relative.parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            source = archive.extractfile(member)
            if source is None:
                raise ValueError("The update archive contains an unreadable file.")
            with source, target.open("wb") as output:
                shutil.copyfileobj(source, output)


def _find_repository_root(staging: Path) -> Path:
    candidates = []
    for csv_path in staging.rglob("files_exploits.csv"):
        parent = csv_path.parent
        if (parent / "searchsploit").is_file() and (parent / ".searchsploit_rc").is_file():
            candidates.append(parent)
    if len(candidates) != 1:
        raise ValueError(
            "The package must contain one Exploit-DB repository with searchsploit, "
            ".searchsploit_rc, and files_exploits.csv."
        )
    repository = candidates[0]
    with (repository / "files_exploits.csv").open("r", encoding="utf-8", errors="replace") as source:
        header = source.readline().lower()
    if "id" not in header or "file" not in header or "description" not in header:
        raise ValueError("The Exploit-DB index header is not recognized.")
    if (repository / "searchsploit").stat().st_size < 1000:
        raise ValueError("The SearchSploit program in the package is incomplete.")
    return repository


def _archive_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _activate_version(version_path: Path) -> None:
    root = _storage_root()
    relative = version_path.resolve().relative_to(root.resolve())
    temporary = root / f"active-{uuid.uuid4().hex}.json"
    temporary.write_text(
        json.dumps({"directory": relative.as_posix()}, indent=2), encoding="utf-8"
    )
    os.replace(temporary, root / "active.json")


def install_searchsploit_archive(archive_path: Path, *, source: str) -> dict:
    if archive_path.stat().st_size > MAX_ARCHIVE_BYTES:
        raise ValueError("The update archive is larger than the 1.5 GB limit.")
    with _UPDATE_LOCK:
        root = _storage_root()
        versions_root = root / "versions"
        staging = root / ".staging" / uuid.uuid4().hex
        versions_root.mkdir(parents=True, exist_ok=True)
        staging.mkdir(parents=True, exist_ok=False)
        try:
            _extract_archive(archive_path, staging)
            repository = _find_repository_root(staging)
            archive_sha256 = _archive_digest(archive_path)
            installed_at = datetime.now(timezone.utc).isoformat()
            version_id = (
                datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
                + "-" + archive_sha256[:12]
            )
            target = versions_root / version_id
            if target.exists():
                version_id += "-" + uuid.uuid4().hex[:6]
                target = versions_root / version_id
            shutil.move(str(repository), str(target))
            resource = target / ".searchsploit_rc"
            resource_text = resource.read_text(encoding="utf-8", errors="replace")
            resource_text = resource_text.replace(
                '"/opt/exploitdb"', f'"{target.as_posix()}"'
            )
            resource.write_text(resource_text, encoding="utf-8")
            (target / "searchsploit").chmod(0o755)
            metadata = {
                "version_id": version_id,
                "installed_at": installed_at,
                "source": source,
                "archive_sha256": archive_sha256,
            }
            (target / "nct-database.json").write_text(
                json.dumps(metadata, indent=2), encoding="utf-8"
            )
            _activate_version(target)
        finally:
            shutil.rmtree(staging, ignore_errors=True)
    return searchsploit_status()


def update_searchsploit_from_internet() -> dict:
    root = _storage_root()
    incoming = root / ".incoming"
    incoming.mkdir(parents=True, exist_ok=True)
    archive_path = incoming / f"exploitdb-{uuid.uuid4().hex}.tar.gz"
    try:
        request = urllib.request.Request(
            OFFICIAL_ARCHIVE_URL,
            headers={"User-Agent": "NCT-SearchSploit-Updater/1"},
        )
        with urllib.request.urlopen(request, timeout=45) as response, archive_path.open("wb") as output:
            total = 0
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_ARCHIVE_BYTES:
                    raise ValueError("The downloaded update exceeds the 1.5 GB limit.")
                output.write(chunk)
        return install_searchsploit_archive(archive_path, source=OFFICIAL_ARCHIVE_URL)
    finally:
        archive_path.unlink(missing_ok=True)


def rollback_searchsploit_database(version_id: str) -> dict:
    if not re.fullmatch(r"[A-Za-z0-9._-]{8,80}", str(version_id or "")):
        raise ValueError("Invalid SearchSploit database version.")
    target = _storage_root() / "versions" / version_id
    if not target.is_dir() or not (target / "nct-database.json").is_file():
        raise FileNotFoundError("SearchSploit database version was not found.")
    with _UPDATE_LOCK:
        _activate_version(target)
    return searchsploit_status()


def _safe_term(value: object) -> str:
    value = re.sub(r"[^A-Za-z0-9._+ -]+", " ", str(value or ""))
    return re.sub(r"\s+", " ", value).strip(" -")[:120]


def _query_for_finding(finding: dict) -> str | None:
    product = _safe_term(finding.get("product"))
    version = _safe_term(finding.get("version"))
    if product.lower() in GENERIC_PRODUCTS:
        return None
    return " ".join(value for value in (product, version) if value).strip() or None


def _finding_match_key(finding: dict) -> str:
    values = (
        finding.get("host_key"),
        finding.get("protocol"),
        finding.get("port"),
        finding.get("product"),
        finding.get("version"),
    )
    return "|".join(str(value or "").strip().lower() for value in values)


def _extract_cves(value: object) -> list[str]:
    return sorted({
        item.upper()
        for item in re.findall(r"\bCVE-\d{4}-\d{4,}\b", str(value or ""), re.IGNORECASE)
    })


def _candidate(item: dict) -> dict:
    edb_id = str(item.get("EDB-ID") or "").strip()
    codes = item.get("Codes")
    return {
        "edb_id": edb_id or None,
        "title": item.get("Title"),
        "platform": item.get("Platform"),
        "type": item.get("Type"),
        "codes": codes,
        "cves": _extract_cves(codes),
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
        _candidate(item) for item in (
            payload.get("RESULTS_EXPLOIT") or payload.get("RESULTS_EXPLOITS") or []
        )
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
            "searched_finding_count": 0,
            "skipped_no_product_count": 0,
            "matched_host_count": 0,
            "match_count": 0,
            "cve_count": 0,
            "cve_candidate_count": 0,
            "non_cve_candidate_count": 0,
            "cve_facets": [],
            "matches": [],
            "warnings": [status["message"]],
            "disclaimer": "Potential product/version matches require analyst validation.",
        }

    query_findings: dict[str, dict[str, dict]] = {}
    skipped_no_product_count = 0
    for finding in hunting.get("findings") or []:
        if finding.get("evidence_kind") == "device_configuration":
            continue
        query = _query_for_finding(finding)
        if not query:
            skipped_no_product_count += 1
            continue
        query_findings.setdefault(query, {})[_finding_match_key(finding)] = finding
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
    for query, keyed_findings in query_findings.items():
        candidates = query_results.get(query, [])
        if not candidates:
            continue
        for match_key, finding in keyed_findings.items():
            matches.append({
                "match_key": match_key,
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
    cve_hosts: dict[str, set[str]] = {}
    cve_candidate_counts: dict[str, int] = {}
    cve_common_names: dict[str, set[str]] = {}
    cve_candidate_count = 0
    non_cve_candidate_count = 0
    for match in matches:
        host_key = str(match.get("host_key") or "")
        match_cves: set[str] = set()
        for candidate in match.get("candidates") or []:
            cves = candidate.get("cves") or _extract_cves(candidate.get("codes"))
            candidate["cves"] = cves
            if cves:
                cve_candidate_count += 1
            else:
                non_cve_candidate_count += 1
            for cve in cves:
                match_cves.add(cve)
                cve_candidate_counts[cve] = cve_candidate_counts.get(cve, 0) + 1
                title = str(candidate.get("title") or "").strip()
                if title:
                    cve_common_names.setdefault(cve, set()).add(title)
                if host_key:
                    cve_hosts.setdefault(cve, set()).add(host_key)
        match["cves"] = sorted(match_cves)
    cve_facets = [
        {
            "cve": cve,
            "year": cve.split("-")[1],
            "candidate_count": cve_candidate_counts[cve],
            "matched_host_count": len(cve_hosts.get(cve, set())),
            "common_names": sorted(cve_common_names.get(cve, set())),
        }
        for cve in sorted(cve_candidate_counts, reverse=True)
    ]
    return {
        "status": "searchsploit_complete",
        "provider": status,
        "query_count": len(query_findings),
        "searched_finding_count": sum(len(items) for items in query_findings.values()),
        "skipped_no_product_count": skipped_no_product_count,
        "matched_host_count": len(matched_hosts),
        "match_count": sum(item["candidate_count"] for item in matches),
        "cve_count": len(cve_facets),
        "cve_candidate_count": cve_candidate_count,
        "non_cve_candidate_count": non_cve_candidate_count,
        "cve_facets": cve_facets,
        "matches": matches,
        "warnings": warnings,
        "disclaimer": "Potential product/version matches require analyst validation.",
    }
