from __future__ import annotations

import json
import subprocess
import zipfile

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.searchsploit import (
    _search,
    enrich_hunting_with_searchsploit,
    install_searchsploit_archive,
    rollback_searchsploit_database,
)


def finding(product: str, version: str = "") -> dict:
    return {
        "host_key": "ip:10.0.0.10",
        "ip": "10.0.0.10",
        "hostname": "web-01",
        "port": 443,
        "protocol": "tcp",
        "service": "https",
        "product": product,
        "version": version,
    }


def test_searchsploit_unavailable_is_nonfatal(monkeypatch):
    monkeypatch.setattr("app.searchsploit.searchsploit_status", lambda: {
        "available": False,
        "message": "Offline data not staged.",
    })

    result = enrich_hunting_with_searchsploit({"findings": [finding("nginx", "1.20")]})

    assert result["status"] == "searchsploit_unavailable"
    assert result["matches"] == []
    assert result["warnings"] == ["Offline data not staged."]


def test_searchsploit_enrichment_sanitizes_queries_and_returns_candidates(monkeypatch):
    monkeypatch.setattr("app.searchsploit.searchsploit_status", lambda: {
        "available": True,
        "command_path": "/opt/exploit-database/searchsploit",
        "message": "ready",
    })
    searches = []

    def fake_search(command_path: str, query: str, _database_path=None):
        searches.append((command_path, query))
        return [{
            "edb_id": "12345",
            "title": "Example candidate",
            "platform": "linux",
            "type": "remote",
            "codes": "CVE-2026-1234",
            "verified": True,
            "date_published": "2026-01-01",
            "path": "/opt/exploit-database/exploits/12345.py",
            "url": "https://www.exploit-db.com/exploits/12345",
        }], None

    monkeypatch.setattr("app.searchsploit._search", fake_search)
    result = enrich_hunting_with_searchsploit({
        "findings": [
            finding("Example Server; touch /tmp/not-allowed", "2.4.1"),
            finding("unknown"),
            {**finding("cisco", "17.1"), "evidence_kind": "device_configuration"},
        ]
    })

    assert searches == [(
        "/opt/exploit-database/searchsploit",
        "Example Server touch tmp not-allowed 2.4.1",
    )]
    assert result["status"] == "searchsploit_complete"
    assert result["query_count"] == 1
    assert result["searched_finding_count"] == 1
    assert result["skipped_no_product_count"] == 1
    assert result["matched_host_count"] == 1
    assert result["match_count"] == 1
    assert result["matches"][0]["match_key"] == (
        "ip:10.0.0.10|tcp|443|example server; touch /tmp/not-allowed|2.4.1"
    )
    assert result["matches"][0]["candidates"][0]["edb_id"] == "12345"
    assert result["matches"][0]["candidates"][0]["cves"] == ["CVE-2026-1234"]
    assert result["matches"][0]["cves"] == ["CVE-2026-1234"]
    assert result["cve_count"] == 1
    assert result["cve_candidate_count"] == 1
    assert result["non_cve_candidate_count"] == 0
    assert result["cve_facets"] == [{
        "cve": "CVE-2026-1234",
        "year": "2026",
        "candidate_count": 1,
        "matched_host_count": 1,
        "common_names": ["Example candidate"],
    }]


def test_searchsploit_enrichment_reuses_persistent_cache_until_database_changes(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("ANALYZER_DATA_DIR", str(tmp_path / "data"))
    provider = {
        "available": True,
        "command_path": "/opt/exploit-database/searchsploit",
        "message": "ready",
        "active_version": "db-v1",
        "archive_sha256": "a" * 64,
        "database_updated_epoch": 1000,
        "database_path": "/opt/exploit-database",
    }
    monkeypatch.setattr("app.searchsploit.searchsploit_status", lambda: dict(provider))
    searches = []

    def fake_search(command_path: str, query: str, _database_path=None):
        searches.append((command_path, query))
        return [{
            "edb_id": "12345",
            "title": "Cached candidate",
            "platform": "linux",
            "type": "remote",
            "codes": "CVE-2026-1234",
            "cves": ["CVE-2026-1234"],
            "verified": True,
            "date_published": "2026-01-01",
            "path": "/opt/exploit-database/exploits/12345.py",
            "url": "https://www.exploit-db.com/exploits/12345",
        }], None

    monkeypatch.setattr("app.searchsploit._search", fake_search)
    hunting = {"findings": [finding("nginx", "1.24")]}

    first = enrich_hunting_with_searchsploit(hunting)
    second = enrich_hunting_with_searchsploit(hunting)

    assert len(searches) == 1
    assert first["cache_hit_count"] == 0
    assert first["cache_miss_count"] == 1
    assert second["cache_hit_count"] == 1
    assert second["cache_miss_count"] == 0
    assert second["matches"][0]["candidates"][0]["title"] == "Cached candidate"

    provider["active_version"] = "db-v2"
    third = enrich_hunting_with_searchsploit(hunting)

    assert len(searches) == 2
    assert third["cache_hit_count"] == 0
    assert third["cache_miss_count"] == 1


def test_searchsploit_reports_when_no_product_fingerprints_are_searchable(monkeypatch):
    monkeypatch.setattr("app.searchsploit.searchsploit_status", lambda: {
        "available": True,
        "command_path": "/opt/exploit-database/searchsploit",
        "message": "ready",
    })
    monkeypatch.setattr(
        "app.searchsploit._search",
        lambda *_: pytest.fail("A generic service must not trigger a SearchSploit query"),
    )

    result = enrich_hunting_with_searchsploit({
        "findings": [
            finding(""),
            {**finding(""), "service": "ssh", "port": 22},
        ]
    })

    assert result["query_count"] == 0
    assert result["searched_finding_count"] == 0
    assert result["skipped_no_product_count"] == 2
    assert result["matches"] == []


def test_searchsploit_reports_query_limits_without_dropping_in_limit_duplicates(monkeypatch):
    monkeypatch.setattr("app.searchsploit.searchsploit_status", lambda: {
        "available": True,
        "command_path": "/opt/exploit-database/searchsploit",
        "message": "ready",
    })
    monkeypatch.setattr("app.searchsploit._search", lambda *_: ([], None))
    findings = [
        {**finding(f"product-{index}", "1.0"), "port": 1000 + index}
        for index in range(41)
    ]
    findings.append({**finding("product-0", "1.0"), "port": 8443})

    result = enrich_hunting_with_searchsploit({"findings": findings})

    assert result["query_count"] == 40
    assert result["searched_finding_count"] == 41
    assert result["omitted_distinct_query_count"] == 1
    assert result["omitted_finding_count"] == 1
    assert result["coverage_complete"] is False
    assert "40-query safety limit" in result["warnings"][0]


def test_searchsploit_failed_query_is_incomplete_and_retryable(monkeypatch):
    monkeypatch.setattr("app.searchsploit.searchsploit_status", lambda: {
        "available": True,
        "command_path": "/opt/exploit-database/searchsploit",
        "message": "ready",
    })
    monkeypatch.setattr(
        "app.searchsploit._search",
        lambda *_: ([], "SearchSploit command failed for nginx 1.24"),
    )

    result = enrich_hunting_with_searchsploit({
        "findings": [finding("nginx", "1.24")]
    })

    assert result["status"] == "searchsploit_incomplete"
    assert result["coverage_complete"] is False
    assert result["failed_query_count"] == 1
    assert result["warnings"] == ["SearchSploit command failed for nginx 1.24"]


def test_searchsploit_rejects_results_from_a_different_database(monkeypatch):
    monkeypatch.setattr("app.searchsploit.subprocess.run", lambda *args, **kwargs: (
        subprocess.CompletedProcess(
            args=args[0], returncode=0,
            stdout=json.dumps({
                "DB_PATH_EXPLOITS": "/offline/other",
                "RESULTS_EXPLOITS": [{"EDB-ID": "12345", "Title": "Wrong data"}],
            }),
            stderr="",
        )
    ))

    results, warning = _search(
        "/offline/frozen/searchsploit", "nginx 1.24", "/offline/frozen",
    )

    assert results == []
    assert warning == (
        "SearchSploit did not confirm the frozen offline database for nginx 1.24."
    )


def test_hunt_network_read_loads_saved_candidates_without_running_searchsploit(monkeypatch):
    import app.main as main

    loaded = []
    hunting = {
        "source": {"scope_summaries": [
            {"run_ids": ["a" * 32, "b" * 32]},
            {"run_ids": ["c" * 32]},
        ]},
        "hosts": [], "findings": [],
    }
    saved = {"status": "retained_candidates_complete", "matches": []}
    monkeypatch.setattr(main, "_latest_network_evidence", lambda: dict(hunting))
    monkeypatch.setattr(
        main, "load_retained_searchsploit_candidates",
        lambda _db, run_ids: loaded.append(run_ids) or dict(saved),
    )
    monkeypatch.setattr(main, "list_saved_networks", lambda _db: [])
    monkeypatch.setattr(main, "_latest_device_reachability_evidence", lambda: [])
    monkeypatch.setattr(
        main, "classify_searchsploit_exposure",
        lambda value, **_kwargs: value,
    )
    monkeypatch.setattr(
        main, "enrich_hunting_with_searchsploit",
        lambda *_args, **_kwargs: pytest.fail("A Hunt read must not launch SearchSploit"),
    )

    result = main.analyze_hunting_network()

    assert loaded == [["a" * 32, "b" * 32, "c" * 32]]
    assert result["searchsploit"] == saved


def database_archive(path, marker: str):
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("exploitdb/searchsploit", "#!/usr/bin/env bash\n" + "#" * 1200)
        archive.writestr(
            "exploitdb/.searchsploit_rc",
            'files_array+=("files_exploits.csv")\npath_array+=("/opt/exploitdb")\n',
        )
        archive.writestr(
            "exploitdb/files_exploits.csv",
            "id,file,description,date,author,type,platform,port\n"
            f"1,exploits/{marker}.txt,{marker},2026-01-01,NCT,remote,linux,80\n",
        )


def test_database_upload_stages_versions_and_supports_rollback(tmp_path, monkeypatch):
    monkeypatch.setenv("ANALYZER_DATA_DIR", str(tmp_path / "data"))
    first_archive = tmp_path / "first.zip"
    second_archive = tmp_path / "second.zip"
    database_archive(first_archive, "first")
    database_archive(second_archive, "second")

    first = install_searchsploit_archive(first_archive, source="uploaded:first.zip")
    second = install_searchsploit_archive(second_archive, source="uploaded:second.zip")

    assert first["available"] is True
    assert second["available"] is True
    assert first["active_version"] != second["active_version"]
    assert len(second["versions"]) == 2
    active_rc = (
        tmp_path / "data" / "searchsploit" / "versions"
        / second["active_version"] / ".searchsploit_rc"
    ).read_text(encoding="utf-8")
    assert "/opt/exploitdb" not in active_rc
    assert second["active_version"] in active_rc

    rolled_back = rollback_searchsploit_database(first["active_version"])

    assert rolled_back["active_version"] == first["active_version"]
    assert sum(1 for item in rolled_back["versions"] if item["active"]) == 1


def test_database_upload_rejects_archive_path_escape(tmp_path, monkeypatch):
    monkeypatch.setenv("ANALYZER_DATA_DIR", str(tmp_path / "data"))
    archive_path = tmp_path / "unsafe.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("../escape", "no")

    with pytest.raises(ValueError, match="unsafe path"):
        install_searchsploit_archive(archive_path, source="uploaded:unsafe.zip")

    assert not (tmp_path / "data" / "searchsploit" / "escape").exists()


def test_searchsploit_parser_accepts_official_singular_json_key(monkeypatch):
    payload = {"RESULTS_EXPLOIT": [{
        "Title": "Example remote candidate",
        "EDB-ID": "54321",
        "Platform": "linux",
        "Type": "remote",
        "Codes": "CVE-2026-54321",
        "Verified": "1",
        "Path": "/opt/exploitdb/exploits/54321.py",
    }]}
    monkeypatch.setattr("app.searchsploit.subprocess.run", lambda *args, **kwargs: (
        subprocess.CompletedProcess(args[0], 0, json.dumps(payload), "")
    ))

    results, warning = _search("/opt/exploitdb/searchsploit", "Example 1.0")

    assert warning is None
    assert results[0]["edb_id"] == "54321"
    assert results[0]["verified"] is True


def test_database_upload_api_activates_valid_offline_package(tmp_path, monkeypatch):
    data_dir = tmp_path / "data"
    monkeypatch.setenv("ANALYZER_DATA_DIR", str(data_dir))
    monkeypatch.setattr("app.main.DATA_DIR", data_dir)
    archive_path = tmp_path / "offline-update.zip"
    database_archive(archive_path, "api-upload")

    with TestClient(app) as client, archive_path.open("rb") as source:
        response = client.post(
            "/api/searchsploit/database/upload",
            files={"file": (archive_path.name, source, "application/zip")},
        )

    assert response.status_code == 200
    assert response.json()["available"] is True
    assert response.json()["source"] == "uploaded:offline-update.zip"
