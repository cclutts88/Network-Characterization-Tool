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

    def fake_search(command_path: str, query: str):
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
