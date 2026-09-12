from __future__ import annotations

from app.searchsploit import enrich_hunting_with_searchsploit


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
    assert result["matched_host_count"] == 1
    assert result["match_count"] == 1
    assert result["matches"][0]["candidates"][0]["edb_id"] == "12345"
