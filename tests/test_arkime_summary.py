from __future__ import annotations

import hashlib
import os
import sqlite3

import pytest
from fastapi.testclient import TestClient

import app.arkime_summary as summary
from app.arkime_summary import (
    ArkimeSummaryConflict,
    ArkimeSummaryError,
    get_arkime_summary_import,
    import_arkime_summary_csv,
    init_arkime_summary_storage,
    list_arkime_summary_imports,
    parse_arkime_summary_csv,
)
from app.database import connect_database
from app.network_scopes import archive_network_scope, create_network_scope


QUERY_START = "2029-12-31T23:00:00+00:00"
QUERY_END = "2030-01-01T01:00:00+00:00"
HEADER = ",".join(summary.SUMMARY_HEADERS)


def csv_bytes(*rows: str) -> bytes:
    return (HEADER + "\n" + "\n".join(rows) + ("\n" if rows else "")).encode()


def network_scope(db, label="Range enclave"):
    return create_network_scope(db, label=label, created_by="scope-admin")


def ingest(db, scope_record, *, content=None, sensor="range summary sensor", **changes):
    parameters = {
        "content": content or csv_bytes(
            "192.0.2.10,198.51.100.20,443,tcp,tls,10,4,14,4096"
        ),
        "original_filename": "communication-summary.csv",
        "media_type": "text/csv",
        "scope_id": scope_record["scope_id"],
        "operator_sensor": sensor,
        "query_start": QUERY_START,
        "query_end": QUERY_END,
        "bounding_mode": "both",
        "query_expression": "vlan == 10",
        "summary_basis": "all_matching_groups",
        "top_n_limit": None,
        "operator_export_assessment": "complete",
        "capture_coverage": "unknown",
        "actor": "analyst",
    }
    parameters.update(changes)
    return import_arkime_summary_csv(db, **parameters)


def table_counts(db):
    names = (
        "artifact_registry", "artifact_observations",
        "arkime_summary_imports", "arkime_summary_receipts",
    )
    with connect_database(db, read_only=True) as connection:
        return {
            name: connection.execute(f"SELECT COUNT(*) FROM {name}").fetchone()[0]
            for name in names
        }


def test_import_retains_exact_source_context_and_immutable_grouped_receipts(tmp_path):
    db = tmp_path / "nct.db"
    scope_record = network_scope(db)
    content = csv_bytes(
        ",2001:db8::20,53,udp,dns,20,0,8,1024",
        "192.0.2.10,198.51.100.20,53,tcp,dns,20,2,,2048",
    )

    result = ingest(db, scope_record, content=content)
    detail = get_arkime_summary_import(db, result["import_id"])

    assert result["sha256"] == hashlib.sha256(content).hexdigest()
    assert result["original_preserved"] is True
    assert result["recorded_export_completeness"] == "complete"
    assert detail["scope"] == {
        "scope_id": scope_record["scope_id"], "label": "Range enclave", "version": 1,
    }
    assert detail["receipts"][0]["source_ip"] is None
    assert detail["receipts"][0]["destination_ip"] == "2001:db8::20"
    assert detail["receipts"][0]["session_count"] == "0"
    assert detail["receipts"][0]["packet_count"] == "8"
    assert detail["receipts"][1]["packet_count"] is None
    assert {row["transport"] for row in detail["receipts"]} == {"tcp", "udp"}
    assert table_counts(db) == {
        "artifact_registry": 1, "artifact_observations": 1,
        "arkime_summary_imports": 1, "arkime_summary_receipts": 2,
    }
    with connect_database(db) as connection, pytest.raises(sqlite3.IntegrityError):
        connection.execute(
            "UPDATE arkime_summary_receipts SET byte_count=1 WHERE import_id=?",
            (result["import_id"],),
        )


def test_api_receipts_preserve_counts_above_browser_safe_integer_range(tmp_path):
    db = tmp_path / "nct.db"
    scope_record = network_scope(db)
    exact = "9007199254740993"
    result = ingest(
        db, scope_record,
        content=csv_bytes(
            f"192.0.2.1,198.51.100.1,443,tcp,tls,10,{exact},{exact},{exact}"
        ),
    )
    receipt = get_arkime_summary_import(db, result["import_id"])["receipts"][0]
    assert receipt["session_count"] == exact
    assert receipt["packet_count"] == exact
    assert receipt["byte_count"] == exact


def test_identical_and_overlapping_files_share_only_exact_storage(tmp_path):
    db = tmp_path / "nct.db"
    scope_record = network_scope(db)
    content = csv_bytes("192.0.2.1,198.51.100.1,443,tcp,tls,10,1,2,3")

    first = ingest(db, scope_record, content=content, sensor="sensor A")
    second = ingest(db, scope_record, content=content, sensor="sensor B")

    assert first["artifact_duplicate"] is False
    assert second["artifact_duplicate"] is True
    assert first["observation_id"] != second["observation_id"]
    assert first["import_id"] != second["import_id"]
    assert table_counts(db) == {
        "artifact_registry": 1, "artifact_observations": 2,
        "arkime_summary_imports": 2, "arkime_summary_receipts": 2,
    }


@pytest.mark.parametrize(
    "content, message",
    [
        (b"", "empty"),
        (b"wrong,header\n1,2\n", "header must be exactly"),
        (csv_bytes("192.0.2.1,not-an-ip,443,tcp,tls,10,1,2,3"), "valid IP"),
        (csv_bytes("192.0.2.1,198.51.100.1,0,tcp,tls,10,1,2,3"), "between 1 and 65535"),
        (csv_bytes("192.0.2.1,198.51.100.1,443,bad,tls,10,1,2,3"), "transport must"),
        (csv_bytes("192.0.2.1,198.51.100.1,443,tcp,tls,4096,1,2,3"), "between 0 and 4095"),
        (csv_bytes("192.0.2.1,198.51.100.1,443,tcp,tls,10,,,"), "at least one count"),
        (csv_bytes("192.0.2.1,198.51.100.1,443,tcp,tls,10,-1,2,3"), "whole number"),
        (csv_bytes(""), "blank"),
    ],
)
def test_parser_rejects_malformed_or_contradictory_rows(content, message):
    with pytest.raises(ArkimeSummaryError, match=message):
        parse_arkime_summary_csv(content)


def test_parser_rejects_duplicate_grouping_but_keeps_protocols_distinct():
    duplicate = csv_bytes(
        "192.0.2.1,198.51.100.1,53,udp,dns,10,1,2,3",
        "192.0.2.1,198.51.100.1,53,udp,dns,10,4,5,6",
    )
    with pytest.raises(ArkimeSummaryError, match="repeats an earlier grouping key"):
        parse_arkime_summary_csv(duplicate)
    parsed = parse_arkime_summary_csv(csv_bytes(
        "192.0.2.1,198.51.100.1,53,udp,dns,10,1,2,3",
        "192.0.2.1,198.51.100.1,53,tcp,dns,10,4,5,6",
    ))
    assert len(parsed["rows"]) == 2


def test_parser_enforces_file_and_row_limits(monkeypatch):
    monkeypatch.setattr(summary, "MAX_ARKIME_SUMMARY_BYTES", 10)
    with pytest.raises(ArkimeSummaryError, match="10 MiB intake limit"):
        parse_arkime_summary_csv(csv_bytes())
    monkeypatch.setattr(summary, "MAX_ARKIME_SUMMARY_BYTES", 10 * 1024 * 1024)
    monkeypatch.setattr(summary, "MAX_ARKIME_SUMMARY_ROWS", 1)
    with pytest.raises(ArkimeSummaryError, match="10,000-row intake limit"):
        parse_arkime_summary_csv(csv_bytes(
            "192.0.2.1,198.51.100.1,53,udp,dns,10,1,2,3",
            "192.0.2.2,198.51.100.1,53,udp,dns,10,1,2,3",
        ))


def test_top_n_and_unknown_basis_cannot_claim_complete(tmp_path):
    db = tmp_path / "nct.db"
    scope_record = network_scope(db)
    with pytest.raises(ArkimeSummaryError, match="cannot be declared complete"):
        ingest(
            db, scope_record, summary_basis="top_n", top_n_limit=100,
            operator_export_assessment="complete",
        )
    with pytest.raises(ArkimeSummaryError, match="cannot be declared complete"):
        ingest(
            db, scope_record, summary_basis="unknown",
            operator_export_assessment="complete",
        )
    top = ingest(
        db, scope_record, summary_basis="top_n", top_n_limit=100,
        operator_export_assessment="unknown",
    )
    assert top["recorded_export_completeness"] == "partial"
    with pytest.raises(ArkimeSummaryError, match="more rows than its top-N limit"):
        ingest(
            db, scope_record,
            content=csv_bytes(
                "192.0.2.1,198.51.100.1,53,udp,dns,10,1,2,3",
                "192.0.2.2,198.51.100.1,53,udp,dns,10,1,2,3",
            ),
            summary_basis="top_n", top_n_limit=1,
            operator_export_assessment="partial",
        )


def test_empty_summary_is_retained_without_claiming_no_traffic(tmp_path):
    db = tmp_path / "nct.db"
    scope_record = network_scope(db)
    result = ingest(
        db, scope_record, content=csv_bytes(), summary_basis="unknown",
        operator_export_assessment="unknown",
    )
    assert result["returned_count"] == 0
    assert result["recorded_export_completeness"] == "unknown"
    assert get_arkime_summary_import(db, result["import_id"])["receipts"] == []


def test_archived_scope_rejects_before_database_publication(tmp_path):
    db = tmp_path / "nct.db"
    scope_record = network_scope(db)
    archive_network_scope(
        db, scope_record["scope_id"], expected_version=1,
        archived_by="admin", reason="Scope retired",
    )
    with pytest.raises(ArkimeSummaryConflict, match="archived"):
        ingest(db, scope_record)
    assert table_counts(db) == {
        "artifact_registry": 0, "artifact_observations": 0,
        "arkime_summary_imports": 0, "arkime_summary_receipts": 0,
    }


def test_receipt_failure_rolls_back_graph_and_keeps_reviewable_orphan(tmp_path):
    db = tmp_path / "nct.db"
    scope_record = network_scope(db)
    init_arkime_summary_storage(db)
    with connect_database(db) as connection:
        connection.execute(
            """CREATE TRIGGER reject_summary_receipt BEFORE INSERT
               ON arkime_summary_receipts
               BEGIN SELECT RAISE(ABORT, 'forced receipt failure'); END"""
        )
    content = csv_bytes("192.0.2.1,198.51.100.1,443,tcp,tls,10,1,2,3")
    with pytest.raises(sqlite3.IntegrityError, match="forced receipt failure"):
        ingest(db, scope_record, content=content)
    assert table_counts(db) == {
        "artifact_registry": 0, "artifact_observations": 0,
        "arkime_summary_imports": 0, "arkime_summary_receipts": 0,
    }
    orphan = summary.canonical_artifact_path(
        summary.artifact_root_for(db), hashlib.sha256(content).hexdigest()
    )
    assert orphan.read_bytes() == content


def test_history_and_receipts_are_bounded_and_revision_safe(tmp_path):
    db = tmp_path / "nct.db"
    scope_record = network_scope(db)
    rows = [
        f"192.0.2.{number % 250 + 1},198.51.100.{number // 250 + 1},{number + 1},tcp,p{number},10,1,2,3"
        for number in range(205)
    ]
    first = ingest(db, scope_record, content=csv_bytes(*rows))
    page = list_arkime_summary_imports(db, limit=1)
    second_page = get_arkime_summary_import(
        db, first["import_id"], limit=100, offset=100,
    )
    assert second_page["receipts"][0]["source_ordinal"] == 100
    assert second_page["receipts"][-1]["source_ordinal"] == 199
    assert second_page["pagination"]["has_more"] is True
    ingest(db, scope_record, sensor="later")
    with pytest.raises(ArkimeSummaryConflict, match="changed while paging"):
        list_arkime_summary_imports(
            db, limit=1, offset=1, revision=page["source_revision"],
        )


def test_read_paths_do_not_initialize_schema(tmp_path, monkeypatch):
    db = tmp_path / "nct.db"
    scope_record = network_scope(db)
    result = ingest(db, scope_record)
    monkeypatch.setattr(
        summary, "init_arkime_summary_storage",
        lambda _: (_ for _ in ()).throw(AssertionError("read path initialized schema")),
    )
    assert list_arkime_summary_imports(db)["pagination"]["total"] == 1
    assert get_arkime_summary_import(db, result["import_id"])["returned_count"] == 1


def test_summary_routes_upload_list_detail_and_verified_download(tmp_path, monkeypatch):
    import app.main as main

    db = tmp_path / "route.db"
    monkeypatch.setattr(main, "DB_PATH", db)
    scope_record = network_scope(db, "Route scope")
    content = csv_bytes("192.0.2.1,198.51.100.1,443,tcp,tls,10,1,2,3")
    data = {
        "scope_id": scope_record["scope_id"], "operator_sensor": "range sensor",
        "query_start": QUERY_START, "query_end": QUERY_END,
        "bounding_mode": "both", "summary_basis": "all_matching_groups",
        "operator_export_assessment": "complete", "capture_coverage": "unknown",
        "query_expression": "vlan == 10",
    }
    with TestClient(main.app) as client:
        template = client.get("/api/arkime/summary-template.csv")
        created = client.post(
            "/api/arkime/summary-imports",
            files={"file": ("summary.csv", content, "text/csv")}, data=data,
        )
        assert created.status_code == 201, created.text
        item = created.json()
        history = client.get("/api/arkime/summary-imports?limit=25&offset=0")
        detail = client.get(f"/api/arkime/summary-imports/{item['import_id']}")
        raw = client.get(item["raw_url"])
    assert template.status_code == history.status_code == detail.status_code == raw.status_code == 200
    assert template.text.startswith(HEADER + "\n")
    assert template.headers["content-disposition"].endswith(
        'filename="nct-arkime-summary-v1.csv"'
    )
    assert history.json()["items"][0]["scope"]["label"] == "Route scope"
    assert detail.json()["receipts"][0]["destination_port"] == 443
    assert detail.json()["receipts"][0]["byte_count"] == "3"
    assert raw.content == content
    assert raw.headers["content-disposition"].endswith('filename="summary.csv"')


def test_summary_upload_requires_analyst_or_administrator_role(tmp_path, monkeypatch):
    import app.main as main

    db = tmp_path / "auth.db"
    monkeypatch.setattr(main, "DB_PATH", db)
    monkeypatch.setattr(main, "auth_enabled", lambda: True)
    identity = {"username": "viewer-a", "display_name": "Viewer", "role": "viewer"}
    monkeypatch.setattr(main, "session_identity", lambda *_args: identity)
    scope_record = network_scope(db)
    data = {
        "scope_id": scope_record["scope_id"], "operator_sensor": "sensor",
        "query_start": QUERY_START, "query_end": QUERY_END,
        "bounding_mode": "both", "summary_basis": "unknown",
        "operator_export_assessment": "unknown", "capture_coverage": "unknown",
    }
    with TestClient(main.app) as client:
        denied = client.post(
            "/api/arkime/summary-imports",
            files={"file": ("summary.csv", csv_bytes(), "text/csv")}, data=data,
        )
        assert denied.status_code == 403
        assert client.get("/api/arkime/summary-imports").status_code == 200
        identity["role"] = "analyst"
        accepted = client.post(
            "/api/arkime/summary-imports",
            files={"file": ("summary.csv", csv_bytes(), "text/csv")}, data=data,
        )
        assert accepted.status_code == 201, accepted.text


def test_raw_route_rejects_changed_and_symlinked_source(tmp_path, monkeypatch):
    import app.main as main

    db = tmp_path / "raw.db"
    monkeypatch.setattr(main, "DB_PATH", db)
    scope_record = network_scope(db)
    result = ingest(db, scope_record)
    canonical = summary.canonical_artifact_path(
        summary.artifact_root_for(db), result["sha256"],
    )
    with TestClient(main.app) as client:
        canonical.write_bytes(b"changed")
        assert client.get(result["raw_url"]).status_code == 409
        canonical.unlink()
        outside = tmp_path / "outside.csv"
        outside.write_bytes(csv_bytes())
        try:
            os.symlink(outside, canonical)
        except (OSError, NotImplementedError) as exc:
            pytest.skip(f"symlink creation unavailable: {exc}")
        assert client.get(result["raw_url"]).status_code == 409
