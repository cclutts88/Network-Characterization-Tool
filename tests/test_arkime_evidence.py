from __future__ import annotations

import hashlib
import json
import os
import sqlite3

import pytest
from fastapi.testclient import TestClient

import app.arkime_evidence as arkime
from app.arkime_evidence import (
    ArkimeEvidenceConflict,
    ArkimeEvidenceError,
    get_arkime_import,
    import_arkime_sessions_json,
    init_arkime_evidence_storage,
    list_arkime_imports,
    parse_arkime_sessions_json,
)
from app.database import connect_database
from app.network_scopes import archive_network_scope, create_network_scope


QUERY_START = "2029-12-31T23:00:00+00:00"
QUERY_END = "2030-01-01T01:00:00+00:00"


def session_row(*, session_id="session-1", source="192.0.2.10", destination="198.51.100.20"):
    return {
        "id": session_id,
        "rootId": f"root-{session_id}",
        "node": "arkime-range-sensor",
        "firstPacket": 1893456000000,
        "lastPacket": 1893456060000,
        "source.ip": source,
        "source.port": 51000,
        "destination.ip": destination,
        "destination.port": 443,
        "network.transport": "tcp",
        "network.packets": 14,
        "network.bytes": 4096,
        "protocol": ["tls", "https"],
        "vlan": [10],
    }


def export_bytes(rows=None, *, filtered=None, total=None):
    rows = [session_row()] if rows is None else rows
    body = {"data": rows}
    if filtered is not None:
        body["recordsFiltered"] = filtered
    if total is not None:
        body["recordsTotal"] = total
    return json.dumps(body, separators=(",", ":")).encode()


def scope(db, label="Range enclave"):
    return create_network_scope(db, label=label, created_by="scope-admin")


def ingest(
    db, destination, *, content=None, sensor="range observation point",
    operator_assessment="complete",
):
    return import_arkime_sessions_json(
        db,
        content=content or export_bytes(filtered=1, total=100),
        original_filename="sessions.json",
        media_type="application/json",
        scope_id=destination["scope_id"],
        operator_sensor=sensor,
        query_start=QUERY_START,
        query_end=QUERY_END,
        bounding_mode="both",
        operator_export_assessment=operator_assessment,
        capture_coverage="unknown",
        query_expression="vlan == 10",
        actor="analyst",
    )


def table_counts(db):
    names = (
        "artifact_registry", "artifact_observations",
        "arkime_imports", "arkime_session_receipts",
    )
    with connect_database(db, read_only=True) as connection:
        return {
            name: connection.execute(f"SELECT COUNT(*) FROM {name}").fetchone()[0]
            for name in names
        }


def test_import_retains_exact_source_scope_and_source_identity(tmp_path):
    db = tmp_path / "nct.db"
    destination = scope(db)

    result = ingest(db, destination)
    detail = get_arkime_import(db, result["import_id"])

    assert result["calculated_export_completeness"] == "complete"
    assert result["capture_coverage"] == "unknown"
    assert result["timestamp_unit"] == "milliseconds"
    assert result["original_preserved"] is True
    assert detail["scope"] == {
        "scope_id": destination["scope_id"],
        "label": "Range enclave",
        "version": 1,
    }
    assert detail["operator_sensor"] == "range observation point"
    assert detail["sessions"][0]["source_node"] == "arkime-range-sensor"
    assert detail["sessions"][0]["context"]["rootId"] == "root-session-1"
    assert detail["sessions"][0]["vlans"] == [10]
    assert table_counts(db) == {
        "artifact_registry": 1,
        "artifact_observations": 1,
        "arkime_imports": 1,
        "arkime_session_receipts": 1,
    }
    with connect_database(db) as connection, pytest.raises(sqlite3.IntegrityError):
        connection.execute(
            "UPDATE arkime_session_receipts SET source_ip = '192.0.2.99'"
        )


def test_identical_bytes_share_storage_but_keep_separate_encounters(tmp_path):
    db = tmp_path / "nct.db"
    destination = scope(db)
    content = export_bytes(filtered=1, total=1)

    first = ingest(db, destination, content=content, sensor="sensor A")
    second = ingest(db, destination, content=content, sensor="sensor B")

    assert first["sha256"] == second["sha256"] == hashlib.sha256(content).hexdigest()
    assert first["artifact_duplicate"] is False
    assert second["artifact_duplicate"] is True
    assert first["observation_id"] != second["observation_id"]
    assert first["import_id"] != second["import_id"]
    assert table_counts(db) == {
        "artifact_registry": 1,
        "artifact_observations": 2,
        "arkime_imports": 2,
        "arkime_session_receipts": 2,
    }


def test_partial_unknown_empty_and_overlapping_exports_remain_separate(tmp_path):
    db = tmp_path / "nct.db"
    destination = scope(db)
    partial = ingest(
        db, destination,
        content=export_bytes(filtered=4, total=20), sensor="sensor A",
        operator_assessment="partial",
    )
    unknown = ingest(
        db, destination,
        content=export_bytes([session_row(session_id="session-2")]), sensor="sensor A",
    )
    empty = ingest(
        db, destination,
        content=export_bytes([], filtered=0, total=20), sensor="sensor A",
    )

    assert partial["calculated_export_completeness"] == "partial"
    assert unknown["calculated_export_completeness"] == "unknown"
    assert empty["calculated_export_completeness"] == "complete"
    assert empty["timestamp_unit"] == "none"
    assert empty["returned_count"] == 0
    assert len({partial["import_id"], unknown["import_id"], empty["import_id"]}) == 3


@pytest.mark.parametrize(
    "content, message",
    [
        (b'{"data":[],"data":[]}', "Duplicate JSON key"),
        (b'{"data":[],"recordsFiltered":NaN}', "Non-finite"),
        (json.dumps({"hits": {"hits": []}}).encode(), "Unsupported Arkime export shape"),
        (
            export_bytes([
                {**session_row(), "source": {"ip": "192.0.2.99"}},
            ], filtered=1, total=1),
            "Conflicting flat and nested values",
        ),
        (
            export_bytes([
                {**session_row(), "srcIp": "192.0.2.99"},
            ], filtered=1, total=1),
            "Conflicting aliases",
        ),
        (export_bytes(filtered=0, total=1), "recordsFiltered is smaller"),
        (export_bytes(filtered=2, total=1), "recordsTotal is smaller"),
    ],
)
def test_ambiguous_or_contradictory_exports_fail_closed(content, message):
    with pytest.raises(ArkimeEvidenceError, match=message):
        parse_arkime_sessions_json(
            content, query_start=QUERY_START, query_end=QUERY_END,
            bounding_mode="both",
        )


@pytest.mark.parametrize(
    "field,value,message",
    [
        ("ipProtocol", -1, "between 0 and 255"),
        ("ipProtocol", 256, "between 0 and 255"),
        ("node", {"name": "sensor"}, "source node must be text"),
        ("id", ["session"], "session ID must be text"),
        ("rootId", {"id": "root"}, "root session ID must be text"),
    ],
)
def test_source_identifiers_and_protocol_domains_reject_malformed_values(field, value, message):
    row = session_row()
    if field == "ipProtocol":
        row.pop("network.transport")
    row[field] = value
    with pytest.raises(ArkimeEvidenceError, match=message):
        parse_arkime_sessions_json(
            export_bytes([row], filtered=1, total=1),
            query_start=QUERY_START, query_end=QUERY_END, bounding_mode="both",
        )


def test_deep_json_returns_a_controlled_validation_error():
    content = b'{"data":' + b"[" * 1200 + b"]" * 1200 + b"}"
    with pytest.raises(ArkimeEvidenceError, match="nested too deeply"):
        parse_arkime_sessions_json(
            content, query_start=QUERY_START, query_end=QUERY_END, bounding_mode="both",
        )


def test_unknown_protocol_and_ports_stay_unknown():
    row = session_row()
    for key in ("source.port", "destination.port", "network.transport", "protocol"):
        row.pop(key)
    parsed = parse_arkime_sessions_json(
        export_bytes([row], filtered=1, total=1),
        query_start=QUERY_START, query_end=QUERY_END, bounding_mode="both",
    )
    item = parsed["sessions"][0]
    assert item["source_port"] is None
    assert item["destination_port"] is None
    assert item["transport"] is None
    assert item["applications"] == []


def test_equivalent_numeric_and_text_transport_aliases_are_accepted():
    row = session_row()
    row["ipProtocol"] = 6
    parsed = parse_arkime_sessions_json(
        export_bytes([row], filtered=1, total=1),
        query_start=QUERY_START, query_end=QUERY_END, bounding_mode="both",
    )
    assert parsed["sessions"][0]["transport"] == "tcp"


def test_limits_and_declared_time_boundary_are_enforced(monkeypatch):
    monkeypatch.setattr(arkime, "MAX_ARKIME_JSON_BYTES", 10)
    with pytest.raises(ArkimeEvidenceError, match="10 MiB intake limit"):
        parse_arkime_sessions_json(
            b"{" + b" " * 20,
            query_start=QUERY_START, query_end=QUERY_END, bounding_mode="both",
        )
    monkeypatch.setattr(arkime, "MAX_ARKIME_JSON_BYTES", 10 * 1024 * 1024)
    monkeypatch.setattr(arkime, "MAX_ARKIME_SESSIONS", 1)
    with pytest.raises(ArkimeEvidenceError, match="10,000-session"):
        parse_arkime_sessions_json(
            export_bytes([session_row(), session_row(session_id="two")]),
            query_start=QUERY_START, query_end=QUERY_END, bounding_mode="both",
        )
    outside = session_row()
    outside["firstPacket"] = outside["lastPacket"] = 1893542400000
    with pytest.raises(ArkimeEvidenceError, match="declared both query window"):
        parse_arkime_sessions_json(
            export_bytes([outside], filtered=1, total=1),
            query_start=QUERY_START, query_end=QUERY_END, bounding_mode="both",
        )
    with pytest.raises(ArkimeEvidenceError, match="Database-time"):
        parse_arkime_sessions_json(
            export_bytes([], filtered=0, total=0),
            query_start=QUERY_START, query_end=QUERY_END, bounding_mode="database",
        )


def test_archived_scope_rejects_import_before_artifact_publication(tmp_path):
    db = tmp_path / "nct.db"
    destination = scope(db)
    archive_network_scope(
        db, destination["scope_id"], expected_version=1,
        archived_by="admin", reason="Scope retired",
    )

    with pytest.raises(ArkimeEvidenceConflict, match="archived"):
        ingest(db, destination)

    assert table_counts(db) == {
        "artifact_registry": 0,
        "artifact_observations": 0,
        "arkime_imports": 0,
        "arkime_session_receipts": 0,
    }


def test_receipt_failure_rolls_back_database_graph_and_leaves_reviewable_orphan(tmp_path):
    db = tmp_path / "nct.db"
    destination = scope(db)
    init_arkime_evidence_storage(db)
    with connect_database(db) as connection:
        connection.execute(
            """CREATE TRIGGER reject_arkime_receipt BEFORE INSERT
               ON arkime_session_receipts
               BEGIN SELECT RAISE(ABORT, 'forced receipt failure'); END"""
        )
    content = export_bytes(filtered=1, total=1)

    with pytest.raises(sqlite3.IntegrityError, match="forced receipt failure"):
        ingest(db, destination, content=content)

    assert table_counts(db) == {
        "artifact_registry": 0,
        "artifact_observations": 0,
        "arkime_imports": 0,
        "arkime_session_receipts": 0,
    }
    orphan = arkime.canonical_artifact_path(
        arkime.artifact_root_for(db), hashlib.sha256(content).hexdigest()
    )
    assert orphan.read_bytes() == content


def test_history_is_bounded_and_rejects_stale_page_revision(tmp_path):
    db = tmp_path / "nct.db"
    destination = scope(db)
    first = ingest(db, destination, content=export_bytes(filtered=1, total=1))
    page = list_arkime_imports(db, limit=1)
    assert page["pagination"] == {"limit": 1, "offset": 0, "total": 1, "has_more": False}
    assert page["items"][0]["import_id"] == first["import_id"]

    ingest(
        db, destination,
        content=export_bytes([session_row(session_id="new")], filtered=1, total=1),
    )
    with pytest.raises(ArkimeEvidenceConflict, match="changed while paging"):
        list_arkime_imports(db, limit=1, offset=1, revision=page["source_revision"])


def test_import_detail_can_page_through_every_session_receipt(tmp_path):
    db = tmp_path / "nct.db"
    destination = scope(db)
    rows = [session_row(session_id=f"session-{number}") for number in range(205)]
    result = ingest(
        db, destination, content=export_bytes(rows, filtered=205, total=205),
    )

    second = get_arkime_import(db, result["import_id"], limit=100, offset=100)
    final = get_arkime_import(db, result["import_id"], limit=100, offset=200)

    assert second["sessions"][0]["source_ordinal"] == 100
    assert second["sessions"][-1]["source_ordinal"] == 199
    assert second["pagination"]["has_more"] is True
    assert final["sessions"][0]["source_ordinal"] == 200
    assert final["sessions"][-1]["source_ordinal"] == 204
    assert final["pagination"] == {
        "limit": 100, "offset": 200, "total": 205, "has_more": False,
    }


def test_history_count_revision_and_rows_share_one_read_snapshot(tmp_path, monkeypatch):
    db = tmp_path / "nct.db"
    destination = scope(db)
    first = ingest(db, destination, content=export_bytes(filtered=1, total=1))
    original_connect = arkime.connect_database
    inserted = False

    class InterleavingConnection:
        def __init__(self, connection):
            object.__setattr__(self, "connection", connection)

        def __getattr__(self, name):
            return getattr(self.connection, name)

        def __setattr__(self, name, value):
            setattr(self.connection, name, value)

        def __enter__(self):
            self.connection.__enter__()
            return self

        def __exit__(self, *args):
            return self.connection.__exit__(*args)

        def execute(self, sql, parameters=()):
            nonlocal inserted
            result = self.connection.execute(sql, parameters)
            if not inserted and sql.startswith("SELECT COUNT(*) FROM arkime_imports"):
                inserted = True
                ingest(
                    db, destination,
                    content=export_bytes(
                        [session_row(session_id="later")], filtered=1, total=1,
                    ),
                )
            return result

    def interleaving_connect(path, *, read_only=False, **kwargs):
        connection = original_connect(path, read_only=read_only, **kwargs)
        return InterleavingConnection(connection) if read_only else connection

    monkeypatch.setattr(arkime, "connect_database", interleaving_connect)
    page = list_arkime_imports(db, limit=100)

    assert page["pagination"]["total"] == 1
    assert [item["import_id"] for item in page["items"]] == [first["import_id"]]


def test_history_reads_do_not_run_schema_initialization(tmp_path, monkeypatch):
    db = tmp_path / "nct.db"
    destination = scope(db)
    result = ingest(db, destination)

    def unexpected_write(_):
        raise AssertionError("a read path attempted schema initialization")

    monkeypatch.setattr(arkime, "init_arkime_evidence_storage", unexpected_write)
    assert list_arkime_imports(db)["pagination"]["total"] == 1
    assert get_arkime_import(db, result["import_id"])["returned_count"] == 1


def test_manual_arkime_routes_upload_list_detail_and_download(tmp_path, monkeypatch):
    import app.main as main

    db = tmp_path / "route.db"
    monkeypatch.setattr(main, "DB_PATH", db)
    destination = scope(db, "Route scope")
    content = export_bytes(filtered=1, total=1)

    with TestClient(main.app) as client:
        page = client.get("/arkime")
        created = client.post(
            "/api/arkime/imports",
            files={"file": ("range-sessions.json", content, "application/json")},
            data={
                "scope_id": destination["scope_id"],
                "operator_sensor": "range sensor",
                "query_start": QUERY_START,
                "query_end": QUERY_END,
                "bounding_mode": "both",
                "operator_export_assessment": "complete",
                "capture_coverage": "unknown",
                "query_expression": "vlan == 10",
            },
        )
        assert created.status_code == 201, created.text
        item = created.json()
        history = client.get("/api/arkime/imports?limit=25&offset=0")
        detail = client.get(f"/api/arkime/imports/{item['import_id']}?limit=25&offset=0")
        raw = client.get(item["raw_url"])

    assert page.status_code == 200
    assert "Automatic read-only pulls" in page.text
    assert "Import Sessions JSON" in page.text
    assert "Query-result completeness and capture coverage are separate" in page.text
    assert history.status_code == detail.status_code == raw.status_code == 200
    assert history.json()["items"][0]["scope"]["label"] == "Route scope"
    assert detail.json()["sessions"][0]["session_id"] == "session-1"
    assert raw.content == content
    assert raw.headers["content-disposition"].endswith('filename="range-sessions.json"')


def test_raw_route_rejects_changed_or_symlinked_canonical_source(tmp_path, monkeypatch):
    import app.main as main

    db = tmp_path / "raw.db"
    monkeypatch.setattr(main, "DB_PATH", db)
    destination = scope(db, "Raw route scope")
    result = ingest(db, destination, content=export_bytes(filtered=1, total=1))
    canonical = arkime.canonical_artifact_path(
        arkime.artifact_root_for(db), result["sha256"],
    )

    with TestClient(main.app) as client:
        canonical.write_bytes(b"changed content")
        changed = client.get(result["raw_url"])
        assert changed.status_code == 409
        assert changed.content != b"changed content"

        canonical.unlink()
        outside = tmp_path / "outside.json"
        outside.write_bytes(export_bytes(filtered=1, total=1))
        try:
            os.symlink(outside, canonical)
        except (OSError, NotImplementedError) as exc:
            pytest.skip(f"symlink creation is unavailable: {exc}")
        linked = client.get(result["raw_url"])
        assert linked.status_code == 409
        assert linked.content != outside.read_bytes()


def test_raw_route_rejects_symlinked_artifact_parent(tmp_path, monkeypatch):
    import app.main as main

    db = tmp_path / "parent.db"
    monkeypatch.setattr(main, "DB_PATH", db)
    destination = scope(db, "Parent route scope")
    result = ingest(db, destination, content=export_bytes(filtered=1, total=1))
    shard = arkime.artifact_root_for(db) / result["sha256"][:2]
    moved = tmp_path / "moved-shard"
    shard.rename(moved)
    try:
        os.symlink(moved, shard, target_is_directory=True)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"directory symlink creation is unavailable: {exc}")

    with TestClient(main.app) as client:
        response = client.get(result["raw_url"])
    assert response.status_code == 409
    assert response.content != (moved / result["sha256"]).read_bytes()


def test_manual_arkime_routes_require_a_session_when_auth_is_enabled(tmp_path, monkeypatch):
    import app.main as main

    monkeypatch.setattr(main, "DB_PATH", tmp_path / "auth.db")
    monkeypatch.setattr(main, "auth_enabled", lambda: True)
    monkeypatch.setattr(main, "session_identity", lambda *args: None)

    with TestClient(main.app, follow_redirects=False) as client:
        page = client.get("/arkime")
        assert page.status_code == 303
        assert page.headers["location"].startswith("/login?next=/arkime")
        assert client.get("/api/arkime/imports").status_code == 401
        assert client.get("/api/arkime/imports/example/raw").status_code == 401
