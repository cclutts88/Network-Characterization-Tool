import sqlite3

import pytest

from app.database import configure_database, connect_database
from app import workspaces


def test_layout_read_uses_no_ddl_during_pending_writer(tmp_path, monkeypatch):
    path = tmp_path / "analyzer.db"
    configure_database(path)
    layout = workspaces.save_layout(path, owner="alice", name="Original", snapshot={})
    writer = connect_database(path)
    writer.execute("BEGIN IMMEDIATE")
    writer.execute("UPDATE analyst_workspace_layouts SET name='Pending'")
    def reader(db_path):
        connection = connect_database(db_path, read_only=True)
        connection.execute("PRAGMA busy_timeout=100")
        def authorize(action, *args):
            return sqlite3.SQLITE_DENY if action in {sqlite3.SQLITE_CREATE_TABLE, sqlite3.SQLITE_CREATE_INDEX, sqlite3.SQLITE_ALTER_TABLE} else sqlite3.SQLITE_OK
        connection.set_authorizer(authorize)
        return connection
    monkeypatch.setattr(workspaces, "connect_database", reader)
    try:
        result = workspaces.list_layouts(path, "alice")
        assert result[0]["layout_id"] == layout["layout_id"]
        assert result[0]["name"] == "Original"
        assert writer.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        assert writer.execute("PRAGMA busy_timeout").fetchone()[0] == 30000
    finally:
        writer.rollback()
        writer.close()


def test_replaced_database_gets_workspace_schema(tmp_path):
    path = tmp_path / "analyzer.db"
    workspaces.save_layout(path, owner="alice", name="Original", snapshot={})
    replacement = tmp_path / "replacement.db"
    with connect_database(replacement) as db:
        db.execute("CREATE TABLE replacement_marker (value TEXT)")
    replacement.replace(path)
    assert workspaces.list_layouts(path, "alice") == []


def test_failed_initialization_can_retry(tmp_path, monkeypatch):
    path = tmp_path / "analyzer.db"
    original = workspaces._create_workspace_schema
    def fail(db_path):
        raise sqlite3.OperationalError("simulated initialization failure")
    monkeypatch.setattr(workspaces, "_create_workspace_schema", fail)
    with pytest.raises(sqlite3.OperationalError):
        workspaces.init_workspace_storage(path)
    monkeypatch.setattr(workspaces, "_create_workspace_schema", original)
    assert workspaces.list_layouts(path, "alice") == []
