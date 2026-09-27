from concurrent.futures import ThreadPoolExecutor
import importlib
import sqlite3

import pytest

from app.database import configure_database, connect_database, initialize_once_per_database


CASES = [
    ('achievements', 'init_achievement_storage', lambda m, p: m.list_achievements(p, owner='alice')),
    ('exposure_reports', 'init_exposure_report_storage', lambda m, p: m.get_exposure_report(p, 'missing')),
    ('host_identities', 'init_host_identity_storage', lambda m, p: m.list_host_identities(p)),
    ('identity_overrides', 'init_os_override_storage', lambda m, p: m.list_os_overrides(p)),
    ('investigation_notes', 'init_note_storage', lambda m, p: m.list_notes(p, 'alice')),
    ('network_semantics', 'init_network_semantics_storage', lambda m, p: m.get_external_wan_gateways(p)),
    ('view_preferences', 'init_view_preference_storage', lambda m, p: m.get_view_workspace(p, owner='alice', page='hunt')),
    ('shell_preferences', 'init_shell_preference_storage', lambda m, p: m.get_shell_preference(p, owner='alice')),
]


@pytest.mark.parametrize('module,initializer,read', CASES, ids=[c[0] for c in CASES])
def test_initialized_views_read_during_writer_without_schema_work(tmp_path, monkeypatch, module, initializer, read):
    module = importlib.import_module('app.' + module)
    path = tmp_path / 'analyzer.db'
    configure_database(path)
    getattr(module, initializer)(path)
    expected = read(module, path)
    with connect_database(path) as writer:
        writer.execute('CREATE TABLE writer_probe (value TEXT)')
        writer.commit()
        writer.execute('BEGIN IMMEDIATE')
        writer.execute("INSERT INTO writer_probe VALUES ('pending')")
        def reader(db_path):
            db = connect_database(db_path, read_only=True)
            db.execute('PRAGMA busy_timeout=100')
            forbidden = {sqlite3.SQLITE_CREATE_TABLE, sqlite3.SQLITE_CREATE_INDEX,
                         sqlite3.SQLITE_CREATE_TRIGGER, sqlite3.SQLITE_ALTER_TABLE,
                         sqlite3.SQLITE_INSERT, sqlite3.SQLITE_UPDATE, sqlite3.SQLITE_DELETE}
            db.set_authorizer(lambda action, *args: sqlite3.SQLITE_DENY if action in forbidden else sqlite3.SQLITE_OK)
            return db
        monkeypatch.setattr(module, 'connect_database', reader)
        assert read(module, path) == expected
        assert writer.execute('PRAGMA journal_mode').fetchone()[0] == 'wal'
        assert writer.execute('PRAGMA busy_timeout').fetchone()[0] == 30000
        writer.rollback()


@pytest.mark.parametrize('module,initializer,read', CASES, ids=[c[0] for c in CASES])
def test_module_initializes_replaced_database(tmp_path, module, initializer, read):
    module = importlib.import_module('app.' + module)
    path = tmp_path / 'analyzer.db'
    getattr(module, initializer)(path)
    expected = read(module, path)
    replacement = tmp_path / 'replacement.db'
    with connect_database(replacement) as db:
        db.execute('CREATE TABLE replacement_marker (value TEXT)')
    replacement.replace(path)
    getattr(module, initializer)(path)
    assert read(module, path) == expected


def test_simultaneous_first_access_initializes_once(tmp_path):
    calls = []
    @initialize_once_per_database
    def initialize(path):
        calls.append(path)
        with connect_database(path) as db:
            db.execute('CREATE TABLE initialized (value TEXT)')
    path = tmp_path / 'analyzer.db'
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(initialize, [path] * 16))
    assert calls == [path.resolve()]


def test_initialization_failure_retries_and_caches_only_success(tmp_path):
    attempts = []
    @initialize_once_per_database
    def initialize(path):
        attempts.append(path)
        if len(attempts) == 1:
            raise sqlite3.OperationalError('simulated failure')
        with connect_database(path) as db:
            db.execute('CREATE TABLE initialized (value TEXT)')
    path = tmp_path / 'analyzer.db'
    with pytest.raises(sqlite3.OperationalError):
        initialize(path)
    initialize(path)
    initialize(path)
    assert len(attempts) == 2
