from concurrent.futures import ThreadPoolExecutor
import sqlite3
import threading

import pytest

from app import workspaces, investigation_notes, view_preferences
from app.database import DatabaseConnection, configure_database


@pytest.mark.parametrize('kind', ['layout', 'note', 'view', 'preset'])
def test_two_sessions_cannot_silently_replace_the_same_version(tmp_path, monkeypatch, kind):
    path = tmp_path / 'analyzer.db'
    configure_database(path)
    if kind == 'layout':
        module = workspaces
        item = module.save_layout(path, owner='alice', name='original', snapshot={})
        conflict = module.WorkspaceConflict
        def save(name):
            return module.save_layout(path, owner='alice', name=name, snapshot={}, layout_id=item['layout_id'], expected_version=1)
    elif kind == 'note':
        module = investigation_notes
        item = module.save_note(path, owner='alice', title='original', kind='note')
        conflict = module.NoteConflict
        def save(name):
            return module.save_note(path, owner='alice', title=name, kind='note', note_id=item['note_id'], expected_version=1)
    elif kind == 'view':
        module = view_preferences
        module.save_view_preference(path, owner='alice', page='hunt', snapshot={}, expected_version=0)
        conflict = module.ViewPreferenceConflict
        def save(name):
            return module.save_view_preference(path, owner='alice', page='hunt', snapshot={'name':name}, expected_version=1)
    else:
        module = view_preferences
        item = module.save_filter_preset(path, owner='alice', page='hunt', name='original', snapshot={})
        conflict = module.ViewPreferenceConflict
        def save(name):
            return module.save_filter_preset(path, owner='alice', page='hunt', name=name, snapshot={}, preset_id=item['preset_id'], expected_version=1)

    reads = threading.Barrier(2)
    starts = threading.Barrier(2)
    class BufferedRow:
        def __init__(self, row):
            self.row = row
        def fetchone(self):
            return self.row
    class InterleavedConnection(DatabaseConnection):
        def execute(self, sql, parameters=()):
            cursor = super().execute(sql, parameters)
            # Force both unprotected readers to see the old value before either
            # writes. A transaction that already owns the write slot cannot be
            # interleaved this way and must not wait for the blocked peer.
            if sql.startswith('SELECT * FROM analyst_') and not self.in_transaction:
                row = cursor.fetchone()
                cursor.close()
                reads.wait(timeout=5)
                return BufferedRow(row)
            return cursor
    def connect(db_path):
        return sqlite3.connect(db_path, timeout=5, factory=InterleavedConnection)
    monkeypatch.setattr(module, 'connect_database', connect)
    def attempt(name):
        starts.wait(timeout=5)
        try:
            return save(name)['version']
        except conflict:
            return 'conflict'
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(attempt, ['first', 'second']))
    assert sorted(results, key=str) == [2, 'conflict']
    table = {'layout': 'analyst_workspace_layouts', 'note': 'analyst_investigation_notes',
             'view': 'analyst_view_preferences', 'preset': 'analyst_filter_presets'}[kind]
    with DatabaseConnection(path) as db:
        assert db.execute(f'SELECT version FROM {table}').fetchall() == [(2,)]
        if kind in {'layout', 'note'}:
            audit = 'analyst_workspace_layout_audit' if kind == 'layout' else 'analyst_investigation_note_audit'
            assert db.execute(f'SELECT COUNT(*) FROM {audit}').fetchone()[0] == 2


def test_failed_audit_rolls_back_layout_change(tmp_path):
    path = tmp_path / 'analyzer.db'
    configure_database(path)
    item = workspaces.save_layout(path, owner='alice', name='original', snapshot={})
    with DatabaseConnection(path) as db:
        db.execute("CREATE TRIGGER reject_audit BEFORE INSERT ON analyst_workspace_layout_audit BEGIN SELECT RAISE(ABORT, 'simulated audit failure'); END")
    with pytest.raises(sqlite3.IntegrityError):
        workspaces.save_layout(path, owner='alice', name='replacement', snapshot={}, layout_id=item['layout_id'], expected_version=1)
    assert workspaces.list_layouts(path, 'alice')[0]['name'] == 'original'
    assert workspaces.list_layouts(path, 'alice')[0]['version'] == 1
