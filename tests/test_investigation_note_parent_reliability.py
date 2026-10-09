from concurrent.futures import ThreadPoolExecutor
import sqlite3
import threading

import pytest

from app import investigation_notes, workspaces
from app.database import connect_database
from app.investigation_notes import (
    MAX_NOTE_MOVE_ITEMS,
    MAX_NOTE_PARENT_DEPTH,
    NoteConflict,
    init_note_storage,
    list_notes,
    save_note,
)


def _raw_folder_chain(db_path, *, owner="alpha", count: int):
    init_note_storage(db_path)
    parent_id = None
    now = "2026-10-09T12:00:00+00:00"
    ids = []
    with connect_database(db_path) as db:
        for index in range(count):
            note_id = f"folder-{index:04d}"
            db.execute(
                """INSERT INTO analyst_investigation_notes
                   (note_id, owner, parent_id, kind, title, content, context_json,
                    position, version, visibility, shared_page, created_at, updated_at)
                   VALUES (?, ?, ?, 'folder', ?, '', '{}', 0, 1, 'personal', NULL, ?, ?)""",
                (note_id, owner, parent_id, f"Folder {index}", now, now),
            )
            ids.append(note_id)
            parent_id = note_id
    return ids


def _raw_children(db_path, *, owner="alpha", parent_id: str, count: int):
    now = "2026-10-09T12:00:00+00:00"
    with connect_database(db_path) as db:
        db.executemany(
            """INSERT INTO analyst_investigation_notes
               (note_id, owner, parent_id, kind, title, content, context_json,
                position, version, visibility, shared_page, created_at, updated_at)
               VALUES (?, ?, ?, 'note', ?, '', '{}', ?, 1, 'personal', NULL, ?, ?)""",
            [
                (
                    f"{parent_id}-child-{index:05d}",
                    owner,
                    parent_id,
                    f"Child {index}",
                    index,
                    now,
                    now,
                )
                for index in range(count)
            ],
        )


@pytest.mark.parametrize("corruption", ["cycle", "missing", "cross-owner", "non-folder"])
def test_parent_preflight_rejects_corrupt_ancestry(tmp_path, corruption):
    db_path = tmp_path / "analyzer.db"
    root = save_note(db_path, owner="alpha", title="Root", kind="folder")
    parent = save_note(
        db_path,
        owner="alpha",
        title="Parent",
        kind="folder",
        parent_id=root["note_id"],
    )
    with connect_database(db_path) as db:
        if corruption == "cycle":
            db.execute(
                "UPDATE analyst_investigation_notes SET parent_id = ? WHERE note_id = ?",
                (parent["note_id"], root["note_id"]),
            )
        elif corruption == "missing":
            db.execute(
                "UPDATE analyst_investigation_notes SET parent_id = 'missing' WHERE note_id = ?",
                (root["note_id"],),
            )
        elif corruption == "cross-owner":
            foreign_id = "foreign-folder"
            db.execute(
                """INSERT INTO analyst_investigation_notes VALUES
                   (?, 'bravo', NULL, 'folder', 'Foreign', '', '{}', 0, 1,
                    'personal', NULL, ?, ?)""",
                (
                    foreign_id,
                    "2026-10-09T12:00:00+00:00",
                    "2026-10-09T12:00:00+00:00",
                ),
            )
            db.execute(
                "UPDATE analyst_investigation_notes SET parent_id = ? WHERE note_id = ?",
                (foreign_id, root["note_id"]),
            )
        else:
            db.execute(
                "UPDATE analyst_investigation_notes SET kind = 'note' WHERE note_id = ?",
                (root["note_id"],),
            )

    with pytest.raises(ValueError):
        save_note(
            db_path,
            owner="alpha",
            title="Blocked child",
            kind="note",
            parent_id=parent["note_id"],
        )


def test_simultaneous_inverse_moves_cannot_create_cycle(tmp_path, monkeypatch):
    db_path = tmp_path / "analyzer.db"
    first = save_note(db_path, owner="alpha", title="First", kind="folder")
    second = save_note(db_path, owner="alpha", title="Second", kind="folder")
    barrier = threading.Barrier(2)
    original = investigation_notes._stage_parent_rows

    def interleaved_stage(db, rows):
        original(db, rows)
        barrier.wait(timeout=5)

    monkeypatch.setattr(investigation_notes, "_stage_parent_rows", interleaved_stage)

    def move(item, parent):
        try:
            return save_note(
                db_path,
                owner="alpha",
                note_id=item["note_id"],
                expected_version=1,
                parent_id=parent["note_id"],
                title=item["title"],
                kind="folder",
            )["version"]
        except NoteConflict:
            return "conflict"

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda pair: move(*pair), [(first, second), (second, first)]))
    assert sorted(results, key=str) == [2, "conflict"]
    items = {item["note_id"]: item for item in list_notes(db_path, "alpha", "analyze")}
    assert sum(item["parent_id"] is not None for item in items.values()) == 1


@pytest.mark.parametrize("drift", ["delete", "move", "kind"])
def test_parent_drift_after_staging_conflicts_without_partial_save(
    tmp_path, monkeypatch, drift
):
    db_path = tmp_path / "analyzer.db"
    parent = save_note(db_path, owner="alpha", title="Parent", kind="folder")
    other = save_note(db_path, owner="alpha", title="Other", kind="folder")
    target = save_note(db_path, owner="alpha", title="Target", kind="note")
    staged = threading.Event()
    release = threading.Event()
    original = investigation_notes._stage_parent_rows

    def paused_stage(db, rows):
        original(db, rows)
        staged.set()
        assert release.wait(timeout=5)

    monkeypatch.setattr(investigation_notes, "_stage_parent_rows", paused_stage)
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(
            save_note,
            db_path,
            owner="alpha",
            note_id=target["note_id"],
            expected_version=1,
            parent_id=parent["note_id"],
            title="Moved target",
            kind="note",
        )
        assert staged.wait(timeout=5)
        with connect_database(db_path) as db:
            if drift == "delete":
                db.execute(
                    "DELETE FROM analyst_investigation_notes WHERE note_id = ?",
                    (parent["note_id"],),
                )
            elif drift == "move":
                db.execute(
                    "UPDATE analyst_investigation_notes SET parent_id = ? WHERE note_id = ?",
                    (other["note_id"], parent["note_id"]),
                )
            else:
                db.execute(
                    "UPDATE analyst_investigation_notes SET kind = 'note' WHERE note_id = ?",
                    (parent["note_id"],),
                )
        release.set()
        with pytest.raises(NoteConflict):
            pending.result(timeout=5)
    saved = next(
        item for item in list_notes(db_path, "alpha", "analyze") if item["note_id"] == target["note_id"]
    )
    assert saved["title"] == "Target"
    assert saved["parent_id"] is None
    assert saved["version"] == 1


def test_parent_metadata_change_after_staging_does_not_false_conflict(tmp_path, monkeypatch):
    db_path = tmp_path / "analyzer.db"
    parent = save_note(db_path, owner="alpha", title="Parent", kind="folder")
    target = save_note(db_path, owner="alpha", title="Target", kind="note")
    staged = threading.Event()
    release = threading.Event()
    original = investigation_notes._stage_parent_rows

    def paused_stage(db, rows):
        original(db, rows)
        staged.set()
        assert release.wait(timeout=5)

    monkeypatch.setattr(investigation_notes, "_stage_parent_rows", paused_stage)
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(
            save_note,
            db_path,
            owner="alpha",
            note_id=target["note_id"],
            expected_version=1,
            parent_id=parent["note_id"],
            title="Moved target",
            kind="note",
        )
        assert staged.wait(timeout=5)
        with connect_database(db_path) as db:
            db.execute(
                """UPDATE analyst_investigation_notes
                   SET title = 'Renamed parent', version = version + 1
                   WHERE note_id = ?""",
                (parent["note_id"],),
            )
        release.set()
        saved = pending.result(timeout=5)
    assert saved["parent_id"] == parent["note_id"]
    assert saved["title"] == "Moved target"


def test_depth_limit_accepts_boundary_and_rejects_deeper_parent(tmp_path):
    db_path = tmp_path / "analyzer.db"
    folders = _raw_folder_chain(db_path, count=MAX_NOTE_PARENT_DEPTH)
    boundary = save_note(
        db_path,
        owner="alpha",
        title="Boundary item",
        kind="note",
        parent_id=folders[-1],
    )
    assert boundary["parent_id"] == folders[-1]
    too_deep = save_note(
        db_path,
        owner="alpha",
        title="Too deep folder",
        kind="folder",
        parent_id=folders[-1],
    )
    with pytest.raises(ValueError, match="at most"):
        save_note(
            db_path,
            owner="alpha",
            title="Rejected item",
            kind="note",
            parent_id=too_deep["note_id"],
        )


def test_folder_move_applies_depth_limit_to_deepest_descendant(tmp_path):
    allowed_db = tmp_path / "allowed.db"
    allowed_destination = _raw_folder_chain(
        allowed_db, count=MAX_NOTE_PARENT_DEPTH - 1
    )
    allowed_folder = save_note(
        allowed_db, owner="alpha", title="Moved folder", kind="folder"
    )
    allowed_child = save_note(
        allowed_db,
        owner="alpha",
        title="Nested child",
        kind="note",
        parent_id=allowed_folder["note_id"],
    )
    moved = save_note(
        allowed_db,
        owner="alpha",
        note_id=allowed_folder["note_id"],
        expected_version=1,
        parent_id=allowed_destination[-1],
        title="Moved folder",
        kind="folder",
    )
    assert moved["parent_id"] == allowed_destination[-1]
    child = next(
        item
        for item in list_notes(allowed_db, "alpha", "analyze")
        if item["note_id"] == allowed_child["note_id"]
    )
    assert child["parent_id"] == allowed_folder["note_id"]

    rejected_db = tmp_path / "rejected.db"
    rejected_destination = _raw_folder_chain(
        rejected_db, count=MAX_NOTE_PARENT_DEPTH
    )
    rejected_folder = save_note(
        rejected_db, owner="alpha", title="Moved folder", kind="folder"
    )
    save_note(
        rejected_db,
        owner="alpha",
        title="Nested child",
        kind="note",
        parent_id=rejected_folder["note_id"],
    )
    with pytest.raises(ValueError, match="more than"):
        save_note(
            rejected_db,
            owner="alpha",
            note_id=rejected_folder["note_id"],
            expected_version=1,
            parent_id=rejected_destination[-1],
            title="Moved folder",
            kind="folder",
        )
    unchanged = next(
        item
        for item in list_notes(rejected_db, "alpha", "analyze")
        if item["note_id"] == rejected_folder["note_id"]
    )
    assert unchanged["parent_id"] is None
    assert unchanged["version"] == 1


def test_descendant_added_after_move_staging_conflicts(tmp_path, monkeypatch):
    db_path = tmp_path / "analyzer.db"
    destination = _raw_folder_chain(db_path, count=MAX_NOTE_PARENT_DEPTH - 1)
    folder = save_note(db_path, owner="alpha", title="Folder", kind="folder")
    child = save_note(
        db_path,
        owner="alpha",
        title="Child folder",
        kind="folder",
        parent_id=folder["note_id"],
    )
    staged = threading.Event()
    release = threading.Event()
    original = investigation_notes._stage_parent_rows

    def paused_stage(db, rows):
        original(db, rows)
        staged.set()
        assert release.wait(timeout=5)

    monkeypatch.setattr(investigation_notes, "_stage_parent_rows", paused_stage)
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(
            save_note,
            db_path,
            owner="alpha",
            note_id=folder["note_id"],
            expected_version=1,
            parent_id=destination[-1],
            title="Folder",
            kind="folder",
        )
        assert staged.wait(timeout=5)
        now = "2026-10-09T12:00:00+00:00"
        with connect_database(db_path) as db:
            db.execute(
                """INSERT INTO analyst_investigation_notes
                   (note_id, owner, parent_id, kind, title, content, context_json,
                    position, version, visibility, shared_page, created_at, updated_at)
                   VALUES ('late-child', 'alpha', ?, 'note', 'Late child', '', '{}',
                           0, 1, 'personal', NULL, ?, ?)""",
                (child["note_id"], now, now),
            )
        release.set()
        with pytest.raises(NoteConflict):
            pending.result(timeout=5)
    saved = next(
        item for item in list_notes(db_path, "alpha", "analyze") if item["note_id"] == folder["note_id"]
    )
    assert saved["parent_id"] is None
    assert saved["version"] == 1


def test_unrelated_branch_change_does_not_block_folder_move(tmp_path, monkeypatch):
    db_path = tmp_path / "analyzer.db"
    destination = save_note(db_path, owner="alpha", title="Destination", kind="folder")
    folder = save_note(db_path, owner="alpha", title="Folder", kind="folder")
    save_note(
        db_path,
        owner="alpha",
        title="Child",
        kind="note",
        parent_id=folder["note_id"],
    )
    unrelated = save_note(db_path, owner="alpha", title="Unrelated", kind="folder")
    staged = threading.Event()
    release = threading.Event()
    original = investigation_notes._stage_parent_rows

    def paused_stage(db, rows):
        original(db, rows)
        staged.set()
        assert release.wait(timeout=5)

    monkeypatch.setattr(investigation_notes, "_stage_parent_rows", paused_stage)
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(
            save_note,
            db_path,
            owner="alpha",
            note_id=folder["note_id"],
            expected_version=1,
            parent_id=destination["note_id"],
            title="Folder",
            kind="folder",
        )
        assert staged.wait(timeout=5)
        now = "2026-10-09T12:00:00+00:00"
        with connect_database(db_path) as db:
            db.execute(
                """INSERT INTO analyst_investigation_notes
                   (note_id, owner, parent_id, kind, title, content, context_json,
                    position, version, visibility, shared_page, created_at, updated_at)
                   VALUES ('unrelated-child', 'alpha', ?, 'note', 'Unrelated child', '',
                           '{}', 0, 1, 'personal', NULL, ?, ?)""",
                (unrelated["note_id"], now, now),
            )
        release.set()
        moved = pending.result(timeout=5)
    assert moved["parent_id"] == destination["note_id"]


def test_folder_move_item_limit_bounds_writer_work(tmp_path, monkeypatch):
    allowed_db = tmp_path / "allowed-width.db"
    destination = save_note(
        allowed_db, owner="alpha", title="Destination", kind="folder"
    )
    folder = save_note(allowed_db, owner="alpha", title="Folder", kind="folder")
    _raw_children(
        allowed_db,
        parent_id=folder["note_id"],
        count=MAX_NOTE_MOVE_ITEMS - 1,
    )
    unrelated = save_note(
        allowed_db, owner="alpha", title="Large unrelated branch", kind="folder"
    )
    _raw_children(allowed_db, parent_id=unrelated["note_id"], count=50_000)
    original_connect = investigation_notes.connect_database
    measured = {"writer": False, "callbacks": 0}

    def monitored_connect(path):
        db = original_connect(path)

        def trace(sql):
            normalized = sql.strip().upper()
            if normalized == "BEGIN IMMEDIATE":
                measured["writer"] = True
            elif normalized in {"COMMIT", "ROLLBACK"}:
                measured["writer"] = False

        def progress():
            if measured["writer"]:
                measured["callbacks"] += 1
            return 0

        db.set_trace_callback(trace)
        db.set_progress_handler(progress, 100)
        return db

    monkeypatch.setattr(investigation_notes, "connect_database", monitored_connect)
    moved = save_note(
        allowed_db,
        owner="alpha",
        note_id=folder["note_id"],
        expected_version=1,
        parent_id=destination["note_id"],
        title="Folder",
        kind="folder",
    )
    assert moved["parent_id"] == destination["note_id"]
    assert measured["callbacks"] <= 400

    rejected_db = tmp_path / "rejected-width.db"
    rejected_destination = save_note(
        rejected_db, owner="alpha", title="Destination", kind="folder"
    )
    rejected_folder = save_note(
        rejected_db, owner="alpha", title="Folder", kind="folder"
    )
    _raw_children(
        rejected_db,
        parent_id=rejected_folder["note_id"],
        count=MAX_NOTE_MOVE_ITEMS,
    )
    with pytest.raises(ValueError, match="at most 1,000 items"):
        save_note(
            rejected_db,
            owner="alpha",
            note_id=rejected_folder["note_id"],
            expected_version=1,
            parent_id=rejected_destination["note_id"],
            title="Folder",
            kind="folder",
        )
    unchanged = next(
        item
        for item in list_notes(rejected_db, "alpha", "analyze")
        if item["note_id"] == rejected_folder["note_id"]
    )
    assert unchanged["parent_id"] is None
    assert unchanged["version"] == 1


def test_added_child_plan_uses_parent_index_without_note_table_scan(tmp_path):
    db_path = tmp_path / "analyzer.db"
    folder = save_note(db_path, owner="alpha", title="Folder", kind="folder")
    _raw_children(db_path, parent_id=folder["note_id"], count=10)
    with connect_database(db_path) as db:
        db.row_factory = sqlite3.Row
        target = investigation_notes._read_save_target(
            db, owner="alpha", note_id=folder["note_id"]
        )
        descendants = investigation_notes._read_descendant_snapshot(
            db, owner="alpha", note_id=folder["note_id"]
        )
        investigation_notes._stage_save_target(db, target, descendants)
        plan = db.execute(
            "EXPLAIN QUERY PLAN "
            + investigation_notes._unstaged_child_sql("nct_note_move_branch")
        ).fetchall()
    details = [str(row[3]) for row in plan]
    assert any(
        "SEARCH child USING INDEX analyst_notes_parent" in detail
        or "SEARCH child USING COVERING INDEX analyst_notes_parent" in detail
        for detail in details
    )
    assert not any("SCAN child" in detail for detail in details)


def test_many_children_added_after_staging_conflict_with_bounded_lock_work(
    tmp_path, monkeypatch
):
    db_path = tmp_path / "analyzer.db"
    destination = save_note(
        db_path, owner="alpha", title="Destination", kind="folder"
    )
    folder = save_note(db_path, owner="alpha", title="Folder", kind="folder")
    staged = threading.Event()
    release = threading.Event()
    original_stage = investigation_notes._stage_parent_rows
    original_connect = investigation_notes.connect_database
    measured = {"writer": False, "callbacks": 0}

    def monitored_connect(path):
        db = original_connect(path)

        def trace(sql):
            normalized = sql.strip().upper()
            if normalized == "BEGIN IMMEDIATE":
                measured["writer"] = True
            elif normalized in {"COMMIT", "ROLLBACK"}:
                measured["writer"] = False

        def progress():
            if measured["writer"]:
                measured["callbacks"] += 1
            return 0

        db.set_trace_callback(trace)
        db.set_progress_handler(progress, 100)
        return db

    def paused_stage(db, rows):
        original_stage(db, rows)
        staged.set()
        assert release.wait(timeout=10)

    monkeypatch.setattr(investigation_notes, "connect_database", monitored_connect)
    monkeypatch.setattr(investigation_notes, "_stage_parent_rows", paused_stage)
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(
            save_note,
            db_path,
            owner="alpha",
            note_id=folder["note_id"],
            expected_version=1,
            parent_id=destination["note_id"],
            title="Folder",
            kind="folder",
        )
        assert staged.wait(timeout=5)
        _raw_children(db_path, parent_id=folder["note_id"], count=50_000)
        release.set()
        with pytest.raises(NoteConflict):
            pending.result(timeout=10)
    assert measured["callbacks"] <= 20
    saved = next(
        item for item in list_notes(db_path, "alpha", "analyze") if item["note_id"] == folder["note_id"]
    )
    assert saved["parent_id"] is None
    assert saved["version"] == 1


def test_deep_parent_walk_uses_bounded_writer_lock_statements(tmp_path, monkeypatch):
    db_path = tmp_path / "analyzer.db"
    folders = _raw_folder_chain(db_path, count=100)
    statements = []
    original_connect = investigation_notes.connect_database

    def traced_connect(path):
        db = original_connect(path)
        active = {"writer": False}

        def trace(sql):
            normalized = sql.strip().upper()
            if normalized == "BEGIN IMMEDIATE":
                active["writer"] = True
            elif active["writer"]:
                statements.append(normalized)
                if normalized in {"COMMIT", "ROLLBACK"}:
                    active["writer"] = False

        db.set_trace_callback(trace)
        return db

    monkeypatch.setattr(investigation_notes, "connect_database", traced_connect)
    save_note(
        db_path,
        owner="alpha",
        title="Deep child",
        kind="note",
        parent_id=folders[-1],
    )
    assert len(statements) <= 12
    assert sum("WITH RECURSIVE ANCESTORS" in sql for sql in statements) == 0


def test_deep_preflight_does_not_block_unrelated_workspace_writer(tmp_path, monkeypatch):
    db_path = tmp_path / "analyzer.db"
    folders = _raw_folder_chain(db_path, count=100)
    inspected = threading.Event()
    release = threading.Event()
    original = investigation_notes._read_parent_snapshot

    def paused_read(db, **kwargs):
        rows = original(db, **kwargs)
        inspected.set()
        assert release.wait(timeout=5)
        return rows

    monkeypatch.setattr(investigation_notes, "_read_parent_snapshot", paused_read)
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(
            save_note,
            db_path,
            owner="alpha",
            title="Deep child",
            kind="note",
            parent_id=folders[-1],
        )
        assert inspected.wait(timeout=5)
        layout = workspaces.save_layout(
            db_path, owner="alpha", name="Concurrent layout", snapshot={}
        )
        assert layout["version"] == 1
        release.set()
        assert pending.result(timeout=5)["parent_id"] == folders[-1]


def test_nonempty_folder_conversion_and_audit_failure_roll_back(tmp_path):
    db_path = tmp_path / "analyzer.db"
    folder = save_note(db_path, owner="alpha", title="Folder", kind="folder")
    save_note(
        db_path,
        owner="alpha",
        title="Child",
        kind="note",
        parent_id=folder["note_id"],
    )
    destination = save_note(
        db_path, owner="alpha", title="Destination", kind="folder"
    )
    with pytest.raises(ValueError, match="items inside"):
        save_note(
            db_path,
            owner="alpha",
            note_id=folder["note_id"],
            expected_version=1,
            title="Folder",
            kind="note",
        )
    with connect_database(db_path) as db:
        db.execute(
            """CREATE TRIGGER reject_note_audit BEFORE INSERT
               ON analyst_investigation_note_audit
               BEGIN SELECT RAISE(ABORT, 'simulated audit failure'); END"""
        )
    with pytest.raises(sqlite3.IntegrityError):
        save_note(
            db_path,
            owner="alpha",
            note_id=folder["note_id"],
            expected_version=1,
            parent_id=destination["note_id"],
            title="Renamed folder",
            kind="folder",
        )
    saved = next(
        item for item in list_notes(db_path, "alpha", "analyze") if item["note_id"] == folder["note_id"]
    )
    assert saved["title"] == "Folder"
    assert saved["kind"] == "folder"
    assert saved["parent_id"] is None
    assert saved["version"] == 1
    with connect_database(db_path) as db:
        db.execute("DROP TRIGGER reject_note_audit")
        db.execute("BEGIN IMMEDIATE")
        db.rollback()


def test_folder_conversion_check_uses_parent_index_with_many_unrelated_notes(tmp_path):
    db_path = tmp_path / "analyzer.db"
    folder = save_note(db_path, owner="alpha", title="Empty folder", kind="folder")
    now = "2026-10-09T12:00:00+00:00"
    with connect_database(db_path) as db:
        db.executemany(
            """INSERT INTO analyst_investigation_notes
               (note_id, owner, parent_id, kind, title, content, context_json,
                position, version, visibility, shared_page, created_at, updated_at)
               VALUES (?, 'alpha', NULL, 'note', ?, '', '{}', ?, 1,
                       'personal', NULL, ?, ?)""",
            [
                (f"unrelated-{index:05d}", f"Unrelated {index}", index, now, now)
                for index in range(5_000)
            ],
        )
        plan = db.execute(
            """EXPLAIN QUERY PLAN SELECT 1 FROM analyst_investigation_notes
               WHERE parent_id = ? LIMIT 1""",
            (folder["note_id"],),
        ).fetchall()
        assert any(
            "SEARCH analyst_investigation_notes USING COVERING INDEX analyst_notes_parent"
            in row[3]
            for row in plan
        )
        assert not any("SCAN analyst_investigation_notes" in row[3] for row in plan)
    converted = save_note(
        db_path,
        owner="alpha",
        note_id=folder["note_id"],
        expected_version=1,
        title="Converted note",
        kind="note",
    )
    assert converted["kind"] == "note"
