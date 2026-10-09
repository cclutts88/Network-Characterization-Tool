from __future__ import annotations

import sqlite3

import pytest

from app import investigation_notes
from app.database import connect_database
from app.investigation_notes import (
    NoteConflict,
    delete_note,
    init_note_storage,
    list_notes,
    preview_note_branch,
    save_note,
    share_note,
)


def _tree(db_path):
    root = save_note(db_path, owner="alpha", title="Case", kind="folder")
    child = save_note(
        db_path,
        owner="alpha",
        parent_id=root["note_id"],
        title="Finding",
        kind="note",
        content="Initial",
    )
    return root, child


def test_branch_preview_binds_descendant_versions_and_visible_counts(tmp_path):
    db_path = tmp_path / "analyzer.db"
    root, child = _tree(db_path)
    preview = preview_note_branch(db_path, owner="alpha", note_id=root["note_id"])

    assert preview["path"] == ["Case"]
    assert preview["items_total"] == 2
    assert preview["folder_count"] == 1
    assert preview["note_count"] == 1
    assert preview["shared_items"] == 0
    assert len(preview["branch_revision"]) == 64

    save_note(
        db_path,
        owner="alpha",
        note_id=child["note_id"],
        expected_version=1,
        parent_id=root["note_id"],
        title="Finding",
        kind="note",
        content="Newer analyst edit",
    )
    with pytest.raises(NoteConflict, match="something inside it changed"):
        delete_note(
            db_path,
            owner="alpha",
            note_id=root["note_id"],
            expected_version=1,
            branch_revision=preview["branch_revision"],
        )
    retained = list_notes(db_path, "alpha")
    assert {item["note_id"] for item in retained} == {root["note_id"], child["note_id"]}
    assert next(item for item in retained if item["note_id"] == child["note_id"])["content"] == "Newer analyst edit"


def test_folder_mutation_requires_preview_and_rejects_added_or_moved_items(tmp_path):
    db_path = tmp_path / "analyzer.db"
    root, child = _tree(db_path)
    with pytest.raises(NoteConflict, match="something inside it changed"):
        share_note(
            db_path,
            owner="alpha",
            note_id=root["note_id"],
            expected_version=1,
            shared=True,
            page="map",
        )

    preview = preview_note_branch(db_path, owner="alpha", note_id=root["note_id"])
    save_note(
        db_path,
        owner="alpha",
        parent_id=root["note_id"],
        title="Late child",
        kind="note",
    )
    with pytest.raises(NoteConflict, match="something inside it changed"):
        share_note(
            db_path,
            owner="alpha",
            note_id=root["note_id"],
            expected_version=1,
            shared=True,
            page="map",
            branch_revision=preview["branch_revision"],
        )
    assert all(item["visibility"] == "personal" for item in list_notes(db_path, "alpha"))

    other = save_note(db_path, owner="alpha", title="Other", kind="folder")
    preview = preview_note_branch(db_path, owner="alpha", note_id=root["note_id"])
    save_note(
        db_path,
        owner="alpha",
        note_id=child["note_id"],
        expected_version=1,
        parent_id=other["note_id"],
        title="Finding",
        kind="note",
        content="Initial",
    )
    with pytest.raises(NoteConflict, match="something inside it changed"):
        delete_note(
            db_path,
            owner="alpha",
            note_id=root["note_id"],
            expected_version=1,
            branch_revision=preview["branch_revision"],
        )


def test_branch_change_after_staging_conflicts_without_partial_share(tmp_path, monkeypatch):
    db_path = tmp_path / "analyzer.db"
    root, child = _tree(db_path)
    preview = preview_note_branch(db_path, owner="alpha", note_id=root["note_id"])
    original_stage = investigation_notes._stage_branch_rows

    def stage_then_edit(db, rows):
        original_stage(db, rows)
        with connect_database(db_path) as other:
            other.execute(
                """UPDATE analyst_investigation_notes
                   SET content = 'Concurrent edit', version = version + 1
                   WHERE note_id = ?""",
                (child["note_id"],),
            )

    monkeypatch.setattr(investigation_notes, "_stage_branch_rows", stage_then_edit)
    with pytest.raises(NoteConflict, match="nothing was changed"):
        share_note(
            db_path,
            owner="alpha",
            note_id=root["note_id"],
            expected_version=1,
            shared=True,
            page="hunt",
            branch_revision=preview["branch_revision"],
        )
    retained = list_notes(db_path, "alpha", "hunt")
    assert all(item["visibility"] == "personal" for item in retained)
    assert next(item for item in retained if item["note_id"] == child["note_id"])["content"] == "Concurrent edit"
    with connect_database(db_path) as db:
        assert db.execute(
            """SELECT COUNT(*) FROM analyst_investigation_note_audit
               WHERE action = 'share'"""
        ).fetchone()[0] == 0


def test_unrelated_branch_change_does_not_create_false_conflict(tmp_path):
    db_path = tmp_path / "analyzer.db"
    root, _child = _tree(db_path)
    other = save_note(db_path, owner="alpha", title="Other", kind="note")
    preview = preview_note_branch(db_path, owner="alpha", note_id=root["note_id"])
    save_note(
        db_path,
        owner="alpha",
        note_id=other["note_id"],
        expected_version=1,
        title="Other changed",
        kind="note",
    )
    shared = share_note(
        db_path,
        owner="alpha",
        note_id=root["note_id"],
        expected_version=1,
        shared=True,
        page="map",
        branch_revision=preview["branch_revision"],
    )
    assert shared["items_updated"] == 2
    assert next(item for item in list_notes(db_path, "alpha") if item["note_id"] == other["note_id"])["visibility"] == "personal"


def test_large_branch_uses_set_based_share_and_delete(tmp_path):
    db_path = tmp_path / "analyzer.db"
    init_note_storage(db_path)
    root = save_note(db_path, owner="alpha", title="Large case", kind="folder")
    now = investigation_notes.utc_now()
    with connect_database(db_path) as db:
        db.executemany(
            """INSERT INTO analyst_investigation_notes
               (note_id, owner, parent_id, kind, title, content, context_json,
                position, version, visibility, shared_page, created_at, updated_at)
               VALUES (?, 'alpha', ?, 'note', ?, '', '{}', ?, 1, 'personal', NULL, ?, ?)""",
            [
                (f"child-{index:04d}", root["note_id"], f"Child {index}", index, now, now)
                for index in range(1_200)
            ],
        )
    preview = preview_note_branch(db_path, owner="alpha", note_id=root["note_id"])
    assert preview["items_total"] == 1_201
    shared = share_note(
        db_path,
        owner="alpha",
        note_id=root["note_id"],
        expected_version=1,
        shared=True,
        page="reach",
        branch_revision=preview["branch_revision"],
    )
    assert shared["items_updated"] == 1_201
    with connect_database(db_path) as db:
        assert db.execute(
            """SELECT COUNT(*) FROM analyst_investigation_notes
               WHERE visibility = 'shared' AND shared_page = 'reach' AND version = 2"""
        ).fetchone()[0] == 1_201

    preview = preview_note_branch(db_path, owner="alpha", note_id=root["note_id"])
    removed = delete_note(
        db_path,
        owner="alpha",
        note_id=root["note_id"],
        expected_version=2,
        branch_revision=preview["branch_revision"],
    )
    assert removed == {
        "deleted": True,
        "note_id": root["note_id"],
        "title": "Large case",
        "items_removed": 1_201,
        "folders_removed": 1,
        "notes_removed": 1_200,
    }


@pytest.mark.parametrize("action", ["share", "delete"])
def test_audit_failure_rolls_back_complete_branch(tmp_path, action):
    db_path = tmp_path / "analyzer.db"
    root, _child = _tree(db_path)
    preview = preview_note_branch(db_path, owner="alpha", note_id=root["note_id"])
    with connect_database(db_path) as db:
        db.execute(
            f"""CREATE TRIGGER reject_branch_audit BEFORE INSERT
                ON analyst_investigation_note_audit
                WHEN NEW.action = '{action}'
                BEGIN SELECT RAISE(ABORT, 'simulated branch audit failure'); END"""
        )
    with pytest.raises(sqlite3.IntegrityError, match="simulated branch audit failure"):
        if action == "share":
            share_note(
                db_path,
                owner="alpha",
                note_id=root["note_id"],
                expected_version=1,
                shared=True,
                page="map",
                branch_revision=preview["branch_revision"],
            )
        else:
            delete_note(
                db_path,
                owner="alpha",
                note_id=root["note_id"],
                expected_version=1,
                branch_revision=preview["branch_revision"],
            )
    retained = list_notes(db_path, "alpha")
    assert len(retained) == 2
    assert all(item["visibility"] == "personal" and item["version"] == 1 for item in retained)


def test_invalid_share_page_and_corrupt_cycle_fail_without_mutation(tmp_path):
    db_path = tmp_path / "analyzer.db"
    root, child = _tree(db_path)
    preview = preview_note_branch(db_path, owner="alpha", note_id=root["note_id"])
    with pytest.raises(ValueError, match="Choose the NCT page"):
        share_note(
            db_path,
            owner="alpha",
            note_id=root["note_id"],
            expected_version=1,
            shared=True,
            page="invalid",
            branch_revision=preview["branch_revision"],
        )
    with connect_database(db_path) as db:
        db.execute(
            "UPDATE analyst_investigation_notes SET parent_id = ? WHERE note_id = ?",
            (child["note_id"], root["note_id"]),
        )
    with pytest.raises(NoteConflict, match="cycle"):
        preview_note_branch(db_path, owner="alpha", note_id=root["note_id"])
