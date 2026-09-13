from __future__ import annotations

import pytest

from app.investigation_notes import (
    NoteConflict,
    delete_note,
    list_notes,
    save_note,
    share_note,
    export_note_markdown,
)


def test_personal_note_tree_and_page_scoped_sharing(tmp_path):
    db_path = tmp_path / "analyzer.db"
    folder = save_note(
        db_path, owner="alpha", title="Gateway review", kind="folder"
    )
    note = save_note(
        db_path,
        owner="alpha",
        parent_id=folder["note_id"],
        title="Validate outside route",
        kind="note",
        content="Confirm next hop with the device owner.",
        context={"source_url": "/network-map"},
    )

    assert {item["title"] for item in list_notes(db_path, "alpha", "map")} == {
        "Gateway review",
        "Validate outside route",
    }
    assert list_notes(db_path, "bravo", "map") == []

    shared = share_note(
        db_path,
        owner="alpha",
        note_id=folder["note_id"],
        expected_version=folder["version"],
        shared=True,
        page="map",
    )
    assert shared["visibility"] == "shared"
    assert shared["shared_page"] == "map"
    visible = list_notes(db_path, "bravo", "map")
    assert {item["title"] for item in visible} == {
        "Gateway review",
        "Validate outside route",
    }
    assert all(item["writable"] is False for item in visible)
    assert list_notes(db_path, "bravo", "hunt") == []

    child = next(item for item in list_notes(db_path, "alpha", "map") if item["note_id"] == note["note_id"])
    assert child["shared_page"] == "map"
    title, markdown = export_note_markdown(
        db_path, viewer="bravo", note_id=folder["note_id"], page="map"
    )
    assert title == "Gateway review"
    assert "## Validate outside route" in markdown
    assert "Confirm next hop" in markdown


def test_note_conflicts_ownership_cycles_and_branch_delete(tmp_path):
    db_path = tmp_path / "analyzer.db"
    parent = save_note(db_path, owner="alpha", title="Parent", kind="folder")
    child = save_note(
        db_path,
        owner="alpha",
        parent_id=parent["note_id"],
        title="Child",
        kind="folder",
    )
    leaf = save_note(
        db_path,
        owner="alpha",
        parent_id=child["note_id"],
        title="Leaf",
        kind="note",
    )

    updated = save_note(
        db_path,
        owner="alpha",
        note_id=leaf["note_id"],
        expected_version=1,
        title="Updated leaf",
        kind="note",
        content="Evidence retained",
        parent_id=child["note_id"],
    )
    assert updated["version"] == 2
    with pytest.raises(NoteConflict):
        save_note(
            db_path,
            owner="alpha",
            note_id=leaf["note_id"],
            expected_version=1,
            title="Stale write",
            kind="note",
        )
    with pytest.raises(ValueError):
        save_note(
            db_path,
            owner="alpha",
            note_id=parent["note_id"],
            expected_version=1,
            parent_id=child["note_id"],
            title="Parent",
            kind="folder",
        )
    with pytest.raises(KeyError):
        delete_note(
            db_path,
            owner="bravo",
            note_id=parent["note_id"],
            expected_version=1,
        )

    removed = delete_note(
        db_path,
        owner="alpha",
        note_id=parent["note_id"],
        expected_version=1,
    )
    assert removed["items_removed"] == 3
    assert list_notes(db_path, "alpha", "map") == []
