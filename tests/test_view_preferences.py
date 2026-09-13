import pytest

from app.view_preferences import (
    ViewPreferenceConflict,
    delete_filter_preset,
    get_view_workspace,
    save_filter_preset,
    save_view_preference,
)


def test_working_views_are_private_versioned_and_page_specific(tmp_path):
    db_path = tmp_path / "analyzer.db"
    first = save_view_preference(
        db_path,
        owner="alpha",
        page="hunt",
        snapshot={"filters": {"osFilter": "Windows"}, "cards": {"inventory": True}},
        expected_version=None,
    )
    assert first["version"] == 1
    assert get_view_workspace(db_path, owner="alpha", page="hunt")["preference"][
        "snapshot"
    ]["filters"]["osFilter"] == "Windows"
    assert get_view_workspace(db_path, owner="bravo", page="hunt")["preference"] is None
    assert get_view_workspace(db_path, owner="alpha", page="analyze")["preference"] is None

    updated = save_view_preference(
        db_path,
        owner="alpha",
        page="hunt",
        snapshot={"filters": {"osFilter": "Linux"}},
        expected_version=1,
    )
    assert updated["version"] == 2
    with pytest.raises(ViewPreferenceConflict):
        save_view_preference(
            db_path,
            owner="alpha",
            page="hunt",
            snapshot={"filters": {}},
            expected_version=1,
        )


def test_named_filter_presets_are_private_and_protected_from_stale_changes(tmp_path):
    db_path = tmp_path / "analyzer.db"
    created = save_filter_preset(
        db_path,
        owner="alpha",
        page="analyze",
        name="Windows servers",
        snapshot={"filters": {"osFilter": "Windows"}},
    )
    assert [item["name"] for item in get_view_workspace(db_path, owner="alpha", page="analyze")["presets"]] == [
        "Windows servers"
    ]
    assert get_view_workspace(db_path, owner="bravo", page="analyze")["presets"] == []

    updated = save_filter_preset(
        db_path,
        owner="alpha",
        page="analyze",
        preset_id=created["preset_id"],
        expected_version=1,
        name="Windows infrastructure",
        snapshot={"filters": {"hostSearch": "server"}},
    )
    assert updated["version"] == 2
    with pytest.raises(ViewPreferenceConflict):
        delete_filter_preset(
            db_path,
            owner="alpha",
            page="analyze",
            preset_id=created["preset_id"],
            expected_version=1,
        )
    deleted = delete_filter_preset(
        db_path,
        owner="alpha",
        page="analyze",
        preset_id=created["preset_id"],
        expected_version=2,
    )
    assert deleted["status"] == "deleted"


def test_view_storage_rejects_unsupported_pages_and_duplicate_names(tmp_path):
    db_path = tmp_path / "analyzer.db"
    with pytest.raises(ValueError):
        get_view_workspace(db_path, owner="alpha", page="map")
    save_filter_preset(
        db_path,
        owner="alpha",
        page="hunt",
        name="Priority systems",
        snapshot={"filters": {}},
    )
    with pytest.raises(ValueError, match="already exists"):
        save_filter_preset(
            db_path,
            owner="alpha",
            page="hunt",
            name="Priority systems",
            snapshot={"filters": {"search": "router"}},
        )
