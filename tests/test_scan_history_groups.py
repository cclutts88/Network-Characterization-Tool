from __future__ import annotations

import sqlite3

from fastapi.testclient import TestClient

from app.scan_history import (
    build_scan_history_catalog,
    scan_history_group_page,
    scan_history_memberships,
)


def scan_run(
    index: int,
    *,
    targets: list[str] | None = None,
    saved_networks: list[dict] | None = None,
    scope: str | None = None,
) -> dict:
    run = {
        "run_id": f"{index:032x}",
        "created_at": f"2026-10-{1 + index // 24:02d}T{index % 24:02d}:00:00+00:00",
        "completed_at": f"2026-10-{1 + index // 24:02d}T{index % 24:02d}:30:00+00:00",
        "display_name": f"Scan {index}",
        "status": "completed",
        "targets": targets or [],
        "manual_targets": targets or [],
        "saved_networks": saved_networks or [],
        "host_count": index,
    }
    if scope:
        run["network_scope_context"] = {"scope_id": scope, "scope_label": scope}
    return run


def test_catalog_covers_old_subnets_beyond_two_hundred_records():
    recent = [scan_run(index, targets=["10.50.15.0/24"]) for index in range(205)]
    old_only = scan_run(999, targets=["10.60.8.0/24"])
    old_only["created_at"] = "2020-01-01T00:00:00+00:00"
    old_only["completed_at"] = "2020-01-01T00:01:00+00:00"

    catalog = build_scan_history_catalog([*recent, old_only])

    assert {item["cidr"] for item in catalog} == {
        "10.50.15.0/24", "10.60.8.0/24"
    }
    assert next(item for item in catalog if item["cidr"] == "10.50.15.0/24")[
        "scan_count"
    ] == 205


def test_same_cidr_stays_grouped_after_saved_network_recreation_and_manual_use():
    first = scan_run(1, saved_networks=[{
        "saved_network_id": "old-id",
        "name": "Old name",
        "cidr": "10.50.15.7/24",
    }])
    second = scan_run(2, saved_networks=[{
        "saved_network_id": "new-id",
        "name": "AFB Development",
        "cidr": "10.50.15.0/24",
    }])
    manual = scan_run(3, targets=["10.50.15.99/24"])

    catalog = build_scan_history_catalog([first, second, manual])

    assert len(catalog) == 1
    assert catalog[0]["cidr"] == "10.50.15.0/24"
    assert catalog[0]["scan_count"] == 3
    assert catalog[0]["name"] == "Subnet 10.50.15.0/24"


def test_group_page_preserves_scope_and_marks_other_exact_targets():
    multi = scan_run(
        10,
        targets=["10.1.0.0/16", "10.1.15.0/24"],
        scope="AFB Dev",
    )
    memberships = scan_history_memberships(multi)
    assert {item["cidr"] for item in memberships} == {
        "10.1.0.0/16", "10.1.15.0/24"
    }
    group_id = next(
        item["group_id"] for item in memberships if item["cidr"] == "10.1.15.0/24"
    )

    page = scan_history_group_page([multi], group_id, limit=25)

    assert page is not None
    assert page["runs"][0]["network_scope_context"]["scope_id"] == "AFB Dev"
    assert page["runs"][0]["history_also_covers"] == [{
        "group_id": next(
            item["group_id"] for item in memberships if item["cidr"] == "10.1.0.0/16"
        ),
        "name": "Subnet 10.1.0.0/16",
        "cidr": "10.1.0.0/16",
    }]


def test_host_lists_and_missing_or_invalid_targets_are_not_inferred_as_subnets():
    hosts = scan_history_memberships(
        scan_run(1, targets=["10.0.0.4", "10.0.0.5"])
    )
    invalid = scan_history_memberships(scan_run(2, targets=["legacy-target"]))
    missing = scan_history_memberships(scan_run(3))

    assert hosts[0]["kind"] == "host_targets"
    assert hosts[0]["cidr"] == ""
    assert "no subnet is inferred" in hosts[0]["description"]
    assert invalid[0]["kind"] == "legacy_targets"
    assert missing[0]["kind"] == "missing_targets"


def test_group_cursor_is_stable_when_a_newer_scan_is_inserted():
    runs = [scan_run(index, targets=["192.0.2.0/24"]) for index in range(30)]
    group_id = scan_history_memberships(runs[0])[0]["group_id"]
    first = scan_history_group_page(runs, group_id, limit=25)
    assert first is not None and first["has_more"]

    newer = scan_run(1000, targets=["192.0.2.0/24"])
    newer["created_at"] = "2030-01-01T00:00:00+00:00"
    second = scan_history_group_page(
        [newer, *runs], group_id, limit=25, cursor=first["next_cursor"]
    )

    assert second is not None
    first_ids = {item["run_id"] for item in first["runs"]}
    second_ids = {item["run_id"] for item in second["runs"]}
    assert len(second_ids) == 5
    assert first_ids.isdisjoint(second_ids)
    assert newer["run_id"] not in second_ids


def test_catalog_handles_representative_metadata_scale():
    runs = [
        scan_run(index, targets=[f"10.{index % 200}.{index % 250}.0/24"])
        for index in range(5_000)
    ]
    catalog = build_scan_history_catalog(runs)
    assert sum(item["scan_count"] for item in catalog) == 5_000


def test_history_metadata_reads_do_not_create_or_initialize_storage(tmp_path):
    import app.poc as poc

    missing = tmp_path / "missing" / "analyzer.db"
    assert poc.list_all_scan_history_metadata(missing) == []
    assert poc.list_scan_history_metadata_by_ids([f"{1:032x}"], missing) == []
    assert not missing.exists()
    assert not missing.parent.exists()

    empty_database = tmp_path / "empty.db"
    with sqlite3.connect(empty_database) as db:
        db.execute("CREATE TABLE unrelated (value TEXT)")
        db.execute("INSERT INTO unrelated VALUES ('preserved')")
    before = empty_database.read_bytes()

    assert poc.list_all_scan_history_metadata(empty_database) == []
    assert poc.list_scan_history_metadata_by_ids(
        [f"{1:032x}"], empty_database
    ) == []
    assert empty_database.read_bytes() == before


def test_scan_history_routes_page_inside_the_exact_subnet(tmp_path, monkeypatch):
    import app.main as main
    import app.poc as poc

    db_path = tmp_path / "analyzer.db"
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    records = [
        scan_run(1, targets=["10.50.15.0/24"], scope="Scope A"),
        scan_run(2, targets=["10.50.15.5/24"], scope="Scope B"),
        scan_run(3, targets=["10.60.8.0/24"]),
    ]
    for record in records:
        record.update({
            "operator": "analyst",
            "reason": "test",
            "originating_host": "test-host",
            "interface": "eth0",
            "profile": "safe",
        })
        poc.insert_scan_run_manifest(record, db_path)

    monkeypatch.setattr(poc, "DB_PATH", db_path)
    monkeypatch.setattr(poc, "DATA_DIR", data_dir)
    monkeypatch.setattr(main, "DB_PATH", db_path)
    monkeypatch.setattr(main, "DATA_DIR", data_dir)
    monkeypatch.setattr(main, "auth_enabled", lambda: False)
    with TestClient(main.app) as client:
        catalog_response = client.get("/api/scan-history-groups?limit=100&offset=0")
        assert catalog_response.status_code == 200
        group = next(
            item for item in catalog_response.json()["groups"]
            if item["cidr"] == "10.50.15.0/24"
        )
        page_response = client.get(
            f"/api/scan-history-groups/{group['group_id']}/runs?limit=1"
        )
        assert page_response.status_code == 200
        first = page_response.json()
        assert first["total"] == 2
        assert first["has_more"] is True
        assert first["runs"][0]["network_scope_context"]["scope_id"] == "Scope B"

        next_response = client.get(
            f"/api/scan-history-groups/{group['group_id']}/runs?limit=1"
            f"&cursor={first['next_cursor']}"
        )
        assert next_response.status_code == 200
        assert next_response.json()["runs"][0]["network_scope_context"][
            "scope_id"
        ] == "Scope A"

        visible = client.get(
            "/api/scan-history-visible-runs",
            params=[("run_id", records[0]["run_id"]), ("run_id", records[1]["run_id"])],
        )
        assert visible.status_code == 200
        assert [item["run_id"] for item in visible.json()["runs"]] == [
            records[0]["run_id"], records[1]["run_id"]
        ]
