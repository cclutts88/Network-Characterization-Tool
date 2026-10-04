from dataclasses import replace
import json

import pytest

from app.artifacts import register_artifact_bytes
from app.database import connect_database
from app.derived_contracts import (
    NMAP_BASE_ANALYSIS_FAMILY,
    NMAP_TOPOLOGY_FAMILY,
    SUPPORTED_DERIVED_RESULT_CONTRACTS,
)
from app.derived_results import (
    associate_derived_result_observation,
    init_derived_result_storage,
    prepare_derived_result,
    publish_derived_result,
)
from app.derived_version_inventory import (
    list_version_group_results,
    list_version_groups,
)


def publish_result(
    db_path, *, family=NMAP_BASE_ANALYSIS_FAMILY, suffix="a", parameters=None,
    analysis_version=None, payload_schema_version=None, generated_at=None,
    observation=None,
):
    contract = SUPPORTED_DERIVED_RESULT_CONTRACTS[family]
    if observation is None:
        inputs = [{
            "role": "source", "kind": "test_identity",
            "identity": suffix, "metadata": {},
        }]
        links = []
    else:
        inputs = [{
            "role": "nmap_xml", "kind": "artifact_sha256",
            "identity": observation["sha256"],
            "metadata": {"media_family": "nmap_xml"},
        }]
        links = [{"role": "nmap_xml", "observation_id": observation["observation_id"]}]
    prepared = prepare_derived_result(
        family=family,
        analysis_version=analysis_version or contract.analysis_version,
        payload_schema_version=payload_schema_version or contract.payload_schema_version,
        parameters=parameters if parameters is not None else dict(contract.parameters),
        inputs=inputs,
        payload={"source": suffix},
        generated_at=generated_at or f"2026-10-03T20:00:0{len(suffix)}+00:00",
    )
    publish_derived_result(db_path, prepared, observation_links=links)
    return prepared


def insert_raw_result(
    db_path, result_id, *, family, version, schema, settings, generated_at,
):
    init_derived_result_storage(db_path)
    with connect_database(db_path) as db:
        db.execute(
            """INSERT INTO derived_results VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                result_id, f"key-{result_id}", family, version, schema, settings,
                "[]", "{}", f"hash-{result_id}", generated_at,
            ),
        )


def test_exact_settings_family_and_schema_remain_separate_groups(tmp_path):
    db_path = tmp_path / "nct.db"
    current = SUPPORTED_DERIVED_RESULT_CONTRACTS[NMAP_BASE_ANALYSIS_FAMILY]
    publish_result(db_path, suffix="a")
    publish_result(db_path, suffix="bb", parameters={**dict(current.parameters), "mode": "other"})
    publish_result(
        db_path, suffix="ccc", payload_schema_version=current.payload_schema_version + 1,
    )
    publish_result(db_path, family=NMAP_TOPOLOGY_FAMILY, suffix="dddd")

    result = list_version_groups(db_path)

    assert result["total_groups"] == 4
    assert len({item["group_id"] for item in result["items"]}) == 4
    assert {item["state"] for item in result["items"]} == {"CURRENT", "STALE"}
    base_groups = [item for item in result["items"] if item["family"] == current.family]
    assert len(base_groups) == 3
    assert len({item["settings_fingerprint"] for item in base_groups}) == 2


def test_group_counts_results_not_duplicate_observations(tmp_path):
    db_path = tmp_path / "nct.db"
    first = register_artifact_bytes(
        db_path=db_path, content=b"<nmaprun/>", source_kind="test",
        source_ref="first", original_filename="scan.xml", actor="analyst",
    )
    second = register_artifact_bytes(
        db_path=db_path, content=b"<nmaprun/>", source_kind="test",
        source_ref="second", original_filename="scan.xml", actor="analyst",
    )
    prepared = publish_result(db_path, observation=first)
    associate_derived_result_observation(
        db_path, prepared.identity,
        role="nmap_xml", observation_id=second["observation_id"],
    )

    groups = list_version_groups(db_path)

    assert groups["total_groups"] == 1
    assert groups["items"][0]["result_count"] == 1


def test_unknown_and_malformed_groups_remain_visible(tmp_path):
    db_path = tmp_path / "nct.db"
    insert_raw_result(
        db_path, "unknown", family="future_family", version="future:1",
        schema=1, settings="{}", generated_at="2026-10-03T20:00:00+00:00",
    )
    insert_raw_result(
        db_path, "malformed", family=NMAP_BASE_ANALYSIS_FAMILY,
        version=SUPPORTED_DERIVED_RESULT_CONTRACTS[NMAP_BASE_ANALYSIS_FAMILY].analysis_version,
        schema=1, settings="{broken", generated_at="2026-10-03T20:00:01+00:00",
    )

    groups = list_version_groups(db_path)

    assert groups["total_groups"] == 2
    assert groups["page_counts"] == {"CURRENT": 0, "STALE": 0, "UNKNOWN": 2}
    assert all(item["state"] == "UNKNOWN" for item in groups["items"])


def test_exact_group_drilldown_rejects_cross_group_selector(tmp_path):
    db_path = tmp_path / "nct.db"
    first = publish_result(db_path, suffix="a", generated_at="2026-10-03T20:00:00+00:00")
    second = publish_result(db_path, suffix="bb", generated_at="2026-10-03T21:00:00+00:00")
    current = SUPPORTED_DERIVED_RESULT_CONTRACTS[NMAP_BASE_ANALYSIS_FAMILY]
    other = publish_result(
        db_path, suffix="ccc", parameters={**dict(current.parameters), "mode": "other"},
    )
    group = next(item for item in list_version_groups(db_path)["items"] if item["state"] == "CURRENT")

    newest = list_version_group_results(
        db_path, group["group_id"], group["representative_result_id"], limit=1,
    )
    oldest = list_version_group_results(
        db_path, group["group_id"], group["representative_result_id"], limit=1, offset=1,
    )

    assert newest["total"] == 2
    assert [item["result_id"] for item in newest["items"]] == [second.identity.result_id]
    assert [item["result_id"] for item in oldest["items"]] == [first.identity.result_id]
    assert newest["has_more"] is True
    assert oldest["has_more"] is False
    with pytest.raises(KeyError, match="not available"):
        list_version_group_results(
            db_path, group["group_id"], other.identity.result_id,
        )


def test_version_group_pagination_is_deterministic_and_page_counts_are_local(tmp_path):
    db_path = tmp_path / "nct.db"
    current = SUPPORTED_DERIVED_RESULT_CONTRACTS[NMAP_BASE_ANALYSIS_FAMILY]
    for index in range(5):
        publish_result(
            db_path,
            suffix="x" * (index + 1),
            parameters={**dict(current.parameters), "group": index},
            generated_at=f"2026-10-03T2{index}:00:00+00:00",
        )

    first = list_version_groups(db_path, limit=2)
    second = list_version_groups(db_path, limit=2, offset=2)
    repeat = list_version_groups(db_path, limit=2)

    assert first["total_groups"] == 5
    assert first["items"] == repeat["items"]
    assert {item["group_id"] for item in first["items"]}.isdisjoint(
        {item["group_id"] for item in second["items"]}
    )
    assert sum(first["page_counts"].values()) == 2
    assert first["has_more"] is True


def test_rollback_contract_changes_classification_without_rewriting_groups(tmp_path):
    db_path = tmp_path / "nct.db"
    publish_result(db_path)
    current = SUPPORTED_DERIVED_RESULT_CONTRACTS[NMAP_BASE_ANALYSIS_FAMILY]
    upgraded = {
        **SUPPORTED_DERIVED_RESULT_CONTRACTS,
        NMAP_BASE_ANALYSIS_FAMILY: replace(current, analysis_version="nmap-base-analysis:2"),
    }

    stale = list_version_groups(db_path, contracts=upgraded)["items"][0]
    restored = list_version_groups(db_path)["items"][0]

    assert stale["group_id"] == restored["group_id"]
    assert stale["state"] == "STALE"
    assert restored["state"] == "CURRENT"


def test_inventory_reads_are_read_only_and_work_with_pending_writer(tmp_path, monkeypatch):
    import app.derived_version_inventory as inventory

    db_path = tmp_path / "nct.db"
    publish_result(db_path)
    group = list_version_groups(db_path)["items"][0]
    original = inventory.connect_database
    calls = []

    def require_read_only(path, **kwargs):
        calls.append(kwargs.get("read_only"))
        return original(path, **kwargs)

    monkeypatch.setattr(inventory, "connect_database", require_read_only)
    writer = connect_database(db_path)
    try:
        writer.execute("BEGIN IMMEDIATE")
        writer.execute("UPDATE artifact_registry SET last_seen_at = last_seen_at")
        assert list_version_groups(db_path)["total_groups"] == 1
        assert list_version_group_results(
            db_path, group["group_id"], group["representative_result_id"],
        )["total"] == 1
    finally:
        writer.rollback()
        writer.close()

    assert calls == [True, True]


def test_missing_database_is_empty_and_invalid_group_id_is_rejected(tmp_path):
    db_path = tmp_path / "missing.db"
    assert list_version_groups(db_path)["items"] == []
    with pytest.raises(ValueError, match="lowercase SHA-256"):
        list_version_group_results(db_path, "bad", "result")
