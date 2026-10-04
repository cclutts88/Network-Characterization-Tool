from dataclasses import replace
import json

from app.database import connect_database
from app.derived_contracts import (
    DEVICE_SUMMARY_FAMILY,
    NMAP_BASE_ANALYSIS_FAMILY,
    NMAP_TOPOLOGY_FAMILY,
    SUPPORTED_DERIVED_RESULT_CONTRACTS,
)
from app.derived_result_status import (
    classify_calculation_contract,
    list_derived_result_status,
)
from app.derived_results import (
    init_derived_result_storage,
    prepare_derived_result,
    publish_derived_result,
)


def publish_contract_result(db_path, family, *, suffix="a", generated_at=None):
    contract = SUPPORTED_DERIVED_RESULT_CONTRACTS[family]
    prepared = prepare_derived_result(
        family=family,
        analysis_version=contract.analysis_version,
        payload_schema_version=contract.payload_schema_version,
        parameters=dict(contract.parameters),
        inputs=[{
            "role": "source", "kind": "test_identity",
            "identity": suffix, "metadata": {},
        }],
        payload={"source": suffix},
        generated_at=generated_at or f"2026-10-03T20:00:0{len(suffix)}+00:00",
    )
    publish_derived_result(db_path, prepared)
    return prepared


def test_supported_families_are_current_under_their_exact_contract(tmp_path):
    db_path = tmp_path / "nct.db"
    families = (
        NMAP_BASE_ANALYSIS_FAMILY,
        NMAP_TOPOLOGY_FAMILY,
        DEVICE_SUMMARY_FAMILY,
    )
    for index, family in enumerate(families):
        publish_contract_result(db_path, family, suffix=str(index))

    result = list_derived_result_status(db_path)

    assert result["total"] == 3
    assert result["page_counts"] == {"CURRENT": 3, "STALE": 0, "UNKNOWN": 0}
    assert {item["family"] for item in result["items"]} == set(families)
    assert all(item["state"] == "CURRENT" for item in result["items"])


def test_version_schema_and_settings_mismatches_are_independently_stale():
    contract = SUPPORTED_DERIVED_RESULT_CONTRACTS[NMAP_BASE_ANALYSIS_FAMILY]
    base = {
        "family": contract.family,
        "analysis_version": contract.analysis_version,
        "payload_schema_version": contract.payload_schema_version,
        "parameters_json": json.dumps(dict(contract.parameters), sort_keys=True),
    }
    version = classify_calculation_contract(
        **{**base, "analysis_version": "older:1"}
    )
    schema = classify_calculation_contract(
        **{**base, "payload_schema_version": contract.payload_schema_version + 1}
    )
    settings = classify_calculation_contract(
        **{**base, "parameters_json": json.dumps({"parser": "other"})}
    )

    assert version["state"] == schema["state"] == settings["state"] == "STALE"
    assert "rule version" in version["reasons"][0]
    assert "output format" in schema["reasons"][0]
    assert "settings" in settings["reasons"][0]


def test_unknown_and_malformed_contracts_never_appear_current(tmp_path):
    db_path = tmp_path / "nct.db"
    init_derived_result_storage(db_path)
    with connect_database(db_path) as db:
        db.execute(
            """INSERT INTO derived_results VALUES
               (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                "unknown-result", "unknown-key", "future_family", "future:1", 1,
                "{}", "[]", "{}", "result-hash", "2026-10-03T20:00:00+00:00",
            ),
        )
        db.execute(
            """INSERT INTO derived_results VALUES
               (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                "malformed-result", "malformed-key", NMAP_BASE_ANALYSIS_FAMILY,
                SUPPORTED_DERIVED_RESULT_CONTRACTS[NMAP_BASE_ANALYSIS_FAMILY].analysis_version,
                1, "{broken", "[]", "{}", "result-hash",
                "2026-10-03T20:00:01+00:00",
            ),
        )

    result = list_derived_result_status(db_path)

    assert result["page_counts"] == {"CURRENT": 0, "STALE": 0, "UNKNOWN": 2}
    assert all(item["state"] == "UNKNOWN" for item in result["items"])


def test_unreadable_required_metadata_is_unknown():
    contract = SUPPORTED_DERIVED_RESULT_CONTRACTS[NMAP_BASE_ANALYSIS_FAMILY]
    settings = json.dumps(dict(contract.parameters))

    for change in (
        {"analysis_version": None},
        {"payload_schema_version": "one"},
        {"parameters_json": None},
    ):
        values = {
            "family": contract.family,
            "analysis_version": contract.analysis_version,
            "payload_schema_version": contract.payload_schema_version,
            "parameters_json": settings,
            **change,
        }
        assert classify_calculation_contract(**values)["state"] == "UNKNOWN"


def test_ambiguous_or_excessively_nested_settings_are_unknown():
    contract = SUPPORTED_DERIVED_RESULT_CONTRACTS[NMAP_BASE_ANALYSIS_FAMILY]
    base = {
        "family": contract.family,
        "analysis_version": contract.analysis_version,
        "payload_schema_version": contract.payload_schema_version,
    }
    duplicate = (
        '{"parser":"wrong","parser":"nct.parse_xml",'
        '"coverage_presence_os_inference_contract":1}'
    )
    deeply_nested = '{"value":' + ('[' * 15_000) + '0' + (']' * 15_000) + '}'

    assert classify_calculation_contract(
        **base, parameters_json=duplicate,
    )["state"] == "UNKNOWN"
    assert classify_calculation_contract(
        **base, parameters_json=deeply_nested,
    )["state"] == "UNKNOWN"


def test_rollback_contract_restores_matching_status_without_changing_result(tmp_path):
    db_path = tmp_path / "nct.db"
    prepared = publish_contract_result(db_path, NMAP_BASE_ANALYSIS_FAMILY)
    current = SUPPORTED_DERIVED_RESULT_CONTRACTS[NMAP_BASE_ANALYSIS_FAMILY]
    upgraded = {
        **SUPPORTED_DERIVED_RESULT_CONTRACTS,
        NMAP_BASE_ANALYSIS_FAMILY: replace(current, analysis_version="nmap-base-analysis:2"),
    }

    assert list_derived_result_status(db_path, contracts=upgraded)["items"][0]["state"] == "STALE"
    assert list_derived_result_status(db_path)["items"][0]["state"] == "CURRENT"
    with connect_database(db_path, read_only=True) as db:
        assert db.execute(
            "SELECT result_json FROM derived_results WHERE result_id = ?",
            (prepared.identity.result_id,),
        ).fetchone()[0] == prepared.result_json


def test_status_is_read_only_paged_and_available_during_pending_writer(tmp_path, monkeypatch):
    import app.derived_result_status as status_module

    db_path = tmp_path / "nct.db"
    for index in range(5):
        publish_contract_result(
            db_path, NMAP_TOPOLOGY_FAMILY, suffix=str(index),
            generated_at=f"2026-10-03T20:00:0{index}+00:00",
        )
    original_connect = status_module.connect_database
    calls = []

    def require_read_only(path, **kwargs):
        calls.append(kwargs.get("read_only"))
        return original_connect(path, **kwargs)

    monkeypatch.setattr(status_module, "connect_database", require_read_only)
    writer = connect_database(db_path)
    try:
        writer.execute("BEGIN IMMEDIATE")
        page = list_derived_result_status(db_path, limit=2, offset=2)
    finally:
        writer.rollback()
        writer.close()

    assert calls == [True]
    assert page["total"] == 5
    assert len(page["items"]) == 2
    assert page["offset"] == 2
    assert page["has_more"] is True
    assert list_derived_result_status(db_path, limit=2, offset=4)["has_more"] is False
    with connect_database(db_path, read_only=True) as db:
        assert db.execute("SELECT COUNT(*) FROM derived_results").fetchone()[0] == 5
