import json

import pytest

from app.artifacts import register_artifact_bytes
from app.database import connect_database
from app.derived_contracts import (
    DEVICE_SUMMARY_FAMILY,
    NMAP_BASE_ANALYSIS_FAMILY,
    SUPPORTED_DERIVED_RESULT_CONTRACTS,
)
from app.derived_dependencies import (
    DerivedDependencyIntegrityError,
    UnsupportedDerivedDependency,
    list_input_observations,
    list_result_inputs,
)
from app.derived_results import (
    associate_derived_result_observation,
    prepare_derived_result,
    publish_derived_result,
)


def observation(db_path, content=b"<nmaprun/>", *, source_ref="upload:a", observed_at=None):
    return register_artifact_bytes(
        db_path=db_path,
        content=content,
        source_kind="test_upload",
        source_ref=source_ref,
        original_filename="evidence.xml",
        actor="analyst",
        observed_at=observed_at,
    )


def publish_result(
    db_path, family, inputs, *, links=None, payload=None,
    analysis_version=None, payload_schema_version=None, parameters=None,
):
    contract = SUPPORTED_DERIVED_RESULT_CONTRACTS[family]
    prepared = prepare_derived_result(
        family=family,
        analysis_version=analysis_version or contract.analysis_version,
        payload_schema_version=payload_schema_version or contract.payload_schema_version,
        parameters=parameters or dict(contract.parameters),
        inputs=inputs,
        payload=payload or {"ok": True},
    )
    publish_derived_result(db_path, prepared, observation_links=links or [])
    return prepared


def nmap_result(db_path, source):
    return publish_result(
        db_path,
        NMAP_BASE_ANALYSIS_FAMILY,
        [{
            "role": "nmap_xml", "kind": "artifact_sha256",
            "identity": source["sha256"], "metadata": {"media_family": "nmap_xml"},
        }],
        links=[{"role": "nmap_xml", "observation_id": source["observation_id"]}],
    )


def device_inputs(source, history):
    return [
        {
            "role": "configuration", "kind": "artifact_sha256",
            "identity": source["sha256"], "metadata": {"selection_rule": "first"},
        },
        {
            "role": "raw_output", "kind": "artifact_sha256",
            "identity": source["sha256"], "metadata": {"selection_rule": "first"},
        },
        {"role": "command_history", **history},
        {
            "role": "manifest_semantics", "kind": "canonical_json_sha256",
            "identity": "a" * 64, "metadata": {"vendor": "test", "commands": []},
        },
        {
            "role": "selection_shape", "kind": "canonical_json_sha256",
            "identity": "b" * 64, "metadata": {"configuration": "first"},
        },
    ]


def test_nmap_input_and_separately_paged_source_records(tmp_path):
    db_path = tmp_path / "nct.db"
    first = observation(
        db_path, source_ref="upload:first", observed_at="2026-10-03T10:00:00+00:00",
    )
    second = observation(
        db_path, source_ref="upload:second", observed_at="2026-10-03T11:00:00+00:00",
    )
    third = observation(
        db_path, source_ref="upload:third", observed_at="2026-10-03T12:00:00+00:00",
    )
    prepared = nmap_result(db_path, first)
    for item in (second, third):
        associate_derived_result_observation(
            db_path, prepared.identity,
            role="nmap_xml", observation_id=item["observation_id"],
        )

    inputs = list_result_inputs(db_path, prepared.identity.result_id)
    newest = list_input_observations(
        db_path, prepared.identity.result_id, "nmap_xml", limit=2,
    )
    oldest = list_input_observations(
        db_path, prepared.identity.result_id, "nmap_xml", limit=2, offset=2,
    )

    assert inputs["total"] == 1
    assert inputs["items"][0]["role"] == "nmap_xml"
    assert inputs["items"][0]["source_record_count"] == 3
    assert [item["source_ref"] for item in newest["items"]] == [
        "upload:third", "upload:second",
    ]
    assert newest["has_more"] is True
    assert [item["source_ref"] for item in oldest["items"]] == ["upload:first"]


@pytest.mark.parametrize(
    "override",
    [
        {"analysis_version": "future-unreviewed:999"},
        {"payload_schema_version": 999},
        {"parameters": {"parser": "future.parser", "contract": 999}},
    ],
)
def test_only_exact_reviewed_input_contracts_are_supported(tmp_path, override):
    db_path = tmp_path / "nct.db"
    source = observation(db_path)
    prepared = publish_result(
        db_path,
        NMAP_BASE_ANALYSIS_FAMILY,
        [{
            "role": "nmap_xml", "kind": "artifact_sha256",
            "identity": source["sha256"], "metadata": {"media_family": "nmap_xml"},
        }],
        links=[{"role": "nmap_xml", "observation_id": source["observation_id"]}],
        **override,
    )

    with pytest.raises(UnsupportedDerivedDependency, match="has not reviewed"):
        list_result_inputs(db_path, prepared.identity.result_id)


def test_retained_exact_reviewed_version_remains_supported(tmp_path):
    db_path = tmp_path / "nct.db"
    source = observation(db_path)
    prepared = nmap_result(db_path, source)

    result = list_result_inputs(db_path, prepared.identity.result_id)

    assert result["analysis_version"] == SUPPORTED_DERIVED_RESULT_CONTRACTS[
        NMAP_BASE_ANALYSIS_FAMILY
    ].analysis_version
    assert result["items"][0]["role"] == "nmap_xml"


def test_device_roles_stay_distinct_when_they_use_identical_bytes(tmp_path):
    db_path = tmp_path / "nct.db"
    source = observation(db_path, b"router configuration")
    history = {
        "kind": "embedded_config_section", "identity": "c" * 64,
        "metadata": {"present": True},
    }
    prepared = publish_result(
        db_path, DEVICE_SUMMARY_FAMILY, device_inputs(source, history),
        links=[
            {"role": "configuration", "observation_id": source["observation_id"]},
            {"role": "raw_output", "observation_id": source["observation_id"]},
        ],
    )

    result = list_result_inputs(db_path, prepared.identity.result_id, limit=2)
    second_page = list_result_inputs(
        db_path, prepared.identity.result_id, limit=2, offset=2,
    )
    all_items = result["items"] + second_page["items"] + list_result_inputs(
        db_path, prepared.identity.result_id, limit=2, offset=4,
    )["items"]
    by_role = {item["role"]: item for item in all_items}

    assert result["total"] == 5
    assert set(by_role) == {
        "configuration", "raw_output", "command_history",
        "manifest_semantics", "selection_shape",
    }
    assert by_role["configuration"]["identity"] == by_role["raw_output"]["identity"]
    assert by_role["configuration"]["source_record_count"] == 1
    assert by_role["raw_output"]["source_record_count"] == 1
    assert by_role["command_history"]["type_label"] == "Embedded history descriptor"


@pytest.mark.parametrize(
    "history,expected_type,expected_text",
    [
        (
            {"kind": "absence_descriptor", "identity": "d" * 64,
             "metadata": {"present": False}},
            "Missing history descriptor", "No dedicated or embedded",
        ),
        (
            {"kind": "embedded_config_section", "identity": "e" * 64,
             "metadata": {"present": True}},
            "Embedded history descriptor", "embedded in configuration",
        ),
    ],
)
def test_missing_and_embedded_history_are_explicit(
    tmp_path, history, expected_type, expected_text,
):
    db_path = tmp_path / f"{history['kind']}.db"
    source = observation(db_path, b"router configuration")
    prepared = publish_result(
        db_path, DEVICE_SUMMARY_FAMILY, device_inputs(source, history),
    )

    item = next(
        item for item in list_result_inputs(db_path, prepared.identity.result_id)["items"]
        if item["role"] == "command_history"
    )
    assert item["type_label"] == expected_type
    assert expected_text in item["explanation"]
    assert item["source_records_supported"] is False


def test_dedicated_empty_history_file_remains_a_zero_byte_source(tmp_path):
    db_path = tmp_path / "nct.db"
    source = observation(db_path, b"router configuration")
    history_source = observation(db_path, b"", source_ref="history:empty")
    history = {
        "kind": "artifact_sha256", "identity": history_source["sha256"],
        "metadata": {"selection_rule": "dedicated_history_file"},
    }
    prepared = publish_result(
        db_path, DEVICE_SUMMARY_FAMILY, device_inputs(source, history),
        links=[{
            "role": "command_history",
            "observation_id": history_source["observation_id"],
        }],
    )

    result = list_input_observations(
        db_path, prepared.identity.result_id, "command_history",
    )
    assert result["total"] == 1
    assert result["items"][0]["size_bytes"] == 0


def test_deleted_observation_leaves_input_without_invented_provenance(tmp_path):
    db_path = tmp_path / "nct.db"
    source = observation(db_path)
    prepared = nmap_result(db_path, source)
    with connect_database(db_path) as db:
        db.execute(
            "DELETE FROM artifact_observations WHERE observation_id = ?",
            (source["observation_id"],),
        )

    inputs = list_result_inputs(db_path, prepared.identity.result_id)
    sources = list_input_observations(
        db_path, prepared.identity.result_id, "nmap_xml",
    )
    assert inputs["items"][0]["source_record_count"] == 0
    assert sources["items"] == []
    assert sources["total"] == 0


def test_conflicting_input_row_fails_visibly(tmp_path):
    db_path = tmp_path / "nct.db"
    source = observation(db_path)
    prepared = nmap_result(db_path, source)
    with connect_database(db_path) as db:
        db.execute(
            "DELETE FROM derived_result_inputs WHERE result_id = ?",
            (prepared.identity.result_id,),
        )
        db.execute(
            """INSERT INTO derived_result_inputs VALUES (?, ?, ?, ?, ?)""",
            (
                prepared.identity.result_id, "nmap_xml", "artifact_sha256",
                "f" * 64, json.dumps({"media_family": "nmap_xml"}, separators=(",", ":")),
            ),
        )

    with pytest.raises(DerivedDependencyIntegrityError, match="do not match"):
        list_result_inputs(db_path, prepared.identity.result_id)


def test_conflicting_manifest_identity_and_observation_digest_fail_visibly(tmp_path):
    first_db = tmp_path / "identity.db"
    source = observation(first_db)
    prepared = nmap_result(first_db, source)
    with connect_database(first_db) as db:
        db.execute("DROP TRIGGER derived_results_no_update")
        db.execute(
            "UPDATE derived_results SET computation_key = ? WHERE result_id = ?",
            ("0" * 64, prepared.identity.result_id),
        )
    with pytest.raises(DerivedDependencyIntegrityError, match="does not match"):
        list_result_inputs(first_db, prepared.identity.result_id)

    second_db = tmp_path / "digest.db"
    source = observation(second_db)
    other = observation(second_db, b"different", source_ref="upload:different")
    prepared = nmap_result(second_db, source)
    with connect_database(second_db) as db:
        db.execute(
            "INSERT INTO derived_result_observation_links VALUES (?, ?, ?, ?)",
            (
                prepared.identity.result_id, "nmap_xml", other["observation_id"],
                "2026-10-03T20:00:00+00:00",
            ),
        )
    with pytest.raises(DerivedDependencyIntegrityError, match="conflict"):
        list_result_inputs(second_db, prepared.identity.result_id)
    with pytest.raises(DerivedDependencyIntegrityError, match="conflict"):
        list_input_observations(second_db, prepared.identity.result_id, "nmap_xml")


def test_dependency_reads_are_read_only_and_work_with_pending_writer(tmp_path, monkeypatch):
    import app.derived_dependencies as dependencies

    db_path = tmp_path / "nct.db"
    source = observation(db_path)
    prepared = nmap_result(db_path, source)
    original = dependencies.connect_database
    calls = []

    def require_read_only(path, **kwargs):
        calls.append(kwargs.get("read_only"))
        return original(path, **kwargs)

    monkeypatch.setattr(dependencies, "connect_database", require_read_only)
    writer = connect_database(db_path)
    try:
        writer.execute("BEGIN IMMEDIATE")
        writer.execute(
            "UPDATE artifact_registry SET last_seen_at = last_seen_at WHERE sha256 = ?",
            (source["sha256"],),
        )
        assert list_result_inputs(db_path, prepared.identity.result_id)["total"] == 1
        assert list_input_observations(
            db_path, prepared.identity.result_id, "nmap_xml",
        )["total"] == 1
    finally:
        writer.rollback()
        writer.close()

    assert calls == [True, True]
