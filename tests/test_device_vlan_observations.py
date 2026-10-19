from __future__ import annotations

import sqlite3

import pytest

from app.device_vlan_observations import (
    DEVICE_VLAN_EXTRACTOR,
    DEVICE_VLAN_SCHEMA_OBJECTS,
    create_device_vlan_schema,
    current_device_vlan_assessment_on_connection,
)


def _assessment(
    db: sqlite3.Connection, assessment_id: str = "assessment-1",
    extractor_version: str = DEVICE_VLAN_EXTRACTOR,
    collection_contract: str = "built-in:test:1",
) -> None:
    db.execute(
        """INSERT INTO device_vlan_assessments(
               assessment_id, assignment_id, run_id, authority_revision,
               assignment_revision, scope_id, configuration_observation_id,
               configuration_sha256, configuration_size_bytes,
               configuration_filename, summary_result_id, extractor_version,
               collection_contract, source_contract_json, coverage_json, recorded_at
           ) VALUES (
               ?, 'assignment-1', 'run-1', 1, 1, 'scope-1',
               'observation-1', ?, 100, 'router.txt', 'summary-1',
               ?, ?, '{}', '{}', 'now'
           )""",
        (assessment_id, "a" * 64, extractor_version, collection_contract),
    )


def _receipt(
    db: sqlite3.Connection, receipt_id: str, vlan_id: int,
    membership_relation: str = "declaration",
) -> None:
    db.execute(
        """INSERT INTO device_vlan_receipts(
               receipt_id, assessment_id, source_observation_id, source_role,
               source_filename, device_context, bridge_context, vlan_id, vlan_name,
               interface_name, membership_relation, evidence_state,
               source_line_number, source_line, related_line_number,
               related_source_line, source_command, source_section,
               source_syntax, facts_json
           ) VALUES (
               ?, 'assessment-1', 'observation-1', 'configuration', 'router.txt',
               'router-1', NULL, ?, NULL, NULL, ?, 'configured',
               1, 'vlan test', NULL, NULL, 'show running-config', 'vlan',
               'cisco_numeric', '{}'
           )""",
        (receipt_id, vlan_id, membership_relation),
    )


def test_v6_vlan_schema_is_exact_and_idempotent() -> None:
    db = sqlite3.connect(":memory:")
    create_device_vlan_schema(db)
    create_device_vlan_schema(db)

    names = {
        row[0] for row in db.execute(
            "SELECT name FROM sqlite_master WHERE name LIKE 'device_vlan_%'"
        )
    }

    assert names == set(DEVICE_VLAN_SCHEMA_OBJECTS)


def test_vlan_schema_retains_reserved_ids_but_rejects_out_of_range_values() -> None:
    db = sqlite3.connect(":memory:")
    create_device_vlan_schema(db)
    _assessment(db)
    _receipt(db, "receipt-0", 0)
    _receipt(db, "receipt-4095", 4095)

    with pytest.raises(sqlite3.IntegrityError):
        _receipt(db, "receipt-4096", 4096)

    assert db.execute(
        "SELECT vlan_id FROM device_vlan_receipts ORDER BY vlan_id"
    ).fetchall() == [(0,), (4095,)]


def test_vlan_assessments_and_receipts_are_immutable() -> None:
    db = sqlite3.connect(":memory:")
    create_device_vlan_schema(db)
    _assessment(db)
    _receipt(db, "receipt-10", 10)

    with pytest.raises(sqlite3.IntegrityError, match="immutable"):
        db.execute(
            "UPDATE device_vlan_assessments SET coverage_json = 'changed' "
            "WHERE assessment_id = 'assessment-1'"
        )
    with pytest.raises(sqlite3.IntegrityError, match="immutable"):
        db.execute("DELETE FROM device_vlan_assessments WHERE assessment_id = 'assessment-1'")
    with pytest.raises(sqlite3.IntegrityError, match="immutable"):
        db.execute(
            "UPDATE device_vlan_receipts SET vlan_name = 'changed' "
            "WHERE receipt_id = 'receipt-10'"
        )
    with pytest.raises(sqlite3.IntegrityError, match="immutable"):
        db.execute("DELETE FROM device_vlan_receipts WHERE receipt_id = 'receipt-10'")


def test_vlan_assessments_retain_old_versions_and_select_only_current_contract() -> None:
    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row
    create_device_vlan_schema(db)
    _assessment(db, "assessment-old", "device-vlan-observations:0")
    _assessment(db, "assessment-current")

    current = current_device_vlan_assessment_on_connection(
        db, assignment_id="assignment-1", collection_contract="built-in:test:1",
    )

    assert current is not None
    assert current["assessment_id"] == "assessment-current"
    assert db.execute("SELECT COUNT(*) FROM device_vlan_assessments").fetchone()[0] == 2
    with pytest.raises(sqlite3.IntegrityError):
        _assessment(db, "assessment-current-duplicate")


@pytest.mark.parametrize("relation", ["pvid", "declared_member"])
def test_vlan_receipts_keep_linux_and_generic_membership_terms(relation: str) -> None:
    db = sqlite3.connect(":memory:")
    create_device_vlan_schema(db)
    _assessment(db)
    _receipt(db, f"receipt-{relation}", 20, relation)

    assert db.execute(
        "SELECT membership_relation FROM device_vlan_receipts"
    ).fetchone()[0] == relation
