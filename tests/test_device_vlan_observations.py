from __future__ import annotations

import sqlite3

import pytest

from app import device_vlan_observations as vlan_module
from app.device_vlan_observations import (
    DEVICE_VLAN_EXTRACTOR,
    DEVICE_VLAN_SCHEMA_OBJECTS,
    create_device_vlan_schema,
    current_device_vlan_assessment_on_connection,
    extract_device_vlan_observations,
    get_device_vlan_observation_status,
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


def test_vlan_status_read_does_not_create_a_missing_database(tmp_path) -> None:
    db_path = tmp_path / "missing.db"

    status = get_device_vlan_observation_status(db_path, "missing-run")
    assert status["state"] == "needs_scope"
    assert status["assignment"] is None
    assert status["assessment"] is None
    assert status["claims"]["live_status"] is False
    assert "retained device evidence" in status["meaning"]
    assert not db_path.exists()


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


def test_vlan_extractor_preserves_cisco_source_lines_and_explicit_relations() -> None:
    extracted = extract_device_vlan_observations(
        b"""vlan 10
 name USERS
interface GigabitEthernet1/0/1
 switchport mode access
 switchport access vlan 10
interface GigabitEthernet1/0/48
 switchport mode trunk
 switchport trunk native vlan 10
 switchport trunk allowed vlan 10,20-21
""",
        device_context="run-cisco",
    )

    assert [(item["vlan_id"], item["membership_relation"]) for item in extracted["receipts"]] == [
        (10, "declaration"),
        (10, "access"),
        (10, "native"),
        (10, "allowed"),
        (20, "allowed"),
        (21, "allowed"),
    ]
    declaration = extracted["receipts"][0]
    assert declaration["vlan_name"] == "USERS"
    assert declaration["source_line_number"] == 1
    assert declaration["related_line_number"] == 2
    assert extracted["coverage"]["unsupported_line_count"] == 0
    assert extracted["coverage"]["absence_supported"] is False


def test_vlan_extractor_keeps_juniper_declared_membership_and_linux_pvid_distinct() -> None:
    juniper = extract_device_vlan_observations(
        b"""set vlans mission vlan-id 4095
set interfaces ge-0/0/1 unit 0 family ethernet-switching vlan members mission
set interfaces ge-0/0/1 unit 0 family ethernet-switching native-vlan-id 0
""",
        device_context="run-juniper",
    )
    assert [(item["vlan_id"], item["membership_relation"]) for item in juniper["receipts"]] == [
        (4095, "declaration"), (4095, "declared_member"), (0, "native"),
    ]

    linux = extract_device_vlan_observations(
        b"""===== bridge vlan show =====
eth2 20 PVID Egress Untagged
eth3 20 Egress
""",
        device_context="run-linux",
    )
    assert [(item["interface_name"], item["membership_relation"]) for item in linux["receipts"]] == [
        ("eth2", "pvid"), ("eth2", "untagged"), ("eth3", "tagged"),
    ]
    assert {item["evidence_state"] for item in linux["receipts"]} == {"observed"}
    assert linux["coverage"]["unsupported_line_count"] == 0


def test_vlan_extractor_retains_common_wrapped_cisco_and_linux_rows() -> None:
    cisco = extract_device_vlan_observations(
        b"""===== show vlan brief =====
10 USERS active Gi1/0/1, Gi1/0/2,
                Gi1/0/3, Gi1/0/4
""",
        device_context="wrapped-cisco",
    )
    assert [
        (item["vlan_id"], item["interface_name"])
        for item in cisco["receipts"] if item["interface_name"]
    ] == [
        (10, "Gi1/0/1"), (10, "Gi1/0/2"),
        (10, "Gi1/0/3"), (10, "Gi1/0/4"),
    ]
    assert cisco["coverage"]["collection_state"] == "supported"

    linux = extract_device_vlan_observations(
        b"""===== bridge vlan show =====
port              vlan-id
eth0              1 PVID Egress Untagged
                  10
                  20-22 Egress Untagged
""",
        device_context="wrapped-linux",
    )
    assert [
        (item["vlan_id"], item["interface_name"], item["membership_relation"])
        for item in linux["receipts"]
    ] == [
        (1, "eth0", "pvid"), (1, "eth0", "untagged"),
        (10, "eth0", "tagged"),
        (20, "eth0", "untagged"), (21, "eth0", "untagged"),
        (22, "eth0", "untagged"),
    ]
    assert linux["coverage"]["collection_state"] == "supported"


def test_vlan_extractor_byte_bounds_related_multibyte_name(monkeypatch) -> None:
    monkeypatch.setattr(vlan_module, "MAX_VLAN_SOURCE_LINE_BYTES", 32)
    extracted = extract_device_vlan_observations(
        ("vlan 20\n name " + ("é" * 20) + "\n").encode(),
        device_context="multibyte-name",
    )

    assert len(extracted["receipts"]) == 1
    assert extracted["receipts"][0]["vlan_name"] is None
    assert extracted["receipts"][0]["related_source_line"] is None
    assert extracted["coverage"]["overlong_line_count"] == 1
    assert extracted["coverage"]["collection_state"] == "partial"


def test_vlan_extractor_makes_partial_and_unsupported_coverage_visible(monkeypatch) -> None:
    monkeypatch.setattr(vlan_module, "MAX_VLAN_SOURCE_LINE_BYTES", 30)
    extracted = extract_device_vlan_observations(
        b"switchport trunk allowed vlan all\n" + b"x" * 40 + b" vlan 20\n\xff\n",
        device_context="run-partial",
    )

    coverage = extracted["coverage"]
    assert extracted["receipts"] == []
    assert coverage["collection_state"] == "unknown"
    assert coverage["collection_state_label"].startswith("No supported VLAN evidence")
    assert coverage["not_collected_supported"] is False
    assert coverage["decoding_loss"] is True
    assert coverage["overlong_line_count"] == 2
    assert coverage["unsupported_line_count"] >= 2
    assert coverage["absence_supported"] is False


def test_vlan_extractor_distinguishes_supported_partial_unsupported_and_unknown() -> None:
    supported = extract_device_vlan_observations(
        b"interface Gi0/1\n switchport access vlan 20\n",
        device_context="supported",
    )
    partial = extract_device_vlan_observations(
        b"interface Gi0/1\n switchport access vlan 20\n"
        b"switchport trunk allowed vlan all\n",
        device_context="partial",
    )
    unsupported = extract_device_vlan_observations(
        b"switchport trunk allowed vlan all\n",
        device_context="unsupported",
    )
    unknown = extract_device_vlan_observations(
        b"ordinary retained output\n",
        device_context="unknown",
    )

    assert supported["coverage"]["collection_state"] == "supported"
    assert partial["coverage"]["collection_state"] == "partial"
    assert unsupported["coverage"]["collection_state"] == "unsupported"
    assert unknown["coverage"]["collection_state"] == "unknown"
    assert all(
        result["coverage"]["not_collected_supported"] is False
        for result in (supported, partial, unsupported, unknown)
    )


def test_vlan_extractor_bounds_receipts_without_claiming_absence(monkeypatch) -> None:
    monkeypatch.setattr(vlan_module, "MAX_VLAN_RECEIPTS", 2)
    extracted = extract_device_vlan_observations(
        b"""interface Gi0/1
 switchport trunk allowed vlan 1-4
""",
        device_context="bounded-run",
    )

    assert [item["vlan_id"] for item in extracted["receipts"]] == [1, 2]
    assert extracted["coverage"]["receipt_limit_reached"] is True
    assert extracted["coverage"]["absence_supported"] is False


def test_vlan_extractor_bounds_source_lines_without_claiming_absence(monkeypatch) -> None:
    monkeypatch.setattr(vlan_module, "MAX_VLAN_SOURCE_LINES", 1)
    extracted = extract_device_vlan_observations(
        b"vlan 1\nvlan 2\n", device_context="line-bounded-run",
    )

    assert [item["vlan_id"] for item in extracted["receipts"]] == [1]
    assert extracted["coverage"]["line_limit_reached"] is True
    assert extracted["coverage"]["source_line_count"] == 2
    assert extracted["coverage"]["processed_line_count"] == 1
    assert extracted["coverage"]["absence_supported"] is False


def test_vlan_extractor_fails_closed_at_processing_deadline(monkeypatch) -> None:
    moments = iter((0.0, 20.0))
    monkeypatch.setattr(vlan_module.time, "monotonic", lambda: next(moments))
    with pytest.raises(ValueError, match="processing-time limit"):
        extract_device_vlan_observations(
            (b"description ordinary line\n" * 256),
            device_context="deadline-run",
        )


def test_vlan_extractor_does_not_execute_commands(monkeypatch) -> None:
    def forbidden(*_args, **_kwargs):
        raise AssertionError("VLAN extraction must not start a process or contact a device")

    monkeypatch.setattr("subprocess.run", forbidden)
    extracted = extract_device_vlan_observations(
        b"vlan 20\n name VOICE\n", device_context="offline-run",
    )

    assert extracted["receipts"][0]["vlan_id"] == 20
