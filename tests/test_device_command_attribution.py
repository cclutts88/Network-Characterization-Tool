from __future__ import annotations

from pathlib import Path

from app import device_command_attribution as attribution
from app.device_configs import (
    command_execution_receipts,
    parse_command_history,
)
from app.device_collection_authority import (
    DeviceCollectionIntegrityError,
    collected_device_manifest_semantics,
)
import pytest


IDENTITY = {
    "scope_id": "scope-a",
    "device_address": "10.0.0.1",
    "ssh_port": 22,
    "username": "collector",
    "vendor": "cisco",
}


def _source(run_id: str, *, identity: dict = IDENTITY, receipts: list[dict] | None = None,
            started: str = "2026-10-25T12:10:00Z") -> dict:
    return {
        "run_id": run_id,
        "semantic_sha256": f"sha-{run_id}",
        "semantics": {
            "device_identity": identity,
            "contact_started_at": started,
            "command_execution_receipts": receipts or [],
        },
    }


def _receipt(receipt_id: str = "receipt-1", command: str = "show version") -> dict:
    return {
        "receipt_id": receipt_id,
        "sequence": 1,
        "command": command,
        "device_identity": IDENTITY,
        "contact_started_at": "2026-10-25T11:59:00Z",
        "contact_completed_at": "2026-10-25T12:00:00Z",
        "execution_status": "sent_in_completed_authenticated_session",
        "acknowledgement": "session_completed_command_not_individually_acknowledged",
    }


def test_receipts_exist_only_for_completed_authenticated_session():
    manifest = {
        "run_id": "prior", "status": "completed",
        "contact_started_at": "2026-10-25T11:59:00Z",
        "completed_at": "2026-10-25T12:00:00Z",
        **IDENTITY,
        "preferred_scope_id": "scope-a",
    }
    receipts = command_execution_receipts(manifest, ["show version", "show interfaces"])
    assert [item["sequence"] for item in receipts] == [1, 2]
    assert all(item["execution_status"] == "sent_in_completed_authenticated_session" for item in receipts)
    assert command_execution_receipts({**manifest, "status": "interrupted"}, ["show version"]) == []


def test_receipt_is_frozen_into_semantics_and_tampering_is_rejected():
    manifest = {
        "run_id": "prior", "status": "completed", "vendor": "cisco",
        "commands": ["show version"], "history_command": "show history",
        "contact_started_at": "2026-10-25T11:59:00Z",
        "completed_at": "2026-10-25T12:00:00Z",
        "device_address": "10.0.0.1", "username": "collector", "ssh_port": 22,
        "preferred_scope_id": "scope-a", "command_receipt_schema_version": 1,
    }
    manifest["command_execution_receipts"] = command_execution_receipts(
        manifest, manifest["commands"]
    )
    semantics = collected_device_manifest_semantics(manifest)
    assert semantics["command_execution_receipts"][0]["receipt_id"]
    manifest["command_execution_receipts"][0]["device_identity"]["scope_id"] = "scope-b"
    with pytest.raises(DeviceCollectionIntegrityError):
        collected_device_manifest_semantics(manifest)
    manifest["command_execution_receipts"] = command_execution_receipts(
        manifest, manifest["commands"]
    )
    manifest["command_execution_receipts"][0]["acknowledgement"] = "confirmed"
    with pytest.raises(DeviceCollectionIntegrityError):
        collected_device_manifest_semantics(manifest)
    manifest["command_execution_receipts"] = command_execution_receipts(
        manifest, manifest["commands"]
    )
    manifest["command_execution_receipts"][0]["normalized_command"] = "show VERSION"
    with pytest.raises(DeviceCollectionIntegrityError):
        collected_device_manifest_semantics(manifest)


def test_parser_preserves_valid_neighbors_raw_lines_timestamps_and_errors():
    result = parse_command_history(
        "[2026-10-25T12:00:02Z] 1 edge# show version\n"
        "% Invalid input detected\n"
        "3 show interfaces\n",
        True,
    )
    assert len(result["entries"]) == 2
    assert result["entries"][0]["command"] == "show version"
    assert result["entries"][0]["observed_at"] == "2026-10-25T12:00:02Z"
    assert result["entries"][0]["raw_line"].startswith("[")
    assert result["parse_errors"] == [
        {"line_number": 2, "raw_line": "% Invalid input detected"}
    ]
    assert len(result["source_sha256"]) == 64


def test_normalization_does_not_erase_case_sensitive_arguments():
    result = parse_command_history(
        "1 show run | include CustomerA\n",
        True,
        nct_commands=["show run | include customera"],
    )
    assert result["entries"][0]["classification"] == "unmatched"


def test_verified_receipt_is_possible_without_direct_occurrence_link(monkeypatch):
    history = parse_command_history(
        "[2026-10-25T12:00:01Z] 1 show version\n2 show version\n", True
    )
    sources = [
        _source("current"),
        _source("prior", receipts=[_receipt()]),
    ]
    monkeypatch.setattr(attribution, "_active_semantics", lambda _path: sources)
    result = attribution.assess_command_attribution(
        history, run_id="current", db_path=Path("unused.db")
    )
    assert result["confirmed_nct_count"] == 0
    assert result["possible_nct_count"] == 2
    assert result["linked_receipt_count"] == 1
    assert len(result["entries"][0]["receipt_refs"]) == 1
    assert result["entries"][1]["receipt_refs"] == []
    assert "retained timing" in result["entries"][0]["label"]


def test_untimed_receipt_match_does_not_claim_occurrence_timing(monkeypatch):
    history = parse_command_history("1 show version\n", True)
    sources = [_source("current"), _source("prior", receipts=[_receipt()])]
    monkeypatch.setattr(attribution, "_active_semantics", lambda _path: sources)
    result = attribution.assess_command_attribution(
        history, run_id="current", db_path=Path("unused.db")
    )
    label = result["entries"][0]["label"]
    assert "history lacks an occurrence time" in label
    assert "and timing" not in label


def test_direct_occurrence_link_can_be_confirmed(monkeypatch):
    history = parse_command_history(
        "[2026-10-25T12:00:01Z] 1 show version\n", True
    )
    history["entries"][0]["occurrence_receipt_id"] = "receipt-1"
    sources = [_source("current"), _source("prior", receipts=[_receipt()])]
    monkeypatch.setattr(attribution, "_active_semantics", lambda _path: sources)
    result = attribution.assess_command_attribution(
        history, run_id="current", db_path=Path("unused.db")
    )
    assert result["confirmed_nct_count"] == 1
    assert result["entries"][0]["attribution_basis"] == "occurrence_receipt_id"


def test_same_address_in_different_scope_does_not_link_receipt(monkeypatch):
    history = parse_command_history("1 show version\n", True)
    other_identity = {**IDENTITY, "scope_id": "scope-b"}
    sources = [
        _source("current"),
        _source("prior", identity=other_identity, receipts=[_receipt()]),
    ]
    monkeypatch.setattr(attribution, "_active_semantics", lambda _path: sources)
    result = attribution.assess_command_attribution(
        history, run_id="current", db_path=Path("unused.db")
    )
    assert result["linked_receipt_count"] == 0
    assert result["entries"][0]["attribution_basis"] == "known_template_only"


def test_truncated_and_historical_collections_explain_limits(monkeypatch):
    history = parse_command_history("1 show version\n", True)
    monkeypatch.setattr(attribution, "_active_semantics", lambda _path: [])
    result = attribution.assess_command_attribution(
        history, run_id="historical", db_path=Path("unused.db"), history_truncated=True
    )
    assert any("predates verified" in item for item in result["limitations"])
    assert any("collection limit" in item for item in result["limitations"])
