import json
import os

import pytest

import app.evidence_retirement_sources as retirement_sources

from app.database import connect_database
from app.evidence_retirement import (
    EvidenceRetirementBlocked,
    EvidenceRetirementError,
    retired_dependency,
    retire_evidence,
)
from app.evidence_retirement_sources import (
    ARKIME_SESSIONS_IMPORT,
    ARKIME_SUMMARY_IMPORT,
    DEVICE_COLLECTION,
    HOSTNAME_EVIDENCE_UPLOAD,
    NMAP_IMPORT,
    NMAP_SCAN_RUN,
    adapter_for_source,
    artifact_observation_dependency,
)
from app.evidence_retirement import init_evidence_retirement_storage


def _db(tmp_path):
    path = tmp_path / "analyzer.db"
    with connect_database(path) as db:
        db.executescript("""
            CREATE TABLE artifact_observations(
                observation_id TEXT PRIMARY KEY,source_kind TEXT,source_ref TEXT,
                original_filename TEXT
            );
            CREATE TABLE scan_runs(run_id TEXT PRIMARY KEY,status TEXT);
            CREATE TABLE device_collection_authority(
                run_id TEXT PRIMARY KEY,state TEXT,artifact_observation_id TEXT
            );
            CREATE TABLE device_collection_authority_inputs(
                run_id TEXT,input_role TEXT,position INTEGER,artifact_observation_id TEXT
            );
            CREATE TABLE arkime_imports(import_id TEXT PRIMARY KEY,observation_id TEXT);
            CREATE TABLE arkime_summary_imports(import_id TEXT PRIMARY KEY,observation_id TEXT);
            CREATE TABLE artifact_scope_assignments(
                assignment_id TEXT PRIMARY KEY,artifact_observation_id TEXT,scope_id TEXT
            );
        """)
    init_evidence_retirement_storage(path)
    return path


def _retire(path, family, encounter, **kwargs):
    return retire_evidence(
        path, source_family=family, encounter_id=encounter,
        actor="analyst", reason="operator requested retirement",
        adapter=adapter_for_source(family, **kwargs),
    )


def test_same_content_nmap_import_siblings_retire_independently(tmp_path):
    path = _db(tmp_path)
    with connect_database(path) as db:
        db.executemany(
            "INSERT INTO artifact_observations VALUES (?,?,?,?)",
            [
                ("obs-a", "nmap_import", "upload:a", "same.xml"),
                ("obs-b", "nmap_import", "upload:b", "same.xml"),
            ],
        )
    result = _retire(path, NMAP_IMPORT, "obs-a")
    assert result["identity_snapshot"]["identities"]["observation_id"] == "obs-a"
    with connect_database(path, read_only=True) as db:
        rows = db.execute(
            "SELECT encounter_id FROM evidence_retirement_events"
        ).fetchall()
    assert rows == [("obs-a",)]


def test_nmap_run_requires_completed_registered_encounter(tmp_path):
    path = _db(tmp_path)
    with connect_database(path) as db:
        db.execute("INSERT INTO scan_runs VALUES ('run-a','running')")
        db.execute(
            "INSERT INTO artifact_observations VALUES ('scan-obs','nmap_scan','run-a','scan.xml')"
        )
    with pytest.raises(EvidenceRetirementBlocked, match="still running"):
        _retire(path, NMAP_SCAN_RUN, "run-a")
    with connect_database(path) as db:
        db.execute("UPDATE scan_runs SET status='completed' WHERE run_id='run-a'")
    result = _retire(path, NMAP_SCAN_RUN, "run-a")
    assert result["identity_snapshot"]["identities"]["run_id"] == "run-a"
    with connect_database(path, read_only=True) as db:
        retired = retired_dependency(
            db, artifact_observation_dependency(NMAP_SCAN_RUN, "scan-obs"),
        )
    assert retired == (1, "run-a")


def test_legacy_nmap_run_without_observation_requires_backfill(tmp_path):
    path = _db(tmp_path)
    with connect_database(path) as db:
        db.execute("INSERT INTO scan_runs VALUES ('legacy','completed')")
    with pytest.raises(EvidenceRetirementError, match="backfill"):
        _retire(path, NMAP_SCAN_RUN, "legacy")


def test_device_collection_inherits_every_registered_child(tmp_path):
    path = _db(tmp_path)
    with connect_database(path) as db:
        db.execute("INSERT INTO device_collection_authority VALUES ('device-a','active','config-obs')")
        db.executemany(
            "INSERT INTO device_collection_authority_inputs VALUES (?,?,?,?)",
            [
                ("device-a", "configuration", 0, "config-obs"),
                ("device-a", "capture", 0, "capture-obs"),
            ],
        )
        db.executemany(
            "INSERT INTO artifact_observations VALUES (?,?,?,?)",
            [
                ("config-obs", "device_collection", "device-a", "config.txt"),
                ("capture-obs", "device_collection", "device-a", "capture.pcap"),
            ],
        )
        db.execute(
            "INSERT INTO artifact_scope_assignments VALUES ('scope-link','config-obs','scope-a')"
        )
    result = _retire(path, DEVICE_COLLECTION, "device-a")
    identities = result["identity_snapshot"]["identities"]
    assert set(value for key, value in identities.items() if key.startswith("artifact_")) == {
        "config-obs", "capture-obs",
    }


def test_scoped_manual_device_upload_uses_exact_active_authority(tmp_path):
    path = _db(tmp_path)
    with connect_database(path) as db:
        db.execute(
            "INSERT INTO device_collection_authority VALUES ('upload-a','active','upload-obs')"
        )
        db.execute(
            "INSERT INTO artifact_observations VALUES "
            "('upload-obs','device_config_upload','upload-a','router.cfg')"
        )
        db.execute(
            "INSERT INTO artifact_scope_assignments VALUES ('scope-link','upload-obs','scope-a')"
        )
    result = _retire(path, DEVICE_COLLECTION, "upload-a")
    identities = result["identity_snapshot"]["identities"]
    assert identities["run_id"] == "upload-a"
    assert identities["artifact_observation:upload-obs"] == "upload-obs"


@pytest.mark.parametrize("state", ["preparing", "deleted"])
def test_device_collection_refuses_non_active_authority(tmp_path, state):
    path = _db(tmp_path)
    with connect_database(path) as db:
        db.execute(
            "INSERT INTO device_collection_authority VALUES ('device-a',?,NULL)", (state,),
        )
    with pytest.raises(EvidenceRetirementBlocked):
        _retire(path, DEVICE_COLLECTION, "device-a")


@pytest.mark.parametrize(
    ("family", "table", "import_id", "observation_id"),
    [
        (ARKIME_SESSIONS_IMPORT, "arkime_imports", "arkime-a", "arkime-obs"),
        (ARKIME_SUMMARY_IMPORT, "arkime_summary_imports", "summary-a", "summary-obs"),
    ],
)
def test_arkime_imports_use_import_and_observation_identity(
    tmp_path, family, table, import_id, observation_id,
):
    path = _db(tmp_path)
    with connect_database(path) as db:
        db.execute(f"INSERT INTO {table} VALUES (?,?)", (import_id, observation_id))
    result = _retire(path, family, import_id)
    assert result["identity_snapshot"]["identities"] == {
        "encounter_id": import_id,
        "import_id": import_id,
        "observation_id": observation_id,
    }


def test_hostname_upload_uses_upload_identity_not_content_hash(tmp_path):
    path = _db(tmp_path)
    evidence = tmp_path / "hostname-evidence"
    evidence_id = "a" * 32
    upload = evidence / evidence_id
    upload.mkdir(parents=True)
    (upload / "source.csv").write_text("ip,hostname\n10.0.0.1,one\n", encoding="utf-8")
    (upload / "manifest.json").write_text(json.dumps({
        "evidence_id": evidence_id, "stored_name": "source.csv",
    }), encoding="utf-8")
    result = _retire(
        path, HOSTNAME_EVIDENCE_UPLOAD, evidence_id,
        hostname_evidence_dir=evidence,
    )
    identities = result["identity_snapshot"]["identities"]
    assert identities["evidence_id"] == evidence_id
    assert not any("sha" in name for name in identities)


@pytest.mark.parametrize("bad_id", ["..", "A" * 32, "a" * 31, "a" * 33])
def test_hostname_upload_refuses_noncanonical_identity(tmp_path, bad_id):
    path = _db(tmp_path)
    with pytest.raises(EvidenceRetirementError, match="identity"):
        _retire(
            path, HOSTNAME_EVIDENCE_UPLOAD, bad_id,
            hostname_evidence_dir=tmp_path / "hostname-evidence",
        )


@pytest.mark.parametrize("linked_item", ["directory", "manifest", "source"])
def test_hostname_upload_never_follows_linked_storage(tmp_path, linked_item):
    path = _db(tmp_path)
    evidence = tmp_path / "hostname-evidence"
    evidence.mkdir()
    evidence_id = "b" * 32
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "source.csv").write_text("ip,hostname\n10.0.0.1,one\n", encoding="utf-8")
    (outside / "manifest.json").write_text(json.dumps({
        "evidence_id": evidence_id, "stored_name": "source.csv",
    }), encoding="utf-8")
    upload = evidence / evidence_id
    if linked_item == "directory":
        upload.symlink_to(outside, target_is_directory=True)
    else:
        upload.mkdir()
        if linked_item == "manifest":
            (upload / "manifest.json").symlink_to(outside / "manifest.json")
            (upload / "source.csv").write_text("retained", encoding="utf-8")
        else:
            (upload / "manifest.json").write_text(json.dumps({
                "evidence_id": evidence_id, "stored_name": "source.csv",
            }), encoding="utf-8")
            (upload / "source.csv").symlink_to(outside / "source.csv")
    with pytest.raises(EvidenceRetirementError):
        _retire(
            path, HOSTNAME_EVIDENCE_UPLOAD, evidence_id,
            hostname_evidence_dir=evidence,
        )


@pytest.mark.parametrize("manifest_value", ["[]", '"text"', "null", "1"])
def test_hostname_upload_requires_manifest_object(tmp_path, manifest_value):
    path = _db(tmp_path)
    evidence = tmp_path / "hostname-evidence"
    evidence_id = "c" * 32
    upload = evidence / evidence_id
    upload.mkdir(parents=True)
    (upload / "manifest.json").write_text(manifest_value, encoding="utf-8")
    with pytest.raises(EvidenceRetirementError, match="object"):
        _retire(
            path, HOSTNAME_EVIDENCE_UPLOAD, evidence_id,
            hostname_evidence_dir=evidence,
        )


def test_hostname_upload_refuses_oversized_manifest_actual_bytes(
    tmp_path, monkeypatch,
):
    path = _db(tmp_path)
    evidence = tmp_path / "hostname-evidence"
    evidence_id = "d" * 32
    upload = evidence / evidence_id
    upload.mkdir(parents=True)
    (upload / "manifest.json").write_bytes(b'{"padding":"' + b"x" * 64 + b'"}')
    monkeypatch.setattr(retirement_sources, "MAX_HOSTNAME_MANIFEST_BYTES", 16)
    with pytest.raises(EvidenceRetirementError, match="invalid|large"):
        _retire(
            path, HOSTNAME_EVIDENCE_UPLOAD, evidence_id,
            hostname_evidence_dir=evidence,
        )


def test_hostname_fifo_manifest_refuses_without_waiting_for_writer(tmp_path):
    path = _db(tmp_path)
    evidence = tmp_path / "hostname-evidence"
    evidence_id = "e" * 32
    upload = evidence / evidence_id
    upload.mkdir(parents=True)
    os.mkfifo(upload / "manifest.json")
    with pytest.raises(EvidenceRetirementError, match="invalid"):
        _retire(
            path, HOSTNAME_EVIDENCE_UPLOAD, evidence_id,
            hostname_evidence_dir=evidence,
        )

