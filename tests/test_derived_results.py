from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path

import pytest

from app.artifacts import get_artifact_observation, init_artifact_storage, register_artifact_bytes
from app.database import connect_database
from app.derived_results import (
    associate_derived_result_observation,
    DerivedResultConflict,
    derived_result_identity,
    init_derived_result_storage,
    load_derived_result,
    prepare_derived_result,
    publish_derived_result,
)
import app.nmap_base_analysis as nmap_base
from app.nmap_base_analysis import analyze_registered_nmap_base
from app.main import parse_xml


XML = b'''<nmaprun scanner="nmap" version="7.95" args="nmap -n -sS 192.0.2.10" start="100">
<scaninfo type="syn" protocol="tcp" numservices="1" services="443"/>
<host starttime="101" endtime="109"><status state="up" reason="syn-ack"/>
<address addr="192.0.2.10" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="443"><state state="open" reason="syn-ack"/><service name="https"/></port>
</ports></host><runstats><finished time="110" exit="success"/><hosts up="1" down="0" total="1"/></runstats></nmaprun>'''


def observation(db: Path, content: bytes = XML, source_ref: str = "upload:one") -> dict:
    return register_artifact_bytes(
        db_path=db,
        content=content,
        source_kind="nmap_import",
        source_ref=source_ref,
        original_filename=f"{source_ref.split(':')[-1]}.xml",
        media_type="application/xml",
        actor="analyst",
    )


def identity(digest: str, *, version="family:1", parameters=None):
    return derived_result_identity(
        family="test_family",
        analysis_version=version,
        payload_schema_version=1,
        parameters=parameters or {},
        inputs=[{
            "role": "source",
            "kind": "artifact_sha256",
            "identity": digest,
            "metadata": {"media_family": "test"},
        }],
    )


def prepared(digest: str, payload=None, **kwargs):
    return prepare_derived_result(
        family="test_family",
        analysis_version=kwargs.get("version", "family:1"),
        payload_schema_version=1,
        parameters=kwargs.get("parameters") or {},
        inputs=[{
            "role": "source",
            "kind": "artifact_sha256",
            "identity": digest,
            "metadata": {"media_family": "test"},
        }],
        payload=payload if payload is not None else {"value": 1},
        generated_at="2030-01-01T00:00:00+00:00",
    )


def test_identity_changes_with_bytes_version_parameters_and_schema():
    base = identity("a" * 64)
    assert identity("b" * 64).computation_key != base.computation_key
    assert identity("a" * 64, version="family:2").computation_key != base.computation_key
    assert identity("a" * 64, parameters={"mode": "other"}).computation_key != base.computation_key
    schema_two = derived_result_identity(
        family="test_family",
        analysis_version="family:1",
        payload_schema_version=2,
        parameters={},
        inputs=[{
            "role": "source", "kind": "artifact_sha256",
            "identity": "a" * 64, "metadata": {"media_family": "test"},
        }],
    )
    assert schema_two.computation_key != base.computation_key


def test_publish_is_immutable_idempotent_and_preserves_observation_links(tmp_path):
    db = tmp_path / "nct.db"
    first = observation(db, source_ref="upload:first")
    second = observation(db, source_ref="upload:second")
    item = prepared(first["sha256"])
    first_publish = publish_derived_result(
        db, item,
        observation_links=[{"role": "source", "observation_id": first["observation_id"]}],
    )
    second_publish = publish_derived_result(
        db, item,
        observation_links=[{"role": "source", "observation_id": second["observation_id"]}],
    )
    assert first_publish["created"] is True
    assert second_publish == {**first_publish, "created": False}
    loaded = load_derived_result(db, item.identity)
    assert loaded["payload"] == {"value": 1}
    with connect_database(db, read_only=True) as connection:
        links = connection.execute(
            """SELECT observation_id FROM derived_result_observation_links
               WHERE result_id = ? ORDER BY observation_id""",
            (item.identity.result_id,),
        ).fetchall()
    assert [row[0] for row in links] == sorted([
        first["observation_id"], second["observation_id"],
    ])

    conflict = prepared(first["sha256"], payload={"value": 2})
    with pytest.raises(DerivedResultConflict):
        publish_derived_result(db, conflict)
    assert load_derived_result(db, item.identity)["payload"] == {"value": 1}


def test_publication_is_atomic_when_observation_disappears(tmp_path):
    db = tmp_path / "nct.db"
    item = prepared("a" * 64)
    with pytest.raises(KeyError):
        publish_derived_result(
            db, item,
            observation_links=[{"role": "source", "observation_id": "missing"}],
        )
    with connect_database(db, read_only=True) as connection:
        assert connection.execute("SELECT COUNT(*) FROM derived_results").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM derived_result_inputs").fetchone()[0] == 0


def test_concurrent_duplicate_publication_is_idempotent(tmp_path):
    db = tmp_path / "nct.db"
    source = observation(db)
    item = prepared(source["sha256"])

    def publish():
        return publish_derived_result(
            db, item,
            observation_links=[{
                "role": "source", "observation_id": source["observation_id"],
            }],
        )

    with ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(lambda _: publish(), range(12)))
    assert sum(result["created"] for result in results) == 1
    with connect_database(db, read_only=True) as connection:
        assert connection.execute("SELECT COUNT(*) FROM derived_results").fetchone()[0] == 1
        assert connection.execute(
            "SELECT COUNT(*) FROM derived_result_observation_links"
        ).fetchone()[0] == 1


def test_corrupt_retained_payload_fails_closed_without_source_changes(tmp_path):
    db = tmp_path / "nct.db"
    source = observation(db)
    item = prepared(source["sha256"])
    init_derived_result_storage(db)
    corrupt = '{"broken":'
    with connect_database(db) as connection:
        connection.execute(
            """INSERT INTO derived_results (
                   result_id, computation_key, family, analysis_version,
                   payload_schema_version, parameters_json, inputs_json,
                   result_json, result_sha256, generated_at
               ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                item.identity.result_id, item.identity.computation_key,
                item.identity.family, item.identity.analysis_version,
                item.identity.payload_schema_version, item.identity.parameters_json,
                item.identity.inputs_json, corrupt,
                hashlib.sha256(corrupt.encode()).hexdigest(), item.generated_at,
            ),
        )
        for input_row in json.loads(item.identity.inputs_json):
            connection.execute(
                """INSERT INTO derived_result_inputs VALUES (?, ?, ?, ?, ?)""",
                (
                    item.identity.result_id, input_row["role"], input_row["kind"],
                    input_row["identity"], json.dumps(
                        input_row["metadata"], sort_keys=True, separators=(",", ":"),
                    ),
                ),
            )
    with pytest.raises(DerivedResultConflict, match="unreadable"):
        load_derived_result(db, item.identity)
    assert get_artifact_observation(db, source["observation_id"])["sha256"] == source["sha256"]


def test_adapter_reuses_exact_bytes_but_preserves_each_observation(tmp_path, monkeypatch):
    db = tmp_path / "nct.db"
    first = observation(db, source_ref="upload:first")
    second = observation(db, source_ref="upload:second")
    calls = []

    def parser(content):
        calls.append(content)
        return parse_xml(content)

    monkeypatch.setattr(nmap_base, "_parse_nmap_xml", parser)
    original = parse_xml(XML)
    first_result = analyze_registered_nmap_base(db, first["observation_id"])
    second_result = analyze_registered_nmap_base(db, second["observation_id"])
    assert first_result["reused"] is False
    assert second_result["reused"] is True
    assert first_result["result_id"] == second_result["result_id"]
    assert first_result["payload"] == second_result["payload"] == original
    assert len(calls) == 1
    assert first_result["observation"]["observation_id"] != second_result["observation"]["observation_id"]
    with connect_database(db, read_only=True) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM derived_result_observation_links"
        ).fetchone()[0] == 2


def test_adapter_rejects_a_fixed_contract_override(tmp_path):
    db = tmp_path / "nct.db"
    source = observation(db)
    with pytest.raises(ValueError, match="fixed by the Nmap base-analysis contract"):
        analyze_registered_nmap_base(
            db,
            source["observation_id"],
            parameters={"parser": "different.parser"},
        )
    with connect_database(db, read_only=True) as connection:
        assert connection.execute("SELECT COUNT(*) FROM derived_results").fetchone()[0] == 0


def test_adapter_rejects_an_alternate_parser_entry_point(tmp_path):
    db = tmp_path / "nct.db"
    source = observation(db)
    init_derived_result_storage(db)
    with pytest.raises(TypeError, match="unexpected keyword argument 'parser'"):
        analyze_registered_nmap_base(
            db,
            source["observation_id"],
            parser=lambda _: {"invented": True},
        )
    with connect_database(db, read_only=True) as connection:
        assert connection.execute("SELECT COUNT(*) FROM derived_results").fetchone()[0] == 0


def test_reused_payload_is_loaded_fresh_from_immutable_storage(tmp_path):
    db = tmp_path / "nct.db"
    first = observation(db, source_ref="upload:first")
    second = observation(db, source_ref="upload:second")
    first_result = analyze_registered_nmap_base(db, first["observation_id"])
    first_result["payload"]["hosts"].clear()

    second_result = analyze_registered_nmap_base(db, second["observation_id"])

    assert second_result["reused"] is True
    assert second_result["payload"] == parse_xml(XML)


def test_adapter_changed_same_size_bytes_and_mtime_cannot_reuse(tmp_path, monkeypatch):
    db = tmp_path / "nct.db"
    changed = XML.replace(b"443", b"444")
    assert len(changed) == len(XML)
    first = observation(db, XML, "upload:first")
    second = observation(db, changed, "upload:second")
    first_path = Path(get_artifact_observation(db, first["observation_id"])["canonical_path"])
    second_path = Path(get_artifact_observation(db, second["observation_id"])["canonical_path"])
    same_time = 1_700_000_000
    os.utime(first_path, (same_time, same_time))
    os.utime(second_path, (same_time, same_time))
    calls = []

    def parser(content):
        calls.append(content)
        return {"digest": hashlib.sha256(content).hexdigest()}

    monkeypatch.setattr(nmap_base, "_parse_nmap_xml", parser)
    first_result = analyze_registered_nmap_base(db, first["observation_id"])
    second_result = analyze_registered_nmap_base(db, second["observation_id"])
    assert first_result["result_id"] != second_result["result_id"]
    assert len(calls) == 2


def test_adapter_rejects_corrupt_canonical_bytes_before_reuse(tmp_path):
    db = tmp_path / "nct.db"
    source = observation(db)
    first = analyze_registered_nmap_base(db, source["observation_id"])
    path = Path(get_artifact_observation(db, source["observation_id"])["canonical_path"])
    path.write_bytes(b"x" * len(XML))
    with pytest.raises(ValueError, match="exact-content verification"):
        analyze_registered_nmap_base(db, source["observation_id"])
    with connect_database(db, read_only=True) as connection:
        assert connection.execute("SELECT COUNT(*) FROM derived_results").fetchone()[0] == 1
    assert first["reused"] is False


def test_observation_deletion_does_not_block_or_delete_disposable_result(tmp_path):
    db = tmp_path / "nct.db"
    source = observation(db)
    result = analyze_registered_nmap_base(db, source["observation_id"])
    with connect_database(db) as connection:
        connection.execute(
            "DELETE FROM artifact_observations WHERE observation_id = ?",
            (source["observation_id"],),
        )
    with connect_database(db, read_only=True) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM derived_results WHERE result_id = ?",
            (result["result_id"],),
        ).fetchone()[0] == 1
        assert connection.execute(
            "SELECT COUNT(*) FROM derived_result_observation_links"
        ).fetchone()[0] == 0


def test_association_uses_the_saved_manifest_and_rejects_a_forged_identity(tmp_path):
    db = tmp_path / "nct.db"
    first = observation(db, source_ref="upload:first")
    second = observation(db, content=XML.replace(b"443", b"444"), source_ref="upload:second")
    item = prepared(first["sha256"])
    publish_derived_result(
        db,
        item,
        observation_links=[{"role": "source", "observation_id": first["observation_id"]}],
    )
    forged = replace(item.identity, inputs_json=identity(second["sha256"]).inputs_json)

    with pytest.raises(DerivedResultConflict, match="does not match its computation key"):
        associate_derived_result_observation(
            db,
            forged,
            role="source",
            observation_id=second["observation_id"],
        )

    with connect_database(db, read_only=True) as connection:
        rows = connection.execute(
            """SELECT input.input_identity, link.observation_id
               FROM derived_result_inputs input
               LEFT JOIN derived_result_observation_links link
                 ON link.result_id = input.result_id AND link.input_role = input.input_role
               WHERE input.result_id = ?""",
            (item.identity.result_id,),
        ).fetchall()
    assert rows == [(first["sha256"], first["observation_id"])]


def test_publication_rejects_inconsistent_identity_and_payload_hash(tmp_path):
    db = tmp_path / "nct.db"
    source = observation(db)
    item = prepared(source["sha256"])

    with pytest.raises(DerivedResultConflict, match="does not match its computation key"):
        publish_derived_result(
            db,
            replace(item, identity=replace(item.identity, family="different_family")),
        )
    with pytest.raises(DerivedResultConflict, match="payload hash is inconsistent"):
        publish_derived_result(db, replace(item, result_sha256="0" * 64))

    init_derived_result_storage(db)
    with connect_database(db, read_only=True) as connection:
        assert connection.execute("SELECT COUNT(*) FROM derived_results").fetchone()[0] == 0


def test_initialization_retries_after_failure_and_database_replacement(tmp_path, monkeypatch):
    import app.derived_results as derived

    db = tmp_path / "nct.db"
    init_artifact_storage(db)
    original = derived.connect_database
    attempts = {"count": 0}

    def fail_once(path, **kwargs):
        attempts["count"] += 1
        if attempts["count"] == 1:
            raise RuntimeError("setup failed")
        return original(path, **kwargs)

    monkeypatch.setattr(derived, "connect_database", fail_once)
    with pytest.raises(RuntimeError):
        init_derived_result_storage(db)
    init_derived_result_storage(db)
    with original(db, read_only=True) as connection:
        assert connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='derived_results'"
        ).fetchone() == (1,)

    replacement = tmp_path / "replacement.db"
    init_artifact_storage(replacement)
    replacement.replace(db)
    init_derived_result_storage(db)
    with original(db, read_only=True) as connection:
        assert connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='derived_results'"
        ).fetchone() == (1,)


def test_read_succeeds_while_wal_writer_is_pending(tmp_path):
    db = tmp_path / "nct.db"
    source = observation(db)
    item = prepared(source["sha256"])
    publish_derived_result(db, item)
    writer = connect_database(db)
    try:
        writer.execute("BEGIN IMMEDIATE")
        writer.execute(
            "UPDATE artifact_registry SET last_seen_at = last_seen_at WHERE sha256 = ?",
            (source["sha256"],),
        )
        assert load_derived_result(db, item.identity)["payload"] == {"value": 1}
    finally:
        writer.rollback()
        writer.close()
