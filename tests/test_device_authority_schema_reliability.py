from __future__ import annotations

import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import threading
import time

import pytest

from app import device_collection_authority, device_evidence_catalog
from app.database import configure_database, connect_database
from app.device_collection_authority import init_device_collection_authority_storage
from app import schema_compatibility as schema
from app.schema_compatibility import schema_fingerprint


AUTHORITY_REFRESH_TRIGGERS = (
    "device_collection_authority_identity_immutable",
    "device_collection_authority_legal_transition",
    "device_collection_authority_inputs_no_update",
    "device_collection_authority_inputs_no_delete",
)
CATALOG_REFRESH_TRIGGERS = (
    "device_evidence_catalog_authority_insert",
    "device_evidence_catalog_authority_update",
)
REFRESH_TRIGGERS = AUTHORITY_REFRESH_TRIGGERS + CATALOG_REFRESH_TRIGGERS


def _schema_snapshot(db_path: Path) -> tuple[str, tuple[tuple, ...]]:
    with connect_database(db_path, read_only=True) as db:
        return (
            schema_fingerprint(db),
            tuple(
                db.execute(
                    """SELECT type, name, tbl_name, sql
                       FROM sqlite_master
                       WHERE name LIKE 'device_collection_authority%'
                          OR name LIKE 'device_evidence_catalog%'
                       ORDER BY type, name"""
                ).fetchall()
            ),
        )


def _data_snapshot(db_path: Path) -> dict[str, tuple[tuple, ...]]:
    tables = (
        "device_collection_authority",
        "device_collection_authority_inputs",
        "device_evidence_catalog",
        "device_evidence_catalog_dirty",
        "device_evidence_catalog_meta",
    )
    with connect_database(db_path, read_only=True) as db:
        return {
            table: tuple(db.execute(f"SELECT * FROM {table} ORDER BY 1").fetchall())
            for table in tables
        }


def _seed_populated_database(db_path: Path) -> None:
    configure_database(db_path)
    init_device_collection_authority_storage(db_path)
    stamp = "2030-01-01T00:00:00+00:00"
    artifact_sha = "a" * 64
    semantics = json.dumps({"device": "active"}, sort_keys=True, separators=(",", ":"))
    semantics_sha = "b" * 64
    with connect_database(db_path) as db:
        db.execute(
            """INSERT INTO artifact_registry (
                   sha256, size_bytes, media_type, canonical_path,
                   first_seen_at, last_seen_at
               ) VALUES (?, 1, 'text/plain', 'artifacts/a', ?, ?)""",
            (artifact_sha, stamp, stamp),
        )
        db.execute(
            """INSERT INTO artifact_observations (
                   observation_id, sha256, source_kind, source_ref,
                   observed_at, metadata_json
               ) VALUES ('observation-active', ?, 'device_upload', 'active-run', ?, '{}')""",
            (artifact_sha, stamp),
        )
        db.execute(
            """INSERT INTO device_collection_authority (
                   run_id, state, revision, created_at
               ) VALUES ('preparing-run', 'preparing', 1, ?)""",
            (stamp,),
        )
        db.execute(
            """INSERT INTO device_collection_authority_inputs (
                   run_id, input_role, position, source_kind, identity, metadata_json
               ) VALUES ('preparing-run', 'configuration', 0, 'absent',
                         'not-provided', '{}')"""
        )
        db.execute(
            """INSERT INTO device_collection_authority (
                   run_id, state, revision, artifact_observation_id,
                   artifact_sha256, retained_filename, selection_contract,
                   semantic_manifest_json, semantic_manifest_sha256,
                   created_at, activated_at
               ) VALUES ('active-run', 'active', 1, 'observation-active', ?,
                         'configuration.txt', 'manual-upload-single-file:1', ?, ?, ?, ?)""",
            (artifact_sha, semantics, semantics_sha, stamp, stamp),
        )
        db.execute(
            """INSERT INTO device_collection_authority (
                   run_id, state, revision, created_at, deleted_at
               ) VALUES ('deleted-run', 'deleted', 2, ?, ?)""",
            (stamp, stamp),
        )
        db.execute(
            """INSERT INTO device_evidence_catalog (
                   run_id, device_key, completed_at, created_at, status, operation,
                   manifest_json, manifest_sha256, authority_revision,
                   selection_contract, semantic_manifest_sha256
               ) VALUES ('active-run', 'ip:192.0.2.10', ?, ?, 'uploaded',
                         'manual_upload', '{}', ?, 1,
                         'manual-upload-single-file:1', ?)""",
            (stamp, stamp, "c" * 64, semantics_sha),
        )
        db.execute("DELETE FROM device_evidence_catalog_dirty")
        db.execute(
            """INSERT INTO device_evidence_catalog_meta(singleton, schema_version)
               VALUES (1, 1)"""
        )


def _phase_five_version_seven_database(db_path: Path) -> None:
    fixture = Path(__file__).parent / "fixtures" / "phase5_r1_schema.sql"
    with sqlite3.connect(db_path) as db:
        db.executescript(fixture.read_text())
        fingerprint = schema_fingerprint(db)
        for version, identity in enumerate(schema.MIGRATION_PLAN[:7], 1):
            db.execute(
                "INSERT INTO nct_schema_migrations VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    identity,
                    version,
                    "0.16.0-range-test-20261025-phase5-r1",
                    "be92fb78e938adc3fced581629d4609ac0a43f6a",
                    "completed",
                    1,
                    "fixture",
                    "fixture",
                    "fixture",
                    fingerprint,
                    fingerprint,
                    None,
                ),
            )
        db.execute(
            "INSERT INTO nct_schema_state VALUES (1,7,7,?,?,?,?,?,?)",
            (
                schema.DATA_LAYOUT_CONTRACT,
                schema.migration_plan_digest(schema.MIGRATION_PLAN[:7]),
                fingerprint,
                "0.16.0-range-test-20261025-phase5-r1",
                "be92fb78e938adc3fced581629d4609ac0a43f6a",
                "fixture",
            ),
        )


def _connect_refusing_trigger(
    original_connect, action_code: int, trigger_name: str,
):
    def connect(*args, **kwargs):
        db = original_connect(*args, **kwargs)

        def authorize(action, name, _table, _database, _source):
            if action == action_code and name == trigger_name:
                return sqlite3.SQLITE_DENY
            return sqlite3.SQLITE_OK

        db.set_authorizer(authorize)
        return db

    return connect


def _assert_authority_guards(db_path: Path) -> None:
    statements = (
        "DELETE FROM device_collection_authority WHERE run_id='active-run'",
        "UPDATE device_collection_authority SET artifact_sha256='changed' "
        "WHERE run_id='active-run'",
        "UPDATE device_collection_authority SET state='preparing' "
        "WHERE run_id='preparing-run'",
        "UPDATE device_collection_authority SET state='active', deleted_at=NULL "
        "WHERE run_id='deleted-run'",
        "UPDATE device_collection_authority_inputs SET identity='changed' "
        "WHERE run_id='preparing-run'",
        "DELETE FROM device_collection_authority_inputs "
        "WHERE run_id='preparing-run'",
    )
    for statement in statements:
        with connect_database(db_path) as db:
            with pytest.raises(sqlite3.IntegrityError):
                db.execute(statement)


@pytest.mark.parametrize("action_code", [sqlite3.SQLITE_DROP_TRIGGER, sqlite3.SQLITE_CREATE_TRIGGER])
@pytest.mark.parametrize("trigger_name", REFRESH_TRIGGERS)
def test_every_trigger_refresh_boundary_rolls_back_atomically(
    tmp_path, monkeypatch, action_code, trigger_name,
):
    db_path = tmp_path / "analyzer.db"
    _seed_populated_database(db_path)
    before_schema = _schema_snapshot(db_path)
    before_data = _data_snapshot(db_path)
    original_connect = device_collection_authority.connect_database
    with monkeypatch.context() as patch:
        patch.setattr(
            device_collection_authority,
            "connect_database",
            _connect_refusing_trigger(original_connect, action_code, trigger_name),
        )
        with pytest.raises(sqlite3.DatabaseError, match="not authorized"):
            init_device_collection_authority_storage.__wrapped__(db_path)

    assert _schema_snapshot(db_path) == before_schema
    assert _data_snapshot(db_path) == before_data
    init_device_collection_authority_storage.__wrapped__(db_path)
    assert _schema_snapshot(db_path) == before_schema
    assert _data_snapshot(db_path) == before_data
    _assert_authority_guards(db_path)


def test_failed_public_initializer_is_not_cached_and_retries(tmp_path, monkeypatch):
    db_path = tmp_path / "retry.db"
    original_connect = device_collection_authority.connect_database
    with monkeypatch.context() as patch:
        patch.setattr(
            device_collection_authority,
            "connect_database",
            _connect_refusing_trigger(
                original_connect,
                sqlite3.SQLITE_CREATE_TRIGGER,
                "device_evidence_catalog_authority_update",
            ),
        )
        with pytest.raises(sqlite3.DatabaseError, match="not authorized"):
            init_device_collection_authority_storage(db_path)

    init_device_collection_authority_storage(db_path)
    with connect_database(db_path, read_only=True) as db:
        names = {
            row[0]
            for row in db.execute(
                "SELECT name FROM sqlite_master WHERE type='trigger'"
            ).fetchall()
        }
    assert set(REFRESH_TRIGGERS).issubset(names)


def test_standalone_catalog_refresh_owns_atomic_rollback(tmp_path):
    db_path = tmp_path / "catalog-only.db"
    _seed_populated_database(db_path)
    before_schema = _schema_snapshot(db_path)
    before_data = _data_snapshot(db_path)
    with connect_database(db_path) as db:
        db.set_authorizer(
            lambda action, name, *_: (
                sqlite3.SQLITE_DENY
                if action == sqlite3.SQLITE_CREATE_TRIGGER
                and name == "device_evidence_catalog_authority_update"
                else sqlite3.SQLITE_OK
            )
        )
        with pytest.raises(sqlite3.DatabaseError, match="not authorized"):
            device_evidence_catalog.ensure_device_evidence_catalog_schema(db)
    assert _schema_snapshot(db_path) == before_schema
    assert _data_snapshot(db_path) == before_data


def test_phase_five_schema_and_saved_fingerprint_are_unchanged(tmp_path):
    db_path = tmp_path / "phase-five.db"
    _phase_five_version_seven_database(db_path)
    before_schema = _schema_snapshot(db_path)
    with connect_database(db_path, read_only=True) as db:
        before_state = db.execute("SELECT * FROM nct_schema_state").fetchall()
        before_history = db.execute(
            "SELECT * FROM nct_schema_migrations ORDER BY target_schema_version"
        ).fetchall()

    init_device_collection_authority_storage.__wrapped__(db_path)

    assert _schema_snapshot(db_path) == before_schema
    with connect_database(db_path, read_only=True) as db:
        assert db.execute("SELECT * FROM nct_schema_state").fetchall() == before_state
        assert db.execute(
            "SELECT * FROM nct_schema_migrations ORDER BY target_schema_version"
        ).fetchall() == before_history


def test_saved_fingerprint_damage_is_refused_before_initializer(tmp_path):
    db_path = tmp_path / "damaged-v7.db"
    _phase_five_version_seven_database(db_path)
    with sqlite3.connect(db_path) as db:
        db.execute("DROP TRIGGER device_collection_authority_identity_immutable")

    with pytest.raises(schema.SchemaCompatibilityError, match="fingerprint"):
        schema.begin_schema_migration(db_path)

    with connect_database(db_path, read_only=True) as db:
        assert db.execute(
            """SELECT 1 FROM sqlite_master
               WHERE type='trigger'
                 AND name='device_collection_authority_identity_immutable'"""
        ).fetchone() is None


def test_reader_never_sees_half_refreshed_schema(tmp_path, monkeypatch):
    db_path = tmp_path / "concurrent.db"
    _seed_populated_database(db_path)
    before_schema = _schema_snapshot(db_path)
    original_connect = device_collection_authority.connect_database
    reached_boundary = threading.Event()
    continue_refresh = threading.Event()

    def paused_connect(*args, **kwargs):
        db = original_connect(*args, **kwargs)

        def authorize(action, name, _table, _database, _source):
            if (
                action == sqlite3.SQLITE_CREATE_TRIGGER
                and name == "device_collection_authority_identity_immutable"
                and not reached_boundary.is_set()
            ):
                reached_boundary.set()
                assert continue_refresh.wait(10)
            return sqlite3.SQLITE_OK

        db.set_authorizer(authorize)
        return db

    errors: list[BaseException] = []

    def refresh():
        try:
            init_device_collection_authority_storage.__wrapped__(db_path)
        except BaseException as exc:  # pragma: no cover - asserted below
            errors.append(exc)

    with monkeypatch.context() as patch:
        patch.setattr(device_collection_authority, "connect_database", paused_connect)
        worker = threading.Thread(target=refresh, daemon=True)
        worker.start()
        assert reached_boundary.wait(10)
        assert _schema_snapshot(db_path) == before_schema
        continue_refresh.set()
        worker.join(10)

    assert not worker.is_alive()
    assert errors == []
    assert _schema_snapshot(db_path) == before_schema


_INTERRUPT_SCRIPT = r"""
import sqlite3
import sys
import time
from pathlib import Path
from app import device_collection_authority as authority

db_path = Path(sys.argv[1])
marker = Path(sys.argv[2])
target = sys.argv[3]
original_connect = authority.connect_database

def paused_connect(*args, **kwargs):
    db = original_connect(*args, **kwargs)
    def authorize(action, name, _table, _database, _source):
        if action == sqlite3.SQLITE_CREATE_TRIGGER and name == target:
            marker.write_text('ready')
            while True:
                time.sleep(1)
        return sqlite3.SQLITE_OK
    db.set_authorizer(authorize)
    return db

authority.connect_database = paused_connect
authority.init_device_collection_authority_storage.__wrapped__(db_path)
"""


@pytest.mark.parametrize(
    "target",
    (
        "device_collection_authority_identity_immutable",
        "device_evidence_catalog_authority_insert",
    ),
)
def test_process_termination_between_drop_and_create_preserves_schema(tmp_path, target):
    db_path = tmp_path / f"interrupted-{target}.db"
    marker = tmp_path / f"{target}.ready"
    _seed_populated_database(db_path)
    before_schema = _schema_snapshot(db_path)
    before_data = _data_snapshot(db_path)
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(Path(__file__).parents[1])
    process = subprocess.Popen(
        [sys.executable, "-c", _INTERRUPT_SCRIPT, str(db_path), str(marker), target],
        cwd=Path(__file__).parents[1],
        env=environment,
    )
    try:
        deadline = time.monotonic() + 15
        while not marker.exists() and process.poll() is None and time.monotonic() < deadline:
            time.sleep(0.05)
        assert marker.exists(), f"child exited before interruption boundary: {process.poll()}"
    finally:
        process.terminate()
        process.wait(timeout=10)

    assert _schema_snapshot(db_path) == before_schema
    assert _data_snapshot(db_path) == before_data
    _assert_authority_guards(db_path)
    subprocess.run(
        [
            sys.executable,
            "-c",
            "from pathlib import Path; from app.device_collection_authority import "
            "init_device_collection_authority_storage as init; "
            "init(Path(__import__('sys').argv[1]))",
            str(db_path),
        ],
        cwd=Path(__file__).parents[1],
        env=environment,
        check=True,
        timeout=30,
    )
    assert _schema_snapshot(db_path) == before_schema
    assert _data_snapshot(db_path) == before_data


def test_catalog_dirty_trigger_still_marks_authority_change(tmp_path):
    db_path = tmp_path / "catalog-trigger.db"
    _seed_populated_database(db_path)
    init_device_collection_authority_storage.__wrapped__(db_path)
    with connect_database(db_path) as db:
        db.execute(
            """UPDATE device_collection_authority
               SET state='deleted', revision=2,
                   deleted_at='2030-01-02T00:00:00+00:00'
               WHERE run_id='active-run'"""
        )
    with connect_database(db_path, read_only=True) as db:
        assert db.execute(
            """SELECT reason FROM device_evidence_catalog_dirty
               WHERE run_id='active-run'"""
        ).fetchone() == ("authority_update",)
