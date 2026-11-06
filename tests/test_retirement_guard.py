from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import shutil
import sqlite3

import pytest

from app.database import connect_database
from app.evidence_retirement import (
    EvidenceRetirementAdapter,
    EvidenceRetirementError,
    init_evidence_retirement_storage,
    retire_evidence,
)
import app.retirement_guard as guard
from app.retirement_guard import (
    RetirementGuardError,
    check_retirement_guard,
    check_retirement_guard_head,
    mark_retirement_restore_hold,
    provision_retirement_guard,
    reconcile_retirement_restore,
)


DATA_IDENTITY = "docker-volume:nct-test-data"


def _adapter() -> EvidenceRetirementAdapter:
    def identities(db, encounter_id):
        row = db.execute(
            "SELECT observation_id FROM source_encounters WHERE encounter_id=?",
            (encounter_id,),
        ).fetchone()
        if row is None:
            raise EvidenceRetirementError("source encounter does not exist")
        return {"encounter_id": encounter_id, "observation_id": row[0]}

    return EvidenceRetirementAdapter(
        resolve_identities=identities,
        active_work_detail=lambda _db, _encounter_id: None,
    )


def _foundation(tmp_path: Path) -> tuple[Path, Path, Path]:
    data = tmp_path / "mission-data"
    guard_dir = tmp_path / "retirement-authority"
    data.mkdir(mode=0o700)
    db_path = data / "analyzer.db"
    with connect_database(db_path) as db:
        db.execute(
            "CREATE TABLE source_encounters("
            "encounter_id TEXT PRIMARY KEY,observation_id TEXT UNIQUE)"
        )
        db.executemany(
            "INSERT INTO source_encounters VALUES (?,?)",
            [("encounter-a", "observation-a"), ("encounter-b", "observation-b")],
        )
    init_evidence_retirement_storage(db_path)
    provision_retirement_guard(
        guard_dir, installation_id="installation-a", data_identity=DATA_IDENTITY,
    )
    return db_path, data, guard_dir


def _retire(path: Path, encounter: str) -> dict:
    return retire_evidence(
        path, source_family="nmap_import", encounter_id=encounter,
        actor="analyst", reason=f"retire {encounter}", adapter=_adapter(),
    )


def test_fresh_admission_and_split_commit_advance_are_safe(tmp_path):
    db_path, data, guard_dir = _foundation(tmp_path)
    initial = check_retirement_guard(
        db_path, data_dir=data, guard_dir=guard_dir, data_identity=DATA_IDENTITY,
    )
    assert initial.ready and initial.revision == 0 and initial.event_digest == "root"
    assert (guard_dir / guard.BINDING_FILE).is_file()
    event = _retire(db_path, "encounter-a")
    before = guard._read_receipt(guard_dir / guard.HIGH_WATER_FILE)
    assert before["revision"] == 0
    advanced = check_retirement_guard(
        db_path, data_dir=data, guard_dir=guard_dir, data_identity=DATA_IDENTITY,
    )
    assert advanced.ready and advanced.revision == 1
    mirrored = guard._read_receipt(next((guard_dir / "events").iterdir()))
    assert mirrored["event_digest"] == event["event_digest"]


def test_normal_initial_binding_interruption_resumes_on_same_database(
    tmp_path, monkeypatch,
):
    db_path, data, guard_dir = _foundation(tmp_path)
    original_atomic = guard._atomic_receipt

    class Crash(BaseException):
        pass

    def interrupt_before_high_water(path, body):
        if path.name == guard.HIGH_WATER_FILE:
            raise Crash()
        return original_atomic(path, body)

    monkeypatch.setattr(guard, "_atomic_receipt", interrupt_before_high_water)
    with pytest.raises(Crash):
        check_retirement_guard(
            db_path, data_dir=data, guard_dir=guard_dir,
            data_identity=DATA_IDENTITY,
        )
    assert (guard_dir / guard.INITIAL_BIND_FILE).is_file()
    assert (guard_dir / guard.BINDING_FILE).is_file()
    assert not (guard_dir / guard.HIGH_WATER_FILE).exists()
    assert not (guard_dir / guard.HOLD_FILE).exists()

    monkeypatch.setattr(guard, "_atomic_receipt", original_atomic)
    resumed = check_retirement_guard(
        db_path, data_dir=data, guard_dir=guard_dir,
        data_identity=DATA_IDENTITY,
    )
    assert resumed.ready and resumed.revision == 0


def test_restore_recovers_an_interrupted_normal_initial_binding(
    tmp_path, monkeypatch,
):
    db_path, data, guard_dir = _foundation(tmp_path)
    original_atomic = guard._atomic_receipt

    class Crash(BaseException):
        pass

    def interrupt_before_high_water(path, body):
        if path.name == guard.HIGH_WATER_FILE:
            raise Crash()
        return original_atomic(path, body)

    monkeypatch.setattr(guard, "_atomic_receipt", interrupt_before_high_water)
    with pytest.raises(Crash):
        check_retirement_guard(
            db_path, data_dir=data, guard_dir=guard_dir,
            data_identity=DATA_IDENTITY,
        )
    initial = guard._read_receipt(guard_dir / guard.INITIAL_BIND_FILE)
    partial = guard._read_receipt(guard_dir / guard.BINDING_FILE)
    assert partial["lineage_id"] == initial["lineage_id"]

    restored = data / "restored-v9.db"
    with connect_database(restored) as db:
        db.execute(
            "CREATE TABLE nct_schema_state(singleton INTEGER PRIMARY KEY,schema_version INTEGER)"
        )
        db.execute("INSERT INTO nct_schema_state VALUES (1,9)")
        db.execute(
            "CREATE TABLE nct_schema_migrations(migration_id TEXT PRIMARY KEY,status TEXT)"
        )
        db.execute(
            "INSERT INTO nct_schema_migrations VALUES "
            "('nct-evidence-retirement-v9','completed')"
        )
    init_evidence_retirement_storage(restored)
    with connect_database(restored, read_only=True) as db:
        restored_lineage = db.execute(
            "SELECT lineage_id FROM evidence_retirement_lineage"
        ).fetchone()[0]
    assert restored_lineage != initial["lineage_id"]
    monkeypatch.setattr(guard, "_atomic_receipt", original_atomic)
    mark_retirement_restore_hold(
        guard_dir, data_identity=DATA_IDENTITY,
        operation_id="restore-interrupted-bind", detail="verified backup restored",
    )
    status = reconcile_retirement_restore(
        restored,
        data_dir=data,
        guard_dir=guard_dir,
        data_identity=DATA_IDENTITY,
        operation_id="restore-interrupted-bind",
    )
    assert status.ready and status.lineage_id == restored_lineage
    rebound = guard._read_receipt(guard_dir / guard.BINDING_FILE)
    assert rebound["lineage_id"] == restored_lineage
    assert (guard_dir / guard.VIRGIN_RESTORE_FILE).is_file()


def test_bounded_live_head_check_detects_unadvanced_event_and_accepts_advanced_head(
    tmp_path,
):
    db_path, data, guard_dir = _foundation(tmp_path)
    assert check_retirement_guard(
        db_path, data_dir=data, guard_dir=guard_dir, data_identity=DATA_IDENTITY,
    ).ready
    _retire(db_path, "encounter-a")
    held = check_retirement_guard_head(
        db_path, data_dir=data, guard_dir=guard_dir, data_identity=DATA_IDENTITY,
    )
    assert not held.ready
    assert "head" in held.reason

    # A real post-commit guard failure persists its hold; use an independently
    # provisioned fixture to prove the normal advanced-head read path.
    advanced = tmp_path / "advanced"
    advanced.mkdir()
    db_path, data, guard_dir = _foundation(advanced)
    assert check_retirement_guard(
        db_path, data_dir=data, guard_dir=guard_dir, data_identity=DATA_IDENTITY,
    ).ready
    _retire(db_path, "encounter-a")
    assert check_retirement_guard(
        db_path, data_dir=data, guard_dir=guard_dir, data_identity=DATA_IDENTITY,
    ).revision == 1
    ready = check_retirement_guard_head(
        db_path, data_dir=data, guard_dir=guard_dir, data_identity=DATA_IDENTITY,
    )
    assert ready.ready and ready.revision == 1


def test_crash_after_event_mirror_before_high_water_resumes_safely(tmp_path):
    db_path, data, guard_dir = _foundation(tmp_path)
    assert check_retirement_guard(
        db_path, data_dir=data, guard_dir=guard_dir, data_identity=DATA_IDENTITY,
    ).ready
    _retire(db_path, "encounter-a")
    with connect_database(db_path, read_only=True) as db:
        _lineage, events = guard._event_receipts(db)
    guard._mirror_events(guard_dir, events)
    assert guard._read_receipt(guard_dir / guard.HIGH_WATER_FILE)["revision"] == 0
    status = check_retirement_guard(
        db_path, data_dir=data, guard_dir=guard_dir, data_identity=DATA_IDENTITY,
    )
    assert status.ready and status.revision == 1


def test_events_without_high_water_fail_closed(tmp_path):
    db_path, data, guard_dir = _foundation(tmp_path)
    _retire(db_path, "encounter-a")
    status = check_retirement_guard(
        db_path, data_dir=data, guard_dir=guard_dir, data_identity=DATA_IDENTITY,
    )
    assert not status.ready
    assert "missing" in status.reason
    assert (guard_dir / guard.HOLD_FILE).is_file()


def test_consumed_fresh_binding_never_recreates_missing_high_water(tmp_path):
    db_path, data, guard_dir = _foundation(tmp_path)
    assert check_retirement_guard(
        db_path, data_dir=data, guard_dir=guard_dir, data_identity=DATA_IDENTITY,
    ).ready
    (guard_dir / guard.HIGH_WATER_FILE).unlink()
    status = check_retirement_guard(
        db_path, data_dir=data, guard_dir=guard_dir, data_identity=DATA_IDENTITY,
    )
    assert not status.ready
    assert status.reason == "retirement high-water receipt is missing"


def test_lost_high_water_and_older_empty_restore_cannot_reset_guard(tmp_path):
    db_path, data, guard_dir = _foundation(tmp_path)
    assert check_retirement_guard(
        db_path, data_dir=data, guard_dir=guard_dir, data_identity=DATA_IDENTITY,
    ).ready
    older = tmp_path / "older.db"
    with connect_database(db_path, read_only=True) as source, connect_database(older) as target:
        source.backup(target)
    _retire(db_path, "encounter-a")
    assert check_retirement_guard(
        db_path, data_dir=data, guard_dir=guard_dir, data_identity=DATA_IDENTITY,
    ).revision == 1
    (guard_dir / guard.HIGH_WATER_FILE).unlink()
    restored = data / "restored-empty.db"
    shutil.copy2(older, restored)
    status = check_retirement_guard(
        restored, data_dir=data, guard_dir=guard_dir, data_identity=DATA_IDENTITY,
    )
    assert not status.ready
    assert status.reason == "retirement high-water receipt is missing"


def test_missing_or_changed_mirrored_tail_fails_closed(tmp_path):
    db_path, data, guard_dir = _foundation(tmp_path)
    assert check_retirement_guard(
        db_path, data_dir=data, guard_dir=guard_dir, data_identity=DATA_IDENTITY,
    ).ready
    _retire(db_path, "encounter-a")
    assert check_retirement_guard(
        db_path, data_dir=data, guard_dir=guard_dir, data_identity=DATA_IDENTITY,
    ).ready
    next((guard_dir / "events").glob("*.json")).unlink()
    status = check_retirement_guard(
        db_path, data_dir=data, guard_dir=guard_dir, data_identity=DATA_IDENTITY,
    )
    assert not status.ready
    assert status.reason == "retirement guard validation failed"


@pytest.mark.parametrize("damage", ["corrupt", "lineage", "same_revision"])
def test_corrupt_or_divergent_guard_creates_persistent_hold(tmp_path, damage):
    db_path, data, guard_dir = _foundation(tmp_path)
    ready = check_retirement_guard(
        db_path, data_dir=data, guard_dir=guard_dir, data_identity=DATA_IDENTITY,
    )
    assert ready.ready
    high_water = guard_dir / guard.HIGH_WATER_FILE
    if damage == "corrupt":
        high_water.write_text("not-json", encoding="utf-8")
    else:
        value = guard._read_receipt(high_water)
        if damage == "lineage":
            value["lineage_id"] = "different-lineage"
        else:
            value["event_digest"] = "different-root"
        guard._atomic_receipt(high_water, value)
    status = check_retirement_guard(
        db_path, data_dir=data, guard_dir=guard_dir, data_identity=DATA_IDENTITY,
    )
    assert not status.ready
    assert (guard_dir / guard.HOLD_FILE).is_file()
    again = check_retirement_guard(
        db_path, data_dir=data, guard_dir=guard_dir, data_identity=DATA_IDENTITY,
    )
    assert not again.ready and again.reason == status.reason


def test_independent_guard_detects_older_database_restore(tmp_path):
    db_path, data, guard_dir = _foundation(tmp_path)
    assert check_retirement_guard(
        db_path, data_dir=data, guard_dir=guard_dir, data_identity=DATA_IDENTITY,
    ).ready
    backup = tmp_path / "older-backup.db"
    with connect_database(db_path, read_only=True) as source, connect_database(backup) as target:
        source.backup(target)
    _retire(db_path, "encounter-a")
    assert check_retirement_guard(
        db_path, data_dir=data, guard_dir=guard_dir, data_identity=DATA_IDENTITY,
    ).revision == 1
    restored = data / "restored.db"
    shutil.copy2(backup, restored)
    status = check_retirement_guard(
        restored, data_dir=data, guard_dir=guard_dir, data_identity=DATA_IDENTITY,
    )
    assert not status.ready
    assert "predates" in status.reason


def test_reverse_concurrent_advance_cannot_lower_high_water(tmp_path):
    db_path, data, guard_dir = _foundation(tmp_path)
    check_retirement_guard(
        db_path, data_dir=data, guard_dir=guard_dir, data_identity=DATA_IDENTITY,
    )
    _retire(db_path, "encounter-a")
    _retire(db_path, "encounter-b")
    with connect_database(db_path, read_only=True) as db:
        lineage, events = guard._event_receipts(db)
    provisioning = guard._provisioning(guard_dir, DATA_IDENTITY)
    root = guard._read_high_water(guard_dir, provisioning)
    head_one = guard._head(lineage, events[:1])
    head_two = guard._head(lineage, events)

    def advance(desired):
        with guard._guard_lock(guard_dir):
            current = guard._read_high_water(guard_dir, provisioning)
            return guard._advance_locked(
                guard_dir, provisioning, current, desired, events,
            )

    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(advance, head_two)
        second = pool.submit(advance, head_one)
        first.result()
        second.result()
    final = guard._read_high_water(guard_dir, provisioning)
    assert root["revision"] == 0
    assert final["revision"] == 2
    assert final["event_digest"] == head_two["event_digest"]


def test_same_revision_divergent_advance_is_refused(tmp_path):
    db_path, data, guard_dir = _foundation(tmp_path)
    check_retirement_guard(
        db_path, data_dir=data, guard_dir=guard_dir, data_identity=DATA_IDENTITY,
    )
    _retire(db_path, "encounter-a")
    with connect_database(db_path, read_only=True) as db:
        lineage, events = guard._event_receipts(db)
    provisioning = guard._provisioning(guard_dir, DATA_IDENTITY)
    current = guard._read_high_water(guard_dir, provisioning)
    desired = guard._head(lineage, events)
    guard._advance_locked(guard_dir, provisioning, current, desired, events)
    divergent = {**desired, "event_digest": "divergent"}
    current = guard._read_high_water(guard_dir, provisioning)
    with pytest.raises(RetirementGuardError, match="diverged"):
        guard._advance_locked(
            guard_dir, provisioning, current, divergent, events,
        )


def test_restore_hold_is_written_before_data_reconciliation(tmp_path):
    db_path, data, guard_dir = _foundation(tmp_path)
    assert check_retirement_guard(
        db_path, data_dir=data, guard_dir=guard_dir, data_identity=DATA_IDENTITY,
    ).ready
    marked = mark_retirement_restore_hold(
        guard_dir, data_identity=DATA_IDENTITY,
        operation_id="restore-1", detail="before swapping restored data",
    )
    assert not marked.ready
    status = check_retirement_guard(
        db_path, data_dir=data, guard_dir=guard_dir, data_identity=DATA_IDENTITY,
    )
    assert not status.ready and "restore" in status.reason
    assert list((guard_dir / "audit").glob("*-hold-*.json"))


def test_restore_reconciliation_reapplies_protected_tail_before_releasing_hold(
    tmp_path,
):
    db_path, data, guard_dir = _foundation(tmp_path)
    assert check_retirement_guard(
        db_path, data_dir=data, guard_dir=guard_dir, data_identity=DATA_IDENTITY,
    ).ready
    backup = tmp_path / "before-retirement.db"
    with connect_database(db_path, read_only=True) as source, connect_database(backup) as target:
        source.backup(target)
    event = _retire(db_path, "encounter-a")
    assert check_retirement_guard(
        db_path, data_dir=data, guard_dir=guard_dir, data_identity=DATA_IDENTITY,
    ).revision == 1
    shutil.copy2(backup, db_path)
    mark_retirement_restore_hold(
        guard_dir, data_identity=DATA_IDENTITY,
        operation_id="restore-tail", detail="before swapping restored data",
    )
    status = reconcile_retirement_restore(
        db_path,
        data_dir=data,
        guard_dir=guard_dir,
        data_identity=DATA_IDENTITY,
        operation_id="restore-tail",
    )
    assert status.ready and status.revision == 1
    with connect_database(db_path, read_only=True) as db:
        row = db.execute(
            "SELECT event_digest,sealed FROM evidence_retirement_events WHERE revision=1"
        ).fetchone()
    assert row == (event["event_digest"], 1)
    assert not (guard_dir / guard.HOLD_FILE).exists()
    assert list((guard_dir / "audit").glob("*-restore-reconciled-*.json"))
    # Model a host interruption after the hold was cleared but before the
    # restored application started. Re-entering the exact operation consumes
    # the durable reconciliation receipt and remains safe and ready.
    retried = reconcile_retirement_restore(
        db_path,
        data_dir=data,
        guard_dir=guard_dir,
        data_identity=DATA_IDENTITY,
        operation_id="restore-tail",
    )
    assert retried.ready and retried.revision == 1
    assert len(list((guard_dir / guard.RECONCILIATION_DIR).glob("*.json"))) == 1


def test_first_upgrade_virgin_guard_recovery_is_operation_bound_and_retry_safe(
    tmp_path, monkeypatch,
):
    db_path, data, guard_dir = _foundation(tmp_path)
    with connect_database(db_path) as db:
        db.execute(
            "CREATE TABLE nct_schema_state(singleton INTEGER PRIMARY KEY,schema_version INTEGER)"
        )
        db.execute("INSERT INTO nct_schema_state VALUES (1,9)")
        db.execute(
            "CREATE TABLE nct_schema_migrations(migration_id TEXT PRIMARY KEY,status TEXT)"
        )
        db.execute(
            "INSERT INTO nct_schema_migrations VALUES "
            "('nct-evidence-retirement-v9','completed')"
        )
    mark_retirement_restore_hold(
        guard_dir, data_identity=DATA_IDENTITY,
        operation_id="first-v8-upgrade", detail="verified v8 backup restored",
    )
    original_atomic = guard._atomic_receipt

    class Crash(BaseException):
        pass

    def interrupt_between_binding_files(path, body):
        if path.name == guard.HIGH_WATER_FILE:
            raise Crash()
        return original_atomic(path, body)

    monkeypatch.setattr(guard, "_atomic_receipt", interrupt_between_binding_files)
    with pytest.raises(Crash):
        reconcile_retirement_restore(
            db_path,
            data_dir=data,
            guard_dir=guard_dir,
            data_identity=DATA_IDENTITY,
            operation_id="first-v8-upgrade",
        )
    assert (guard_dir / guard.VIRGIN_RESTORE_FILE).is_file()
    assert (guard_dir / guard.BINDING_FILE).is_file()
    assert not (guard_dir / guard.HIGH_WATER_FILE).exists()
    assert (guard_dir / guard.HOLD_FILE).is_file()

    monkeypatch.setattr(guard, "_atomic_receipt", original_atomic)
    status = reconcile_retirement_restore(
        db_path,
        data_dir=data,
        guard_dir=guard_dir,
        data_identity=DATA_IDENTITY,
        operation_id="first-v8-upgrade",
    )
    assert status.ready and status.revision == 0 and status.event_digest == "root"
    assert not (guard_dir / guard.HOLD_FILE).exists()
    with pytest.raises(RetirementGuardError, match="another operation|hold is missing"):
        reconcile_retirement_restore(
            db_path,
            data_dir=data,
            guard_dir=guard_dir,
            data_identity=DATA_IDENTITY,
            operation_id="different-upgrade",
        )


def test_pre_v9_restore_adopts_protected_lineage_after_exact_migration(tmp_path):
    db_path, data, guard_dir = _foundation(tmp_path)
    assert check_retirement_guard(
        db_path, data_dir=data, guard_dir=guard_dir, data_identity=DATA_IDENTITY,
    ).ready
    event = _retire(db_path, "encounter-a")
    protected = check_retirement_guard(
        db_path, data_dir=data, guard_dir=guard_dir, data_identity=DATA_IDENTITY,
    )
    assert protected.revision == 1

    # Model the exact v9 migration of a verified pre-v9 backup: the migration
    # created a new empty lineage, but the protected host authority owns the
    # lineage and retired tail that must win before any runtime can restart.
    restored = data / "restored-pre-v9.db"
    with connect_database(restored) as db:
        db.execute(
            "CREATE TABLE source_encounters("
            "encounter_id TEXT PRIMARY KEY,observation_id TEXT UNIQUE)"
        )
        db.execute(
            "INSERT INTO source_encounters VALUES ('encounter-a','observation-a')"
        )
        db.execute(
            "CREATE TABLE nct_schema_state(singleton INTEGER PRIMARY KEY,schema_version INTEGER)"
        )
        db.execute("INSERT INTO nct_schema_state VALUES (1,9)")
        db.execute(
            "CREATE TABLE nct_schema_migrations(migration_id TEXT PRIMARY KEY,status TEXT)"
        )
        db.execute(
            "INSERT INTO nct_schema_migrations VALUES "
            "('nct-evidence-retirement-v9','completed')"
        )
    init_evidence_retirement_storage(restored)
    with connect_database(restored, read_only=True) as db:
        random_lineage = db.execute(
            "SELECT lineage_id FROM evidence_retirement_lineage"
        ).fetchone()[0]
    assert random_lineage != protected.lineage_id

    mark_retirement_restore_hold(
        guard_dir, data_identity=DATA_IDENTITY,
        operation_id="restore-pre-v9", detail="verified pre-v9 backup",
    )
    status = reconcile_retirement_restore(
        restored,
        data_dir=data,
        guard_dir=guard_dir,
        data_identity=DATA_IDENTITY,
        operation_id="restore-pre-v9",
    )
    assert status.ready and status.revision == 1
    with connect_database(restored) as db:
        assert db.execute(
            "SELECT lineage_id FROM evidence_retirement_lineage"
        ).fetchone()[0] == protected.lineage_id
        assert db.execute(
            "SELECT event_digest FROM evidence_retirement_events WHERE revision=1"
        ).fetchone()[0] == event["event_digest"]
        with pytest.raises(sqlite3.DatabaseError, match="immutable"):
            db.execute(
                "UPDATE evidence_retirement_lineage SET lineage_id='changed'"
            )


def test_restore_reconciliation_refuses_wrong_operation_and_keeps_hold(tmp_path):
    db_path, data, guard_dir = _foundation(tmp_path)
    assert check_retirement_guard(
        db_path, data_dir=data, guard_dir=guard_dir, data_identity=DATA_IDENTITY,
    ).ready
    mark_retirement_restore_hold(
        guard_dir, data_identity=DATA_IDENTITY,
        operation_id="restore-one", detail="before swap",
    )
    with pytest.raises(RetirementGuardError, match="another operation"):
        reconcile_retirement_restore(
            db_path,
            data_dir=data,
            guard_dir=guard_dir,
            data_identity=DATA_IDENTITY,
            operation_id="restore-two",
        )
    assert (guard_dir / guard.HOLD_FILE).exists()


def test_guard_refuses_data_nested_storage_and_wrong_identity(tmp_path):
    db_path, data, guard_dir = _foundation(tmp_path)
    nested = data / "guard"
    nested.mkdir(mode=0o700)
    with pytest.raises(RetirementGuardError, match="separate"):
        guard._separate_paths(data, nested)
    status = check_retirement_guard(
        db_path, data_dir=data, guard_dir=guard_dir,
        data_identity="docker-volume:different",
    )
    assert not status.ready
    assert "different data storage" in status.reason
    assert not (guard_dir / guard.HOLD_FILE).exists()


def test_provisioning_never_overwrites_existing_authority(tmp_path):
    target = tmp_path / "guard"
    provision_retirement_guard(
        target, installation_id="one", data_identity=DATA_IDENTITY,
    )
    with pytest.raises(RetirementGuardError, match="already provisioned"):
        provision_retirement_guard(
            target, installation_id="two", data_identity=DATA_IDENTITY,
        )
    value = guard._read_receipt(target / guard.PROVISIONING_FILE)
    assert value["installation_id"] == "one"


def test_provisioning_refuses_symlinked_guard_root(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    target = tmp_path / "guard-link"
    target.symlink_to(outside, target_is_directory=True)
    with pytest.raises(RetirementGuardError, match="symlink"):
        provision_retirement_guard(
            target, installation_id="one", data_identity=DATA_IDENTITY,
        )
    assert list(outside.iterdir()) == []


def test_unavailable_or_rejected_guard_returns_hold_without_mutating_it(
    tmp_path, monkeypatch,
):
    db_path, data, guard_dir = _foundation(tmp_path)
    original_hold = guard._hold_locked

    def forbidden_hold(*args, **kwargs):
        raise AssertionError("a rejected guard must not be mutated")

    def unavailable(_path):
        raise OSError("guard storage unavailable")

    monkeypatch.setattr(guard, "_secure_directory", unavailable)
    monkeypatch.setattr(guard, "_hold_locked", forbidden_hold)
    status = check_retirement_guard(
        db_path, data_dir=data, guard_dir=guard_dir, data_identity=DATA_IDENTITY,
    )
    assert not status.ready
    assert "unavailable" in status.reason
    monkeypatch.setattr(guard, "_hold_locked", original_hold)


def test_symlinked_audit_directory_is_never_written(tmp_path):
    db_path, data, guard_dir = _foundation(tmp_path)
    outside = tmp_path / "outside-audit"
    outside.mkdir()
    canary = outside / "canary.txt"
    canary.write_text("unchanged", encoding="utf-8")
    shutil.rmtree(guard_dir / "audit")
    (guard_dir / "audit").symlink_to(outside, target_is_directory=True)

    status = check_retirement_guard(
        db_path, data_dir=data, guard_dir=guard_dir, data_identity=DATA_IDENTITY,
    )
    assert not status.ready
    assert not (guard_dir / guard.HOLD_FILE).exists()
    assert [path.name for path in outside.iterdir()] == ["canary.txt"]

    with pytest.raises(RetirementGuardError, match="not a directory"):
        mark_retirement_restore_hold(
            guard_dir, data_identity=DATA_IDENTITY,
            operation_id="restore-symlink", detail="must not follow audit symlink",
        )
    assert canary.read_text(encoding="utf-8") == "unchanged"
    assert [path.name for path in outside.iterdir()] == ["canary.txt"]

