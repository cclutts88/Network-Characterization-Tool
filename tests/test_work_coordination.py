from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import multiprocessing
from pathlib import Path
import sqlite3

import pytest

from app.database import configure_database
from app.work_coordination import (
    WorkLeaseConflict,
    WorkLeaseLost,
    WorkRecoveryRequired,
    acquire_work_lease,
    release_work_lease,
    renew_work_lease,
    work_lease_status,
)


def _database(tmp_path: Path) -> Path:
    path = tmp_path / "analyzer.db"
    configure_database(path)
    return path


def _process_claim(db_text: str, owner: str, barrier, results) -> None:
    barrier.wait(timeout=10)
    try:
        lease = acquire_work_lease(
            Path(db_text),
            lease_key="analysis:process-race",
            work_kind="retained-analysis",
            work_id="attempt-1",
            owner_id=owner,
        )
        results.put(("acquired", lease.fencing_epoch))
    except WorkLeaseConflict:
        results.put(("conflict", None))


def _process_claim_then_renew(db_text: str, ready, proceed, results) -> None:
    lease = acquire_work_lease(
        Path(db_text),
        lease_key="analysis:process-renewal",
        work_kind="retained-analysis",
        work_id="attempt-old",
        owner_id="process-old",
    )
    results.put(("acquired", lease.fencing_epoch))
    ready.set()
    proceed.wait(timeout=15)
    try:
        renew_work_lease(Path(db_text), lease)
        results.put(("renewed", lease.fencing_epoch))
    except WorkLeaseLost:
        results.put(("lost", lease.fencing_epoch))


def test_two_workers_race_and_only_one_acquires(tmp_path: Path) -> None:
    db_path = _database(tmp_path)

    def claim(owner: str):
        try:
            return acquire_work_lease(
                db_path,
                lease_key="analysis:job-1",
                work_kind="retained-analysis",
                work_id="attempt-1",
                owner_id=owner,
            )
        except WorkLeaseConflict:
            return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(claim, ("worker-a", "worker-b")))

    winners = [item for item in results if item is not None]
    assert len(winners) == 1
    status = work_lease_status(db_path, "analysis:job-1")
    assert status["currently_owned"] is True
    assert status["fencing_epoch"] == 1


def test_two_separate_processes_race_and_only_one_acquires(tmp_path: Path) -> None:
    db_path = _database(tmp_path)
    context = multiprocessing.get_context("spawn")
    barrier = context.Barrier(2)
    results = context.Queue()
    workers = [
        context.Process(
            target=_process_claim,
            args=(str(db_path), owner, barrier, results),
        )
        for owner in ("process-a", "process-b")
    ]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=15)
        assert worker.exitcode == 0
    outcomes = [results.get(timeout=2), results.get(timeout=2)]
    assert sorted(item[0] for item in outcomes) == ["acquired", "conflict"]
    assert work_lease_status(db_path, "analysis:process-race")["fencing_epoch"] == 1


def test_separate_process_cannot_renew_after_expiry_takeover(tmp_path: Path) -> None:
    db_path = _database(tmp_path)
    context = multiprocessing.get_context("spawn")
    ready, proceed, results = context.Event(), context.Event(), context.Queue()
    worker = context.Process(
        target=_process_claim_then_renew,
        args=(str(db_path), ready, proceed, results),
    )
    worker.start()
    assert ready.wait(timeout=10)
    assert results.get(timeout=2) == ("acquired", 1)
    with pytest.raises(WorkLeaseConflict):
        acquire_work_lease(
            db_path,
            lease_key="analysis:process-renewal",
            work_kind="retained-analysis",
            work_id="attempt-new",
            owner_id="process-new",
        )
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            "UPDATE work_leases SET expires_at='2000-01-01T00:00:00.000Z' WHERE lease_key=?",
            ("analysis:process-renewal",),
        )
    replacement = acquire_work_lease(
        db_path,
        lease_key="analysis:process-renewal",
        work_kind="retained-analysis",
        work_id="attempt-new",
        owner_id="process-new",
    )
    assert replacement.fencing_epoch == 2
    proceed.set()
    worker.join(timeout=15)
    assert worker.exitcode == 0
    assert results.get(timeout=2) == ("lost", 1)


def test_expired_reclaim_increments_epoch_and_fences_old_owner(tmp_path: Path) -> None:
    db_path = _database(tmp_path)
    old = acquire_work_lease(
        db_path,
        lease_key="analysis:job-1",
        work_kind="retained-analysis",
        work_id="attempt-1",
        owner_id="worker-a",
    )
    with sqlite3.connect(db_path) as db:
        db.execute(
            "UPDATE work_leases SET expires_at = '2000-01-01T00:00:00.000Z' "
            "WHERE lease_key = ?",
            (old.lease_key,),
        )
    new = acquire_work_lease(
        db_path,
        lease_key=old.lease_key,
        work_kind="retained-analysis",
        work_id="attempt-2",
        owner_id="worker-b",
    )
    assert new.fencing_epoch == old.fencing_epoch + 1
    with pytest.raises(WorkLeaseLost):
        renew_work_lease(db_path, old)
    with pytest.raises(WorkLeaseLost):
        release_work_lease(db_path, old)
    release_work_lease(db_path, new)
    assert work_lease_status(db_path, old.lease_key)["state"] == "released"


def test_unexpired_owner_cannot_be_replaced(tmp_path: Path) -> None:
    db_path = _database(tmp_path)
    current = acquire_work_lease(
        db_path,
        lease_key="analysis:job-1",
        work_kind="retained-analysis",
        work_id="attempt-1",
        owner_id="worker-a",
    )
    with pytest.raises(WorkLeaseConflict, match="still responsible"):
        acquire_work_lease(
            db_path,
            lease_key=current.lease_key,
            work_kind="retained-analysis",
            work_id="attempt-2",
            owner_id="worker-b",
        )
    renewed = renew_work_lease(db_path, current)
    assert renewed.fencing_epoch == current.fencing_epoch


def test_unsafe_expiry_enters_durable_recovery_required(tmp_path: Path) -> None:
    db_path = _database(tmp_path)
    lease = acquire_work_lease(
        db_path,
        lease_key="storage-maintenance",
        work_kind="storage-compaction",
        work_id="plan-1",
        owner_id="worker-a",
        expired_policy="recovery_required",
    )
    with sqlite3.connect(db_path) as db:
        db.execute(
            "UPDATE work_leases SET expires_at = '2000-01-01T00:00:00.000Z' "
            "WHERE lease_key = ?",
            (lease.lease_key,),
        )
    with pytest.raises(WorkRecoveryRequired):
        acquire_work_lease(
            db_path,
            lease_key=lease.lease_key,
            work_kind="storage-compaction",
            work_id="plan-2",
            owner_id="worker-b",
            expired_policy="recovery_required",
        )
    status = work_lease_status(db_path, lease.lease_key)
    assert status["state"] == "recovery_required"
    assert status["currently_owned"] is False
    with pytest.raises(WorkRecoveryRequired):
        acquire_work_lease(
            db_path,
            lease_key=lease.lease_key,
            work_kind="storage-compaction",
            work_id="plan-3",
            owner_id="worker-c",
            expired_policy="recovery_required",
        )
