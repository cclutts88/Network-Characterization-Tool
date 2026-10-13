from __future__ import annotations

import threading
from pathlib import Path

import app.poc as poc
import app.derived_jobs as derived
import app.storage_health as storage


class _StuckThread:
    def join(self, *_args, **_kwargs) -> None:
        return None

    def is_alive(self) -> bool:
        return True


class _BlockingStartThread(_StuckThread):
    def __init__(self, entered: threading.Event, release: threading.Event) -> None:
        self.entered = entered
        self.release = release

    def start(self) -> None:
        self.entered.set()
        assert self.release.wait(2)


def test_scan_shutdown_requests_cancel_and_reports_live_writer() -> None:
    control = poc.RunControl()
    thread = _StuckThread()
    with poc.ACTIVE_RUNS_LOCK:
        poc.ACTIVE_RUNS["test-run"] = control
        poc.ACTIVE_RUN_THREADS["test-run"] = thread
    try:
        assert poc.stop_scan_workers(timeout=0) is False
        assert control.cancel_event.is_set()
    finally:
        with poc.ACTIVE_RUNS_LOCK:
            poc.ACTIVE_RUNS.pop("test-run", None)
            poc.ACTIVE_RUN_THREADS.pop("test-run", None)
        poc.resume_scan_workers()


def test_schedule_batch_shutdown_reports_live_writer() -> None:
    thread = _StuckThread()
    with poc.ACTIVE_SCHEDULE_BATCHES_LOCK:
        poc.ACTIVE_SCHEDULE_BATCHES.add("test-schedule")
        poc.ACTIVE_SCHEDULE_THREADS["test-schedule"] = thread
    try:
        assert poc.stop_schedule_batch_workers(timeout=0) is False
    finally:
        with poc.ACTIVE_SCHEDULE_BATCHES_LOCK:
            poc.ACTIVE_SCHEDULE_BATCHES.discard("test-schedule")
            poc.ACTIVE_SCHEDULE_THREADS.pop("test-schedule", None)
        poc.resume_scan_workers()


def test_storage_shutdown_reports_active_writer_then_confirms_exit(
    tmp_path: Path, monkeypatch,
) -> None:
    entered = threading.Event()
    release = threading.Event()

    def blocked_analysis(_db_path: Path) -> dict:
        entered.set()
        release.wait(2)
        return {"status": "ok"}

    monkeypatch.setattr(storage, "analyze_storage", blocked_analysis)
    db_path = tmp_path / "analyzer.db"
    try:
        storage.start_storage_job(db_path, "dry-run")
        assert entered.wait(1)
        assert storage.stop_storage_jobs(timeout=0) is False
        release.set()
        assert storage.stop_storage_jobs(timeout=2) is True
    finally:
        release.set()
        storage.resume_storage_jobs()


def _assert_shutdown_waits_for_atomic_admission(
    *,
    start,
    stop,
    entered: threading.Event,
    release: threading.Event,
) -> bool:
    start_errors: list[BaseException] = []
    stop_results: list[bool] = []

    def run_start() -> None:
        try:
            start()
        except BaseException as exc:
            start_errors.append(exc)

    starter = threading.Thread(target=run_start)
    starter.start()
    assert entered.wait(1)
    stopper = threading.Thread(target=lambda: stop_results.append(stop()))
    stopper.start()
    assert not stopper.join(timeout=0.05)
    assert stop_results == []
    release.set()
    starter.join(timeout=1)
    stopper.join(timeout=1)
    assert not starter.is_alive()
    assert not stopper.is_alive()
    assert start_errors == []
    assert len(stop_results) == 1
    return stop_results[0]


def test_storage_admission_cannot_cross_shutdown_fence(tmp_path: Path, monkeypatch) -> None:
    entered = threading.Event()
    release = threading.Event()
    fake = _BlockingStartThread(entered, release)
    db_path = tmp_path / "analyzer.db"
    storage.resume_storage_jobs()
    monkeypatch.setattr(storage, "_new_storage_thread", lambda _work: fake)
    try:
        stopped = _assert_shutdown_waits_for_atomic_admission(
            start=lambda: storage.start_storage_job(db_path, "dry-run"),
            stop=lambda: storage.stop_storage_jobs(timeout=0),
            entered=entered,
            release=release,
        )
        assert stopped is False
    finally:
        release.set()
        with storage._LOCK:
            storage._ACTIVE.discard(str(db_path))
            storage._THREADS.pop(str(db_path), None)
        storage.resume_storage_jobs()


def test_scan_admission_cannot_cross_shutdown_fence(tmp_path: Path, monkeypatch) -> None:
    entered = threading.Event()
    release = threading.Event()
    fake = _BlockingStartThread(entered, release)
    run_id = "a" * 32
    poc.resume_scan_workers()
    monkeypatch.setattr(poc, "evidence_mutations_blocked", lambda _path: False)
    monkeypatch.setattr(
        poc, "claim_next_queued_scan",
        lambda *_args: {"run_id": run_id, "status": "dispatching"},
    )
    monkeypatch.setattr(poc, "with_queue_state", lambda manifest, _path: manifest)
    monkeypatch.setattr(poc, "_new_scan_worker_thread", lambda *_args, **_kwargs: fake)
    try:
        stopped = _assert_shutdown_waits_for_atomic_admission(
            start=lambda: poc.dispatch_next_queued_run(
                db_path=tmp_path / "analyzer.db", data_dir=tmp_path,
            ),
            stop=lambda: poc.stop_scan_workers(timeout=0),
            entered=entered,
            release=release,
        )
        assert stopped is False
    finally:
        release.set()
        with poc.ACTIVE_RUNS_LOCK:
            poc.ACTIVE_RUNS.pop(run_id, None)
            poc.ACTIVE_RUN_THREADS.pop(run_id, None)
        poc.resume_scan_workers()


def test_schedule_admission_cannot_cross_shutdown_fence(tmp_path: Path, monkeypatch) -> None:
    entered = threading.Event()
    release = threading.Event()
    fake = _BlockingStartThread(entered, release)
    schedule_id = "b" * 32
    schedule = {"schedule_id": schedule_id, "targets": ["192.0.2.1"]}
    poc.resume_scan_workers()
    monkeypatch.setattr(poc, "get_scan_schedule", lambda *_args: schedule.copy())
    monkeypatch.setattr(poc, "get_schedule_scope_context", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(poc, "schedule_target_chunks", lambda *_args: [["192.0.2.1"]])
    monkeypatch.setattr(poc, "_store_scan_schedule", lambda value, _path: value)
    monkeypatch.setattr(
        poc,
        "prepare_schedule_occurrence",
        lambda *_args, **_kwargs: {
            "occurrence_id": "c" * 32,
            "batch_id": "c" * 32,
            "status": "waiting",
            "created": True,
            "chunk_count": 1,
        },
    )
    monkeypatch.setattr(poc, "_new_schedule_batch_thread", lambda *_args, **_kwargs: fake)
    try:
        stopped = _assert_shutdown_waits_for_atomic_admission(
            start=lambda: poc.queue_scan_schedule_batch(
                schedule_id,
                advance_schedule=False,
                db_path=tmp_path / "analyzer.db",
                data_dir=tmp_path,
            ),
            stop=lambda: poc.stop_schedule_batch_workers(timeout=0),
            entered=entered,
            release=release,
        )
        assert stopped is False
    finally:
        release.set()
        with poc.ACTIVE_SCHEDULE_BATCHES_LOCK:
            poc.ACTIVE_SCHEDULE_BATCHES.discard(schedule_id)
            poc.ACTIVE_SCHEDULE_THREADS.pop(schedule_id, None)
        poc.resume_scan_workers()


def test_derived_admission_cannot_cross_shutdown_fence(tmp_path: Path, monkeypatch) -> None:
    entered = threading.Event()
    release = threading.Event()
    fake = _BlockingStartThread(entered, release)
    db_path = (tmp_path / "analyzer.db").resolve()

    class FakeDb:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def execute(self, *_args, **_kwargs):
            return None

    derived.resume_derived_job_worker()
    monkeypatch.setattr(derived, "init_pipeline_intake_storage", lambda _path: None)
    monkeypatch.setattr(derived, "connect_database", lambda _path: FakeDb())
    monkeypatch.setattr(derived, "_new_derived_worker_thread", lambda *_args: fake)
    try:
        stopped = _assert_shutdown_waits_for_atomic_admission(
            start=lambda: derived.start_derived_job_worker(db_path, tmp_path),
            stop=lambda: derived.stop_derived_job_worker(db_path, timeout=0),
            entered=entered,
            release=release,
        )
        assert stopped is False
    finally:
        release.set()
        with derived._WORKERS_LOCK:
            derived._WORKERS.pop(db_path, None)
        derived.resume_derived_job_worker()
