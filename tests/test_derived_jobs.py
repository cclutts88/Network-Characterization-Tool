import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from app.artifacts import register_artifact_file
from app.database import configure_database, connect_database
import app.derived_jobs as jobs
from app.derived_jobs import (
    DerivedJobConflict,
    claim_next_derived_job,
    enqueue_nmap_base_job,
    execute_claimed_derived_job,
    init_derived_job_storage,
    list_derived_jobs,
    recover_interrupted_derived_jobs,
    retry_derived_job,
    run_next_derived_job,
    scan_run_job_statuses,
)
from app.poc import init_poc_storage


XML = b'''<nmaprun scanner="nmap" version="7.95" start="100">
<scaninfo type="syn" protocol="tcp" numservices="1" services="443"/>
<host starttime="101" endtime="109"><status state="up" reason="syn-ack"/>
<address addr="192.0.2.10" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port>
</ports></host><runstats><finished time="110" exit="success"/><hosts up="1" down="0" total="1"/></runstats></nmaprun>'''


def make_run(db: Path, data_dir: Path, run_id: str, content: bytes = XML):
    init_poc_storage(db)
    run_dir = data_dir / "scan-runs" / run_id
    run_dir.mkdir(parents=True)
    path = run_dir / "scan.xml"
    path.write_bytes(content)
    manifest = {"run_id": run_id, "status": "completed", "created_at": "2030-01-01T00:00:00+00:00"}
    with connect_database(db) as connection:
        connection.execute(
            "INSERT INTO scan_runs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (run_id, manifest["created_at"], "completed", "analyst", "test", "host",
             "eth0", "profile", json.dumps(manifest)),
        )
    artifact = register_artifact_file(
        db_path=db, source_path=path, source_kind="nmap_scan", source_ref=run_id,
        original_filename="scan.xml", actor="analyst",
        observation_key=f"nmap_scan:{run_id}:scan.xml",
    )
    return path, artifact


@pytest.fixture
def queue_only(monkeypatch):
    monkeypatch.setattr(jobs, "start_derived_job_worker", lambda *args, **kwargs: None)


def test_request_tokens_are_idempotent_and_separate_from_job_identity(tmp_path, queue_only):
    db, data = tmp_path / "nct.db", tmp_path / "data"
    make_run(db, data, "a" * 32)
    first = enqueue_nmap_base_job(db, "a" * 32, request_token="request-one", requested_by="alice")
    repeated = enqueue_nmap_base_job(db, "a" * 32, request_token="request-one", requested_by="alice")
    second_request = enqueue_nmap_base_job(db, "a" * 32, request_token="request-two", requested_by="bob")
    assert first["job_id"] == repeated["job_id"] == second_request["job_id"]
    assert first["attempt_count"] == 1
    with connect_database(db, read_only=True) as connection:
        assert connection.execute("SELECT COUNT(*) FROM derived_analysis_job_requests").fetchone()[0] == 2
    make_run(db, data, "b" * 32, XML.replace(b"443", b"444"))
    with pytest.raises(DerivedJobConflict, match="different work"):
        enqueue_nmap_base_job(db, "b" * 32, request_token="request-one", requested_by="alice")


def test_only_one_worker_can_claim_an_attempt(tmp_path, queue_only):
    db, data = tmp_path / "nct.db", tmp_path / "data"
    make_run(db, data, "c" * 32)
    enqueue_nmap_base_job(db, "c" * 32, request_token="claim", requested_by="alice")
    with ThreadPoolExecutor(max_workers=6) as pool:
        claims = list(pool.map(lambda _: claim_next_derived_job(db), range(12)))
    assert sum(item is not None for item in claims) == 1


def test_job_publishes_result_provenance_and_completion_together(tmp_path, queue_only):
    db, data = tmp_path / "nct.db", tmp_path / "data"
    path, artifact = make_run(db, data, "d" * 32)
    created = enqueue_nmap_base_job(db, "d" * 32, request_token="publish", requested_by="alice")
    claim = claim_next_derived_job(db)
    result = execute_claimed_derived_job(db, claim, path)
    retained = list_derived_jobs(db)["items"][0]
    assert result["observation"]["observation_id"] == artifact["observation_id"]
    assert retained["latest_attempt"]["state"] == "completed"
    assert retained["latest_attempt"]["outcome"] == "created"
    assert retained["latest_attempt"]["result_id"] == created["target_result_id"]
    with connect_database(db, read_only=True) as connection:
        assert connection.execute("SELECT COUNT(*) FROM derived_results").fetchone()[0] == 1
        assert connection.execute("SELECT COUNT(*) FROM derived_result_observation_links").fetchone()[0] == 1


def test_lost_claim_rolls_back_new_result_and_success(tmp_path, queue_only):
    db, data = tmp_path / "nct.db", tmp_path / "data"
    path, _ = make_run(db, data, "e" * 32)
    enqueue_nmap_base_job(db, "e" * 32, request_token="lost", requested_by="alice")
    claim = claim_next_derived_job(db)
    with connect_database(db) as connection:
        connection.execute(
            "UPDATE derived_analysis_job_attempts SET claim_token = 'replacement' WHERE attempt_id = ?",
            (claim["attempt_id"],),
        )
    with pytest.raises(DerivedJobConflict, match="no longer owns|lost its claim"):
        execute_claimed_derived_job(db, claim, path)
    with connect_database(db, read_only=True) as connection:
        assert connection.execute("SELECT COUNT(*) FROM derived_results").fetchone()[0] == 0
        assert connection.execute("SELECT state FROM derived_analysis_job_attempts").fetchone()[0] == "running"


def test_restart_preserves_queued_and_interrupts_only_running_work(tmp_path, queue_only):
    db, data = tmp_path / "nct.db", tmp_path / "data"
    make_run(db, data, "f" * 32)
    make_run(db, data, "1" * 32, XML.replace(b"443", b"444"))
    first = enqueue_nmap_base_job(db, "f" * 32, request_token="first", requested_by="alice")
    enqueue_nmap_base_job(db, "1" * 32, request_token="second", requested_by="alice")
    claim_next_derived_job(db)
    assert recover_interrupted_derived_jobs(db) == 1
    listed = list_derived_jobs(db, limit=10)["items"]
    states = {item["source_run_id"]: item["latest_attempt"]["state"] for item in listed}
    assert sorted(states.values()) == ["interrupted", "queued"]
    interrupted = next(item for item in listed if item["latest_attempt"]["state"] == "interrupted")
    retry = retry_derived_job(
        db, interrupted["job_id"], request_token="retry", requested_by="bob"
    )
    assert retry["attempt_count"] == 2
    assert retry["latest_attempt"]["state"] == "queued"
    assert retry["latest_attempt"]["requested_by"] == "bob"


def test_identical_bytes_keep_encounter_jobs_and_reuse_one_result(tmp_path, queue_only):
    db, data = tmp_path / "nct.db", tmp_path / "data"
    make_run(db, data, "2" * 32)
    make_run(db, data, "3" * 32)
    first = enqueue_nmap_base_job(db, "2" * 32, request_token="one", requested_by="alice")
    assert run_next_derived_job(db, data)
    second = enqueue_nmap_base_job(db, "3" * 32, request_token="two", requested_by="alice")
    assert run_next_derived_job(db, data)
    listed = list_derived_jobs(db, limit=10)["items"]
    assert first["job_id"] != second["job_id"]
    assert {item["latest_attempt"]["outcome"] for item in listed} == {"created", "reused"}
    with connect_database(db, read_only=True) as connection:
        assert connection.execute("SELECT COUNT(*) FROM derived_results").fetchone()[0] == 1
        assert connection.execute("SELECT COUNT(*) FROM derived_result_observation_links").fetchone()[0] == 2


def test_direct_warm_reuse_completes_without_false_lost_claim(tmp_path, queue_only):
    db, data = tmp_path / "nct.db", tmp_path / "data"
    first_path, _ = make_run(db, data, "7" * 32)
    second_path, _ = make_run(db, data, "8" * 32)
    enqueue_nmap_base_job(db, "7" * 32, request_token="cold", requested_by="alice")
    execute_claimed_derived_job(db, claim_next_derived_job(db), first_path)
    enqueue_nmap_base_job(db, "8" * 32, request_token="warm", requested_by="alice")
    reused = execute_claimed_derived_job(db, claim_next_derived_job(db), second_path)
    assert reused["reused"] is True
    retained = {item["source_run_id"]: item for item in list_derived_jobs(db, limit=10)["items"]}
    assert retained["8" * 32]["latest_attempt"]["state"] == "completed"
    assert retained["8" * 32]["latest_attempt"]["outcome"] == "reused"


def test_concurrent_first_publication_during_parse_returns_reuse_success(
    tmp_path, queue_only, monkeypatch,
):
    db, data = tmp_path / "nct.db", tmp_path / "data"
    path, artifact = make_run(db, data, "e1" * 16)
    enqueue_nmap_base_job(db, "e1" * 16, request_token="concurrent", requested_by="alice")
    original = jobs._parse_nmap_xml

    def publish_elsewhere(content):
        parsed = original(content)
        from app.nmap_base_analysis import analyze_registered_nmap_result
        from app.derived_contracts import (
            NMAP_BASE_ANALYSIS_FAMILY, NMAP_BASE_ANALYSIS_VERSION,
            NMAP_BASE_PARAMETERS, NMAP_BASE_PAYLOAD_SCHEMA_VERSION,
        )
        analyze_registered_nmap_result(
            db, artifact["observation_id"], family=NMAP_BASE_ANALYSIS_FAMILY,
            analysis_version=NMAP_BASE_ANALYSIS_VERSION,
            payload_schema_version=NMAP_BASE_PAYLOAD_SCHEMA_VERSION,
            parameters=dict(NMAP_BASE_PARAMETERS), parser=original,
        )
        return parsed

    monkeypatch.setattr(jobs, "_parse_nmap_xml", publish_elsewhere)
    result = execute_claimed_derived_job(db, claim_next_derived_job(db), path)
    assert result["reused"] is True
    item = list_derived_jobs(db)["items"][0]
    assert item["latest_attempt"]["state"] == "completed"
    assert item["latest_attempt"]["outcome"] == "reused"
    with connect_database(db, read_only=True) as connection:
        assert connection.execute("SELECT COUNT(*) FROM derived_results").fetchone()[0] == 1
        assert connection.execute("SELECT COUNT(*) FROM derived_result_observation_links").fetchone()[0] == 1


def test_changed_retained_copy_fails_without_rescan_or_result(tmp_path, queue_only):
    db, data = tmp_path / "nct.db", tmp_path / "data"
    path, _ = make_run(db, data, "4" * 32)
    enqueue_nmap_base_job(db, "4" * 32, request_token="changed", requested_by="alice")
    path.write_bytes(XML.replace(b"443", b"444"))
    assert run_next_derived_job(db, data)
    item = list_derived_jobs(db)["items"][0]
    assert item["latest_attempt"]["state"] == "failed"
    assert "does not match" in item["latest_attempt"]["error"]
    with connect_database(db, read_only=True) as connection:
        assert connection.execute("SELECT COUNT(*) FROM derived_results").fetchone()[0] == 0


def test_contract_change_before_execution_fails_instead_of_retargeting(tmp_path, queue_only, monkeypatch):
    db, data = tmp_path / "nct.db", tmp_path / "data"
    make_run(db, data, "6" * 32)
    queued = enqueue_nmap_base_job(db, "6" * 32, request_token="frozen", requested_by="alice")
    monkeypatch.setattr(jobs, "NMAP_BASE_ANALYSIS_VERSION", "nmap-base-analysis:2")
    assert run_next_derived_job(db, data)
    retained = list_derived_jobs(db)["items"][0]
    assert retained["job_id"] == queued["job_id"]
    assert retained["target_analysis_version"] == "nmap-base-analysis:1"
    assert retained["latest_attempt"]["state"] == "failed"
    assert "calculation rules changed" in retained["latest_attempt"]["error"]
    with connect_database(db, read_only=True) as connection:
        assert connection.execute("SELECT COUNT(*) FROM derived_results").fetchone()[0] == 0


def test_run_local_change_during_parse_rolls_back_result_and_success(
    tmp_path, queue_only, monkeypatch,
):
    db, data = tmp_path / "nct.db", tmp_path / "data"
    path, _ = make_run(db, data, "9" * 32)
    enqueue_nmap_base_job(db, "9" * 32, request_token="race", requested_by="alice")
    original = jobs._parse_nmap_xml

    def change_during_parse(content):
        parsed = original(content)
        path.write_bytes(XML.replace(b"443", b"444"))
        return parsed

    monkeypatch.setattr(jobs, "_parse_nmap_xml", change_during_parse)
    assert run_next_derived_job(db, data)
    item = list_derived_jobs(db)["items"][0]
    assert item["latest_attempt"]["state"] == "failed"
    assert "does not match" in item["latest_attempt"]["error"]
    with connect_database(db, read_only=True) as connection:
        assert connection.execute("SELECT COUNT(*) FROM derived_results").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM derived_result_observation_links").fetchone()[0] == 0


def test_claim_loss_during_calculation_cannot_publish(tmp_path, queue_only, monkeypatch):
    db, data = tmp_path / "nct.db", tmp_path / "data"
    path, _ = make_run(db, data, "0" * 32)
    enqueue_nmap_base_job(db, "0" * 32, request_token="claim-race", requested_by="alice")
    claim = claim_next_derived_job(db)
    original = jobs._parse_nmap_xml

    def lose_claim(content):
        parsed = original(content)
        with connect_database(db) as connection:
            connection.execute(
                "UPDATE derived_analysis_job_attempts SET claim_token = 'other' WHERE attempt_id = ?",
                (claim["attempt_id"],),
            )
        return parsed

    monkeypatch.setattr(jobs, "_parse_nmap_xml", lose_claim)
    with pytest.raises(DerivedJobConflict, match="lost its claim"):
        execute_claimed_derived_job(db, claim, path)
    with connect_database(db, read_only=True) as connection:
        assert connection.execute("SELECT COUNT(*) FROM derived_results").fetchone()[0] == 0


def test_source_authority_change_during_calculation_cannot_publish(
    tmp_path, queue_only, monkeypatch,
):
    db, data = tmp_path / "nct.db", tmp_path / "data"
    path, _ = make_run(db, data, "d1" * 16)
    enqueue_nmap_base_job(db, "d1" * 16, request_token="authority-race", requested_by="alice")
    original = jobs._parse_nmap_xml

    def add_competing_observation(content):
        parsed = original(content)
        register_artifact_file(
            db_path=db, source_path=path, source_kind="nmap_scan",
            source_ref="d1" * 16, original_filename="scan.xml", actor="other",
            observation_key="competing-authority",
        )
        return parsed

    monkeypatch.setattr(jobs, "_parse_nmap_xml", add_competing_observation)
    assert run_next_derived_job(db, data)
    item = list_derived_jobs(db)["items"][0]
    assert item["latest_attempt"]["state"] == "failed"
    assert "one authoritative" in item["latest_attempt"]["error"]
    with connect_database(db, read_only=True) as connection:
        assert connection.execute("SELECT COUNT(*) FROM derived_results").fetchone()[0] == 0


def test_symlinked_run_file_or_directory_is_ineligible_and_cannot_run(tmp_path, queue_only):
    db, data = tmp_path / "nct.db", tmp_path / "data"
    path, _ = make_run(db, data, "a1" * 16)
    enqueue_nmap_base_job(db, "a1" * 16, request_token="link-file", requested_by="alice")
    real = tmp_path / "outside.xml"
    real.write_bytes(XML)
    path.unlink()
    path.symlink_to(real)
    status = scan_run_job_statuses(db, ["a1" * 16], data)["a1" * 16]
    assert status["eligible"] is False
    assert "symbolic links" in status["eligibility_reason"]
    assert run_next_derived_job(db, data)
    assert list_derived_jobs(db)["items"][0]["latest_attempt"]["state"] == "failed"

    db2, data2 = tmp_path / "nct2.db", tmp_path / "data2"
    _, _ = make_run(db2, data2, "b1" * 16)
    enqueue_nmap_base_job(db2, "b1" * 16, request_token="link-dir", requested_by="alice")
    run_dir = data2 / "scan-runs" / ("b1" * 16)
    outside_dir = tmp_path / "outside-run"
    run_dir.rename(outside_dir)
    run_dir.symlink_to(outside_dir, target_is_directory=True)
    status = scan_run_job_statuses(db2, ["b1" * 16], data2)["b1" * 16]
    assert status["eligible"] is False
    assert "symbolic links" in status["eligibility_reason"]
    assert run_next_derived_job(db2, data2)
    assert list_derived_jobs(db2)["items"][0]["latest_attempt"]["state"] == "failed"


def test_scan_history_status_is_read_only_and_explains_missing_local_file(tmp_path, queue_only):
    db, data = tmp_path / "nct.db", tmp_path / "data"
    path, _ = make_run(db, data, "5" * 32)
    init_derived_job_storage(db)
    before = db.stat().st_mtime_ns
    status = scan_run_job_statuses(db, ["5" * 32], data)["5" * 32]
    assert status["eligible"] is True
    assert status["current_job"] is None
    path.unlink()
    missing = scan_run_job_statuses(db, ["5" * 32], data)["5" * 32]
    assert missing["eligible"] is False
    assert "unavailable" in missing["eligibility_reason"]
    assert db.stat().st_mtime_ns == before


def test_status_reads_never_create_storage_and_use_committed_snapshot(tmp_path, queue_only):
    missing = tmp_path / "missing.db"
    assert list_derived_jobs(missing) == {
        "items": [], "total": 0, "limit": 25, "offset": 0, "has_more": False,
    }
    assert not missing.exists()

    db, data = tmp_path / "nct.db", tmp_path / "data"
    make_run(db, data, "c1" * 16)
    enqueue_nmap_base_job(db, "c1" * 16, request_token="snapshot", requested_by="alice")
    configure_database(db)
    writer = connect_database(db)
    try:
        writer.execute("BEGIN IMMEDIATE")
        writer.execute("UPDATE derived_analysis_job_attempts SET state = 'running'")
        during = list_derived_jobs(db)["items"][0]
        assert during["latest_attempt"]["state"] == "queued"
        writer.commit()
    finally:
        writer.close()
    after = list_derived_jobs(db)["items"][0]
    assert after["latest_attempt"]["state"] == "running"
