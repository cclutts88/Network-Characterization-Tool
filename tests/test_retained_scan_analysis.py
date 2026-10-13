import json
from pathlib import Path
import time
import tracemalloc

import pytest
from fastapi.testclient import TestClient

from app.artifacts import register_artifact_file
from app.database import connect_database
import app.derived_jobs as jobs
from app.derived_jobs import (
    claim_next_derived_job,
    enqueue_nmap_base_job,
    execute_claimed_derived_job,
)
from app.poc import init_poc_storage
from app.main import app
from app.retained_scan_analysis import (
    GROUP_COMPOSITION_VERSION,
    RetainedScanAnalysisUnavailable,
    load_prepared_scan_group,
    list_prepared_scan_group_metadata,
)


XML = b'''<nmaprun scanner="nmap" version="7.95" start="100">
<scaninfo type="syn" protocol="tcp" numservices="1" services="443"/>
<host starttime="101" endtime="109"><status state="up" reason="syn-ack"/>
<address addr="192.0.2.10" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="443"><state state="open" reason="syn-ack"/><service name="https" product="nginx" version="1"/></port>
</ports></host><runstats><finished time="110" exit="success"/><hosts up="1" down="0" total="1"/></runstats></nmaprun>'''


def make_run(
    db: Path, data: Path, run_id: str, content: bytes = XML, *,
    batch: str | None = None, chunk_number: int | None = None,
    chunk_count: int | None = None,
) -> tuple[dict, Path]:
    init_poc_storage(db)
    run_dir = data / "scan-runs" / run_id
    run_dir.mkdir(parents=True)
    path = run_dir / "scan.xml"
    path.write_bytes(content)
    manifest = {
        "run_id": run_id, "status": "completed",
        "created_at": f"2030-01-01T00:00:{chunk_number or 1:02d}+00:00",
        "completed_at": f"2030-01-01T00:01:{chunk_number or 1:02d}+00:00",
        "display_name": "Prepared history",
        "targets": ["192.0.2.0/24"],
        "coverage": {"targets": ["192.0.2.0/24"], "protocols": ["TCP"]},
        "schedule_batch_id": batch, "chunk_number": chunk_number,
        "chunk_count": chunk_count,
    }
    with connect_database(db) as connection:
        connection.execute(
            "INSERT INTO scan_runs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (run_id, manifest["created_at"], "completed", "analyst", "test", "host",
             "eth0", "profile", json.dumps(manifest, sort_keys=True)),
        )
    artifact = register_artifact_file(
        db_path=db, source_path=path, source_kind="nmap_scan", source_ref=run_id,
        original_filename="scan.xml", actor="analyst",
        observation_key=f"nmap_scan:{run_id}:scan.xml",
    )
    manifest["artifact_registry"] = {
        "status": "complete",
        "files": [{"filename": "scan.xml", "sha256": artifact["sha256"]}],
    }
    with connect_database(db) as connection:
        connection.execute(
            "UPDATE scan_runs SET manifest_json = ? WHERE run_id = ?",
            (json.dumps(manifest, sort_keys=True), run_id),
        )
    return manifest, path


def prepare(db: Path, run_id: str, path: Path, token: str) -> dict:
    queued = enqueue_nmap_base_job(
        db, run_id, request_token=token, requested_by="analyst",
    )
    claim = claim_next_derived_job(db)
    execute_claimed_derived_job(db, claim, path)
    return queued


@pytest.fixture(autouse=True)
def queue_only(monkeypatch):
    monkeypatch.setattr(jobs, "start_derived_job_worker", lambda *args, **kwargs: None)


def test_prepared_result_reopens_read_only_with_exact_provenance(tmp_path):
    db, data = tmp_path / "nct.db", tmp_path / "data"
    manifest, path = make_run(db, data, "a" * 32)
    queued = prepare(db, manifest["run_id"], path, "prepare-a")

    writer = connect_database(db)
    try:
        writer.execute("BEGIN IMMEDIATE")
        result = load_prepared_scan_group(db, data, manifest["run_id"])
    finally:
        writer.rollback()
        writer.close()

    assert result["analysis"]["hosts"][0]["ip"] == "192.0.2.10"
    assert result["provenance"]["composition_version"] == GROUP_COMPOSITION_VERSION
    child = result["provenance"]["children"][0]
    assert child["result_id"] == queued["target_result_id"]
    assert child["sha256"]
    assert child["analysis_version"].startswith("nmap-base-analysis:")


def test_historical_analysis_route_is_read_only_and_returns_separate_annotations(tmp_path, monkeypatch):
    db, data = tmp_path / "nct.db", tmp_path / "data"
    manifest, path = make_run(db, data, "1" * 32)
    prepare(db, manifest["run_id"], path, "prepare-route")
    monkeypatch.setattr("app.main.DB_PATH", db)
    monkeypatch.setattr("app.main.DATA_DIR", data)
    monkeypatch.setattr(
        "app.main.analyze_scan_run_nmap_base",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("read route parsed source XML")),
    )

    with TestClient(app) as client:
        writer = connect_database(db)
        try:
            writer.execute("BEGIN IMMEDIATE")
            response = client.get(f"/api/scan-runs/{manifest['run_id']}/analysis")
        finally:
            writer.rollback()
            writer.close()

    assert response.status_code == 200
    payload = response.json()
    assert payload["analysis"]["hosts"][0]["ip"] == "192.0.2.10"
    assert payload["saved_result_provenance"]["children"][0]["run_id"] == manifest["run_id"]
    assert payload["current_annotations"] == []


def test_unprepared_registered_and_legacy_runs_fail_with_explicit_actions(tmp_path):
    db, data = tmp_path / "nct.db", tmp_path / "data"
    registered, _ = make_run(db, data, "b" * 32)
    with pytest.raises(RetainedScanAnalysisUnavailable) as registered_error:
        load_prepared_scan_group(db, data, registered["run_id"])
    assert registered_error.value.code == "prepare_required"
    assert "Prepare from saved scan" in str(registered_error.value)

    legacy_id = "c" * 32
    legacy_dir = data / "scan-runs" / legacy_id
    legacy_dir.mkdir(parents=True)
    (legacy_dir / "scan.xml").write_bytes(XML)
    legacy = {"run_id": legacy_id, "status": "completed", "created_at": "2020-01-01T00:00:00+00:00"}
    with connect_database(db) as connection:
        connection.execute(
            "INSERT INTO scan_runs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (legacy_id, legacy["created_at"], "completed", "analyst", "test", "host", "eth0", "profile", json.dumps(legacy)),
        )
    with pytest.raises(RetainedScanAnalysisUnavailable) as legacy_error:
        load_prepared_scan_group(db, data, legacy_id)
    assert legacy_error.value.code == "conversion_required"
    assert "backfill" in str(legacy_error.value)


def test_exact_old_scheduled_group_is_not_lost_behind_history_window(tmp_path):
    db, data = tmp_path / "nct.db", tmp_path / "data"
    first, first_path = make_run(
        db, data, "d" * 32, batch="old-batch", chunk_number=1, chunk_count=2,
    )
    second_xml = XML.replace(b"192.0.2.10", b"192.0.2.11")
    second, second_path = make_run(
        db, data, "e" * 32, second_xml, batch="old-batch", chunk_number=2, chunk_count=2,
    )
    prepare(db, first["run_id"], first_path, "prepare-first")
    prepare(db, second["run_id"], second_path, "prepare-second")
    with connect_database(db) as connection:
        connection.executemany(
            "INSERT INTO scan_runs VALUES (?, ?, 'completed', 'analyst', 'test', 'host', 'eth0', 'profile', ?)",
            [
                (
                    f"{index:032x}", f"2040-01-01T00:{index // 60 % 60:02d}:{index % 60:02d}+00:00",
                    json.dumps({"run_id": f"{index:032x}", "status": "completed", "created_at": "2040-01-01T00:00:00+00:00"}),
                )
                for index in range(1, 5002)
                if f"{index:032x}" not in {first["run_id"], second["run_id"]}
            ],
        )
    result = load_prepared_scan_group(db, data, first["run_id"])
    assert result["group"]["run_ids"] == [first["run_id"], second["run_id"]]
    assert {host["ip"] for host in result["analysis"]["hosts"]} == {"192.0.2.10", "192.0.2.11"}


def test_missing_chunk_and_changed_local_evidence_fail_closed(tmp_path):
    db, data = tmp_path / "nct.db", tmp_path / "data"
    manifest, path = make_run(
        db, data, "f" * 32, batch="broken-batch", chunk_number=1, chunk_count=2,
    )
    prepare(db, manifest["run_id"], path, "prepare-broken")
    with pytest.raises(RetainedScanAnalysisUnavailable) as missing:
        load_prepared_scan_group(db, data, manifest["run_id"])
    assert missing.value.code == "group_incomplete"

    with connect_database(db) as connection:
        stored = json.loads(connection.execute(
            "SELECT manifest_json FROM scan_runs WHERE run_id = ?", (manifest["run_id"],),
        ).fetchone()[0])
        stored["chunk_count"] = 1
        stored["chunk_number"] = 1
        stored["schedule_batch_id"] = None
        connection.execute(
            "UPDATE scan_runs SET manifest_json = ? WHERE run_id = ?",
            (json.dumps(stored, sort_keys=True), manifest["run_id"]),
        )
    path.write_bytes(XML.replace(b"443", b"444"))
    with pytest.raises(RetainedScanAnalysisUnavailable) as changed:
        load_prepared_scan_group(db, data, manifest["run_id"])
    assert changed.value.code == "evidence_changed"


def test_database_and_manifest_completion_status_must_agree(tmp_path):
    db, data = tmp_path / "nct.db", tmp_path / "data"
    manifest, path = make_run(db, data, "7" * 32)
    prepare(db, manifest["run_id"], path, "prepare-status")
    with connect_database(db) as connection:
        connection.execute(
            "UPDATE scan_runs SET status = 'failed' WHERE run_id = ?",
            (manifest["run_id"],),
        )
    with pytest.raises(RetainedScanAnalysisUnavailable) as conflict:
        load_prepared_scan_group(db, data, manifest["run_id"])
    assert conflict.value.code == "source_incomplete"


def test_authoritative_scan_observation_must_be_unique(tmp_path):
    db, data = tmp_path / "nct.db", tmp_path / "data"
    manifest, path = make_run(db, data, "8" * 32)
    prepare(db, manifest["run_id"], path, "prepare-ambiguous")
    with connect_database(db) as connection:
        connection.execute(
            """INSERT INTO artifact_observations (
                   observation_id, sha256, source_kind, source_ref, observed_at,
                   original_filename, actor, metadata_json
               )
               SELECT ?, sha256, source_kind, source_ref, observed_at,
                      original_filename, actor, metadata_json
               FROM artifact_observations
               WHERE source_kind = 'nmap_scan' AND source_ref = ?
                 AND original_filename = 'scan.xml'""",
            ("duplicate-observation", manifest["run_id"]),
        )
    with pytest.raises(RetainedScanAnalysisUnavailable) as conflict:
        load_prepared_scan_group(db, data, manifest["run_id"])
    assert conflict.value.code == "analysis_conflict"


def test_stale_job_with_higher_attempt_number_cannot_shadow_current_job(tmp_path):
    db, data = tmp_path / "nct.db", tmp_path / "data"
    manifest, path = make_run(db, data, "9" * 32)
    queued = prepare(db, manifest["run_id"], path, "prepare-current")
    with connect_database(db) as connection:
        current = connection.execute(
            "SELECT * FROM pipeline_jobs WHERE source_run_id = ?",
            (manifest["run_id"],),
        ).fetchone()
        columns = [item[1] for item in connection.execute("PRAGMA table_info(pipeline_jobs)")]
        stale = dict(zip(columns, current))
        stale.update({
            "job_id": "stale-job", "job_key": "stale-job-key",
            "source_observation_id": "superseded-observation",
            "source_sha256": "0" * 64,
        })
        connection.execute(
            f"INSERT INTO pipeline_jobs ({', '.join(columns)}) VALUES ({', '.join('?' for _ in columns)})",
            tuple(stale[column] for column in columns),
        )
        connection.execute(
            """INSERT INTO pipeline_job_attempts (
                   attempt_id, job_id, attempt_number, state, requested_by,
                   requested_at, finished_at, result_id, output_kind, output_id
               ) VALUES (?, ?, 2, 'completed', 'analyst', ?, ?, ?, 'derived_result', ?)""",
            (
                "stale-attempt", "stale-job", "2040-01-01T00:00:00+00:00",
                "2040-01-01T00:01:00+00:00", "f" * 64, "f" * 64,
            ),
        )
    result = load_prepared_scan_group(db, data, manifest["run_id"])
    assert result["provenance"]["children"][0]["result_id"] == queued["target_result_id"]


@pytest.mark.parametrize("column", ["result_id", "output_id"])
def test_completed_attempt_result_identifiers_must_agree(tmp_path, column):
    db, data = tmp_path / "nct.db", tmp_path / "data"
    manifest, path = make_run(db, data, "a1" * 16)
    prepare(db, manifest["run_id"], path, f"prepare-mismatch-{column}")
    with connect_database(db) as connection:
        job_id = connection.execute(
            "SELECT job_id FROM pipeline_jobs WHERE source_run_id = ?",
            (manifest["run_id"],),
        ).fetchone()[0]
        connection.execute(
            f"UPDATE pipeline_job_attempts SET {column} = ? WHERE job_id = ?",
            ("f" * 64, job_id),
        )
    with pytest.raises(RetainedScanAnalysisUnavailable) as conflict:
        load_prepared_scan_group(db, data, manifest["run_id"])
    assert conflict.value.code == "analysis_conflict"


def test_metadata_listing_does_not_open_saved_result_payloads_or_files(tmp_path, monkeypatch):
    db, data = tmp_path / "nct.db", tmp_path / "data"
    manifest, path = make_run(db, data, "b1" * 16)
    prepare(db, manifest["run_id"], path, "prepare-metadata")
    monkeypatch.setattr(
        "app.retained_scan_analysis._load_derived_result",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("payload opened")),
    )
    path.unlink()
    metadata = list_prepared_scan_group_metadata(db)
    assert metadata[0]["selection_run_id"] == manifest["run_id"]


def test_single_run_manifest_cannot_substitute_another_run(tmp_path):
    db, data = tmp_path / "nct.db", tmp_path / "data"
    first, first_path = make_run(db, data, "c1" * 16)
    second, second_path = make_run(db, data, "c2" * 16)
    prepare(db, first["run_id"], first_path, "prepare-first-substitution")
    prepare(db, second["run_id"], second_path, "prepare-second-substitution")
    with connect_database(db) as connection:
        stored = json.loads(connection.execute(
            "SELECT manifest_json FROM scan_runs WHERE run_id = ?", (first["run_id"],),
        ).fetchone()[0])
        stored["run_id"] = second["run_id"]
        connection.execute(
            "UPDATE scan_runs SET manifest_json = ? WHERE run_id = ?",
            (json.dumps(stored, sort_keys=True), first["run_id"]),
        )
    with pytest.raises(RetainedScanAnalysisUnavailable) as conflict:
        load_prepared_scan_group(db, data, first["run_id"])
    assert conflict.value.code == "source_conflict"


def test_grouped_chunk_manifest_cannot_substitute_another_chunk(tmp_path):
    db, data = tmp_path / "nct.db", tmp_path / "data"
    first, first_path = make_run(
        db, data, "d1" * 16, batch="substitution", chunk_number=1, chunk_count=2,
    )
    second, second_path = make_run(
        db, data, "d2" * 16, batch="substitution", chunk_number=2, chunk_count=2,
    )
    prepare(db, first["run_id"], first_path, "prepare-first-chunk-substitution")
    prepare(db, second["run_id"], second_path, "prepare-second-chunk-substitution")
    with connect_database(db) as connection:
        stored = json.loads(connection.execute(
            "SELECT manifest_json FROM scan_runs WHERE run_id = ?", (second["run_id"],),
        ).fetchone()[0])
        stored["run_id"] = first["run_id"]
        connection.execute(
            "UPDATE scan_runs SET manifest_json = ? WHERE run_id = ?",
            (json.dumps(stored, sort_keys=True), second["run_id"]),
        )
    with pytest.raises(RetainedScanAnalysisUnavailable) as conflict:
        load_prepared_scan_group(db, data, first["run_id"])
    assert conflict.value.code == "source_conflict"


def test_current_job_state_is_not_shadowed_by_stale_job_attempt(tmp_path):
    db, data = tmp_path / "nct.db", tmp_path / "data"
    manifest, _path = make_run(db, data, "e1" * 16)
    enqueue_nmap_base_job(db, manifest["run_id"], request_token="current-queued", requested_by="analyst")
    with connect_database(db) as connection:
        current = connection.execute(
            "SELECT * FROM pipeline_jobs WHERE source_run_id = ?", (manifest["run_id"],),
        ).fetchone()
        columns = [item[1] for item in connection.execute("PRAGMA table_info(pipeline_jobs)")]
        stale = dict(zip(columns, current))
        stale.update({
            "job_id": "old-job", "job_key": "old-job-key",
            "source_observation_id": "old-observation", "source_sha256": "0" * 64,
        })
        connection.execute(
            f"INSERT INTO pipeline_jobs ({', '.join(columns)}) VALUES ({', '.join('?' for _ in columns)})",
            tuple(stale[column] for column in columns),
        )
        connection.execute(
            """INSERT INTO pipeline_job_attempts (
                   attempt_id, job_id, attempt_number, state, requested_by,
                   requested_at, finished_at, error
               ) VALUES ('old-failure', 'old-job', 2, 'failed', 'analyst', ?, ?, 'old failure')""",
            ("2040-01-01T00:00:00+00:00", "2040-01-01T00:01:00+00:00"),
        )
    with pytest.raises(RetainedScanAnalysisUnavailable) as unavailable:
        load_prepared_scan_group(db, data, manifest["run_id"])
    assert unavailable.value.code == "preparing"
    assert "old failure" not in str(unavailable.value)


def test_metadata_selector_handles_reviewed_prepared_history_ceiling(tmp_path):
    db, data = tmp_path / "nct.db", tmp_path / "data"
    manifest, path = make_run(db, data, "f1" * 16)
    prepare(db, manifest["run_id"], path, "prepare-indexed-history")
    with connect_database(db) as connection:
        job_columns = [item[1] for item in connection.execute("PRAGMA table_info(pipeline_jobs)")]
        attempt_columns = [item[1] for item in connection.execute("PRAGMA table_info(pipeline_job_attempts)")]
        job_template = dict(zip(job_columns, connection.execute(
            "SELECT * FROM pipeline_jobs WHERE source_run_id = ?", (manifest["run_id"],),
        ).fetchone()))
        attempt_template = dict(zip(attempt_columns, connection.execute(
            "SELECT * FROM pipeline_job_attempts WHERE job_id = ?", (job_template["job_id"],),
        ).fetchone()))
        digest = job_template["source_sha256"]
        created = "2040-01-01T00:00:00+00:00"
        for index in range(1, 5000):
            run_id = f"{index + 10000:032x}"
            observation_id = f"prepared-observation-{index}"
            job_id = f"prepared-job-{index}"
            scaled_manifest = {
                **manifest, "run_id": run_id, "created_at": created, "completed_at": created,
                "display_name": f"Prepared history {index}", "schedule_batch_id": None,
                "chunk_number": None, "chunk_count": None,
            }
            connection.execute(
                "INSERT INTO scan_runs VALUES (?, ?, 'completed', 'analyst', 'test', 'host', 'eth0', 'profile', ?)",
                (run_id, created, json.dumps(scaled_manifest, sort_keys=True)),
            )
            connection.execute(
                """INSERT INTO artifact_observations (
                       observation_id, sha256, source_kind, source_ref, observed_at,
                       original_filename, actor, metadata_json
                   ) VALUES (?, ?, 'nmap_scan', ?, ?, 'scan.xml', 'analyst', '{}')""",
                (observation_id, digest, run_id, created),
            )
            job = dict(job_template)
            job.update({
                "job_id": job_id, "job_key": f"prepared-job-key-{index}",
                "source_run_id": run_id, "source_observation_id": observation_id,
                "source_ref": run_id,
            })
            connection.execute(
                f"INSERT INTO pipeline_jobs ({', '.join(job_columns)}) VALUES ({', '.join('?' for _ in job_columns)})",
                tuple(job[column] for column in job_columns),
            )
            attempt = dict(attempt_template)
            attempt.update({"attempt_id": f"prepared-attempt-{index}", "job_id": job_id})
            connection.execute(
                f"INSERT INTO pipeline_job_attempts ({', '.join(attempt_columns)}) VALUES ({', '.join('?' for _ in attempt_columns)})",
                tuple(attempt[column] for column in attempt_columns),
            )
    tracemalloc.start()
    started = time.perf_counter()
    metadata = list_prepared_scan_group_metadata(db)
    elapsed = time.perf_counter() - started
    _current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert len(metadata) == 5000
    assert manifest["run_id"] in {item["selection_run_id"] for item in metadata}
    assert elapsed < 5.0
    assert peak < 64 * 1024 * 1024
