from __future__ import annotations

import json
import hashlib
import os
from pathlib import Path
import threading
from concurrent.futures import ThreadPoolExecutor

from fastapi.testclient import TestClient
import pytest

from app.artifacts import get_artifact_observation, init_artifact_storage, register_artifact_file
from app.automated_nmap_foundation import (
    AutomatedNmapFoundationConflict,
    get_automated_scan_foundation_status,
    init_automated_nmap_foundation_storage,
    process_automated_scan_foundation,
    recover_interrupted_automated_scan_foundation,
)
from app.database import connect_database
from app.derived_jobs import (
    claim_next_derived_job,
    enqueue_automated_nmap_scope_job,
    recover_interrupted_derived_jobs,
    retry_derived_job,
    run_next_derived_job,
    scan_run_job_statuses,
)
from app.network_scopes import archive_network_scope, create_network_scope
from app.poc import (
    ScanRunRequest,
    delete_all_scan_data,
    delete_scan_data,
    init_poc_storage,
    issue_delete_challenge,
    prepare_scan_run,
)
from app.saved_networks import SavedNetworkCreate, create_saved_network
from app.saved_network_scope_associations import (
    change_saved_network_scope_association,
    get_run_scope_context,
)
from app.searchsploit_results import load_retained_searchsploit_candidates
from app.searchsploit import searchsploit_provider_snapshot
from app.searchsploit_results import (
    candidate_result_identity,
    generate_searchsploit_candidate_result,
)


XML = b'''<nmaprun scanner="nmap" version="7.95" args="nmap -n -sS 192.0.2.10" start="100">
<scaninfo type="syn" protocol="tcp" numservices="1" services="443"/>
<host starttime="101" endtime="109"><status state="up" reason="syn-ack"/>
<address addr="192.0.2.10" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port>
</ports></host><runstats><finished time="110" timestr="done"/><hosts up="1" down="0" total="1"/></runstats></nmaprun>'''


def candidate_payload(_hunting, **_kwargs):
    candidate = {
        "edb_id": "12345", "title": "Offline candidate", "platform": "linux",
        "type": "remote", "codes": "CVE-2026-1234", "cves": ["CVE-2026-1234"],
        "verified": True, "date_published": "2026-01-01", "path": "12345.py",
        "url": "https://www.exploit-db.com/exploits/12345",
    }
    match = {
        "match_key": "ip:192.0.2.10|tcp|443|example|1.0",
        "host_key": "ip:192.0.2.10", "ip": "192.0.2.10", "hostname": None,
        "port": 443, "protocol": "tcp", "service": "https",
        "product": "example", "version": "1.0", "query": "example 1.0",
        "candidate_count": 1, "candidates": [candidate], "cves": ["CVE-2026-1234"],
    }
    return {
        "status": "searchsploit_complete", "provider": {}, "query_count": 1,
        "cache_hit_count": 0, "cache_miss_count": 1, "searched_finding_count": 1,
        "skipped_no_product_count": 0, "matched_host_count": 1, "match_count": 1,
        "cve_count": 1, "cve_candidate_count": 1, "non_cve_candidate_count": 0,
        "cve_facets": [], "matches": [match], "coverage_complete": True,
        "query_limit": 40, "candidate_limit_per_query": 25,
        "omitted_distinct_query_count": 0, "omitted_finding_count": 0,
        "candidate_limit_reached_query_count": 0, "warnings": [],
        "disclaimer": "Potential product/version matches require analyst validation.",
    }


def scoped_run(
    tmp_path: Path, *, content: bytes = XML, label: str = "Lab",
    cidr: str = "192.0.2.0/24", db_path: Path | None = None,
):
    db_path = db_path or (tmp_path / "analyzer.db")
    init_artifact_storage(db_path)
    init_poc_storage(db_path)
    network = create_saved_network(
        SavedNetworkCreate(
            name=f"{label} subnet", cidr=cidr, created_by="analyst"
        ),
        db_path,
    )
    scope = create_network_scope(
        db_path, label=label, created_by="admin", reason="Approved context"
    )
    association = change_saved_network_scope_association(
        db_path,
        network["saved_network_id"],
        scope_id=scope["scope_id"],
        expected_association_id=None,
        expected_revision=None,
        actor="analyst",
        reason="Reviewed authorization record",
    )
    request = ScanRunRequest(
        operator="analyst",
        created_by="analyst",
        name="Scoped completed scan",
        originating_host="nct-test",
        interface="eth0",
        profile="Standard",
        profile_id="builtin-standard",
        profile_version=2,
        targets=[network["cidr"]],
        manual_targets=[],
        saved_network_ids=[network["saved_network_id"]],
        reviewed_scope_associations=[{
            "association_id": association["association_id"],
            "revision": association["revision"],
        }],
        capture=True,
        timeout_seconds=30,
    )
    run = prepare_scan_run(request, db_path, interfaces={"eth0"})
    run["status"] = "completed"
    run["completed_at"] = run["created_at"]
    with connect_database(db_path) as db:
        db.execute(
            "UPDATE scan_runs SET status = 'completed', manifest_json = ? WHERE run_id = ?",
            (json.dumps(run), run["run_id"]),
        )
    xml_path = tmp_path / f"{run['run_id']}-scan.xml"
    xml_path.write_bytes(content)
    observation = register_artifact_file(
        db_path=db_path,
        source_path=xml_path,
        source_kind="nmap_scan",
        source_ref=run["run_id"],
        original_filename="scan.xml",
        actor="analyst",
        observed_at=run["completed_at"],
        observation_key=f"nmap_scan:{run['run_id']}:scan.xml",
        run_id=run["run_id"],
        scope_context=get_run_scope_context(db_path, run["run_id"]),
    )
    init_automated_nmap_foundation_storage(db_path)
    return db_path, run, scope, observation


def test_explicit_processing_uses_retained_scope_and_is_exactly_replayable(tmp_path):
    db_path, run, scope, observation = scoped_run(tmp_path)
    component_path = tmp_path / "tcp-scan.xml"
    component_path.write_bytes(XML)
    component = register_artifact_file(
        db_path=db_path, source_path=component_path, source_kind="nmap_scan",
        source_ref=run["run_id"], original_filename="tcp-scan.xml", actor="analyst",
        observed_at=run["completed_at"],
        observation_key=f"nmap_scan:{run['run_id']}:tcp-scan.xml",
        run_id=run["run_id"], scope_context=get_run_scope_context(db_path, run["run_id"]),
    )

    ready = get_automated_scan_foundation_status(db_path, run["run_id"])
    first = process_automated_scan_foundation(db_path, run["run_id"], "analyst")
    replay = process_automated_scan_foundation(db_path, run["run_id"], "analyst")

    assert ready["state"] == "ready"
    assert ready["scope_id"] == scope["scope_id"]
    assert first["status"]["state"] == "foundation_complete"
    assert first["status"]["network_contact"] is False
    assert replay["processing"]["completed_replay"] is True
    analysis_status = scan_run_job_statuses(
        db_path, [run["run_id"]], tmp_path,
    )[run["run_id"]]
    assert analysis_status["current_job"] is None
    with connect_database(db_path, read_only=True) as db:
        assert db.execute(
            "SELECT status FROM scan_runs WHERE run_id = ?", (run["run_id"],)
        ).fetchone()[0] == "completed"
        assert db.execute(
            "SELECT COUNT(*) FROM entity_assessments WHERE artifact_observation_id = ?",
            (observation["observation_id"],),
        ).fetchone()[0] == 1
        assert db.execute(
            "SELECT COUNT(*) FROM entity_assessments WHERE artifact_observation_id = ?",
            (component["observation_id"],),
        ).fetchone()[0] == 0


def test_supported_intake_saves_candidates_and_reuses_exact_content_for_encounters(
    tmp_path, monkeypatch,
):
    import app.derived_jobs as jobs
    import app.searchsploit_results as results

    provider = {
        "available": True, "provider": "SearchSploit / Exploit-DB",
        "provider_key": "a" * 64, "active_version": "dataset-a",
        "archive_sha256": "b" * 64, "database_updated_epoch": 1000,
        "database_path": "/offline/a", "command_path": "/offline/a/searchsploit",
        "installed_at": "2030-01-01T00:00:00+00:00", "source": "test",
        "message": "ready",
    }
    monkeypatch.setattr(jobs, "start_derived_job_worker", lambda *args, **kwargs: None)
    monkeypatch.setattr(jobs, "searchsploit_provider_snapshot", lambda: dict(provider))
    monkeypatch.setattr(results, "searchsploit_provider_snapshot", lambda: dict(provider))
    assessment_calls = []

    def counted_candidate_payload(*args, **kwargs):
        assessment_calls.append(True)
        payload = candidate_payload(*args, **kwargs)
        payload["cache_hit_count"] = len(assessment_calls) - 1
        payload["cache_miss_count"] = 1 if len(assessment_calls) == 1 else 0
        return payload

    monkeypatch.setattr(
        results, "enrich_hunting_with_searchsploit", counted_candidate_payload,
    )
    db_path = tmp_path / "analyzer.db"
    (tmp_path / "first").mkdir()
    (tmp_path / "second").mkdir()
    first_db, first_run, _, first_observation = scoped_run(
        tmp_path / "first", db_path=db_path,
    )
    second_db, second_run, _, second_observation = scoped_run(
        tmp_path / "second", label="Second", cidr="198.51.100.0/24", db_path=db_path,
    )

    enqueue_automated_nmap_scope_job(
        first_db, first_run["run_id"], request_token="first", requested_by="analyst",
    )
    assert run_next_derived_job(first_db, tmp_path)
    assert run_next_derived_job(first_db, tmp_path)
    enqueue_automated_nmap_scope_job(
        second_db, second_run["run_id"], request_token="second", requested_by="analyst",
    )
    assert run_next_derived_job(second_db, tmp_path)
    assert run_next_derived_job(second_db, tmp_path)

    retained = load_retained_searchsploit_candidates(
        db_path, [first_run["run_id"], second_run["run_id"]]
    )
    assert retained["status"] == "retained_candidates_complete"
    assert len(assessment_calls) == 1
    assert retained["match_count"] == 1
    assert len(retained["encounters"]) == 2
    assert {item["observation_id"] for item in retained["encounters"]} == {
        first_observation["observation_id"], second_observation["observation_id"],
    }
    with connect_database(db_path, read_only=True) as db:
        assert db.execute(
            "SELECT COUNT(*) FROM derived_results WHERE family = ?",
            ("nmap_searchsploit_candidates",),
        ).fetchone()[0] == 1
        assert db.execute(
            """SELECT COUNT(*) FROM derived_result_observation_links link
               JOIN derived_results result ON result.result_id = link.result_id
               WHERE result.family = ?""",
            ("nmap_searchsploit_candidates",),
        ).fetchone()[0] == 2
        stored_payload = json.loads(db.execute(
            "SELECT result_json FROM derived_results WHERE family = ?",
            ("nmap_searchsploit_candidates",),
        ).fetchone()[0])
        assert "cache_hit_count" not in stored_payload
        assert "cache_miss_count" not in stored_payload

    mixed = load_retained_searchsploit_candidates(
        db_path, [first_run["run_id"], "legacy-unregistered-run"]
    )
    assert mixed["status"] == "retained_candidates_partial"
    assert mixed["coverage_complete"] is False
    assert len(mixed["source_states"]) == 2
    assert mixed["source_states"][-1]["state"] == "historical_unassessed"
    assert mixed["source_states"][-1]["run_id"] == "legacy-unregistered-run"


def test_failed_candidate_query_records_retryable_attempt_without_result(
    tmp_path, monkeypatch,
):
    import app.derived_jobs as jobs
    import app.searchsploit_results as results

    provider = {
        "available": True, "provider": "SearchSploit / Exploit-DB",
        "provider_key": "f" * 64, "active_version": "dataset-f",
        "archive_sha256": "e" * 64, "database_updated_epoch": 1000,
        "database_path": "/offline/f", "command_path": "/offline/f/searchsploit",
        "message": "ready",
    }
    incomplete = candidate_payload({})
    incomplete.update({
        "status": "searchsploit_incomplete",
        "coverage_complete": False,
        "failed_query_count": 1,
        "warnings": ["Local query failed."],
    })
    monkeypatch.setattr(jobs, "start_derived_job_worker", lambda *args, **kwargs: None)
    monkeypatch.setattr(jobs, "searchsploit_provider_snapshot", lambda: dict(provider))
    monkeypatch.setattr(results, "searchsploit_provider_snapshot", lambda: dict(provider))
    monkeypatch.setattr(
        results, "enrich_hunting_with_searchsploit", lambda *_args, **_kwargs: dict(incomplete),
    )
    db_path, run, _, _ = scoped_run(tmp_path)
    enqueue_automated_nmap_scope_job(
        db_path, run["run_id"], request_token="scope", requested_by="analyst",
    )

    assert run_next_derived_job(db_path, tmp_path)
    assert run_next_derived_job(db_path, tmp_path)

    retained = load_retained_searchsploit_candidates(db_path, [run["run_id"]])
    assert retained["status"] == "retained_candidates_not_available"
    assert retained["coverage_complete"] is False
    assert retained["source_states"][0]["state"] == "failed"
    assert "could not complete every product/version query" in (
        retained["source_states"][0]["detail"]
    )
    with connect_database(db_path, read_only=True) as db:
        assert db.execute(
            "SELECT COUNT(*) FROM derived_results WHERE family = ?",
            ("nmap_searchsploit_candidates",),
        ).fetchone()[0] == 0


@pytest.mark.skipif(os.name == "nt", reason="Uses a disposable POSIX SearchSploit stub")
def test_candidate_generation_binds_executable_and_reported_database(
    tmp_path, monkeypatch,
):
    import app.searchsploit_results as results

    frozen_database = tmp_path / "frozen-db"
    other_database = tmp_path / "other-db"
    frozen_database.mkdir()
    other_database.mkdir()

    def executable(name: str, reported_database: Path) -> tuple[Path, str]:
        path = tmp_path / name
        output = json.dumps({
            "DB_PATH_EXPLOITS": str(reported_database),
            "RESULTS_EXPLOITS": [],
        })
        path.write_text(
            "#!/bin/sh\ncat <<'NCT_SEARCHSPLOIT_JSON'\n"
            f"{output}\nNCT_SEARCHSPLOIT_JSON\n",
            encoding="utf-8",
        )
        path.chmod(0o755)
        return path, hashlib.sha256(path.read_bytes()).hexdigest()

    wrong_command, wrong_sha = executable("searchsploit-wrong", other_database)
    correct_command, correct_sha = executable("searchsploit-correct", frozen_database)

    def provider(command: Path, command_sha256: str) -> dict:
        return searchsploit_provider_snapshot({
            "available": True,
            "provider": "SearchSploit / Exploit-DB",
            "active_version": "same-dataset",
            "archive_sha256": "a" * 64,
            "database_updated_epoch": 1000,
            "database_path": str(frozen_database),
            "command_path": str(command),
            "command_sha256": command_sha256,
            "installed_at": "2030-01-01T00:00:00+00:00",
            "source": "test",
            "message": "ready",
        })

    wrong_provider = provider(wrong_command, wrong_sha)
    correct_provider = provider(correct_command, correct_sha)
    assert wrong_provider["provider_key"] != correct_provider["provider_key"]

    content = XML.replace(
        b'<service name="https"/>',
        b'<service name="https" product="nginx" version="1.24"/>',
    )
    db_path, _, _, observation = scoped_run(tmp_path, content=content)
    monkeypatch.setenv("ANALYZER_DATA_DIR", str(tmp_path / "data"))
    active_provider = dict(wrong_provider)
    monkeypatch.setattr(
        results, "searchsploit_provider_snapshot", lambda: dict(active_provider),
    )

    with pytest.raises(RuntimeError, match="could not complete every"):
        generate_searchsploit_candidate_result(
            db_path, observation["observation_id"], provider=wrong_provider,
        )
    with connect_database(db_path, read_only=True) as db:
        assert db.execute(
            "SELECT COUNT(*) FROM derived_results WHERE family = ?",
            ("nmap_searchsploit_candidates",),
        ).fetchone()[0] == 0

    active_provider.clear()
    active_provider.update(correct_provider)
    completed = generate_searchsploit_candidate_result(
        db_path, observation["observation_id"], provider=correct_provider,
    )

    assert completed["payload"]["coverage_complete"] is True
    assert completed["payload"]["query_count"] == 1
    assert completed["payload"]["matches"] == []
    assert completed["payload"]["match_count"] == 0
    assert candidate_result_identity(
        observation["sha256"], wrong_provider,
    ).result_id != completed["result_id"]


def test_candidate_stage_records_unavailable_database_without_page_read_work(
    tmp_path, monkeypatch,
):
    import app.derived_jobs as jobs

    provider = {
        "available": False, "provider": "SearchSploit / Exploit-DB",
        "provider_key": None, "message": "Offline data not staged.",
    }
    monkeypatch.setattr(jobs, "start_derived_job_worker", lambda *args, **kwargs: None)
    monkeypatch.setattr(jobs, "searchsploit_provider_snapshot", lambda: dict(provider))
    db_path, run, _, _ = scoped_run(tmp_path)
    enqueue_automated_nmap_scope_job(
        db_path, run["run_id"], request_token="scope", requested_by="analyst",
    )
    assert run_next_derived_job(db_path, tmp_path)

    retained = load_retained_searchsploit_candidates(db_path, [run["run_id"]])
    assert retained["status"] == "retained_candidates_not_available"
    assert retained["matches"] == []
    assert retained["source_states"][0]["state"] == "failed"
    assert retained["source_states"][0]["detail"] == "Offline data not staged."
    assert claim_next_derived_job(db_path) is None


def test_candidate_stage_restart_retry_and_dataset_change_are_explicit(
    tmp_path, monkeypatch,
):
    import app.derived_jobs as jobs
    import app.searchsploit_results as results

    first_provider = {
        "available": True, "provider": "SearchSploit / Exploit-DB",
        "provider_key": "c" * 64, "active_version": "dataset-c",
        "archive_sha256": "d" * 64, "database_updated_epoch": 1000,
        "database_path": "/offline/c", "command_path": "/offline/c/searchsploit",
        "message": "ready",
    }
    active_provider = dict(first_provider)
    monkeypatch.setattr(jobs, "start_derived_job_worker", lambda *args, **kwargs: None)
    monkeypatch.setattr(jobs, "searchsploit_provider_snapshot", lambda: dict(first_provider))
    monkeypatch.setattr(results, "searchsploit_provider_snapshot", lambda: dict(active_provider))
    monkeypatch.setattr(results, "enrich_hunting_with_searchsploit", candidate_payload)
    db_path, run, _, _ = scoped_run(tmp_path)
    enqueue_automated_nmap_scope_job(
        db_path, run["run_id"], request_token="scope", requested_by="analyst",
    )
    assert run_next_derived_job(db_path, tmp_path)
    claimed = claim_next_derived_job(db_path)
    assert claimed is not None
    assert recover_interrupted_derived_jobs(db_path) == 1
    with connect_database(db_path, read_only=True) as db:
        candidate_job_id = db.execute(
            "SELECT job_id FROM pipeline_jobs WHERE job_type = ?",
            ("nmap_searchsploit_candidates",),
        ).fetchone()[0]
    retry_derived_job(
        db_path, candidate_job_id, request_token="retry-candidate", requested_by="analyst",
    )
    active_provider["provider_key"] = "e" * 64
    active_provider["active_version"] = "dataset-e"
    assert run_next_derived_job(db_path, tmp_path)

    retained = load_retained_searchsploit_candidates(db_path, [run["run_id"]])
    assert retained["status"] == "retained_candidates_not_available"
    assert retained["source_states"][0]["state"] == "failed"
    assert "dataset changed" in retained["source_states"][0]["detail"]
    with connect_database(db_path, read_only=True) as db:
        assert db.execute(
            "SELECT COUNT(*) FROM derived_results WHERE family = ?",
            ("nmap_searchsploit_candidates",),
        ).fetchone()[0] == 0


def test_corrupt_canonical_file_records_error_without_partial_receipts_then_retries(tmp_path):
    db_path, run, _, observation = scoped_run(tmp_path)
    artifact = get_artifact_observation(db_path, observation["observation_id"])
    canonical = Path(artifact["canonical_path"])
    original = canonical.read_bytes()
    canonical.write_bytes(b"corrupt")

    with pytest.raises(ValueError):
        process_automated_scan_foundation(db_path, run["run_id"], "analyst")
    failed = get_automated_scan_foundation_status(db_path, run["run_id"])
    with connect_database(db_path, read_only=True) as db:
        assert db.execute("SELECT COUNT(*) FROM entity_assessments").fetchone()[0] == 0
        assert db.execute(
            "SELECT COUNT(*) FROM assessment_scope_assignment_links"
        ).fetchone()[0] == 0

    canonical.write_bytes(original)
    retried = process_automated_scan_foundation(db_path, run["run_id"], "analyst")
    assert failed["state"] == "processing_error"
    assert failed["latest_attempt"]["error"]
    assert retried["status"]["state"] == "foundation_complete"


def test_identical_bytes_in_separate_runs_keep_separate_receipts(tmp_path):
    db_path = tmp_path / "analyzer.db"
    first_db, first_run, _, first_observation = scoped_run(
        tmp_path, label="First", db_path=db_path,
    )
    second_db, second_run, _, second_observation = scoped_run(
        tmp_path, label="Second", cidr="198.51.100.0/24", db_path=db_path,
    )

    assert first_observation["sha256"] == second_observation["sha256"]
    assert first_observation["observation_id"] != second_observation["observation_id"]
    assert process_automated_scan_foundation(
        first_db, first_run["run_id"], "analyst"
    )["status"]["state"] == "foundation_complete"
    assert process_automated_scan_foundation(
        second_db, second_run["run_id"], "analyst"
    )["status"]["state"] == "foundation_complete"
    with connect_database(db_path, read_only=True) as db:
        assert db.execute("SELECT COUNT(*) FROM artifact_registry").fetchone()[0] == 1
        assert db.execute("SELECT COUNT(*) FROM artifact_observations").fetchone()[0] == 2
        assert db.execute("SELECT COUNT(*) FROM entity_assessments").fetchone()[0] == 2


def test_archived_scope_blocks_new_processing_but_not_completed_replay(tmp_path):
    before_dir = tmp_path / "before"
    after_dir = tmp_path / "after"
    before_dir.mkdir()
    after_dir.mkdir()
    blocked_db, blocked_run, blocked_scope, _ = scoped_run(before_dir)
    archive_network_scope(
        blocked_db, blocked_scope["scope_id"], expected_version=1,
        archived_by="admin", reason="Retired context",
    )
    with pytest.raises(AutomatedNmapFoundationConflict, match="archived"):
        process_automated_scan_foundation(blocked_db, blocked_run["run_id"], "analyst")

    replay_db, replay_run, replay_scope, _ = scoped_run(after_dir)
    process_automated_scan_foundation(replay_db, replay_run["run_id"], "analyst")
    archive_network_scope(
        replay_db, replay_scope["scope_id"], expected_version=1,
        archived_by="admin", reason="Retired after processing",
    )
    replay = process_automated_scan_foundation(replay_db, replay_run["run_id"], "analyst")
    assert replay["processing"]["completed_replay"] is True


def test_route_roles_status_and_server_owned_actor(tmp_path, monkeypatch):
    import app.main as main
    import app.poc as poc

    db_path, run, _, _ = scoped_run(tmp_path)
    monkeypatch.setattr(main, "DB_PATH", db_path)
    monkeypatch.setattr(poc, "DB_PATH", db_path)
    # This route test verifies the signed-in requester on an explicit action.
    # The separate intake tests cover startup recovery and automatic admission.
    monkeypatch.setattr(main, "recover_missing_automated_nmap_intents", lambda *args: [])
    monkeypatch.setattr(main, "auth_enabled", lambda: True)
    monkeypatch.setattr(
        main, "session_identity",
        lambda *args: {"username": "alice", "display_name": "Alice", "role": "analyst"},
    )
    with TestClient(main.app) as client:
        status = client.get(f"/api/scan-runs/{run['run_id']}/foundation-status")
        processed = client.post(
            f"/api/scan-runs/{run['run_id']}/foundation-process",
            json={"request_token": "route-process"},
        )
        blocked = client.post(
            f"/api/scan-runs/{run['run_id']}/foundation-process",
            json={"request_token": "route-blocked"},
            headers={"Origin": "https://outside.example"},
        )
    assert status.status_code == 200
    assert processed.status_code == 202
    assert processed.json()["job"]["requested_by"] == "alice"
    assert blocked.status_code == 403

    monkeypatch.setattr(
        main, "session_identity",
        lambda *args: {"username": "viewer", "display_name": "Viewer", "role": "viewer"},
    )
    with TestClient(main.app) as client:
        readable = client.get(f"/api/scan-runs/{run['run_id']}/foundation-status")
        denied = client.post(
            f"/api/scan-runs/{run['run_id']}/foundation-process",
            json={"request_token": "viewer-denied"},
        )
    assert readable.status_code == 200
    assert denied.status_code == 403


def test_grouped_history_keeps_retained_scope_beside_foundation_status(
    tmp_path, monkeypatch,
):
    import app.main as main
    import app.poc as poc

    db_path, run, scope, _ = scoped_run(tmp_path)
    monkeypatch.setattr(main, "DB_PATH", db_path)
    monkeypatch.setattr(poc, "DB_PATH", db_path)
    monkeypatch.setattr(main, "auth_enabled", lambda: False)
    with TestClient(main.app) as client:
        grouped = client.get("/api/scan-runs-grouped?limit=25&offset=0")

    assert grouped.status_code == 200
    retained = next(
        item for group in grouped.json() for item in group["runs"]
        if item["run_id"] == run["run_id"]
    )
    assert retained["network_scope_context"]["scope_id"] == scope["scope_id"]
    assert retained["foundation_status"]["scope_id"] == scope["scope_id"]


def test_legacy_attempt_history_is_interrupted_at_cutover_then_frozen(tmp_path):
    db_path, run, _, observation = scoped_run(tmp_path)
    canonical = Path(
        get_artifact_observation(db_path, observation["observation_id"])["canonical_path"]
    )
    with connect_database(db_path) as db:
        for name in (
            "scan_foundation_attempt_no_insert",
            "scan_foundation_attempt_no_update",
            "scan_foundation_attempt_no_delete",
        ):
            db.execute(f"DROP TRIGGER {name}")
        evidence = db.execute(
            """SELECT observation.observation_id, assignment.assignment_id
               FROM artifact_observations observation
               JOIN scan_inherited_scope_assignments inherited
                 ON inherited.observation_id = observation.observation_id
               JOIN artifact_scope_assignments assignment
                 ON assignment.assignment_id = inherited.assignment_id
               WHERE observation.source_ref = ?""",
            (run["run_id"],),
        ).fetchone()
        if evidence is None:
            current = __import__(
                "app.automated_nmap_foundation", fromlist=["_run_evidence", "_ensure_inherited_assignment"]
            )
            details = current._run_evidence(db, run["run_id"])
            assignment_id = current._ensure_inherited_assignment(db, details, "legacy")
            observation_id = details["observation_id"]
        else:
            observation_id, assignment_id = evidence
        values = (run["run_id"], observation_id, assignment_id, "2030-01-01T00:00:00+00:00")
        db.execute(
            """INSERT INTO scan_foundation_processing_attempts
               (attempt_id, run_id, observation_id, assignment_id, actor,
                started_at, finished_at, status, error)
               VALUES ('zz-older', ?, ?, ?, 'older', ?, ?, 'error', 'older failure')""",
            (*values, values[-1]),
        )
        db.execute(
            """INSERT INTO scan_foundation_processing_attempts
               (attempt_id, run_id, observation_id, assignment_id, actor,
                started_at, status)
               VALUES ('aa-newer', ?, ?, ?, 'newer', ?, 'running')""",
            values,
        )
    init_automated_nmap_foundation_storage.__wrapped__(db_path)
    with connect_database(db_path) as db:
        latest = db.execute(
            """SELECT status, error FROM scan_foundation_processing_attempts
               WHERE attempt_id = 'aa-newer'"""
        ).fetchone()
        assert latest[0] == "interrupted"
        assert "durable pipeline cutover" in latest[1]
        with pytest.raises(Exception, match="read-only"):
            db.execute(
                "UPDATE scan_foundation_processing_attempts SET actor = 'changed' WHERE attempt_id = 'aa-newer'"
            )
    assert recover_interrupted_automated_scan_foundation(db_path) == 0


@pytest.mark.parametrize("attempt_status", ["complete", "error", "running"])
@pytest.mark.parametrize("delete_mode", ["single", "all"])
def test_protected_scan_deletion_preserves_database_and_files(
    tmp_path, attempt_status, delete_mode,
):
    db_path, run, _, _ = scoped_run(tmp_path)
    process_automated_scan_foundation(db_path, run["run_id"], "analyst")
    with connect_database(db_path) as db:
        mapped = {"complete": "completed", "error": "failed", "running": "running"}[attempt_status]
        db.execute(
            """UPDATE pipeline_job_attempts SET state = ?,
                   error = CASE WHEN ? = 'failed' THEN 'test failure' END,
                   finished_at = CASE WHEN ? = 'running' THEN NULL ELSE started_at END
               WHERE job_id = (
                   SELECT job_id FROM pipeline_jobs WHERE source_run_id = ?
                   ORDER BY requested_at DESC LIMIT 1
               )""",
            (mapped, mapped, mapped, run["run_id"]),
        )
    data_dir = tmp_path / "data"
    retained = data_dir / "scan-runs" / run["run_id"] / "scan.xml"
    retained.parent.mkdir(parents=True)
    retained.write_bytes(XML)
    imported = data_dir / "imports" / "manual.xml"
    imported.parent.mkdir(parents=True)
    imported.write_bytes(XML)

    if delete_mode == "single":
        challenge = issue_delete_challenge("scan", run["run_id"])["challenge"]
        action = lambda: delete_scan_data(
            run["run_id"], challenge, db_path=db_path, data_dir=data_dir,
        )
    else:
        challenge = issue_delete_challenge("all", None)["challenge"]
        action = lambda: delete_all_scan_data(
            challenge, db_path=db_path, data_dir=data_dir,
        )
    with pytest.raises(RuntimeError, match="retained"):
        action()

    assert retained.read_bytes() == XML
    assert imported.read_bytes() == XML
    with connect_database(db_path, read_only=True) as db:
        assert db.execute(
            "SELECT COUNT(*) FROM scan_runs WHERE run_id = ?", (run["run_id"],)
        ).fetchone()[0] == 1


def test_delete_racing_active_processing_fails_closed(tmp_path, monkeypatch):
    import app.derived_jobs as jobs

    db_path, run, _, _ = scoped_run(tmp_path)
    data_dir = tmp_path / "data"
    retained = data_dir / "scan-runs" / run["run_id"] / "scan.xml"
    retained.parent.mkdir(parents=True)
    retained.write_bytes(XML)
    entered = threading.Event()
    release = threading.Event()
    original = jobs.ingest_assigned_nmap_observation

    def paused(*args, **kwargs):
        entered.set()
        assert release.wait(timeout=5)
        return original(*args, **kwargs)

    monkeypatch.setattr(jobs, "ingest_assigned_nmap_observation", paused)
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(
            process_automated_scan_foundation, db_path, run["run_id"], "analyst"
        )
        assert entered.wait(timeout=5)
        challenge = issue_delete_challenge("scan", run["run_id"])["challenge"]
        with pytest.raises(RuntimeError, match="retained"):
            delete_scan_data(
                run["run_id"], challenge, db_path=db_path, data_dir=data_dir,
            )
        assert retained.read_bytes() == XML
        release.set()
        assert future.result(timeout=5)["status"]["state"] == "foundation_complete"
